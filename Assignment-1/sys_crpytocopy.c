
#include <linux/linkage.h>
#include <linux/moduleloader.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include "user_types.h"
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/crypto.h>
#include <linux/err.h>
#include <linux/scatterlist.h>
#include <crypto/hash.h>
#include <linux/string.h>
#include <crypto/skcipher.h>
#define PAGE_CACHE_SIZE 4096 /* page size */
#define EXTRA_CREDIT 1
asmlinkage extern long (*sysptr)(void *arg);
/**
* @brief Utility function to unlink filesystem object
*
* @param file The pointer of a file to be unlinked
* @return int
*
* @source https://www.kernel.org/doc/htmldocs/filesystems/API-vfs-unlink.html
* @source https://android.googlesource.com/kernel/common/+/refs/heads/android-mainline/fs/incfs/vfs.c
*/
int utility_unlink(struct file *file)
{
	inode_lock_nested(file->f_path.dentry->d_parent->d_inode, I_MUTEX_PARENT);
	vfs_unlink(file->f_path.dentry->d_parent->d_inode, file->f_path.dentry, NULL);
	inode_unlock(file->f_path.dentry->d_parent->d_inode);
	return -EACCES;
}
/**
* @brief Utility function to read bytes from file to buffer using vfs_read().
*        If error, will clear all the bytes that has written previously using vfs_unlink.
*
* @param file The pointer of a file to read
* @param buf The buffer to store the bytes
* @param count Number of bytes to read
* @param pos The offset for the file pointer
* @return int
*/
int utility_read(struct file *file, char *buf, size_t count, unsigned long long *pos)
{
	if (vfs_read(file, buf, count, pos) < 0) {
		printk("vfs_read() - Error in reading\n Cleared partially written file\n");
		return utility_unlink(file);
	}
	return 0;
}
/**
* @brief Utility function to write bytes to buffer from file using vfs_wite().
*        If error, will clear all the bytes that has written previously using vfs_unlink.
*
* @param file The pointer of a file to write
* @param buf The buffer that store the bytes
* @param count Number of bytes to write
* @param pos The offset for the file pointer
* @return int
*/
int utility_write(struct file *file, char *buf, size_t count, unsigned long long *pos)
{
	if (vfs_write(file, buf, count, pos) < 0) {
		printk("vfs_write() - Error in writing\n Cleared partially written file\n");
		return utility_unlink(file);
	}
	return 0;
}
/**
* @brief Utility function to initialize before operations.
*        This function is called before every operation, i.e., copy, encrypt and decrypt
*
* @param kernel_addr The cryptocopy_params in kernel space
* @param user_addr The cryptocopy_params in user space
* @param infile_fp The pointer of input file
* @param outfile_fp The pointer of output file
* @param buffer The buffer to read from input file
* @param infile_offset The offset for the file pointer
* @param infile_size The size of infile
* @return int
*/
int utility_syscall_init(cryptocopy_params *kernel_addr, cryptocopy_params *user_addr, struct file **infile_fp, struct file **outfile_fp, char **buffer, unsigned long long  *infile_offset, unsigned long long *infile_size)
{
	int ret = 0;
	mm_segment_t oldfs;
	struct kstat infile_stat;

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	if(vfs_stat(user_addr->infile, &infile_stat) != 0)
	{ // to get the file status. vfs_stat takes user address.
		printk("vfs_stat() - user file status is not valid\n");
		ret = -EINVAL;
		goto end;
	}
	*infile_size = infile_stat.size;
	*infile_fp = filp_open(kernel_addr->infile, O_RDONLY, 0);
	set_fs(oldfs);
	if(*infile_fp == NULL || IS_ERR(*infile_fp)) // IS_ERR(0) = 0, so extra null check
	{
		printk("filp_open() - error while opening the input file\n");
		ret = PTR_ERR(*infile_fp);
		*infile_fp = NULL;
		goto end;
	}
	if(S_ISREG((*infile_fp)->f_inode->i_mode) == 0) // to check whether the given file is a regular file
	{
		printk("S_ISREG() - input file is not regular\n");
		ret = -EISDIR;
		goto end;
	}
	*infile_offset = (*infile_fp)->f_pos; // initialize with file position just after opening
	*buffer = kmalloc(sizeof(char) * (PAGE_CACHE_SIZE + 1), GFP_KERNEL);
	if(*buffer == NULL)
	{
		printk("utility_syscall_init() - memory not allocated by kmalloc - buffer\n");
		ret = -ENOMEM;
		goto end;
	}
	oldfs = get_fs();
	set_fs(KERNEL_DS); //since we do not need any translation
	*outfile_fp = filp_open(kernel_addr->outfile, O_CREAT |  O_WRONLY | O_TRUNC, infile_stat.mode);
	if(*outfile_fp == NULL || IS_ERR(*outfile_fp)) // IS_ERR(0) = 0, so extra null check
	{
		printk("filp_open() - error while opening the output file\n");
		ret = PTR_ERR(*outfile_fp);
		*outfile_fp = NULL;
		goto end;
	}
	/* To determine whether the file is a regualar file (i.e. on on disk or mass storage
		 rather than say a directory, socket, symbolic link for example. */
	if(S_ISREG((*outfile_fp)->f_inode->i_mode) == 0)
	{
			printk("S_ISREG() - output file is not regular\n");
			ret = -EISDIR;
			goto end;
	}
	if((*infile_fp)->f_inode == (*outfile_fp)->f_inode) { // check for same inode pointing
		  printk("utility_syscall_init() - input and output files pointing to same inode\n");
		  ret = -EINVAL;
			goto end;
	}
end:
set_fs(oldfs);
return ret;
}
/**
* @brief Syscall implementation of copy operation
*
* @param kernel_addr The cryptocopy_params in kernel space
* @param user_addr The cryptocopy_params in user space
* @return int
*/
int syscall_copy(cryptocopy_params *kernel_addr, cryptocopy_params *user_addr)
{
	int ret = 0;
	struct file *infile_fp = NULL;
	struct file *outfile_fp = NULL;
	char *buffer = NULL;
	unsigned long long  infile_offset = 0;
	unsigned long long infile_size = 0;
	unsigned long long infile_offset_itr = 0;
	unsigned long long min_size = 0;
	unsigned long long output_offset = 0;
	mm_segment_t oldfs = get_fs();
	ret = utility_syscall_init(kernel_addr,user_addr,&infile_fp,&outfile_fp,&buffer,&infile_offset,&infile_size); //initialize before the copy operation
	if(ret != 0)goto end;
	set_fs(KERNEL_DS); // as we do not need any translation
	infile_offset_itr = infile_offset;
	while(infile_offset_itr < infile_size) // till we read all the bytes
	{
			min_size = PAGE_CACHE_SIZE < (infile_size - infile_offset_itr) ? PAGE_CACHE_SIZE : (infile_size - infile_offset_itr); // min(4096, remaining bytes)
		  ret = utility_read(infile_fp, buffer, min_size, &infile_offset_itr); // read min(4096, remaining bytes) from input file
			if(ret != 0) goto end;
			buffer[min_size] = '\0'; // terminate with end character
			ret = utility_write(outfile_fp, buffer, min_size, &output_offset); // writing them to output file
			if(ret != 0) goto end;
	}
end:
  set_fs(oldfs);
	if(outfile_fp)
		filp_close(outfile_fp, NULL);
	if(buffer)
	  kfree(buffer);
	if (infile_fp)
		filp_close(infile_fp, NULL);
	return ret;
}
/**
* @brief function to encrypt the password using MD5 algortihm
*        This function converts the password to 16 bytes hash using MD5 algortihm
*
* @param password The password in user space
* @param password_len The length of the password
* @param encrypted_password buffer store the encrypted password
* @return void
*
* @source https://www.kernel.org/doc/html/latest/crypto/api-intro.html
*/
void utility_password_encrypt(char *password, int password_len, char *encrypted_password)
{
	struct scatterlist sg[2];
	struct crypto_ahash *tfm = NULL;
	struct ahash_request *req = NULL;
	if (encrypted_password == NULL)
	{
		printk("utility_password_encrypt() - encrypted_password is NULL\n");
		goto end;
	}
	sg_init_one(sg, password, password_len);
	tfm = crypto_alloc_ahash("md5", 0, CRYPTO_ALG_ASYNC); //allocate ahash cipher handle:
	if (IS_ERR(tfm))
	{
		printk("crypto_alloc_ahash() - failed\n");
		goto end;
	}
	req = ahash_request_alloc(tfm, GFP_ATOMIC);
	if (req == NULL)
	{
		printk("ahash_request_alloc() - failed\n");
		goto end;
	}
	ahash_request_set_callback(req, 0, NULL, NULL);
	ahash_request_set_crypt(req, sg, encrypted_password, password_len);
	if (crypto_ahash_digest(req))
	{
		printk("crypto_ahash_digest() - failed\n");
		goto end;
	}
	encrypted_password[MD5_KEY_LEN] = '\0';
end:
	if (req)
		ahash_request_free(req);
	if (tfm)
		crypto_free_ahash(tfm);
}
/**
* @brief Combined data structure for cipher operation.
*
* @source https://www.kernel.org/doc/html/v4.18/crypto/api-samples.html
*/
struct skcipher_def
{
	struct scatterlist sg;
	struct crypto_skcipher *tfm;
	struct skcipher_request *req;
	struct crypto_wait wait;
};
/**
* @brief function to encrypt the password using MD5 algortihm
*        This function converts the password to 16 bytes hash using MD5 algortihm
*
* @param skcipher_def Struct that holds the request
* @param flag The flag that says whether to encrypt or decrypt
* @return unsigned int
*
* @source https://www.kernel.org/doc/html/v4.18/crypto/api-samples.html
*/
unsigned int utility_skcipher_encdec(struct skcipher_def *sk, int flag)
{
	int rc;
	if (flag == ENCRYPTION)
		rc = crypto_skcipher_encrypt(sk->req);
	else
		rc = crypto_skcipher_decrypt(sk->req);
	if (rc)
		printk("skcipher encrypt returned with result %d\n", rc);
	return rc;
}
/**
* @brief function to initialize and execute cipher operation
*        The IV (Initialization Vector) used for encryption is "$saiharishavula$" (16 bytes).
*        And also, for the extra credit, it combines page number (first 8 bytes)
*        and inode number (second 8 bytes) for IV.
*
* @param scratchpad The chunk of bytes that has to encrypted/decrypted
* @param scratchpad_len The length of the chunk
* @param password The password to encrypt with
* @param password_len The length of the password
* @param page_number The page number to set the first 8 bytes of IV [Extra Credit]
* @param file_inode_number The inode number to set the second 8 bytes of IV [Extra Credit]
* @param flag The flag that says whether to encrypt or decrypt
* @return int
*
* @source https://www.kernel.org/doc/html/v4.18/crypto/api-samples.html
*/
int utility_skcipher(char *scratchpad, size_t scratchpad_len, char *password, int password_len, size_t page_number, char *file_inode_number, int flag)
{
	struct skcipher_def sk;
	struct crypto_skcipher *skcipher = NULL;
	struct skcipher_request *req = NULL;
#ifdef EXTRA_CREDIT
	char *page_number_str = NULL;
#endif
	char *ivdata = NULL;
	char *key = NULL;
	int ret = -EFAULT;
	skcipher = crypto_alloc_skcipher("ctr(aes)", 0, CRYPTO_ALG_ASYNC); /*AES Cipher*/
	if (IS_ERR(skcipher)) {
		printk("utility_skcipher() - could not allocate skcipher handle\n");
		return PTR_ERR(skcipher);
	}

	req = skcipher_request_alloc(skcipher, GFP_KERNEL);
	if (!req) {
		printk("skcipher_request_alloc() - could not allocate skcipher request\n");
		ret = -ENOMEM;
		goto end;
	}
	skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG, crypto_req_done, &sk.wait);
	if (crypto_skcipher_setkey(skcipher, password, password_len)) {
		printk("crypto_skcipher_setkey - unable to set key\n");
		ret = -EAGAIN;
		goto end;
	}
	ivdata = kmalloc(16, GFP_KERNEL);
	if (ivdata == NULL)
	{
		printk("utility_skcipher() - memory not allocated by kmalloc - IV\n");
		goto end;
	}

#ifdef EXTRA_CREDIT
	page_number_str = kmalloc(sizeof(char) * 8, GFP_KERNEL);
	if (page_number_str == NULL)
	{
		printk("utility_skcipher() - memory not allocated by kmalloc - page_number_str\n");
		goto end;
	}
	sprintf(page_number_str, "%08lu", page_number);
	memcpy(ivdata, page_number_str, 8);
	memcpy(ivdata + 8, file_inode_number, 8);
#else
	memcpy(ivdata, "$saiharishavula$",16);
#endif
	sk.tfm = skcipher;
	sk.req = req;

	sg_init_one(&sk.sg, scratchpad, scratchpad_len);
	skcipher_request_set_crypt(req, &sk.sg, &sk.sg, scratchpad_len, ivdata);
	crypto_init_wait(&sk.wait);
	ret = utility_skcipher_encdec(&sk, flag);
	if (ret)
		goto end;
end:
#ifdef EXTRA_CREDIT
	kfree(page_number_str);
#endif
	kfree(ivdata);
	kfree(key);
	if (skcipher)
		crypto_free_skcipher(skcipher);
	if (req)
		skcipher_request_free(req);
	return ret;
}
/**
* @brief Syscall implementation of encryption operation
*
* @param kernel_addr The cryptocopy_params in kernel space
* @param user_addr The cryptocopy_params in user space
* @return int
*/
int syscall_encryption(cryptocopy_params *kernel_addr, cryptocopy_params *user_addr)
{
	int ret = 0;
	struct file *infile_fp = NULL;
	struct file *outfile_fp = NULL;
	char *buffer = NULL;
	unsigned long long  infile_offset = 0;
	unsigned long long infile_size = 0;
	unsigned long long infile_offset_itr = 0;
	unsigned long long min_size = 0;
	unsigned long long output_offset = 0;
	char *passkey = NULL;
#ifdef EXTRA_CREDIT
  char *inode_number_str = NULL;
	unsigned long long page_number = 0;
#endif

	mm_segment_t oldfs = get_fs();
	ret = utility_syscall_init(kernel_addr,user_addr,&infile_fp,&outfile_fp,&buffer,&infile_offset,&infile_size); //initialize before the encrypt operation
	if(ret != 0)goto end;
	set_fs(KERNEL_DS); // no need of translation
	passkey  = kmalloc(MD5_KEY_LEN+1, GFP_KERNEL);
	if (passkey == NULL) {
		ret = -ENOMEM;
		printk("syscall_encryption() - memory not allocated by kmalloc - passkey\n");
		goto end;
	}
	utility_password_encrypt(kernel_addr->keybuf, kernel_addr->keylen, passkey); // encrypt the password using md5 algo
	ret = utility_write(outfile_fp, passkey, MD5_KEY_LEN, &output_offset); // write the 16 bytes of encrypted password to the output file
	if(ret != 0) {
		printk("syscall_encryption() - error in vfs_write - outfile_fp\n");
		goto end;
	}

#ifdef EXTRA_CREDIT
				inode_number_str = kmalloc(8, GFP_KERNEL);
				if (inode_number_str == NULL) {
					ret = -ENOMEM;
					goto end;
				}
				sprintf(inode_number_str, "%08lu", (unsigned long)infile_fp->f_inode->i_ino); // second 8 bytes is inode number of a file
				ret = utility_write(outfile_fp, inode_number_str, 8, &output_offset); // save it by writing it output file to retrieve and verify during decryption
				if(ret != 0) {
					printk("syscall_encryption() - error in vfs_write - outfile_fp\n");
					goto end;
				}
#endif
	infile_offset_itr = infile_offset;
	while(infile_offset_itr < infile_size) // till we read all the bytes
	{
		min_size = PAGE_CACHE_SIZE < (infile_size - infile_offset_itr) ? PAGE_CACHE_SIZE : (infile_size - infile_offset_itr); // min(4096, remaining bytes)
		ret = utility_read(infile_fp, buffer, min_size, &infile_offset_itr); // read the bytes to encrypt
		if(ret != 0) {
			printk("syscall_encryption() - error in vfs_read - infile_fp\n");
			goto end;
		}
#ifdef EXTRA_CREDIT
    ret = utility_skcipher(buffer, min_size, kernel_addr->keybuf, kernel_addr->keylen, page_number, inode_number_str, kernel_addr->flags); // encrypt the read bytes using dynamic IV
#else
		ret = utility_skcipher(buffer, min_size, kernel_addr->keybuf, kernel_addr->keylen, 0, NULL, kernel_addr->flags); // encrypt the read bytes using static IV
#endif
		if(ret != 0) {
			printk("syscall_encryption() - error in utility_skcipher\n");
			goto end;
		}
		buffer[min_size] = '\0';
		ret = utility_write(outfile_fp, buffer, min_size, &output_offset); //write the encrypted bytes to output file
		if(ret != 0) {
			printk("syscall_encryption() - error in vfs_write - outfile_fp\n");
			goto end;
		}
#ifdef EXTRA_CREDIT
	  page_number++; // increment the page number for dynamic IV
#endif
	}
end:
  set_fs(oldfs);
	if(outfile_fp)
		filp_close(outfile_fp, NULL);
	if(buffer)
	  kfree(buffer);
	if (infile_fp)
		filp_close(infile_fp, NULL);
	kfree(passkey);
	return ret;
}
/**
* @brief Syscall implementation of decryption operation
*
* @param kernel_addr The cryptocopy_params in kernel space
* @param user_addr The cryptocopy_params in user space
* @return int
*/
int syscall_decryption(cryptocopy_params *kernel_addr, cryptocopy_params *user_addr)
{
	int ret = 0;
	struct file *infile_fp = NULL;
	struct file *outfile_fp = NULL;
	char *buffer = NULL;
	unsigned long long  infile_offset = 0;
	unsigned long long infile_size = 0;
	unsigned long long infile_offset_itr = 0;
	unsigned long long min_size = 0;
	unsigned long long output_offset = 0;
	char *passkey = NULL;
	char *preamble = NULL;
#ifdef EXTRA_CREDIT
  char *inode_number_str = NULL;
	unsigned long long page_number = 0;
#endif

	mm_segment_t oldfs = get_fs();
	ret = utility_syscall_init(kernel_addr,user_addr,&infile_fp,&outfile_fp,&buffer,&infile_offset,&infile_size);//initialize before the encrypt operation
	if(ret != 0)goto end;
	set_fs(KERNEL_DS);
	infile_offset_itr = infile_offset;
	passkey  = kmalloc(MD5_KEY_LEN+1, GFP_KERNEL);
	if (passkey == NULL) {
		printk("syscall_decryption() - memory not allocated by kmalloc - passkey\n");
		ret = -ENOMEM;
		goto end;
	}
	preamble  = kmalloc(MD5_KEY_LEN+1, GFP_KERNEL);
	if (preamble == NULL) {
		printk("syscall_decryption() - memory not allocated by kmalloc - preamble\n");
		ret = -ENOMEM;
		goto end;
	}
	ret = utility_read(infile_fp, preamble, MD5_KEY_LEN, &infile_offset_itr);
	if(ret != 0) {
		printk("syscall_decryption() - error in vfs_read - infile_fp\n");
		goto end;
	}
	preamble[MD5_KEY_LEN] = '\0';
	utility_password_encrypt(kernel_addr->keybuf, kernel_addr->keylen, passkey); // encrypt the password given during decryption
	if (strcmp(passkey, preamble) != 0) { // check whether the both passwords(passwords given during encytion and decrytopn) are same
		printk("Compare - passwords do not match - must give the same passwords for encryption and decryption\n");
		ret = -EINVAL;
		goto end;
	}
#ifdef EXTRA_CREDIT
	inode_number_str = kmalloc(8 * sizeof(char), GFP_KERNEL);
	if (inode_number_str == NULL) {
		ret = -ENOMEM;
		goto end;
	}
	ret = utility_read(infile_fp, inode_number_str, 8, &infile_offset_itr); // read the inode number of file that is written during encryption
	if(ret != 0) {
		printk("syscall_decryption() - error in vfs_read - infile_fp\n");
		goto end;
	}
#endif
	while(infile_offset_itr < infile_size) // till we read all the bytes
	{
		min_size = PAGE_CACHE_SIZE < (infile_size - infile_offset_itr) ? PAGE_CACHE_SIZE : (infile_size - infile_offset_itr); // min(4096, remainng bytes)
		ret = utility_read(infile_fp, buffer, min_size, &infile_offset_itr); // read the bytes to decrpyt
		if(ret != 0) {
			printk("syscall_decryption() - error in vfs_read - infile_fp\n");
			goto end;
		}
#ifdef EXTRA_CREDIT
    ret = utility_skcipher(buffer, min_size, kernel_addr->keybuf, kernel_addr->keylen, page_number, inode_number_str, kernel_addr->flags); // decrypt the read bytes using dynamic IV
#else
		ret = utility_skcipher(buffer, min_size, kernel_addr->keybuf, kernel_addr->keylen, 0, NULL, kernel_addr->flags); // decrypt the read bytes using static IV
#endif
		if(ret != 0) {
			printk("syscall_decryption() - error in utility_skcipher\n");
			goto end;
		}
		buffer[min_size] = '\0';
		ret = utility_write(outfile_fp, buffer, min_size, &output_offset); // write the decrypted bytes to the output file
		if(ret != 0) {
			printk("syscall_decryption() - error in vfs_write - outfile_fp\n");
			goto end;
		}
#ifdef EXTRA_CREDIT
	  page_number++;// increment the page number for dynamic IV
#endif
	}
end:
  set_fs(oldfs);
	if(outfile_fp)
		filp_close(outfile_fp, NULL);
	if(buffer)
	  kfree(buffer);
	if (infile_fp)
		filp_close(infile_fp, NULL);
	kfree(passkey);
	kfree(preamble);
	return ret;
}
/**
* @brief Utility function to check the validity of user and kernel space parameters.
*        This function copies the contents from user space to kernel space.
*
* @param arg The parameters in user space
* @param kernel_addr The cryptocopy_params in kernel space
* @param infile Kmalloc buffer (getname) for user infile
* @param outfile Kmalloc buffer (getname) for user outfile
* @param keybuf Kmalloc buffer (getname) for user keybuf
* @return int
*/
int utility_check_params(void *arg, cryptocopy_params **kernel_addr, struct filename **infile, struct filename **outfile, struct filename **keybuf)
{
	if(access_ok(arg, sizeof(cryptocopy_params)) == 0)
	{
		printk("utility_check_params() - invalid userspace address - access_ok()\n");
		return -EFAULT;
	}
	*kernel_addr = kmalloc(sizeof(cryptocopy_params), GFP_KERNEL);

	if (*kernel_addr == NULL){
		printk("utility_check_params() - memory not allocated by kmalloc\n");
		return -ENOMEM;
	}

	if(copy_from_user(*kernel_addr, arg, sizeof(cryptocopy_params)) != 0)
	{
		printk("utility_check_params() - Error in copying the userspace address to kernel address - copy_from_user()\n");
		return -EFAULT;
	}
	if((*kernel_addr)->flags == 0)
	{
		printk("utility_check_params() - no operation is specified\n");
		return -EINVAL;
	}

	if((*kernel_addr)->flags != 1 && (*kernel_addr)->flags != 2 && (*kernel_addr)->flags != 4)
	{
		printk("utility_check_params() - invalid operation is given. must be either copy(-c),encrypt(-e),decrypt(-d)\n");
		return -EINVAL;
	}

	if ((*kernel_addr)->flags != 4 && (*kernel_addr)->keylen < 6) {
		printk("utility_check_params() - password should be greater than equal to 6, but given password length is %d\n", (*kernel_addr)->keylen);
		return -EINVAL;
	}

	if ((*kernel_addr)->flags != 4) {
		if ((*kernel_addr)->keybuf == NULL) {
			printk("utility_check_params() - password is NULL\n");
			return -EINVAL;
		}

		*keybuf = getname((*kernel_addr)->keybuf);
		if (keybuf == NULL) {
			printk("utility_check_params() - error in user space password\n");
			return -EINVAL;
		}
		(*kernel_addr)->keybuf = (char *)(*keybuf)->name;
	}

	if((*kernel_addr)->infile == NULL)
	{
		printk("utility_check_params() - infile is NULL\n");
		return -EINVAL;
	}

	*infile = getname((*kernel_addr)->infile);
	if (*infile == NULL) {
		printk("utility_check_params() - error in user space infile\n");
		return -EINVAL;
	}
	(*kernel_addr)->infile = (char *)(*infile)->name;

	if((*kernel_addr)->outfile == NULL){
		printk("utility_check_params() - outfile is NULL\n");
		return -EINVAL;
	}

	*outfile = getname((*kernel_addr)->outfile);
	if(outfile == NULL)
	{
		printk("utility_check_params() - error in user space outfile\n");
		return -EINVAL;
	}
	(*kernel_addr)->outfile = (char *)(*outfile)->name;
	if(strcmp((*kernel_addr)->infile, (*kernel_addr)->outfile) == 0)
	{
		printk("utility_check_params() - input and output files are same\n");
		return -EINVAL;
	}
	if((*kernel_addr)->flags == 4 && (*kernel_addr)->keylen > 0)
	{
		printk("utility_check_params() - copy operation does not require password\n");
		return -EINVAL;
	}
	return 0;
}
/**
* @brief Main function for cryptocopy system call.
*
* @param arg The parameters in user space
* @return long
*/
asmlinkage long cryptocopy(void *arg)
{
	int ret = 0;
	int operation = 0;
	cryptocopy_params *kernel_addr = NULL;
	struct filename *infile = NULL;
	struct filename *outfile = NULL;
	struct filename *keybuf = NULL;

	if(arg == NULL)
		return -EINVAL;

  ret = utility_check_params(arg,&kernel_addr,&infile,&outfile,&keybuf); // check for validity

	if(ret != 0)goto end;

	operation = kernel_addr->flags;
	switch (operation) {
		case COPY:
			ret = syscall_copy(kernel_addr, (cryptocopy_params *)arg);
			if(ret != 0){
				printk("syscall_copy() - Failed\n");
				ret = -EINVAL;
				goto end;
			}
		  break;
		case ENCRYPTION:
			ret = syscall_encryption(kernel_addr, (cryptocopy_params *)arg);
			if(ret != 0){
				printk("syscall_encryption() - Failed\n");
				ret = -EINVAL;
				goto end;
			}
			break;
		case DECRYPTION:
			ret = syscall_decryption(kernel_addr, (cryptocopy_params *)arg);
			if(ret != 0){
				printk("syscall_decryption() - Failed\n");
				ret = -EINVAL;
				goto end;
			}
			 break;
	}
end:
	if(outfile)
		putname(outfile);
	if(infile)
		putname(infile);
	if(keybuf)
	  putname(keybuf);
  if(kernel_addr)
	  kfree(kernel_addr);
	return ret;
}

static int __init init_sys_cryptocopy(void)
{
	printk("installed new sys_cryptocopy module\n");
	if (sysptr == NULL)
		sysptr = cryptocopy;
	return 0;
}
static void  __exit exit_sys_cryptocopy(void)
{
	if (sysptr != NULL)
		sysptr = NULL;
	printk("removed sys_cryptocopy module\n");
}
module_init(init_sys_cryptocopy);
module_exit(exit_sys_cryptocopy);
MODULE_LICENSE("GPL");
