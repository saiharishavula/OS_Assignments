// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 1998-2020 Erez Zadok
 * Copyright (c) 2009	   Shrikar Archak
 * Copyright (c) 2003-2020 Stony Brook University
 * Copyright (c) 2003-2020 The Research Foundation of SUNY
 */

#include "stbfs.h"

# include <linux/kernel.h>
# include <linux/fs.h>
# include <linux/uaccess.h>
# include <linux/err.h>
# include <linux/module.h>
# include <linux/stat.h>
# include <linux/namei.h>
# include <linux/ceph/decode.h>
# include <linux/slab.h>
# include <linux/scatterlist.h>
# include <linux/mm.h>
# include <generated/autoconf.h>
# include <asm/unistd.h>
# include <linux/rtc.h>
# include <linux/cred.h>
# include <linux/key-type.h>
# include <linux/hash.h>
# include <crypto/md5.h>
# include <crypto/aes.h>
# include <crypto/skcipher.h>
# include <crypto/hash.h>
# include <keys/ceph-type.h>
static int stbfs_create(struct inode *dir, struct dentry *dentry,
			 umode_t mode, bool want_excl)
{
	int err;
	struct dentry *lower_dentry;
	struct dentry *lower_parent_dentry = NULL;
	struct path lower_path;
	
	if (strcmp(dentry->d_parent->d_name.name,".stb") == 0){
		printk("Creating a file in .stb folder is restricted. (Only undelete operation is allowed in .stb folder)\n");
	    return -EPERM;
	}

	stbfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_parent_dentry = lock_parent(lower_dentry);

	err = vfs_create(d_inode(lower_parent_dentry), lower_dentry, mode,
			 want_excl);
	if (err)
		goto out;
	err = stbfs_interpose(dentry, dir->i_sb, &lower_path);
	if (err)
		goto out;
	fsstack_copy_attr_times(dir, stbfs_lower_inode(dir));
	fsstack_copy_inode_size(dir, d_inode(lower_parent_dentry));

out:
	unlock_dir(lower_parent_dentry);
	stbfs_put_lower_path(dentry, &lower_path);
	return err;
}

static int stbfs_link(struct dentry *old_dentry, struct inode *dir,
		       struct dentry *new_dentry)
{
	struct dentry *lower_old_dentry;
	struct dentry *lower_new_dentry;
	struct dentry *lower_dir_dentry;
	u64 file_size_save;
	int err;
	struct path lower_old_path, lower_new_path;

	file_size_save = i_size_read(d_inode(old_dentry));
	stbfs_get_lower_path(old_dentry, &lower_old_path);
	stbfs_get_lower_path(new_dentry, &lower_new_path);
	lower_old_dentry = lower_old_path.dentry;
	lower_new_dentry = lower_new_path.dentry;
	lower_dir_dentry = lock_parent(lower_new_dentry);

	err = vfs_link(lower_old_dentry, d_inode(lower_dir_dentry),
		       lower_new_dentry, NULL);
	if (err || d_really_is_negative(lower_new_dentry))
		goto out;

	err = stbfs_interpose(new_dentry, dir->i_sb, &lower_new_path);
	if (err)
		goto out;
	fsstack_copy_attr_times(dir, d_inode(lower_new_dentry));
	fsstack_copy_inode_size(dir, d_inode(lower_new_dentry));
	set_nlink(d_inode(old_dentry),
		  stbfs_lower_inode(d_inode(old_dentry))->i_nlink);
	i_size_write(d_inode(new_dentry), file_size_save);
out:
	unlock_dir(lower_dir_dentry);
	stbfs_put_lower_path(old_dentry, &lower_old_path);
	stbfs_put_lower_path(new_dentry, &lower_new_path);
	return err;
}

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
	int err = 0;
	inode_lock_nested(file->f_path.dentry->d_parent->d_inode, I_MUTEX_PARENT);
	err = vfs_unlink(file->f_path.dentry->d_parent->d_inode, file->f_path.dentry, NULL);
	inode_unlock(file->f_path.dentry->d_parent->d_inode);
	return err;
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
int utility_read(struct file *in_file, struct file *out_file, char *buf, size_t count, unsigned long long *pos)
{
	int bytes = vfs_read(in_file, buf, count, pos);
	if (bytes < 0) {
		printk("vfs_read() - Error in reading\n Cleared partially written file\n");
		return utility_unlink(out_file);
	}
	return bytes;
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
	int bytes = vfs_write(file, buf, count, pos);
	if (bytes < 0) {
		printk("vfs_write() - Error in writing\n Cleared partially written file\n");
		return utility_unlink(file);
	}
	return bytes;
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
int utility_syscall_init(cryptocopy_params *kernel_addr, struct file **infile_fp, struct file **outfile_fp, char **buffer, unsigned long long  *infile_offset)
{
	int ret = 0;
	mm_segment_t oldfs;

	oldfs = get_fs();
	set_fs(KERNEL_DS);
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
	*buffer = kmalloc(sizeof(char) * (PAGE_SIZE + 1), GFP_KERNEL);
	if(*buffer == NULL)
	{
		printk("utility_syscall_init() - memory not allocated by kmalloc - buffer\n");
		ret = -ENOMEM;
		goto end;
	}
	oldfs = get_fs();
	set_fs(KERNEL_DS); //since we do not need any translation
	*outfile_fp = filp_open(kernel_addr->outfile, O_CREAT |  O_WRONLY, 0644);
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
int syscall_copy(cryptocopy_params *kernel_addr)
{
	int ret = 0;
	struct file *infile_fp = NULL;
	struct file *outfile_fp = NULL;
	char *buffer = NULL;
	unsigned long long  infile_offset = 0;
	unsigned long long infile_offset_itr = 0;
	unsigned long long min_size = 0;
	unsigned long long output_offset = 0;
	unsigned long long infile_size = 0;
	mm_segment_t oldfs = get_fs();
	ret = utility_syscall_init(kernel_addr,&infile_fp,&outfile_fp,&buffer,&infile_offset); //initialize before the copy operation
	if(ret != 0)goto end;
	set_fs(KERNEL_DS); // as we do not need any translation
	infile_size = kernel_addr->infile_size;
	infile_offset_itr = infile_offset;
	while(infile_offset_itr < infile_size) // till we read all the bytes
	{
		min_size = PAGE_SIZE < (infile_size - infile_offset_itr) ? PAGE_SIZE : (infile_size - infile_offset_itr); // min(4096, remaining bytes)
		ret = utility_read(infile_fp, outfile_fp, buffer, min_size, &infile_offset_itr); // read min(4096, remaining bytes) from input file
		if(ret < 0) 
			goto end;
		buffer[min_size] = '\0'; // terminate with end character
		ret = utility_write(outfile_fp, buffer, min_size, &output_offset); // writing them to output file
		if(ret < 0) 
			goto end;
	}
end:
  	set_fs(oldfs);
	if(outfile_fp)
		filp_close(outfile_fp, NULL);
	if(buffer)
	  	kfree(buffer);
	if(infile_fp)
		filp_close(infile_fp, NULL);
	return ret;
}
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
	if (flag == 1)
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
	memcpy(ivdata, "$saiharishavula$",16);
	sk.tfm = skcipher;
	sk.req = req;

	sg_init_one(&sk.sg, scratchpad, scratchpad_len);
	skcipher_request_set_crypt(req, &sk.sg, &sk.sg, scratchpad_len, ivdata);
	crypto_init_wait(&sk.wait);
	ret = utility_skcipher_encdec(&sk, flag);
	if (ret)
		goto end;
end:
	kfree(ivdata);
	kfree(key);
	if (skcipher)
		crypto_free_skcipher(skcipher);
	if (req)
		skcipher_request_free(req);
	return ret;
}

static int stbfs_unlink(struct inode *dir, struct dentry *dentry)
{
	int err;
	struct dentry *lower_dentry;
	struct inode *lower_dir_inode = stbfs_lower_inode(dir);
	struct dentry *lower_dir_dentry;
	struct path lower_path;
	char *old_file=NULL;
	char *new_file=NULL;
	char *current_uid_str=NULL;
    mm_segment_t oldfs;
	char *buffer = NULL;
	char *old_file_abs_path = NULL;
	uid_t current_uid;
	int total_mem_blocks;
	int mem_block = 0;
	uid_t file_uid;
	u64 time_in_ns;
	char *enc_key_buffer = NULL;
	char *time_in_ns_str = NULL;
	char *old_file_path=NULL;
	char *page_buffer = NULL;
	struct file *file_pointer = NULL;
	struct inode *old_file_inode;
	struct file *old_file_fp = NULL;
	struct file *new_file_fp = NULL;
	int bytes_read;
	int bytes_write;
	cryptocopy_params *kernel_addr = NULL;
	
	/* get the current user id */
	current_uid = get_uid(current_user())->uid.val;
	/* get the lower path of current dentry */
	stbfs_get_lower_path(dentry, &lower_path);

	/* old file - current file to be deleted */
	/* new file - new file that is moved to .stb folder after unlink */

	/* Allocate memory for old file path */
	old_file_abs_path = kmalloc(MAX_PATH_LEN, GFP_KERNEL);
	if(old_file_abs_path == NULL){
		err = -ENOMEM;
		printk("Memory allocated error - old_file_abs_path\n");
		goto end;
	}
	/* Allocate memory for new file */
	new_file = kmalloc(MAX_PATH_LEN, GFP_KERNEL);
	if(new_file == NULL){
		err = -ENOMEM;
		printk("Memory allocated error - new_file\n");
		goto end;
	}

	/* get the original location of .stb folder by appending mount point path with .stb*/
	strcpy(new_file,STBFS_SB(dentry->d_sb)->root_path);
	/* append .stb */
	strcat(new_file,"/.stb/");
	strcpy(old_file_abs_path,new_file);
	strcat(old_file_abs_path,dentry->d_name.name);
	/* allocate memory for old file path */
	old_file_path = kmalloc(MAX_FILENAME_LEN, GFP_KERNEL);
	if (old_file_path == NULL){
		printk("Memory allocated error - old_file_path\n");
		err = -ENOMEM;
		goto end;
	}
	/* get the path of the old (current) file */
	/* here old_file is just a pointer, which points to allocated old_file_path */
	old_file = d_path(&lower_path, old_file_path, 256);
	if (IS_ERR(old_file)){
		err = PTR_ERR(old_file);
		goto end;
	}
	/* check if the current file is in .stb folder */
	if(strcmp(old_file,old_file_abs_path) == 0){
		/* permanently delete the file if file uid and current uid matches */
		/* allocate the memory to compute the user id from current file */
		buffer = kmalloc(5, GFP_KERNEL);
		if (buffer == NULL){
			err = -ENOMEM;
			printk("Memory allocated error - buffer\n");
			goto end;
		}
		/* The first 4 characters of file name stores the user id information */
		strncpy(buffer, dentry->d_name.name, 4);
		buffer[4] = '\0';
		err = kstrtoint(buffer,0,&file_uid);
		if(err != 0){
			printk("Error occured in kstrtoint - %d\n", err);
			goto end;
		}
		/* check if the current user id and file user id matches or not */
		if(file_uid == current_uid){
			/* Permanently delete the file */
			goto unlink;
		}else{
			/* User is not allowed to delete the file*/
			err = -EACCES;
			printk("Current User is not allowed to delete the file\n");
			d_drop(dentry);
			goto end;
		}
	}else{
		/* move the file to trash bin folder (.stb) */
		/* compute timestamp in nanoseconds append it to new file name */
		time_in_ns = ktime_get_real_ns();
		time_in_ns_str = kmalloc(22,GFP_KERNEL);
		if(time_in_ns_str == NULL){
			err = -ENOMEM;
			printk("Memory allocated error - time_in_ns_str\n");
			goto end;
		}
		sprintf(time_in_ns_str, "%020llu", time_in_ns);
		/* compute userid to append it to new file name */
		current_uid_str = kmalloc(40,GFP_KERNEL);
		if(current_uid_str == NULL){
			err = -ENOMEM;
			printk("Memory allocated error - current_uid_str\n");
			goto end;
		}
		/* compute user id */
		snprintf(current_uid_str, 5, "%04d",(int)current_uid);
		/* append a delimiter */
		strcat(current_uid_str,"-");
		/* append time stamp */
		strcat(current_uid_str,time_in_ns_str);
		/* append a delimiter */
		strcat(current_uid_str,"-");
		/* append it current new name (ex. usr/src/hw2-savula/CSE-506/.stb/XXXX-XXXXXXXXXXXXXX-) */
		strcat(new_file,current_uid_str);
		/* finally append current file name to the new file name */
		strcat(new_file,dentry->d_name.name);

		/* allocate memory for the struct cryptocopy_params to be used in copy functionality*/
		kernel_addr = kmalloc(sizeof(cryptocopy_params), GFP_KERNEL);
		if (kernel_addr == NULL){
			printk("Memory not allocated - kernel_addr\n");
			return -ENOMEM;
		}

		/* check if the encryption key is given or not */
		if(strlen(STBFS_SB(dentry->d_sb)->key) == 0){
			/* Mounted without encryption key */
			kernel_addr->infile = old_file;
			kernel_addr->outfile = new_file;

			/* get the file descriptor to compute the total size of the current file */
			file_pointer = filp_open(old_file, O_RDONLY, 0);
			if (file_pointer == NULL || IS_ERR(file_pointer)) {
				printk("filp_open() - error while opening the old_file\n");
				err = PTR_ERR(file_pointer);
				file_pointer = NULL;
				goto end;
			}
			/* compute the total size of the current file */
			old_file_inode = file_pointer->f_path.dentry->d_inode;
			kernel_addr->infile_size = i_size_read(old_file_inode);
			/* copy the current file and move it to trash bin (.stb folder) */
			syscall_copy(kernel_addr);
			/* delete the current file */
			goto unlink;
		}else{
			/* Mounted with encryption key */
			/* allocate the memory to store the encryption key */
			enc_key_buffer = kmalloc(MAX_ENCKEY_LEN,GFP_KERNEL);
			if(enc_key_buffer == NULL){
				err = -ENOMEM;
				printk("Memory allocated error - enc_key_buffer\n");
				goto end;
			}
			/* retrieve the encryption key from the super block's private field*/
			strcpy(enc_key_buffer,STBFS_SB(dentry->d_sb)->key);
			kernel_addr->keybuf = enc_key_buffer;
			kernel_addr->keylen = strlen(STBFS_SB(dentry->d_sb)->key);
			kernel_addr->keybuf[kernel_addr->keylen] = '\0';
			/* the encrypted file with extention .enc */
			strcat(new_file, ".enc");

			/* get the file descriptor of old file with read mode */
			old_file_fp = filp_open(old_file, O_RDONLY, 0);
			if (old_file_fp == NULL || IS_ERR(old_file_fp)) {
				printk("filp_open() - error while opening the old_file\n");
				err = PTR_ERR(old_file_fp);
				old_file_fp = NULL;
				goto end;
			}
			/* set the old file pointer offset */
			old_file_fp->f_pos = 0; 

			/* get the file descriptor of old file with write mode */
			new_file_fp = filp_open(new_file, O_WRONLY | O_CREAT, dir->i_mode);
			if (new_file_fp == NULL || IS_ERR(new_file_fp)) {
				printk("filp_open() - error while opening the new_file\n");
				err = PTR_ERR(new_file_fp);
				new_file_fp = NULL;
				goto end;
			}
			/* set the new file pointer offset */
			new_file_fp->f_pos = 0; 
			
			/* allocate the memory for page buffer(4096 bytes) to encrypt block by block*/
			page_buffer = kmalloc(PAGE_SIZE + 1,GFP_KERNEL);
			if (page_buffer == NULL) {
				err = -ENOMEM;
				printk("Memory error - page_buffer\n");
				goto end;
			}

			/*calculate the total number of blocks*/
			total_mem_blocks = (int)(i_size_read(old_file_fp->f_path.dentry->d_inode) / PAGE_SIZE);
			oldfs = get_fs();
			set_fs(KERNEL_DS);
			/* encrypt the data block by block */
			while (mem_block <= total_mem_blocks){
				/*read bytes from old file*/
				bytes_read = utility_read(old_file_fp, new_file_fp, page_buffer, PAGE_SIZE, &old_file_fp->f_pos);
				if(bytes_read<0){
					printk("Bytes read are negative - vfs_read()\n");
					goto unlink_partial_failure;
				}
				if(bytes_read == 0){
					/* done with all the bytes */
					break;
				}
				/*encryption*/
				err = utility_skcipher(page_buffer, bytes_read, kernel_addr->keybuf, kernel_addr->keylen, 0, NULL, 1);
				/*if encryption fails, handle the partial failure */
				if (err != 0) {
					printk("ERROR: Encryption Failed.\n");
					goto unlink_partial_failure;
				}
				page_buffer[bytes_read] = '\0';
				/*Write bytes to new file*/
				bytes_write = utility_write(new_file_fp, page_buffer, bytes_read, &new_file_fp->f_pos);
				/*if write fails, handle the partial failure */
				if(bytes_write != bytes_read){
					err = -EIO;
					goto unlink_partial_failure;
				}
				mem_block++;
			}
			set_fs(oldfs);
			/* delete the current file */
			goto unlink;
		}
		
	}
unlink:
	lower_dentry = lower_path.dentry;
	dget(lower_dentry);
	lower_dir_dentry = lock_parent(lower_dentry);
	if (lower_dentry->d_parent != lower_dir_dentry ||d_unhashed(lower_dentry)) {
		err = -EINVAL;
		goto unlink_end;
	}
	err = vfs_unlink(lower_dir_inode, lower_dentry, NULL);

	/*
	 * Note: unlinking on top of NFS can cause silly-renamed files.
	 * Trying to delete such files results in EBUSY from NFS
	 * below.  Silly-renamed files will get deleted by NFS later on, so
	 * we just need to detect them here and treat such EBUSY errors as
	 * if the upper file was successfully deleted.
	 */

	if (err == -EBUSY && lower_dentry->d_flags & DCACHE_NFSFS_RENAMED){
		err = 0;
	}
	if (err){
		goto unlink_end;
	}
	fsstack_copy_attr_times(dir, lower_dir_inode);
	fsstack_copy_inode_size(dir, lower_dir_inode);
	set_nlink(d_inode(dentry), stbfs_lower_inode(d_inode(dentry))->i_nlink);
	d_inode(dentry)->i_ctime = dir->i_ctime;
	d_drop(dentry); /* this is needed, else LTP fails (VFS won't do it) */
unlink_end:
	unlock_dir(lower_dir_dentry);
	dput(lower_dentry);
	stbfs_put_lower_path(dentry, &lower_path);
end:
	if(old_file_abs_path)
		kfree(old_file_abs_path);
	if(old_file_path)
		kfree(old_file_path);
	if(new_file)
		kfree(new_file);
	if(buffer)
		kfree(buffer);
	if(enc_key_buffer)
		kfree(enc_key_buffer);
	if(time_in_ns_str)
		kfree(time_in_ns_str);
	if(current_uid_str)
		kfree(current_uid_str);
	if(file_pointer)
		filp_close(file_pointer, NULL);
	if(page_buffer)
		kfree(page_buffer);
	if(new_file_fp)
		filp_close(new_file_fp, NULL);
	if(old_file_fp)
		filp_close(old_file_fp, NULL);
	return err;
unlink_partial_failure:
	set_fs(oldfs);
	err = utility_unlink(new_file_fp);
	d_drop(dentry);
	goto end;
}

static int stbfs_symlink(struct inode *dir, struct dentry *dentry,
			  const char *symname)
{
	int err;
	struct dentry *lower_dentry;
	struct dentry *lower_parent_dentry = NULL;
	struct path lower_path;

	stbfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_parent_dentry = lock_parent(lower_dentry);

	err = vfs_symlink(d_inode(lower_parent_dentry), lower_dentry, symname);
	if (err)
		goto out;
	err = stbfs_interpose(dentry, dir->i_sb, &lower_path);
	if (err)
		goto out;
	fsstack_copy_attr_times(dir, stbfs_lower_inode(dir));
	fsstack_copy_inode_size(dir, d_inode(lower_parent_dentry));

out:
	unlock_dir(lower_parent_dentry);
	stbfs_put_lower_path(dentry, &lower_path);
	return err;
}

static int stbfs_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	int err;
	struct dentry *lower_dentry;
	struct dentry *lower_parent_dentry = NULL;
	struct path lower_path;

	if (strcmp(dentry->d_parent->d_name.name,".stb") == 0){
		printk("creating a directory in .stb folder is restricted. (Only undelete operation is allowed in .stb folder)\n");
	    return -EPERM;
	}

	stbfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_parent_dentry = lock_parent(lower_dentry);

	err = vfs_mkdir(d_inode(lower_parent_dentry), lower_dentry, mode);
	if (err)
		goto out;

	err = stbfs_interpose(dentry, dir->i_sb, &lower_path);
	if (err)
		goto out;

	fsstack_copy_attr_times(dir, stbfs_lower_inode(dir));
	fsstack_copy_inode_size(dir, d_inode(lower_parent_dentry));
	/* update number of links on parent directory */
	set_nlink(dir, stbfs_lower_inode(dir)->i_nlink);

out:
	unlock_dir(lower_parent_dentry);
	stbfs_put_lower_path(dentry, &lower_path);
	return err;
}

static int stbfs_rmdir(struct inode *dir, struct dentry *dentry)
{
	struct dentry *lower_dentry;
	struct dentry *lower_dir_dentry;
	int err;
	struct path lower_path;

	if (strcmp(dentry->d_parent->d_name.name,".stb") == 0){
		printk("Removing a directory in .stb folder is restricted. (Only undelete operation for a file is allowed in .stb folder)\n");
	    return -EPERM;
	}

	stbfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_dir_dentry = lock_parent(lower_dentry);
	if (lower_dentry->d_parent != lower_dir_dentry ||
	    d_unhashed(lower_dentry)) {
		err = -EINVAL;
		goto out;
	}

	err = vfs_rmdir(d_inode(lower_dir_dentry), lower_dentry);
	if (err)
		goto out;

	d_drop(dentry);	/* drop our dentry on success (why not VFS's job?) */
	if (d_inode(dentry))
		clear_nlink(d_inode(dentry));
	fsstack_copy_attr_times(dir, d_inode(lower_dir_dentry));
	fsstack_copy_inode_size(dir, d_inode(lower_dir_dentry));
	set_nlink(dir, d_inode(lower_dir_dentry)->i_nlink);

out:
	unlock_dir(lower_dir_dentry);
	stbfs_put_lower_path(dentry, &lower_path);
	return err;
}

static int stbfs_mknod(struct inode *dir, struct dentry *dentry, umode_t mode,
			dev_t dev)
{
	int err;
	struct dentry *lower_dentry;
	struct dentry *lower_parent_dentry = NULL;
	struct path lower_path;

	stbfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_parent_dentry = lock_parent(lower_dentry);

	err = vfs_mknod(d_inode(lower_parent_dentry), lower_dentry, mode, dev);
	if (err)
		goto out;

	err = stbfs_interpose(dentry, dir->i_sb, &lower_path);
	if (err)
		goto out;
	fsstack_copy_attr_times(dir, stbfs_lower_inode(dir));
	fsstack_copy_inode_size(dir, d_inode(lower_parent_dentry));

out:
	unlock_dir(lower_parent_dentry);
	stbfs_put_lower_path(dentry, &lower_path);
	return err;
}

/*
 * The locking rules in stbfs_rename are complex.  We could use a simpler
 * superblock-level name-space lock for renames and copy-ups.
 */
static int stbfs_rename(struct inode *old_dir, struct dentry *old_dentry,
			 struct inode *new_dir, struct dentry *new_dentry,
			 unsigned int flags)
{
	int err = 0;
	struct dentry *lower_old_dentry = NULL;
	struct dentry *lower_new_dentry = NULL;
	struct dentry *lower_old_dir_dentry = NULL;
	struct dentry *lower_new_dir_dentry = NULL;
	struct dentry *trap = NULL;
	struct path lower_old_path, lower_new_path;

	if (flags)
		return -EINVAL;
    if(strcmp(old_dentry->d_parent->d_name.name, ".stb") == 0){
		printk("Rename not possible in .stb folder\n");
		return -EPERM;
	}
	printk("Rename not in .stb folder\n");
	stbfs_get_lower_path(old_dentry, &lower_old_path);
	stbfs_get_lower_path(new_dentry, &lower_new_path);
	lower_old_dentry = lower_old_path.dentry;
	lower_new_dentry = lower_new_path.dentry;
	lower_old_dir_dentry = dget_parent(lower_old_dentry);
	lower_new_dir_dentry = dget_parent(lower_new_dentry);


	trap = lock_rename(lower_old_dir_dentry, lower_new_dir_dentry);
	err = -EINVAL;
	/* check for unexpected namespace changes */
	if (lower_old_dentry->d_parent != lower_old_dir_dentry)
		goto out;
	if (lower_new_dentry->d_parent != lower_new_dir_dentry)
		goto out;
	/* check if either dentry got unlinked */
	if (d_unhashed(lower_old_dentry) || d_unhashed(lower_new_dentry))
		goto out;
	/* source should not be ancestor of target */
	if (trap == lower_old_dentry)
		goto out;
	/* target should not be ancestor of source */
	if (trap == lower_new_dentry) {
		err = -ENOTEMPTY;
		goto out;
	}

	err = vfs_rename(d_inode(lower_old_dir_dentry), lower_old_dentry,
			 d_inode(lower_new_dir_dentry), lower_new_dentry,
			 NULL, 0);
	if (err)
		goto out;

	fsstack_copy_attr_all(new_dir, d_inode(lower_new_dir_dentry));
	fsstack_copy_inode_size(new_dir, d_inode(lower_new_dir_dentry));
	if (new_dir != old_dir) {
		fsstack_copy_attr_all(old_dir,
				      d_inode(lower_old_dir_dentry));
		fsstack_copy_inode_size(old_dir,
					d_inode(lower_old_dir_dentry));
	}

out:
	unlock_rename(lower_old_dir_dentry, lower_new_dir_dentry);
	dput(lower_old_dir_dentry);
	dput(lower_new_dir_dentry);
	stbfs_put_lower_path(old_dentry, &lower_old_path);
	stbfs_put_lower_path(new_dentry, &lower_new_path);
	return err;
}

static const char *stbfs_get_link(struct dentry *dentry, struct inode *inode,
				   struct delayed_call *done)
{
	DEFINE_DELAYED_CALL(lower_done);
	struct dentry *lower_dentry;
	struct path lower_path;
	char *buf;
	const char *lower_link;

	if (!dentry)
		return ERR_PTR(-ECHILD);

	stbfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;

	/*
	 * get link from lower file system, but use a separate
	 * delayed_call callback.
	 */
	lower_link = vfs_get_link(lower_dentry, &lower_done);
	if (IS_ERR(lower_link)) {
		buf = ERR_CAST(lower_link);
		goto out;
	}

	/*
	 * we can't pass lower link up: have to make private copy and
	 * pass that.
	 */
	buf = kstrdup(lower_link, GFP_KERNEL);
	do_delayed_call(&lower_done);
	if (!buf) {
		buf = ERR_PTR(-ENOMEM);
		goto out;
	}

	fsstack_copy_attr_atime(d_inode(dentry), d_inode(lower_dentry));

	set_delayed_call(done, kfree_link, buf);
out:
	stbfs_put_lower_path(dentry, &lower_path);
	return buf;
}

static int stbfs_permission(struct inode *inode, int mask)
{
	struct inode *lower_inode;
	int err;

	lower_inode = stbfs_lower_inode(inode);
	err = inode_permission(lower_inode, mask);
	return err;
}

static int stbfs_setattr(struct dentry *dentry, struct iattr *ia)
{
	int err;
	struct dentry *lower_dentry;
	struct inode *inode;
	struct inode *lower_inode;
	struct path lower_path;
	struct iattr lower_ia;

	inode = d_inode(dentry);

	/*
	 * Check if user has permission to change inode.  We don't check if
	 * this user can change the lower inode: that should happen when
	 * calling notify_change on the lower inode.
	 */
	if(strcmp(dentry->d_parent->d_name.name, ".stb") == 0){
		printk("setattr not allowed in .stb folder\n");
		err = -EPERM;
		goto out_err;
	}
	err = setattr_prepare(dentry, ia);
	if (err)
		goto out_err;

	stbfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_inode = stbfs_lower_inode(inode);

	/* prepare our own lower struct iattr (with the lower file) */
	memcpy(&lower_ia, ia, sizeof(lower_ia));
	if (ia->ia_valid & ATTR_FILE)
		lower_ia.ia_file = stbfs_lower_file(ia->ia_file);

	/*
	 * If shrinking, first truncate upper level to cancel writing dirty
	 * pages beyond the new eof; and also if its' maxbytes is more
	 * limiting (fail with -EFBIG before making any change to the lower
	 * level).  There is no need to vmtruncate the upper level
	 * afterwards in the other cases: we fsstack_copy_inode_size from
	 * the lower level.
	 */
	if (ia->ia_valid & ATTR_SIZE) {
		err = inode_newsize_ok(inode, ia->ia_size);
		if (err)
			goto out;
		truncate_setsize(inode, ia->ia_size);
	}

	/*
	 * mode change is for clearing setuid/setgid bits. Allow lower fs
	 * to interpret this in its own way.
	 */
	if (lower_ia.ia_valid & (ATTR_KILL_SUID | ATTR_KILL_SGID))
		lower_ia.ia_valid &= ~ATTR_MODE;

	/* notify the (possibly copied-up) lower inode */
	/*
	 * Note: we use d_inode(lower_dentry), because lower_inode may be
	 * unlinked (no inode->i_sb and i_ino==0.  This happens if someone
	 * tries to open(), unlink(), then ftruncate() a file.
	 */
	inode_lock(d_inode(lower_dentry));
	err = notify_change(lower_dentry, &lower_ia, /* note: lower_ia */
			    NULL);
	inode_unlock(d_inode(lower_dentry));
	if (err)
		goto out;

	/* get attributes from the lower inode */
	fsstack_copy_attr_all(inode, lower_inode);
	/*
	 * Not running fsstack_copy_inode_size(inode, lower_inode), because
	 * VFS should update our inode size, and notify_change on
	 * lower_inode should update its size.
	 */

out:
	stbfs_put_lower_path(dentry, &lower_path);
out_err:
	return err;
}

static int stbfs_getattr(const struct path *path, struct kstat *stat,
                          u32 request_mask, unsigned int flags)
{
	int err;
        struct dentry *dentry = path->dentry;
	struct kstat lower_stat;
	struct path lower_path;

	stbfs_get_lower_path(dentry, &lower_path);
	err = vfs_getattr(&lower_path, &lower_stat, request_mask, flags);
	if (err)
		goto out;
	fsstack_copy_attr_all(d_inode(dentry),
			      d_inode(lower_path.dentry));
	generic_fillattr(d_inode(dentry), stat);
	stat->blocks = lower_stat.blocks;
out:
	stbfs_put_lower_path(dentry, &lower_path);
	return err;
}

static int
stbfs_setxattr(struct dentry *dentry, struct inode *inode, const char *name,
		const void *value, size_t size, int flags)
{
	int err; struct dentry *lower_dentry;
	struct path lower_path;

	stbfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	if (!(d_inode(lower_dentry)->i_opflags & IOP_XATTR)) {
		err = -EOPNOTSUPP;
		goto out;
	}
	err = vfs_setxattr(lower_dentry, name, value, size, flags);
	if (err)
		goto out;
	fsstack_copy_attr_all(d_inode(dentry),
			      d_inode(lower_path.dentry));
out:
	stbfs_put_lower_path(dentry, &lower_path);
	return err;
}

static ssize_t
stbfs_getxattr(struct dentry *dentry, struct inode *inode,
		const char *name, void *buffer, size_t size)
{
	int err;
	struct dentry *lower_dentry;
	struct inode *lower_inode;
	struct path lower_path;

	stbfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_inode = stbfs_lower_inode(inode);
	if (!(d_inode(lower_dentry)->i_opflags & IOP_XATTR)) {
		err = -EOPNOTSUPP;
		goto out;
	}
	err = vfs_getxattr(lower_dentry, name, buffer, size);
	if (err)
		goto out;
	fsstack_copy_attr_atime(d_inode(dentry),
				d_inode(lower_path.dentry));
out:
	stbfs_put_lower_path(dentry, &lower_path);
	return err;
}

static ssize_t
stbfs_listxattr(struct dentry *dentry, char *buffer, size_t buffer_size)
{
	int err;
	struct dentry *lower_dentry;
	struct path lower_path;

	stbfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	if (!(d_inode(lower_dentry)->i_opflags & IOP_XATTR)) {
		err = -EOPNOTSUPP;
		goto out;
	}
	err = vfs_listxattr(lower_dentry, buffer, buffer_size);
	if (err)
		goto out;
	fsstack_copy_attr_atime(d_inode(dentry),
				d_inode(lower_path.dentry));
out:
	stbfs_put_lower_path(dentry, &lower_path);
	return err;
}

static int
stbfs_removexattr(struct dentry *dentry, struct inode *inode, const char *name)
{
	int err;
	struct dentry *lower_dentry;
	struct inode *lower_inode;
	struct path lower_path;

	stbfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_inode = stbfs_lower_inode(inode);
	if (!(lower_inode->i_opflags & IOP_XATTR)) {
		err = -EOPNOTSUPP;
		goto out;
	}
	err = vfs_removexattr(lower_dentry, name);
	if (err)
		goto out;
	fsstack_copy_attr_all(d_inode(dentry), lower_inode);
out:
	stbfs_put_lower_path(dentry, &lower_path);
	return err;
}

const struct inode_operations stbfs_symlink_iops = {
	.permission	= stbfs_permission,
	.setattr	= stbfs_setattr,
	.getattr	= stbfs_getattr,
	.get_link	= stbfs_get_link,
	.listxattr	= stbfs_listxattr,
};

const struct inode_operations stbfs_dir_iops = {
	.create		= stbfs_create,
	.lookup		= stbfs_lookup,
	.link		= stbfs_link,
	.unlink		= stbfs_unlink,
	.symlink	= stbfs_symlink,
	.mkdir		= stbfs_mkdir,
	.rmdir		= stbfs_rmdir,
	.mknod		= stbfs_mknod,
	.rename		= stbfs_rename,
	.permission	= stbfs_permission,
	.setattr	= stbfs_setattr,
	.getattr	= stbfs_getattr,
	.listxattr	= stbfs_listxattr,
};

const struct inode_operations stbfs_main_iops = {
	.permission	= stbfs_permission,
	.setattr	= stbfs_setattr,
	.getattr	= stbfs_getattr,
	.listxattr	= stbfs_listxattr,
};

static int stbfs_xattr_get(const struct xattr_handler *handler,
			    struct dentry *dentry, struct inode *inode,
			    const char *name, void *buffer, size_t size)
{
	return stbfs_getxattr(dentry, inode, name, buffer, size);
}

static int stbfs_xattr_set(const struct xattr_handler *handler,
			    struct dentry *dentry, struct inode *inode,
			    const char *name, const void *value, size_t size,
			    int flags)
{
	if (value)
		return stbfs_setxattr(dentry, inode, name, value, size, flags);

	BUG_ON(flags != XATTR_REPLACE);
	return stbfs_removexattr(dentry, inode, name);
}

const struct xattr_handler stbfs_xattr_handler = {
	.prefix = "",		/* match anything */
	.get = stbfs_xattr_get,
	.set = stbfs_xattr_set,
};

const struct xattr_handler *stbfs_xattr_handlers[] = {
	&stbfs_xattr_handler,
	NULL
};
