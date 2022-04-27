// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 1998-2020 Erez Zadok
 * Copyright (c) 2009	   Shrikar Archak
 * Copyright (c) 2003-2020 Stony Brook University
 * Copyright (c) 2003-2020 The Research Foundation of SUNY
 */

#include "stbfs.h"
# include <linux/module.h>
# include <linux/kernel.h>
# include <linux/slab.h>
# include <linux/fs.h>
# include <linux/uaccess.h>
# include <generated/autoconf.h>
# include <asm/unistd.h>
# include <linux/err.h>
# include <linux/scatterlist.h>
# include <linux/stat.h>
# include <linux/namei.h>
# include <linux/hash.h>
# include <linux/slab.h>
# include <linux/mm.h>
# include <linux/key-type.h>
# include <linux/ceph/decode.h>
# include <crypto/md5.h>
# include <crypto/aes.h>
# include <linux/scatterlist.h>
# include <keys/ceph-type.h>
#include <crypto/skcipher.h>
#define MD5_KEY_LEN 16
#define READ_ONLY _IOR(0, 1 , int32_t *)

static ssize_t stbfs_read(struct file *file, char __user *buf,
			   size_t count, loff_t *ppos)
{
	int err;
	struct file *lower_file;
	struct dentry *dentry = file->f_path.dentry;

	lower_file = stbfs_lower_file(file);
	err = vfs_read(lower_file, buf, count, ppos);
	/* update our inode atime upon a successful lower read */
	if (err >= 0)
		fsstack_copy_attr_atime(d_inode(dentry),
					file_inode(lower_file));

	return err;
}

static ssize_t stbfs_write(struct file *file, const char __user *buf,
			    size_t count, loff_t *ppos)
{
	int err;

	struct file *lower_file;
	struct dentry *dentry = file->f_path.dentry;

	lower_file = stbfs_lower_file(file);
	err = vfs_write(lower_file, buf, count, ppos);
	/* update our inode times+sizes upon a successful lower write */
	if (err >= 0) {
		fsstack_copy_inode_size(d_inode(dentry),
					file_inode(lower_file));
		fsstack_copy_attr_times(d_inode(dentry),
					file_inode(lower_file));
	}

	return err;
}

struct dir_context *old_ctx;
static int list_dir(struct dir_context *ctx, const char *name, int namlen,loff_t offset, u64 ino, unsigned int d_type){
	
	uid_t file_uid;
	char *buffer = NULL;
	uid_t current_uid;
	int ret = 0;
	
	/* get the current user id */
	current_uid = get_uid(current_user())->uid.val;

	/* filenames '.' and '..' are visible to everyone irrespective of user id match.*/
	if((current_uid == 0) || (strcmp(name,".") == 0) || (strcmp(name,"..") == 0)){
		return old_ctx->actor(old_ctx, name, namlen, offset, ino, d_type);
	}
	/* extract the user id from the file name to match it with current user id*/
	buffer = kmalloc(5,GFP_KERNEL);
	if(buffer == NULL){
		ret = -ENOMEM;
		goto end;
	}
	strncpy(buffer, name, 4);
	buffer[4] = '\0';
	ret = kstrtoint(buffer,0,&file_uid);
	if(ret != 0){
		/* this says the file naming is different. so it does not belong to current user */
		ret = 0;
		goto end;
	}
	/* list only the files owned by the user */
	if(current_uid == file_uid){
		ret = old_ctx->actor(old_ctx, name, namlen, offset, ino, d_type);
		goto end;
	}
	else{
		goto end;
	}
end:
	if(buffer)
		kfree(buffer);
	return ret;
}

static int stbfs_readdir(struct file *file, struct dir_context *ctx)
{
	int err;
	struct file *lower_file = NULL;
	struct dentry *dentry = file->f_path.dentry;
	/* create the custom context for .stb folder */
	struct dir_context new_ctx  = {.actor = &list_dir, .pos = ctx->pos};
	old_ctx = ctx;
	lower_file = stbfs_lower_file(file);
	if(strcmp(file->f_path.dentry->d_name.name,".stb") == 0){
		/*listing the files in .stb folder */
		err = iterate_dir(lower_file, &new_ctx);
	}else{
		/*listing the files NOT in .stb folder */
		err = iterate_dir(lower_file, ctx);
	}
	file->f_pos = lower_file->f_pos;
	if (err >= 0)		/* copy the atime */
		fsstack_copy_attr_atime(d_inode(dentry),
					file_inode(lower_file));
	return err;
}
/**
* @brief undelete operation using ioctl
*
* @param file The file to be undeleted
* @return long
*/
long stbfs_undelete(struct file *file)
{
	long err = -ENOTTY;
	struct inode *dir;
	struct dentry *dentry;
	struct file *lower_file;
	struct dentry *lower_dentry=NULL;
	struct dentry *lower_dir_dentry=NULL;
	struct inode *lower_dir_inode = NULL;
	struct path lower_path;
	mm_segment_t  oldfs;
	char *old_file = NULL;
	char *new_file = NULL;
	char *old_file_path = NULL;
	char *new_file_with_ext = NULL;
	struct file *new_file_fp = NULL;
	struct file *old_file_fp = NULL;
	int bytes_read;
	int total_mem_blocks;
	char *enc_key_buffer = NULL;
	int mem_block = 0;
	int bytes_write;
	char *page_buffer = NULL;
	char *old_file_abs_path = NULL;
	uid_t current_uid;
	struct inode *old_file_inode;
	uid_t file_uid;
	cryptocopy_params *kernel_addr = NULL;
	char *buffer = NULL;
	struct file *file_pointer = NULL;
	

	lower_file = stbfs_lower_file(file);

	/*get the current user id*/
	current_uid = get_uid(current_user())->uid.val;

	/* allocate the memory to store the file user id */
	buffer = kmalloc(5,GFP_KERNEL);
	if (buffer == NULL){
		err = -ENOMEM;
		printk("Memory allocated error - buffer\n");
		goto end;
	}
	/*The first 4 characters of a file name contains user id info*/
	strncpy(buffer, lower_file->f_path.dentry->d_name.name, 4);
	buffer[4] = '\0';
	/* str to int conversion */
	err = kstrtoint(buffer,0,&file_uid);
	if(err != 0){
		printk("Error occured in kstrtoint - %ld\n", err);
		goto end;
	}
	/* check whether current user can undelete the file */
	if(current_uid != file_uid){
		err = -EACCES;
		printk("Current user is not the owner of the file. So, cannot undelete\n");
		goto end;
	}
	
	/* get the lower path of current dentry */
	dir = file->f_path.dentry->d_inode;
	dentry = file->f_path.dentry;
	lower_dir_inode = lower_file->f_path.dentry->d_parent->d_inode;
	stbfs_get_lower_path(dentry, &lower_path);
	
	/* old file - current file to be deleted */
	/* new file - new file that is moved to .stb folder after unlink */
	
	/* Allocate memory for old file path */
	old_file_path = kmalloc(MAX_PATH_LEN, GFP_KERNEL);
	if (old_file_path == NULL){
		err = -ENOMEM;
		printk("Memory alloc error - old_file_path\n");
		goto end;
	}
	/* get the path of the old (current) file */
	/* here old_file is just a pointer, which points to allocated old_file_path */
	old_file = d_path(&lower_file->f_path, old_file_path, MAX_PATH_LEN);
	if (IS_ERR(old_file)){
		err = PTR_ERR(old_file);
		goto end;
	}
	/* Allocate memory for old file path */
	old_file_abs_path = kmalloc(MAX_PATH_LEN, GFP_KERNEL);
	if(old_file_abs_path == NULL){
		err = -ENOMEM;
		printk("Memory alloc error - old_file_abs_path\n");
		goto end;
	}

	/* check if the current file is in .stb folder */
	strcpy(old_file_abs_path,STBFS_SB(dentry->d_sb)->root_path);
	strcat(old_file_abs_path,"/.stb/");
	strcat(old_file_abs_path,lower_file->f_path.dentry->d_name.name);

	/* return if to be  undeleted file is not in .stb folder */
	if(strcmp(old_file,old_file_abs_path)){
		printk("To be undeleted file is NOT in .stb folder\n");
		err = -EINVAL;
		goto end;
	}

	/*The Nomenclature of the file name is 4 chars (uid) - 20 chars (time stamp) - file name*/
	/* so skip 26 chars to retrive the original name of the file */
	new_file_with_ext = kmalloc(MAX_FILENAME_LEN,GFP_KERNEL);
	if(new_file_with_ext == NULL){
		err = -ENOMEM;
		printk("Memory alloc error - new_file_with_ext\n");
		goto end;
	}
	/* skip 26 chars following the nomenclature of the file name */
	strcat(new_file_with_ext,lower_file->f_path.dentry->d_name.name+26);
	
	/* allocate memory for the struct cryptocopy_params to be used in copy functionality*/
	kernel_addr = kmalloc(sizeof(cryptocopy_params), GFP_KERNEL);
	if (kernel_addr == NULL){
		printk("Memory not allocated - kernel_addr\n");
		err = -ENOMEM;
		goto end;
	}

	/*If extension is not '.enc' then we have to just rename the file*/
	if(strcmp(old_file + (strlen(old_file)-4), ".enc")){
		/* just rename the current file and store it in user CWD*/
		/* assign values to the struct for copying */
		kernel_addr->infile = old_file;
		kernel_addr->outfile = new_file_with_ext;
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
		/* copy the current file and move it to user CWD */
		syscall_copy(kernel_addr);
		/* delete the current file */
		goto unlink;

	}else{
		/* return if mounted without encryption key*/
		if(strlen(STBFS_SB(dentry->d_sb)->key) == 0){
			printk("Encryption Key is NOT provided during the mount\n");
			err = -EINVAL;
			goto end;
		}
		/* allocate the memory to store the encryption key */
		enc_key_buffer = kmalloc(MAX_ENCKEY_LEN,GFP_KERNEL);
		if(enc_key_buffer == NULL){
			err = -ENOMEM;
			printk("Memory allocated error - enc_key_buffer\n");
			goto end;
		}
		/* retrieve the encryption key from the super block's private field*/
		strcpy(enc_key_buffer,STBFS_SB(dentry->d_sb)->key);
		/* allocate the memory for the new file */
		new_file = kmalloc(MAX_FILENAME_LEN,GFP_KERNEL);
		if(new_file == NULL){
			err = -ENOMEM;
			printk("Memory alloc error - new_file\n");
			goto end;
		}
		/* the new name should not have file extention */
		snprintf(new_file, strlen(new_file_with_ext)-3, "%s", new_file_with_ext);

		/* assign values to the struct for decryption */
		kernel_addr->keybuf = enc_key_buffer;
		kernel_addr->keylen = strlen(STBFS_SB(dentry->d_sb)->key);
		kernel_addr->keybuf[kernel_addr->keylen] = '\0';
		
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

		/*Open the new file with new name in write mode*/
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
				/* all bytes are read */
				break;
			}
			/*decryption*/
			err = utility_skcipher(page_buffer, bytes_read, kernel_addr->keybuf, kernel_addr->keylen, 0, NULL, 2);
			/*if encryption fails, handle the partial failure */
			if (err != 0) {
				printk("ERROR: Encryption Failed.\n");
				goto unlink_partial_failure;
			}
			page_buffer[bytes_read] = '\0';
			/*write bytes to new file*/
			bytes_write = utility_write(new_file_fp, page_buffer, bytes_read, &new_file_fp->f_pos);
			/*if write fails, handle the partial failure */
			if(bytes_write!=bytes_read){
				printk("New bytes written - %d\n", bytes_write);
				printk("Old bytes written - %d\n", bytes_read);
				err = -EIO;
				goto unlink_partial_failure;
			}
			mem_block++;
		}
		set_fs(oldfs);
		/* delete the current file */
		goto unlink;
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
	if(buffer)
		kfree(buffer);
	if(old_file_path)
		kfree(old_file_path);
	if(old_file_abs_path)
		kfree(old_file_abs_path);
	if(new_file)
		kfree(new_file);
	if(new_file_with_ext)
		kfree(new_file_with_ext);
	if(kernel_addr)
		kfree(kernel_addr);
	if(file_pointer)
		filp_close(file_pointer, NULL);
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
static long stbfs_unlocked_ioctl(struct file *file, unsigned int cmd,
				  unsigned long arg)
{
	long err = -ENOTTY;
	struct file *lower_file;

	lower_file = stbfs_lower_file(file);

	/* XXX: use vfs_ioctl if/when VFS exports it */
	if (!lower_file || !lower_file->f_op)
		goto out;
	if (lower_file->f_op->unlocked_ioctl)
		err = lower_file->f_op->unlocked_ioctl(lower_file, cmd, arg);

	/* some ioctls can change inode attributes (EXT2_IOC_SETFLAGS) */
	if (!err)
		fsstack_copy_attr_all(file_inode(file),
				      file_inode(lower_file));

	if(cmd == READ_ONLY){
		err = stbfs_undelete(file);
		goto out;
	}else{
		goto out;
	}
out:
	return err;
}

#ifdef CONFIG_COMPAT
static long stbfs_compat_ioctl(struct file *file, unsigned int cmd,
				unsigned long arg)
{
	long err = -ENOTTY;
	struct file *lower_file;

	lower_file = stbfs_lower_file(file);

	/* XXX: use vfs_ioctl if/when VFS exports it */
	if (!lower_file || !lower_file->f_op)
		goto out;
	if (lower_file->f_op->compat_ioctl)
		err = lower_file->f_op->compat_ioctl(lower_file, cmd, arg);

out:
	return err;
}
#endif

static int stbfs_mmap(struct file *file, struct vm_area_struct *vma)
{
	int err = 0;
	bool willwrite;
	struct file *lower_file;
	const struct vm_operations_struct *saved_vm_ops = NULL;

	/* this might be deferred to mmap's writepage */
	willwrite = ((vma->vm_flags | VM_SHARED | VM_WRITE) == vma->vm_flags);

	/*
	 * File systems which do not implement ->writepage may use
	 * generic_file_readonly_mmap as their ->mmap op.  If you call
	 * generic_file_readonly_mmap with VM_WRITE, you'd get an -EINVAL.
	 * But we cannot call the lower ->mmap op, so we can't tell that
	 * writeable mappings won't work.  Therefore, our only choice is to
	 * check if the lower file system supports the ->writepage, and if
	 * not, return EINVAL (the same error that
	 * generic_file_readonly_mmap returns in that case).
	 */
	lower_file = stbfs_lower_file(file);
	if (willwrite && !lower_file->f_mapping->a_ops->writepage) {
		err = -EINVAL;
		printk(KERN_ERR "stbfs: lower file system does not "
		       "support writeable mmap\n");
		goto out;
	}

	/*
	 * find and save lower vm_ops.
	 *
	 * XXX: the VFS should have a cleaner way of finding the lower vm_ops
	 */
	if (!STBFS_F(file)->lower_vm_ops) {
		err = lower_file->f_op->mmap(lower_file, vma);
		if (err) {
			printk(KERN_ERR "stbfs: lower mmap failed %d\n", err);
			goto out;
		}
		saved_vm_ops = vma->vm_ops; /* save: came from lower ->mmap */
	}

	/*
	 * Next 3 lines are all I need from generic_file_mmap.  I definitely
	 * don't want its test for ->readpage which returns -ENOEXEC.
	 */
	file_accessed(file);
	vma->vm_ops = &stbfs_vm_ops;

	file->f_mapping->a_ops = &stbfs_aops; /* set our aops */
	if (!STBFS_F(file)->lower_vm_ops) /* save for our ->fault */
		STBFS_F(file)->lower_vm_ops = saved_vm_ops;

out:
	return err;
}

static int stbfs_open(struct inode *inode, struct file *file)
{
	int err = 0;
	struct file *lower_file = NULL;
	struct path lower_path;

	/* don't open unhashed/deleted files */
	if (d_unhashed(file->f_path.dentry)) {
		err = -ENOENT;
		goto out_err;
	}

	// if (strcmp(file->f_path.dentry->d_parent->d_name.name,".stb") == 0){
	// 	printk("Opening a file in .stb folder is restricted. (Only undelete operation is allowed in .stb folder)\n");
	// 	err = -EPERM;
	// 	goto out_err;
	// }

	file->private_data =
		kzalloc(sizeof(struct stbfs_file_info), GFP_KERNEL);
	if (!STBFS_F(file)) {
		err = -ENOMEM;
		goto out_err;
	}

	/* open lower object and link stbfs's file struct to lower's */
	stbfs_get_lower_path(file->f_path.dentry, &lower_path);
	lower_file = dentry_open(&lower_path, file->f_flags, current_cred());
	path_put(&lower_path);
	if (IS_ERR(lower_file)) {
		err = PTR_ERR(lower_file);
		lower_file = stbfs_lower_file(file);
		if (lower_file) {
			stbfs_set_lower_file(file, NULL);
			fput(lower_file); /* fput calls dput for lower_dentry */
		}
	} else {
		stbfs_set_lower_file(file, lower_file);
	}

	if (err)
		kfree(STBFS_F(file));
	else
		fsstack_copy_attr_all(inode, stbfs_lower_inode(inode));
out_err:
	return err;
}

static int stbfs_flush(struct file *file, fl_owner_t id)
{
	int err = 0;
	struct file *lower_file = NULL;

	lower_file = stbfs_lower_file(file);
	if (lower_file && lower_file->f_op && lower_file->f_op->flush) {
		filemap_write_and_wait(file->f_mapping);
		err = lower_file->f_op->flush(lower_file, id);
	}

	return err;
}

/* release all lower object references & free the file info structure */
static int stbfs_file_release(struct inode *inode, struct file *file)
{
	struct file *lower_file;

	lower_file = stbfs_lower_file(file);
	if (lower_file) {
		stbfs_set_lower_file(file, NULL);
		fput(lower_file);
	}

	kfree(STBFS_F(file));
	return 0;
}

static int stbfs_fsync(struct file *file, loff_t start, loff_t end,
			int datasync)
{
	int err;
	struct file *lower_file;
	struct path lower_path;
	struct dentry *dentry = file->f_path.dentry;

	err = __generic_file_fsync(file, start, end, datasync);
	if (err)
		goto out;
	lower_file = stbfs_lower_file(file);
	stbfs_get_lower_path(dentry, &lower_path);
	err = vfs_fsync_range(lower_file, start, end, datasync);
	stbfs_put_lower_path(dentry, &lower_path);
out:
	return err;
}

static int stbfs_fasync(int fd, struct file *file, int flag)
{
	int err = 0;
	struct file *lower_file = NULL;

	lower_file = stbfs_lower_file(file);
	if (lower_file->f_op && lower_file->f_op->fasync)
		err = lower_file->f_op->fasync(fd, lower_file, flag);

	return err;
}

/*
 * Stbfs cannot use generic_file_llseek as ->llseek, because it would
 * only set the offset of the upper file.  So we have to implement our
 * own method to set both the upper and lower file offsets
 * consistently.
 */
static loff_t stbfs_file_llseek(struct file *file, loff_t offset, int whence)
{
	int err;
	struct file *lower_file;

	err = generic_file_llseek(file, offset, whence);
	if (err < 0)
		goto out;

	lower_file = stbfs_lower_file(file);
	err = generic_file_llseek(lower_file, offset, whence);

out:
	return err;
}

/*
 * Stbfs read_iter, redirect modified iocb to lower read_iter
 */
ssize_t
stbfs_read_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	int err;
	struct file *file = iocb->ki_filp, *lower_file;

	lower_file = stbfs_lower_file(file);
	if (!lower_file->f_op->read_iter) {
		err = -EINVAL;
		goto out;
	}

	get_file(lower_file); /* prevent lower_file from being released */
	iocb->ki_filp = lower_file;
	err = lower_file->f_op->read_iter(iocb, iter);
	iocb->ki_filp = file;
	fput(lower_file);
	/* update upper inode atime as needed */
	if (err >= 0 || err == -EIOCBQUEUED)
		fsstack_copy_attr_atime(d_inode(file->f_path.dentry),
					file_inode(lower_file));
out:
	return err;
}

/*
 * Stbfs write_iter, redirect modified iocb to lower write_iter
 */
ssize_t
stbfs_write_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	int err;
	struct file *file = iocb->ki_filp, *lower_file;

	lower_file = stbfs_lower_file(file);
	if (!lower_file->f_op->write_iter) {
		err = -EINVAL;
		goto out;
	}

	get_file(lower_file); /* prevent lower_file from being released */
	iocb->ki_filp = lower_file;
	err = lower_file->f_op->write_iter(iocb, iter);
	iocb->ki_filp = file;
	fput(lower_file);
	/* update upper inode times/sizes as needed */
	if (err >= 0 || err == -EIOCBQUEUED) {
		fsstack_copy_inode_size(d_inode(file->f_path.dentry),
					file_inode(lower_file));
		fsstack_copy_attr_times(d_inode(file->f_path.dentry),
					file_inode(lower_file));
	}
out:
	return err;
}

const struct file_operations stbfs_main_fops = {
	.llseek		= generic_file_llseek,
	.read		= stbfs_read,
	.write		= stbfs_write,
	.unlocked_ioctl	= stbfs_unlocked_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= stbfs_compat_ioctl,
#endif
	.mmap		= stbfs_mmap,
	.open		= stbfs_open,
	.flush		= stbfs_flush,
	.release	= stbfs_file_release,
	.fsync		= stbfs_fsync,
	.fasync		= stbfs_fasync,
	.read_iter	= stbfs_read_iter,
	.write_iter	= stbfs_write_iter,
};

/* trimmed directory options */
const struct file_operations stbfs_dir_fops = {
	.llseek		= stbfs_file_llseek,
	.read		= generic_read_dir,
	.iterate	= stbfs_readdir,
	.unlocked_ioctl	= stbfs_unlocked_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= stbfs_compat_ioctl,
#endif
	.open		= stbfs_open,
	.release	= stbfs_file_release,
	.flush		= stbfs_flush,
	.fsync		= stbfs_fsync,
	.fasync		= stbfs_fasync,
};

