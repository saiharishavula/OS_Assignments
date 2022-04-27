// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 1998-2020 Erez Zadok
 * Copyright (c) 2009	   Shrikar Archak
 * Copyright (c) 2003-2020 Stony Brook University
 * Copyright (c) 2003-2020 The Research Foundation of SUNY
 */

#include "stbfs.h"
#include <linux/kernel.h>
#include <linux/mount.h>
#include <linux/genhd.h>
#include <linux/syscalls.h>
#include <linux/mm.h>
#include <linux/uaccess.h>
#include <linux/device.h>
#include <linux/slab.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/namei.h>
#include <linux/ramfs.h>
#include <linux/kthread.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <crypto/skcipher.h>
#include <crypto/hash.h>
#include <linux/scatterlist.h>
static struct task_struct *thread;
char enc_key[256];
#define MD5_KEY_LEN 16

/**
* @brief To create the directory
*
* @source https://elixir.bootlin.com/linux/latest/source/drivers/base/devtmpfs.c#L168
*/
static int dev_mkdir(const char *name, umode_t mode)
{
	struct dentry *dentry;
	struct path path;
	int err;
	mm_segment_t oldfs;
	oldfs = get_fs();
	set_fs(KERNEL_DS);
	dentry = kern_path_create(AT_FDCWD, name, &path, LOOKUP_DIRECTORY);
    set_fs(oldfs);
	if (IS_ERR(dentry))
		return PTR_ERR(dentry);

	err = vfs_mkdir(path.dentry->d_inode, dentry, mode);
	if (!err)
		/* mark as kernel-created inode */
		dentry->d_inode->i_private = &thread;
	done_path_create(&path, dentry);
	return err;
}
/**
* @brief To create the path
*
* @source https://elixir.bootlin.com/linux/latest/source/drivers/base/devtmpfs.c#L168
*/
static int create_path(const char *nodepath)
{
	char *s;
  	int err = 0;
	char *path = NULL;

	/* parent directories do not exist, create them */
	path = kstrdup(nodepath, GFP_KERNEL);
	if (!path)
		return -ENOMEM;

	s = path;
	for (;;){
		s = strchr(s, '/');
		if (!s)
			break;
		s[0] = '\0';
		err = dev_mkdir(path, 0755);
		if (err && err != -EEXIST)
			break;
		s[0] = '/';
		s++;
	}
	kfree(path);
	return err;
}
/*
 * There is no need to lock the stbfs_super_info's rwsem as there is no
 * way anyone can have a reference to the superblock at this point in time.
 */
static int stbfs_read_super(struct super_block *sb, void *raw_data, int silent)
{
	int err = 0;
	struct super_block *lower_sb;
	struct path lower_path;
	char *dev_name = (char *) raw_data;
	struct inode *inode;

	if (!dev_name) {
		printk(KERN_ERR
		       "stbfs: read_super: missing dev_name argument\n");
		err = -EINVAL;
		goto out;
	}

	/* parse lower path */
	err = kern_path(dev_name, LOOKUP_FOLLOW | LOOKUP_DIRECTORY,
			&lower_path);
	if (err) {
		printk(KERN_ERR	"stbfs: error accessing "
		       "lower directory '%s'\n", dev_name);
		goto out;
	}

	/* allocate superblock private data */
	sb->s_fs_info = kzalloc(sizeof(struct stbfs_sb_info), GFP_KERNEL);
	if (!STBFS_SB(sb)) {
		printk(KERN_CRIT "stbfs: read_super: out of memory\n");
		err = -ENOMEM;
		goto out_free;
	}
	/* storing the encryption key given at the time of mount*/
	strcpy(STBFS_SB(sb)->key,enc_key);
	/* storing the absolute path of the mount point*/
	strcpy(STBFS_SB(sb)->root_path,dev_name);
	/* set the lower superblock field of upper superblock */
	lower_sb = lower_path.dentry->d_sb;
	atomic_inc(&lower_sb->s_active);
	stbfs_set_lower_super(sb, lower_sb);

	/* inherit maxbytes from lower file system */
	sb->s_maxbytes = lower_sb->s_maxbytes;

	/*
	 * Our c/m/atime granularity is 1 ns because we may stack on file
	 * systems whose granularity is as good.
	 */
	sb->s_time_gran = 1;

	sb->s_op = &stbfs_sops;
	sb->s_xattr = stbfs_xattr_handlers;

	sb->s_export_op = &stbfs_export_ops; /* adding NFS support */

	/* get a new inode and allocate our root dentry */
	inode = stbfs_iget(sb, d_inode(lower_path.dentry));
	if (IS_ERR(inode)) {
		err = PTR_ERR(inode);
		goto out_sput;
	}
	sb->s_root = d_make_root(inode);
	if (!sb->s_root) {
		err = -ENOMEM;
		goto out_iput;
	}
	d_set_d_op(sb->s_root, &stbfs_dops);

	/* link the upper and lower dentries */
	sb->s_root->d_fsdata = NULL;
	err = new_dentry_private_data(sb->s_root);
	if (err)
		goto out_freeroot;

	/* if get here: cannot have error */

	/* set the lower dentries for s_root */
	stbfs_set_lower_path(sb->s_root, &lower_path);

	/*
	 * No need to call interpose because we already have a positive
	 * dentry, which was instantiated by d_make_root.  Just need to
	 * d_rehash it.
	 */
	d_rehash(sb->s_root);
	if (!silent)
		printk(KERN_INFO
		       "stbfs: mounted on top of %s type %s\n",
		       dev_name, lower_sb->s_type->name);
	
	/* append the trash bin folder (.stb) */
	strcat(dev_name,"/.stb/");
	/* create the trash bin folder */
	err = create_path(dev_name);
	if(err == 0 || err == -17){
		/* errno 17  - file already exits */ 
		err = 0;
		goto out;
	 	
	}else{
		printk("error at creating the path - errno - %d\n", err);
		goto out_freeroot;
	}

	goto out; /* all is well */
	/* no longer needed: free_dentry_private_data(sb->s_root); */
out_freeroot:
	dput(sb->s_root);
out_iput:
	iput(inode);
out_sput:
	/* drop refs we took earlier */
	atomic_dec(&lower_sb->s_active);
	kfree(STBFS_SB(sb));
	sb->s_fs_info = NULL;
out_free:
	path_put(&lower_path);

out:
	return err;
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
struct dentry *stbfs_mount(struct file_system_type *fs_type, int flags,
			    const char *dev_name, void *raw_data)
{
	void *lower_path_name = (void *) dev_name;
    char key[40];
	/* check if the encryption key is given or not */
    if(raw_data == NULL){
		/* since mounted without encryption key, make key null */
		enc_key[0] = '\0'; 
 		return mount_nodev(fs_type, flags, lower_path_name,stbfs_read_super);
    }else{
		/* check for correctness of argument */
		snprintf(key, 5, "%s",(char *)raw_data);
		if(strcmp(key,"enc=") != 0){
			printk("Invalid Argument. Encryption key should be given as enc=password\n");
			return ERR_PTR(-EINVAL);
		}
		/* if argument given correct, copy max of 32 chars from the argument, and then hash the key */
		snprintf(key, 33, "%s",(char *)raw_data+4);
		//strcpy(key,(char *)raw_data+4);
		if(strlen(key) == 0){
			printk("Invalid Argument. Encryption key length cannot be zero.\n");
			return ERR_PTR(-EINVAL);
		}else{
			/* Secure the key by hasing */
			utility_password_encrypt(key, strlen(key), enc_key);
		}
	}
	return mount_nodev(fs_type, flags, lower_path_name, stbfs_read_super);
}

static struct file_system_type stbfs_fs_type = {
	.owner		= THIS_MODULE,
	.name		= STBFS_NAME,
	.mount		= stbfs_mount,
	.kill_sb	= generic_shutdown_super,
	.fs_flags	= 0,
};
MODULE_ALIAS_FS(STBFS_NAME);

static int __init init_stbfs_fs(void)
{
	int err;

	pr_info("Registering stbfs " STBFS_VERSION "\n");
	printk("new module\n");


	err = stbfs_init_inode_cache();
	if (err)
		goto out;
	err = stbfs_init_dentry_cache();
	if (err)
		goto out;
	err = register_filesystem(&stbfs_fs_type);
out:
	if (err) {
		stbfs_destroy_inode_cache();
		stbfs_destroy_dentry_cache();
	}
	return err;
}

static void __exit exit_stbfs_fs(void)
{
	stbfs_destroy_inode_cache();
	stbfs_destroy_dentry_cache();
	unregister_filesystem(&stbfs_fs_type);
	pr_info("Completed stbfs module unload\n");
}

MODULE_AUTHOR("Erez Zadok, Filesystems and Storage Lab, Stony Brook University"
	      " (http://www.fsl.cs.sunysb.edu/)");
MODULE_DESCRIPTION("STBFS " STBFS_VERSION
		   " (http://stbfs.filesystems.org/)");
MODULE_LICENSE("GPL");

module_init(init_stbfs_fs);
module_exit(exit_stbfs_fs);
