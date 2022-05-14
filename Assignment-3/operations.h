#include <linux/linkage.h>
#include <linux/moduleloader.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/cred.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <linux/string.h>
#include <linux/gfp.h>
#include <linux/err.h>
#include <linux/jiffies.h>
#include <linux/namei.h>
#include <linux/timex.h>
#include <crypto/hash.h>
#include <crypto/skcipher.h>
#include <linux/random.h>
#include <linux/time.h>
#include <linux/rtc.h>

#include "constants.h"

/******************** Utility functions used in operations ***********************/

/**
 * @brief Utility to print and write log into log file
 *
 * @param fo log file descriptor to write the log to
 * @param content content to write into file
 * @return int
 */
int write_file_util(struct file *fo, char *content)
{
        mm_segment_t prev_fs;
        int written;
        if(fo==NULL) {
                pr_err("invalid file descriptor\n");
                return -EINVAL;
        }
        if(content==NULL || strlen(content)==0) {
                pr_err("No content to write");
                return -EINVAL;
        }

        prev_fs = get_fs();
        set_fs(KERNEL_DS);

        // printk("Content to write:%s\n", content);
        written = vfs_write(fo, content, strlen(content), &fo->f_pos);

        set_fs(prev_fs);

        if (written < strlen(content)) {
                pr_warn("unable to write whole content into output file\n");
                return -1;
        }
        return 0;
}

/**
 * @brief Utility to print and write log into log file
 *
 * @param log log to be written
 * @param fo log file descriptor to write the log to
 * @param log_level 0-info, 1-warn, 2-error
 * @return int
 */
int print_write_log(char* log, struct file *fo, int log_level)
{

        if(fo==NULL) {
                pr_err("invalid file descriptor\n");
                return -EINVAL;
        }

        if(log==NULL || strlen(log)==0) {
                pr_err("No content to write");
                return -EINVAL;
        }

        if(log_level == 0)
                printk("%s", log);
        else if(log_level == 1)
                pr_warn("%s", log);
        else if(log_level == 2)
                pr_err("%s", log);


        return write_file_util(fo, log);
}

/**
 * @brief Utility to read from file and write into buffer
 *
 * @param filp_in file to read from
 * @param buf character buffer to write the contents of a file to
 * @param len length of the content to read
 * @return int
 */
int read_util(struct file *filp_in, char *buf, int len)
{
        int read = 0;
        mm_segment_t prev_fs;

        prev_fs = get_fs();
        set_fs(KERNEL_DS);
        read = vfs_read(filp_in, buf, len, &(filp_in->f_pos));
        set_fs(prev_fs);
        return read;
}

/**
 * @brief Utility to create job_id named log file in JOB_OUTPUT_PATH
 *
 * @param log_output_fo The file pointer of log file created
 * @param job_id job_id for which the log file is getting created
 * @return int
 */
int create_log_file(struct file **log_output_fo, int job_id)
{

        int ret = 0;
        char *log_file_path = NULL;

        printk("Inside create_log_file function");
        job_id = job_id % MAX_JOB_ID;
        log_file_path = kmalloc(MAX_PATH_SIZE, GFP_KERNEL);
        if (log_file_path == NULL) {
                pr_err("Error allocating space for outputfilepath\n");
                ret = -ENOMEM;
                goto out;
        }

        sprintf(log_file_path, "%s%d", JOB_OUTPUT_PATH, job_id);

        *log_output_fo = filp_open(log_file_path, O_WRONLY | O_CREAT | O_TRUNC, 0);
        if (!*log_output_fo || IS_ERR(*log_output_fo)) {
                pr_err("Error opening the output file to store the data\n");
                ret = PTR_ERR(log_output_fo);
                goto out;
        }
        (*log_output_fo)->f_pos = 0;
        printk("Successfully returned the logfile pointer");

out:
        if(log_file_path!=NULL) kfree(log_file_path);
        return ret;
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
int safe_unlink(struct file *file)
{
        int err = 0;
        inode_lock_nested(file->f_path.dentry->d_parent->d_inode, I_MUTEX_PARENT);
        err = vfs_unlink(file->f_path.dentry->d_parent->d_inode, file->f_path.dentry, NULL);
        inode_unlock(file->f_path.dentry->d_parent->d_inode);
        return err;
}

/****************** Beginning of operations ******************/

/****************** Operation to get hash of the file ******************/

/**
 * get_hash_of_buffer() - Obtain Md5 hash of key.
 *
 * @key: key for which we want to obtain the hash
 * @key_len: length of the key passed
 * @hash: hash of the key is stored in this
 * This functions obtains the PASSWORD_SIZE hash of given string key.
 * Sourced from:https://www.kernel.org/doc/html/v5.4/crypto/api-samples.html. Modified Accordingly.
 * https://www.kernel.org/doc/html/latest/crypto/api-intro.html
 * Also in my HW1 sys_cryptocopy.c file.
 * @return: return 0 on success , <0 on failures.
 */
int get_hash_of_buffer(char *buffer, char *hash)
{
        struct crypto_ahash *tfm = NULL;
        struct ahash_request *req = NULL;
        struct scatterlist sg[2];
        int ret_val = 0, buffer_len = 0;
        if (buffer == NULL)
        {
                pr_err("buffer shouldnot be null or empty\n");
                ret_val = -1;
                goto out;
        }
        if (hash == NULL)
        {
                pr_err("hash shouldnot be null\n");
                ret_val = -1;
                goto out;
        }
        buffer_len = strlen(buffer);
        sg_init_one(sg, buffer, buffer_len);
        tfm = crypto_alloc_ahash("md5", 0, CRYPTO_ALG_ASYNC);
        if (IS_ERR(tfm))
        {
                pr_err("crypto_alloc_ahash() - failed\n");
                ret_val = -1;
                goto out;
        }
        req = ahash_request_alloc(tfm, GFP_ATOMIC);
        if (req == NULL)
        {
                pr_err("ahash_request_alloc() - failed\n");
                ret_val = -1;
                goto out;
        }
        ahash_request_set_callback(req, 0, NULL, NULL);
        ahash_request_set_crypt(req, sg, hash, buffer_len);
        if (crypto_ahash_digest(req))
        {
                pr_err("crypto_ahash_digest() - failed\n");
                ret_val = -1;
                goto out;
        }
        hash[MD5_KEY_LEN] = '\0';
out:
        if (req)
                ahash_request_free(req);
        if (tfm)
                crypto_free_ahash(tfm);

        return 0;
}

/**
 * @brief Operation to compute hash of the file
 *
 * @param job job details containing all the necessary fields for operation like filename, etc
 * @param hash hash of the file is stored into this
 * @return int
 */
int compute_hash(struct work_queue_job *job, char* hash)
{
        int ret = 0;
        char *buffer, *log=NULL, *infile;
        struct file *infile_fo = NULL, *output_fo = NULL;
        int job_id;
        struct kstat *file_props = NULL;

        if(job == NULL){
                pr_err("job is null\n");
                return -EINVAL;
        }
        infile = job->infile;
        job_id = job->id;
        printk("Before null check and condition checks\n");
        if(infile==NULL || strlen(infile)==0) {
                pr_err("infile cannot be null or empty\n");
                return -EINVAL;
        }

        if(hash == NULL) {
                pr_err("hash cannot be null as we store the hash in this field\n");
                return -EINVAL;
        }
        printk("Inside compute_hash method\n");

        buffer = kzalloc(BUFFER_SIZE, GFP_KERNEL);
        if(buffer == NULL) {
                pr_err("Unable to allocate space for buffer");
                return -EINVAL;
        }
        log = kmalloc(MAX_LOG_SIZE, GFP_KERNEL);
        if (log == NULL) {
                pr_err("Error allocating space for log file output\n");
                ret = -ENOMEM;
                goto out;
        }

        //create logfile
        ret = create_log_file(&output_fo, job_id);
        if(output_fo == NULL) {
                pr_err("log file descriptor is NULL");
                goto out;
        }

        //for file_props
        file_props = kmalloc(sizeof(struct kstat), GFP_KERNEL);
        if (file_props == NULL) {
                ret = -ENOMEM;
                sprintf(log, "%s\n", "Computation of hash failed due to insufficent memory");
                print_write_log(log, output_fo, 0);
                goto out;
        }

        infile_fo = filp_open(infile, O_RDONLY, 0);
        if (!infile_fo || IS_ERR(infile_fo)) {
                sprintf(log, "%s", "Error opening the input file!\n");
                print_write_log(log, output_fo, 1);
                ret = PTR_ERR(infile_fo);
                goto out;
        }

        ret = vfs_stat(infile, file_props);
        if (ret) {
                sprintf(log, "\t%s\n", "Filename invalid or file not present\n");
                print_write_log(log, output_fo, 1);
                goto out;
        }

        // validate user access to input file
        if (job->uid != file_props->uid.val || job->gid != file_props->gid.val) {
                ret = -EACCES;
                sprintf(log, "%s: %s\n", "User do not have access to file", infile);
                print_write_log(log, output_fo, 1);
                goto out;
        }

        //starting the hash with constant which will get overriden as we compute it chunkwise
        //our hash will use this
        memcpy(hash, "srikanharijaidee", 16);
        hash[MD5_KEY_LEN] = '\0';
        printk("Before while loop\n");
        while((ret=read_util(infile_fo, buffer, 4080))>0) {
                printk("Inside WHILE loop of computing hash, read = %d\n", ret);
                strcat(buffer, hash);
                printk("buffer: %s\n", buffer);
                ret = get_hash_of_buffer(buffer, hash);
                if(ret<0) {
                        pr_err("Error in getting md5 hash of buffer\n");
                        break;
                }
        }

        if(ret<0) {
                sprintf(log, "%s, hash:%s\n", "Error computing hash for the input file", hash);
                print_write_log(log, output_fo, 2);
        }else {
                sprintf(log, "%s, hash:%s\n", "Successfully computed hash for the input file", hash);
                print_write_log(log, output_fo, 0);
                //write_file_util(output_fo, log);
        }

out:
        if(buffer!=NULL)
                kfree(buffer);
        if(log!=NULL)
                kfree(log);
        if (file_props != NULL)
                kfree(file_props);
        if (infile_fo)
                filp_close(infile_fo, NULL);
        if (output_fo)
                filp_close(output_fo, NULL);
        if(ret>0) return 0;
        return ret;
}

/****************** Operation to delete files ******************/

/**
 * @brief Operation to delete multiple files
 *
 * @param job job details containing all the necessary fields for operation like filenames, etc
 * @return int
 */
int delete_multiple_files(struct work_queue_job *job)
{
        int deletion_failed = 0, ret = 0, i, ret_status, number_of_files, job_id;
        struct file *fo = NULL, *output_fo = NULL;
        struct kstat *file_props = NULL;
        char *log;
        char **file_names;

        if(job == NULL){
                pr_err("job is null\n");
                return -EINVAL;
        }

        file_names = job->filenames;
        number_of_files = job->number_of_files;
        job_id = job->id;

        if (file_names == NULL || number_of_files == 0) {
                pr_err("files cannot be NULL or EMPTY");
                return -EINVAL;
        }

        //can find the length of string array using sizeof(files)/sizeof(char*) in case we cant hardcode
        //In case one of the files is invalid or doesnt exists, rather than returning with Invalid error,
        //I will skip that spefic erroneous file, printing warn logs. and continue the action.

        //create file for the output
        log = kmalloc(MAX_LOG_SIZE, GFP_KERNEL);
        if (log == NULL) {
                pr_err("Error allocating space for log file output\n");
                ret = -ENOMEM;
                goto out;
        }

        ret = create_log_file(&output_fo, job_id);
        if(output_fo == NULL || ret<0) {
                pr_err("Error creating log file descriptor");
                goto out;
        }
        //for file_props
        file_props = kmalloc(sizeof(struct kstat), GFP_KERNEL);
        if (file_props == NULL) {
                ret = -ENOMEM;
                sprintf(log, "%s\n", "Deletion of multiple files failed due to insufficent memory");
                print_write_log(log, output_fo, 2);
                goto out;
        }
        for (i = 0; i < number_of_files; i++) {
                if (file_names[i] == NULL || strlen(file_names[i]) == 0) {
                        deletion_failed++;
                        sprintf(log, "%s",
                                "input file for deletion is either null or empty!\n");
                        print_write_log(log, output_fo, 1);
                        continue;
                }
                ret_status = vfs_stat(file_names[i], file_props);
                if (ret_status) {
                        sprintf(log, "\t%s\n", "Filename invalid or file not present\n");
                        print_write_log(log, output_fo, 1);
                        continue;
                }

                // validate user access to input file
                if (job->uid != file_props->uid.val || job->gid != file_props->gid.val) {
                        sprintf(log, "%s: %s\n", "User do not have access to file", file_names[i]);
                        print_write_log(log, output_fo, 1);
                        continue;
                }

                fo = filp_open(file_names[i], O_RDONLY, 0);
                if (!fo || IS_ERR(fo)) {
                        deletion_failed++;
                        sprintf(log, "%s: %s%s", "input file for deletion",
                                file_names[i], " doesnt exist\n");
                        print_write_log(log, output_fo, 1);
                        continue;
                }
                // close the file before deletion of the file
                if (fo)
                        filp_close(fo, NULL);
                //Now we can go ahead and delete this file
                ret = safe_unlink(fo);
                if (ret != 0) {
                        deletion_failed++;
                        sprintf(log, "%s: %s\n",
                                "deletion failed for file", file_names[i]);
                        print_write_log(log, output_fo, 1);
                } else {
                        sprintf(log, "%s: %s\n",
                                "Successfully deleted the file",
                                file_names[i]);
                        print_write_log(log, output_fo, 0);
                }
        }

out:
        if (log != NULL)
                kfree(log);
        if (file_props != NULL)
                kfree(file_props);
        if (output_fo)
                filp_close(output_fo, NULL);
        if (ret != 0)
                return ret;
        return deletion_failed;
}

/******************Operation to rename files*************************/

/**
 * @brief Utility to safely rename with necessary locking and reference releases
 *
 * @param old_file file to rename from
 * @param new_file file to rename to
 * @return int
 */
int safe_rename(struct file *old_file, struct file *new_file)
{
        int ret = 0;
        struct dentry *old_dentry = NULL, *new_dentry = NULL,
                      *old_parent_dentry = NULL, *new_parent_dentry = NULL, *trap = NULL;
        struct inode *old_parent, *new_parent;

        old_dentry = old_file->f_path.dentry;
        new_dentry = new_file->f_path.dentry;

        old_parent = old_dentry->d_parent->d_inode;
        new_parent = new_dentry->d_parent->d_inode;

        dget(old_dentry);
        dget(new_dentry);
        old_parent_dentry=dget_parent(old_dentry);
        new_parent_dentry=dget_parent(new_dentry);

        trap = lock_rename(old_parent_dentry,new_parent_dentry);

        if(trap == old_dentry) {
                ret = -EINVAL;
                goto out;
        }

        if(trap == new_dentry) {
                ret = -ENOTEMPTY;
                goto out;
        }

        ret = vfs_rename(old_parent,old_dentry,new_parent,new_dentry,NULL,0);
        if(ret) {
                printk("Error in performing vfs_rename()\n");
                ret= -ECANCELED;
                goto out;
        }

out:
        unlock_rename(old_parent_dentry,new_parent_dentry);
        dput(old_parent_dentry);
        dput(new_parent_dentry);
        dput(old_dentry);
        dput(new_dentry);

        return ret;
}

/**
 * @brief Operation to rename multiple files
 *
 * @param job job details containing all the necessary fields for operation like filenames, etc
 * @return int
 */
int rename_multiple_files(struct work_queue_job *job)
{
        int i, ret=0, rename_failed=0;
        struct file *old_file_p=NULL, *new_file_p=NULL, *output_fo=NULL;
        char *log;
        struct kstat *file_props = NULL;
        char **file_names;
        int number_of_files, job_id, ret_status;

        if(job == NULL){
                pr_err("job is null\n");
                return -EINVAL;
        }

        file_names = job->filenames;
        number_of_files = job->number_of_files;
        job_id = job->id;

        if(file_names == NULL || number_of_files==0) {
                pr_err("files cannot be NULL or EMPTY\n");
                return -EINVAL;
        }

        if((number_of_files)%2 == 1) {
                pr_err("number of files cannot be odd\n");
                return -EINVAL;
        }
        log = kmalloc(MAX_LOG_SIZE, GFP_KERNEL);
        if (log == NULL) {
                pr_err("Error allocating space for log file output\n");
                ret = -ENOMEM;
                goto out;
        }
        ret = create_log_file(&output_fo, job_id);
        if(output_fo == NULL || ret<0) {
                pr_err("Error creating log file descriptor");
                goto out;
        }

        //for file_props
        file_props = kmalloc(sizeof(struct kstat), GFP_KERNEL);
        if (file_props == NULL) {
                ret = -ENOMEM;
                sprintf(log, "%s\n", "Renaming of multiple files failed due to insufficent memory");
                print_write_log(log, output_fo, 0);
                goto out;
        }

        for(i=0; i<number_of_files; i+=2) {
                if(file_names[i]==NULL || strlen(file_names[i])==0) {
                        rename_failed++;
                        sprintf(log, "%s", "input file for renaming is either null or empty!\n");
                        print_write_log(log, output_fo, 1);
                        continue;
                }
                if(file_names[i+1]==NULL || strlen(file_names[i+1])==0) {
                        rename_failed++;
                        sprintf(log, "%s", "output file for renaming is either null or empty!\n");
                        print_write_log(log, output_fo, 1);
                        continue;
                }

                ret_status = vfs_stat(file_names[i], file_props);
                if (ret_status) {
                        sprintf(log, "\t%s\n", "Filename invalid or file not present\n");
                        print_write_log(log, output_fo, 1);
                        continue;
                }

                // validate user access to input file
                if (job->uid != file_props->uid.val || job->gid != file_props->gid.val) {
                        sprintf(log, "%s: %s\n", "User do not have access to file", file_names[i]);
                        print_write_log(log, output_fo, 1);
                        continue;
                }

                //open input file in read only mode
                old_file_p = filp_open(file_names[i], O_RDONLY, 0);
                if(!old_file_p || IS_ERR(old_file_p)) {
                        rename_failed++;
                        sprintf(log, "%s: %s%s", "input file of renaming", file_names[i], " doesnt exist\n");
                        print_write_log(log, output_fo, 1);
                        continue;
                }

                //check if the there is a file with output name already exists
                new_file_p = filp_open(file_names[i+1], O_RDONLY, 0);
                if(!IS_ERR(new_file_p)) {
                        rename_failed++;
                        sprintf(log, "%s: %s%s", "file with outputname of renaming", file_names[i+1], " already exists\n");
                        print_write_log(log, output_fo, 1);
                        filp_close(new_file_p, NULL);
                        continue;
                }

                new_file_p = filp_open(file_names[i+1], O_WRONLY | O_CREAT | O_TRUNC, 0);
                if(!new_file_p || IS_ERR(new_file_p)) {
                        rename_failed++;
                        sprintf(log, "%s: %s", "Unable to create new file with name", file_names[i+1]);
                        print_write_log(log, output_fo, 1);
                        continue;
                }

                //Now we can go ahead and rename this file
                ret = safe_rename(old_file_p, new_file_p);
                if(ret!=0) {
                        rename_failed++;
                        sprintf(log, "%s: %s to: %s\n", "rename failed for file", file_names[i], file_names[i+1]);
                        print_write_log(log, output_fo, 1);
                }else {
                        sprintf(log, "%s: %s to: %s\n", "Successfully renamed the file", file_names[i], file_names[i+1]);
                        print_write_log(log, output_fo, 0);
                }
                if (old_file_p)
                        filp_close(old_file_p, NULL);
                if (new_file_p)
                        filp_close(new_file_p, NULL);
        }

out:
        if(log != NULL) kfree(log);
        if (output_fo)
                filp_close(output_fo, NULL);
        if (file_props != NULL)
                kfree(file_props);
        if(ret!=0) return ret;
        return rename_failed;
}

/******************Operation to concatenate files*************************/

/**
 * @brief Utility to copy from one file to other
 *
 * @param src source file to copy from
 * @param dest destination file to copy to
 * @return int
 */
int copy_file(struct file* src, struct file* dest)
{
        int ret = 0, read, written;
        char *buffer = NULL;
        mm_segment_t prev_fs;

        if(src==NULL || dest==NULL) {
                pr_err("invalid src/dest file");
                return -EINVAL;
        }
        buffer = kzalloc(PAGE_SIZE, GFP_KERNEL);
        //memset(buffer, '\0', PAGE_SIZE);
        if (buffer == NULL) {
                pr_err("Not enough memory to be allocated for buffer");
                return -ENOMEM;
        }

        src->f_pos=0;
        prev_fs = get_fs();
        set_fs(KERNEL_DS);
        while ((read = vfs_read(src, buffer, PAGE_SIZE,
                                &src->f_pos)) > 0) {
                printk("in copying, the read is: %d", read);
                written =
                        vfs_write(dest, buffer, read, &dest->f_pos);
                if (written < read) {
                        pr_warn("Not able to copy the content from buffer to concatfile\n");
                        set_fs(prev_fs); //set back to previous fs
                        ret = -ECANCELED;
                        goto out;
                }
        }
out:
        if(buffer!=NULL) kfree(buffer);
        set_fs(prev_fs);
        return ret;
}

/**
 * @brief Operation to concatenate files
 *
 * @param job contains all details of the operation like filenames, job_id etc
 * @return int
 */
int concatenate_files(struct work_queue_job *job) {
        int i, ret;
        struct file* job_output_file = NULL, *concatenated_file = NULL, *in_file = NULL;
        char *log;
        char **file_names;
        int number_of_files, job_id;
        struct kstat *file_props = NULL;

        if(job == NULL){
                pr_err("job is null\n");
                return -EINVAL;
        }

        file_names = job->filenames;
        number_of_files = job->number_of_files;
        job_id = job->id;

        if(number_of_files < 2) {
                pr_err("number of files cannot be less than 2");
                return -EINVAL;
        }

        if(file_names[number_of_files-1] == NULL || strlen(file_names[number_of_files-1])==0) {
                pr_err("invalid output filename");
                return -EINVAL;
        }
        log = kmalloc(MAX_LOG_SIZE, GFP_KERNEL);
        if (log == NULL) {
                pr_err("Error allocating space for log file output\n");
                ret = -ENOMEM;
                goto out;
        }

        ret = create_log_file(&job_output_file, job_id);
        if(job_output_file == NULL || ret<0) {
                pr_err("Error creating log file descriptor");
                goto out;
        }

        //for file_props
        file_props = kmalloc(sizeof(struct kstat), GFP_KERNEL);
        if (file_props == NULL) {
                ret = -ENOMEM;
                sprintf(log, "%s\n", "Concatenation of multiple files failed due to insufficent memory");
                print_write_log(log, job_output_file, 2);
                goto out;
        }

        concatenated_file = filp_open(file_names[number_of_files-1], O_WRONLY | O_CREAT | O_TRUNC, 0);
        if(!concatenated_file || IS_ERR(concatenated_file)) {
                sprintf(log, "%s\n", "Error opening concatenated file descriptor");
                print_write_log(log, job_output_file, 2);
                ret = PTR_ERR(concatenated_file);
                goto out;
        }
        concatenated_file->f_pos = 0;
        //concatenation is binary operation, either success in concatening all files or failed even in failing to concatenate single file.
        for(i=0; i<number_of_files-1; i++) {
                ret = vfs_stat(file_names[i], file_props);
                if (ret) {
                        sprintf(log, "\t%s\n", "Filename invalid or file not present\n");
                        print_write_log(log, job_output_file, 2);
                        break;
                }

                // validate user access to input file
                if (job->uid != file_props->uid.val || job->gid != file_props->gid.val) {
                        sprintf(log, "%s: %s\n", "User do not have access to file, Aborting the concatenation", file_names[i]);
                        print_write_log(log, job_output_file, 2);
                        ret = -EACCES;
                        break;
                }
                in_file = NULL;
                in_file = filp_open(file_names[i], O_RDONLY, 0);
                if(!in_file || IS_ERR(in_file)) {
                        sprintf(log, "%s: %s", "Error reading input file descriptor for file", file_names[i]);
                        print_write_log(log, job_output_file, 2);
                        ret = PTR_ERR(in_file);
                        break;
                }
                //copy file_names[i] to concatenated_file
                ret = copy_file(in_file, concatenated_file);
                if(ret<0) {
                        sprintf(log, "%s: %s", "Error concatenating file:", file_names[i]);
                        print_write_log(log, job_output_file, 2);
                        break;
                }
                filp_close(in_file, NULL);
                in_file = NULL;
        }

        if(ret==0) {
                sprintf(log, "%s: %s\n", "Successfully concatenated all files to", file_names[number_of_files-1]);
                print_write_log(log, job_output_file, 0);
        }else{
                sprintf(log, "%s: %s%s\n", "concatenation to", file_names[number_of_files-1], " failed");
                print_write_log(log, job_output_file, 2);
                //delete the file in case there is error in concatenation.
                if (concatenated_file)
                        filp_close(concatenated_file, NULL);
                safe_unlink(concatenated_file);
        }

out:

        if(log!=NULL) kfree(log);
        if (file_props != NULL)
                kfree(file_props);
        if (job_output_file)
                filp_close(job_output_file, NULL);
        if (in_file)
                filp_close(in_file, NULL);
        if (concatenated_file)
                filp_close(concatenated_file, NULL);

        return ret;
}

/*******************Operation to encrypt/decrypt file*********************/

static int test_skcipher(char *keybuf, char *buf, int keylen, int bufsize, int flag)
{
        struct crypto_skcipher *tfm = NULL;
        struct skcipher_request *req = NULL;
        struct scatterlist sg;
        DECLARE_CRYPTO_WAIT(wait);
        u8 iv[16];
        int ret;

        tfm = crypto_alloc_skcipher("ctr(aes)", 0, 0);
        if (IS_ERR(tfm)) {
                printk("Error allocating ctr(aes) handle: %ld\n", PTR_ERR(tfm));
                return PTR_ERR(tfm);
        }

        ret = crypto_skcipher_setkey(tfm, keybuf, keylen);
        if (ret) {
                printk("Error setting key: %d\n", ret);
                goto out;
        }

        req = skcipher_request_alloc(tfm, GFP_KERNEL);
        if (!req) {
                ret = -ENOMEM;
                goto out;
        }
        memcpy(iv, "hardcodedivvalue", 16);
        sg_init_one(&sg, buf, bufsize);
        skcipher_request_set_callback(
                req, CRYPTO_TFM_REQ_MAY_BACKLOG | CRYPTO_TFM_REQ_MAY_SLEEP,
                crypto_req_done, &wait);
        skcipher_request_set_crypt(req, &sg, &sg, bufsize, iv);
        if (flag == 1)
                ret = crypto_wait_req(crypto_skcipher_encrypt(req), &wait);
        else
                ret = crypto_wait_req(crypto_skcipher_decrypt(req), &wait);
        if (ret) {
                printk("Error encrypting data: %d\n", ret);
                goto out;
        }
out:
        crypto_free_skcipher(tfm);
        skcipher_request_free(req);
        return ret;
}

/**
 * @brief utility to encrypt the password
 *
 * @param password password to encrypt
 * @param password_len length of the password
 * @param encrypted_password encrypted password is stored in this
 */

void utility_password_encrypt(char *password, int password_len, char *encrypted_password)
{
        struct scatterlist sg[2];
        struct crypto_ahash *tfm = NULL;
        struct ahash_request *req = NULL;
        if (encrypted_password == NULL) {
                printk("utility_password_encrypt() - encrypted_password is NULL\n");
                goto end;
        }
        sg_init_one(sg, password, password_len);
        tfm = crypto_alloc_ahash(
                "md5", 0, CRYPTO_ALG_ASYNC); //allocate ahash cipher handle:
        if (IS_ERR(tfm)) {
                printk("crypto_alloc_ahash() - failed\n");
                goto end;
        }
        req = ahash_request_alloc(tfm, GFP_ATOMIC);
        if (req == NULL) {
                printk("ahash_request_alloc() - failed\n");
                goto end;
        }
        ahash_request_set_callback(req, 0, NULL, NULL);
        ahash_request_set_crypt(req, sg, encrypted_password, password_len);
        if (crypto_ahash_digest(req)) {
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
 * @brief Operation to encrypt/decrypt the file
 *
 * @param job job containing operation details
 * @param enc_flag 1 for encryption, 2 for decryption
 * @return int
 */
int encrypt_decrypt_file(struct work_queue_job *job, u16 enc_flag)
{
        int return_val = 0;
        int ret_status, unlink_status;
        char *buf = NULL;
        char *log_filename = NULL;
        char *log = NULL;
        char *hashed_key = NULL;
        char *rehashed_key = NULL;
        bool EOF_flag = false;
        int write_size = BUFFER_BLOCK_SIZE;

        struct file *input_file = NULL;
        struct file *output_file = NULL;
        struct kstat *infile_props = NULL;
        struct file *log_file = NULL;
        struct inode *input_inode = NULL;
        struct inode *output_inode = NULL;
        ssize_t read_status;
        ssize_t write_status;
        mm_segment_t oldFs;
        uid_t user_uid;
        gid_t user_gid;

        char *input_filename = job->infile;
        char *output_filename = job->outfile;
        char *enc_key = job->encryption_key;
        int job_id = job->id;
        user_uid = job->uid;
        user_gid = job->gid;

        if(enc_flag!=1 && enc_flag!=2) {
                pr_err("invalid enc_flag");
                return -EINVAL;
        }

        /* ------------------------- logging --------------------------- */
        log_filename = kmalloc(MAX_PATH_SIZE, GFP_KERNEL);
        if (log_filename == NULL) {
                pr_err("Error allocating space for log_filename\n");
                return_val = -ENOMEM;
                goto out;
        }
        sprintf(log_filename, "%s%d", JOB_OUTPUT_PATH, job_id);
        log_file = filp_open(log_filename, O_WRONLY | O_CREAT | O_TRUNC, 0);
        if (!log_file || IS_ERR(log_file)) {
                pr_err("Error opening the output file to store the data\n");
                if(!log_file)
                        return_val = -ENOENT;
                else
                        return_val = PTR_ERR(log_file);
                goto out;
        }
        log = kmalloc(MAX_LOG_SIZE, GFP_KERNEL);
        if (log == NULL) {
                pr_err("Error allocating space for log file output\n");
                return_val = -ENOMEM;
                goto out;
        }
        /* ------------------------------------------------------------- */

        // check status of infile
        infile_props = kmalloc(sizeof(struct kstat), GFP_KERNEL);
        if (infile_props == NULL) {
                return_val = -ENOMEM;
                sprintf(log, "%s\n", "Encrypt/Decrypt failed!\n Insufficent memory");
                print_write_log(log, log_file, 0);
                goto out;
        }
        ret_status = vfs_stat(input_filename, infile_props);
        if (ret_status) {
                return_val = -ENOENT;
                sprintf(log, "%s\n", "Encrypt/Decrypt failed!\n Input file do not exist");
                print_write_log(log, log_file, 0);
                goto out;
        }

        // validate user access to input file
        if (user_uid != infile_props->uid.val ||
            user_gid != infile_props->gid.val) {
                return_val = -EACCES;
                sprintf(log, "%s %s\n", "Encrypt/Decrypt failed!\n User do not have access to file", input_filename);
                print_write_log(log, log_file, 0);
                goto out;
        }

        input_file = filp_open(input_filename, O_RDONLY, 0);
        if (!input_file || IS_ERR(input_file)) {
                if(!input_file)
                        return_val = -ENOENT;
                else
                        return_val = PTR_ERR(input_file);
                sprintf(log, "%s %s\n", "Encrypt/Decrypt failed!\n Cannot open input file", input_filename);
                print_write_log(log, log_file, 0);
                goto out;
        }

        output_file = filp_open(output_filename, O_CREAT | O_WRONLY | O_TRUNC, infile_props->mode);
        if (!output_file || IS_ERR(output_file)) {
                if(!input_file)
                        return_val = -ENOENT;
                else
                        return_val = PTR_ERR(output_file);
                sprintf(log, "%s %s\n", "Encrypt/Decrypt failed!\n Cannot open output file", output_filename);
                print_write_log(log, log_file, 0);
                goto out;
        }

        hashed_key = kmalloc(MD5_KEY_LEN, GFP_KERNEL);
        if (hashed_key == NULL) {
                return_val = -ENOMEM;
                sprintf(log, "%s\n", "Encrypt/Decrypt failed!\n Insufficent memory");
                print_write_log(log, log_file, 0);
                goto file_cleanup;
        }

        rehashed_key = kmalloc(MD5_KEY_LEN, GFP_KERNEL);
        if (rehashed_key == NULL) {
                return_val = -ENOMEM;
                sprintf(log, "%s\n", "Encrypt/Decrypt failed!\n Insufficent memory");
                print_write_log(log, log_file, 0);
                goto file_cleanup;
        }

        buf = kmalloc(write_size, GFP_KERNEL);
        if (buf == NULL) {
                return_val = -ENOMEM;
                sprintf(log, "%s\n", "Encrypt/Decrypt failed!\n Insufficent memory");
                print_write_log(log, log_file, 0);
                goto file_cleanup;
        }

        // check if input and output are regular and different files
        input_inode = input_file->f_path.dentry->d_inode;
        output_inode = output_file->f_path.dentry->d_inode;
        if (input_inode == output_inode) {
                return_val = -EINVAL;
                sprintf(log, "%s\n", "Encrypt/Decrypt failed!\n Input and Output files are same");
                print_write_log(log, log_file, 0);
                goto file_cleanup;
        }
        if (!S_ISREG(input_inode->i_mode) || !S_ISREG(output_inode->i_mode)) {
                return_val = -EINVAL;
                sprintf(log, "%s\n", "Encrypt/Decrypt failed!\n Input/Output file is not a regular file");
                print_write_log(log, log_file, 0);
                goto file_cleanup;
        }

        // set output file ownerships
        output_inode->i_uid.val = user_uid;
        output_inode->i_gid.val = user_gid;

        // hash and rehash the key again
        utility_password_encrypt(enc_key, strlen(enc_key), hashed_key);
        utility_password_encrypt(hashed_key, strlen(hashed_key), rehashed_key);

        oldFs = get_fs();
        set_fs(KERNEL_DS);

        // set the file pointers to the beginning of the files
        log_file->f_pos = 0;
        output_file->f_pos = 0;
        input_file->f_pos = 0;

        /* encrypt preamble */
        if (enc_flag == 1) {
                // write hash to start of the file
                write_status = vfs_write(output_file, rehashed_key, MD5_KEY_LEN, &(output_file->f_pos));
                if (write_status < 0) {
                        return_val = -EIO;
                        set_fs(oldFs);
                        sprintf(log, "%s\n", "Encrypt/Decrypt failed!\n Read/Write operation failed");
                        print_write_log(log, log_file, 0);
                        goto file_cleanup;
                }

        } /* decrypt and verify preamble */
        else if (enc_flag == 2) {
                // check the hash present in the file
                read_status = vfs_read(input_file, buf, MD5_KEY_LEN, &(input_file->f_pos));
                if (read_status < 0) {
                        return_val = -EIO;
                        set_fs(oldFs);
                        sprintf(log, "%s\n", "Encrypt/Decrypt failed!\n Read/Write operation failed");
                        print_write_log(log, log_file, 0);
                        goto file_cleanup;
                }

                if (memcmp(rehashed_key, buf, MD5_KEY_LEN) != 0) {
                        printk("Encryption key mismatch\n");
                        return_val = -EACCES;
                        set_fs(oldFs);
                        sprintf(log, "%s\n", "Encrypt/Decrypt failed!\n Password used for encryption is not the same password");
                        print_write_log(log, log_file, 0);
                        goto file_cleanup;
                }
        }

        do {
                /* encrypt condition */
                if (enc_flag == 1) {
                        // read buffer
                        read_status = vfs_read(input_file, buf, write_size, &(input_file->f_pos));
                        if (read_status < 0) {
                                return_val = -EIO;
                                set_fs(oldFs);
                                sprintf(log, "%s\n", "Encrypt/Decrypt failed!\n Read/Write operation failed");
                                print_write_log(log, log_file, 0);
                                goto file_cleanup;
                        }

                        if (read_status < write_size) {
                                write_size = read_status;
                                EOF_flag = true;
                        }

                        // encrypt buffer
                        ret_status = test_skcipher(hashed_key, buf, MD5_KEY_LEN, write_size, 1);
                        if (ret_status) {
                                return_val = -ret_status;
                                sprintf(log, "%s\n", "Encrypt/Decrypt failed!\n Encyption failed");
                                print_write_log(log, log_file, 0);
                                goto file_cleanup;
                        }

                        // write encrypted buffer
                        write_status = vfs_write(output_file, buf, write_size, &(output_file->f_pos));
                        if (write_status < 0) {
                                return_val = -EIO;
                                set_fs(oldFs);
                                sprintf(log, "%s\n", "Encrypt/Decrypt failed!\n Read/Write operation failed");
                                print_write_log(log, log_file, 0);
                                goto file_cleanup;
                        }
                } /* decrypt condition */
                else if (enc_flag == 2) {
                        // read buffer
                        read_status = vfs_read(input_file, buf, write_size, &(input_file->f_pos));
                        if (read_status < 0) {
                                return_val = -EIO;
                                set_fs(oldFs);
                                sprintf(log, "%s\n", "Encrypt/Decrypt failed!\n Read/Write operation failed");
                                print_write_log(log, log_file, 0);
                                goto file_cleanup;
                        }

                        if (read_status < write_size) {
                                write_size = read_status;
                                EOF_flag = true;
                        }

                        // decrypt buffer
                        ret_status = test_skcipher(hashed_key, buf, MD5_KEY_LEN, write_size, 2);
                        if (ret_status) {
                                return_val = -ret_status;
                                sprintf(log, "%s\n", "Encrypt/Decrypt failed!\n Decryption failed");
                                print_write_log(log, log_file, 0);
                                goto file_cleanup;
                        }

                        // write decrypted buffer
                        write_status = vfs_write(output_file, buf, write_size, &(output_file->f_pos));
                        if (write_status < 0) {
                                set_fs(oldFs);
                                sprintf(log, "%s\n", "Encrypt/Decrypt failed!\n Read/Write operation failed");
                                print_write_log(log, log_file, 0);
                                goto file_cleanup;
                        }
                }
        } while (!EOF_flag);
        printk("Encrypt/Decrypt complete");

        // successful copy/encrypt/decrypt
        if (EOF_flag) {
                sprintf(log, "%s: %s\n", "Successfully encrypted/decrypted the file to", output_filename);
                print_write_log(log, log_file, 0);

                return_val = 0;
                set_fs(oldFs);

                filp_close(input_file, NULL);
                return_val = safe_unlink(input_file);
                if (return_val != 0) {
                        sprintf(log, "%s: %s\n", "deletion failed for file", input_filename);
                        print_write_log(log, log_file, 1);
                        goto file_cleanup;
                } else {
                        sprintf(log, "%s: %s\n", "Successfully deleted the file", input_filename);
                        print_write_log(log, log_file, 0);
                        goto out;
                }
        }
file_cleanup:
        sprintf(log, "%s: %s\n", "Encryption/Decryption failed for the file", input_filename);
        print_write_log(log, log_file, 2);
        filp_close(output_file, 0);

        unlink_status = safe_unlink(output_file);
        if (unlink_status < 0)
                return_val = -EBUSY;
out:
        if (log_filename != NULL)
                kfree(log_filename);
        if (rehashed_key != NULL)
                kfree(rehashed_key);
        if(infile_props != NULL)
                kfree(infile_props);
        if (hashed_key != NULL)
                kfree(hashed_key);
        if (log != NULL)
                kfree(log);
        if (buf)
                kfree(buf);
        if (log_file)
                filp_close(log_file, 0);
        if (output_file)
                filp_close(output_file, 0);
        if (input_file)
                filp_close(input_file, 0);
        return return_val;
}

/********************* Operation to get stat of the files************************/
/**
 * @brief Obtain formatted date for given timespec64
 *
 * @param time timespec64
 * @param formatted_date formatted date is inserted into this
 * @return char*
 *
 * @source https://stackoverflow.com/questions/47532135/retrieve-linux-time-using-struct-timespec
 */
int get_formatted_date(char* formatted_date, struct timespec64 time)
{
        struct rtc_time tm;
        int minutes = 0;
        unsigned long sec = 0;
        unsigned long ns = 0;

        if(formatted_date == NULL) {
                pr_err("Invalid formatted_date pointer");
                return -EINVAL;
        }
        minutes = sys_tz.tz_minuteswest + 4;

        sec = (unsigned long ) time.tv_sec;
        sec -= (minutes * 60 * 60);
        ns = time.tv_nsec;
        rtc_time_to_tm(sec, &tm);

        sprintf(formatted_date, "%02d-%02d-%04d %02d:%02d:%02d.%05ld -%04d",
                tm.tm_mon + 1, tm.tm_mday, tm.tm_year + 1900, tm.tm_hour, tm.tm_min, tm.tm_sec, ns, minutes*100);

        return 0;
}

/**
 * @brief The function to get stat of multiple files
 *
 * @param job job details of the operation
 * @return int
 *
 * @source https://docs.huihoo.com/doxygen/linux/kernel/3.7/structkstat.html
 */
int stat_multiple_files(struct work_queue_job *job)
{
        int return_val = 0;
        int ret_status = 0;
        int i;

        char *log_filename = NULL;
        char *log_buf = NULL;
        struct file *log_file = NULL;
        struct kstat *file_props = NULL;

        char **file_names = job->filenames, *formatted_date=NULL;
        int number_of_files = job->number_of_files;
        int job_id = job->id;
        uid_t user_uid = job->uid;
        gid_t user_gid = job->gid;

        /* ------------------------- logging --------------------------- */
        log_filename = kmalloc(MAX_PATH_SIZE, GFP_KERNEL);
        if (log_filename == NULL) {
                pr_err("Error allocating space for log_filename\n");
                return_val = -ENOMEM;
                goto out;
        }
        sprintf(log_filename, "%s%d", JOB_OUTPUT_PATH, job_id);
        log_file = filp_open(log_filename, O_WRONLY | O_CREAT | O_TRUNC, 0);
        if (!log_file || IS_ERR(log_file)) {
                pr_err("Error opening the output file to store the data\n");
                if(!log_file)
                        return_val = -ENOENT;
                else
                        return_val = PTR_ERR(log_file);
                goto out;
        }
        log_buf = kmalloc(MAX_LOG_SIZE, GFP_KERNEL);
        if (log_buf == NULL) {
                pr_err("Error allocating space for log file output\n");
                return_val = -ENOMEM;
                goto out;
        }
        /* ------------------------------------------------------------- */
        formatted_date = kmalloc(128, GFP_KERNEL);
        if (formatted_date == NULL) {
                return_val = -ENOMEM;
                sprintf(log_buf, "%s\n", "Encrypt/Decrypt failed!\n Insufficent memory");
                print_write_log(log_buf, log_file, 2);
                goto out;
        }
        file_props = kmalloc(sizeof(struct kstat), GFP_KERNEL);
        if (file_props == NULL) {
                return_val = -ENOMEM;
                sprintf(log_buf, "%s\n", "Encrypt/Decrypt failed!\n Insufficent memory");
                print_write_log(log_buf, log_file, 2);
                goto out;
        }

        i = 0;
        for(; i<number_of_files; i++) {
                char* cur_filename = file_names[i];
                sprintf(log_buf, "%d: %s %s\n", i+1, "Getting stat for file - ", cur_filename);
                write_file_util(log_file, log_buf);

                ret_status = vfs_stat(cur_filename, file_props);
                if (ret_status) {
                        sprintf(log_buf, "\t%s\n", "Filename invalid or file not present\n");
                        write_file_util(log_file, log_buf);
                        continue;
                }

                // validate user access to input file
                if (user_uid != file_props->uid.val || user_gid != file_props->gid.val) {
                        sprintf(log_buf, "%s %s\n", "Stat failed!\n User do not have access to file", cur_filename);
                        print_write_log(log_buf, log_file, 0);
                        continue;
                }

                // uid and gid
                sprintf(log_buf, "\tuid: %d;\t\tgid: %d\n", file_props->uid.val, file_props->gid.val);
                write_file_util(log_file, log_buf);

                //permissions
                sprintf(log_buf, "%s%s%s%s%s%s%s%s%s%s%s\n", "\tAccess: ", (S_ISDIR(file_props->mode)) ? "d" : "-",
                        (file_props->mode & S_IRUSR) ? "r" : "-", (file_props->mode & S_IWUSR) ? "w" : "-",
                        (file_props->mode & S_IXUSR) ? "x" : "-", (file_props->mode & S_IRGRP) ? "r" : "-",
                        (file_props->mode & S_IWGRP) ? "w" : "-", (file_props->mode & S_IXGRP) ? "x" : "-",
                        (file_props->mode & S_IROTH) ? "r" : "-", (file_props->mode & S_IWOTH) ? "w" : "-",
                        (file_props->mode & S_IXOTH) ? "x" : "-");
                write_file_util(log_file, log_buf);

                // inode number, blocks and size
                sprintf(log_buf, "\tinode-number: %lld;\tblocks: %lld;\ttotal-size: %lld\n",
                        file_props->ino, file_props->blocks, file_props->size);
                write_file_util(log_file, log_buf);

                // dates
                get_formatted_date(formatted_date, file_props->atime);
                sprintf(log_buf, "\tlast-access-date: %s\n", formatted_date);
                write_file_util(log_file, log_buf);
                get_formatted_date(formatted_date, file_props->mtime);
                sprintf(log_buf, "\tlast-modify-date: %s\n", formatted_date);
                write_file_util(log_file, log_buf);
                get_formatted_date(formatted_date, file_props->ctime);
                sprintf(log_buf, "\tlast-change-date: %s\n", formatted_date);
                write_file_util(log_file, log_buf);
                get_formatted_date(formatted_date, file_props->btime);
                sprintf(log_buf, "\tbirth-date: %s\n", formatted_date);
                write_file_util(log_file, log_buf);

                sprintf(log_buf, "stat for file %s complete\n\n", cur_filename);
                write_file_util(log_file, log_buf);
        }
        sprintf(log_buf, "stat job complete!\n");
        print_write_log(log_buf, log_file, 0);

out:
        if (file_props != NULL)
                kfree(file_props);
        if (log_buf != NULL)
                kfree(log_buf);
        if(formatted_date != NULL)
                kfree(formatted_date);
        if (log_filename != NULL)
                kfree(log_filename);
        if (log_file)
                filp_close(log_file, 0);
        return return_val;
}

/*********************Operation to compress/decompress the file************************/

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
        mm_segment_t prev_fs;
        int bytes;
        prev_fs = get_fs();
        set_fs(KERNEL_DS);
        bytes = vfs_read(in_file, buf, count, pos);
        if (bytes < 0) {
                printk("vfs_read() - Error in reading\n Cleared partially written file\n");
                set_fs(prev_fs);
                return safe_unlink(out_file);
        }
        set_fs(prev_fs);
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
        mm_segment_t prev_fs;
        int bytes;
        prev_fs = get_fs();
        set_fs(KERNEL_DS);
        bytes = vfs_write(file, buf, count, pos);
        if (bytes < 0) {
                printk("vfs_write() - Error in writing\n Cleared partially written file\n");
                set_fs(prev_fs);
                return safe_unlink(file);
        }
        set_fs(prev_fs);
        return bytes;
}
/**
 * @brief Utility function to compress/decompress a file
 *
 * @param in_buffer The pointer of a char buffer to be compressed/decompressed
 * @param in_buffer_len The pointer of a char buffer to be compressed/decompressed
 * @param out_buffer The pointer of a char buffer to be compressed/decompressed
 * @param out_buffer_len The pointer of a char buffer to be compressed/decompressed
 * @param flag The flag which represents to perform compression or decompression
 * @return int
 *
 * @source https://elixir.bootlin.com/linux/latest/source/crypto/testmgr.c#L3206
 */
int utility_compress_decompress(char *in_buffer, int in_buffer_len, char *out_buffer, int *out_buffer_len, int flag)
{
        int err = 0;
        struct crypto_comp *tfm;
        char *crypto_algo = "deflate";
        if(flag == 1) {
                *out_buffer_len = COMPRESSION_BUFFER_SIZE;
        }else{
                *out_buffer_len = BUFFER_SIZE;
        }

        tfm = crypto_alloc_comp(crypto_algo, 0, 0);
        if (IS_ERR(tfm)) {
                err = PTR_ERR(tfm);
                pr_err("Error - Crypto comp not allocated\n");
                goto out;
        }
        if(flag == 1) {
                memset(out_buffer, 0, COMPRESSION_BUFFER_SIZE);
                err = crypto_comp_compress(tfm, in_buffer, in_buffer_len, out_buffer, out_buffer_len);

        }else{
                memset(out_buffer, 0, BUFFER_SIZE);
                err = crypto_comp_decompress(tfm, in_buffer, in_buffer_len, out_buffer, out_buffer_len);

        }
        if (err) {
                pr_err("compression Failed\n");
                crypto_free_comp(tfm);
                goto out;
        }

        printk("dlen = %d\n", *out_buffer_len);
        crypto_free_comp(tfm);
out:
        return err;
}
/**
 * @brief The function to compress/decompress a file
 *
 * @param in_filename The pointer of a char buffer which has filepath of the file to be compressed/decompressed
 * @param flag The flag which represents to perform compression or decompression
 * @param job_id The ID of the job
 * @return int
 *
 * @source https://elixir.bootlin.com/linux/latest/source/crypto/testmgr.c#L3206
 */
int compress_decompress_file(struct work_queue_job *job, int flag)
{
        int err = 0;
        int bytes = 0;
        struct file *in_file_fp = NULL;
        struct file *out_file_fp = NULL;
        struct file *log_fo=NULL;
        char *in_buffer = NULL;
        char *out_buffer = NULL;
        char *out_filename = NULL;
        char *log = NULL, *in_filename;
        int in_filename_len;
        int out_filename_len;
        int extn_len;
        int out_buffer_len = 0, job_id;
        struct kstat *file_props = NULL;

        if(job == NULL){
                pr_err("job is null\n");
                return -EINVAL;
        }

        if(flag == 1) {
                extn_len = 8;
        }else{
                extn_len = 5;
        }
        job_id = job->id;
        in_filename = job->infile;
        if(in_filename == NULL || strlen(in_filename)==0) {
                pr_err("input file name cannot be null or empty\n");
                return -EINVAL;
        }
        in_filename_len = strlen(in_filename);
        out_filename_len = in_filename_len + extn_len;

        out_filename = kmalloc(out_filename_len + 1, GFP_KERNEL);
        if (!out_filename) {
                pr_err("Error allocating space for output file\n");
                err = -ENOMEM;
                goto out;
        }

        strncpy(out_filename, in_filename, in_filename_len);
        out_filename[in_filename_len] = '\0';
        if(flag == 1) {
                strcat(out_filename, ".deflate");
        }else{
                strcat(out_filename,".dcmp");
        }
        out_filename[out_filename_len] = '\0';

        printk("in dochecks, inp file = %s\n", in_filename);
        in_buffer = kmalloc(BUFFER_SIZE, GFP_KERNEL);
        if(!in_buffer) {
                pr_err("Memory not allocated\n");
                err = -ENOMEM;
                goto out;
        }
        if(flag == 1) {
                out_buffer = kmalloc(COMPRESSION_BUFFER_SIZE, GFP_KERNEL);
        }else{
                out_buffer = kmalloc(BUFFER_SIZE, GFP_KERNEL);

        }
        if(!out_buffer) {
                pr_err("Memory not allocated\n");
                err = -ENOMEM;
                goto out;
        }
        in_file_fp  = filp_open(in_filename, O_RDONLY, 0);
        if (!in_file_fp || IS_ERR(in_file_fp)) {
                printk("Files %s does not exist\n", in_filename);
                err = PTR_ERR(in_file_fp);
                goto out;
        }
        out_file_fp  = filp_open(out_filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (!out_file_fp || IS_ERR(out_file_fp)) {
                printk("Files %s does not exist\n", out_filename);
                err = PTR_ERR(out_file_fp);
                goto out;
        }

        log = kmalloc(MAX_LOG_SIZE, GFP_KERNEL);
        if (log == NULL) {
                pr_err("Error allocating space for log file output\n");
                err = -ENOMEM;
                goto out;
        }
        err = create_log_file(&log_fo, job_id);
        if(log_fo == NULL) {
                pr_err("log file descriptor is NULL");
                goto out;
        }

        //for file_props
        file_props = kmalloc(sizeof(struct kstat), GFP_KERNEL);
        if (file_props == NULL) {
                err = -ENOMEM;
                sprintf(log, "%s\n", "Deletion of multiple files failed due to insufficent memory");
                print_write_log(log, log_fo, 0);
                goto out;
        }

        err = vfs_stat(in_filename, file_props);
        if (err) {
                sprintf(log, "\t%s\n", "Filename invalid or file not present\n");
                print_write_log(log, log_fo, 1);
                goto out;
        }

        // validate user access to input file
        if (job->uid != file_props->uid.val || job->gid != file_props->gid.val) {
                sprintf(log, "%s: %s\n", "User do not have access to file", in_filename);
                print_write_log(log, log_fo, 1);
                err = -EACCES;
                goto out;
        }

        printk("file opened\n");
        while (1) {
                bytes = utility_read(in_file_fp, out_file_fp, in_buffer, BUFFER_SIZE, &in_file_fp->f_pos);
                if (bytes == 0)
                        break;
                if (bytes < 0) {
                        printk("error in reading file\n");
                        err = -ECANCELED;
                        break;
                }
                printk("deflate compression - bytes read - %d\n", bytes);
                if(flag == 1) {
                        err = utility_compress_decompress(in_buffer, bytes, out_buffer, &out_buffer_len,1);
                }else{
                        err = utility_compress_decompress(in_buffer, bytes, out_buffer, &out_buffer_len,2);

                }
                if (err) {
                        safe_unlink(out_file_fp);
                        break;
                }
                out_buffer[out_buffer_len] = '\0';
                bytes = utility_write(out_file_fp, out_buffer, out_buffer_len, &out_file_fp->f_pos);
                if (bytes < 0) {
                        printk("error in writing file\n");
                        err = -ECANCELED;
                        break;
                }
        }

        if(err==0) {
                if(flag == 1)
                        sprintf(log, "%s: %s\n", "Successfully compressed the file", in_filename);
                else
                        sprintf(log, "%s: %s\n", "Successfully decompressed the file", in_filename);
                print_write_log(log, log_fo, 0);
        } else {
                if(flag == 1)
                        sprintf(log, "%s: %s\n", "Error in compressing the file", in_filename);
                else
                        sprintf(log, "%s: %s\n", "Error in decompressing the file", in_filename);
                print_write_log(log, log_fo, 2);
        }

out:

        if(log!=NULL)
                kfree(log);
        if (file_props != NULL)
                kfree(file_props);
        if (log_fo)
                filp_close(log_fo, NULL);
        if(out_filename)
                kfree(out_filename);
        if(in_buffer)
                kfree(in_buffer);
        if(out_buffer)
                kfree(out_buffer);
        if (in_file_fp)
                filp_close(in_file_fp, NULL);
        if (out_file_fp)
                filp_close(out_file_fp, NULL);
        return err;
}