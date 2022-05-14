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
#include <linux/timex.h>
#include <crypto/skcipher.h>
#include <linux/random.h>
#include <linux/hashtable.h>
#include <linux/mutex.h>
#include <linux/delay.h>

#include "async_queue.h"
#include "queue_args.h"
#include "operations.h"

asmlinkage extern long (*sysptr)(void *arg);
DECLARE_HASHTABLE(hmap, SIZE_OF_MAP_BITS);
static int JOB_ID;
/**
* @brief Utility function to free the job
*
* @param job The job to be freed
*/
void utility_free_job(struct work_queue_job *job)
{
        int i = 0;
        if(job) {
                if(job->infile)
                        kfree(job->infile);
                if(job->outfile)
                        kfree(job->outfile);
                if(job->encryption_key)
                        kfree(job->encryption_key);
                if(job->number_of_files > 0 && job->filenames) {
                        for (i=0; i < job->number_of_files; i++) {
                                if (job->filenames[i])
                                        kfree(job->filenames[i]);
                        }
                        kfree(job->filenames);
                }
                kfree(job);
                job = NULL;
        }
}
/**
* @brief Utility function to free the job
*
* @param job The job to be freed
*/
void utility_deepcopy_job(struct work_queue_job *old_job, struct work_queue_job *new_job)
{
        int i=0;
        new_job->id = old_job->id;
        new_job->uid = old_job->uid;
        new_job->gid = old_job->gid;
        new_job->type = old_job->type;
        new_job->priority = old_job->priority;
        new_job->number_of_files = old_job->number_of_files;
        if(old_job->encryption_key){
                new_job->encryption_key = kmalloc(MD5_KEY_LEN, GFP_ATOMIC);
                if(!new_job->encryption_key)
                        goto out;
                strcpy(new_job->encryption_key, old_job->encryption_key);
        }
        if(old_job->infile){
                new_job->infile = kmalloc(MAX_PATH_SIZE, GFP_ATOMIC);
                if(!new_job->infile)
                        goto out;
                strcpy(new_job->infile, old_job->infile);
        }
        if(old_job->outfile){
                new_job->outfile = kmalloc(MAX_PATH_SIZE, GFP_ATOMIC);
                if(!new_job->outfile)
                        goto out;
                strcpy(new_job->outfile, old_job->outfile);
        }
        if (old_job->number_of_files > 0) {
                new_job->filenames = kmalloc(old_job->number_of_files * sizeof(char *), GFP_ATOMIC);
                if(!new_job->filenames) {
                        printk("Insufficient memory to allot to filenames");
                        goto out;
                }
                i = 0;
                for (; i < old_job->number_of_files; i++) {
                        new_job->filenames[i] = kmalloc(MAX_PATH_SIZE, GFP_ATOMIC);
                        if(!new_job->filenames[i]) {
                                printk("Insufficient memory to allot to filenames");
                                goto out;
                        }
                        strcpy(new_job->filenames[i], old_job->filenames[i]);
                }
        }
        return;
out:
        utility_free_job(new_job);
}


/* ------------------- Map Utility Functions ------------------- */
/**
* @brief Utility function to add key into the map
*
* @param job_id The map key stores job_id
* @param job The map value stores pointer of the struct work_queue_job
* @return int
*/
int utility_add_key(int job_id, struct work_queue_job *job)
{
        // printk("utility_add_key");
        int err = 0;
        struct h_node *hnode = kmalloc(sizeof(struct h_node), GFP_ATOMIC);
        if (hnode == NULL) {
                printk("Error - Memory not allocated\n");
                err = -ENOMEM;
                goto out;
        }
        hnode->job_id = job_id;
        hnode->job = job;
        hnode->delete = 0;
        hash_add(hmap, &(hnode->node), hnode->job_id);
        // printk("key added\n");
out:
        return err;
}
/**
* @brief Utility function to get job from the map
*
* @param job_id The map key to retreive its value(job)
* @return pointer of the struct work_queue_job
*/
struct work_queue_job *utility_get_value(int job_id)
{
        // printk("utility_get_value")
        struct h_node *hnode;
        hash_for_each_possible (hmap, hnode, node, job_id) {
                if (job_id == hnode->job_id && hnode->delete==0)
                        return hnode->job;
        }
        return NULL;
}
/**
* @brief Utility function to delete key from the map
*
* @param job_id The job_id to be deleted
* @return int
*/
int utility_delete_key(int job_id)
{
        // printk("utility_delete_key")
        struct h_node *hnode;
        struct h_node *hnode_to_delete = NULL;

        hash_for_each_possible (hmap, hnode, node, job_id) {
                if (job_id == hnode->job_id && hnode->delete==0) {
                        hnode_to_delete = hnode;
                        break;
                }
        }

        if (hnode_to_delete) {
                hnode_to_delete->delete = 1;
                return 0;
        }
        return 1;
}
/**
* @brief Utility function to convert the enum type of job to string
*
* @param job The type of the job
* @return pointer of char
*/
char *utility_getjobfromtype(job_type job)
{
        switch (job)
        {
        case POLL:
                return "POLL";
        case DELETE:
                return "DELETE";
        case RENAME:
                return "RENAME";
        case STAT:
                return "STAT";
        case CONCAT:
                return "CONCAT";
        case HASH:
                return "HASH";
        case ENCRYPT:
                return "ENCRYPT";
        case DECRYPT:
                return "DECRYPT";
        case LIST_CURRENT_JOBS:
                return "LIST_CURRENT_JOBS";
        case SET_JOB_PRIORITY:
                return "SET_JOB_PRIORITY";
        case DELETE_JOB:
                return "DELETE_JOB";
        case COMPRESS:
                return "COMPRESS";
        case DECOMPRESS:
                return "DECOMPRESS";
        default:
                return NULL;
        }
        return NULL;
}
/**
 * @brief Utility function to convert the enum type of priority to string
 *
 * @param job The priority of job
 * @return priority in string
 */
char *utility_getpriorityfromenum(job_priority priority)
{
        switch (priority)
        {
        case LOW:
                return "LOW";
        case MEDIUM:
                return "MEDIUM";
        case HIGH:
                return "HIGH";
        default:
                return NULL;
        }
        return NULL;
}
/**
* @brief The function to show current pending jobs according to user
*
* @param uid The user id
* @return pointer of char which stores information related to jobs
*/
char *op_list_all(uid_t uid)
{
        // printk("utility_list_all")
        char *joblist;
        char *job_info;
        unsigned bkt;
        struct h_node *curr;

        joblist = kmalloc(LIST_JOBS_MAX_SIZE, GFP_ATOMIC);
        if(!joblist) {
                printk("No memory to allot to job info\n");
                return NULL;
        }
        job_info = kmalloc(BUFFER_BLOCK_SIZE, GFP_ATOMIC);
        if(!job_info) {
                kfree(joblist);
                printk("No memory to allot to job info\n");
                return NULL;
        }

        hash_for_each (hmap, bkt, curr, node) {
                // printk("JobID - %d JobType - %d\n", curr->job_id,curr->job->type);
                if(curr->delete==0 && (uid==0 || curr->job->uid==uid)) {
                        sprintf(job_info, "Job-Id: %d;\t Job: %s;\t Priority: %s\n", curr->job_id,
                                utility_getjobfromtype(curr->job->type), utility_getpriorityfromenum(curr->job->priority));
                        strcat(joblist, job_info);
                }
        }
        kfree(job_info);
        return joblist;
}
/* ------------------------------------------------------------- */

/* ------------------- Queue Functionality --------------------- */
/**
* @brief The function to execute the job/work. The thread executes the work
*        based on its operation.
*
* @param work The work to be executed
*/
void utility_delay_function(struct work_struct *work)
{
        //msleep(30000);
        struct work_queue_job *job;
        struct delayed_work *d_work;
        char *hash;
        struct h_node *hnode;
        struct h_node *hnode_to_delete = NULL;
        int ret = 0;

        if (exit_program == 1) {
                printk("Module is unloaded, Job execution is skipped\n");
                return;
        }

        d_work = to_delayed_work(work);
        job = container_of(d_work, struct work_queue_job, d_work);
        printk("Jobid Picked- %d\n", job->id);

        hash_for_each_possible (hmap, hnode, node, job->id) {
                if (job->id == hnode->job_id) {
                        if(hnode->delete == 1) {
                                printk("work deleted\n");
                                goto out;
                        } else {
                               hnode_to_delete = hnode;
                        }
                        break;
                }
        }

        if (hnode_to_delete) {
                hash_del(&(hnode_to_delete->node));
                if(hnode_to_delete)
                        kfree(hnode_to_delete);
        }

        mutex_unlock(&wq->mutex);

        // actual job execution
        switch (job->type) {
        case DELETE:
                // printk("Delete Function\n");
                ret = delete_multiple_files(job);
                break;
        case RENAME:
                // printk("Rename Function\n");
                ret = rename_multiple_files(job);
                break;
        case STAT:
                // printk("Stat Function\n");
                ret = stat_multiple_files(job);
                break;
        case CONCAT:
                // printk("Concatenation Function\n");
                ret = concatenate_files(job);
                break;
        case HASH:
                // printk("Hash Function\n");
                hash = kzalloc(128, GFP_ATOMIC);
                if(hash==NULL) {
                        pr_err("Error allocating space for hash");
                        ret = -ENOMEM;
                        break;
                }
                ret = compute_hash(job, hash);
                if(hash!=NULL) kfree(hash);
                break;
        case ENCRYPT:
                // printk("Encrypt Function\n");
                ret = encrypt_decrypt_file(job, 1);
                break;
        case DECRYPT:
                // printk("Decrypt Function\n");
                ret = encrypt_decrypt_file(job, 2);
                break;
        case COMPRESS:
                // printk("Compress Function\n");
                ret = compress_decompress_file(job, 1);
                break;
        case DECOMPRESS:
                // printk("Decompress Function\n");
                ret = compress_decompress_file(job, 2);
                break;
        default:
                break;
        }
out:
        utility_free_job(job);

        printk("Operation return value: %d\n", ret);
        mutex_lock(&wq->mutex);
        atomic_dec(&wq->size);
        if (atomic_read(&(wq->size)) < WORK_QUEUE_SIZE) {
                wake_up_all(&producer_wait_queue);
        }
        mutex_unlock(&wq->mutex);
}
/**
* @brief The function to enqueue the work into the workqueue. The work is pushed
*        into the workqueue based on its priority.
*
* @param job The job to be pushed
* @return int
*/
int utility_enqueue(struct work_queue_job *job)
{
        // printk("utility_enqueue");
        int err = 0;
        while (1) {
                mutex_lock(&wq->mutex);

                if (atomic_read(&wq->size) >= WORK_QUEUE_SIZE) {
                        mutex_unlock(&wq->mutex);
                        if (atomic_read(&producer_wait_queue_count) <=
                            MAX_PRODUCERS) {
                                atomic_inc(&producer_wait_queue_count);
                                wait_event_interruptible(
                                        producer_wait_queue,
                                        atomic_read(&wq->size) <
                                        WORK_QUEUE_SIZE);
                                atomic_dec(&producer_wait_queue_count);
                                continue;
                        } else {
                                printk("Cannot use more producers\n");
                                err = -ENOSPC;
                                goto out;
                        }
                }

                INIT_DELAYED_WORK(&job->d_work, utility_delay_function);
                utility_add_key(job->id, job);

                switch (job->priority) {
                case LOW:
                        queue_delayed_work(wq->wq_struct, &job->d_work,
                                           LOW_PRIORITY_DELAY);
                        break;
                case MEDIUM:
                        queue_delayed_work(wq->wq_struct, &job->d_work,
                                           MED_PRIORITY_DELAY);
                        break;
                case HIGH:
                        queue_delayed_work(wq->wq_struct, &job->d_work,
                                           HIGH_PRIORITY_DELAY);
                        break;
                default:
                        printk("Error - priority is not correctly given");
                        err = -EINVAL;
                        goto out;
                        break;
                }
                atomic_inc(&wq->size);
                break;
        }
out:
        mutex_unlock(&wq->mutex);
        return err;
}
/**
* @brief The function to delete a job/work from the workqueue. The job/work
*        gets deleted only if current user either root or owner of the job
*
* @param job The job_id of the job to be deleted
* @param uid The current user id
* @return int
*/
int op_delete_job(int job_id, uid_t uid)
{
        // printk("op_delete_job");
        int err = 0;
        struct work_queue_job *job;
        mutex_lock(&wq->mutex);
        job = utility_get_value(job_id);
        if (job == NULL) {
                printk("Error - No work in the map\n");
                mutex_unlock(&wq->mutex);
                err = -ESRCH;
                goto out;
        }
        if((uid != 0) && (job->uid != uid)){
                printk("Current user cannot delete the job\n");
                mutex_unlock(&wq->mutex);
                err = -EACCES;
                goto out;
        }
        err = utility_delete_key(job_id);
        if(err){
                err = -EINPROGRESS;
                goto out;
        }

        atomic_dec(&(wq->size));
        mutex_unlock(&wq->mutex);
        printk("deleting job with id %d\n", job_id);

        //utility_free_job(job);
out:
        return err;

}
/**
* @brief The function to change the priority of a job/work in the workqueue. The priority
*        gets changed only if current user either root or owner of the job
*
* @param job The job_id of the job to be deleted
* @param uid The current user id
* @param new_priority The new priority of the job
* @return int
*/
int op_change_priority(int job_id, uid_t uid, job_priority new_priority)
{
        // printk("op_change_priority");
        int err = 0;
        struct work_queue_job *job;
        struct work_queue_job *new_job;

        mutex_lock(&wq->mutex);
        job = utility_get_value(job_id);

        if (job == NULL) {
                printk("Error - No work in the map\n");
                mutex_unlock(&wq->mutex);
                err = -ESRCH;
                goto out;
        }
        if((uid != 0) && (job->uid != uid)){
                printk("Current user cannot change the priority of the job\n");
                mutex_unlock(&wq->mutex);
                err = -EACCES;
                goto out;
        }

        if (job->priority == new_priority) {
                printk("New Priority is same as Old Priority. Don't do anything\n");
                mutex_unlock(&wq->mutex);
                err = -EBADRQC;
                goto out;
        }

        err = utility_delete_key(job->id);
        if(err) {
                err = -EINPROGRESS;
                goto out;
        }

        new_job = kmalloc(sizeof(struct work_queue_job), GFP_ATOMIC);
        if (!new_job) {
                printk("Memory unavailable for creating a job");
                err = -ENOMEM;
                goto out;
        }
        utility_deepcopy_job(job, new_job);
        mutex_unlock(&wq->mutex);
        new_job->priority = new_priority;

        err = utility_enqueue(new_job);
        if (err) {
                printk("Error - Changing priority - enqueuing a job\n");
                goto out;
        }

out:
        return err;
}
/**
* @brief The function to initialize the workqueue
*
*/
int init_work_queue(void)
{
        int err = 0;
        wq = kmalloc(sizeof(struct work_queue), GFP_ATOMIC);
        if (wq == NULL) {
                err = -ENOMEM;
                goto out;
        }
        wq->wq_struct = create_workqueue("async_queue");
        //wq->wq_struct = kmalloc(sizeof(struct workqueue_struct), GFP_ATOMIC);

        if (wq->wq_struct == NULL) {
                err = -ENOMEM;
                goto out;
        }

        mutex_init(&wq->mutex);
        atomic_set(&wq->size, 0);
out:
        return err;
}
/* ------------------------------------------------------------- */

/**
* @brief Main function for async_queue system call.
*
* @param arg The parameters in user space
* @return long
*/
asmlinkage long async_queue(void __user *arg)
{
        // Populate Args from user space
        QueueArgs *args;
        int i;
        int err;
        int ret_status;
        char *enc_key;
        char **filenames;
        char *infile;
        char *outfile;
        char *output_filename;
        char *list_jobs_output;
        struct work_queue_job *job;

        i = 0;
        err = 0;
        infile = NULL;
        outfile = NULL;
        enc_key = NULL;
        filenames = NULL;
        output_filename = NULL;
        list_jobs_output = NULL;

        args = kmalloc(sizeof(QueueArgs), GFP_ATOMIC);
        if (args == NULL)
                return -ENOMEM;
        ret_status = copy_from_user(args, (struct QueueArgs *)arg,
                                    sizeof(QueueArgs));
        if (ret_status != 0) {
                err = -EINVAL;
                goto out;
        }

        /* ---------------------- Poll systemcall ---------------------- */
        if(args->job == POLL) {
                if(args->job_id > JOB_ID) {
                        printk("Invalid job_id\n");
                        err = -ESRCH;
                        goto out;
                }
                job = utility_get_value(args->job_id);
                if(!job) {
                        printk("Job complete!");
                        // user do not have access to job
                        if(current_uid().val != 0 && current_uid().val != job->uid){
                                printk("current userid doesnot match with job_uid\n");
                                err = -EACCES;
                                goto out;
                        }
                        output_filename = kmalloc(strlen(JOB_OUTPUT_PATH) + 5, GFP_ATOMIC);
                        if(!output_filename) {
                                printk("No memory to allot joboutput filename\n");
                                err = -ENOMEM;
                        }
                        sprintf(output_filename, "%s%d", JOB_OUTPUT_PATH, args->job_id);
                        if (copy_to_user((void *)args->private_data, output_filename, MAX_PATH_SIZE)) {
                                printk("Error returning output filename to user\n");
                                err = -EFAULT;
                        }
                        goto out;
                } else {
                        printk("Job in progress");
                        err = -ENOENT;
                        goto out;
                }
                goto out;
        }
        /* ------------------------------------------------------------- */

        /* ------------------ Argument verification -------------------- */

        // Verify Args:
        // printk("job: %d\n", args->job);
        // printk("number of files: %d\n", args->number_of_files);
        // printk("job_id: %d\n", args->job_id);
        // printk("priority: %d\n", args->priority);

        if (args->input_filename) {
                infile = kmalloc(MAX_PATH_SIZE, GFP_ATOMIC);
                if(!infile) {
                        printk("Insufficient memory to allot to input filename");
                        goto out;
                }
                ret_status = copy_from_user(infile, (char *)args->input_filename, MAX_PATH_SIZE);
                if (ret_status != 0) {
                        err = -EINVAL;
                        goto out;
                }
                // printk("input filename: %s\n", infile);
        }
        if (args->output_filename) {
                outfile = kmalloc(MAX_PATH_SIZE, GFP_ATOMIC);
                if(!outfile) {
                        printk("Insufficient memory to allot to output filename");
                        goto out;
                }
                ret_status = copy_from_user(outfile, (char *)args->output_filename, MAX_PATH_SIZE);
                if (ret_status != 0) {
                        err = -EINVAL;
                        goto out;
                }
                // printk("output filename: %s\n", outfile);
        }
        if (args->encryption_key) {
                enc_key = kmalloc(MD5_KEY_LEN, GFP_ATOMIC);
                if(!enc_key) {
                        printk("Insufficient memory to allot to encryption_key");
                        goto out;
                }
                ret_status = copy_from_user(enc_key, (char *)args->encryption_key, MD5_KEY_LEN);
                if (ret_status != 0) {
                        err = -EINVAL;
                        goto out;
                }
                // printk("encryption key: %s\n", enc_key);
        }
        if (args->number_of_files > 0) {
                filenames = kmalloc(args->number_of_files * sizeof(char *), GFP_ATOMIC);
                if(!filenames) {
                        printk("Insufficient memory to allot to filenames");
                        goto out;
                }
                i = 0;
                for (; i < args->number_of_files; i++) {
                        filenames[i] = kmalloc(MAX_PATH_SIZE, GFP_ATOMIC);
                        if(!filenames[i]) {
                                printk("Insufficient memory to allot to filenames");
                                goto out;
                        }
                        ret_status = copy_from_user(filenames[i],
                                                    (char *)args->file_names[i],
                                                    MAX_PATH_SIZE);
                        if (ret_status != 0) {
                                err = -EINVAL;
                                goto out;
                        }
                        // printk("\t filename: %s\n", filenames[i]);
                }
        }
        /* ------------------------------------------------------------- */

        /* --------------------- Syscall operations -------------------- */
        switch (args->job) {
        case LIST_CURRENT_JOBS:
                // printk("List all Jobs\n");
                list_jobs_output = op_list_all(current_uid().val);
                if(copy_to_user((void *)args->private_data, list_jobs_output, LIST_JOBS_MAX_SIZE)) {
                        printk("Error copying to user\n");
                        err = -EFAULT;
                }
                goto out;
        case SET_JOB_PRIORITY:
                // printk("Change/Set job priority\n");
                err = op_change_priority(args->job_id, current_uid().val, args->priority);
                if (err)
                        printk("change priority operation failed");
                goto out;
        case DELETE_JOB:
                // printk("Deleting the job\n");
                err = op_delete_job(args->job_id, current_uid().val);
                if (err)
                        printk("delete job operation failed");
                goto out;
        default:
                break;
        }

        job = kmalloc(sizeof(struct work_queue_job), GFP_ATOMIC);
        if (!job) {
                printk("Memory unavailable for creating a job");
                err = -ENOMEM;
                goto out;
        }

        job->id = JOB_ID;
        job->uid = current_uid().val;
        job->gid = current_gid().val;
        job->type = args->job;
        job->priority = args->priority;
        job->number_of_files = args->number_of_files;
        job->filenames = filenames;
        job->encryption_key = enc_key;
        job->infile = infile;
        job->outfile = outfile;

        args->job_id = JOB_ID;
        // ToDo: not enqueue in case of error?
        if (copy_to_user((struct QueueArgs *)arg, args, sizeof(QueueArgs))) {
                printk("Error returning job_id to user\n");
        }

        // enqueue the job to async queue for later processing
        utility_enqueue(job);

        JOB_ID += 1;
        JOB_ID %= MAX_JOB_ID;
        /* ------------------------------------------------------------- */

out:
        if (args)
                kfree(args);
        if(output_filename)
                kfree(output_filename);
        if(list_jobs_output)
                kfree(list_jobs_output);
        return err;
}

static int __init init_sys_async_queue(void)
{
        int err = 0;

        err = init_work_queue();
        if (err) {
                printk("Error - Failed while initializing work queue\n");
                goto out;
        }

        JOB_ID = 0;
        hash_init(hmap);
        exit_program = 0;

        init_waitqueue_head(&producer_wait_queue);

        atomic_set(&(producer_wait_queue_count), 0);

        printk("installed new sys_async_queue module\n");
        if (sysptr == NULL)
                sysptr = async_queue;

out:
        return err;
}

static void __exit exit_sys_async_queue(void)
{
        exit_program = 1;

        if (wq) {
                destroy_workqueue(wq->wq_struct);
                kfree(wq);
        }

        if (sysptr != NULL)
                sysptr = NULL;
        printk("removed sys_async_queue module\n");
}

MODULE_LICENSE("GPL");
module_init(init_sys_async_queue);
module_exit(exit_sys_async_queue);