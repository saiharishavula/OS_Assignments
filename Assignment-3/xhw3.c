#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <openssl/sha.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <pthread.h>

#include "queue_args.h"
#include "constants.h"

#ifndef __NR_async_queue
#error async_queue system call not defined
#endif

/* -------------------- Only for testing ----------------------- */
void print(QueueArgs args)
{
        printf("Syscall Args:\n");
        printf("\t job type: %d\n", args.job);
        printf("\t number_of_files: %d\n", args.number_of_files);
        printf("\t job id: %d\n", args.job_id);
        printf("\t priority: %d\n", args.priority);
        printf("\t input_filename: %s\n", args.input_filename);
        printf("\t output_filename: %s\n", args.output_filename);
        printf("\t encryption_key: %s\n", args.encryption_key);
        printf("\t Filenames:\n");
        int i = 0;
        for(; i<args.number_of_files; i++) {
                printf("\t\t file---> %s\n", args.file_names[i]);
        }
        printf("\n");
}
/* ------------------------------------------------------------- */

/* ------------------------------------------------------------- */
/**
* @brief The helper function for user program usage instructions
*
*/
void print_info()
{
        printf("User program usage instructions:\n");
        printf("\t Base command: ./xhw3 <args>\n");

        printf("Arguments:\n");
        // unlink
        printf("\t-u: unlink (or) delete multiple files\n");
        printf("\t\t Additional arguments: <filename(s)> to delete\n");
        printf("\t\t Example: ./xhw3 -u file1 file2 file3\n\n");
        // rename files
        printf("\t-r: rename multiple files\n");
        printf("\t\t Additional arguments: <infile(s) outfile(s)> to rename\n");
        printf("\t\t Example: ./xhw3 -r file1_original file1_final file2_original file2_final\n\n");
        // stat files
        printf("\t-s: get file stat for multiple files\n");
        printf("\t\t Additional arguments: <filename(s)> to get stat\n");
        printf("\t\t Example: ./xhw3 -s file1 file2 file3\n\n");
        // concatenate files
        printf("\t-c: concatenate multiple files into a single file\n");
        printf("\t\t Additional arguments: <filename(s)> to concatenate\n");
        printf("\t\t NOTE: number of files should be greater than 1 and the last filename is the name of output file\n");
        printf("\t\t Example: ./xhw3 -c file1 file2 outfile\n\n");
        // hash files
        printf("\t-h: compute and return a hash for given file\n");
        printf("\t\t Additional arguments: <filename> to get hash for\n");
        printf("\t\t Example: ./xhw3 -h file_name\n\n");
        // encrypt file
        printf("\t-e: encrypt the given file\n");
        printf("\t\t Additional arguments: -p <encryption_key> <input_filename> <output_filename>\n");
        printf("\t\t NOTE: encryption_key should be between 8 and 16 characters in length\n");
        printf("\t\t Example: ./xhw3 -p MySecretPassKey -e in_file out_file\n\n");
        // decrypt file
        printf("\t-d: decrypt the given file\n");
        printf("\t\t Additional arguments: -p <encryption_key> <input_filename> <output_filename>\n");
        printf("\t\t\t NOTE: encryption_key should be between 8 and 16 characters in length\n");
        printf("\t\t Example: ./xhw3 -p MySecretPassKey -d in_file out_file\n\n");
        // compress file
        printf("\t-a: compress the given file to a smaller file with <input_filename.deflate>\n");
        printf("\t\t Additional arguments: -a <input_filename>\n");
        printf("\t\t Example: ./xhw3 -a in_file\n\n");
        // decompress file
        printf("\t-b: decompress the given .deflate file to <file.deflate.dcmp>\n");
        printf("\t\t Additional arguments: -b  <input_filename.deflate>\n");
        printf("\t\t Example: ./xhw3 -b in_file.deflate\n\n");
        // Job Specific commands
        printf("\t-j: provide job specific commands\n");
        printf("\t\t Additional arguments: 1 ->List all the jobs currently in the queue\n");
        printf("\t\t Additional arguments: 2 <job_id> <priority> ->Set the priority of job <job_id> to <priority>\n");
        printf("\t\t Additional arguments: 3 <job_id> ->Delete the job from the queue (if the job execution has not started yet)\n");
        printf("\t\t NOTE: job_id should be a valid integer and a job_id of a job in queue (Appropriate Error would be returned or else)\n");
        printf("\t\t NOTE: priority of the job should be between 3(High priority) and 1(Low priority)\n");
        printf("\t\t Example to list jobs: ./xhw3 -j 1\n");
        printf("\t\t Example to set priority: ./xhw3 -j 2 121 3\n");
        printf("\t\t Example to delete job: ./xhw3 -j 3 15\n\n");
         // Optional Command
        printf("Other Commands:\n");
        printf("\t-i: Get help on different arguments of user program(xhw3)\n");
        printf("\t-o: Add -o to any Job commands (except queue specific commands) to wait for output from job\n");
        printf("\t\t: This argument can be used to poll for job output continuously till the job completes\n");
        printf("\t-g: To request status for a particular job - poll for job output once\n");
        printf("\t\t Additional option: -g <job_id>\n");
        printf("\t\t Return: Job Status: Completed/In-progress/Waiting and ouput of the job if Job Status is completed\n");
        printf("\t\t Example: ./xhw3 -g 10\n");
        
}

/**
* @brief The Utility function read and print contents of the file
*
* @param filename The name of file to read
* @param job_id The ID of the job
* @return int
*/
int utility_read_file(char *filename, int job_id)
{
        FILE *ptr;
        char *buf;
        // wait for 2 secs for the job to complete writing to file
        sleep(2);
        ptr = fopen(filename, "a+");

        if (NULL == ptr) {
                // file not present, return -1
                return -1;
        }

        printf("Job %d complete\n", job_id);
        printf("Job Output:\n");
        buf = malloc(50);
        if(!buf) {
                printf("No memory to get job output\n");
                return 0;
        }
        while (fgets(buf, 50, ptr) != NULL) {
                printf("%s", buf);
        }

        free(buf);
        fclose(ptr);
        return 0;
}

/**
* @brief The Thread callback function to poll job output
*
* @param p The void pointer which stores the job_id
* @return void pointer
*/
void *poll_output_from_file(void *p)
{
        int job_id = *(int *)p;
        QueueArgs args;
        int rc = 0;
        int count = 0;

        args.job_id = job_id;
        args.job = POLL;
        args.private_data =  (void *)malloc(MAX_PATH_SIZE);
        if(!args.private_data) {
                printf("Insufficent memory to poll output\n");
                printf("Polling Incomplete!\n");
                return NULL;
        }

        // try untill the file is found
        while(true) {
                rc = syscall(__NR_async_queue, (void *)&args);
                if (rc == 0) {
                        rc = utility_read_file((char *)args.private_data, job_id);
                        if(rc == -1) {
                                printf("Job is currently Running!\n");
                        }
                        break;
                }
                else{
                        if(errno == ESRCH || errno == EFAULT) {
                                printf("Error getting Job status!\n");
                                break;
                        } else if(errno = EACCES) {
                                printf("Error! User does not have access to job: %d!\n", job_id);
                                break;
                        }  else if(errno == ENOENT) {
                                // job still in progress;
                                count++;
                                sleep(2);
                                if(count == MAX_POLL_TIME) {
                                        printf("Max polling time reached,stopping polling!\n");
                                        break;
                                }
                        }
                }
        }
        printf("Polling complete!\n");
        if(args.private_data)
                free(args.private_data);
        return NULL;
}
/* ------------------------------------------------------------- */

/**
* @brief main user function for calling the system call
*
* @param argc Number of command line arguments
* @param argv Command line arguments
* @return int
*
* @source https://stackoverflow.com/questions/6450152/getopt-value-stays-null
* @source https://www.geeksforgeeks.org/getopt-function-in-c-to-parse-command-line-arguments/
*/
int main(int argc, char *argv[])
{
        QueueArgs args;
        int i = 0;
        int rc = 0;
        int count = 0;
        int job_id = 0;
        bool enc_dec_flag = false;
        bool compress_flag = false;
        bool poll_output = false;
        bool get_output = false;
        struct stat st = {0};

        args.number_of_files = 0;
        args.file_names = NULL;
        args.input_filename = NULL;
        args.output_filename = NULL;
        args.encryption_key = NULL;
        args.job_id = 0; // job_id will be set by sys_call as a return value
        args.priority = 1; // default priority of a new job
        args.private_data = NULL;

        // user thread for polling output of a job
        pthread_t user_thread;

        char opt;
        while (optind < argc && (opt = getopt(argc, argv, "a:b:u:r:s:c:h:p:e:d:j:i::g:")) != -1) {
                switch (opt) {

                // unlink/delete multiple file
                case 'u':
                        i = 0;
                        if(count != 0) {
                                goto invalid_arg;
                        }
                        args.number_of_files = argc - optind + 1;
                        args.file_names = calloc(args.number_of_files, sizeof(char *));
                        if(!args.file_names) {
                                printf("Insufficient memory to allocate filenames\n");
                                goto out;
                        }
                        optind--;
                        for (; optind < argc && *argv[optind] != '-'; optind++) {
                                args.file_names[i] = malloc(MAX_PATH_SIZE);
                                if(!args.file_names[i]) {
                                        printf("Insufficient memory to allocate filenames\n");
                                        goto out;
                                }
                                realpath(argv[optind], args.file_names[i]);
                                i++;
                        }
                        if (optind != argc) {
                                if(*(argv[optind]+1) == 'o') {
                                        poll_output = true;
                                        optind += 1;
                                        args.number_of_files -= 1;
                                }
                                if(optind != argc) {
                                        goto invalid_arg;
                                }

                        }
                        args.job = DELETE;
                        break;

                // rename multiple files
                case 'r':
                        i = 0;
                        args.number_of_files = argc - optind + 1;
                        if(count != 0) {
                                goto invalid_arg;
                        }
                        args.file_names = calloc(args.number_of_files, sizeof(char *));
                        if(!args.file_names) {
                                printf("Insufficient memory to allocate filenames\n");
                                goto out;
                        }
                        optind--;
                        for (; optind < argc && *argv[optind] != '-'; optind++) {
                                args.file_names[i] = malloc(MAX_PATH_SIZE);
                                if(!args.file_names[i]) {
                                        printf("Insufficient memory to allocate filenames\n");
                                        goto out;
                                }
                                realpath(argv[optind], args.file_names[i]);
                                i++;
                        }
                        if (optind != argc) {
                                if(*(argv[optind]+1) == 'o') {
                                        poll_output = true;
                                        optind += 1;
                                        args.number_of_files -= 1;
                                }
                                if(optind != argc || args.number_of_files % 2 != 0) {
                                        goto invalid_arg;
                                }

                        }
                        args.job = RENAME;
                        break;

                // stat multiple files
                case 's':
                        i = 0;
                        if(count != 0) {
                                goto invalid_arg;
                        }
                        args.number_of_files = argc - optind + 1;
                        args.file_names = calloc(args.number_of_files, sizeof(char *));
                        if(!args.file_names) {
                                printf("Insufficient memory to allocate filenames\n");
                                goto out;
                        }
                        optind--;
                        for (; optind < argc && *argv[optind] != '-'; optind++) {
                                args.file_names[i] = malloc(MAX_PATH_SIZE);
                                if(!args.file_names[i]) {
                                        printf("Insufficient memory to allocate filenames\n");
                                        goto out;
                                }
                                realpath(argv[optind], args.file_names[i]);
                                i++;
                        }
                        if (optind != argc) {
                                if(*(argv[optind]+1) == 'o') {
                                        poll_output = true;
                                        optind += 1;
                                        args.number_of_files -= 1;
                                }
                                if(optind != argc) {
                                        goto invalid_arg;
                                }

                        }
                        args.job = STAT;
                        break;

                // concatenate multiple files to single file
                case 'c':
                        i = 0;
                        args.number_of_files = argc - optind + 1;
                        if(count != 0 || args.number_of_files <= 1) {
                                goto invalid_arg;
                        }
                        args.file_names = calloc(args.number_of_files, sizeof(char *));
                        if(!args.file_names) {
                                printf("Insufficient memory to allocate filenames\n");
                                goto out;
                        }
                        optind--;
                        for (; optind < argc && *argv[optind] != '-'; optind++) {
                                args.file_names[i] = malloc(MAX_PATH_SIZE);
                                if(!args.file_names[i]) {
                                        printf("Insufficient memory to allocate filenames\n");
                                        goto out;
                                }
                                realpath(argv[optind], args.file_names[i]);
                                i++;
                        }
                        if (optind != argc) {
                                if(*(argv[optind]+1) == 'o') {
                                        poll_output = true;
                                        optind += 1;
                                        args.number_of_files -= 1;
                                }
                                if(optind != argc) {
                                        goto invalid_arg;
                                }

                        }
                        args.job = CONCAT;
                        break;

                // compute hash of the input file
                case 'h':
                        if(count != 0) {
                                goto invalid_arg;
                        }
                        args.input_filename = malloc(MAX_PATH_SIZE);
                        if(!args.input_filename) {
                                printf("Insufficient memory to allocate filenames\n");
                                goto out;
                        }
                        realpath(argv[optind - 1], args.input_filename);
                        if (optind != argc) {
                                if(*(argv[optind]+1) == 'o') {
                                        poll_output = true;
                                        optind += 1;
                                }
                                if(optind != argc) {
                                        goto invalid_arg;
                                }
                        }
                        args.job = HASH;
                        break;

                // save the hashed encryption key
                case 'p':
                        if(args.encryption_key || strlen(argv[optind - 1]) < 8
                           || strlen(argv[optind - 1]) > 16) {
                                printf("Invalid Encryption key or multiple keys provided\n");
                                printf("Use ./xhw3 -i for help\n");
                                goto out;
                        }
                        count++;
                        args.encryption_key = malloc(MD5_KEY_LEN);
                        if(!args.encryption_key) {
                                printf("Insufficient memory to allocate memory\n");
                                goto out;
                        }
                        strcpy(args.encryption_key, argv[optind - 1]);
                        if (optind != argc) {
                                if(*(argv[optind]+1) == 'o') {
                                        poll_output = true;
                                        optind += 1;
                                }
                        }
                        break;

                // compress input_file -> output_file
                case 'a':
                        if(compress_flag || optind > argc) {
                                goto invalid_arg;
                        }
                        count++;
                        compress_flag = true;
                        args.input_filename = malloc(MAX_PATH_SIZE);
                        if(!args.input_filename) {
                                printf("Insufficient memory to allocate filenames\n");
                                goto out;
                        }
                        realpath(argv[optind - 1], args.input_filename);
                        args.job = COMPRESS;

                        if (optind != argc) {
                                if(*(argv[optind]+1) == 'o') {
                                        poll_output = true;
                                        optind += 1;
                                }
                                if(optind != argc) {
                                        goto invalid_arg;
                                }
                        }
                        break;

                // decompress input_file -> output_file
                case 'b':
                        if(compress_flag || optind > argc) {
                                goto invalid_arg;
                        }
                        count++;
                        compress_flag = true;
                        args.input_filename = malloc(MAX_PATH_SIZE);
                        if(!args.input_filename) {
                                printf("Insufficient memory to allocate filenames\n");
                                goto out;
                        }
                        realpath(argv[optind - 1], args.input_filename);
                        args.job = DECOMPRESS;

                        if (optind != argc) {
                                if(*(argv[optind]+1) == 'o') {
                                        poll_output = true;
                                        optind += 1;
                                }
                                if(optind != argc) {
                                        goto invalid_arg;
                                }
                        }
                        break;

                // encrypt input_file -> output_file
                case 'e':
                        if(enc_dec_flag || optind+1 > argc) {
                                goto invalid_arg;
                        }
                        count++;
                        enc_dec_flag = true;
                        args.input_filename = malloc(MAX_PATH_SIZE);
                        if(!args.input_filename) {
                                printf("Insufficient memory to allocate filenames\n");
                                goto out;
                        }
                        args.output_filename = malloc(MAX_PATH_SIZE);
                        if(!args.output_filename) {
                                printf("Insufficient memory to allocate filenames\n");
                                goto out;
                        }
                        realpath(argv[optind - 1], args.input_filename);
                        realpath(argv[optind], args.output_filename);
                        args.job = ENCRYPT;

                        if (optind+1 != argc) {
                                if(*(argv[optind+1]+1) == 'o') {
                                        poll_output = true;
                                        optind += 2;
                                }
                        }
                        break;

                // decrypt input_file -> output_file
                case 'd':
                        if(enc_dec_flag || optind+1 > argc) {
                                goto invalid_arg;
                        }
                        count++;
                        enc_dec_flag = true;
                        args.input_filename = malloc(MAX_PATH_SIZE);
                        if(!args.input_filename) {
                                printf("Insufficient memory to allocate filenames\n");
                                goto out;
                        }
                        args.output_filename = malloc(MAX_PATH_SIZE);
                        if(!args.output_filename) {
                                printf("Insufficient memory to allocate filenames\n");
                                goto out;
                        }
                        realpath(argv[optind - 1], args.input_filename);
                        realpath(argv[optind], args.output_filename);
                        args.job = DECRYPT;

                        if (optind+1 != argc) {
                                if(*(argv[optind+1]+1) == 'o') {
                                        poll_output = true;
                                        optind += 2;
                                }
                        }
                        break;

                // job/queue specific commands
                case 'j':
                        if(count != 0) {
                                goto invalid_arg;
                        }
                        count++;
                        // list all the current jobs
                        if(atoi(argv[optind - 1]) == 1) {
                                args.job = LIST_CURRENT_JOBS;
                        }
                        // set the job priority to given value
                        else if(atoi(argv[optind - 1]) == 2) {
                                if (optind + 2 > argc) {
                                        goto invalid_arg;
                                }
                                args.job_id = atoi(argv[optind]);
                                args.priority = atoi(argv[optind + 1])-1;
                                args.job = SET_JOB_PRIORITY;
                                optind += 2;
                        }
                        // delete job from the queue
                        else if(atoi(argv[optind - 1]) == 3){
                                if (optind + 1 > argc) {
                                        goto invalid_arg;
                                }
                                args.job_id = atoi(argv[optind]);
                                args.job = DELETE_JOB;
                                optind += 1;
                        }
                        // none from above then invalid
                        else {
                                goto invalid_arg;
                        }

                        if (optind != argc || args.priority > 2 || args.priority < 0) {
                                goto invalid_arg;
                        }
                        break;

                // get output status of a particular job
                case 'g':
                        if(count != 0 || optind >  argc) {
                                goto invalid_arg;
                        }
                        get_output = true;
                        job_id = atoi(argv[optind-1]);
                        break;

                // print command info
                case 'i':
                        print_info();
                        goto out;

                default:
                        printf("No arguments are passed\n");
                        printf("Use ./xhw3 -i for help\n");
                        goto out;
                }
        }

        // validation
        if(enc_dec_flag) {
                if(!args.encryption_key) {
                        printf("Invalid Arguments - No Encryption Key provided\n");
                        printf("Use ./xhw3 -i for help\n");
                        goto out;
                }
        }
        if(compress_flag && enc_dec_flag) {
                goto invalid_arg;
        }

        // case: get output of a specific job
        if(get_output) {
                args.job_id = job_id;
                args.job = POLL;
                args.private_data = (void *)malloc(MAX_PATH_SIZE);
                if(!args.private_data) {
                        printf("Insufficent memory to get output\n");
                        goto out;
                }

                rc = syscall(__NR_async_queue, (void *)&args);
                if (rc == 0) {
                        rc = utility_read_file((char *)args.private_data, job_id);
                        // job not in queue but no file is generated
                        if(rc == -1)
                                printf("Job is currently Running!\n");
                }
                else{
                        if(errno == ESRCH || errno == EFAULT) {
                                printf("Error getting Job status!\n");
                        } else if(errno = EACCES) {
                                printf("Error! User does not have access to job: %d!\n", job_id);
                        } else if(errno == ENOENT) {
                                // job still in queue;
                                printf("Job is Waiting in the queue\n");
                        }
                }
                goto out;
        }

        // case: list all queued jobs
        if(args.job == LIST_CURRENT_JOBS) {
                args.private_data = (void *)malloc(LIST_JOBS_MAX_SIZE);
                if(!args.private_data) {
                        printf("Insufficent memory to assign to list jobs output\n");
                        goto out;
                }
        }
        // print(args);

        // create the output directory if not exists
        if (stat(JOB_OUTPUT_PATH, &st) == -1) {
                printf("creating job folder\n");
                mkdir("./.joboutputs", 0777);
        }

        // async_queue syscall
        rc = syscall(__NR_async_queue, (void *)&args);
        if (rc == 0) {
                printf("System call success: %d\n", rc);
                if(!(args.job == LIST_CURRENT_JOBS || args.job == SET_JOB_PRIORITY
                     || args.job == DELETE_JOB))
                        printf("Job Submitted to the Queue with job_id: %d\n", args.job_id);
                if(args.job == LIST_CURRENT_JOBS) {
                        printf("Listing all queue jobs: \n");
                        printf("%s\n", (char *)args.private_data);
                        goto out;
                }
        }
        else{
                if(args.job == DELETE || (args.job == SET_JOB_PRIORITY) ) {
                        if(rc == EACCES) {
                                printf("User do not have access to the job id %d\n", args.job_id);
                        } else if(rc == ESRCH || rc == EINPROGRESS) {
                                printf("Job Invalid/Completed/In-progress! Operation skipped\n");
                        } else if(rc == EBADRQC) {
                                printf("Invalid request: new priority is same as old priority\n");
                        } else {
                                printf("Job failed with Error: %d (errno = %d - %s)\n", rc, errno, strerror(errno));
                        }
                } else{
                        printf("System call failed with Error: %d (errno = %d - %s)\n", rc, errno, strerror(errno));
                }
                goto out;
        }

        // case: if polling is enabled
        if(poll_output) {
                // create a new thread to poll the output of the submitted job
                pthread_create(&user_thread, NULL, poll_output_from_file, (void *)&args.job_id);

                printf("Waiting for job output: \n");
                pthread_join(user_thread, NULL);
        }

out:
        if(args.file_names) {
                for(i=0; i<args.number_of_files; i++)
                        free(args.file_names[i]);
                free(args.file_names);
        }
        if(args.encryption_key)
                free(args.encryption_key);
        if(args.input_filename)
                free(args.input_filename);
        if(args.output_filename)
                free(args.output_filename);
        if(args.private_data)
                free(args.private_data);
        exit(0);
invalid_arg:
        printf("Invalid Arguments\n");
        printf("Use ./xhw3 -i for help\n");
        goto out;

}
