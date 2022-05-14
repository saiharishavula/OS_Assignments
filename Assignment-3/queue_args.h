#ifndef QUEUE_ARGS_H
#define QUEUE_ARGS_H

/* Job Type argument to be passed to syscall */
typedef enum job_type {
        POLL,
        DELETE,
        RENAME,
        STAT,
        CONCAT,
        HASH,
        ENCRYPT,
        DECRYPT,
        LIST_CURRENT_JOBS,
        SET_JOB_PRIORITY,
        DELETE_JOB,
        COMPRESS,
        DECOMPRESS
}job_type;

typedef enum job_priority {
        LOW,
        MEDIUM,
        HIGH
} job_priority;

typedef struct {
        job_type job;
        int number_of_files;
        char **file_names;
        char *input_filename;
        char *output_filename;
        char *encryption_key;
        int job_id;
        int priority;
        void *private_data;
} QueueArgs;

#endif
