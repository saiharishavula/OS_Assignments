#include "constants.h"
#include "queue_args.h"

struct work_queue_job {
        int id;
        uid_t uid;
        gid_t gid;
        job_type type;
        job_priority priority;
        int number_of_files;
        char **filenames;
        char *infile;
        char *outfile;
        char *encryption_key;
        struct delayed_work d_work;
};

struct h_node {
        int job_id;
        int delete;
        struct work_queue_job *job;
        struct hlist_node node;
};

struct work_queue {
        struct workqueue_struct *wq_struct;
        struct mutex mutex;
        atomic_t size;
};

bool exit_program;
struct work_queue *wq;
// for throttling the job_queue
static wait_queue_head_t producer_wait_queue;
atomic_t producer_wait_queue_count;
