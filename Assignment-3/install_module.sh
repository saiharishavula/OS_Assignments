#!/bin/sh
set -x
rmmod sys_async_queue
# remove the old log entries present in the job outputs folder
if [ -d "/usr/src/hw3-cse506g05/CSE-506/.joboutputs" ]; then
    # Control will enter here if $DIRECTORY exists.
    rm -r /usr/src/hw3-cse506g05/CSE-506/.joboutputs
fi
insmod sys_async_queue.ko
