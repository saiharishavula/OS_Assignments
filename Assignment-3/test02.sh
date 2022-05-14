#!/bin/sh
# test hash of the files, hash of same content files are same
rmmod sys_async_queue
rm -r /usr/src/hw3-cse506g05/CSE-506/.joboutputs
insmod sys_async_queue.ko

set -x
content="This is a test file to test hash functionality"
# echo $content
echo $content >hash_in.test.$$
./xhw3 -h hash_in.test.$$
retval=$?
# perform hash of the hash_in.test.$$
if test $retval != 0 ; then
        echo hash computation failed with error: $retval
        exit $retval
else
        echo hash computation succeeded
fi
# sleep to complete the action
sleep 7

echo $content >hash_in1.test.$$
./xhw3 -h hash_in1.test.$$
retval=$?
# perform hash of the hash_in1.test.$$
if test $retval != 0 ; then
        echo hash computation failed with error: $retval
        exit $retval
else
        echo hash computation succeeded
fi

# sleep to complete the action
sleep 7

hash1=$(cat /usr/src/hw3-cse506g05/CSE-506/.joboutputs/0)
hash2=$(cat /usr/src/hw3-cse506g05/CSE-506/.joboutputs/1)

if test "$hash1" = "$hash2"; then
    echo "Test Passed. Hash of the files with same content are same."
else
    echo "Test Failed. Hash of the files with same content are different."
fi