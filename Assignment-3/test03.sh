#!/bin/sh
# test deletion of multiple files
set -x
echo "file1 to delete" >d1
echo "file2 to delete" >d2
echo "file2 to delete" >d3

./xhw3 -u d1 d2 d3
retval=$?
# perform deletion of multiple files
if test $retval != 0 ; then
        echo deletion of multiple files failed with error: $retval
        exit $retval
else
        echo deletion of multiple files succeeded
fi

sleep 7

FILE=d1
if test -f "$FILE"; then
    echo "deletion of d1 failed"
else
    echo "deletion of d1 succeeded"
fi

FILE=d2
if test -f "$FILE"; then
    echo "deletion of d2 failed"
else
    echo "deletion of d2 succeeded"
fi

FILE=d3
if test -f "$FILE"; then
    echo "deletion of d3 failed"
else
    echo "deletion of d3 succeeded"
fi