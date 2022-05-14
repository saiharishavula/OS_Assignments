#!/bin/sh
# test renaming of multiple files
set -x
content1="file1 to concatenate"
echo $content1 >c1

content2="file2 to concatenate"
echo $content2 >c2

content3="file3 to concatenate"
echo $content3 >c3

./xhw3 -c c1 c2 c3 c4
retval=$?
# perform concatenation of multiple files
if test $retval != 0 ; then
        echo concatenation of multiple files failed with error: $retval
        exit $retval
else
        echo concatenation of multiple files succeeded
fi

# sleep to complete the action
sleep 7

content4='file1 to concatenate
file2 to concatenate
file3 to concatenate'
echo $content4
postconcat=$(cat c4)
if test "$content4" = "$postconcat"; then
        echo "TEST PASSED. all files content concatenated"
        exit 0
else
        echo "TEST FAILED. concatenation failed"
        exit 1
fi