#!/bin/sh
# test renaming of multiple files
set -x
content1="file1 to rename"
echo $content1 >r1

content2="file2 to rename"
echo $content2 >r2

content3="file3 to rename"
echo $content3 >r3

./xhw3 -r r1 r1a r2 r2a r3 r3a 
retval=$?
# perform renaming of multiple files
if test $retval != 0 ; then
        echo renaming of multiple files failed with error: $retval
        exit $retval
else
        echo renaming of multiple files succeeded
fi

# sleep to complete the action
sleep 7

FILE1=r1 
FILE2=r1a
postren=$(cat r1a)
if [ -f "$FILE1" -a ! -f "$FILE2" ]; then
    echo "renaming of r1 to r1a failed"
elif test "$content1" = "$postren"; then
    echo "renaming of r1 to r1a succeeded"
else
    echo "renaming of r1 to r1a failed"
fi

FILE1=r2 
FILE2=r2a
postren=$(cat r2a)
if [ -f "$FILE1" -a ! -f "$FILE2" ]; then
    echo "renaming of r2 to r2a failed"
elif test "$content2" = "$postren"; then
    echo "renaming of r2 to r2a succeeded"
else
    echo "renaming of r2 to r2a failed"
fi

FILE1=r3
FILE2=r3a
postren=$(cat r3a)
if [ -f "$FILE1" -a ! -f "$FILE2" ]; then
    echo "renaming of r3 to r3a failed"
elif test "$content3" = "$postren"; then
    echo "renaming of r3 to r3a succeeded"
else
    echo "renaming of r3 to r3a failed"
fi