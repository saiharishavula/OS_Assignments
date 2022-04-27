#!/bin/sh
# restore a non-encrypted file in .stb folder to user CWD
set -x
./stbctl -u mnt/stbfs/.stb/file-name
retval=$?
if test $retval != 0 ; then # as the program should fail
    echo stbctl program succeeded
else
	echo stbctl failed with error
	exit $retval
fi