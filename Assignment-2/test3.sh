#!/bin/sh
# restore a non-encrypted file in .stb folder to user CWD
set -x
./stbctl -u mnt/stbfs/.stb/0000-01649471935432315955-test1.enc
retval=$?
if test $retval != 0 ; then
	echo stbctl failed with error: $retval
	exit $retval
else
	echo stbctl program succeeded
fi
#now verify that the two files are the same
if cmp test1 large_file ; then
	echo "stbctl: input and output files contents are the same"
	exit 0
else
	echo "stbctl: input and output files contents DIFFER"
	exit 1
fi
