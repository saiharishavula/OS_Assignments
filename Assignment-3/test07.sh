#!/bin/sh
# test complete compression and decompression functionalities
set -x
content="This is a test file to test compression and decompression"
# echo $content
echo $content >e_in.test.$$
/bin/rm -f e_out.test.$$
./xhw3 -a e_in.test.$$
retval=$?
# perform compression from e_in file and save compressed file in e_in.deflate file
if test $retval != 0 ; then
        echo compression failed with error: $retval
        exit $retval
else
        echo compression succeeded
fi

# sleep to complete the action
sleep 7

# perform decompression from e_in.deflate and save it to e_in.deflate.dcmp file
./xhw3 -b e_in.test.$$.deflate
retval=$?
if test $retval != 0 ; then
        echo decompression failed with error: $retval
        exit $retval
else
        echo decompression succeeded
fi

# sleep to complete the action
sleep 7

# now verify that the two files are the same
if cmp e_in.test.$$ e_in.test.$$.deflate.dcmp ; then
	echo "TEST PASSED: input and output files contents are the same"
	exit 0
else
	echo "TEST FAILED: input and output files contents DIFFER"
	exit 1
fi

