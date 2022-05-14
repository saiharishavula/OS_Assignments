#!/bin/sh
# test complete encryption and decryption functionalities
set -x
content="This is a test file to test encryption and decryption"
# echo $content
echo $content >e_in.test.$$
/bin/rm -f e_out.test.$$
./xhw3 -p "shortpassword" -e e_in.test.$$ e_out.test.$$
retval=$?
# perform encryption from e_in file and save encrypted file in e_out file
if test $retval != 0 ; then
        echo encryption failed with error: $retval
        exit $retval
else
        echo encryption succeeded
fi

# sleep to complete the action
sleep 7

# perform decryption from e_out and save it to d_out file
./xhw3 -p "shortpassword" -d e_out.test.$$ d_out.test.$$
retval=$?
if test $retval != 0 ; then
        echo decryption failed with error: $retval
        exit $retval
else
        echo decryption succeeded
fi

# sleep to complete the action
sleep 7

postdecr=$(cat d_out.test.$$)
# echo $postdecr
# compare the contenets of d_out file with e_in file
if test "$content" = "$postdecr"; then
        echo "TEST PASSED. input and decrypted file contents are same"
        exit 0
else
        echo "TEST FAILED. input and decrypted file contents are varying"
        exit 1
fi
