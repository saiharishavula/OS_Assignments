#include <asm/unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include "user_types.h"
#include <openssl/md5.h>
#include <openssl/hmac.h>
#define MIN_PASS_LEN 6
#ifndef __NR_cryptocopy
#error cryptocopy system call not defined
#endif
/**
* @brief Utility function to check the correctness of command line arguments
*
* @param argc cryptocopy_params in user space
* @return bool
*
* @source https://stackoverflow.com/questions/6450152/getopt-value-stays-null
* @source https://www.geeksforgeeks.org/getopt-function-in-c-to-parse-command-line-arguments/
*/
bool utility_check_params(cryptocopy_params *cparams)
{
	if (cparams->flags == 0)
	{
		printf("No operation is specified. One of the operations from Encryption(-e), Decryption(-d), Copy(-c) must be provided. See the help(-h) message on how to use.\n");
	  return false;
	}
	if(cparams->flags == 4 && cparams->keylen != 0)
	{
		printf("Password is not necessary for copy operation. See the help(-h) message on how to use.\n");
		return false;
	}
	if(cparams->infile == NULL && cparams->outfile == NULL)
	{
		printf("Input and Output filenames are not given. See the help(-h) message on how to use.\n");
		return false;
	}
	if(cparams->infile == NULL)
	{
		printf("Input filename is not given. See the help(-h) message on how to use.\n");
		return false;
	}
	if(cparams->outfile == NULL)
	{
		printf("Output filename is not given. See the help(-h) message on how to use.\n");
		return false;
	}
	return true;
}
/**
* @brief main user function for calling the system call
*
* @param argc Number of command line arguments
* @param argv Command line arguments
* @return int
*
* @source https://stackoverflow.com/questions/6450152/getopt-value-stays-null
* @source https://www.geeksforgeeks.org/getopt-function-in-c-to-parse-command-line-arguments/
*/
int main(int argc, char *argv[])
{
   int rc=0;
   cryptocopy_params cparams;
   size_t keybuf_len = 0;
   unsigned char *MD5_hash = NULL;
		cparams.infile = NULL;
		cparams.outfile = NULL;
		cparams.keybuf = NULL;
	  cparams.keylen = 0;
	  cparams.flags = 0;
	  int option;
		bool is_password_given = false;
		bool is_keylen_given = false;
		bool is_encryption_unit_given = false;

	while ((option = getopt (argc, argv, "chedp:l:u:")) != -1)
	{
		switch (option)
		{
			case 'l':
			 if(is_keylen_given == true)
			 {
				 printf("Key length is already provided. See help(-h) message on how to use.\n");
				 rc = 1;
				 goto end;
			 }
			 case 'u':
				if(is_encryption_unit_given == true)
				{
					printf("Encryption unit length is already given. See help(-h) message on how to use.\n");
					rc = 1;
					goto end;
				}
		   case 'c':
			  if(is_password_given == true)
			  {
				  printf("Password should be provided for encryption of a file. See help(-h) message on how to use.\n");
					rc = 1;
				  goto end;
			  }
		    if(cparams.flags != 0)
				{
					printf("Only one operation can be called at a time. See help(-h) message on how to use.\n");
					rc = 1;
					goto end;
				}
	     	cparams.flags = COPY;
				break;
			case 'd':
				if(is_password_given == false)
				{
					printf("Password should be provided for decryption of a file. See help(-h) message on how to use.\n");
					rc = 1;
					goto end;
				}
				if(cparams.flags != 0)
				{
					printf("Only one operation can be called at a time. See help(-h) message on how to use.\n");
					rc = 1;
					goto end;
				}
				cparams.flags = DECRYPTION;
				break;
			case 'e':
				if(is_password_given == false)
				{
					printf("Password should be provided for encryption of a file. See help(-h) message on how to use.\n");
					rc = 1;
					goto end;
				}
				if(cparams.flags != 0)
				{
					printf("Only one operation can be called at a time. See help(-h) message on how to use.\n");
					rc = 1;
					goto end;
				}
				cparams.flags = ENCRYPTION;
				break;
			case 'p':
			  if(is_password_given == true)
				{
					printf("Password can given only once. See help(-h) message on how to use.\n");
					rc = 1;
					goto end;
				}
			  is_password_given = true;
				cparams.keybuf = optarg;
				keybuf_len = strlen(cparams.keybuf);
				if(keybuf_len >= MIN_PASS_LEN)
                                {
				   MD5_hash = (unsigned char *)malloc(sizeof(char) * MD5_KEY_LEN);
				   if(!MD5_hash)
				   {
				        printf("Unable to allocate memory - MD5_hash\n");
								rc = 1;
					goto end;
				   }
				   cparams.keybuf = (char *)MD5((const unsigned char *)cparams.keybuf, keybuf_len, MD5_hash);
				   cparams.keylen = MD5_KEY_LEN;
                                }
				else
				{
					printf("User-level passwords should be at least 6 characters\n");
					rc = 1;
					goto end;
				}
				break;
			case 'h':
				printf("Help - Usage on how to call the system call\n");
				printf("For copy : ./xhw1 -c infile outfile\n");
				printf("For encryption : ./xhw1 -p password -e infile outfile\n");
				printf("For decryption : ./xhw1 -p password -d infile outfile\n");
				rc = 1;
				goto end;
		}
	}
	for(; optind < argc; optind+=2)
	{
	   cparams.infile = argv[optind];
	   cparams.outfile = argv[optind+1];
  }
	if(!utility_check_params(&cparams)){
		rc = 1;
		goto end;
	}
	void *dummy = ((void *)&cparams);
  rc = syscall(__NR_cryptocopy, dummy);

	if (rc == 0)
	 	printf("syscall returned %d\n", rc);
	else
	 	printf("syscall returned %d (errno=%d)\n", rc, errno);
end:
	if(MD5_hash)
		free(MD5_hash);
	exit(rc);
}
