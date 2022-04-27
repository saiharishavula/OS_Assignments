#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#define READ_ONLY  _IOR(0, 1 , int32_t *)
/**
* @brief User function for undelete operation using ioctl(2)
*
* @source https://embetronicx.com/tutorials/linux/device-drivers/ioctl-tutorial-in-linux/#IOCTL_Tutorial_in_Linux
*/
int main(int argc, char* const argv[]){

	int fd;
	int err = 0;
	int option;
	bool is_command_correct = false;
	char *file_to_undelete = NULL;
	while ((option = getopt(argc, argv, "u")) != -1) {
		switch (option) {
			case 'u':
				is_command_correct = true;
				file_to_undelete = argv[optind];
				printf("file to be undeleted - %s\n", file_to_undelete);
				break;
			default:
				printf("Help message\n");
				printf("To perform the undelete operation using ioctl(2), the command is as follows\n");
				printf("./stbctl -u mnt/stbfs/.stb/filename\n");
				err = 1;
				goto out;
				break;
		}
	}
	if(is_command_correct == false){
		printf("Help message\n");
		printf("To perform the undelete operation using ioctl(2), the command is as follows\n");
		printf("./stbctl -u mnt/stbfs/.stb/filename\n");
		err = 1;
		goto out;
	}else{
		fd = open(file_to_undelete, O_RDWR);
		if(fd < 0) {
			printf("File Open Failed with error code - %d\n", fd);
			err = fd;
			goto out;
		}
		err = ioctl(fd, READ_ONLY, 0);
		close(fd);
		if(err == 0){
			printf("ioctl operation to undelete the file succedded\n");
			goto out;
		}else{
			printf("ioctl operation to undelete the file failed - errno - %d\n", errno);
			goto out;
		}
	}
out:
	return err;
}
