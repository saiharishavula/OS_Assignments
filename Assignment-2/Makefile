STBFS_VERSION="0.1"

EXTRA_CFLAGS += -DSTBFS_VERSION=\"$(STBFS_VERSION)\"

obj-m += stbfs.o

INC=/lib/modules/$(shell uname -r)/build/arch/x86/include

all: stbctl stbfs

stbctl: stbctl.c
	gcc -Wall -Werror -I$(INC)/generated/uapi -I$(INC)/uapi stbctl.c -o stbctl

stbfs:
	make -Wall -Werror -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -f stbfs
	rm -f stbctl

stbfs-y := dentry.o file.o inode.o main.o super.o lookup.o mmap.o
# INC=/lib/modules/$(shell uname -r)/build/arch/x86/include
# stbctl: stbctl.c
# 	gcc -Wall -Werror -I$(INC)/generated/uapi -I$(INC)/uapi stbctl.c -o stbctl
# clean:
# 	rm -f stbctl