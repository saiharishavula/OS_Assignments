obj-m += sys_async_queue.o

INC=/lib/modules/$(shell uname -r)/build/arch/x86/include

all: xhw3 async_queue

xhw3: xhw3.c
	gcc -Wall -Werror -I$(INC)/generated/uapi -I$(INC)/uapi xhw3.c -o xhw3 -lcrypto -lssl -lpthread

async_queue:
	make -Wall -Werror -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) clean
	rm -f xhw3

