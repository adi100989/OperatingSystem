obj-m += sys_xcrypt.o

INC=/lib/modules/$(shell uname -r)/build/arch/x86/include

all: xcipher xcrypt

xcipher: xcipher.c
	gcc -lssl  -Wall -Werror -I$(INC)/generated/uapi -I$(INC)/uapi xcipher.c -o xcipher

xcrypt:
	make -Wall -Werror -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
		
	insmod sys_xcrypt.ko
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -f xcipher
	rmmod sys_xcrypt.ko

