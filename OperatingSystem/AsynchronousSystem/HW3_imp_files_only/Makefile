obj-m += sys_submitjob.o

#INC=/lib/modules/$(shell uname -r)/build/arch/x86/include

all: hw3 submitjob

hw3: hw3.c
	gcc -Wall -Werror -I$(INC)/generated/uapi -lssl -I$(INC)/uapi hw3.c -o hw3.o -lpthread

submitjob:
	make -Wall -Werror -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -f hw3.o
	rm -f listner.o
