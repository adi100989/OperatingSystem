AMFS_VERSION="0.1"

EXTRA_CFLAGS += -DAMFS_VERSION=\"$(AMFS_VERSION)\"

obj-$(CONFIG_AM_FS) += amfs.o
all:
	gcc -Wall -Werror amfsctl.c -o amfsctl
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
#	rmmod amfs.ko
	insmod amfs.ko

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rmmod amfs.ko
amfs-y := dentry.o file.o inode.o main.o super.o lookup.o mmap.o
