/*http://tuxthink.blogspot.com/2011/01/creating-ioctl-command.html*/

#include <linux/ioctl.h>
//#define IOC_MAGIC 0xb550ca11 // defines the magic number

#define IOCTL_ADD _IOWR('a',0, char **) // defines our ioctl call
#define IOCTL_REMOVE _IOWR('b',1, char **)
#define IOCTL_LIST _IORW('c',2, char *)

//#define IOCTL_MAGIC_MAX 2