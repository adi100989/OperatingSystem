#include <sys/ioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

int main(int argc, char **argv)
{
	int choice, fd, err, flag;
	void *buffer= NULL;
	//char *pattern=NULL,*mount_point=NULL;
	err = 0;
	flag = -1;
	
	while((choice = getopt (argc, argv, "la:r:")) != -1)
     {
       switch(choice)
           { 
            case 'a' :
                flag = 0;
				printf("\n in the add case");
				printf("\n optarg %s",optarg);
				printf("\n optind %s", argv[optind]);
				fd = open(argv[optind], O_RDONLY);
				//fd = open(argv[optind], O_WRONLY|O_CREAT|O_TRUNC);
				if (fd != -1)
				{
					printf("Device opened -Calling ioctl\n");
					ioctl(fd, 0, optarg);
					close(fd);
				} else
					printf("Device not found");
				break;
			case 'r' :
                flag = 1;
				printf("\n in the remove case");
				printf("\n optarg %s",optarg);
				printf("\n optind %s", argv[optind]);
				fd = open(argv[optind], O_RDONLY);
				if (fd != -1)
				{
					printf("Device opened - Calling ioctl\n");
					ioctl(fd, 1, optarg);
					close(fd);
				} else
					printf("Device not found");
				
				break;	
			case 'l' :
                flag = 20;
				printf("\n in the list case");
				printf("\n optarg %s",optarg);
				printf("\n optind %s", argv[optind]);
				fd = open(argv[optind], O_RDONLY);
				if (fd != -1)
				{	
					
					buffer=(void *)malloc(200);
				printf("\n Device opened - Calling ioctl\nList printed in the kernal space. [User space not working]");
					ioctl(fd, 20,buffer);
					printf("\n data passed from kernel to user is  %s",(char*)buffer); //check this again.. not working
					close(fd);
				} else
					printf("Device not found");
						break;	
			default: 
				printf("\n 1. To list known patterns : $ ./amfsctl -l /mnt/amfs");
				printf("2. To add a new pattern :$ ./amfsctl -a 'newpatt' /mnt/amfs");
				printf("3. To remove an old pattern :$ ./amfsctl -r 'oldpatt' /mnt/amfs");
                
				err = -1;
				goto exit;
				break;

		}
	}
	
	exit:
	//printf("\n u encountered an error. try again.");
	return err;
}
