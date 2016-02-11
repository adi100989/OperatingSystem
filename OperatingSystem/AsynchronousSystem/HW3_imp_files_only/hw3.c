#include <asm/unistd.h>
#include <sys/syscall.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <syscall.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <stddef.h>
#include <openssl/md5.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <openssl/md5.h>
#include <pthread.h>
#include "job_struct.h"

#define NETLINK_USER 31

#define MAX_PAYLOAD 1024 /* maximum payload size*/
struct sockaddr_nl src_addr, dest_addr;
struct nlmsghdr *nlh = NULL;
struct iovec iov;
int sock_fd;
struct msghdr msg;

pthread_t tid;

#ifndef __NR_submitjob
#error submitjob system call not defined
#endif

/* To track the error number returned by the system call.*/
extern int errno;

void* get_status_from_kernel(void *arg) 
{
    /* Read message from kernel */
    recvmsg(sock_fd, &msg, 0);
    printf("Hey kernel just updated us with the task status!\n");
    printf("Task status: %s\n", (char*) NLMSG_DATA(nlh));
    close(sock_fd);
	
	return NULL;
}

void define_n_bind_socket()
{
    int job_id = getpid(); //(*(int *)arg);

    sock_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_USER);
    if (sock_fd < 0)
        return;

    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid = job_id;

    bind(sock_fd, (struct sockaddr *)&src_addr, sizeof(src_addr));

    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.nl_family = AF_NETLINK;
    dest_addr.nl_pid = 0; /* For Linux Kernel */
    dest_addr.nl_groups = 0; /* unicast */

    nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));
    memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
    nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
    nlh->nlmsg_pid = job_id; //getpid();
    nlh->nlmsg_flags = 0;

    strcpy(NLMSG_DATA(nlh), "Hello");

    iov.iov_base = (void *)nlh;
    iov.iov_len = nlh->nlmsg_len;
    msg.msg_name = (void *)&dest_addr;
    msg.msg_namelen = sizeof(dest_addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    return;
}

int main(int argc, char *argv[])
{  
    int optionChar;
    int errorFlag = 0;
    int i = 0;
    int sum_of_flags = 0;
    int catFlag = 0, compFlag = 0, dcompFlag = 0, chkFlag = 0, encryptFlag = 0,
        dcryptFlag = 0, pFlag = 0, cancelFlag = 0, chngFlag = 0, listFlag = 0, helpFlag = 0;
    unsigned char cipher_key[16];
	int error;
    char *listBuf = NULL;

    job_struct job_ob;
    // Setting the default priority for jobs
    job_ob.priority = 0;
    job_ob.job_id = -1;
    job_ob.no_of_files = 0;
    job_ob.files = NULL;
    job_ob.pid = getpid();

    while((optionChar = getopt(argc, argv, "acdkxypfblh")) != -1)
    {
        switch(optionChar)
        {
            case 'a':
                    if (catFlag == 1)
                    {
                        fprintf(stderr, "Wrong usage. Check help!\n");
                        return 0;
                    }
                    catFlag = 1;
                    job_ob.job_type = JTYPE_CONCAT;
                    break;
            case 'c':
                    if (compFlag == 1)
                    {
                        fprintf(stderr, "Wrong usage. Check help!\n");
                        return 0;
                    }
                    compFlag = 1;
                    job_ob.job_type = JTYPE_CONPRESS;
                    break;
            case 'd':
                    if (dcompFlag == 1)
                    {
                        fprintf(stderr, "Wrong usage. Check help!\n");
                        return 0;
                    }
                    dcompFlag = 1;
                    job_ob.job_type = JTYPE_DECOMPRESS;
                    break;
            case 'k':
                    if (chkFlag == 1)
                    {
                        fprintf(stderr, "Wrong usage. Check help!\n");
                        return 0;
                    }
                    chkFlag = 1;
                    job_ob.job_type = JTYPE_CHECKSUM;
                    break;
            case 'x':
                    if (encryptFlag == 1)
                    {
                        fprintf(stderr, "Wrong usage. Check help!\n");
                        return 0;
                    }
                    encryptFlag = 1;
                    job_ob.job_type = JTYPE_ENCRYPT;
                    break;
            case 'y':
                    if (dcryptFlag == 1)
                    {
                        fprintf(stderr, "Wrong usage. Check help!\n");
                        return 0;
                    }
                    dcryptFlag = 1;
                    job_ob.job_type = JTYPE_DECRYPT;
                    break;
            case 'p':
                    if (pFlag == 1)
                    {
                        fprintf(stderr, "Wrong usage. Check help!\n");
                        return 0;
                    }
                    pFlag = 1;
                    job_ob.priority = 1;
                    break;
            case 'f':
                    if (cancelFlag == 1)
                    {
                        fprintf(stderr, "Wrong usage. Check help!\n");
                        return 0;
                    }
                    cancelFlag = 1;
                    job_ob.job_type = JTYPE_CANCEL;
                    break;
            case 'b':
                    if (chngFlag == 1)
                    {
                        fprintf(stderr, "Wrong usage. Check help!\n");
                        return 0;
                    }
                    chngFlag = 1;
                    job_ob.job_type = JTYPE_CHANGE;
                    break;
            case 'l':
                    if (listFlag == 1)
                    {
                        fprintf(stderr, "Wrong usage. Check help!\n");
                        return 0;
                    }
                    listFlag = 1;
                    job_ob.job_type = JTYPE_LIST;
                    break;
            case 'h':
                    if (helpFlag == 1)
                    {
                        fprintf(stderr, "Wrong usage. Check help!\n");
                        return 0;
                    }
                    helpFlag = 1;

                    printf("The program ./hw3.o concatenates, compresses, decompresses, encrypts, decrypts,"
                            " calculates checksum, adds priority to a job, cancels a job, changes the priority"
                            " of a job and lists all the jobs in the queue.\n\n");
                    printf("Usage: %s {-a|-c|-d|-x|-y|-k|-l|-f|-b} {<destFile> <sourceFile>}\n\n", argv[0]);
                    printf("-a :            Concatenates. One destFile followed by atleast one srcFile. -p optional.\n");
                    printf("-c :            Compression. One destFile followed by one srcFile. -p optional.\n");
                    printf("-d :            Decompression. One destFile followed by one srcFile. -p optional.\n");
                    printf("-x :            Encryption. One destFile followed by one srcFile. -p optional.\n");
                    printf("-y :            Decryption. One destFile followed by one srcFile. -p optional.\n");
                    printf("-k :            Checksum. One destFile followed by one srcFile. -p optional.\n");
                    printf("-l :            List jobs in queue.\n");
                    printf("-f :            Cancel jobs in queue. Job id required.\n");
                    printf("-b :            Change job priority. Job id andd priority {0|1} required.\n");
                    printf("-h :            Help.\n");
                    return 0;

                    break;
            default:  //'?' in case of invalid option characters or missing arguments 
                    errorFlag = 1;
                    return 0;
    	}
    }

    sum_of_flags = catFlag + compFlag + dcompFlag + chkFlag + encryptFlag
                 + dcryptFlag + pFlag + cancelFlag + chngFlag + listFlag;

    if (sum_of_flags > 2)
    {
        fprintf(stderr, "Wrong usage. Check help!\n");
        return 0;
    }
    else if (sum_of_flags == 2 && pFlag == 0)
    {
        fprintf(stderr, "Wrong usage. Check help!\n");
        return 0;
    }
    else if (sum_of_flags == 1 && pFlag == 1)
    {
        fprintf(stderr, "Wrong usage. Check help!\n");
        return 0;
    }
    else
    {
        if ((catFlag + compFlag + dcompFlag + chkFlag) == 1)
        {
            if (catFlag && (argc - 2 - pFlag < 2))
            {
                fprintf(stderr, "Atleast two filenames required!\n");
                return 0;
            }
            if (!catFlag && (argc - 2 - pFlag != 2))
            {
                fprintf(stderr, "Two filenames allowed!\n");
                return 0;
            }
            job_ob.no_of_files = argc - 2 - pFlag;
            job_ob.files = malloc(job_ob.no_of_files * sizeof(char *));
            for(i = 0; i < job_ob.no_of_files; i++)
            {
                job_ob.files[i] = (char *) argv[optind + i];
                //printf("file: %s\n", job_ob.files[i]);
            }
        }
        else if ((encryptFlag + dcryptFlag) == 1)
        {
            if (argc - 2 - pFlag != 3)
            {
                fprintf(stderr, "Three inputs allowed!\n");
                return 0;
            }
            if (strlen((char *) argv[optind]) < 6)
            {
                fprintf(stderr, "Error! Passphrase is too small. Length should be minimum 6.\n");
                return 0;
            }
            job_ob.no_of_files = argc - 2 - pFlag;
            job_ob.files = malloc(job_ob.no_of_files * sizeof(char *));
            for(i = 0; i < job_ob.no_of_files; i++)
            {
                job_ob.files[i] = (char *) argv[optind + i];
                //printf("file: %s\n", job_ob.files[i]);
            }
            // Convert the user passphrase to MD5 hash of 128 bit
            MD5((const unsigned char *)job_ob.files[0], strlen(job_ob.files[0]), cipher_key);
            job_ob.files[0] = (char *)cipher_key;
        }
        else if (chngFlag)
        {
            if (argc - 2 - pFlag != 2)
            {
                fprintf(stderr, "Two inputs allowed!\n");
                return 0;
            }
            job_ob.job_id = strtol(argv[optind], argv, 10);
            if (job_ob.job_id == 0)
            {
                printf("Invalid input!\n");
                return 0;
            }
            //printf("Changeflag; job_id: %lu\n", job_ob.job_id);
            if (! ( (strcmp(argv[optind + 1], "0") == 0) || (strcmp(argv[optind + 1], "1") == 0) ) )
            {
                printf("Invalid input!\n");
                return 0;
            }
            job_ob.priority = strtol(argv[optind + 1], argv, 10);
            //printf("Changeflag; priority: %d\n", job_ob.priority);
        }
        else if (cancelFlag)
        {
            if (argc - 2 - pFlag != 1)
            {
                fprintf(stderr, "One input allowed!\n");
                return 0;
            }
            job_ob.job_id = strtol(argv[optind], argv, 10); // 123abc passes.. change code
            printf("Cancel request for job_id %lu requested ...\n", job_ob.job_id);
            if (job_ob.job_id == 0)
            {
                printf("Invalid input!\n");
                return 0;
            }
            //printf("Cancel job; job_id: %lu\n", job_ob.job_id);
        }
        else if (listFlag) 
        {
            if(argc - 2 - pFlag > 0)
            {
                fprintf(stderr, "Error! Wrong usage. Check help!\n");
                return 0;
            }

            // malloc a buffer to store job info
            listBuf = (char *) malloc(50*MAX_JOB_CNT);
            memset(listBuf, '\0', 50*MAX_JOB_CNT);
            job_ob.files = &listBuf;
        }
    }

	define_n_bind_socket();
    /* System Call */
    if ((error = (syscall(__NR_submitjob, &job_ob))) != 0)
    {
        switch (errno)
        {
            case 1:
                    printf("Operation not permitted!\n");
                    break;
            case 2:
                    printf("No such file or directory!\n");
                    break;
            case 3:
                    printf("No such job!\n");
                    break;
    	    case 11:
    		        printf("Max number of jobs reached! Try later.\n");
    		        break;
    	    case 14:
                    printf("Bad address!\n");
                    break;
    	    case 22:
                    printf("Invalid argument!\n");
                    break;
            case 36:
                    printf("File name too long!\n");
                    break;
            case 90:
                    printf("Pass-phrase should be within 6-4096 characters!\n");
                    break;
            case 114:
                    printf("Job not found in queue. Probably already completed!\n");
                    break;
        }
    }
    else
    {
        if (listFlag)
        {
            printf("JOB ID     JOB TYPE           PRIORITY\n");
            printf("----------------------------------------\n");
            printf("%s\n", listBuf);
        }
        else if (cancelFlag)
        {
            printf("Job %lu cancelled successfully!\n", job_ob.job_id);
        }
        else if (chngFlag)
        {
            printf("Priority of job %lu changed successfully!\n", job_ob.job_id);
        }

        else if (catFlag || compFlag || dcompFlag || chkFlag || encryptFlag || dcryptFlag)
        {
            printf("Your job was queued successfully. you job_id is: %lu\n\n", job_ob.job_id);
		    
    	    if (pthread_create(&tid, NULL, &get_status_from_kernel, &(job_ob.job_id)) != 0)
    	    {
                printf("Hey the pthread could not be created!\n");
    	    }
    	    else
    	    {
                printf("My agent will now listen to kernel on the created socket and"
                        " print on stdout whenever the task is done.\n");
    		    printf("I am now off to calculating Pi!\n\n");
    	    }
    	    for(i =1; i <= 20; i++)
    	    {
                sleep(1);
                printf("%d %% Pi calculation done\n", i*5);
                fflush(stdout);
    	    }
            pthread_join(tid, NULL);
        }
    }

    return 0;
}

