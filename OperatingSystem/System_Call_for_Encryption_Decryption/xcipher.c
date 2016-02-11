#include <asm/unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <string.h>
#include <openssl/md5.h>
#include "pass_struct.h"


#ifndef __NR_xcrypt
#error xcrypt system call not defined
#endif
/*MAIN USER LEVEL FUNCTION */

#define MD5_LENGTH 16

int main(int argc, char *argv[])
{
    int rc=0; // to capture the error code as return value.
    int choice=0; //used in switch case for getopt()

    /*  set all option flags to 0   */
    int p_flag=0, e_flag=0, d_flag=0, help_flag=0;

    char password[MD5_LENGTH + 1]; // MD5_LENGTH =16
    /* https://www.openssl.org/docs/manmaster/crypto/md5.html  */

    void *buffer = (void *) malloc (sizeof(struct myargs));
    struct myargs *args_adi = (struct myargs *) malloc (sizeof(struct myargs));
    unsigned char MD5_hash[MD5_LENGTH + 1];

    while((choice = getopt (argc, argv, "p:edh")) != -1)
     {
       switch(choice)
           {
             case 'p' :
                   p_flag = 1;

                /*              if (!optarg)
                                {
                                        perror("length of password smaller than 6");
                                        goto exit;
                                } */
                    if(strlen(optarg) < 6)
                     {
                         perror("length of password smaller than 6");
                         goto exit;
                     }

                    if(strlen(optarg) > 32)
                     {
                         perror("password longer than 32");
                         goto exit;
                     }

                     strcpy(password, optarg);
                    // printf("\n password is %s",password);
   /*creating a MD5 hash of the password supplied on command line
                                      and storing it in the keybuf*/
                    MD5((unsigned char*) password,strlen(password),MD5_hash);
                    //printf("\n MD5 is %s",MD5_hash);

                    memcpy((void *)args_adi->keybuf,MD5_hash, 16);
                   // printf("\n MD5 is %s",MD5_hash);
                    MD5_hash[MD5_LENGTH]='\0';
                    args_adi->keylen = 16;
                   // printf("\n keybuf is %d",strlen((char *)args_adi->keybuf));
                   // printf("\n keylen=%d", args_adi->keylen);
              break;

              case 'e' :
                    e_flag = 1;
                    break;

              case 'd' :
                    d_flag = 1;
                    break;

               case 'h' :
                    help_flag = 1;
                    break;

               default :
                    printf ("\n Bad arguments");
                    goto exit;
                }// end of switch
        } //end of while

  /*check if the number of arguments in the CMD line is of the correct number */
        if ((argc<6) || (argc>7))
         {
           perror("\n Number of arguments are less than 6 or more than 7.EXIT");
           goto exit;

        }

        if (help_flag==1)
        {
            printf("\n You have asked for help.");
            printf("\n 1.ENCRYPTION: The format for the cmd line is ./xcipher -p 'your password' -e inputfile outputfile ");
            printf("\n 2.DECRYPTION: The format for the cmd line is ./xcipher -p 'your password' -d inputfile outputfile ");
        }
        if((e_flag==1) && (d_flag==1))
        {
            perror("\n encryption and decryption cannot be done together");
            goto exit;

        }
        else
        {
            if (e_flag==1) args_adi->flags=0; //for encryption
            if (d_flag==1) args_adi->flags=1; // for decryption
        }
       /* copying values of infile and outfile into the structure variable  */
        strncpy(args_adi->infile, argv[optind], strlen(argv[optind]));
        strncpy(args_adi->outfile, argv[optind+1], strlen(argv[optind+1]));
        /*creating a void* buffer to send to the kernel*/
        memcpy((void *) buffer, (void *)args_adi, sizeof(struct myargs));


        rc = syscall(__NR_xcrypt,buffer);

        if (rc == 0)
            printf("\n syscall returned %d\n", rc);
        else
            printf("\n syscall returned %d (errno=%d)\n", rc, errno);


        free(args_adi);
        free(buffer);
        return 0;

        exit :
                if (args_adi)
                        free(args_adi);
                if (buffer)
                        free(buffer);
 return -1;
}

