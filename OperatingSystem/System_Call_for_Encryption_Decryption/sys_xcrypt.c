#include <linux/linkage.h>
#include <linux/moduleloader.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <asm/uaccess.h>
#include <linux/vmalloc.h>
#include <linux/stat.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <asm/unistd.h>
#include <linux/path.h>
#include <linux/err.h>
#include <linux/scatterlist.h>
#include <crypto/hash.h>
#include <linux/key-type.h>
#include <keys/user-type.h>
#include <crypto/md5.h>
#include <crypto/aes.h>

#include "pass_struct.h"

#define AES_KEY_SIZE 16
#define MD5_DIGEST_LENGTH 16

asmlinkage extern long (*sysptr)(void *arg);


/* Source: http://lxr.free-electrons.com/source/net/ceph/crypto.c#L157 and CryptoAPI */

/*##################################################################################### */
/*                           Encryption function                                       */
/*##################################################################################### */

static int encrypt(char *key, int key_len,
                            char *dst, int dst_len,
                             char *src, int src_len)
{
    struct scatterlist sg_in[1], sg_out[1];

/* call crypto_alloc_blkcipher for assigning AES algorithm with CTR mode   */
    struct crypto_blkcipher *tfm = crypto_alloc_blkcipher("ctr(aes)", 0, CRYPTO_ALG_ASYNC);
    struct blkcipher_desc desc = { .tfm = tfm, .flags = 0 };
    int ret=0;

    if (IS_ERR(tfm))
     {
       printk("\n tfm error %ld ", PTR_ERR(tfm));
       return -1;
      }
    /* Basic Checks before set_buffer() and set_key()  */
    if (key_len==16 && sg_in!=NULL && sg_out !=NULL && tfm!=NULL && key!=NULL )
      {
         /*initializing the scatterlist table for input*/
         sg_init_table(sg_in, 1);
         /* set buffer for scatterlist input with source data */
         sg_set_buf(&sg_in[0], src, src_len);
         /* calling the crypto block cipher setKey() */
         crypto_blkcipher_setkey(tfm, key, key_len);
       }
    else
        return -1;  // if an error exists then exit.

        /* Initialize the table for output  and set buffer with input/output details */
        sg_init_table(sg_out, 1);
        sg_set_buf(&sg_out[0], dst, src_len);

         /*Start the encryption process*/

        ret = crypto_blkcipher_encrypt(&desc, sg_out, sg_in, src_len);

        /* if the encryption process fails then return the error message*/
         if (ret < 0)
         {
               printk("\n encrypt failed");
               pr_err("Encrypt() failed with error code %d\n", ret);
               goto exit;
         }
exit:
      crypto_free_blkcipher(tfm); //free the blockcipher structure
        return ret;
 }

/* Source: http://lxr.free-electrons.com/source/net/ceph/crypto.c and CryptoAPI */
/*##################################################################################### */
/*                           Decryption function                                       */
/*##################################################################################### */

static int decrypt(char *key, int key_len,
                            char *dst, int dst_len,
                             char *src, int src_len)
{

         struct scatterlist sg_out[1], sg_in[1];

/* call crypto_alloc_blkcipher for assigning AES algorithm with CTR mode   */
         struct crypto_blkcipher *tfm = crypto_alloc_blkcipher("ctr(aes)", 0, CRYPTO_ALG_ASYNC);
         struct blkcipher_desc desc = { .tfm = tfm };

         int ret=0;
        // int last_byte;

/* if Error while creating the crypto_blkcipher structure: exit  */
         if (IS_ERR(tfm))
                 return -1;

 /*initializing the scatterlist table for input*/
         sg_init_table(sg_in,1);
 /*initializing the scatterlist table for output*/
         sg_init_table(sg_out, 1);
 /*initializing the scatterlist buffer with input/ output  details*/
         sg_set_buf(sg_in, src, src_len);
         sg_set_buf(&sg_out[0], dst, dst_len);

 /*  call teh crypto block cipher set key function*/

         crypto_blkcipher_setkey(tfm, key, key_len);

/* if while decrypting there is an error then return the failed error code and exit */
         ret = crypto_blkcipher_decrypt(&desc, sg_out, sg_in, src_len);
         if (ret < 0) {
                 pr_err("ceph_aes_decrypt failed %d\n", ret);
                 goto exit;
         }
/*-------------------- REMOVED: NOT IMPLEMNTING PADDING--------------
         if (src_len <= dst_len)
                 last_byte = ((char *)dst)[src_len - 1];
          else
                 last_byte = pad[src_len - dst_len - 1];
         if (last_byte <= 16 && src_len >= last_byte) {
                 dst_len = src_len - last_byte;
         } else {
                 pr_err("ceph_aes_decrypt got bad padding %d on src len %d\n",
                        last_byte, src_len);
                 return -EPERM;
         }
-------------------------------------------------------------------------*/
exit:
        crypto_free_blkcipher(tfm); // free the block cipher structure
        return ret;
 }

/* Source: Adapted from the Wrapfs.c file mentioned in teh HW1 folder */

/*##################################################################################### */
/*                           Main Kernel function                                       */
/*##################################################################################### */


asmlinkage long xcrypt(void *arg)
{
        /*GFP_KERNEL used as a flag for normal kernel allocation without locks */
        struct myargs *kbuffer = kmalloc(sizeof(struct myargs),GFP_KERNEL);

        /* copying the passed structure which was void* to struct myargs *kbuffer  */
        unsigned long copy_flag = copy_from_user(kbuffer, arg, sizeof(struct myargs));

        int error_code=0, k_keylen=0;

        /*initialize all the file structures for read/write */
        struct file *input_file=NULL, *output_file=NULL, *temp_file=NULL;

         /*initialize all the buffers  for read/write */
        void *file_buffer_read=NULL, *file_buffer_write=NULL;

        int  bytes_read=0, bytes_write=0,total_bytes=0, input_size=0;
       unsigned char keybuf[MD5_DIGEST_LENGTH+1]; //used to store the MD5 hashed password(for encryption/decryption)

        mm_segment_t oldfs;

        k_keylen=strlen(kbuffer->keybuf);
        printk("\n key %d",k_keylen);

        memcpy((void *)keybuf, (void *)kbuffer->keybuf,MD5_DIGEST_LENGTH+1);

         /* a check for Kmalloc success /failure */
        if (!kbuffer)
        {
          printk("\n Kmalloc failed with error %d", -ENOMEM);
          error_code= -ENOMEM;
          goto exit;
        }
        else printk("\n kmalloc succeeded");

        /* check for copy_from_user fail and success */
        if (copy_flag!=0)
        {
        /*copy from user failed.Maybe due to invalid argument/ no memory left. I will be passing "invalid" error code*/
          printk("\n copy from user failed withe error code %d\n",-EINVAL);
          error_code= -EINVAL;
          goto exit;
        }
        else
          printk("\n copy from user succeeded. kbuffer created of size %d \n",sizeof(kbuffer));

        /* to check for invalid and NULL arguments */
       if ((kbuffer->infile==NULL)||(kbuffer->outfile==NULL)||
            (kbuffer->flags!=0 || kbuffer->flags!=1) ||(kbuffer->keybuf==NULL))
            //|| (kbuffer->keylen != k_keylen))
        {
          printk("The arguments are invalid. Some values null .Error=%d",-EINVAL);
          printk("\n infile=%s, outfile=%s, flags=%d, keybuf=%s,keylen=%d, k_keylen=%d",kbuffer->infile,kbuffer->outfile,kbuffer->flags,kbuffer->keybuf,kbuffer->keylen,k_keylen); 
	  error_code=-EINVAL;
          goto exit;
        }
       else printk("arguments valid");


/*after all error checks complete. Open/create file structure to read and write and perform
                                                  read/write checks  . */

/*-------------------------------------------------------------------------------------------------------
        1. Read file is opened and all error checks are done
        2. Write file is opened and all error checks are done
        3. Data is read from the input file, encrypted/decrypted  and written to the output file.
-------------------------------------------------------------------------------------------------------*/

        /* open the read file in the read only mode*/
        input_file = filp_open(kbuffer->infile, O_RDONLY, 0);
        if (!input_file || IS_ERR(input_file)) //check for opening error
        {
                printk("\n File opening error. Error returned= %d\n", (int) PTR_ERR(input_file));
                error_code=(int)PTR_ERR(input_file);
                goto exit;
        }

        else printk("\n no opening error");

        if (!input_file->f_op->read) // file(system) doesn't allow reads
        {
                printk("\n File doesn't allow reads ");
                error_code=-3;
                goto exit;
        }
        else printk("\n this is a read file");

        /* opening a temporary file */

         temp_file = filp_open ("temp_file.txt", O_WRONLY|O_CREAT|O_TRUNC,00666);  //00666
        /* check if there is an error opening a temp file*/
        if (!temp_file)
        {
            printk("\n error in opening a temporary file. %d",-EBADF);
            error_code=-EBADF;
            goto exit;
         }

          /*if temp file and input file have the same inode number[changed]*/
        if (input_file->f_inode->i_ino == temp_file->f_inode->i_ino)
        {
           printk("\n Input file and temporary file have the same inode. Error= %d",-EBADF);
           error_code=-EBADF;
           goto exit;
         }

        /*opening a write file*/

        output_file = filp_open(kbuffer->outfile, O_WRONLY|O_CREAT, 00666);

        /* check if there is an error opening a output file*/
        if (!output_file || IS_ERR(output_file))
        {
            printk("\n File opening error. Error returned= %d\n", (int) PTR_ERR(output_file));
            error_code=(int)PTR_ERR(output_file);
            goto exit;
        }
        else printk("\n no opening error for write file");

        if (!output_file->f_op->write)
        {  // file(system) doesn't allow writes
             printk("\n File doesn't allow writes ");
             error_code=-4;
             goto exit;
        }
        else printk("\n this is a write file");


        // if input file and output file have the same inode number
        if(input_file->f_inode->i_ino == output_file->f_inode->i_ino)
        {
          printk("\n Input file and output file  have the same inode number. Error= %d",-EBADF);
          error_code=-EBADF;
          goto exit;
        }

        //create a buffer for read and check
        file_buffer_read= kmalloc(PAGE_SIZE,GFP_KERNEL);
        if (!file_buffer_read)   //check for Kmalloc for file_buffer_read
          {
           printk("\n Kmalloc(file_buffer_read) failed with error %d", -ENOMEM);
           error_code= -ENOMEM;
           goto exit;
          }
        else printk("\n kmalloc for file_buffer_read succeeded");

        //create a buffer for write and check
        file_buffer_write= kmalloc(PAGE_SIZE,GFP_KERNEL);
        if (!file_buffer_write)   //check for Kmalloc for file_buffer_write
          {
            printk("\n Kmalloc(file_buffer_write) failed with error %d", -ENOMEM);
            error_code= -ENOMEM;
            goto exit;
         }
        else printk("\n kmalloc for file_buffer_write succeeded");


        /* start read /write in PAGE_SIZE increments.*/
        oldfs = get_fs();  // set oldfs to present DS
        set_fs(KERNEL_DS);  // set present to kernel data segment

        /* check if the input file size is not 0 */

        input_size=input_file->f_inode->i_size;  //calculate the size of input file changed

        if (input_size<=0)
        {
             printk("\n input file size is 0 . error.");
             error_code=-4;
             goto exit;
        }

        input_file->f_pos=0;             //set the input file pointer to 0 position
        total_bytes=input_size;
        //printk("\n total_bytes %d ", total_bytes);
        //temp_file->f_pos=0;
        output_file->f_pos=0;
        while (total_bytes>0)
        {

        /*READ into a file_buffer_read and transfer contents of file_buffer_read to write the temp file */
        /*
                if total bytes i.e. the size of file is less than the PAGE_SIZE, then execute the below block

        */

        if (total_bytes<PAGE_SIZE)
        {
                bytes_read = input_file->f_op->read(input_file,file_buffer_read , total_bytes, &input_file->f_pos);

                                         /* ----------       Encryption ----------   */
                if (kbuffer->flags ==0)
                {
                   error_code=encrypt(keybuf,AES_KEY_SIZE, file_buffer_write, bytes_read,file_buffer_read, bytes_read);
                   if (error_code <0)
                        {
                           printk("\n error in encryption ");
                           goto exit;
                        }
                   //printk("\n file buffer==%s",file_buffer_write);
                   //printk("\n file buffer==%s",file_buffer_read);
                }

                else if (kbuffer->flags ==1)
                {
                                 /* ----------      Decryption ----------   */

                    error_code=decrypt(keybuf,AES_KEY_SIZE, file_buffer_write, bytes_read,file_buffer_read, bytes_read);
                    if (error_code <0)
                      {
                         printk("\n error in Decryption ");
                         goto exit;
                       }
                }


              bytes_write=output_file->f_op->write(output_file,file_buffer_write , bytes_read, &output_file->f_pos);
              total_bytes=0;
       //       printk("\n bytes read %d", bytes_read);
       //       printk("\n bytes written %d", bytes_write);

        }
        else
        {
                 /*
                      if total bytes i.e. the size of file is equal to the PAGE_SIZE, then execute the below block

                 */
                bytes_read = input_file->f_op->read(input_file,file_buffer_read , PAGE_SIZE, &input_file->f_pos);
                total_bytes=total_bytes-bytes_read;

                                /*------------------  Encryption ---------------- */
                if (kbuffer->flags ==0)
                {
                        error_code=encrypt(keybuf,AES_KEY_SIZE, file_buffer_write, PAGE_SIZE, file_buffer_read, PAGE_SIZE);
                        if (error_code <0)
                            {
                                printk("\n error in encryption ");
                                goto exit;
                        }
                }
                else if (kbuffer->flags ==1)
                {                  /*------------Decryption-----------------*/
                        error_code=decrypt(keybuf, AES_KEY_SIZE, file_buffer_write, PAGE_SIZE, file_buffer_read, PAGE_SIZE);
                        if (error_code <0)
                        {
                                printk("\n error in encryption ");
                                goto exit;
                        }
                }

  //              memcpy(file_buffer_write,file_buffer_read,strlen(file_buffer_read));
               bytes_write=output_file->f_op->write(output_file, file_buffer_write , PAGE_SIZE, &output_file->f_pos);
               // printk("\n bytes read %d", bytes_read);
               // printk("\n bytes written %d", bytes_write);
        }

        if (bytes_read !=bytes_write) //if the number of bytes read is not same as those written.
        {
                printk("\n Read write error. %d ",-ENOMEM);
                error_code=-ENOMEM;
                goto exit;
        }
        }
        if (error_code==0) // if no errors encountered. rename temp to output file[NOT IMPLEMENTED]
        {
                printk("\n file read /write successful");

        }
        set_fs(oldfs);

        /* close all open files

        filp_close(input_file, NULL);
        filp_close(temp_file,NULL);
        filp_close(output_file,NULL);
        */
        error_code=0;
             /*Do all neccessary cleanup */
        exit:
                if (kbuffer)
                         kfree(kbuffer);
                if(file_buffer_read)
                        kfree(file_buffer_read);
                if(file_buffer_write)
                        kfree(file_buffer_write);
                if(input_file)
                        filp_close(input_file, NULL);
                if(output_file)
                        filp_close(output_file, NULL);
                if(temp_file)
                        filp_close(temp_file, NULL);
return error_code;
}

static int __init init_sys_xcrypt(void)
{
        printk("installed new sys_xcrypt module\n");
        if (sysptr == NULL)
                        sysptr = xcrypt;
        return 0;
}
static void  __exit exit_sys_xcrypt(void)
{
        if (sysptr != NULL)
                        sysptr = NULL;
        printk("removed sys_xcrypt module\n");
}
module_init(init_sys_xcrypt);
module_exit(exit_sys_xcrypt);
MODULE_LICENSE("GPL");

