#include <linux/linkage.h>
#include <linux/moduleloader.h>
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
#include "job_struct.h"
#include <linux/workqueue.h>
#include <linux/delay.h>
#include <linux/list.h>
#include <linux/crypto.h>
#include <net/sock.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <crypto/hash.h>

#define NETLINK_USER 31

#define CEPH_AES_IV "cephsageyudagreg"
static const u8 *aes_iv = (u8 *)CEPH_AES_IV;

asmlinkage extern long (*sysptr)(void *arg);

typedef struct {
	struct work_struct my_work;
	job_struct *job_obj;
} my_work_struct;

typedef struct {
	struct list_head jlist;
	unsigned long job_id;
	struct work_struct *work_ptr;
} job_list_struct;

static unsigned int job_cnt;
static unsigned long job_id_cnt;
static struct workqueue_struct *my_low_pwq;
static struct workqueue_struct *my_high_pwq;
job_list_struct *job_list_head, *tmp_list_node;
struct list_head *pos, *q;

struct sock *nl_sk = NULL;

static void push_msg_to_user(struct sk_buff *skb)
{
        struct nlmsghdr *nlh;
        int pid;
        struct sk_buff *skb_out;
        int msg_size;
        char *msg="Hello from kernel";
        int res = 0;

        printk(KERN_INFO "Entering: %s\n", __FUNCTION__);

        msg_size=strlen(msg);

        nlh = (struct nlmsghdr*)skb->data;
        printk(KERN_INFO "Netlink received msg payload:%s\n",(char*)nlmsg_data(nlh));
        pid = nlh->nlmsg_pid; /*pid of sending process */

        skb_out = nlmsg_new(msg_size,0);

        if(!skb_out)
        {

            printk(KERN_ERR "Failed to allocate new skb\n");
            return;
        }
        nlh = nlmsg_put(skb_out,0,0,NLMSG_DONE,msg_size,0);
        NETLINK_CB(skb_out).dst_group = 0; /* not in mcast group */
        strncpy(nlmsg_data(nlh),msg,msg_size);

        while(job_id_cnt <= 3)
        {
                msleep(500);
        }

        res = nlmsg_unicast(nl_sk,skb_out,pid);

        if(res<0)
            printk(KERN_INFO "Error while sending bak to user\n");

}


// deletes mapping of job_id,work_obj from custom_queue
// return = 0: success, else failure 
static int delete_from_custom_queue(unsigned long job_id)
{

	int error = -1;
	
	printk("Entered delete_from_custom_queue\n");
	
	list_for_each_safe(pos, q, &(job_list_head->jlist))
	{
	
                tmp_list_node = list_entry(pos, job_list_struct, jlist);

                // printk("job_id: %d @ %p\n", tmp_list_node, tmp_list_node->work_ptr);
                if ( tmp_list_node->job_id == job_id)
                {
                        error = 0;
                        list_del(&tmp_list_node->jlist);

                        printk("job_id: %lu deleted!\n", job_id);

                        /* free up the memory */
                        if (tmp_list_node != NULL)
                        {
                                kfree(tmp_list_node);
                                tmp_list_node = NULL;
                        }
                        // Decrementing the job count
                        job_cnt--;
                        break;
                }
	}

        printk("Exiting delete_from_custom_queue\n");
	
	return error;
}

static void concat( struct work_struct *work_obj)
{
	my_work_struct *my_work_obj = (my_work_struct*) work_obj;
	int i = 0;
	int err = 0, is_in_file_error = 0;
	struct file * dest_filp = NULL;
	struct file * in_filp = NULL;
	char * readBuf = NULL;
	int readBytes;
	mm_segment_t oldfs;

	printk(KERN_ALERT "Entered concat\n");

	oldfs = get_fs();  //Save the current FS segment
	set_fs(KERNEL_DS); //set_fs(get_ds());

    	/* Open the first file in append mode */
	dest_filp = filp_open(my_work_obj->job_obj->files[0], O_WRONLY|O_APPEND, FMODE_WRITE);
	if (!dest_filp || IS_ERR(dest_filp)) {
		printk("Destination file open error %d\n", (int) PTR_ERR(dest_filp));
		err = -ENOENT; /* set error */
		goto out;
	}
	if (!(dest_filp->f_op)) {
    	printk(KERN_ALERT "No file operations on the destination file!\n");
    	err = -ENOENT;
    	goto out_close_dest_file;
	}
	if (!dest_filp->f_op->write) {
		printk("No write permission on the destination file!\n");
		err = -ENOENT; /* set error */
		/* file(system) doesn't allow write */
		goto out_close_dest_file;
	}

	/* Allocate the buffer for reading from the input file */
	readBuf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!readBuf) {
		err = -ENOMEM;
		printk(KERN_ERR
	   		   "Read buffer allocation failed!\n");
		goto out_close_dest_file;
	}

	/* Open other files in read mode in a loop */
	for(i = 1; i < my_work_obj->job_obj->no_of_files; i++)
    {
    	//printk("File %d : %s\n", i, my_work_obj->job_obj->files[i]);

		in_filp = filp_open(my_work_obj->job_obj->files[i], O_RDONLY, FMODE_READ);
		if (!in_filp || IS_ERR(in_filp)) 
		{
			printk("Input file %d open error %d\n", i, (int) PTR_ERR(in_filp));
			err = -ENOENT; /* set error */
			goto out_free_readbuf;
		}
		if (!(in_filp->f_op))
   		{
            printk(KERN_ALERT "No file operations on the %d input file!\n", i);
            err = -ENOENT;
            is_in_file_error = 1;
            goto out_close_in_file;
    	}
		if (!in_filp->f_op->read)
		{
			printk("No read permission on the %d input file!\n", i);
			err = -ENOENT; /* set error */
			/* file(system) doesn't allow reads */
			is_in_file_error = 1;
			goto out_close_in_file;
		}

		memset(readBuf, '\0', PAGE_SIZE);
		/* Copy the contents from the input file to the dest file */
		while ((readBytes = in_filp->f_op->read(in_filp, readBuf, PAGE_SIZE, &in_filp->f_pos)) > 0) {
			//printk("readBuf contents are: \n%s\n", readBuf);
			dest_filp->f_op->write(dest_filp, readBuf, readBytes, &dest_filp->f_pos);
			memset(readBuf, '\0', PAGE_SIZE);
		}

		out_close_in_file:
			filp_close(in_filp, NULL);
			in_filp = NULL;
			if (is_in_file_error)
			{
				goto out_free_readbuf;
			}

    }
	msleep(10 * 1000);

	printk("Concat job(%lu) done successfully\n", my_work_obj->job_obj->job_id);

out_free_readbuf:
	kfree(readBuf);
	readBuf = NULL;
out_close_dest_file:
	filp_close(dest_filp, NULL);
	dest_filp = NULL;
out:
	set_fs(oldfs); //Reset to save FS


	/* Cleaning my_work_obj */

	// deleting from custom_queue
	if(delete_from_custom_queue(my_work_obj->job_obj->job_id) != 0)
	{
		printk("ALERT! could not delete work_obj from custom queue\n");
	}
	
	// Cleaning files data from my_work_obj
        for(i = 0; i<my_work_obj->job_obj->no_of_files; i++)
        {
                kfree(my_work_obj->job_obj->files[i]);
                my_work_obj->job_obj->files[i] = NULL;
        }
        kfree(my_work_obj->job_obj->files);
        my_work_obj->job_obj->files = NULL;
		
	// Cleaning Free'ing my_work_obj->job_obj and my_work_obj itself
	kfree(my_work_obj->job_obj);
	my_work_obj->job_obj = NULL;
	kfree(my_work_obj);
	my_work_obj = NULL;


	printk(KERN_ALERT "Exiting concat\n");
	printk("concat_curr_no_of_jobs: %d\n", job_cnt);

	return;
}

static void compress(struct work_struct *work_obj)
{
	my_work_struct *my_work_obj = (my_work_struct * ) work_obj;
	int i = 0;
	int err = 0;
	struct file *dest_filp = NULL;
	struct file *in_filp = NULL;
	char *readBuf = NULL, *writeBuf = NULL, *bufLen=NULL;
	int readBytes;
	unsigned int writeBytes;
	mm_segment_t oldfs;
	
	struct crypto_comp *comp_tfm = crypto_alloc_comp("deflate", 0, 0);
	printk(KERN_ALERT "Entered compression!\n");

	oldfs = get_fs();  //Save the current FS segment
	set_fs(KERNEL_DS); //set_fs(get_ds());

    // Open the dest file
	dest_filp = filp_open(my_work_obj->job_obj->files[0], O_WRONLY|O_CREAT|O_TRUNC, FMODE_WRITE);
	if (!dest_filp || IS_ERR(dest_filp)) {
		printk("Destination file open error %d\n", (int) PTR_ERR(dest_filp));
		err = -ENOENT; // set error 
		goto out;
	}
	if (!(dest_filp->f_op)) {
    	printk(KERN_ALERT "No file operations on the destination file!\n");
    	err = -ENOENT;
    	goto out_close_dest_file;
	}
	if (!dest_filp->f_op->write) {
		printk("No write permission on the destination file!\n");
		err = -ENOENT; // set error
		// file(system) doesn't allow write 
		goto out_close_dest_file;
	}

	// Allocate the buffer for reading from the input file 
	readBuf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!readBuf) {
		err = -ENOMEM;
		printk(KERN_ERR
	   		   "Read buffer allocation failed!\n");
		goto out_close_dest_file;
	}
	memset(readBuf, '\0', PAGE_SIZE);

	writeBuf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!writeBuf) {
		err = -ENOMEM;
		printk(KERN_ERR
   		   		"Write buffer allocation failed!\n");
		goto out_free_readbuf;
	}
	memset(writeBuf, '\0', PAGE_SIZE);

	// Open input file in read mode
	in_filp = filp_open(my_work_obj->job_obj->files[1], O_RDONLY, FMODE_READ);
	if (!in_filp || IS_ERR(in_filp)) 
	{
		printk("Input file open error: %d\n", (int) PTR_ERR(in_filp));
		err = -ENOENT; // set error 
		goto out_free_writebuf;
	}
	if (!(in_filp->f_op))
	{
        printk(KERN_ALERT "No file operations on the input file!\n");
        err = -ENOENT;
        goto out_close_in_file;
	}
	if (!in_filp->f_op->read)
	{
		printk("No read permission on the input file!\n");
		err = -ENOENT; // set error 
		// file(system) doesn't allow reads 
		goto out_close_in_file;
	}

	bufLen = kmalloc(5, GFP_KERNEL);
	if (!bufLen) 
	{
		err = -ENOMEM;
		printk(KERN_ERR
   		   		"bufLen buffer allocation failed!\n");
		goto out_free_bufLen;
	}
	memset(bufLen, '\0', 5);

	// Compress the contents from the input file and store in the dest file 
	while ((readBytes = in_filp->f_op->read(in_filp, readBuf, PAGE_SIZE, &in_filp->f_pos)) > 0) 
	{
		//printk("Compress: readBuf contents bfore compress are: \n%s\n", readBuf);
		//printk("Compress: writeBuf contents bfore compress are: \n%s\n", writeBuf);
		writeBytes = PAGE_SIZE;
		
		err = crypto_comp_compress(comp_tfm, readBuf, readBytes, writeBuf, &writeBytes);
		//printk("Compress: readBuf contents after compress are: \n%s\n", readBuf);
		//printk("Compress: writeBuf contents after compress are: \n%s\n", writeBuf);
		//printk("error returned form crypto_comp_compress: %d\n", err);
		if (err < 0)
		{
			printk("Error while Compressing!\n");
			goto out_free_bufLen;
		}
		
		snprintf(bufLen, 5, "%04d", writeBytes);
		
		dest_filp->f_op->write(dest_filp, bufLen, 4, &dest_filp->f_pos);
		//printk(" the length of the %d number buffer is %s\n ",writeBytes,bufLen);
		dest_filp->f_op->write(dest_filp, writeBuf, writeBytes, &dest_filp->f_pos);
		memset(readBuf, '\0', PAGE_SIZE);
	}

	msleep(10 * 1000);

	printk("compression job(%lu) done successfully!\n", my_work_obj->job_obj->job_id);

out_free_bufLen:
	kfree(bufLen);
	bufLen = NULL;
out_close_in_file:
	filp_close(in_filp, NULL);
	in_filp = NULL;
out_free_writebuf:
	kfree(writeBuf);
	writeBuf = NULL;
out_free_readbuf:
	kfree(readBuf);
	readBuf = NULL;
out_close_dest_file:
	filp_close(dest_filp, NULL);
	dest_filp = NULL;
out:
	set_fs(oldfs); //Reset to save FS

	
	/* Cleaning my_work_obj */

	// deleting from custom_queue
	if(delete_from_custom_queue(my_work_obj->job_obj->job_id) != 0)
	{
		printk("ALERT! could not delete work_obj from custom queue\n");
	}
	
	// Cleaning files data from my_work_obj
    for(i = 0; i<my_work_obj->job_obj->no_of_files; i++)
    {
        kfree(my_work_obj->job_obj->files[i]);
        my_work_obj->job_obj->files[i] = NULL;
    }
    kfree(my_work_obj->job_obj->files);
    my_work_obj->job_obj->files = NULL;
		
	// Cleaning Free'ing my_work_obj->job_obj and my_work_obj itself
	kfree(my_work_obj->job_obj);
	my_work_obj->job_obj = NULL;
	kfree(my_work_obj);
	my_work_obj = NULL;


	printk(KERN_ALERT "Exiting compression\n");	
	printk("compress_curr_no_of_jobs: %d\n", job_cnt);

	return;
	
}

static void decompress(struct work_struct *work_obj)
{
	my_work_struct *my_work_obj = (my_work_struct*) work_obj;
	int i = 0;
	int err = 0;
	struct file * dest_filp = NULL;
	struct file * in_filp = NULL;
	char * readBuf = NULL,* writeBuf = NULL;
	int readBytes, intBufLen=0;
	unsigned int writeBytes;
	mm_segment_t oldfs;
	
	struct crypto_comp *comp_tfm = crypto_alloc_comp("deflate", 0, 0);
	printk(KERN_ALERT "Entered decompression\n");
	
	
	oldfs = get_fs();  //Save the current FS segment
	set_fs(KERNEL_DS); //set_fs(get_ds());

    // Open the dest file 
	dest_filp = filp_open(my_work_obj->job_obj->files[0], O_WRONLY|O_TRUNC|O_CREAT, FMODE_WRITE);
	if (!dest_filp || IS_ERR(dest_filp)) 
	{
		printk("Destination file open error %d\n", (int) PTR_ERR(dest_filp));
		err = -ENOENT; // set error 
		goto out;
	}
	if (!(dest_filp->f_op)) 
	{
    	printk(KERN_ALERT "No file operations on the destination file!\n");
    	err = -ENOENT;
    	goto out_close_dest_file;
	}
	if (!dest_filp->f_op->write) 
	{
		printk("No write permission on the destination file!\n");
		err = -ENOENT; // set error
		// file(system) doesn't allow write 
		goto out_close_dest_file;
	}

	// Allocate the buffer for reading from the input file 
	readBuf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!readBuf) 
	{
		err = -ENOMEM;
		printk(KERN_ERR
	   		   "Read buffer allocation failed!\n");
		goto out_close_dest_file;
	}
	memset(readBuf, '\0', PAGE_SIZE);

    writeBuf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!writeBuf) 
	{
        err = -ENOMEM;
        printk(KERN_ERR
                   "Write buffer allocation failed!\n");
        goto out_free_readbuf;
    }
    memset(writeBuf, '\0', PAGE_SIZE);

	// Open input file in read mode 
	in_filp = filp_open(my_work_obj->job_obj->files[1], O_RDONLY, FMODE_READ);
	if (!in_filp || IS_ERR(in_filp)) 
	{
		printk("Input file open error %d\n", (int) PTR_ERR(in_filp));
		err = -ENOENT; // set error 
		goto out_free_writebuf;
	}
	if (!(in_filp->f_op))
		{
        printk(KERN_ALERT "No file operations on the input file!\n");
        err = -ENOENT;
        goto out_close_in_file;
	}
	if (!in_filp->f_op->read)
	{
		printk("No read permission on the input file!\n");
		err = -ENOENT; // set error 
		// file(system) doesn't allow reads 
		goto out_close_in_file;
	}

	readBytes = in_filp->f_op->read(in_filp, readBuf, 4, &in_filp->f_pos);
	intBufLen = (int)(readBuf[3] - 48) + ((int)(readBuf[2] - 48) * 10) + ((int)(readBuf[1] - 48) * 100) + ((int)(readBuf[0] - 48) * 1000);
	//printk("\n the readBufLen=%d  for buffer %s", intBufLen, readBuf);
			
	// Copy the contents from the input file to the dest file 
	while ((readBytes = in_filp->f_op->read(in_filp, readBuf, intBufLen, &in_filp->f_pos)) > 0) 
	{
		//printk("readBuf contents are: \n%s\n", readBuf);
		writeBytes = PAGE_SIZE;
		err = crypto_comp_decompress(comp_tfm, readBuf, readBytes, writeBuf, &writeBytes);
		//printk("error returned from decompress: %d\n", err);
		if (err < 0)
		{
			printk("Error while decompressing!\n");
			goto out_close_in_file;
		}
		dest_filp->f_op->write(dest_filp, writeBuf, writeBytes, &dest_filp->f_pos);
		memset(readBuf, '\0', PAGE_SIZE);
		readBytes = in_filp->f_op->read(in_filp, readBuf, 4, &in_filp->f_pos);
		intBufLen = (int)(readBuf[3] - 48) + ((int)(readBuf[2] - 48) * 10) + ((int)(readBuf[1] - 48) * 100) + ((int)(readBuf[0] - 48) * 1000);
		//printk("\n the readBufLen=%d  for buffer %s",intBufLen,readBuf);
	}

	msleep(10 * 1000);

	printk("Decompression job(%lu) done successfully!\n", my_work_obj->job_obj->job_id);

out_close_in_file:
	filp_close(in_filp, NULL);
	in_filp = NULL;
out_free_writebuf:
	kfree(writeBuf);
	writeBuf = NULL;
out_free_readbuf:
	kfree(readBuf);
	readBuf = NULL;
out_close_dest_file:
	filp_close(dest_filp, NULL);
	dest_filp = NULL;
out:
	set_fs(oldfs); //Reset to save FS
    
	
	/* Cleaning my_work_obj */

	// deleting from custom_queue
	if(delete_from_custom_queue(my_work_obj->job_obj->job_id) != 0)
	{
		printk("ALERT! could not delete work_obj from custom queue\n");
	}
	
	// Cleaning files data from my_work_obj
    for(i = 0; i<my_work_obj->job_obj->no_of_files; i++)
    {
        kfree(my_work_obj->job_obj->files[i]);
        my_work_obj->job_obj->files[i] = NULL;
    }
    kfree(my_work_obj->job_obj->files);
    my_work_obj->job_obj->files = NULL;
		
	// Cleaning Free'ing my_work_obj->job_obj and my_work_obj itself
	kfree(my_work_obj->job_obj);
	my_work_obj->job_obj = NULL;
	kfree(my_work_obj);
	my_work_obj = NULL;


	printk(KERN_ALERT "Exiting decompression\n");
	printk("decompress_curr_no_of_jobs: %d\n", job_cnt);
	
	return;
	
}



static void checksum(struct work_struct *work_obj)
{
	my_work_struct *my_work_obj = (my_work_struct * ) work_obj;
	int i = 0;
	int err = 0;
	struct file *dest_filp = NULL;
	struct file *in_filp = NULL;
	char *readBuf = NULL, *writeBuf = NULL, *bufLen=NULL;
	int readBytes;
	//unsigned int writeBytes;
	struct shash_desc * shash=NULL;
	u8 *md5_hash=NULL;
	struct crypto_shash *md5=NULL;
	mm_segment_t oldfs;
	
	printk(KERN_ALERT "Entered checksum!\n");

	oldfs = get_fs();  //Save the current FS segment
	set_fs(KERNEL_DS); //set_fs(get_ds());
	
	
    // Open the dest file
	dest_filp = filp_open(my_work_obj->job_obj->files[0], O_WRONLY|O_CREAT|O_TRUNC, FMODE_WRITE);
	if (!dest_filp || IS_ERR(dest_filp)) {
		printk("Destination file open error %d\n", (int) PTR_ERR(dest_filp));
		err = -ENOENT; // set error 
		goto out;
	}
	if (!(dest_filp->f_op)) {
    	printk(KERN_ALERT "No file operations on the destination file!\n");
    	err = -ENOENT;
    	goto out_close_dest_file;
	}
	if (!dest_filp->f_op->write) {
		printk("No write permission on the destination file!\n");
		err = -ENOENT; // set error
		// file(system) doesn't allow write 
		goto out_close_dest_file;
	}

	// Allocate the buffer for reading from the input file 
	readBuf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!readBuf) {
		err = -ENOMEM;
		printk(KERN_ERR
	   		   "Read buffer allocation failed!\n");
		goto out_close_dest_file;
	}
	memset(readBuf, '\0', PAGE_SIZE);

	writeBuf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!writeBuf) {
		err = -ENOMEM;
		printk(KERN_ERR
   		   		"Write buffer allocation failed!\n");
		goto out_free_readbuf;
	}
	memset(writeBuf, '\0', PAGE_SIZE);

	// Open input file in read mode
	in_filp = filp_open(my_work_obj->job_obj->files[1], O_RDONLY, FMODE_READ);
	if (!in_filp || IS_ERR(in_filp)) 
	{
		printk("Input file open error: %d\n", (int) PTR_ERR(in_filp));
		err = -ENOENT; // set error 
		goto out_free_writebuf;
	}
	if (!(in_filp->f_op))
	{
        printk(KERN_ALERT "No file operations on the input file!\n");
        err = -ENOENT;
        goto out_close_in_file;
	}
	if (!in_filp->f_op->read)
	{
		printk("No read permission on the input file!\n");
		err = -ENOENT; // set error 
		// file(system) doesn't allow reads 
		goto out_close_in_file;
	}

	bufLen = kmalloc(33, GFP_KERNEL);
	if (!bufLen) 
	{
		err = -ENOMEM;
		printk(KERN_ERR
   		   		"bufLen buffer allocation failed!\n");
		goto out_free_bufLen;
	}
	memset(bufLen, '\0', 33);
	//md5 calculations
	md5 = crypto_alloc_shash("md5", 0, 0); 
    if (IS_ERR(md5))
		goto out_free_bufLen;

    shash = kmalloc(sizeof(struct shash_desc) + crypto_shash_descsize(md5),GFP_KERNEL);
	
	if (!shash)
    {
        printk(KERN_ALERT "shash memory allocation failed!");
        err = -ENOMEM;
		
        goto out_free_shash;
    }

	md5_hash = kmalloc(16,GFP_KERNEL);
	if (!md5_hash)
    {
        printk(KERN_ALERT "md5_hash memory allocation failed!");
        err = -ENOMEM;
        goto out_free_md5_hash;
    }
		
	memset(md5_hash,0,16);
	
	
    shash->tfm = md5;
    shash->flags = 0x0;

    if (crypto_shash_init(shash))
    {
        printk(KERN_ALERT "crypto_shash_init() on given arg Failed!");
        err = -EINVAL;
		//memset(md5_hash,0,16);
        goto out_free_bufLen;
    }

	// get the checksum of  the contents from the input file and store in the dest file 
	while ((readBytes = in_filp->f_op->read(in_filp, readBuf, PAGE_SIZE, &in_filp->f_pos)) > 0) 
	{
		//writeBytes = PAGE_SIZE;
		
		if (crypto_shash_update(shash,(const char *)readBuf,readBytes))
    {
        printk(KERN_ALERT "crypto_shash_update() on given arg Failed!");
        err = -EINVAL;
		//memset(md5_hash,0,17);
        goto out_free_bufLen;
    }
		memset(readBuf, '\0', PAGE_SIZE);
	}
	
	//printk(" keybuf value = %s\n",keyBuf);
    if (crypto_shash_final(shash, md5_hash))
    {
        printk(KERN_ALERT "crypto_shash_final() on given arg Failed!");
        err = -EINVAL;
		//memset(md5_hash,0,17);
        goto out_free_bufLen;
    }
		
		//snprintf(bufLen, 16, "%s", md5_hash);
		for (i=0;i<16;i++){
		printk ("%02x ", md5_hash[i]);
		//bufLen[2*i] = snprintf(bufLen[2*i], 2,"%02X", md5_hash[i]);
		//snprintf(bufLen,2*i,"%02x",md5_hash[i]);
		}
		//dest_filp->f_op->write(dest_filp, bufLen, 16, &dest_filp->f_pos);
		//printk(" the length of the %d number buffer is %s\n ",writeBytes,bufLen);
		//dest_filp->f_op->write(dest_filp, writeBuf, writeBytes, &dest_filp->f_pos);
	
	
	
	snprintf(bufLen,33,"%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
	md5_hash[0],md5_hash[1],md5_hash[2],md5_hash[3],md5_hash[4],md5_hash[5],md5_hash[6],md5_hash[7],md5_hash[8],md5_hash[9],md5_hash[10],md5_hash[11],md5_hash[12],md5_hash[13],md5_hash[14],md5_hash[15]);
	bufLen[32]='\0';
	//sprintf(bufLen,2,"%02x",bufLen[i]);
	printk("\n md5_hash value is %s",bufLen);
	//for (i=0;i<16;i++){
		
		//printk ("%02x", bufLen[i]);
		//snprintf(bufLen,2,"%02x",bufLen[i]);
		//bufLen1 += sprintf(bufLen1, "%02X", bufLen[i]);
		//}
		
		
	dest_filp->f_op->write(dest_filp, bufLen, 33, &dest_filp->f_pos);
		
	msleep(10 * 1000);

	printk("checksum job done successfully!\n");


out_free_md5_hash:	
	kfree(md5_hash);
	md5_hash=NULL;
out_free_shash:	
	kfree(shash);
	crypto_free_shash(md5);
out_free_bufLen:
	kfree(bufLen);
	bufLen = NULL;	
out_close_in_file:
	filp_close(in_filp, NULL);
	in_filp = NULL;
out_free_writebuf:
	kfree(writeBuf);
	writeBuf = NULL;
out_free_readbuf:
	kfree(readBuf);
	readBuf = NULL;
out_close_dest_file:
	filp_close(dest_filp, NULL);
	dest_filp = NULL;
out:
	set_fs(oldfs); //Reset to save FS
    
	
	/* Cleaning my_work_obj */

	// deleting from custom_queue
	if(delete_from_custom_queue(my_work_obj->job_obj->job_id) != 0)
	{
		printk("ALERT! could not delete work_obj from custom queue\n");
	}
	
	// Cleaning files data from my_work_obj
    for(i = 0; i<my_work_obj->job_obj->no_of_files; i++)
    {
        kfree(my_work_obj->job_obj->files[i]);
        my_work_obj->job_obj->files[i] = NULL;
    }
    kfree(my_work_obj->job_obj->files);
    my_work_obj->job_obj->files = NULL;
		
	// Cleaning Free'ing my_work_obj->job_obj and my_work_obj itself
	kfree(my_work_obj->job_obj);
	my_work_obj->job_obj = NULL;
	kfree(my_work_obj);
	my_work_obj = NULL;


	printk(KERN_ALERT "Exiting checksum\n");
	printk("checksum_curr_no_of_jobs: %d\n", job_cnt);
	
	return;
}


/*
	Description: Checks if the file "do not exist" already.
	
	@param filename: filename which has to be chcked to not to be existing already.
	@return: 1 if it does not exist already else 0
*/
int check_if_file_do_not_exist(char *filename)
{
	struct file *filep;

	filep = filp_open(filename, O_RDONLY, 0);
	if(IS_ERR(filep)) 
	{
		return 1;
	}

	filp_close(filep,NULL);
	return 0;
}


// Copied from net/ceph/crypto.c (Kernel source code): as it is
/*
 * Should be used for buffers allocated with ceph_kvmalloc().
 * Currently these are encrypt out-buffer (ceph_buffer) and decrypt
 * in-buffer (msg front).
 *
 * Dispose of @sgt with teardown_sgtable().
 *
 * @prealloc_sg is to avoid memory allocation inside sg_alloc_table()
 * in cases where a single sg is sufficient.  No attempt to reduce the
 * number of sgs by squeezing physically contiguous pages together is
 * made though, for simplicity.
 */
static int setup_sgtable(struct sg_table *sgt, struct scatterlist *prealloc_sg,
						 const void *buf, unsigned int buf_len)
{
		struct scatterlist *sg;
		const bool is_vmalloc = is_vmalloc_addr(buf);
		unsigned int off = offset_in_page(buf);
		unsigned int chunk_cnt = 1;
		unsigned int chunk_len = PAGE_ALIGN(off + buf_len);
		int i;
		int ret;

		if (buf_len == 0) {
				memset(sgt, 0, sizeof(*sgt));
				return -EINVAL;
		}

		if (is_vmalloc) {
				chunk_cnt = chunk_len >> PAGE_SHIFT;
				chunk_len = PAGE_SIZE;
		}

		if (chunk_cnt > 1) {
				ret = sg_alloc_table(sgt, chunk_cnt, GFP_NOFS);
				if (ret)
						return ret;
		} else {
				WARN_ON(chunk_cnt != 1);
				sg_init_table(prealloc_sg, 1);
				sgt->sgl = prealloc_sg;
				sgt->nents = sgt->orig_nents = 1;
		}

		for_each_sg(sgt->sgl, sg, sgt->orig_nents, i) {
				struct page *page;
				unsigned int len = min(chunk_len - off, buf_len);

				if (is_vmalloc)
						page = vmalloc_to_page(buf);
				else
						page = virt_to_page(buf);

				sg_set_page(sg, page, len, off);

				off = 0;
				buf += len;
				buf_len -= len;
		}
		WARN_ON(buf_len != 0);

		return 0;
}

// Copied from net/ceph/crypto.c : as it is
static void teardown_sgtable(struct sg_table *sgt)
{
		if (sgt->orig_nents > 1)
				sg_free_table(sgt);
}

// Copied from net/ceph/crypto.c (Kernel source code) : as it is
static int ceph_aes_encrypt(const void *key, int key_len,
							void *dst, size_t *dst_len,
							const void *src, size_t src_len)
{
	struct scatterlist sg_in[2], prealloc_sg;
	struct sg_table sg_out;
	struct crypto_blkcipher *tfm = crypto_alloc_blkcipher("cbc(aes)", 0, CRYPTO_ALG_ASYNC);
	struct blkcipher_desc desc = { .tfm = tfm, .flags = 0 };
	int ret;
	void *iv;
	int ivsize;
	size_t zero_padding = (0x10 - (src_len & 0x0f));
	char pad[16];

	if (IS_ERR(tfm))
			return PTR_ERR(tfm);

	memset(pad, zero_padding, zero_padding);

	*dst_len = src_len + zero_padding;

	sg_init_table(sg_in, 2);
	sg_set_buf(&sg_in[0], src, src_len);
	sg_set_buf(&sg_in[1], pad, zero_padding);
	ret = setup_sgtable(&sg_out, &prealloc_sg, dst, *dst_len);
	if (ret)
			goto out_tfm;

	crypto_blkcipher_setkey((void *)tfm, key, key_len);
	iv = crypto_blkcipher_crt(tfm)->iv;
	ivsize = crypto_blkcipher_ivsize(tfm);
	memcpy(iv, aes_iv, ivsize);

	ret = crypto_blkcipher_encrypt(&desc, sg_out.sgl, sg_in,
								 src_len + zero_padding);
	if (ret < 0) {
			pr_err("ceph_aes_crypt failed %d\n", ret);
			goto out_sg;
	}

	out_sg:
		teardown_sgtable(&sg_out);
	out_tfm:
		crypto_free_blkcipher(tfm);
	return ret;
}


// Copied from net/ceph/crypto.c (Kernel source code) : made minimal changes
static int ceph_aes_decrypt(const void *key, int key_len,
							void *dst, size_t *dst_len,
							const void *src, size_t src_len)
{
	struct scatterlist sg_in[1], sg_out[2];
	struct crypto_blkcipher *tfm = crypto_alloc_blkcipher("cbc(aes)", 0, CRYPTO_ALG_ASYNC);
	struct blkcipher_desc desc = { .tfm = tfm };
	char pad[16];
	void *iv;
	int ivsize;
	int ret;
	
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);
	
	crypto_blkcipher_setkey((void *)tfm, key, key_len);
	sg_init_table(sg_in, 1);
	sg_init_table(sg_out, 2);
	sg_set_buf(sg_in, src, src_len);
	sg_set_buf(&sg_out[0], dst, *dst_len);
	sg_set_buf(&sg_out[1], pad, sizeof(pad));

	iv = crypto_blkcipher_crt(tfm)->iv;
	ivsize = crypto_blkcipher_ivsize(tfm);
	
	memcpy(iv, aes_iv, ivsize); 

	ret = crypto_blkcipher_decrypt(&desc, sg_out, sg_in, src_len);
	crypto_free_blkcipher(tfm);
	if (ret < 0) {
		pr_err("ceph_aes_decrypt failed %d\n", ret);
		return ret;
	}

	return 0;
}



/*
	Description: checks if the input and output file are not same.
	
	@param in_file: file* pointing to input file in kernel space
	@param out_file: file* pointing to output file in kernel space        
	@return: 1 if both the files are same else 0.
	
	REFERENCES:
		http://sophie.zarb.org/distrib/CentOS/5/i386/by-pkgid/ea32411352494358b8d75a78402a4713/files/3494
*/
static inline int validate_files_not_same(struct file *in_file, struct file *out_file)
{

	struct inode *in_inode = in_file->f_path.dentry->d_inode;
	struct inode *out_inode = out_file->f_path.dentry->d_inode;

	return (( strcmp(in_inode->i_sb->s_id, out_inode->i_sb->s_id) == 0) && (in_inode->i_ino == out_inode->i_ino) );
}

    // copied from fs/dcache.c (Kernel source code) : as it is
    struct dentry *d_ancestor(struct dentry *p1, struct dentry *p2)
    {
        struct dentry *p;

        for (p = p2; !IS_ROOT(p); p = p->d_parent) 
        {
            if (p->d_parent == p1)
                    return p;
        }
        return NULL;
    }

    // copied from /fs/namei.c (kernel source code) : as it is
    struct dentry *lock_rename(struct dentry *p1, struct dentry *p2)
    {
        struct dentry *p;

        if (p1 == p2) {
                mutex_lock_nested(&p1->d_inode->i_mutex, I_MUTEX_PARENT);
                return NULL;
        }

        mutex_lock(&p1->d_inode->i_sb->s_vfs_rename_mutex);

        p = d_ancestor(p2, p1);
        if (p) {
                mutex_lock_nested(&p2->d_inode->i_mutex, I_MUTEX_PARENT);
                mutex_lock_nested(&p1->d_inode->i_mutex, I_MUTEX_CHILD);
                return p;
        }

        p = d_ancestor(p1, p2);
        if (p) {
                mutex_lock_nested(&p1->d_inode->i_mutex, I_MUTEX_PARENT);
                mutex_lock_nested(&p2->d_inode->i_mutex, I_MUTEX_CHILD);
                return p;
        }

        mutex_lock_nested(&p1->d_inode->i_mutex, I_MUTEX_PARENT);
        mutex_lock_nested(&p2->d_inode->i_mutex, I_MUTEX_PARENT2);
        return NULL;
    }

    // copied from fs/namei.c (Kernel source code) : as it is
    void unlock_rename(struct dentry *p1, struct dentry *p2)
    {
        mutex_unlock(&p1->d_inode->i_mutex);
        if (p1 != p2) 
        {
            mutex_unlock(&p2->d_inode->i_mutex);
            mutex_unlock(&p1->d_inode->i_sb->s_vfs_rename_mutex);
        }
    }


    /*
        Description: Does the job of vfs_rename, but takes mutex lock before calling vfs_rename and releases locks later.
        
        @param old_parent_dentry: struct dentry* pointing to the dentry of the parent of old file (file to be renamed) 
        @param old_dentry: struct dentry* pointing to the dentry of the old file
        @param new_parent_dentry: struct dentry* pointing to the dentry of the parent of new file (file to be renames to)
        @param new_dentry: struct dentry* pointing to the dentry of the parent of new file

        @return: 0 if rename happens successfuly else -ve (standard error_code) if any validations fails.
        
        REFERENCES:
            wrapfs_rename: http://lxr.fsl.cs.sunysb.edu/linux/source/fs/wrapfs/inode.c#L235
            vfs_rename:    http://lxr.fsl.cs.sunysb.edu/linux/source/fs/namei.c#L4109
    */
    long custom_vfs_rename( struct dentry *old_parent_dentry, struct dentry *old_dentry, 
                            struct dentry *new_parent_dentry, struct dentry *new_dentry)
    {
        int error = 0;
        struct dentry *trap = NULL;
        
        // Taking locks before calling vfs_rename
        trap = lock_rename(old_parent_dentry, new_parent_dentry);

        /* source should not be ancestor of target */
        if (trap == old_dentry) 
        {
            error = -EINVAL;
            goto out;
        }
        /* target should not be ancestor of source */
        if (trap == new_dentry) 
        {
            error = -ENOTEMPTY;
            goto out;
        }

        // actual vfs_rename call
        error = vfs_rename( old_parent_dentry->d_inode, old_dentry, 
                            new_parent_dentry->d_inode, new_dentry, NULL, 0 );

        out:
            // releasing locks
            unlock_rename(old_parent_dentry,new_parent_dentry);

        return error;
    }

 struct file* open_output_file(char *out_file,umode_t mode)
    {
    	struct file *filep = NULL;


    	// Check for the errors and return NULL if error is found. 
    	// Close file if opened and error found.
    	if(out_file == NULL)
    	{
    		printk(KERN_ALERT "*out_file passed was NULL\n");
    		return NULL;
    	}

      	filep = filp_open(out_file, O_WRONLY|O_CREAT, mode);

      	if(IS_ERR(filep))
      	{
        	printk(KERN_ALERT "Error occured in opening mentioned file\n");
    		return NULL;	
      	}
    	
    	if ( !(filep->f_op) )
    	{
    		printk(KERN_ALERT "f_op (operations of file missing) of file missing!\n");
    		filp_close(filep, NULL);
    		return NULL;
    	}

    	if (!filep->f_op->write){
    		printk(KERN_ALERT "f_op->write (write operation) missing on file (But, File opened to write)\n");
    		filp_close(filep, NULL);
    		return NULL;
    	}  
      	
    	
    	return filep;
    }


    /*
        Description: Opens the input; handles the errors in opening file if any occurs.
        
        @param in_file: input_file_name, stored in kernel space char* variable.
        @return: NULL in case of error, else reference (pointer) to the struct file pointing to output_file         
        
        REFERENCES:
            Same as open_output_file()'s references
    */
    struct file* open_input_file(char *in_file)
    {	
    	struct file *filep = NULL;
    	

    	// Check for the errors and return NULL if error is found. 
    	// Close file if opened and error found.
    	if(in_file == NULL)
    	{
    		printk(KERN_ALERT "*in_file passed was NULL\n");
    		return NULL;
    	}

    	filep = filp_open(in_file, O_EXCL, 0);
    	
    	if(IS_ERR(filep))
    	{
    		printk(KERN_ALERT "Error occured in opening mentioned file\n");
    		return NULL;
    	}	

    	if ( !(filep->f_op) )
    	{
    		printk(KERN_ALERT "f_op (operations of file missing) of file missing!\n");
    		filp_close(filep, NULL);
    		return NULL;
    	}

    	if (!filep->f_op->read)
    	{
    		printk(KERN_ALERT "f_op->read (read operation) missing on file (But, File opened to read)\n");
    		filp_close(filep, NULL);
    		return NULL;
    	}  
    	
    	return filep;	
    }


	
static void encryption(struct work_struct *work_obj)
{	
	// Code structure is as mentioned: (#tags for indexing code sections)
	// 1. #varDec : vairable declarations 
	// 2. #memPlace : variable memory allocations and initialisation (memset)
	// 3. #validateArgs : Validation of the arguments sent from userspace
	// 4. #copyArgs : copying arguments from user-space to kernel-space struct
	// 5. #ioPlace : open input and output files and validations of input/output files
	// 6. #md5Place : Calculating MD5 hash of keybuf
	// 7. #encryptDecrypt : encryption or decryption on the basis of flags passed.
	// 8. #renameTempFile : Rename the temp file to the output_file_name using custom_vfs_rename
	// 9. #freePlace : deallocating / free'ng the memory allocated of buffers

	//    #debug : denotes just random debug statements, but will have been commented_out

	/* #varDec */
	//syscall_args *k_args = NULL;
	printk(KERN_ALERT "entered Encryption \n");
	my_work_struct *my_work_obj = (my_work_struct * ) work_obj;
	mm_segment_t fs;
	umode_t in_file_mode;
	struct file *in_file = NULL;
	struct file *out_file = NULL, *out_tmp_file = NULL;
	struct crypto_shash *md5;
	struct shash_desc *shash;		
	int i,buf_len=16,padding_pos,pad_val, ret, pad_size, output_file_to_be_deleted = 0,keylen=16;
	long error, pad_size_long;
	size_t in_data_size,read_size;
	char *in_data_buf, *en_in_data_buf, *hashed_key_buf, *en_pad_size_buf, *pad_size_buf; 
	char *tmp_suffix = ".temp",*tmp_output_filename;
	char *keybuf=NULL;
	char pad_size_tmp[3];
	u8 *md5_hash = NULL;

	// #memPlace  	
	//k_args = kmalloc(sizeof(syscall_args), GFP_KERNEL);
	//if (!k_args)
	//{
	//	printk(KERN_ALERT "memory allocation of k_args failed!\n");
	//	error = -ENOMEM;
	//	goto FINAL_OUT;
	//}
	//memset(k_args, 0, sizeof(syscall_args));
	
	
	
	md5_hash = kmalloc(16, GFP_KERNEL);
	if (!md5_hash)
	{
		printk(KERN_ALERT "memory allocation of md5_hash failed!\n");
		error = -ENOMEM;
		goto CLEAN_KARGS_EXIT;            
	}
	memset(md5_hash, 0, 16);
	
	pad_size_buf = (char *) kmalloc(16, GFP_KERNEL);
	if (!pad_size_buf)
	{
		printk(KERN_ALERT "memory allocation of pad_size_buf failed!\n");
		error = -ENOMEM;
		goto CLEAN_MD5_HASH_EXIT;            
	}
	memset(pad_size_buf, 0, 16);

	en_pad_size_buf = (char *) kmalloc(16, GFP_KERNEL);
	if (!en_pad_size_buf)
	{
		printk(KERN_ALERT "memory allocation of en_pad_size_buf failed!\n");
		error = -ENOMEM;
		goto CLEAN_PAD_SIZE_BUF_EXIT;            
	}
	memset(en_pad_size_buf, 0, 16);
	
	in_data_buf = (char *) kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!in_data_buf)
	{
		printk(KERN_ALERT "memory allocation of in_data_buf failed!\n");
		error = -ENOMEM;
		goto CLEAN_EN_PAD_SIZE_BUF_EXIT;            
	}
	memset(in_data_buf, 0, PAGE_SIZE);
	
	en_in_data_buf = (char *) kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!en_in_data_buf)
	{
		printk(KERN_ALERT "memory allocation of en_in_data_buf failed!\n");
		error = -ENOMEM;
		goto CLEAN_IN_DATA_BUF_EXIT;            
	}
	memset(en_in_data_buf, 0, PAGE_SIZE);

	hashed_key_buf = (char *) kmalloc(16, GFP_KERNEL);
	if (!hashed_key_buf)
	{
		printk(KERN_ALERT "memory allocation of hashed_key_buf failed!\n");
		error = -ENOMEM;
		goto CLEAN_EN_IN_DATA_BUF_EXIT;            
	}
	memset(hashed_key_buf, 0, 16);

	keybuf = (char *) kmalloc(16, GFP_KERNEL);
	if (!keybuf)
	{
		printk(KERN_ALERT "memory allocation of keybuf failed!\n");
		error = -ENOMEM;
		goto CLEAN_KEYBUF_EXIT;            
	}
	memset(keybuf, 0, 16);
	memcpy(keybuf,my_work_obj->job_obj->files[0],16);
	printk(" the keybuf received %s\n",keybuf);
	// #validateArgs 
	//error = validate_user_arguments(arg);
	//if (error != 0) 
	//{
	//	printk(KERN_ALERT "Validations of the user arguments failed!");
	//	goto CLEAN_HASHED_KEY_BUF_EXIT;
	//}   



	// #copyArgs 
	// @TODO: validations in copy function.
	//error = copy_arguments_from_user_to_kernel_space(arg, k_args);      
	//if(error!=0)
	//{
	//	printk(KERN_ALERT "Some error occured, in copying");
	//	goto CLEAN_HASHED_KEY_BUF_EXIT;
	//}

	tmp_output_filename = (char *) kmalloc(strlen(my_work_obj->job_obj->files[1]) + strlen(tmp_suffix) + 1, GFP_KERNEL);
	
	if (!tmp_output_filename)
	{
		printk(KERN_ALERT "memory allocation of tmp_output_filename failed!\n");
		error = -ENOMEM;
		goto CLEAN_HASHED_KEY_BUF_EXIT;            
	}
	memset(tmp_output_filename, 0, strlen(my_work_obj->job_obj->files[1])+strlen(tmp_suffix)+1);
	memcpy(tmp_output_filename,my_work_obj->job_obj->files[1],strlen(my_work_obj->job_obj->files[1]));
	memcpy(tmp_output_filename + strlen(my_work_obj->job_obj->files[1]), tmp_suffix, strlen(tmp_suffix));
	tmp_output_filename[strlen(tmp_output_filename)] = '\0';
	printk("The tmp_output_filename is %s \n",tmp_output_filename);


	// #ioPlace 
	// Lets open the input file and fetch the corresponding permissions as well
	in_file = open_input_file(my_work_obj->job_obj->files[2]); 
	if (in_file == NULL)
	{
		printk(KERN_ALERT "could not open the input file!\n");
		error = -ENOENT;
		goto CLEAN_HASHED_KEY_BUF_EXIT;
	}

	// Get mode and size of the input file. Mode required before opening output file.
	// as we are opening the output file with same mode as input file's mode
	in_file_mode = in_file->f_path.dentry->d_inode->i_mode;
	in_data_size = in_file->f_path.dentry->d_inode->i_size;



	// ** Kindly note: out_file points to temporary file and out_tmp_file points to actual output file.
	// **     This just happened to be so, coz of the incremental code convention i used.


	// check if output file already exists. 
	// If it does not exist already, then it has to be deleted in case of failure
	output_file_to_be_deleted = check_if_file_do_not_exist(my_work_obj->job_obj->files[1]);

	// Lets open the output file and and provide the permissions fetched from input file
	// Original : out_file = open_output_file(k_args->out_file,in_file_mode);
	out_file = open_output_file(tmp_output_filename,in_file_mode);
	if (out_file ==NULL)
	{
		printk(KERN_ALERT "could not open the output file!\n");
		error = -ENOENT;
		goto CLOSE_IN_FILE_EXIT;
	}   

	if(validate_files_not_same(in_file,out_file))
	{
		printk(KERN_ALERT "Validation Failed! input and output.temp are same files\n");
		error = -EINVAL;
		goto CLOSE_OUT_FILE_EXIT;
	}
	
	// out tmp file
	out_tmp_file = open_output_file(my_work_obj->job_obj->files[1],in_file_mode);
	if (out_tmp_file ==NULL)
	{
		printk(KERN_ALERT "could not open the output file!\n");
		error = -ENOENT;
		goto CLOSE_OUT_FILE_EXIT;
	}

	if(validate_files_not_same(in_file,out_tmp_file))
	{
		printk(KERN_ALERT "Validation Failed! input and output are same files\n");
		error = -EINVAL;
		goto CLOSE_OUT_TMP_FILE_EXIT;
	}	    	



	/* #md5Place */
	md5 = crypto_alloc_shash("md5", 0, 0);
	if (IS_ERR(md5))
			error= -1;

	shash = kmalloc(sizeof(struct shash_desc) + crypto_shash_descsize(md5),GFP_KERNEL);

	if (!shash)
	{
		printk(KERN_ALERT "shash memory allocation failed!");
		error = -ENOMEM;
		goto CLOSE_OUT_TMP_FILE_EXIT;
	}

	shash->tfm = md5;
	shash->flags = 0x0;

	if (crypto_shash_init(shash))
	{
		printk(KERN_ALERT "crypto_shash_init() on given arg Failed!");
		error = -EINVAL;
		goto CLOSE_OUT_TMP_FILE_EXIT;
	}

	if (crypto_shash_update(shash,(const char *)keybuf,keylen))
	{
		printk(KERN_ALERT "crypto_shash_update() on given arg Failed!");
		error = -EINVAL;
		goto CLOSE_OUT_TMP_FILE_EXIT;
	}   

	if (crypto_shash_final(shash, md5_hash))
	{
		printk(KERN_ALERT "crypto_shash_final() on given arg Failed!");
		error = -EINVAL;
		goto CLOSE_OUT_TMP_FILE_EXIT;
	}
	kfree(shash);
	crypto_free_shash(md5);



	/* #encryptDecrypt */
	fs = get_fs();
	set_fs(get_ds());

	out_file->f_op->write(out_file,md5_hash,16,&out_file->f_pos);
			
	// Lets find out end_of_file_padding_size, pad it as well, encrypt it and write it in output_file
	if((in_data_size%16) == 0)
	{
		pad_size = 0;
	}
	else
	{
		pad_size = 16 - (in_data_size%16);
	}
	
	sprintf(pad_size_tmp,"%d",pad_size);
	pad_size_tmp[2] = '\0';
	memcpy(pad_size_buf,pad_size_tmp,2); 

	buf_len=16;	
	error = ceph_aes_encrypt(md5_hash,16,en_pad_size_buf,&buf_len,pad_size_buf,16);

	if(error<0)
	{
		printk(KERN_ALERT "Encryption of pad_size_buf failed! \n");
		error = -EFAULT;    
		goto CLOSE_OUT_TMP_FILE_EXIT;
	}	
	out_file->f_op->write(out_file,en_pad_size_buf,16,&out_file->f_pos);            
	

	// Now lets read the complete file in PAGE_SIZE in loop and encrypt and write it in output_file 
	i=0;
	while ((read_size = in_file->f_op->read(in_file,in_data_buf,PAGE_SIZE,&in_file->f_pos)) > 0)	
	{	

		if(read_size == PAGE_SIZE)
		{	buf_len = PAGE_SIZE;
			error = ceph_aes_encrypt(md5_hash,16,en_in_data_buf,&buf_len,in_data_buf,PAGE_SIZE);
			if(error<0)
			{
				printk(KERN_ALERT "Encryption of whole-page input_data at iteration: %d failed!\n",i);
				error = -EFAULT;
				goto CLOSE_OUT_TMP_FILE_EXIT;
			}
			
			out_file->f_op->write(out_file,en_in_data_buf,PAGE_SIZE,&out_file->f_pos);
		}	
		else
		{	
			pad_val = 0;
			for(padding_pos=0;padding_pos<pad_size;padding_pos++)
			{
				memcpy(in_data_buf+read_size+padding_pos,&pad_val,1);
			}
			buf_len = read_size+pad_size;
			memset(en_in_data_buf, 0, PAGE_SIZE);
			error = ceph_aes_encrypt(md5_hash,16,en_in_data_buf,&buf_len,in_data_buf,buf_len);
			if(error<0)
			{
				printk(KERN_ALERT "Encryption of partial-page input_data at iteration: %d failed!\n",i);
				error = -EFAULT;
				goto CLOSE_OUT_TMP_FILE_EXIT;
			}
			
			out_file->f_op->write(out_file,en_in_data_buf,read_size+pad_size,&out_file->f_pos);
		}
	i++;
	}
	set_fs(fs);	



	/* #renameTempFile */
	error = custom_vfs_rename(out_file->f_path.dentry->d_parent, out_file->f_path.dentry, 
		out_tmp_file->f_path.dentry->d_parent, out_tmp_file->f_path.dentry);

	if(error < 0)
	{
		error = -EPERM;
		printk( KERN_ALERT "vfs_rename failed!\n");
	}



	/* #freePlace */
	CLOSE_OUT_TMP_FILE_EXIT:
		filp_close(out_tmp_file, NULL);
		if (error < 0)
		{
			// Kindly note: out_file points to temporary file and out_tmp_file points to actual output file.
			//      This just happened to be so, coz of the incremental code convention i used.
			// delete both out_file and out_tmp_file
			if (output_file_to_be_deleted == 1 && out_tmp_file != NULL && out_tmp_file->f_path.dentry != NULL && out_tmp_file->f_path.dentry->d_parent->d_inode != NULL)
			{
				vfs_unlink(out_tmp_file->f_path.dentry->d_parent->d_inode, out_tmp_file->f_path.dentry, NULL);
			}
		}

	CLOSE_OUT_FILE_EXIT:
		filp_close(out_file, NULL);
		if (error < 0)
		{
			// Kindly note: out_file points to temporary file and out_tmp_file points to actual output file.
			//      This just happened to be so, coz of the incremental code convention i used.
			// delete both out_file and out_tmp_file
			if (out_file != NULL && out_file->f_path.dentry != NULL && out_file->f_path.dentry->d_parent->d_inode != NULL)
			{
				vfs_unlink(out_file->f_path.dentry->d_parent->d_inode, out_file->f_path.dentry, NULL);
			}
		}

	CLOSE_IN_FILE_EXIT:
		filp_close(in_file, NULL);

	CLEAN_HASHED_KEY_BUF_EXIT:
		kfree(hashed_key_buf);

	CLEAN_KEYBUF_EXIT:
		kfree(keybuf);	
		
	CLEAN_EN_IN_DATA_BUF_EXIT:
		kfree(en_in_data_buf);

	CLEAN_IN_DATA_BUF_EXIT:
		kfree(in_data_buf);

	CLEAN_EN_PAD_SIZE_BUF_EXIT:
		kfree(en_pad_size_buf);

	CLEAN_PAD_SIZE_BUF_EXIT:
		kfree(pad_size_buf);

	CLEAN_MD5_HASH_EXIT:
		kfree(md5_hash);

	CLEAN_KARGS_EXIT:
	//	kfree(k_args);
		
	FINAL_OUT:
	
	
	/* Cleaning my_work_obj */

	// deleting from custom_queue
	if(delete_from_custom_queue(my_work_obj->job_obj->job_id) != 0)
	{
		printk("ALERT! could not delete work_obj from custom queue\n");
	}
	
	// Cleaning files data from my_work_obj
    for(i = 1; i<my_work_obj->job_obj->no_of_files; i++)
    {
        kfree(my_work_obj->job_obj->files[i]);
        my_work_obj->job_obj->files[i] = NULL;
    }
    kfree(my_work_obj->job_obj->files);
    my_work_obj->job_obj->files = NULL;
		
	// Cleaning Free'ing my_work_obj->job_obj and my_work_obj itself
	kfree(my_work_obj->job_obj);
	my_work_obj->job_obj = NULL;
	kfree(my_work_obj);
	my_work_obj = NULL;


	printk(KERN_ALERT "Exiting encryption\n");
	printk("encryption_curr_no_of_jobs: %d\n", job_cnt);
	
	return;

}


static void decryption(struct work_struct *work_obj)
{	
	// Code structure is as mentioned: (#tags for indexing code sections)
	// 1. #varDec : vairable declarations 
	// 2. #memPlace : variable memory allocations and initialisation (memset)
	// 3. #validateArgs : Validation of the arguments sent from userspace
	// 4. #copyArgs : copying arguments from user-space to kernel-space struct
	// 5. #ioPlace : open input and output files and validations of input/output files
	// 6. #md5Place : Calculating MD5 hash of keybuf
	// 7. #encryptDecrypt : encryption or decryption on the basis of flags passed.
	// 8. #renameTempFile : Rename the temp file to the output_file_name using custom_vfs_rename
	// 9. #freePlace : deallocating / free'ng the memory allocated of buffers

	//    #debug : denotes just random debug statements, but will have been commented_out

	/* #varDec */
	//syscall_args *k_args = NULL;
	printk(KERN_ALERT "entered decryption \n");
	my_work_struct *my_work_obj = (my_work_struct * ) work_obj;
	mm_segment_t fs;
	umode_t in_file_mode;
	struct file *in_file = NULL;
	struct file *out_file = NULL, *out_tmp_file = NULL;
	struct crypto_shash *md5;
	struct shash_desc *shash;		
	int i,buf_len=16,padding_pos,pad_val, ret, pad_size, output_file_to_be_deleted = 0,keylen=16;
	long error, pad_size_long;
	size_t in_data_size,read_size;
	char *in_data_buf, *en_in_data_buf, *hashed_key_buf, *en_pad_size_buf, *pad_size_buf; 
	char *tmp_suffix = ".temp",*tmp_output_filename;
	char *keybuf=NULL;
	char pad_size_tmp[3];
	u8 *md5_hash = NULL;

	// #memPlace  	
	//k_args = kmalloc(sizeof(syscall_args), GFP_KERNEL);
	//if (!k_args)
	//{
	//	printk(KERN_ALERT "memory allocation of k_args failed!\n");
	//	error = -ENOMEM;
	//	goto FINAL_OUT;
	//}
	//memset(k_args, 0, sizeof(syscall_args));
	
	md5_hash = kmalloc(16, GFP_KERNEL);
	if (!md5_hash)
	{
		printk(KERN_ALERT "memory allocation of md5_hash failed!\n");
		error = -ENOMEM;
		goto CLEAN_KARGS_EXIT;            
	}
	memset(md5_hash, 0, 16);
	
	pad_size_buf = (char *) kmalloc(16, GFP_KERNEL);
	if (!pad_size_buf)
	{
		printk(KERN_ALERT "memory allocation of pad_size_buf failed!\n");
		error = -ENOMEM;
		goto CLEAN_MD5_HASH_EXIT;            
	}
	memset(pad_size_buf, 0, 16);

	en_pad_size_buf = (char *) kmalloc(16, GFP_KERNEL);
	if (!en_pad_size_buf)
	{
		printk(KERN_ALERT "memory allocation of en_pad_size_buf failed!\n");
		error = -ENOMEM;
		goto CLEAN_PAD_SIZE_BUF_EXIT;            
	}
	memset(en_pad_size_buf, 0, 16);
	
	in_data_buf = (char *) kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!in_data_buf)
	{
		printk(KERN_ALERT "memory allocation of in_data_buf failed!\n");
		error = -ENOMEM;
		goto CLEAN_EN_PAD_SIZE_BUF_EXIT;            
	}
	memset(in_data_buf, 0, PAGE_SIZE);
	
	en_in_data_buf = (char *) kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!en_in_data_buf)
	{
		printk(KERN_ALERT "memory allocation of en_in_data_buf failed!\n");
		error = -ENOMEM;
		goto CLEAN_IN_DATA_BUF_EXIT;            
	}
	memset(en_in_data_buf, 0, PAGE_SIZE);

	hashed_key_buf = (char *) kmalloc(16, GFP_KERNEL);
	if (!hashed_key_buf)
	{
		printk(KERN_ALERT "memory allocation of hashed_key_buf failed!\n");
		error = -ENOMEM;
		goto CLEAN_EN_IN_DATA_BUF_EXIT;            
	}
	memset(hashed_key_buf, 0, 16);
	keybuf = (char *) kmalloc(16, GFP_KERNEL);
	if (!keybuf)
	{
		printk(KERN_ALERT "memory allocation of keybuf failed!\n");
		error = -ENOMEM;
		goto CLEAN_KEYBUF_EXIT;            
	}
	memset(keybuf, 0, 16);
	memcpy(keybuf,my_work_obj->job_obj->files[0],16);
	printk(" the keybuf received %s\n",keybuf);


	// #validateArgs 
	//error = validate_user_arguments(arg);
	//if (error != 0) 
	//{
	//	printk(KERN_ALERT "Validations of the user arguments failed!");
	//	goto CLEAN_HASHED_KEY_BUF_EXIT;
	//}   



	// #copyArgs 
	// @TODO: validations in copy function.
	//error = copy_arguments_from_user_to_kernel_space(arg, k_args);      
	//if(error!=0)
	//{
	//	printk(KERN_ALERT "Some error occured, in copying");
	//	goto CLEAN_HASHED_KEY_BUF_EXIT;
	//}

	tmp_output_filename = (char *) kmalloc(strlen(my_work_obj->job_obj->files[1]) + strlen(tmp_suffix) + 1, GFP_KERNEL);
	
	if (!tmp_output_filename)
	{
		printk(KERN_ALERT "memory allocation of tmp_output_filename failed!\n");
		error = -ENOMEM;
		goto CLEAN_HASHED_KEY_BUF_EXIT;            
	}
	memset(tmp_output_filename, 0, strlen(my_work_obj->job_obj->files[1])+strlen(tmp_suffix)+1);
	memcpy(tmp_output_filename,my_work_obj->job_obj->files[1],strlen(my_work_obj->job_obj->files[1]));
	memcpy(tmp_output_filename + strlen(my_work_obj->job_obj->files[1]), tmp_suffix, strlen(tmp_suffix));
	tmp_output_filename[strlen(tmp_output_filename)] = '\0';
	printk("The tmp_output_filename is %s \n",tmp_output_filename);


	// #ioPlace 
	// Lets open the input file and fetch the corresponding permissions as well
	in_file = open_input_file(my_work_obj->job_obj->files[2]); 
	if (in_file == NULL)
	{
		printk(KERN_ALERT "could not open the input file!\n");
		error = -ENOENT;
		goto CLEAN_HASHED_KEY_BUF_EXIT;
	}

	// Get mode and size of the input file. Mode required before opening output file.
	// as we are opening the output file with same mode as input file's mode
	in_file_mode = in_file->f_path.dentry->d_inode->i_mode;
	in_data_size = in_file->f_path.dentry->d_inode->i_size;



	// ** Kindly note: out_file points to temporary file and out_tmp_file points to actual output file.
	// **     This just happened to be so, coz of the incremental code convention i used.


	// check if output file already exists. 
	// If it does not exist already, then it has to be deleted in case of failure
	output_file_to_be_deleted = check_if_file_do_not_exist(my_work_obj->job_obj->files[1]);

	// Lets open the output file and and provide the permissions fetched from input file
	// Original : out_file = open_output_file(k_args->out_file,in_file_mode);
	out_file = open_output_file(tmp_output_filename,in_file_mode);
	if (out_file ==NULL)
	{
		printk(KERN_ALERT "could not open the output file!\n");
		error = -ENOENT;
		goto CLOSE_IN_FILE_EXIT;
	}   

	if(validate_files_not_same(in_file,out_file))
	{
		printk(KERN_ALERT "Validation Failed! input and output.temp are same files\n");
		error = -EINVAL;
		goto CLOSE_OUT_FILE_EXIT;
	}
	
	// out tmp file
	out_tmp_file = open_output_file(my_work_obj->job_obj->files[1],in_file_mode);
	if (out_tmp_file ==NULL)
	{
		printk(KERN_ALERT "could not open the output file!\n");
		error = -ENOENT;
		goto CLOSE_OUT_FILE_EXIT;
	}

	if(validate_files_not_same(in_file,out_tmp_file))
	{
		printk(KERN_ALERT "Validation Failed! input and output are same files\n");
		error = -EINVAL;
		goto CLOSE_OUT_TMP_FILE_EXIT;
	}	    	



	/* #md5Place */
	md5 = crypto_alloc_shash("md5", 0, 0);
	if (IS_ERR(md5))
			error= -1;

	shash = kmalloc(sizeof(struct shash_desc) + crypto_shash_descsize(md5),GFP_KERNEL);

	if (!shash)
	{
		printk(KERN_ALERT "shash memory allocation failed!");
		error = -ENOMEM;
		goto CLOSE_OUT_TMP_FILE_EXIT;
	}

	shash->tfm = md5;
	shash->flags = 0x0;

	if (crypto_shash_init(shash))
	{
		printk(KERN_ALERT "crypto_shash_init() on given arg Failed!");
		error = -EINVAL;
		goto CLOSE_OUT_TMP_FILE_EXIT;
	}

	if (crypto_shash_update(shash,(const char *)keybuf,keylen))
	{
		printk(KERN_ALERT "crypto_shash_update() on given arg Failed!");
		error = -EINVAL;
		goto CLOSE_OUT_TMP_FILE_EXIT;
	}   

	if (crypto_shash_final(shash, md5_hash))
	{
		printk(KERN_ALERT "crypto_shash_final() on given arg Failed!");
		error = -EINVAL;
		goto CLOSE_OUT_TMP_FILE_EXIT;
	}
	kfree(shash);
	crypto_free_shash(md5);



	/* #encryptDecrypt */
	fs = get_fs();
	set_fs(get_ds());
	

    		in_file->f_op->read(in_file,hashed_key_buf,16,&in_file->f_pos);

    		// Compare if the key provided is same as the one stored in the input file.
    	 	ret = memcmp(md5_hash, hashed_key_buf, 16);	
    		if(0 != ret)
    		{
                printk(KERN_ALERT "key/password given by user is invalid!");
                error = -EACCES;
                goto CLOSE_OUT_TMP_FILE_EXIT;
    		}		
    		else
    		{
    			/// decrypt and write in output file here
    			// read the 2nd half of preamble and fetch padding size

    			in_file->f_op->read(in_file,en_pad_size_buf,16,&in_file->f_pos);	
    			buf_len = 16;
    			error = ceph_aes_decrypt(md5_hash,16,pad_size_buf,&buf_len,en_pad_size_buf,16);
    			
    			if(error<0)
    			{
                    printk(KERN_ALERT "Decryption of pad_size_buf (read_from_input_file) failed!");
                    error = -EFAULT;
                    goto CLOSE_OUT_TMP_FILE_EXIT;
    			}	
    				
    			memcpy(pad_size_tmp, pad_size_buf, 2);
    			pad_size_tmp[2]='\0';
    			pad_size_long = simple_strtol(pad_size_tmp,(char **)&pad_size_tmp,0); 		
    		    
                i=0;
    			while ((read_size = in_file->f_op->read(in_file,in_data_buf,PAGE_SIZE,&in_file->f_pos)) > 0)	
    			{	
    				memset(en_in_data_buf, 0, PAGE_SIZE);
    				buf_len = read_size;

    				error = ceph_aes_decrypt(md5_hash,16,en_in_data_buf,&buf_len,in_data_buf,read_size);

    				if (error < 0) 
    				{
    					printk(KERN_ALERT "Drecrypt of input data Failed!");
                        error = -EFAULT;
                        goto CLOSE_OUT_TMP_FILE_EXIT;                        
    				}

    				if (i == (in_data_size/PAGE_SIZE))
                    {
        				read_size = read_size - pad_size_long ; 
                    }   
    				out_file->f_op->write(out_file,en_in_data_buf,read_size,&out_file->f_pos);
    				
                    i++;    			
    			}
    		}
	set_fs(fs);	



	/* #renameTempFile */
	error = custom_vfs_rename(out_file->f_path.dentry->d_parent, out_file->f_path.dentry, 
		out_tmp_file->f_path.dentry->d_parent, out_tmp_file->f_path.dentry);

	if(error < 0)
	{
		error = -EPERM;
		printk( KERN_ALERT "vfs_rename failed!\n");
	}



	/* #freePlace */
	CLOSE_OUT_TMP_FILE_EXIT:
		filp_close(out_tmp_file, NULL);
		if (error < 0)
		{
			// Kindly note: out_file points to temporary file and out_tmp_file points to actual output file.
			//      This just happened to be so, coz of the incremental code convention i used.
			// delete both out_file and out_tmp_file
			if (output_file_to_be_deleted == 1 && out_tmp_file != NULL && out_tmp_file->f_path.dentry != NULL && out_tmp_file->f_path.dentry->d_parent->d_inode != NULL)
			{
				vfs_unlink(out_tmp_file->f_path.dentry->d_parent->d_inode, out_tmp_file->f_path.dentry, NULL);
			}
		}

	CLOSE_OUT_FILE_EXIT:
		filp_close(out_file, NULL);
		if (error < 0)
		{
			// Kindly note: out_file points to temporary file and out_tmp_file points to actual output file.
			//      This just happened to be so, coz of the incremental code convention i used.
			// delete both out_file and out_tmp_file
			if (out_file != NULL && out_file->f_path.dentry != NULL && out_file->f_path.dentry->d_parent->d_inode != NULL)
			{
				vfs_unlink(out_file->f_path.dentry->d_parent->d_inode, out_file->f_path.dentry, NULL);
			}
		}

	CLOSE_IN_FILE_EXIT:
		filp_close(in_file, NULL);

	CLEAN_HASHED_KEY_BUF_EXIT:
		kfree(hashed_key_buf);

	CLEAN_EN_IN_DATA_BUF_EXIT:
		kfree(en_in_data_buf);
	
	CLEAN_KEYBUF_EXIT:
		kfree(keybuf);
	
	CLEAN_IN_DATA_BUF_EXIT:
		kfree(in_data_buf);

	CLEAN_EN_PAD_SIZE_BUF_EXIT:
		kfree(en_pad_size_buf);

	CLEAN_PAD_SIZE_BUF_EXIT:
		kfree(pad_size_buf);

	CLEAN_MD5_HASH_EXIT:
		kfree(md5_hash);

	CLEAN_KARGS_EXIT:
	//	kfree(k_args);
		
	FINAL_OUT:
	
	
	/* Cleaning my_work_obj */

	// deleting from custom_queue
	if(delete_from_custom_queue(my_work_obj->job_obj->job_id) != 0)
	{
		printk("ALERT! could not delete work_obj from custom queue\n");
	}
	
	// Cleaning files data from my_work_obj
    for(i = 1; i<my_work_obj->job_obj->no_of_files; i++)
    {
        kfree(my_work_obj->job_obj->files[i]);
        my_work_obj->job_obj->files[i] = NULL;
    }
    kfree(my_work_obj->job_obj->files);
    my_work_obj->job_obj->files = NULL;
		
	// Cleaning Free'ing my_work_obj->job_obj and my_work_obj itself
	kfree(my_work_obj->job_obj);
	my_work_obj->job_obj = NULL;
	kfree(my_work_obj);
	my_work_obj = NULL;


	printk(KERN_ALERT "Exiting decryption\n");
	printk("decryption_curr_no_of_jobs: %d\n", job_cnt);
	
	return;

}



		
long validateParams(void *arg)
{
	int i = 0;

	job_struct *usrargs = (job_struct *) arg;

	//printk("In validateParams!\n");
	/* Check if the structure pointer is NULL or is non accessible */
	if (usrargs == NULL || !access_ok(VERIFY_READ, usrargs, sizeof(job_struct)))
	{
		printk("struct pointer is NULL!\n");
		return -EFAULT;
	}

	/* Check if files pointer is NULL or is non accessible */
	if(usrargs->job_type < 7)
	{
	
		if (usrargs->files == NULL || !access_ok(VERIFY_READ, 
	    			usrargs->files, sizeof(usrargs->files)))
		{
			printk("files pointer is NULL!\n");
			return -EFAULT;
		}

		/* Check if the filename addresses in the array pointed to by files pointer are NULL or are non accessible */
		for(i = 0; i < usrargs->no_of_files; i++)
    		{
			//printk("%p\n", usrargs->files[i]);
			if (usrargs->files[i] == NULL || !access_ok(VERIFY_READ, usrargs->files[i], sizeof(usrargs->files[i])))
			{
				printk("A filename address is NULL!\n");
				return -EFAULT;
			}
		}

		/* check if the file names are too long */
		for(i = 0; i < usrargs->no_of_files; i++)
   		 {
    			if ((strlen(usrargs->files[i]) > MAX_FILENAME))
    			{
	     			printk("A file name is too long!\n");
            			return -ENAMETOOLONG;
    			}
    		}

	}
        return 0;
}



long copyUserToKernel(job_struct * srcArg, job_struct * destArg)
{

	int error = 0, i = 0;
	int files_copied = 0;

        /* copy the Priority */
        if ((copy_from_user(&(destArg->priority), &(srcArg->priority), sizeof(int))) != 0)
        {
                printk("copy from user for priority of job failed!\n");
                error = -EPERM;
                goto out;
        }

	/* copy the job type */
	if ((copy_from_user(&(destArg->job_type), &(srcArg->job_type), sizeof(int))) != 0)
	{
		printk("copy from user for job type failed!\n");
		error = -EPERM;
		goto out;
	}

	/* copy the no_of_files */
	if ((copy_from_user(&(destArg->no_of_files), &(srcArg->no_of_files), sizeof(int))) != 0)
	{
		printk("copy from user for no_of_files failed!\n");
		error = -EPERM;
		goto out;
	}

	// different data for list (-l)
	if (destArg->job_type == JTYPE_LIST)
	{
		if ((copy_from_user(&(destArg->files), &(srcArg->files), sizeof(char **))) != 0)
		{
			printk("copy from user for job files failed!\n");
			error = -EPERM;
			goto out;
		}
	}
	else if (destArg->job_type == JTYPE_CANCEL)
	{
        	if ((copy_from_user(&(destArg->job_id), &(srcArg->job_id), sizeof(unsigned long))) != 0)
        	{
               		printk("copy from user for job id failed!\n");
                	error = -EPERM;
                	goto out;
        	}
	}
	else
	{
		/* malloc the files array */
		destArg->files = kmalloc(srcArg->no_of_files * sizeof(char *), GFP_KERNEL);
		if (!(destArg->files))
		{
			printk("kmalloc of files array failed!\n");
			error = -ENOMEM;
			goto out;
		}

		/* kmalloc for the filenames */
		for(i = 0; i < srcArg->no_of_files; i++)
	    {
			/* allocate a memory in kernel space first */
			destArg->files[i] = kmalloc(strlen(srcArg->files[i]) + 1, GFP_KERNEL);
			if (!(destArg->files[i]))
			{
				printk("kmalloc of filename buf failed!\n");
				error = -ENOMEM;
				goto out_free_files_array;
			}
			files_copied++;
			memset (destArg->files[i], '\0', strlen(srcArg->files[i]) + 1);
			/* copy the file name in the newly allocated memory */
			if (copy_from_user( destArg->files[i], 
				    srcArg->files[i], 
				    strlen(srcArg->files[i]) ) != 0)
			{
				printk("copy from user for filename %d failed!\n", i);
				error = -EPERM;
				goto out_free_files_array;
			}
		}
	}


/* If you reached here then no error found. */
	goto out;

out_free_files_array:
	for(i = 0; i<files_copied; i++)
	{
		kfree(destArg->files[i]);
		destArg->files[i] = NULL;
	}
	kfree(destArg->files);
	destArg->files = NULL;

out:
	return error;
}



asmlinkage long submitjob(void *arg)
{
	
	/* Variable declarations*/
	long error = 0;
	job_struct *job_obj = NULL;
	my_work_struct *work_obj;
	job_list_struct *job_list_node;
	int i = 0;
	char *job_id_str = NULL;
	unsigned long job_id_size = 0;
	char *job_type_str = NULL;
	char *job_priority_str = NULL;


	// Check if max no of jobs already scheduled
	// but by pass this if the user wants to list the queue, cancel a job or change priority of a job
	printk("Current no of jobs in queue: %d\n", job_cnt);
	if (job_cnt >= MAX_JOB_CNT && ((job_struct *)arg)->job_type < 7)
	{
		error = -EAGAIN;
		printk("Job Queue FULL!\n");
	        goto out_invalid_params;
	}
	
	// debugging
	printk(KERN_ALERT "Entered function submitjob!\n");
	
	/* Before copying the userland parameters to kernel, check arg for validities */
	error = validateParams(arg);
	if (error != 0)
	{
		goto out_invalid_params;
	}
	job_obj = kmalloc(sizeof(job_struct), GFP_KERNEL);
	if (!job_obj)
	{
		error = -ENOMEM;
		goto out_invalid_params;
	}
	memset(job_obj, 0, sizeof(job_struct));
	error = copyUserToKernel(arg, job_obj);
	if (error < 0)
	{
		printk("Data copy from user to kernel failed!\n");
		goto out_free_job_obj_buf;
	}

	// check the job_type and proceed accordingly
	if (job_obj->job_type == JTYPE_LIST)
	{
		// iterate through the custom job list and print the info
		list_for_each(pos, &(job_list_head->jlist))
		{
			tmp_list_node = list_entry(pos, job_list_struct, jlist);
			//printk("job_id: %lu @ %p\n", tmp_list_node->job_id, tmp_list_node->work_ptr);
			// dump the info in (*(job_obj->files))
			job_id_size = snprintf(NULL, 0, "%lu", tmp_list_node->job_id);
			//printk("job_id_size: %lu\n", job_id_size);
			job_id_str = (char *) kmalloc(job_id_size+1, GFP_KERNEL);
			if (!job_id_str) 
			{
	        	error = -ENOMEM;
	        	printk(KERN_ERR
	        	   	   "Job id str buffer allocation failed!\n");
	        	goto out_free_job_obj_buf;
    		}
    		memset(job_id_str, '\0', job_id_size+1);
			snprintf((char *) job_id_str, job_id_size+1, "%lu", tmp_list_node->job_id);
			//printk("after snprintf; job id: %s\n", job_id_str);
			if (copy_to_user((char *)((*(job_obj->files)) + i), (char *) job_id_str, strlen(job_id_str)) != 0) 
			{
				printk("Copy to user failed in list job queue!\n");
				error = -EPERM;
				goto out_free_job_obj_buf;
			}
			i += strlen(job_id_str);

			// free the job_id_str buff
			kfree(job_id_str);
			job_id_str = NULL;

			// copy the job type to the user buffer
			switch (((my_work_struct *) (tmp_list_node->work_ptr))->job_obj->job_type)
			{
				case 1:
					job_type_str = "        Concatenation";
					break;
				case 2:
					job_type_str = "        Compression  ";
					break;
				case 3:
					job_type_str = "        Decompression";
					break;
				case 4:
					job_type_str = "        Checksum     ";
					break;
				case 5:
					job_type_str = "        Encryption   ";
					break;
				case 6:
					job_type_str = "        Decryption   ";
					break;
			}
			if (copy_to_user((char *)((*(job_obj->files)) + i), (char *) job_type_str, strlen(job_type_str)) != 0) 
			{
				printk("Copy to user failed in list job queue!\n");
				error = -EPERM;
				goto out_free_job_obj_buf;
			}
			i += strlen(job_type_str);

			// copy the job priority to the user buffer
			if ( ((my_work_struct *) (tmp_list_node->work_ptr))->job_obj->priority == 0 )
			{
				job_priority_str = "        Low";
			}
			else
			{
				job_priority_str = "        High";
			}
			if (copy_to_user((char *)((*(job_obj->files)) + i), (char *) job_priority_str, strlen(job_priority_str)) != 0) 
			{
				printk("Copy to user failed in list job queue!\n");
				error = -EPERM;
				goto out_free_job_obj_buf;
			}
			i += strlen(job_priority_str);

			// add a new line character
			if (copy_to_user((char *)((*(job_obj->files)) + i), (char *)"\n", 1) != 0) 
			{
				printk("Copy to user failed in list job queue!\n");
				error = -EPERM;
				goto out_free_job_obj_buf;
			}
			i += 1;
			//printk("printing the user buffer:\n%s\n", (*(job_obj->files)));
		}	

	}
	else if (job_obj->job_type == JTYPE_CANCEL)
	{
		list_for_each_safe(pos, q, &(job_list_head->jlist))
        	{
			
        		tmp_list_node = list_entry(pos, job_list_struct, jlist);

			if ( tmp_list_node->job_id == job_obj->job_id)
                	{
                        	error = cancel_work_sync( (struct work_struct*) tmp_list_node->work_ptr );
				printk("error returned from cancel job is: %ld\n", error);
				if(error == 1)	
				{
					printk("The job(%lu) was cancelled\n", job_obj->job_id);
				}
				else
				{
                                        printk("The job(%lu) do not exist in queue. Probably already completed.\n", job_obj->job_id);
				}

                                if ( (tmp_list_node != NULL && delete_from_custom_queue(tmp_list_node->job_id) != 0) )
                                {
                                        printk("ALERT! could not delete work_obj from custom queue\n");
                                }
				break;	
                	}
        	}	

	}
	else // for job type: 1,2,3,4,5,6
	{
		work_obj = (my_work_struct *)kmalloc(sizeof(my_work_struct), GFP_KERNEL);
		
		if(work_obj)
		{
			memset(work_obj, 0, sizeof(my_work_struct));		


			if (job_obj->job_type == JTYPE_CONCAT)
			{
				INIT_WORK( (struct work_struct *) work_obj, concat ); 
			}
			else if (job_obj->job_type == JTYPE_CONPRESS)
			{
				INIT_WORK( (struct work_struct *) work_obj, compress );
			}
			else if (job_obj->job_type == JTYPE_DECOMPRESS)
			{
				INIT_WORK( (struct work_struct *) work_obj, decompress );
			}
			else if (job_obj->job_type == 4)
			{
				INIT_WORK( (struct work_struct *) work_obj, checksum ); //[changed here]
			}
			else if (job_obj->job_type == 5)
			{
				INIT_WORK( (struct work_struct *) work_obj, encryption ); //[changed here]
			}
			else if (job_obj->job_type == 6)
			{
				INIT_WORK( (struct work_struct *) work_obj, decryption ); //[changed here]
			}
			// initialize the work object with call back function
			//INIT_WORK( (struct work_struct *) work_obj, decompress ); //[change here]

			// populate work_obj with the job_obj contents in the corresponding variable
			work_obj->job_obj = job_obj;

			// increment and allocate job_id; create mapping
			job_id_cnt++;

			// Submit the job to custom queue before submitting to work queue
			// allocate and add
			job_list_node = (job_list_struct * ) kmalloc(sizeof(job_list_struct), GFP_KERNEL);
			if (!job_list_node) 
			{
				error = -ENOMEM;
				printk(KERN_ERR "Job list buffer allocation failed!\n");
				goto out_free_job_obj_buf;
			}
			// create mapping 
			job_list_node->job_id = job_id_cnt;
			job_list_node->work_ptr = (struct work_struct*) work_obj;

	        	/* Put in the custom queue */
	        	list_add_tail(&(job_list_node->jlist), &(job_list_head->jlist));
			
			// job_cnt = no of jobs in work queue
                        job_cnt++;

			printk("Added job %lu to custom queue!\n", job_id_cnt);

			// return job_id to user as well & update job_id of kernel job_obj
			((job_struct*) arg)->job_id = job_id_cnt; 			
			work_obj->job_obj->job_id = job_id_cnt;

			// now submit the job to the work queue
			// return_value (ret):  1 = success and -EBUSY = failure
			if(((my_work_struct *) (job_list_node->work_ptr))->job_obj->priority == 0)
			{
				error = queue_work( my_low_pwq, (struct work_struct *) work_obj );	
			}
			else
			{
				error = queue_work( my_high_pwq, (struct work_struct *) work_obj );
			}

			if(error == 1) // Success: Job enqueued successfully
			{
				// update error with appropriate success value
				error = 0;
				if(((my_work_struct *) (job_list_node->work_ptr))->job_obj->priority == 0)
				{
					printk("job(%lu) enqueued in low_priority_queue Successfully\n",job_list_node->job_id);
				}
				else
				{
					printk("job(%lu) enqueued in high_priority_queue Successfully\n",job_list_node->job_id);
				}

				printk("producer_after_adding_job_cnt= %d\n", job_cnt);
			}
			else
			{	
				error = -EOPNOTSUPP;
				printk("Job failed to be queued to the work queue!\n");
				// delete the job from the custom queue
				printk("Deleting the job submitted to the custom queue!\n");
				if (delete_from_custom_queue(job_id_cnt) != 0)
				{
					printk("ALERT! could not delete work_obj from custom queue\n");
				}
			}

		}
		else
		{
			error = -ENOMEM;
			goto out_free_job_obj_buf; 
		}

	}

	//debug: Just listing all the queued jobs
	// list_for_each(pos, &(job_list_head->jlist)) 
	// {
	// 	tmp_list_node = list_entry(pos, job_list_struct, jlist);
	// 	printk("job_id: %lu @ %p\n", tmp_list_node->job_id, tmp_list_node->work_ptr);
	// }



	// Reached here without error
	goto out_invalid_params;

out_free_job_obj_buf:
	if(job_obj != NULL)
	{
		kfree(job_obj);
		job_obj = NULL;
	}

out_invalid_params:
	printk("Exiting Submitjob\n");
	return error;
	//return 0;
}

static int __init init_sys_submitjob(void)
{
	int error = 0;
        struct netlink_kernel_cfg cfg = {
                .input = push_msg_to_user,
        };

	printk(KERN_ALERT "installed new sys_submitjob module\n");
	if (sysptr == NULL)
		sysptr = submitjob;

	my_low_pwq = alloc_workqueue("low_priority_wqueue", 0, 4);
	
	if(my_low_pwq)
	{
		printk("My low priority work queue created successfully\n");	
	} 
	else
	{
		printk("Failed! low priority work queue couldn't be created\n");
		error = -ENOMEM;
		goto out;
	}

	my_high_pwq = alloc_workqueue("high_priority_wqueue", WQ_HIGHPRI, 4);

        if(my_high_pwq)
        {
                printk("My high priority work queue created successfully\n");
        }
        else
        {
		printk("Failed! High priority work queue couldn't be created\n");
                error = -ENOMEM;
		goto out_clean_low;
        }

	// initializing the global static varaibles
	job_id_cnt = 0;
	job_cnt = 0;


	// Creating a custom list for maintaining the job_queue shadow
	job_list_head = ( job_list_struct *) kmalloc(sizeof( job_list_struct), GFP_KERNEL);

	if (!job_list_head) 
	{
    		error = -ENOMEM;
    		printk(KERN_ERR "Job list head buffer allocation failed!\n");
    		goto out_clean_high;
	}

	/* Initialize the list head */
	INIT_LIST_HEAD(&job_list_head->jlist);	


        nl_sk = netlink_kernel_create(&init_net, NETLINK_USER, &cfg);
        if(!nl_sk)
        {
                printk(KERN_ALERT "Error creating socket.\n");
                return -10;
        }
	
	// reached here = No errors
	goto out; 

out_clean_high:
        if(my_high_pwq)
        {
                flush_workqueue( my_high_pwq );
                destroy_workqueue( my_high_pwq );
                my_high_pwq = NULL;
                printk(KERN_ALERT "ERROR: My high priority work queue flushed and destroyed successfully\n");
        }

out_clean_low:
	if(my_low_pwq)
        {
		flush_workqueue( my_low_pwq );
		destroy_workqueue( my_low_pwq );
		my_low_pwq = NULL;
		printk(KERN_ALERT "ERROR: My low priority work queue flushed and destroyed successfully\n");
	}

out:
	return error;
}
static void  __exit exit_sys_submitjob(void)
{
	if (sysptr != NULL)
		sysptr = NULL;

	if(my_low_pwq)
	{
		flush_workqueue( my_low_pwq );
		destroy_workqueue( my_low_pwq );
		my_low_pwq = NULL;
		printk(KERN_ALERT "My low priority work queue flushed and destroyed successfully\n");
	}

        if(my_high_pwq)
        {
                flush_workqueue( my_high_pwq );
                destroy_workqueue( my_high_pwq );
                my_high_pwq = NULL;
                printk(KERN_ALERT "My high priority work queue flushed and destroyed successfully\n");
        }

	
	/* free the list */
	list_for_each_safe(pos, q, &job_list_head->jlist) 
	{
		tmp_list_node = list_entry(pos, job_list_struct, jlist);

		list_del(pos);
		kfree(tmp_list_node);
	}

	if (job_list_head != NULL) 
	{
		kfree(job_list_head);
		job_list_head = NULL;
	}	
	
	netlink_kernel_release(nl_sk);
	
	printk(KERN_ALERT "removed sys_submitjob module\n");
}
module_init(init_sys_submitjob);
module_exit(exit_sys_submitjob);
MODULE_LICENSE("GPL");

