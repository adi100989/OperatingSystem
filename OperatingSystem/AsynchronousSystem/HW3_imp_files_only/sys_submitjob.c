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
#include <linux/spinlock.h>

#define NETLINK_USER 31
#define CEPH_AES_IV "cephsageyudagreg"
#define AES_BLOCK_SIZE 16
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
struct sk_buff *skb_in;

static DEFINE_SPINLOCK(job_id_cnt_lock);
static DEFINE_SPINLOCK(job_cnt_lock);
static DEFINE_MUTEX(custom_queue_list_lock);

static void push_msg_to_user(int job_id, char *msg)
{
	struct nlmsghdr *nlh;
	int pid;
	struct sk_buff *skb_out;
	int msg_size;
	int res;

	msg_size = strlen(msg);

	pid = job_id;

	skb_out = nlmsg_new(msg_size, 0);
	if (!skb_out) 
	{
		printk(KERN_ERR "Failed to allocate new skb!\n");
  		return;
	}

	nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, msg_size, 0);
	NETLINK_CB(skb_out).dst_group = 0; /* not in mcast group */
	strncpy(nlmsg_data(nlh), msg, msg_size);

	res = nlmsg_unicast(nl_sk, skb_out, pid);
	if (res < 0)
	{
   		printk(KERN_INFO "Error while sending back to user!\n");
   	}
}

// deletes mapping of job_id,work_obj from custom_queue
// return = 0: success, else failure 
static int delete_from_custom_queue(unsigned long job_id)
{
	int error = -1;
	printk("Entered delete_from_custom_queue\n");
	
	mutex_lock(&custom_queue_list_lock);
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
	mutex_unlock(&custom_queue_list_lock);
	printk("Exiting delete_from_custom_queue!\n");
	return error;
}

static void concat(struct work_struct *work_obj)
{
	my_work_struct *my_work_obj = (my_work_struct*) work_obj;
	int i = 0;
	int err = 0, is_in_file_error = 0;
	struct file *dest_filp = NULL;
	struct file *in_filp = NULL;
	char *readBuf = NULL;
	int readBytes;
	mm_segment_t oldfs;
	char *msg_to_user_buf;

	printk(KERN_ALERT "Entered concat\n");
	msleep(1000);
	// delete the job from custom_queue
	if(delete_from_custom_queue(my_work_obj->job_obj->job_id) != 0)
	{
		printk("ALERT! Could not delete work_obj from custom queue\n");
		return;
	}

	oldfs = get_fs();  //Save the current FS segment
	set_fs(KERNEL_DS); //set_fs(get_ds());

    /* Open the first file in append mode */
	dest_filp = filp_open(my_work_obj->job_obj->files[0], O_WRONLY|O_APPEND, FMODE_WRITE);
	if (!dest_filp || IS_ERR(dest_filp)) 
	{
		printk("Destination file open error %d\n", (int) PTR_ERR(dest_filp));
		err = -ENOENT; /* set error */
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
		err = -ENOENT; /* set error */
		/* file(system) doesn't allow write */
		goto out_close_dest_file;
	}

	/* Allocate the buffer for reading from the input file */
	readBuf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!readBuf) 
	{
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
		while ((readBytes = in_filp->f_op->read(in_filp, readBuf, PAGE_SIZE, &in_filp->f_pos)) > 0) 
		{
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
	
out_free_readbuf:
	kfree(readBuf);
	readBuf = NULL;
out_close_dest_file:
	filp_close(dest_filp, NULL);
	dest_filp = NULL;
out:
	
	msg_to_user_buf = kmalloc(100, GFP_KERNEL);
	if (!msg_to_user_buf) 
	{
		err = -ENOMEM;
		printk(KERN_ERR
	   		   "Message to user buffer allocation failed!\n");
		goto final_out;
	}
	memset(msg_to_user_buf, '\0', 100);
	if (err != 0)
	{
		printk("Concat job(%lu) failed. Sending message to user.\n", my_work_obj->job_obj->job_id);
		snprintf(msg_to_user_buf, 100, "Concatenation job (job id: %lu) failed!", my_work_obj->job_obj->job_id);
	}
	else
	{
		printk("Concat job(%lu) done successfully. Sending message to user.\n", my_work_obj->job_obj->job_id);
		snprintf(msg_to_user_buf, 100, "Concatenation job (job id: %lu) done successfully!", my_work_obj->job_obj->job_id);
	}

    push_msg_to_user((int)my_work_obj->job_obj->pid, msg_to_user_buf);

    kfree(msg_to_user_buf);

final_out:
	set_fs(oldfs); //Reset to save FS

	/* Cleaning my_work_obj */
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

	printk(KERN_ALERT "Exiting concat!\n");
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
    char *msg_to_user_buf;
	
	struct crypto_comp *comp_tfm = crypto_alloc_comp("deflate", 0, 0);
	printk(KERN_ALERT "Entered compression!\n");
	msleep(1000);
	// delete the job from custom_queue
	if(delete_from_custom_queue(my_work_obj->job_obj->job_id) != 0)
	{
		printk("ALERT! Could not delete work_obj from custom queue\n");
		return;
	}

	oldfs = get_fs();  //Save the current FS segment
	set_fs(KERNEL_DS); //set_fs(get_ds());

    // Open the dest file
	dest_filp = filp_open(my_work_obj->job_obj->files[0], O_WRONLY|O_CREAT|O_TRUNC, FMODE_WRITE);
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
    msg_to_user_buf = kmalloc(100, GFP_KERNEL);
    if (!msg_to_user_buf)
    {
        err = -ENOMEM;
        printk(KERN_ERR
                   "Message to user buffer allocation failed!\n");
        goto final_out;
    }
    memset(msg_to_user_buf, '\0', 100);
    if (err != 0)
    {
        printk("Compression job(%lu) failed. Sending message to user.\n", my_work_obj->job_obj->job_id);
        snprintf(msg_to_user_buf, 100, "Compression job (job id: %lu) failed!", my_work_obj->job_obj->job_id);
    }
    else
    {
        printk("Compression job(%lu) done successfully. Sending message to user.\n", my_work_obj->job_obj->job_id);
        snprintf(msg_to_user_buf, 100, "Compression job (job id: %lu) done successfully!", my_work_obj->job_obj->job_id);
    }

    push_msg_to_user((int)my_work_obj->job_obj->pid, msg_to_user_buf);

    kfree(msg_to_user_buf);

final_out:

	set_fs(oldfs); //Reset to save FS
	
	/* Cleaning my_work_obj */
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

	printk(KERN_ALERT "Exiting compression!\n");	
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
    char *msg_to_user_buf;
	
	struct crypto_comp *comp_tfm = crypto_alloc_comp("deflate", 0, 0);
	printk(KERN_ALERT "Entered decompression\n");
	msleep(1000);
	// delete the job from custom_queue
	if(delete_from_custom_queue(my_work_obj->job_obj->job_id) != 0)
	{
		printk("ALERT! Could not delete work_obj from custom queue\n");
		return;
	}
	
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

    msg_to_user_buf = kmalloc(100, GFP_KERNEL);
    if (!msg_to_user_buf)
    {
        err = -ENOMEM;
        printk(KERN_ERR
                   "Message to user buffer allocation failed!\n");
        goto final_out;
    }
    memset(msg_to_user_buf, '\0', 100);
    if (err != 0)
    {
        printk("Decompression job(%lu) failed. Sending message to user.\n", my_work_obj->job_obj->job_id);
        snprintf(msg_to_user_buf, 100, "Decompression job (job id: %lu) failed!", my_work_obj->job_obj->job_id);
    }
    else
    {
        printk("Decompression job(%lu) done successfully. Sending message to user.\n", my_work_obj->job_obj->job_id);
        snprintf(msg_to_user_buf, 100, "Decompression job (job id: %lu) done successfully!", my_work_obj->job_obj->job_id);
    }

    push_msg_to_user((int)my_work_obj->job_obj->pid, msg_to_user_buf);

    kfree(msg_to_user_buf);

final_out:

	set_fs(oldfs); //Reset to save FS
	
	/* Cleaning my_work_obj */	
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

	printk(KERN_ALERT "Exiting decompression!\n");
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
	char *readBuf = NULL, *writeBuf = NULL, *bufLen = NULL;
	int readBytes;
	struct shash_desc * shash = NULL;
	u8 *md5_hash = NULL;
	struct crypto_shash *md5 = NULL;
	mm_segment_t oldfs;
    char *msg_to_user_buf;
	
	printk(KERN_ALERT "Entered checksum!\n");
	msleep(1000);
	// delete the job from custom_queue
	if(delete_from_custom_queue(my_work_obj->job_obj->job_id) != 0)
	{
		printk("ALERT! Could not delete work_obj from custom queue\n");
		return;
	}

	oldfs = get_fs();  //Save the current FS segment
	set_fs(KERNEL_DS); //set_fs(get_ds());
	
    // Open the dest file
	dest_filp = filp_open(my_work_obj->job_obj->files[0], O_WRONLY|O_CREAT|O_TRUNC, FMODE_WRITE);
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
    {
		goto out_free_bufLen;
	}
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
        goto out_free_bufLen;
    }

	// get the checksum of  the contents from the input file and store in the dest file 
	while ((readBytes = in_filp->f_op->read(in_filp, readBuf, PAGE_SIZE, &in_filp->f_pos)) > 0) 
	{
		if (crypto_shash_update(shash, (const char *)readBuf, readBytes))
    	{
        	printk(KERN_ALERT "crypto_shash_update() on given arg Failed!");
        	err = -EINVAL;
        	goto out_free_bufLen;
    	}
		memset(readBuf, '\0', PAGE_SIZE);
	}
	
	//printk(" keybuf value = %s\n",keyBuf);
    if (crypto_shash_final(shash, md5_hash))
    {
        printk(KERN_ALERT "crypto_shash_final() on given arg Failed!");
        err = -EINVAL;
        goto out_free_bufLen;
    }
	//printk(" the length of the %d number buffer is %s\n ",writeBytes,bufLen);

	snprintf(bufLen,33,"%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
			 md5_hash[0],md5_hash[1],md5_hash[2],md5_hash[3],md5_hash[4],md5_hash[5],md5_hash[6],
			 md5_hash[7],md5_hash[8],md5_hash[9],md5_hash[10],md5_hash[11],md5_hash[12],md5_hash[13],
			 md5_hash[14],md5_hash[15]);
	bufLen[32]='\0';
	printk("md5_hash value is %s\n", bufLen);
		
	dest_filp->f_op->write(dest_filp, bufLen, 33, &dest_filp->f_pos);
		
	msleep(10 * 1000);

	printk("checksum job (%lu) done successfully!\n", my_work_obj->job_obj->job_id);

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
    msg_to_user_buf = kmalloc(100, GFP_KERNEL);
    if (!msg_to_user_buf)
    {
        err = -ENOMEM;
        printk(KERN_ERR
                   "Message to user buffer allocation failed!\n");
        goto final_out;
    }
    memset(msg_to_user_buf, '\0', 100);
    if (err != 0)
    {
        printk("Checksum job(%lu) failed. Sending message to user.\n", my_work_obj->job_obj->job_id);
        snprintf(msg_to_user_buf, 100, "Checksum job (job id: %lu) failed!", my_work_obj->job_obj->job_id);
    }
    else
    {
        printk("Checksum job(%lu) done successfully. Sending message to user.\n", my_work_obj->job_obj->job_id);
        snprintf(msg_to_user_buf, 100, "Checksum job (job id: %lu) done successfully!", my_work_obj->job_obj->job_id);
    }

    push_msg_to_user((int)my_work_obj->job_obj->pid, msg_to_user_buf);

    kfree(msg_to_user_buf);

final_out:

	set_fs(oldfs); //Reset to save FS
	
	/* Cleaning my_work_obj */
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

	printk(KERN_ALERT "Exiting checksum!\n");
	printk("checksum_curr_no_of_jobs: %d\n", job_cnt);
	
	return;
}


// The following functions are used in encryption decryption


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

	if (buf_len == 0) 
	{
		memset(sgt, 0, sizeof(*sgt));
		return -EINVAL;
	}

	if (is_vmalloc) 
	{
	    chunk_cnt = chunk_len >> PAGE_SHIFT;
	    chunk_len = PAGE_SIZE;
	}

	if (chunk_cnt > 1) 
	{
	    ret = sg_alloc_table(sgt, chunk_cnt, GFP_NOFS);
	    if (ret)
	    {
	        return ret;
	    }
	} 
	else 
	{
	    WARN_ON(chunk_cnt != 1);
	    sg_init_table(prealloc_sg, 1);
	    sgt->sgl = prealloc_sg;
	    sgt->nents = sgt->orig_nents = 1;
	}

	for_each_sg(sgt->sgl, sg, sgt->orig_nents, i) 
	{
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

static void teardown_sgtable(struct sg_table *sgt)
{
    if (sgt->orig_nents > 1)
        sg_free_table(sgt);
}

/* The aes encryption and decryption functions are taken from the following source:
http://lxr.fsl.cs.sunysb.edu/linux/source/net/ceph/crypto.c
*/
static int my_aes_encrypt(const void *key, int key_len,
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
	if (ret < 0) 
	{
	    pr_err("ceph_aes_crypt failed %d\n", ret);
	    goto out_sg;
	}

out_sg:
    teardown_sgtable(&sg_out);
out_tfm:
    crypto_free_blkcipher(tfm);
    return ret;
}

static int my_aes_decrypt(const void *key, int key_len,
                         void *dst, size_t *dst_len,
                         const void *src, size_t src_len)
{
	struct sg_table sg_in;
	struct scatterlist sg_out[2], prealloc_sg;
	struct crypto_blkcipher *tfm = crypto_alloc_blkcipher("cbc(aes)", 0, CRYPTO_ALG_ASYNC);
	struct blkcipher_desc desc = { .tfm = tfm };
	char pad[AES_BLOCK_SIZE];
	void *iv;
	int ivsize;
	int ret;

	if (IS_ERR(tfm))
        return PTR_ERR(tfm);

	sg_init_table(sg_out, 2);
	sg_set_buf(&sg_out[0], dst, *dst_len);
	sg_set_buf(&sg_out[1], pad, sizeof(pad));
	ret = setup_sgtable(&sg_in, &prealloc_sg, src, src_len);
	if (ret)
	    goto out_tfm;

	crypto_blkcipher_setkey((void *)tfm, key, key_len);
	iv = crypto_blkcipher_crt(tfm)->iv;
	ivsize = crypto_blkcipher_ivsize(tfm);
	memcpy(iv, aes_iv, ivsize);

	ret = crypto_blkcipher_decrypt(&desc, sg_out, sg_in.sgl, src_len);
	if (ret < 0) 
	{
	    pr_err("ceph_aes_decrypt failed %d\n", ret);
	    goto out_sg;
    }

out_sg:
    teardown_sgtable(&sg_in);
out_tfm:
    crypto_free_blkcipher(tfm);
    return ret;
}

/* Fuction to print the MD5 hash. Used in debugging/testing */
// static void dump(char *hash_md5)
// {
// 	int i;

// 	for (i = 0; i < 16 ; i++) {
// 		printk("%02x", (unsigned char)hash_md5[i]);
// 	}
// 	printk("\n");
// }

static void encryption(struct work_struct *work_obj)
{
	my_work_struct *my_work_obj = (my_work_struct * ) work_obj;
	int i;

	long error = 0;
	/* Variables for file operations */
	struct file *in_filp;
	struct file *out_filp;
	char *readBuf =  NULL;
	char *cryptBuf = NULL;
	char *paddingBufEncrypt = NULL;
	char paddingBitsStr[3];
	mm_segment_t oldfs;
	int  paddingBits, readBytes;
	int pageSize;  /* pointer to the page size length is required 
			  		  in encryption/decryption api */
	int cryptRet;
	umode_t inputFileMode;
	size_t inputFileSize;
	
	/* Variables used to calculate the MD5 hash of the key */
	char* MD5_hash_key = NULL;
	struct crypto_shash *md5;
	struct shash_desc *shash;

	struct inode *outputFileInode = NULL;
	struct dentry *outputFileDentry = NULL;
    char *msg_to_user_buf;

    printk(KERN_ALERT "Entered encryption!\n");
	msleep(1000);
    // delete the job from custom_queue
	if(delete_from_custom_queue(my_work_obj->job_obj->job_id) != 0)
	{
		printk("ALERT! Could not delete work_obj from custom queue\n");
		return;
	}

	oldfs = get_fs();  //Save the current FS segment
	set_fs(KERNEL_DS);

	/* Calculate the MD5 hash of the key accepted in my_work structure */
	/* The following code has been written by going through the following sources:
	   http://shell-storm.org/repo/Linux-Kernel/lkm_samples/hash_md5.c
	   http://lxr.fsl.cs.sunysb.edu/linux/source/crypto/md5.c
	   http://openssl.org/docs/manmaster/crypto/md5.html
	*/
	md5 = crypto_alloc_shash("md5", 0, 0);
	if (md5 == NULL)
	{
		error = -EINVAL;
		goto md5_hashing_failed;
	}
	shash = kmalloc(sizeof(struct shash_desc) + crypto_shash_descsize(md5), 
			GFP_KERNEL);
	if (!shash)
	{
		error = -ENOMEM;
		goto md5_hashing_failed;
	}
	memset(shash, 0, sizeof(struct shash_desc) + crypto_shash_descsize(md5));
	shash->tfm = md5;
	shash->flags = 0;

	MD5_hash_key = kmalloc(AES_BLOCK_SIZE, GFP_KERNEL);
	if (!MD5_hash_key)
	{
		error = -ENOMEM;
		goto md5_buf_alloc_failed;
	}
	memset(MD5_hash_key, 0, AES_BLOCK_SIZE);
	
	if (crypto_shash_init(shash))
	{
		error = -EINVAL;
		goto md5_proc_failed;
	}
	if (crypto_shash_update(shash, (const char *)my_work_obj->job_obj->files[0], 16))
	{
		error = -EINVAL;
		goto md5_proc_failed;
	}
	if (crypto_shash_final(shash, MD5_hash_key))
	{
		error = -EINVAL;
		goto md5_proc_failed;
	}

	crypto_free_shash(md5);
	/* End of MD5 hashing of the key. Hashed key in MD5_hash_key */
	//printk("MD5 hash of the key: %s\n", MD5_hash_key);
	//dump(MD5_hash_key);

	/* Read from the input file */
	/* Open the file */
	//printk("Input file: %s\n", my_work_obj->job_obj->files[2]);
	in_filp = filp_open(my_work_obj->job_obj->files[2], O_RDONLY, 0);
	if (!in_filp || IS_ERR(in_filp)) 
	{
		printk("Input file open error!\n");
		error = -ENOENT; /* set error */
		goto input_file_open_failed;
	}
	if (!(in_filp->f_op))
    {
        printk(KERN_ALERT "No file operations on the input file!\n");
        error = -ENOENT;
        goto input_file_no_file_op;
    }
	if (!in_filp->f_op->read)
	{
		printk("No read permission on the input file!\n");
		error = -ENOENT; /* set error */
		/* file(system) doesn't allow reads */
		goto input_file_no_read_perm;
	}
		
	/* get the input file size and the permissions */
	inputFileSize = in_filp->f_path.dentry->d_inode->i_size;
	inputFileMode = in_filp->f_path.dentry->d_inode->i_mode;

	out_filp = filp_open(my_work_obj->job_obj->files[1], O_WRONLY|O_CREAT, inputFileMode);
	if (!out_filp || IS_ERR(out_filp))
	{
		printk("Output file open err %d\n", (int) PTR_ERR(out_filp));
		error = -ENOENT;
		goto output_file_open_failed;
	}
	if (!(out_filp->f_op))
	{
		printk(KERN_ALERT "No file operations on the output file!\n");
		error = -ENOENT;
		goto output_file_no_file_op;
	}
	if (!out_filp->f_op->write)
	{
		printk("No read permission on the input file!\n");
        error = -ENOENT; /* set error */
        /* file(system) doesn't allow reads */
        goto output_file_no_write_perm;
	}
	
	/* store the output file inode and dentry so that the output file can be vfs_renamed
	   and vfs_unlinked in the case of partial write */
	outputFileInode = out_filp->f_path.dentry->d_parent->d_inode;
	outputFileDentry = out_filp->f_path.dentry;

	/* Check if the input file and the output file are the same. 
	   We do not want to mess with the input file */
	if(in_filp->f_path.dentry->d_inode->i_ino ==
			       out_filp->f_path.dentry->d_inode->i_ino)
	{
		printk("Input and output files are the same!\n");
		error = -EINVAL; /* Whar errno to set?? */
		goto same_input_output_file;
	}

	/* Allocate the buffer for reading from the input file */
    readBuf = kmalloc(4096, GFP_KERNEL);
    if (!readBuf)
    {
        error = -ENOMEM;
        printk("Input buffer allocation failed\n");
        goto input_kbuf_failed;
    }
	
	/* Allocate the buffer to store the encrypted/decrypted data */
	cryptBuf = kmalloc(4096, GFP_KERNEL);
	if (!cryptBuf)
	{
        error = -ENOMEM;
        printk("Input buffer allocation failed\n");
        goto crypt_kbuf_failed;
    }

    memset(readBuf, 0, 4096);
	memset(cryptBuf, 0, 4096);
	in_filp->f_pos = 0;           /* start offset */
	out_filp->f_pos = 0;

	/* Encrypt!!! */
    	/* The hash of the key which is already calculated is to be stored
	   in the preamble of the encrypted file */

	out_filp->f_op->write(out_filp, MD5_hash_key, 16, &out_filp->f_pos);
	
	/* Find out if padding is required, if yes then calculate 
	   the number of bytes to be padded, store it in paddingBits,
	   store paddingBits in paddingBufEncrypt, encrypt this and put
	   in the output file */
	if (inputFileSize % 16 == 0)
	{
		paddingBits = 0;
	}
	else
	{
		paddingBits = 16 - (inputFileSize % 16);
	}
	//printk("Padding Bits: %d\n", paddingBits);	
	paddingBufEncrypt = kmalloc(16, GFP_KERNEL);
	if (!paddingBufEncrypt)
	{
    	error = -ENOMEM;
    	printk("Padding buffer allocation failed\n");
    	goto padding_kbuf_failed;
	}
	memset(paddingBufEncrypt, 0, 16);
	sprintf(paddingBitsStr, "%d", paddingBits);
	paddingBitsStr[2] = '\0';
	memcpy(paddingBufEncrypt, paddingBitsStr, 2);
	//printk("Padding bytes as string: %s\n", paddingBitsStr);
    /* Next 16 bytes in the encrypted file should be the padding value */
    out_filp->f_op->write(out_filp, paddingBufEncrypt, 16, &out_filp->f_pos);

	/* Run the while loop, get page size blocks from the input file, 
	   copy it to the buffer, encrypt it and write to the output file. */
	while ((readBytes = in_filp->f_op->read(in_filp, readBuf, 4096, &in_filp->f_pos)) > 0)
	{
		if (readBytes < 4096)
		{
			pageSize = readBytes + paddingBits;
			//printk("Padding required: %d\n", paddingBits);
			/* Now encrypt the padded block here if readBuf cant be paded */
			cryptRet = my_aes_encrypt(my_work_obj->job_obj->files[0], AES_BLOCK_SIZE,
                                      cryptBuf, &pageSize, readBuf, readBytes + paddingBits);
			if (cryptRet < 0)
			{
				error = -EFAULT;
				goto encrypt_failed;
			}
			readBytes += paddingBits; /* So that the last buffer size to
						     be written to out file is plus the 
						     padding bits */
		}
		else  /* readBytes == 4096 */
		{
			pageSize = PAGE_SIZE;
			//printk("readByets: %d\n",readBytes);
			/* AES encryption of the readBuf */
			cryptRet = my_aes_encrypt(my_work_obj->job_obj->files[0], AES_BLOCK_SIZE,
				    				  cryptBuf, &pageSize, readBuf, PAGE_SIZE);
			if (cryptRet < 0)
            {
                error = -EFAULT;
                goto encrypt_failed;
            }
		}

		/* Write the cryptBuf to the output file */
		out_filp->f_op->write(out_filp, cryptBuf, readBytes, &out_filp->f_pos); 			
	}

    msleep(3*1000);

encrypt_failed:
	kfree(paddingBufEncrypt);  /* Free the padding buffer */

padding_kbuf_failed:
	kfree(cryptBuf);	

crypt_kbuf_failed:
	kfree(readBuf);  /* Free the kernel buffer used for data transfer */

input_kbuf_failed:

same_input_output_file:

output_file_no_write_perm:

output_file_no_file_op:
    filp_close(out_filp, NULL);
    out_filp = NULL;

output_file_open_failed:

input_file_no_read_perm:

input_file_no_file_op:
	filp_close(in_filp, NULL);
	in_filp = NULL;

input_file_open_failed:

md5_proc_failed:
	kfree(MD5_hash_key);

md5_buf_alloc_failed:
	kfree(shash);

md5_hashing_failed:

    msg_to_user_buf = kmalloc(100, GFP_KERNEL);
    if (!msg_to_user_buf)
    {
        error = -ENOMEM;
        printk(KERN_ERR
                   "Message to user buffer allocation failed!\n");
        goto final_out;
    }
    memset(msg_to_user_buf, '\0', 100);
    if (error != 0)
    {
        printk("Encryption job(%lu) failed. Sending message to user.\n", my_work_obj->job_obj->job_id);
        snprintf(msg_to_user_buf, 100, "Encryption job (job id: %lu) failed!", my_work_obj->job_obj->job_id);
    }
    else
    {
        printk("Encryption job(%lu) done successfully. Sending message to user.\n", my_work_obj->job_obj->job_id);
        snprintf(msg_to_user_buf, 100, "Encryption job (job id: %lu) done successfully!", my_work_obj->job_obj->job_id);
    }

    push_msg_to_user((int)my_work_obj->job_obj->pid, msg_to_user_buf);

    kfree(msg_to_user_buf);

final_out:

	set_fs(oldfs); //Reset to save FS
	
	/* Cleaning my_work_obj */	
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

	printk(KERN_ALERT "Exiting encryption!\n");
	printk("encryption_curr_no_of_jobs: %d\n", job_cnt);
	
	return;
}


static void decryption(struct work_struct *work_obj)
{
	my_work_struct *my_work_obj = (my_work_struct * ) work_obj;
	int i;

	long error = 0;
	/* Variables for file operations */
	struct file *in_filp;
	struct file *out_filp;
	char *readBuf =  NULL;
	char *cryptBuf = NULL;
	char *paddingBufDecrypt = NULL;
	char paddingBitsStr[3];
	mm_segment_t oldfs;
	int  paddingBits, readBytes;
	int pageSize;  /* pointer to the page size length is required 
			  		  in encryption/decryption api */
	int cryptRet;
	umode_t inputFileMode;
	size_t inputFileSize;
	
	/* Variables used to calculate the MD5 hash of the key */
	char* MD5_hash_key = NULL;
	struct crypto_shash *md5;
	struct shash_desc *shash;

	struct inode *outputFileInode = NULL;
	struct dentry *outputFileDentry = NULL;
    char *msg_to_user_buf;

    printk(KERN_ALERT "Entered encryption!\n");
	msleep(1000);
    // delete the job from custom_queue
	if(delete_from_custom_queue(my_work_obj->job_obj->job_id) != 0)
	{
		printk("ALERT! Could not delete work_obj from custom queue\n");
		return;
	}

	oldfs = get_fs();  //Save the current FS segment
	set_fs(KERNEL_DS);

	/* Calculate the MD5 hash of the key accepted in my_work structure */
	/* The following code has been written by going through the following sources:
	   http://shell-storm.org/repo/Linux-Kernel/lkm_samples/hash_md5.c
	   http://lxr.fsl.cs.sunysb.edu/linux/source/crypto/md5.c
	   http://openssl.org/docs/manmaster/crypto/md5.html
	*/
	md5 = crypto_alloc_shash("md5", 0, 0);
	if (md5 == NULL)
	{
		error = -EINVAL;
		goto md5_hashing_failed;
	}
	shash = kmalloc(sizeof(struct shash_desc) + crypto_shash_descsize(md5), 
			GFP_KERNEL);
	if (!shash)
	{
		error = -ENOMEM;
		goto md5_hashing_failed;
	}
	memset(shash, 0, sizeof(struct shash_desc) + crypto_shash_descsize(md5));
	shash->tfm = md5;
	shash->flags = 0;

	MD5_hash_key = kmalloc(AES_BLOCK_SIZE, GFP_KERNEL);
	if (!MD5_hash_key)
	{
		error = -ENOMEM;
		goto md5_buf_alloc_failed;
	}
	memset(MD5_hash_key, 0, AES_BLOCK_SIZE);
	
	if (crypto_shash_init(shash))
	{
		error = -EINVAL;
		goto md5_proc_failed;
	}
	if (crypto_shash_update(shash, (const char *)my_work_obj->job_obj->files[0], 16))
	{
		error = -EINVAL;
		goto md5_proc_failed;
	}
	if (crypto_shash_final(shash, MD5_hash_key))
	{
		error = -EINVAL;
		goto md5_proc_failed;
	}

	crypto_free_shash(md5);
	/* End of MD5 hashing of the key. Hashed key in MD5_hash_key */
	//printk("MD5 hash of the key: %s\n", MD5_hash_key);
	//dump(MD5_hash_key);

	/* Read from the input file */
	/* Open the file */
	in_filp = filp_open(my_work_obj->job_obj->files[2], O_RDONLY, 0);
	if (!in_filp || IS_ERR(in_filp)) 
	{
		printk("Input file open error %d\n", (int) PTR_ERR(in_filp));
		error = -ENOENT; /* set error */
		goto input_file_open_failed;
	}
	if (!(in_filp->f_op))
    {
        printk(KERN_ALERT "No file operations on the input file!\n");
        error = -ENOENT;
        goto input_file_no_file_op;
    }
	if (!in_filp->f_op->read)
	{
		printk("No read permission on the input file!\n");
		error = -ENOENT; /* set error */
		/* file(system) doesn't allow reads */
		goto input_file_no_read_perm;
	}
		
	/* get the input file size and the permissions */
	inputFileSize = in_filp->f_path.dentry->d_inode->i_size;
	inputFileMode = in_filp->f_path.dentry->d_inode->i_mode;

	out_filp = filp_open(my_work_obj->job_obj->files[1], O_TRUNC|O_CREAT, inputFileMode);
	if (!out_filp || IS_ERR(out_filp))
	{
		printk("Output file open err %d\n", (int) PTR_ERR(out_filp));
		error = -ENOENT;
		goto output_file_open_failed;
	}
	if (!(out_filp->f_op))
	{
		printk(KERN_ALERT "No file operations on the output file!\n");
		error = -ENOENT;
		goto output_file_no_file_op;
	}
	if (!out_filp->f_op->write)
	{
		printk("No read permission on the input file!\n");
        error = -ENOENT; /* set error */
        /* file(system) doesn't allow reads */
        goto output_file_no_write_perm;
	}
	
	/* store the output file inode and dentry so that the output file can be vfs_renamed
	   and vfs_unlinked in the case of partial write */
	outputFileInode = out_filp->f_path.dentry->d_parent->d_inode;
	outputFileDentry = out_filp->f_path.dentry;

	/* Check if the input file and the output file are the same. 
	   We do not want to mess with the input file */
	if(in_filp->f_path.dentry->d_inode->i_ino ==
			       out_filp->f_path.dentry->d_inode->i_ino)
	{
		printk("Input and output files are the same!\n");
		error = -EINVAL;
		goto same_input_output_file;
	
	}

	/* Allocate the buffer for reading from the input file */
    readBuf = kmalloc(4096, GFP_KERNEL);
    if (!readBuf)
    {
        error = -ENOMEM;
        printk("Input buffer allocation failed\n");
        goto input_kbuf_failed;
    }
	
	/* Allocate the buffer to store the encrypted/decrypted data */
	cryptBuf = kmalloc(4096, GFP_KERNEL);
	if (!cryptBuf)
	{
        error = -ENOMEM;
        printk("Input buffer allocation failed\n");
        goto crypt_kbuf_failed;
    }

    memset(readBuf, 0, 4096);
	memset(cryptBuf, 0, 4096);
	in_filp->f_pos = 0;  /* start offset */
	out_filp->f_pos = 0;

	/* Decrypt!!! */
	/* First read the MD5 hashed key from the preamble of the input file */
	in_filp->f_op->read(in_filp, readBuf, 16, &in_filp->f_pos);
	/* The key from the user land after hashing should be compared with readBuf to check
	   whether right passphrase was entered by the user or not. The key from the user
	   land has already been hashed and is in MD5_hash_key */
	
	if((memcmp(readBuf, MD5_hash_key, 16)) != 0)
	{
		error = -EINVAL;
		printk("Passphrase not correct!\n");
		goto passphrase_not_correct;
	}

	paddingBufDecrypt = kmalloc(16, GFP_KERNEL);
    if (!paddingBufDecrypt)
    {
	    error = -ENOMEM;
	    printk("Padding buffer allocation failed\n");
	    goto padding_kbuf_failed;
    }
    memset(paddingBufDecrypt, 0, 16);
	/* Read the number of bytes padded in the input file */
	in_filp->f_op->read(in_filp, paddingBufDecrypt, 16, &in_filp->f_pos);
	/* Convert the number to an integer */
	memcpy(paddingBitsStr, paddingBufDecrypt, 2);
	paddingBitsStr[2] = '\0';
	//printk("padding to be removed in str: %s\n", paddingBitsStr);
	paddingBits = simple_strtol(paddingBitsStr, (char **)&paddingBitsStr, 0); 
	//printk("padding to be removed: %d\n", paddingBits);
	
	/* While Loop to read 1 page at a time and decrypt and 
	   write to the output file */
	while ((readBytes = in_filp->f_op->read(in_filp, readBuf, 4096, &in_filp->f_pos)) > 0)
    {
		/* AES decryption on readBuf */
		if (readBytes < 4096)
        {
			/* Here tread carefully. eg if in file is 5000 bytes then only
			   5012 bytes are written on the encrypted file. Paddingbits
			   should be 12. Check if newline needs to be appended or not */
			//printk("Decryption: < 4096: readBytes: %d\n", readBytes);
			pageSize = readBytes;
			cryptRet = my_aes_decrypt(my_work_obj->job_obj->files[0], AES_BLOCK_SIZE,
                                		          cryptBuf, &pageSize, readBuf, pageSize);
			if (cryptRet < 0)
            {
                error = -EFAULT;
                goto decrypt_failed;
            }
			readBytes -= paddingBits;
			//printk("Decryption: < 4096: new readBytes to be put in out file: %d\n", readBytes);
		}
		else /* readBytes == 4096 */
		{
			pageSize = PAGE_SIZE;
			printk("Decryption: readBytes: %d\n", readBytes);
			cryptRet = my_aes_decrypt(my_work_obj->job_obj->files[0], AES_BLOCK_SIZE,
                                        		  cryptBuf, &pageSize, readBuf, PAGE_SIZE);
			if (cryptRet < 0)
			{
            	error = -EFAULT;
               	goto decrypt_failed;
			}
		}
		/* Write the decrypted blocks in the output file */
		out_filp->f_op->write(out_filp, cryptBuf, readBytes, &out_filp->f_pos);
	}

	msleep(3*1000);

decrypt_failed:
	/* Free the padding buffer */
	kfree(paddingBufDecrypt);

padding_kbuf_failed:

passphrase_not_correct:
	kfree(cryptBuf);	

crypt_kbuf_failed:
	kfree(readBuf);  /* Free the kernel buffer used for data transfer */

input_kbuf_failed:

same_input_output_file:

output_file_no_write_perm:

output_file_no_file_op:
    filp_close(out_filp, NULL);
    out_filp = NULL;

output_file_open_failed:

input_file_no_read_perm:

input_file_no_file_op:
	filp_close(in_filp, NULL);
	in_filp = NULL;

input_file_open_failed:

md5_proc_failed:
	kfree(MD5_hash_key);

md5_buf_alloc_failed:
	kfree(shash);

md5_hashing_failed:

    msg_to_user_buf = kmalloc(100, GFP_KERNEL);
    if (!msg_to_user_buf)
    {
        error = -ENOMEM;
        printk(KERN_ERR
                   "Message to user buffer allocation failed!\n");
        goto final_out;
    }
    memset(msg_to_user_buf, '\0', 100);
    if (error != 0)
    {
        printk("Decryption job(%lu) failed. Sending message to user.\n", my_work_obj->job_obj->job_id);
        snprintf(msg_to_user_buf, 100, "Decryption job (job id: %lu) failed!", my_work_obj->job_obj->job_id);
    }
    else
    {
        printk("Decryption job(%lu) done successfully. Sending message to user.\n", my_work_obj->job_obj->job_id);
        snprintf(msg_to_user_buf, 100, "Decryption job (job id: %lu) done successfully!", my_work_obj->job_obj->job_id);
    }

    push_msg_to_user((int)my_work_obj->job_obj->pid, msg_to_user_buf);

    kfree(msg_to_user_buf);

final_out:

	set_fs(oldfs); //Reset to save FS
	
	/* Cleaning my_work_obj */
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

	printk(KERN_ALERT "Exiting decryption!\n");
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

    /* copy the pid */
    if ((copy_from_user(&(destArg->pid), &(srcArg->pid), sizeof(int))) != 0)
    {
        printk("copy from user for pid of job failed!\n");
        error = -EPERM;
        goto out;
    }

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
	else if (destArg->job_type == JTYPE_CANCEL || destArg->job_type == JTYPE_CHANGE)
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
	job_struct *duplicate_job_obj = NULL;
	my_work_struct *work_obj;
	my_work_struct *duplicate_work_obj;
	job_list_struct *job_list_node;
	int i = 0;
	char *job_id_str = NULL;
	unsigned long job_id_size = 0;
	char *job_type_str = NULL;
	char *job_priority_str = NULL;

	// Check if max no of jobs already scheduled
	// but by pass this if the user wants to list the queue, cancel a job or change priority of a job
	spin_lock(&job_cnt_lock);	
	printk("Current no of jobs in queue: %d\n", job_cnt);
	if (job_cnt >= MAX_JOB_CNT && ((job_struct *)arg)->job_type < 7)
	{
		error = -EAGAIN;
		printk("Job Queue FULL!\n");
	    spin_unlock(&job_cnt_lock);
	    goto out_invalid_params;
	}
        // job_cnt = no of jobs in work queue
	if(((job_struct *)arg)->job_type < 7)
	{
        	job_cnt++;
	}
	spin_unlock(&job_cnt_lock);

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
		mutex_lock(&custom_queue_list_lock);
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
			mutex_unlock(&custom_queue_list_lock);
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
		mutex_unlock(&custom_queue_list_lock);
	}
	else if (job_obj->job_type == JTYPE_CANCEL)
	{
		error = -ESRCH;
		
		mutex_lock(&custom_queue_list_lock);
		list_for_each_safe(pos, q, &(job_list_head->jlist))
    	{
    		tmp_list_node = list_entry(pos, job_list_struct, jlist);

			if ( tmp_list_node->job_id == job_obj->job_id)
            {
                // @TODO: need to free the job_obj in work_ptr before cancel_work_sync is called.
                // cancel_work_sync most probably frees the work_obj Also before freeinf job_obj,
                // need to take a lock as this job might be in execution.
                error = cancel_work_sync( (struct work_struct*) tmp_list_node->work_ptr );
				//printk("error returned from cancel job is: %ld\n", error);
				if(error == 1)	
				{
					printk("The job(%lu) was cancelled\n", job_obj->job_id);
					error = 0;
				}
				else
				{
                    printk("The job(%lu) do not exist in queue. Probably already completed.\n", job_obj->job_id);
                    error = -EALREADY;
				}

                if ( (tmp_list_node != NULL && delete_from_custom_queue(tmp_list_node->job_id) != 0) )
                {
                    printk("ALERT! Could not delete work_obj from custom queue\n");
                    error = -EPERM;
                }
				break;	
            }
    	}
	mutex_unlock(&custom_queue_list_lock);	
	}
	else if (job_obj->job_type == JTYPE_CHANGE)
	{
		error = -ESRCH;
		mutex_lock(&custom_queue_list_lock);
		list_for_each_safe(pos, q, &(job_list_head->jlist))
    	{
    		tmp_list_node = list_entry(pos, job_list_struct, jlist);

			if ( tmp_list_node->job_id == job_obj->job_id)
            {
                error = 0; // got the job
                // return error if the priority of the job is same as requested
                if (job_obj->priority == ((my_work_struct *) (tmp_list_node->work_ptr))->job_obj->priority)
                {
                	printk("The job (%lu) already has the same priority as requested!\n", job_obj->job_id);
                	error = EINVAL;
                	break;
                }

                // cancel the job first
                // @TODO: need to free the job_obj in work_ptr before cancel_work_sync is called.
                // cancel_work_sync most probably frees the work_obj Also before freeinf job_obj,
                // need to take a lock as this job might be in execution.

                // Here as job_obj is not being freed by us as of now, just memcpy the data from
                // job_obj. Malloc a new work_obj. Make a work_ptr and submit to the appr. queue.
                duplicate_job_obj = kmalloc(sizeof(job_struct), GFP_KERNEL);
				if (!duplicate_job_obj)
				{
					error = -ENOMEM;
					mutex_unlock(&custom_queue_list_lock);
					goto out_invalid_params;
				}
				memset(duplicate_job_obj, 0, sizeof(job_struct));
				memcpy(duplicate_job_obj, ((my_work_struct *) (tmp_list_node->work_ptr))->job_obj, sizeof(job_struct));
                error = cancel_work_sync( (struct work_struct*) tmp_list_node->work_ptr );
				//printk("error returned from cancel job is: %ld\n", error);
				if(error == 1)	
				{
					printk("Change priority: The job(%lu) was cancelled from current queue!\n", job_obj->job_id);
					// Now queue the job to the appropriate work queue
					duplicate_work_obj = (my_work_struct *)kmalloc(sizeof(my_work_struct), GFP_KERNEL);
					if(!duplicate_work_obj)
					{
						printk("duplicate_work_obj kmalloc failed!\n");
						error = -ENOMEM;
						mutex_unlock(&custom_queue_list_lock);
						goto out_free_job_obj_buf; 
					}
					memset(duplicate_work_obj, 0, sizeof(my_work_struct));		
					if (duplicate_job_obj->job_type == JTYPE_CONCAT)
					{
						INIT_WORK( (struct work_struct *) duplicate_work_obj, concat ); 
					}
					else if (duplicate_job_obj->job_type == JTYPE_CONPRESS)
					{
						INIT_WORK( (struct work_struct *) duplicate_work_obj, compress );
					}
					else if (duplicate_job_obj->job_type == JTYPE_DECOMPRESS)
					{
						INIT_WORK( (struct work_struct *) duplicate_work_obj, decompress );
					}
					else if (duplicate_job_obj->job_type == JTYPE_CHECKSUM)
					{
						INIT_WORK( (struct work_struct *) duplicate_work_obj, checksum );
					}
					else if (job_obj->job_type == JTYPE_ENCRYPT)
					{
						INIT_WORK( (struct work_struct *) duplicate_work_obj, encryption ); //[changed here]
					}
					else if (job_obj->job_type == JTYPE_DECRYPT)
					{
						INIT_WORK( (struct work_struct *) duplicate_work_obj, decryption); //[changed here]
					}
					// Update the new priority in duplicate_job_obj
					duplicate_job_obj->priority = job_obj->priority;
					// populate work_obj with the job_obj contents in the corresponding variable
					duplicate_work_obj->job_obj = duplicate_job_obj;
					// Update mapping in the custom queue.
					tmp_list_node->work_ptr = (struct work_struct*) duplicate_work_obj;

					// now submit the duplicate job to the work queue
					// return_value (ret):  1 = success and -EBUSY = failure
					if(job_obj->priority == 0)
					{
						error = queue_work( my_low_pwq, (struct work_struct *) duplicate_work_obj );	
					}
					else
					{
						error = queue_work( my_high_pwq, (struct work_struct *) duplicate_work_obj );
					}

					if(error == 1) // Success: Job enqueued successfully
					{
						// update error with appropriate success value
						error = 0;
						if(job_obj->priority == 0)
						{
							printk("Job(%lu) enqueued in low_priority_queue successfully\n", job_obj->job_id);
						}
						else
						{
							printk("Job(%lu) enqueued in high_priority_queue Successfully\n",job_obj->job_id);
						}
					}
					else
					{	
						error = -EOPNOTSUPP;
						printk("Job failed to be queued to the work queue!\n");
						// delete the job from the custom queue
						printk("Deleting the job submitted to the custom queue!\n");
						if (delete_from_custom_queue(job_obj->job_id) != 0)
						{
							printk("ALERT! Could not delete work_obj from custom queue\n");
						}
					}
				}
				else
				{
                    printk("The job(%lu) do not exist in queue. Probably already completed.\n", job_obj->job_id);
                    error = -EALREADY;
				}
				break;	
        	}
   		}
		mutex_unlock(&custom_queue_list_lock);
	}
	else // for job type: 1,2,3,4,5,6
	{
		work_obj = (my_work_struct *)kmalloc(sizeof(my_work_struct), GFP_KERNEL);
		
		if(work_obj)
		{
			memset(work_obj, 0, sizeof(my_work_struct));	

			// initialize the work object with call back function
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
			else if (job_obj->job_type == JTYPE_CHECKSUM)
			{
				INIT_WORK( (struct work_struct *) work_obj, checksum );
			}
			else if (job_obj->job_type == JTYPE_ENCRYPT)
			{
				INIT_WORK( (struct work_struct *) work_obj, encryption ); 
			}
			else if (job_obj->job_type == JTYPE_DECRYPT)
			{
				INIT_WORK( (struct work_struct *) work_obj, decryption ); 
			}

			// populate work_obj with the job_obj contents in the corresponding variable
			work_obj->job_obj = job_obj;

			// Submit the job to custom queue before submitting to work queue
			// allocate and add
			job_list_node = (job_list_struct * ) kmalloc(sizeof(job_list_struct), GFP_KERNEL);
			if (!job_list_node) 
			{
				error = -ENOMEM;
				printk(KERN_ERR "Job list buffer allocation failed!\n");
				goto out_free_job_obj_buf;
			}

                        // increment and allocate job_id; create mapping
                        spin_lock(&job_id_cnt_lock);
                        job_id_cnt++;
			// create mapping 
			job_list_node->job_id = job_id_cnt;
                        spin_unlock(&job_id_cnt_lock);

			job_list_node->work_ptr = (struct work_struct*) work_obj;

	        /* Put in the custom queue */
		mutex_lock(&custom_queue_list_lock);
		printk("mutex_taken_by: %lu\n", job_list_node->job_id);
	        list_add_tail(&(job_list_node->jlist), &(job_list_head->jlist));
                printk("mutex_released_by: %lu\n", job_list_node->job_id);
		mutex_unlock(&custom_queue_list_lock);
			// job_cnt = no of jobs in work queue
            		//job_cnt++;

			printk("Added job %lu to custom queue!\n", job_list_node->job_id);

			// return job_id to user as well & update job_id of kernel job_obj
			((job_struct*) arg)->job_id = job_list_node->job_id; 			
			work_obj->job_obj->job_id = job_list_node->job_id;

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
				if (delete_from_custom_queue(job_list_node->job_id) != 0)
				{
					printk("ALERT! Could not delete work_obj from custom queue\n");
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
	printk("Exiting Submitjob!\n");
	return error;
}

static int __init init_sys_submitjob(void)
{
	int error = 0;
    struct netlink_kernel_cfg cfg = {
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

