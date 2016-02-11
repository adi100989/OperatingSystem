/*
 * Copyright (c) 1998-2014 Erez Zadok
 * Copyright (c) 2009	   Shrikar Archak
 * Copyright (c) 2003-2014 Stony Brook University
 * Copyright (c) 2003-2014 The Research Foundation of SUNY
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include "amfs.h"
#include <linux/list.h>
#include <asm/uaccess.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/file.h>
//#define VALUE "bad_file_flag"

#include <linux/xattr.h>

/******* start *******[aditi]***/

// define a structure for patterns*/
struct pattern_list{
	struct list_head list; // the head
	char *pattern;	       // the actual pattern string
	};

/********* end  ***[aditi]*********/

static ssize_t amfs_read(struct file *file, char __user *buf,
			   size_t count, loff_t *ppos)
{
	int err;
	struct file *lower_file;
	struct dentry *dentry = file->f_path.dentry;
	/******start ****[aditi] *************/
	/* to access the list head using sb private info for bad patterns*/
	
	struct super_block *sb=file->f_inode->i_sb;
	struct amfs_sb_info *sbi=sb->s_fs_info;
	struct list_head *p=sbi->my_list;
	struct list_head *pos;
	char *temp_buf=NULL, *ret=NULL;
	struct pattern_list *tmp=NULL;
	int setError=0,xattr=0;
	unsigned char* val=NULL;
	val=(char *)kzalloc(3,GFP_KERNEL);
	strcpy(val,"bad");
	
	/******** end ***[aditi]*************/
	lower_file = amfs_lower_file(file);
	err = vfs_read(lower_file, buf, count, ppos);
	//printk("\n in file.c->amfs_read() with err=%d",err);
	/* update our inode atime upon a successful lower read */
	if (err >= 0)
		fsstack_copy_attr_atime(dentry->d_inode,
					file_inode(lower_file));
					
					
	/****** start **[aditi]*****************/
	/*
		buf : contains the contents of the file read. 
		i have to read the buf values and check if any bad pattern exists
		and setattr() to its inode. I will then send an error message which 
		will stop the file read.
	*/	
	
	//printk("\n the buffer is=%s ",buf);
	//printk("\n sb_file path is %s",sbi->file_path);
	
	xattr=vfs_getxattr(dentry, "user.bad", val,3 );
	if(xattr<=0)
	  {
	 // printk("\n Extra attribute does not exist %d",xattr);
	  
	  }
	else
	  {
	  printk("\n Extra attribute= user.bad already set previously with size= %d \n BAD FILE",xattr);
	  err=-EACCES;
	  goto exit;
	  }
		
	
	//printk("\n traversing the list using list_for_each\n");
	list_for_each(pos, p)
	{
		//*ret=NULL;
		tmp=list_entry(pos, struct pattern_list, list);
	//	printk("\n pattern is    %s", tmp->pattern);
		temp_buf=(char *)kzalloc(strlen(tmp->pattern),GFP_KERNEL);
		strcpy(temp_buf,tmp->pattern);
		//printk("\n the temp_buf now has the pattern %s",temp_buf);
		
		ret=strstr(buf,temp_buf); //check whether temp_buf in buf
		
		if (ret!=NULL)
		{
			printk("\n the file has malicious patterns.");
			setError= vfs_setxattr(dentry,"user.bad",val,3,0);
			//printk("\n the setxattr has been set with value %s and  error= %d",val,setError);
			err=-EACCES;	
		}		
		kfree(temp_buf);
	}	
	
		

	/*******  end   ******[aditi]***********/	
	kfree(val);
	exit:
	
	return err;
}

static ssize_t amfs_write(struct file *file, const char __user *buf,
			    size_t count, loff_t *ppos)
{
	int err,xattr=0;

	struct file *lower_file;
	struct dentry *dentry = file->f_path.dentry;
	
	/******start ****[aditi] *************/
	/* to access the list head using sb private info for bad patterns*/
	
	struct super_block *sb=file->f_inode->i_sb;
	struct amfs_sb_info *sbi=sb->s_fs_info;
	struct list_head *p=sbi->my_list;
	struct list_head *pos;
	char *temp_buf=NULL, *ret=NULL;
	struct pattern_list *tmp=NULL;
	unsigned char* val=NULL;
	int setError=0;
	val=(char *)kzalloc(3,GFP_KERNEL);
	strcpy(val,"bad");
	/******** end ***[aditi]*************/

	lower_file = amfs_lower_file(file);
	
	err = vfs_write(lower_file, buf, count, ppos);
	
	
	/****** start **[aditi]*****************/
	/*
		buf : contains the contents of the file read. 
		i have to read the buf values and check if any bad pattern exists
		and setattr() to its inode. I will then send an error message which 
		will stop the file write.
	*/	
	
	
	xattr=vfs_getxattr(dentry, "user.bad", val,3 );
		if(xattr<=0)
		{
		//	printk("\n Extra attribute does not exist %d",xattr);
	  
		}
		else
		{
		printk("Extra attribute 'user.bad' already set with size= %d \n BAD FILE",xattr);
		err=-EACCES;
		goto exit;
		}
	
	
	//printk("\n traversing the list using list_for_each\n");
	list_for_each(pos, p)
	{
		
		tmp=list_entry(pos, struct pattern_list, list);
		
		temp_buf=(char *)kzalloc(strlen(tmp->pattern),GFP_KERNEL);
		strcpy(temp_buf,tmp->pattern);
		
		ret=strstr(buf,temp_buf); //check whether temp_buf in buf
		
		if (ret!=NULL)
		{
			printk("\n the file has malicious pattern = %s \n Setting Extra attribute to mark it bad",temp_buf);
			setError= vfs_setxattr(dentry,"user.bad",val,3,0);
			err=-EACCES;
			kfree(temp_buf);
			goto exit;
			
		}		
		kfree(temp_buf);
	}	
	/*
	xattr=vfs_getxattr(dentry, "user.bad", val,3 );
	if(xattr<=0)
	{
		//printk("Extra attribute does not exist %d\n",xattr);
  
	}
	else
	{
	printk("Extra attribute= user.bad now set within write with  size= %d \n BAD FILE",xattr);
	err=-EACCES;
	goto exit;
	}
	*/
	
	
	/*******  end   ******[aditi]***********/	

	/* update our inode times+sizes upon a successful lower write */
	// printk("\n in file.c->amfs_write() with err=%d",err);

	if (err >= 0) {
		fsstack_copy_inode_size(dentry->d_inode,
					file_inode(lower_file));
		fsstack_copy_attr_times(dentry->d_inode,
					file_inode(lower_file));
	}
exit:
	kfree(val);
	return err;
}

static int amfs_readdir(struct file *file, struct dir_context *ctx)
{
	int err;
	struct file *lower_file = NULL;
	struct dentry *dentry = file->f_path.dentry;

	lower_file = amfs_lower_file(file);
	err = iterate_dir(lower_file, ctx);
	// printk("\n in file.c->amfs_readdir() with err=%d",err);

	file->f_pos = lower_file->f_pos;
	if (err >= 0)		/* copy the atime */
		fsstack_copy_attr_atime(dentry->d_inode,
					file_inode(lower_file));
	return err;
}
/******** start   ***[aditi]*****************/
/*****  code for update file*********/

   /*    read the pattern file to generate a linked list */
long update_file(char *path, struct list_head *p)
{		
		
		long err=0;
		struct list_head *pos;
		struct pattern_list *tmp;
		/*initialize all the file structures for read/write */
		struct file *output_file=NULL;
		 /*initialize all the buffers  for read/write */
		char *file_buffer_read=NULL;
		int  bytes_read=0;
		mm_segment_t oldfs;
		
		/* open the read file in the read only mode*/
		output_file = filp_open(path, O_TRUNC, 00666);
if (!output_file|| IS_ERR(output_file)) //check for opening error
		{
				printk("\n File opening error. Error returned= %d\n", (int) PTR_ERR(output_file));
				err=(int)PTR_ERR(output_file);
				goto exit;
		}

		else printk("\n no opening error");

		if (!output_file->f_op->write) // file(system) doesn't allow reads
		{
				printk("\n File doesn't allow writes ");
				err=-EACCES;
				goto exit;
		}
		else printk("\n this is a write file");
		
		//create a buffer for read and check
						
		/* start write in PAGE_SIZE increments.*/
		oldfs = get_fs();  // set oldfs to present DS
		set_fs(KERNEL_DS);  // set present to kernel data segment

		/* check if the input file size is not 0 */

		output_file->f_pos=0;             //set the input file pointer to 0 position
		
		//int x=0;
		list_for_each(pos, p)
		{
		tmp=list_entry(pos, struct pattern_list, list);
		//printk("pattern is    %s\n", tmp->pattern);
		file_buffer_read= kzalloc(strlen(tmp->pattern),GFP_KERNEL);
		strcpy(file_buffer_read,tmp->pattern);
		bytes_read=output_file->f_op->write(output_file,file_buffer_read , strlen(file_buffer_read), &output_file->f_pos);
		bytes_read=output_file->f_op->write(output_file,"\n" , 1, &output_file->f_pos);
		kfree(file_buffer_read);
		}	
		
		set_fs(oldfs);
		
	exit:
		if(output_file)
			filp_close(output_file, NULL);
	return err;	

}
/******** end   ***[aditi]*****************/


static long amfs_unlocked_ioctl(struct file *file, unsigned int cmd,
				  unsigned long arg)
{
	long err = -ENOTTY;
	
	struct file *lower_file;
/****  start ************** [aditi] ***/

	struct super_block *sb=file->f_inode->i_sb;
	struct amfs_sb_info *sbi=sb->s_fs_info;
	struct list_head *p=sbi->my_list;
	struct pattern_list  *tmp=NULL;
	struct list_head *pos, *q;
	char *buf=NULL, *args=NULL;
	int copyflag;
	printk("\n the cmd is %d  arg  %s filepath %s",cmd, (char *)arg, sbi->file_path);
	switch(cmd){
		case 0: //for adding pattern
		{
			printk("\n IOCTL CALLED: adding pattern in %s",sbi->file_path);
			printk("\n the pattern is %s",(char *)arg);
				tmp= (struct pattern_list *)kzalloc(sizeof(struct pattern_list),GFP_KERNEL);
				tmp->pattern=(char *)kzalloc(sizeof((char *)arg),GFP_KERNEL);
				strcpy(tmp->pattern,(char *)arg);
				list_add(&(tmp->list),p);
				/*update the file using amfs_read*/
				err=update_file(sbi->file_path, sbi->my_list);
				
				
			break;
		}
		case 1: //removing pattern
		{
			printk("\n IOCTL CALLED: deleting pattern in %s",sbi->file_path);
			printk("\n the pattern is %s",(char *)arg);
			list_for_each_safe(pos, q, p)
			{
				tmp= list_entry(pos, struct pattern_list, list);
				if (strcmp((char*)arg, tmp->pattern)==0)
				{
				printk("\n freeing item %s ", tmp->pattern);
				list_del(pos);
				kfree(tmp);
				}
			}
			err=update_file(sbi->file_path, sbi->my_list);
			break;
		}
		case 20: // listing pattern
		{ 	
			//copy to user the file loction for updated patterns
			buf= kzalloc(strlen(sbi->file_path),GFP_KERNEL);
			args= kzalloc(strlen(sbi->file_path),GFP_KERNEL);
			strcpy(buf,sbi->file_path);
			strcpy(args,sbi->file_path);
			printk("\n buf now has value %s",buf);
			copyflag= copy_to_user((void *)args, (void *)buf, strlen(buf));
			if (!copyflag)
			{
				printk("\n not copied to copy_to_user buffer");
			}
			printk("\n IOCTL CALLED: listing pattern from  %s",sbi->file_path);
			//printk("traversing the list using list_for_each_entry()\n");
			list_for_each(pos, p)
			{
				tmp=list_entry(pos, struct pattern_list, list);
				printk("\n pattern is    %s", tmp->pattern);
			}	
			printk("\n");
			
			kfree(buf);
			kfree(args);
			
		}
	}
/**** add end by [aditi] ***/	
	lower_file = amfs_lower_file(file);

	/* XXX: use vfs_ioctl if/when VFS exports it */
	if (!lower_file || !lower_file->f_op)
		goto out;
	if (lower_file->f_op->unlocked_ioctl)
		err = lower_file->f_op->unlocked_ioctl(lower_file, cmd, arg);

	/* some ioctls can change inode attributes (EXT2_IOC_SETFLAGS) */
	if (!err)
		fsstack_copy_attr_all(file_inode(file),
				      file_inode(lower_file));
					  
/**************[aditi]*******
pattern_error:
	kfree(pattern);

*******[aditi]******/					  
out:
	return err;
}

#ifdef CONFIG_COMPAT
static long amfs_compat_ioctl(struct file *file, unsigned int cmd,
				unsigned long arg)
{
	long err = -ENOTTY;
	struct file *lower_file;

	lower_file = amfs_lower_file(file);

	/* XXX: use vfs_ioctl if/when VFS exports it */
	if (!lower_file || !lower_file->f_op)
		goto out;
	if (lower_file->f_op->compat_ioctl)
		err = lower_file->f_op->compat_ioctl(lower_file, cmd, arg);

out:
	return err;
}
#endif

static int amfs_mmap(struct file *file, struct vm_area_struct *vma)
{
	int err = 0;
	bool willwrite;
	struct file *lower_file;
	const struct vm_operations_struct *saved_vm_ops = NULL;

	/* this might be deferred to mmap's writepage */
	willwrite = ((vma->vm_flags | VM_SHARED | VM_WRITE) == vma->vm_flags);

	/*
	 * File systems which do not implement ->writepage may use
	 * generic_file_readonly_mmap as their ->mmap op.  If you call
	 * generic_file_readonly_mmap with VM_WRITE, you'd get an -EINVAL.
	 * But we cannot call the lower ->mmap op, so we can't tell that
	 * writeable mappings won't work.  Therefore, our only choice is to
	 * check if the lower file system supports the ->writepage, and if
	 * not, return EINVAL (the same error that
	 * generic_file_readonly_mmap returns in that case).
	 */
	lower_file = amfs_lower_file(file);
	if (willwrite && !lower_file->f_mapping->a_ops->writepage) {
		err = -EINVAL;
		printk(KERN_ERR "amfs: lower file system does not "
		       "support writeable mmap\n");
		goto out;
	}

	/*
	 * find and save lower vm_ops.
	 *
	 * XXX: the VFS should have a cleaner way of finding the lower vm_ops
	 */
	if (!AMFS_F(file)->lower_vm_ops) {
		err = lower_file->f_op->mmap(lower_file, vma);
		if (err) {
			printk(KERN_ERR "amfs: lower mmap failed %d\n", err);
			goto out;
		}
		saved_vm_ops = vma->vm_ops; /* save: came from lower ->mmap */
	}

	/*
	 * Next 3 lines are all I need from generic_file_mmap.  I definitely
	 * don't want its test for ->readpage which returns -ENOEXEC.
	 */
	file_accessed(file);
	vma->vm_ops = &amfs_vm_ops;

	file->f_mapping->a_ops = &amfs_aops; /* set our aops */
	if (!AMFS_F(file)->lower_vm_ops) /* save for our ->fault */
		AMFS_F(file)->lower_vm_ops = saved_vm_ops;

out:
	return err;
}

static int amfs_open(struct inode *inode, struct file *file)
{
	/************************[aditi]*************************/
	/* can I use getattr here to disable open() of bad files*/
	/*************************[aditi]************************/

	int err = 0;
	struct file *lower_file = NULL;
	struct path lower_path;

	/* don't open unhashed/deleted files */
	if (d_unhashed(file->f_path.dentry)) {
		err = -ENOENT;
		goto out_err;
	}
	
	file->private_data =
		kzalloc(sizeof(struct amfs_file_info), GFP_KERNEL);
	if (!AMFS_F(file)) {
		err = -ENOMEM;
		goto out_err;
	}

	/* open lower object and link amfs's file struct to lower's */
	amfs_get_lower_path(file->f_path.dentry, &lower_path);
	lower_file = dentry_open(&lower_path, file->f_flags, current_cred());
	path_put(&lower_path);
	if (IS_ERR(lower_file)) {
		err = PTR_ERR(lower_file);
		lower_file = amfs_lower_file(file);
		if (lower_file) {
			amfs_set_lower_file(file, NULL);
			fput(lower_file); /* fput calls dput for lower_dentry */
		}
	} else {
		amfs_set_lower_file(file, lower_file);
	}

	if (err)
		kfree(AMFS_F(file));
	else
		fsstack_copy_attr_all(inode, amfs_lower_inode(inode));
out_err:
	return err;
}

static int amfs_flush(struct file *file, fl_owner_t id)
{
	int err = 0;
	struct file *lower_file = NULL;

	lower_file = amfs_lower_file(file);
	if (lower_file && lower_file->f_op && lower_file->f_op->flush) {
		filemap_write_and_wait(file->f_mapping);
		err = lower_file->f_op->flush(lower_file, id);
	}

	return err;
}

/* release all lower object references & free the file info structure */
static int amfs_file_release(struct inode *inode, struct file *file)
{
	struct file *lower_file;

	lower_file = amfs_lower_file(file);
	if (lower_file) {
		amfs_set_lower_file(file, NULL);
		fput(lower_file);
	}

	kfree(AMFS_F(file));
	return 0;
}

static int amfs_fsync(struct file *file, loff_t start, loff_t end,
			int datasync)
{
	int err;
	struct file *lower_file;
	struct path lower_path;
	struct dentry *dentry = file->f_path.dentry;

	err = __generic_file_fsync(file, start, end, datasync);
	if (err)
		goto out;
	lower_file = amfs_lower_file(file);
	amfs_get_lower_path(dentry, &lower_path);
	err = vfs_fsync_range(lower_file, start, end, datasync);
	amfs_put_lower_path(dentry, &lower_path);
out:
	return err;
}

static int amfs_fasync(int fd, struct file *file, int flag)
{
	int err = 0;
	struct file *lower_file = NULL;

	lower_file = amfs_lower_file(file);
	if (lower_file->f_op && lower_file->f_op->fasync)
		err = lower_file->f_op->fasync(fd, lower_file, flag);

	return err;
}

static ssize_t amfs_aio_read(struct kiocb *iocb, const struct iovec *iov,
			       unsigned long nr_segs, loff_t pos)
{
	int err = -EINVAL;
	struct file *file, *lower_file;

	file = iocb->ki_filp;
	lower_file = amfs_lower_file(file);
	if (!lower_file->f_op->aio_read)
		goto out;
	/*
	 * It appears safe to rewrite this iocb, because in
	 * do_io_submit@fs/aio.c, iocb is a just copy from user.
	 */
	get_file(lower_file); /* prevent lower_file from being released */
	iocb->ki_filp = lower_file;
	err = lower_file->f_op->aio_read(iocb, iov, nr_segs, pos);
	iocb->ki_filp = file;
	fput(lower_file);
	/* update upper inode atime as needed */
	if (err >= 0 || err == -EIOCBQUEUED)
		fsstack_copy_attr_atime(file->f_path.dentry->d_inode,
					file_inode(lower_file));
out:
	return err;
}

static ssize_t amfs_aio_write(struct kiocb *iocb, const struct iovec *iov,
				unsigned long nr_segs, loff_t pos)
{
	int err = -EINVAL;
	struct file *file, *lower_file;

	file = iocb->ki_filp;
	lower_file = amfs_lower_file(file);
	if (!lower_file->f_op->aio_write)
		goto out;
	/*
	 * It appears safe to rewrite this iocb, because in
	 * do_io_submit@fs/aio.c, iocb is a just copy from user.
	 */
	get_file(lower_file); /* prevent lower_file from being released */
	iocb->ki_filp = lower_file;
	err = lower_file->f_op->aio_write(iocb, iov, nr_segs, pos);
	iocb->ki_filp = file;
	fput(lower_file);
	/* update upper inode times/sizes as needed */
	if (err >= 0 || err == -EIOCBQUEUED) {
		fsstack_copy_inode_size(file->f_path.dentry->d_inode,
					file_inode(lower_file));
		fsstack_copy_attr_times(file->f_path.dentry->d_inode,
					file_inode(lower_file));
	}
out:
	return err;
}

/*
 * amfs cannot use generic_file_llseek as ->llseek, because it would
 * only set the offset of the upper file.  So we have to implement our
 * own method to set both the upper and lower file offsets
 * consistently.
 */
static loff_t amfs_file_llseek(struct file *file, loff_t offset, int whence)
{
	int err;
	struct file *lower_file;

	err = generic_file_llseek(file, offset, whence);
	if (err < 0)
		goto out;

	lower_file = amfs_lower_file(file);
	err = generic_file_llseek(lower_file, offset, whence);

out:
	return err;
}

/*
 * amfs read_iter, redirect modified iocb to lower read_iter
 */
ssize_t
amfs_read_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	int err;
	struct file *file = iocb->ki_filp, *lower_file;

	lower_file = amfs_lower_file(file);
	if (!lower_file->f_op->read_iter) {
		err = -EINVAL;
		goto out;
	}

	get_file(lower_file); /* prevent lower_file from being released */
	iocb->ki_filp = lower_file;
	err = lower_file->f_op->read_iter(iocb, iter);
	iocb->ki_filp = file;
	fput(lower_file);
	/* update upper inode atime as needed */
	if (err >= 0 || err == -EIOCBQUEUED)
		fsstack_copy_attr_atime(file->f_path.dentry->d_inode,
					file_inode(lower_file));
out:
	return err;
}

/*
 * amfs write_iter, redirect modified iocb to lower write_iter
 */
ssize_t
amfs_write_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	int err;
	struct file *file = iocb->ki_filp, *lower_file;

	lower_file = amfs_lower_file(file);
	if (!lower_file->f_op->write_iter) {
		err = -EINVAL;
		goto out;
	}

	get_file(lower_file); /* prevent lower_file from being released */
	iocb->ki_filp = lower_file;
	err = lower_file->f_op->write_iter(iocb, iter);
	iocb->ki_filp = file;
	fput(lower_file);
	/* update upper inode times/sizes as needed */
	if (err >= 0 || err == -EIOCBQUEUED) {
		fsstack_copy_inode_size(file->f_path.dentry->d_inode,
					file_inode(lower_file));
		fsstack_copy_attr_times(file->f_path.dentry->d_inode,
					file_inode(lower_file));
	}
out:
	return err;
}

const struct file_operations amfs_main_fops = {
	.llseek		= generic_file_llseek,
	.read		= amfs_read,
	.write		= amfs_write,
	.unlocked_ioctl	= amfs_unlocked_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= amfs_compat_ioctl,
#endif
	.mmap		= amfs_mmap,
	.open		= amfs_open,
	.flush		= amfs_flush,
	.release	= amfs_file_release,
	.fsync		= amfs_fsync,
	.fasync		= amfs_fasync,
	.aio_read	= amfs_aio_read,
	.aio_write	= amfs_aio_write,
	.read_iter	= amfs_read_iter,
	.write_iter	= amfs_write_iter,
};

/* trimmed directory options */
const struct file_operations amfs_dir_fops = {
	.llseek		= amfs_file_llseek,
	.read		= generic_read_dir,
	.iterate	= amfs_readdir,
	.unlocked_ioctl	= amfs_unlocked_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= amfs_compat_ioctl,
#endif
	.open		= amfs_open,
	.release	= amfs_file_release,
	.flush		= amfs_flush,
	.fsync		= amfs_fsync,
	.fasync		= amfs_fasync,
};
