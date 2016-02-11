#include "amfs.h"
#include <linux/module.h>
#include <linux/string.h>
#include <linux/parser.h>
#include <linux/list.h>
#include <linux/linkage.h>
#include <linux/moduleloader.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <asm/uaccess.h>
#include <linux/stat.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/kernel.h>
#include <asm/unistd.h>
#include <linux/path.h>
#include <linux/err.h>

static LIST_HEAD(mylist_head);
/*
 * There is no need to lock the amfs_super_info's rwsem as there is no
 * way anyone can have a reference to the superblock at this point in time.
 */
/*added [Aditi] */

/* list and code https://isis.poly.edu/kulesh/stuff/src/klist/ ,
https://www.cs.uic.edu/~hnagaraj/articles/linked-list/link-list-test.c,
http://www.makelinux.net/ldd3/chp-11-sect-5 and list.h  */

/* define a structure for patterns*/
struct pattern_list{
	struct list_head list; // the head
	char *pattern;	       // the actual pattern string
	};

enum {pattdb, none};

static const match_table_t tokens = {
	{pattdb, "pattdb=%s"},
	{none, NULL} ,     
};

/*    read the pattern file to generate a linked list */
void create_pattern_list(char *path)
{		
		//printk("\n in create pattern list");
		int error_code=0;
		
		/*initialize all the file structures for read/write */
		struct file *input_file=NULL;

		 /*initialize all the buffers  for read/write */
		char *file_buffer_read=NULL;

		int  bytes_read=0,total_bytes=0, input_size=0;
		char *token = NULL, *str = NULL, *tofree = NULL; // for tokenizing
		struct pattern_list *tmp;
		mm_segment_t oldfs;
		
		/* pattern list changes here [aditi] */
		
		printk("\n in function create_pattern_list. path is   %s ",(char *)path);				
		/* pattern list changes end here [aditi] */
		
		/* open the read file in the read only mode*/
		input_file = filp_open(path, O_RDONLY, 0);
		if (!input_file || IS_ERR(input_file)) //check for opening error
		{
				printk("\n File opening error. Error returned= %d\n", (int) PTR_ERR(input_file));
				error_code=(int)PTR_ERR(input_file);
				goto exit;
		}

		//else printk("\n no opening error");

		if (!input_file->f_op->read) // file(system) doesn't allow reads
		{
				printk("\n File doesn't allow reads ");
				error_code=-EACCES;
				goto exit;
		}
		//else printk("\n this is a read file");
		
		//create a buffer for read and check
		file_buffer_read= kzalloc(PAGE_SIZE,GFP_KERNEL);
		if (!file_buffer_read)   //check for Kmalloc for file_buffer_read
		  {
		   printk("\n Kmalloc(file_buffer_read) failed with error %d", -ENOMEM);
		   error_code= -ENOMEM;
		   goto exit;
		  }
		//else printk("\n kmalloc for file_buffer_read succeeded");

		
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
		bytes_read=0;
		
		
		//printk("\n total bytes is    %d",total_bytes);
		while (total_bytes>0)
			{

		/*READ into a file_buffer_read and transfer contents of file_buffer_read to write the temp file */
		/*
				if total bytes i.e. the size of file is less than the PAGE_SIZE, then execute the below block

		*/
		//printk("\n total bytes is    %d",total_bytes);
		if (total_bytes<PAGE_SIZE)
		{			
	
		bytes_read = input_file->f_op->read(input_file,file_buffer_read , total_bytes, &input_file->f_pos);
		total_bytes=0;
		//printk("\n the bytes_read is =%d",bytes_read);
		
		while((token = strsep(&file_buffer_read, "\n")) != NULL)
		{	
			//printk("reached cp2\n");
			//printk("\n token  %s",token);
			if(!*token)
			{
				continue;
			}
		//printk("\n token is %s and left string is  %s",token,file_buffer_read);
		
		tmp= (struct pattern_list *)kzalloc(sizeof(struct pattern_list),GFP_KERNEL);
		tmp->pattern=(char *)kzalloc(sizeof(token),GFP_KERNEL);
		strcpy(tmp->pattern,token);
		token=NULL;
		list_add(&(tmp->list),&mylist_head);
						
		}
		}
		else
		{
					
		bytes_read = input_file->f_op->read(input_file,file_buffer_read , total_bytes, &input_file->f_pos);
		total_bytes=total_bytes-bytes_read;
		//printk("\n the bytes_read is =%d",bytes_read);
		
		while((token = strsep(&file_buffer_read, "\n")) != NULL)
		{	
			
		//	printk("reached cp2\n");
		//	printk("\n token  %s",token);
			if(!*token)
			{
				continue;
			}
		//printk("\n token is %s and left string is  %s",token,file_buffer_read);
		tmp= (struct pattern_list *)kzalloc(sizeof(struct pattern_list),GFP_KERNEL);
		tmp->pattern=(char *)kzalloc(sizeof(token),GFP_KERNEL);
		strcpy(tmp->pattern,token);
		//token=NULL;
		list_add(&(tmp->list),&mylist_head);
		}
			
		}
			}
		if (error_code==0) // if no errors encountered. 
		{
				printk("\n file read /write successful");
				printk("\n the list has these values...   \n");
				//display(&p_head);
				
			//	printk("traversing the list using list_for_each_entry()\n");
				list_for_each_entry(tmp, &mylist_head, list)
					printk("  %s\n", tmp->pattern);
				printk("\n");

		}
		set_fs(oldfs);
		
	exit:
		if(file_buffer_read)
			kfree(file_buffer_read);
		
		if(input_file)
			filp_close(input_file, NULL);
		if(str)
			kfree(str);
		if(tofree)
			kfree(tofree);
	return;	

}

	/* parse option for function(taken from ecryptfs) */
	static char* amfs_parse_options(char *options)
	{
		char *p;
		int err = 0;
		substring_t args[MAX_OPT_ARGS];
		int token;
		char *path=NULL;
		//printk("\n begin parsing for option: %s",options);
	   
		if(!options)
		{
			err = -EINVAL;
		}
		if (strstr(options,"pattdb=")==0){ printk("\n pattdb pattern found");}
		
		while((p = strsep(&options, ",")) != NULL){
			if(!*p){
				continue;
			}
			token = match_token(p, tokens, args);
			switch(token){
			case pattdb:
				path=match_strdup(&args[0]);
			//	printk("\n pattern path is  %s",path);
				return path;
/*add later [aditi]	if(!path)
				{
				printk("\n the path is =%s",path);	
				err=0;
				}
				else 
				{
					printk("\n pattern path is empty. error ");
					err=-EINVAL;
				}
add later [aditi]*/					
				break;
			case none:
			default:
				err = -EINVAL;
				printk(KERN_WARNING"%s: amfs: unrecognized option [%s]\n",__func__, p);
				break;
			}
		}
		
		return NULL;
	}
/*added: end*/

static int amfs_read_super(struct super_block *sb, void *raw_data, void *options, int silent)
{
	int err = 0;
	struct super_block *lower_sb;
	struct amfs_sb_info *sbi=sb->s_fs_info; //[aditi]
	
	struct path lower_path;
	char *dev_name = (char *) raw_data;
	struct inode *inode;
	
	if (!dev_name)
		{
		printk(KERN_ERR"amfs: read_super: missing dev_name argument\n");
		err = -EINVAL;
		goto out;
	}
	/* added  to parse the file path[aditi] */
	strcpy((char *)options, amfs_parse_options(options)); /* got back the path after parsing*/
	if (options==NULL) 
	{
		printk("\n parsing of the pattern file error");
		goto out;
	}
	else printk("\n mount point after parsing is   %s",(char*)options);
	/* add end*/
	/* parse lower path */
	err = kern_path(dev_name, LOOKUP_FOLLOW | LOOKUP_DIRECTORY,
			&lower_path);
	if (err) 
	{
		printk(KERN_ERR	"amfs: error accessing "
		       "lower directory '%s'\n", dev_name);
		goto out;
	}

	/* allocate superblock private data */
	//printk("\n in main.c->amfs_read_super().. allocate superblock data");
	sb->s_fs_info = kzalloc(sizeof(struct amfs_sb_info), GFP_KERNEL);
	if (!AMFS_SB(sb)) 
	{
		printk(KERN_CRIT "amfs: read_super: out of memory\n");
		err = -ENOMEM;
		goto out_free;
	}
	
	/* set the lower superblock field of upper superblock */
	lower_sb = lower_path.dentry->d_sb;
	atomic_inc(&lower_sb->s_active);
	amfs_set_lower_super(sb, lower_sb);
	/* inherit maxbytes from lower file system */
	sb->s_maxbytes = lower_sb->s_maxbytes;

	/*
	 * Our c/m/atime granularity is 1 ns because we may stack on file
	 * systems whose granularity is as good.
	 */
	sb->s_time_gran = 1;

	sb->s_op = &amfs_sops;

	/* get a new inode and allocate our root dentry */
	inode = amfs_iget(sb, lower_path.dentry->d_inode);
	if (IS_ERR(inode)) {
		err = PTR_ERR(inode);
		goto out_sput;
	}
	sb->s_root = d_make_root(inode);
	if (!sb->s_root) {
		err = -ENOMEM;
		goto out_iput;
	}
	d_set_d_op(sb->s_root, &amfs_dops);

	/* link the upper and lower dentries */
	sb->s_root->d_fsdata = NULL;
	err = new_dentry_private_data(sb->s_root);
	if (err)
		goto out_freeroot;

	/* if get here: cannot have error */

	/* set the lower dentries for s_root */
	amfs_set_lower_path(sb->s_root, &lower_path);

	/*
	 * No need to call interpose because we already have a positive
	 * dentry, which was instantiated by d_make_root.  Just need to
	 * d_rehash it.
	 */
	d_rehash(sb->s_root);
	if (!silent)
		printk(KERN_INFO
		       "amfs: mounted on top of %s type %s\n",
		       dev_name, lower_sb->s_type->name);

	/* added by [aditi] */
	sbi->my_list=&mylist_head; 
	sbi->file_path=kzalloc(sizeof(options),GFP_KERNEL);
	strcpy(sbi->file_path,(char *)options);	//added [aditi]
	create_pattern_list((char *)options); 
	//printk("\n reached my_list Allocation");
	
	
	/* add ended [aditi]*/		   
			   
			   
	goto out; /* all is well */

	/* no longer needed: free_dentry_private_data(sb->s_root); */
out_freeroot:
	dput(sb->s_root);
out_iput:
	iput(inode);
out_sput:
	/* drop refs we took earlier */
	atomic_dec(&lower_sb->s_active);
	kfree(AMFS_SB(sb));
	sb->s_fs_info = NULL;
out_free:
	path_put(&lower_path);

out:
	//struct list_head *pattern_list= create_pattern_list(options); //added [aditi]
	
	return err;
}

struct dentry *amfs_mount(struct file_system_type *fs_type, int flags,
			    const char *dev_name, void *raw_data)
{
	void *lower_path_name = (void *) dev_name;
	/*added: begin */
    int error=0;

	struct super_block *s = sget(fs_type, NULL, set_anon_super, flags, NULL);
	//printk("\n Main.c(amfs_mount) raw data=%s",(char*)raw_data);

    if (IS_ERR(s))
        return ERR_CAST(s);

    error = amfs_read_super(s, (void *)lower_path_name, (void *)raw_data, flags & MS_SILENT ? 1 : 0);
    if (error) {
			deactivate_locked_super(s);
			return ERR_PTR(error);
	}
        s->s_flags |= MS_ACTIVE;
        return dget(s->s_root);
    /* ORIGINAL : [aditi]
	return mount_nodev(fs_type, flags, lower_path_name,
			   amfs_read_super);
    
    */
}



static struct file_system_type amfs_fs_type = {
        .owner          = THIS_MODULE,
        .name           = AMFS_NAME,
        .mount          = amfs_mount,
        .kill_sb        = generic_shutdown_super,
        .fs_flags       = 0,
};
MODULE_ALIAS_FS(AMFS_NAME);

static int __init init_amfs_fs(void)
{
        int err;

        pr_info("Registering wrapfs " AMFS_VERSION "\n");

        err = amfs_init_inode_cache();
        if (err)
                goto out;
        err = amfs_init_dentry_cache();
        if (err)
                goto out;
        err = register_filesystem(&amfs_fs_type);
out:
        if (err) {
                amfs_destroy_inode_cache();
                amfs_destroy_dentry_cache();
        }
        return err;
}

static void __exit exit_amfs_fs(void)
{
        amfs_destroy_inode_cache();
        amfs_destroy_dentry_cache();
        unregister_filesystem(&amfs_fs_type);
        pr_info("Completed amfs module unload\n");
}

MODULE_AUTHOR("Erez Zadok, Filesystems and Storage Lab, Stony Brook University"
              " (http://www.fsl.cs.sunysb.edu/)");
MODULE_DESCRIPTION("amfs " AMFS_VERSION
                   " (http://wrapfs.filesystems.org/)");
MODULE_LICENSE("GPL");
module_init(init_amfs_fs);
module_exit(exit_amfs_fs);
     