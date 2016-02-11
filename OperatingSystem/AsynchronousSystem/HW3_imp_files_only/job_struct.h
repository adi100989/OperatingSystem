#define __NR_submitjob 359 

#define MAX_FILENAME 256
#define MAX_JOB_CNT 8

#define JTYPE_CONCAT 1
#define JTYPE_CONPRESS 2
#define JTYPE_DECOMPRESS 3
#define JTYPE_CHECKSUM 4
#define JTYPE_ENCRYPT 5
#define JTYPE_DECRYPT 6
#define JTYPE_CANCEL 7
#define JTYPE_CHANGE 8
#define JTYPE_LIST 9

typedef struct job_args {
	int job_type;
	int no_of_files;        
	unsigned long job_id;
	char **files;
	int priority;	      
	int pid;	
} job_struct;
