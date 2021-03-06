#include<linux/init.h>
#include<linux/module.h>
#include<linux/kernel.h>
#include<linux/errno.h>
#include<linux/types.h>
#include<linux/unistd.h>
#include<asm/current.h>
#include<linux/sched.h>
#include<linux/syscalls.h>
#include "../heapsentry.h"
#include <linux/types.h>
#include <linux/list.h>
#include <linux/hashtable.h>
#include <linux/slab.h>


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Team RuntimeError");


///system call table at usr/include/i386-linux-gnu/asm/unistd_32.h
#define SYSCALL_TABLE 0xc17901c0
#define PID_TABLE_SIZE 10

//flag for test case
long testcast_pid=-1;

//A hashtable to store pid and corresponding canaries (first level)
DEFINE_HASHTABLE(pid_table, 16);

//A hashtable to manage pid, key = pid
struct pid_canary_hlist{
	long pid;      //key
	int num_of_canary;
	int *buf_cnt;
	int *free_cnt;
	int *need_free;
	Canary *alloc_buf;
	size_t *free_buf;

	struct hlist_head canary_table[1 << PID_TABLE_SIZE];
	struct hlist_node node;
};


//A hashtable to manage canaries, key = block_addr (second level)
struct canary_hlist{
	int canary_val;
	size_t block_addr;   //key
	int block_size;

	struct hlist_node node;
};

//Access system call table via address
unsigned long *sys_call_table = (unsigned long *) SYSCALL_TABLE;

//High risk system calls 
asmlinkage int (*original_open)(const char *pathname, int flags);
asmlinkage int (*original_execve)(const char *filename, char *const argv[], char *const envp[]);
asmlinkage int (*original_chmod)(const char *pathname, mode_t mode);
asmlinkage int (*original_fchmod) (int fd, mode_t mode);
asmlinkage pid_t (*original_fork) (void);
asmlinkage pid_t (*original_vfork) (void);
asmlinkage long (*original_clone)(unsigned long flags, void *child_stack,void *ptid, \
	                           void *ctid, struct pt_regs *regs);
asmlinkage pid_t (*original_getpid) (void);
asmlinkage void (*original_exit_group) (int status);

asmlinkage void new_exit_group(int status);


/*This function is a system call for running test case. In test case, we first call this syscall,
then the kernel will set testcast_pid to current pid.*/
asmlinkage void set_testcase_pid(void){
	testcast_pid = original_getpid();
	printk(KERN_EMERG "[PID = %lu] [INFO] Set_testcase_pid = %lu\n", testcast_pid, testcast_pid);
	return;
}

/*This function is to find struct pid_canary_hlist for current process. If current pid is in
kernel hash table, it will return the address. Else it will kmalloc space and insert it into 
pid_table.*/
asmlinkage struct pid_canary_hlist *get_pid_table(void){
	long pid = original_getpid();

	//pid already in the pid_table
	struct pid_canary_hlist *obj;
	hash_for_each_possible(pid_table, obj, node, pid){
		if(obj->pid == pid){
			return obj;
		}
	}

	//insert new pid pid into the pid_table
	struct pid_canary_hlist *new_obj =  (struct pid_canary_hlist*) kmalloc(sizeof(struct pid_canary_hlist), GFP_KERNEL);
	int size = 1<<PID_TABLE_SIZE;
	int i;
	for(i=0; i < size; i++){
		new_obj->canary_table[i].first = NULL;
	}
	new_obj->pid = pid;
	new_obj->num_of_canary = 0;
	new_obj->buf_cnt = NULL;
	new_obj->free_cnt = NULL;
	new_obj->alloc_buf = NULL;
	new_obj->free_buf = NULL;
	hash_add(pid_table, &new_obj->node, new_obj->pid);
	printk(KERN_EMERG "[PID = %lu] [INFO] New process detected, insert to hash table.\n", new_obj->pid);
	
	return new_obj;
}

/*This function is a system call. It will get address of alloc_buf and buf_cnt, which are 
in user_space*/
asmlinkage void accept_alloc_canary_buf_addr(Canary *alloc_buf, int *buf_cnt){
	struct pid_canary_hlist *cur_pid_table = get_pid_table();
	cur_pid_table->alloc_buf = alloc_buf;
	cur_pid_table->buf_cnt = buf_cnt;
	printk(KERN_EMERG "[PID = %lu] [INFO] alloc_buf address is %p\n", cur_pid_table->pid, \
			                                          cur_pid_table->buf_cnt);
}

/*This function is a system call. It will get address of free_buf and free_cnt, which are 
in user_space.*/
asmlinkage void accept_free_canary_buf_addr(size_t *free_buf, int *free_cnt, int *need_free){
	struct pid_canary_hlist *cur_pid_table = get_pid_table();
	cur_pid_table->free_buf = free_buf;
	cur_pid_table->free_cnt = free_cnt;
	cur_pid_table->need_free = need_free;
	printk(KERN_EMERG "[PID = %lu] [INFO] free_buf address is %p\n", cur_pid_table->pid, \
			                                          cur_pid_table->free_buf);
}

/*This function is a system call. It will pull the pending alloc_buf from user space and check all
canaries. If there is a wrong canary, the process will exit.*/
asmlinkage int pull_and_check_alloc_canary_buf(void){
	//get current pid
	struct pid_canary_hlist *cur_pid_table = get_pid_table();

	//pull alloc_buf
	if(cur_pid_table->alloc_buf == NULL){
		printk(KERN_EMERG "[PID = %lu] [INFO] User space alloc_buf is NULL.", cur_pid_table->pid);
		return 0;
	}

	int buf_cnt;
	get_user(buf_cnt, cur_pid_table->buf_cnt);
	Canary *alloc_buf_kernel = (Canary *)kmalloc(sizeof(struct Canary)*buf_cnt, GFP_KERNEL);
	if(copy_from_user(alloc_buf_kernel, cur_pid_table->alloc_buf, sizeof(struct Canary)*buf_cnt)!=0){
		printk(KERN_EMERG "[PID = %lu] [ERROR] Can't copy from user_space %p to kernel_space %p\n.", cur_pid_table->pid, \
			                               cur_pid_table->alloc_buf, alloc_buf_kernel);
		return 0;
	}
	
	int i;
	for(i=0; i<buf_cnt; i++){
		struct canary_hlist *cur_canary = (struct canary_hlist *) kmalloc(sizeof(struct canary_hlist), GFP_KERNEL);
		cur_canary->canary_val = alloc_buf_kernel[i].canary_val;
		cur_canary->block_addr = alloc_buf_kernel[i].block_addr;
		cur_canary->block_size = alloc_buf_kernel[i].block_size;
		hash_add(cur_pid_table->canary_table, &cur_canary->node, cur_canary->block_addr);
		cur_pid_table->num_of_canary++;
		printk(KERN_EMERG "[PID = %lu] [INFO] Accept Canary val = %d, addr = %p\n", cur_pid_table->pid, \
			                                alloc_buf_kernel[i].canary_val, (void *)alloc_buf_kernel[i].block_addr);
	}
	kfree(alloc_buf_kernel);

	//check all canary values
	int bkt=0;
	struct canary_hlist *cur_canary = NULL;
	hash_for_each(cur_pid_table->canary_table, bkt, cur_canary, node){
		//check canary
		int user_space_canary_val;
		size_t *canary_addr = (size_t *)(cur_canary->block_addr + cur_canary->block_size - sizeof(int));
		get_user(user_space_canary_val, canary_addr);
		if(user_space_canary_val != cur_canary->canary_val){
			printk(KERN_EMERG "[PID = %lu] [ERROR] Wrong Canary at addr = %p\n",cur_pid_table->pid, \
			                                              (size_t *)cur_canary->block_addr);
			new_exit_group(7);
			// return -1;
		}
	}

	//set user_space buf_cnt to 0;
	put_user(0, cur_pid_table->buf_cnt);
	return 0;
}

/*This function is a system call. It will pull the pending free_buf from user space and check all
canaries. If there is a wrong canary, the process will exit.*/
asmlinkage int pull_and_check_free_canary_buf(void){
	
	struct pid_canary_hlist *cur_pid_table = get_pid_table();
	if(cur_pid_table->free_buf == NULL){
		printk(KERN_EMERG "[PID = %lu] [INFO] User space free_buf is NULL.", cur_pid_table->pid);
		return 0;
	}

	int free_cnt;
	get_user(free_cnt, cur_pid_table->free_cnt);
	size_t *free_buf_kernel = (Canary *)kmalloc(sizeof(struct Canary)*free_cnt, GFP_KERNEL);
	if(copy_from_user(free_buf_kernel, cur_pid_table->free_buf, sizeof(size_t)*free_cnt)!=0){
		printk(KERN_EMERG "[PID = %lu] [ERROR] Can't copy from user_space %p to kernel_space %p\n.", cur_pid_table->pid, \
			                                cur_pid_table->free_buf, free_buf_kernel);
		return 0;
	}

	int i;
	for(i=0; i<free_cnt; i++){
		//verify canaries
		struct canary_hlist *cur_canary = NULL;
		int key = free_buf_kernel[i];
		hash_for_each_possible(cur_pid_table->canary_table, cur_canary, node, key){
			if(cur_canary->block_addr == key){
				int user_space_canary_val;
				size_t *canary_addr = (size_t *)(cur_canary->block_addr + cur_canary->block_size - sizeof(int));
				get_user(user_space_canary_val, canary_addr);
				if(user_space_canary_val != cur_canary->canary_val){
					printk(KERN_EMERG "[PID = %lu] [ERROR] Wrong Canary at addr = %p\n",cur_pid_table->pid, \
					                                              (size_t *)cur_canary->block_addr);
					new_exit_group(7);
					// return -1;
				}
	            
            	cur_pid_table->num_of_canary--;
				printk(KERN_EMERG "[PID = %lu] [INFO] Remove Canary val = %d, addr = %p\n",cur_pid_table->pid, \
				                         cur_canary->canary_val, (void *) cur_canary->block_addr);
	            hash_del(&cur_canary->node);
	            kfree(cur_canary);  
			}
		}
	}
	kfree(free_buf_kernel);

	//Inform user space to free free_buf
	put_user(1, cur_pid_table->need_free);
	return 0;
}

/*This function is to release the pid_table's space in kernel.*/
asmlinkage void free_pid_table(void){

	struct pid_canary_hlist *cur_pid_table = get_pid_table();
	printk(KERN_EMERG "[PID = %lu] [INFO] Start to free process hash table.\n", cur_pid_table->pid);
	int bkt=0;
	struct canary_hlist *cur_canary = NULL;
	hash_for_each(cur_pid_table->canary_table, bkt, cur_canary, node){
		printk(KERN_EMERG "[PID = %lu] [INFO] Free canary val = %d, addr = %p\n",cur_pid_table->pid, \
			                         cur_canary->canary_val, (void *)cur_canary->block_addr);
        hash_del(&cur_canary->node);
        kfree(cur_canary);
	}

	hash_del(&cur_pid_table->node);
	kfree(cur_pid_table);
}


/*Re-implement exit_group()*/
asmlinkage void new_exit_group(int status){
	printk(KERN_EMERG "[PID = %lu] [INFO] exit_group() detected, will free process hash table.\n", original_getpid());
	free_pid_table();
	if(status == 7){
		printk(KERN_EMERG "[PID = %lu] [INFO] Process EXIT due to WRONG canary!\n", original_getpid());
	}
	else{
		printk(KERN_EMERG "[PID = %lu] [INFO] Process EXIT!\n", original_getpid());
	}
	return (*original_exit_group)(status);
}

/*Re-implement open()*/
asmlinkage int new_open(const char *pathname, int flags) {
    if(original_getpid() == testcast_pid){
    	printk(KERN_EMERG "[PID = %lu] [INFO] High-risk open() detected in testcase.\n", testcast_pid);
    	pull_and_check_free_canary_buf();
    	pull_and_check_alloc_canary_buf();

    }
    return (*original_open)(pathname, flags);
    	
}

/*Re-implement execve()*/
asmlinkage int new_execve(const char *filename, char *const argv[], char *const envp[]){
	if(original_getpid() == testcast_pid){
    	printk(KERN_EMERG "[PID = %lu] [INFO] High-risk execve() detected in testcase.\n", testcast_pid);
    	pull_and_check_free_canary_buf();
    	pull_and_check_alloc_canary_buf();
    	free_pid_table();
    }
    return (*original_execve)(filename, argv, envp);
}

/*Re-implement chmod()*/
asmlinkage int new_chmod(const char *pathname, mode_t mode){
	if(original_getpid() == testcast_pid){
    	printk(KERN_EMERG "[PID = %lu] [INFO] High-risk chmod() detected in testcase.\n", testcast_pid);
    	pull_and_check_free_canary_buf();
    	pull_and_check_alloc_canary_buf();

    }
    return (*original_chmod)(pathname, mode);
}

/*Re-implement fchmod()*/
asmlinkage int new_fchmod(int fd, mode_t mode){
	if(original_getpid() == testcast_pid){
    	printk(KERN_EMERG "[PID = %lu] [INFO] High-risk fchmod() detected in testcase.\n", testcast_pid);
    	pull_and_check_free_canary_buf();
    	pull_and_check_alloc_canary_buf();

    }
    return (*original_fchmod)(fd, mode);
}

/*Re-implement fork()*/
asmlinkage pid_t new_fork(void){
	if(original_getpid() == testcast_pid){
    	printk(KERN_EMERG "[PID = %lu] [INFO] High-risk fork() detected in testcase.\n", testcast_pid);
    	pull_and_check_free_canary_buf();
    	pull_and_check_alloc_canary_buf();
    }
    return (*original_fork)();
}

/*Re-implement vfork()*/
asmlinkage pid_t new_vfork(void){
	if(original_getpid() == testcast_pid){
    	printk(KERN_EMERG "[PID = %lu] [INFO] High-risk vfork() detected in testcase.\n", testcast_pid);
    	pull_and_check_free_canary_buf();
    	pull_and_check_alloc_canary_buf();
    }
    return (*original_vfork)();
}
/*Re-implement clone()*/
asmlinkage long new_clone(unsigned long flags, void *child_stack, void *ptid, void *ctid, struct pt_regs *regs){
	if(original_getpid() == testcast_pid){
		printk(KERN_EMERG "[PID = %lu] [INFO] High-risk clone() detected in testcase.\n", testcast_pid);
    	pull_and_check_free_canary_buf();
    	pull_and_check_alloc_canary_buf();   
    }
    
    return (*original_clone)(flags, child_stack, ptid, ctid, regs);
}

/*This function is to initialize the HeapSentry module. It will add our customized system calls 
to sys_call_table, and hijack all original high-risk system calls.*/
static int init_mod(void){
	printk(KERN_EMERG "[INFO] Module iniliazed, syscall table address: %x\n", SYSCALL_TABLE);
	
	//Changing control bit to allow write	
	write_cr0 (read_cr0 () & (~ 0x10000));

	//System call for HeapSentry
	sys_call_table[360] = (unsigned long *) set_testcase_pid;
	sys_call_table[361] = (unsigned long *) accept_alloc_canary_buf_addr;
	sys_call_table[362] = (unsigned long *) accept_free_canary_buf_addr;
	sys_call_table[369] = (unsigned long *) pull_and_check_alloc_canary_buf;
	sys_call_table[370] = (unsigned long *) pull_and_check_free_canary_buf;
	

	original_getpid = (void *)sys_call_table[__NR_getpid];
	original_exit_group = (void *)sys_call_table[__NR_exit_group];	
	original_open = (void *)sys_call_table[__NR_open];
	original_fork = (void *)sys_call_table[__NR_fork];
	original_vfork = (void *)sys_call_table[__NR_vfork];
	original_clone = (void *)sys_call_table[__NR_clone];
	original_chmod = (void *)sys_call_table[__NR_chmod];
	original_fchmod = (void *)sys_call_table[__NR_fchmod];
	original_execve = (void *)sys_call_table[__NR_execve];
	

	sys_call_table[__NR_exit_group] = new_exit_group;
	sys_call_table[__NR_open] = new_open;
	sys_call_table[__NR_fork] = new_fork;
	sys_call_table[__NR_vfork] = new_vfork;
	sys_call_table[__NR_clone] = new_clone;
	sys_call_table[__NR_chmod] = new_chmod;
	sys_call_table[__NR_fchmod] = new_fchmod;
	sys_call_table[__NR_execve] = new_execve;
	
	//Changing control bit back
	write_cr0 (read_cr0 () | 0x10000);
	return 0;
}
/*This function is to recove system call table and set all system calls to orginal system calls.*/
static void exit_mod(void){
	//Cleanup
	write_cr0 (read_cr0 () & (~ 0x10000));

	sys_call_table[360] = NULL;
	sys_call_table[361] = NULL;
	sys_call_table[362] = NULL;
	sys_call_table[369] = NULL;
	sys_call_table[370] = NULL;
	sys_call_table[__NR_getpid] = original_getpid;

	sys_call_table[__NR_exit_group] = original_exit_group;
	sys_call_table[__NR_open] = original_open;
	sys_call_table[__NR_fork] = original_fork;
	sys_call_table[__NR_vfork] = original_vfork;
	sys_call_table[__NR_clone] = original_clone;
	sys_call_table[__NR_fchmod] = original_fchmod;
	sys_call_table[__NR_chmod] = original_chmod;
	sys_call_table[__NR_execve] = original_execve;
	

	write_cr0 (read_cr0 () | 0x10000);

	printk(KERN_EMERG "[INFO] Module exited, syscall table address: %x\n", SYSCALL_TABLE);
	return;
}



module_init(init_mod);
module_exit(exit_mod);
