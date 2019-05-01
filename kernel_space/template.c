/*
 * This is the template file used to build a system
 * specific kernel module.
*/


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
MODULE_AUTHOR("maK");

#define SYSCALL_TABLE_TEMPLATE
#define PID_TABLE_SIZE 10

long testcast_pid=-1;

//A hashtable to store key = pid, val = canary_hlist;
struct pid_canary_hlist{
	long pid;      //key
	int num_of_canary;
	int *buf_cnt;
	int *free_cnt;
	Canary *alloc_buf;
	size_t *free_buf;
	struct hlist_head canary_table[1 << PID_TABLE_SIZE];
	struct hlist_node node;
};


//A hashtable to store key = block_addr, val = canary_val;
struct canary_hlist{
	int canary_val;
	size_t block_addr;   //key
	int block_size;

	struct hlist_node node;
};


unsigned long *sys_call_table = (unsigned long *) SYSCALL_TABLE;

asmlinkage int (*original_write)(unsigned int, const char __user *, size_t);
asmlinkage int (*original_open)(const char *pathname, int flags);
asmlinkage long (*original_getpid) (void);


DEFINE_HASHTABLE(pid_table, 16);

asmlinkage void set_testcase_pid(void){
	testcast_pid = original_getpid();
	printk(KERN_EMERG "[PID = %lu] set_testcase_pid = %lu\n", testcast_pid);
	return;
}


asmlinkage struct pid_canary_hlist *get_pid_table(void){
	long pid = original_getpid();

	//pid already in the pid_table
	struct pid_canary_hlist *obj;
	hash_for_each_possible(pid_table, obj, node, pid){
		if(obj->pid == pid){
			// printk(KERN_EMERG "Find pid = %d\n", obj->pid);
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
	printk(KERN_EMERG "[PID = %lu] Insert new pid.\n", new_obj->pid);
	
	return new_obj;
}


asmlinkage int check_canary(void){
	struct pid_canary_hlist *cur_pid_table = get_pid_table();

	int bkt=0;
	struct canary_hlist *cur_canary = NULL;
	hash_for_each(cur_pid_table->canary_table, bkt, cur_canary, node){
		//check canary
		printk(KERN_EMERG "[PID = %lu] Print Canary val = %d\n",cur_pid_table->pid, cur_canary->canary_val);
	}

	return 0;
}


asmlinkage void accept_alloc_canary_buf_addr(Canary *alloc_buf, int *buf_cnt){
	struct pid_canary_hlist *cur_pid_table = get_pid_table();
	cur_pid_table->alloc_buf = alloc_buf;
	cur_pid_table->buf_cnt = buf_cnt;
	printk(KERN_EMERG "[PID = %lu] [INFO] alloc_buf address is %p\n.", cur_pid_table->pid, \
			                                          cur_pid_table->buf_cnt);
}

asmlinkage void accept_free_canary_buf_addr(size_t *free_buf, int *free_cnt){
	struct pid_canary_hlist *cur_pid_table = get_pid_table();
	cur_pid_table->free_buf = free_buf;
	cur_pid_table->free_cnt = free_cnt;
	printk(KERN_EMERG "[PID = %lu] [INFO] free_buf address is %p\n.", cur_pid_table->pid, \
			                                          cur_pid_table->free_buf);
}

asmlinkage void pull_alloc_canary_buf(void){
	//get current pid
	struct pid_canary_hlist *cur_pid_table = get_pid_table();
	
	if(cur_pid_table->alloc_buf == NULL){
		printk(KERN_EMERG "[PID = %lu] [INFO] User space alloc_buf is NULL.");
		return;
	}

	int buf_cnt;
	get_user(buf_cnt, cur_pid_table->buf_cnt);
	Canary *alloc_buf_kernel = (Canary *)kmalloc(sizeof(struct Canary)*buf_cnt, GFP_KERNEL);
	if(copy_from_user(alloc_buf_kernel, cur_pid_table->alloc_buf, sizeof(struct Canary)*buf_cnt)!=0){
		printk(KERN_EMERG "[PID = %lu] [ERROR] Can't copy from user_space %p to kernel_space %p\n.", cur_pid_table->pid, \
			                               cur_pid_table->alloc_buf, alloc_buf_kernel);
	}
	
	int i;
	for(i=0; i<buf_cnt; i++){
		struct canary_hlist *cur_canary = (struct canary_hlist *) kmalloc(sizeof(struct canary_hlist), GFP_KERNEL);
		cur_canary->canary_val = alloc_buf_kernel[i].canary_val;
		cur_canary->block_addr = alloc_buf_kernel[i].block_addr;
		cur_canary->block_size = alloc_buf_kernel[i].block_size;
		hash_add(cur_pid_table->canary_table, &cur_canary->node, cur_canary->block_addr);
		cur_pid_table->num_of_canary++;
		printk(KERN_EMERG "[PID = %lu] Accept Canary val = %d, addr = %d\n", cur_pid_table->pid, \
			                                alloc_buf_kernel[i].canary_val, alloc_buf_kernel[i].block_addr);
	}
	kfree(alloc_buf_kernel);

	//set user_space buf_cnt to 0;
	put_user(0, cur_pid_table->buf_cnt);
}

asmlinkage int pull_free_canary_buf(void){
	
	struct pid_canary_hlist *cur_pid_table = get_pid_table();
	if(cur_pid_table->free_buf == NULL){
		printk(KERN_EMERG "[PID = %lu] [INFO] User space free_buf is NULL.");
		return;
	}

	int free_cnt;
	get_user(free_cnt, cur_pid_table->free_cnt);
	size_t *free_buf_kernel = (Canary *)kmalloc(sizeof(struct Canary)*free_cnt, GFP_KERNEL);
	if(copy_from_user(free_buf_kernel, cur_pid_table->free_buf, sizeof(size_t)*free_cnt)!=0){
		printk(KERN_EMERG "[PID = %lu] [ERROR] Can't copy from user_space %p to kernel_space %p\n.", cur_pid_table->pid, \
			                                cur_pid_table->free_buf, free_buf_kernel);
	}


	int i;
	for(i=0; i<free_cnt; i++){
		int key = free_buf_kernel[i];
		struct canary_hlist *cur_canary = NULL;
		hash_for_each_possible(cur_pid_table->canary_table, cur_canary, node, key){
			if(cur_canary->block_addr == key){
				cur_pid_table->num_of_canary--;
				printk(KERN_EMERG "[PID = %lu] Remove Canary val = %d, addr = %d\n",cur_pid_table->pid, \
					                         cur_canary->canary_val, cur_canary->block_addr);
	            hash_del(&cur_canary->node);
	            kfree(cur_canary);
			}
		}
	}
	kfree(free_buf_kernel);

	if(i == free_cnt)
		return 0;
	else
		return -1;
}

asmlinkage int new_write(unsigned int fd, const char __user *buf, size_t count){
	printk(KERN_INFO "NEW write to fd = %d/n", fd);	
	//Hijacked write function here
	return (*original_write)(fd, buf, count);
}

asmlinkage int new_open(const char *pathname, int flags) {
    if(original_getpid() == testcast_pid){
    	printk(KERN_EMERG "[PID = %lu] This is a testcase.\n", testcast_pid);
    }
    check_canary();
    return (*original_open)(pathname, flags);
}

static int init_mod(void){
	printk(KERN_EMERG "Syscall Table Address: %x\n", SYSCALL_TABLE);
	
	//Changing control bit to allow write	
	write_cr0 (read_cr0 () & (~ 0x10000));
	sys_call_table[360] = (unsigned long *) set_testcase_pid;
	sys_call_table[361] = (unsigned long *) accept_alloc_canary_buf_addr;
	sys_call_table[362] = (unsigned long *) accept_free_canary_buf_addr;
	sys_call_table[369] = (unsigned long *) pull_alloc_canary_buf;
	sys_call_table[370] = (unsigned long *) pull_free_canary_buf;
	

	original_getpid = sys_call_table[__NR_getpid];

	// original_write = (void *)sys_call_table[__NR_write];
	original_open = (void *)sys_call_table[__NR_open];
	// sys_call_table[__NR_write] = new_write;
	sys_call_table[__NR_open] = new_open;
 //    printk(KERN_EMERG "Write system call old address: %x\n", original_write);
	// printk(KERN_EMERG "Write system call new address: %x\n", new_write);
	// printk(KERN_EMERG "Open system call old address: %x\n", original_open);
	// printk(KERN_EMERG "Open system call new address: %x\n", new_open);

	//Changing control bit back
	write_cr0 (read_cr0 () | 0x10000);
	return 0;
}

static void exit_mod(void){
	//Cleanup
	write_cr0 (read_cr0 () & (~ 0x10000));
	// sys_call_table[__NR_write] = original_write;
	sys_call_table[__NR_open] = original_open;
	sys_call_table[360] = NULL;
	sys_call_table[361] = NULL;
	sys_call_table[362] = NULL;
	sys_call_table[363] = NULL;
	sys_call_table[364] = NULL;
	sys_call_table[368] = NULL;
	sys_call_table[369] = NULL;
	sys_call_table[370] = NULL;
	sys_call_table[__NR_getpid] = original_getpid;

	write_cr0 (read_cr0 () | 0x10000);
	printk(KERN_EMERG "Module exited cleanly");
	return;
}



module_init(init_mod);
module_exit(exit_mod);
