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
// #include <sys/types.h>

// #include<asm/system.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("maK");

#define SYSCALL_TABLE_TEMPLATE
#define PID_TABLE_SIZE 10

//A hashtable to store key = pid, val = canary_hlist;
struct pid_canary_hlist{
	long pid;
	int num_of_canary;
	// struct hlist_head (*canary_hlist_head)[1 << PID_TABLE_SIZE];
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


// DEFINE_HASHTABLE(htable, 10);
DEFINE_HASHTABLE(htable, 16);
DEFINE_HASHTABLE(pid_table, 16);


asmlinkage int new_write(unsigned int fd, const char __user *buf, size_t count){
	printk(KERN_INFO "NEW write to fd = %d/n", fd);	
	//Hijacked write function here
	return (*original_write)(fd, buf, count);
}
asmlinkage int new_open(const char *pathname, int flags) {
	// printk(KERN_EMERG "1111111111111111 %s\n", *pathname);
    // hijacked open
    return (*original_open)(pathname, flags);
}


asmlinkage int sys_canary(size_t canary){
	if(access_ok(VERIFY_READ, (size_t *) canary, sizeof(size_t))){
		int x;
		printk(KERN_EMERG "Access ok");
		get_user(x, (size_t *) canary);
		printk(KERN_EMERG "Access ok, %d\n", x);
	}
	else{
		printk(KERN_EMERG "Can't access");
	}
	return 1;
}

asmlinkage struct pid_canary_hlist *get_pid_table(void){
	long pid = original_getpid();

	//pid already in the pid_table
	struct pid_canary_hlist *obj;
	hash_for_each_possible(pid_table, obj, node, pid){
		if(obj->pid == pid){
			printk(KERN_EMERG "Find pid = %d\n", obj->pid);
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
	hash_add(pid_table, &new_obj->node, new_obj->pid);
	printk(KERN_EMERG "Add pid = %d\n", new_obj->pid);
	
	return new_obj;
}

asmlinkage int accept_canary(int canary_val, size_t block_addr, int block_size){
	//get or create pid_canary_hlist for cur_pid, return address
	struct pid_canary_hlist *cur_pid_table = get_pid_table();
	printk(KERN_EMERG "[pid = %d]\n", cur_pid_table->pid);
	//insert cur_canary into cur_pid table
	struct canary_hlist *cur_canary = (struct canary_hlist *) kmalloc(sizeof(struct canary_hlist), GFP_KERNEL);
	cur_canary->canary_val = canary_val;
	cur_canary->block_addr = block_addr;
	cur_canary->block_size = block_size;
	// printk(KERN_EMERG "canary_hlist_head = %p\n", cur_pid_table->canary_table);
	hash_add(cur_pid_table->canary_table, &cur_canary->node, cur_canary->block_addr);

	printk(KERN_EMERG "[pid = %d] Add canary val = %d, addr = %p\n", cur_pid_table->pid, cur_canary->canary_val \
		                                              , (void *)cur_canary->block_addr);
	return 1;
}


asmlinkage int remove_canary(size_t block_addr){
	struct pid_canary_hlist *cur_pid_table = get_pid_table();

	bool flag = false;
	size_t key = block_addr;
	struct canary_hlist* obj;
	hash_for_each_possible(cur_pid_table->canary_table, obj, node, key) {
        if(obj->block_addr == key) {
            printk(KERN_EMERG "[pid = %d] Remove Canary val = %d, addr = %p\n", cur_pid_table->pid, obj->canary_val, \
            	                                         (void *)obj->block_addr);
            hash_del(&obj->node);
            kfree(obj);
            flag = true;
        }
    }
    if(!flag)
    	return -1; //Can't free
	return 0;
}



asmlinkage struct pid_canary_hlist *test_add_pid_hlist(void){
	struct pid_canary_hlist *obj =  (struct pid_canary_hlist*) kmalloc(sizeof(struct pid_canary_hlist), GFP_KERNEL);
	obj->pid = 1;
	obj->num_of_canary = 0;
	// obj->canary_hlist_head = tmp;
	int i=0;
	int size = 1<<PID_TABLE_SIZE;
	for(i=0; i < size; i++){
		obj->canary_table[i].first = NULL;
	}
	hash_add(pid_table, &obj->node, obj->pid);
	printk(KERN_EMERG "Add pid = %d\n", obj->pid);

	struct canary_hlist *c1 = (struct canary_hlist *) kmalloc(sizeof(struct canary_hlist), GFP_KERNEL);
	c1->canary_val = 6;
	c1->block_addr = 6;
	c1->block_size = 6;
	hash_add(obj->canary_table, &c1->node, c1->block_addr);
	printk(KERN_EMERG "Add c = %d\n", c1->canary_val);

	struct canary_hlist *c2 = (struct canary_hlist *) kmalloc(sizeof(struct canary_hlist), GFP_KERNEL);
	c2->canary_val = 7;
	c2->block_addr = 7;
	c2->block_size = 7;
	hash_add(obj->canary_table, &c2->node, c2->block_addr);
	printk(KERN_EMERG "Add c = %d\n", c2->canary_val);
	int key = 7;
	struct canary_hlist* c_obj;
	hash_for_each_possible(obj->canary_table, c_obj, node, key) {
        if(c_obj->block_addr == key) {
            printk(KERN_EMERG "Remove Canary val = %d, addr = %d\n", c_obj->canary_val, c_obj->block_addr);
            // hash_del(&obj->node);
            // kfree(obj);
            // flag = true;
        }
    }

    return obj;

}

asmlinkage void test_pid_hlist(void){
	int key = 7;
	printk(KERN_EMERG "Try to find key = %d\n", key);
	struct pid_canary_hlist *obj = test_add_pid_hlist();
	printk(KERN_EMERG "Hash size = %d\n", HASH_SIZE(obj->canary_table));
	struct canary_hlist *c_obj = NULL;
	hash_for_each_possible(obj->canary_table, c_obj, node, key) {

        printk(KERN_EMERG "Find Canary addr = %d\n", c_obj->block_addr);
    }
}

asmlinkage void accept_canary_buf(Canary *alloc_buf, int buf_cnt){
	
	struct pid_canary_hlist *cur_pid_table = get_pid_table();

	Canary *alloc_buf_kernel = (Canary *)kmalloc(sizeof(struct Canary)*buf_cnt, GFP_KERNEL);
	if(copy_from_user(alloc_buf_kernel, alloc_buf, sizeof(struct Canary)*buf_cnt)!=0){
		printk(KERN_EMERG "[ERROR] Can't copy from user_space %p to kernel_space %p\n.", alloc_buf, alloc_buf_kernel);
	}
	
	int i;
	for(i=0; i<buf_cnt; i++){
		struct canary_hlist *cur_canary = (struct canary_hlist *) kmalloc(sizeof(struct canary_hlist), GFP_KERNEL);
		cur_canary->canary_val = alloc_buf_kernel[i].canary_val;
		cur_canary->block_addr = alloc_buf_kernel[i].block_addr;
		cur_canary->block_size = alloc_buf_kernel[i].block_size;
		hash_add(cur_pid_table->canary_table, &cur_canary->node, cur_canary->block_addr);
		printk(KERN_EMERG "Accept Canary val = %d, addr = %d\n", alloc_buf_kernel[i].canary_val, \
			                        alloc_buf_kernel[i].block_addr);
	}
	kfree(alloc_buf_kernel);
}

asmlinkage void free_canary_buf(size_t *free_buf, int free_cnt){

	struct pid_canary_hlist *cur_pid_table = get_pid_table();

	size_t *free_buf_kernel = (Canary *)kmalloc(sizeof(struct Canary)*free_cnt, GFP_KERNEL);
	if(copy_from_user(free_buf_kernel, free_buf, sizeof(size_t)*free_cnt)!=0){
		printk(KERN_EMERG "[ERROR] Can't copy from user_space %p to kernel_space %p\n.", free_buf, free_buf_kernel);
	}


	int i;
	for(i=0; i<free_cnt; i++){
		int key = free_buf_kernel[i];
		struct canary_hlist *cur_canary = NULL;
		hash_for_each_possible(cur_pid_table->canary_table, cur_canary, node, key){
			if(cur_canary->block_addr == key){
				printk(KERN_EMERG "Remove Canary val = %d, addr = %d\n", cur_canary->canary_val, cur_canary->block_addr);
	            hash_del(&cur_canary->node);
	            kfree(cur_canary);
			}
		}
	}
	kfree(free_buf_kernel);
}

static int init_mod(void){
	printk(KERN_EMERG "Syscall Table Address: %x\n", SYSCALL_TABLE);
	
	//Changing control bit to allow write	
	write_cr0 (read_cr0 () & (~ 0x10000));
	// orig_saved = (unsigned long *)(sys_call_table[__NR_hello]);
	// sys_call_table[360] = (unsigned long *) sys_canary;
	sys_call_table[361] = (unsigned long *) accept_canary;
	sys_call_table[362] = (unsigned long *) remove_canary;
	sys_call_table[368] = (unsigned long *) test_pid_hlist;
	sys_call_table[369] = (unsigned long *) accept_canary_buf;
	sys_call_table[370] = (unsigned long *) free_canary_buf;
	// sys_call_table[364] = (unsigned long *) get_pid_table;
	original_getpid = sys_call_table[__NR_getpid];

	// original_write = (void *)sys_call_table[__NR_write];
	// original_open = (void *)sys_call_table[__NR_open];
	// sys_call_table[__NR_write] = new_write;
	// sys_call_table[__NR_open] = new_open;
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
	// sys_call_table[__NR_open] = original_open;
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
