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
// #include <sys/types.h>

// #include<asm/system.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("maK");

#define SYSCALL_TABLE_TEMPLATE
// #define __NR_hello 360

struct object
{
    int id;
    char name[16];

    struct hlist_node node;
};

struct pid_canary_hlist{

};

struct canary_hlist{
	int canary_val;
	size_t block_addr;   //key
	size_t block_size;

	struct hlist_node node;
};

unsigned long *sys_call_table = (unsigned long *) SYSCALL_TABLE;

asmlinkage int (*original_write)(unsigned int, const char __user *, size_t);
asmlinkage int (*original_open)(const char *pathname, int flags);


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
asmlinkage int sys_hello(void){
	printk(KERN_EMERG "i am hack syscall!\n");
    return 0;
}

asmlinkage int sys_canary(size_t canary){
	// size_t c = *(size_t *)addr_canary;
	// printk(KERN_EMERG "canary_addr = %p\n", (size_t) addr_canary);
	// size_t v = *(size_t *) addr_canary;
	if(access_ok(VERIFY_READ, (size_t *) canary, sizeof(size_t))){
		int x;
		printk(KERN_EMERG "Access ok");
		get_user(x, (size_t *) canary);
		printk(KERN_EMERG "Access ok, %d\n", x);
	}
	else{
		printk(KERN_EMERG "Can't access");
	}
	// printk(KERN_EMERG "canary = %d\n", *canary);
	return 1;
}

asmlinkage int accept_canary(int canary_val, int block_addr, int block_size){
	DEFINE_HASHTABLE(htable, 3);
	struct canary_hlist c = {
		.canary_val = tmp1,
		.block_addr = tmp2,
		.block_size = tmp3,
	};
	hash_add(htable, &c.node, c.block_addr);

	printk(KERN_EMERG "Canary addr = %d, val = %x\n", c.canary_val, c.block_addr);
	return 0;
}


asmlinkage int remove_canary(size_t block_addr){
	struct canary_hlist* obj;
	hash_for_each_possible(htable, obj, node, block_addr) {
	        if(obj->block_addr == block_addr) {
	            printk(KERN_EMERG "Remove Canary addr = %d, val = %x\n", obj->canary_val, obj->block_addr);
	            
	        }
	    }
	return 0;
}


static int init_mod(void){
	printk(KERN_EMERG "Syscall Table Address: %x\n", SYSCALL_TABLE);
	
	//Changing control bit to allow write	
	write_cr0 (read_cr0 () & (~ 0x10000));
	// orig_saved = (unsigned long *)(sys_call_table[__NR_hello]);
	sys_call_table[360] = (unsigned long *) sys_canary;
	sys_call_table[361] = (unsigned long *) accept_canary;
	// sys_call_table[362] = (unsigned long *) test_hash;
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
	write_cr0 (read_cr0 () | 0x10000);
	printk(KERN_EMERG "Module exited cleanly");
	return;
}

module_init(init_mod);
module_exit(exit_mod);
