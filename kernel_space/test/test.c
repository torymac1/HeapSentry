#include <linux/unistd.h>
#include <syscall.h>
#include <sys/types.h>
#include <stdio.h>
// #include "../"
// #include <linux/types.h>


int canary = 777;

// void t1(int *c){
// 	printf("%d\n",*c);
// }

// int canary_test()
// {
// 	int ret = -2;
	
// 	// size_t *v = (size_t *) addr_canary;
// 	// printf("%d\n",v[0]);
// 	// t1(&canary);
// 	printf("%x\n",(size_t) &canary);
// 	syscall(360, (size_t) &canary);
// 	// __asm__ __volatile__("int $0x80":"=a"(ret):"a"(360),"b"((int) &canary): "memory");
// 	// printf("%d\n",r);
// 	return ret;
// }

int main(void)
{
    int p = -1;
    int a = 1, b = 1;
   	syscall(363, a, b);
   	syscall(363, 2, 2);
   	syscall(363, 3, 3);
   	syscall(364,3);
    syscall(364,3);
    // p = canary_test();
    // printf("%d\n",pid);
    return p;
}

