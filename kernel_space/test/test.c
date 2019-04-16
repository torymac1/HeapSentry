#include <linux/unistd.h>
#include <syscall.h>
#include <sys/types.h>
#include <stdio.h>


int canary = 777;

void t1(int *c){
	printf("%d\n",*c);
}

int canary_test()
{
	int r = -2;
	
	// size_t *v = (size_t *) addr_canary;
	// printf("%d\n",v[0]);
	t1(&canary);
	// syscall(360, &canary);
	// __asm__ __volatile__("int $0x80":"=a"(r):"a"(360),"b"((int) &canary): "memory");
	// printf("%d\n",r);
	return r;
}

int main(void)
{
    int p = -1;
    // pid = syscall(360);
    p = canary_test();
    // printf("%d\n",pid);
    return p;
}

