#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <string.h>
#include <errno.h>
#include <sys/mount.h>

void fork_test()
{
	char *p1 = malloc(10);
	strcpy(p1,"overflowtesting");
	// strcpy(p1,"over");
	fork();
	printf("Forking in the heap overflow\n"); 
	free(p1);
}

int main()
{
	syscall(360);
	printf("High-Risk Call Fork Testing\n");
	fork_test();
	return 0;
}