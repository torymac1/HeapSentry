#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <string.h>
#include <errno.h>
#include <sys/mount.h>


void overflow()
{
	char *p1 = malloc(10);
	char *p2 = malloc(6);
	char *p3 = malloc(8);
	strcpy(p2,"123456789");
	free(p1);
	free(p2);
	free(p3);
}


int main()
{
	syscall(360);
	printf("Overflow Testing\n");
	overflow();
	return 0;
}