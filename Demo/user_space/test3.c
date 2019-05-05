#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <string.h>
#include <errno.h>
#include <sys/mount.h>


void chmod_test()
{
	char *p1 = malloc(10);
	strcpy(p1,"overflowtesting");
	const char *path;
  	path = "test.c";
	chmod(path, S_IRUSR|S_IRGRP|S_IROTH); 
	// chmod(path, S_IRUSR|S_IRGRP|S_IROTH|S_IWUSR|S_IWGRP|S_IWOTH);
	free(p1);
}



int main()
{
	syscall(360);
	printf("High-Risk Call \"Chmod\" Testing\n");
	chmod_test();
	return 0;
}


