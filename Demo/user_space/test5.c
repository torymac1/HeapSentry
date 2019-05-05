#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <string.h>
#include <errno.h>
#include <sys/mount.h>

int execve_test()
{
    char *p1 = malloc(10);
    strcpy(p1,"overflowtesting");
    char * argv[ ]={"./test","test_sample",(char *)0};
    char * envp[ ]={0};
    execve("./test",argv,envp);
    printf("execve test successfully\n");
    free(p1);
    return 1;
}
 
int main()
{
	syscall(360);
	printf("High Risk Function Execve Testing\n");
	execve_test(); 
	return 0;
}