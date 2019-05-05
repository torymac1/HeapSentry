#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <string.h>
#include <errno.h>
#include <sys/mount.h>


void performance(int n)
{
	clock_t start,end;
	double cpu_time_used;
	start = clock();
	char* p[n];
	int i;
	for(i=0;i<n;i++){
	  p[i]=(char*)malloc(sizeof(char)*5);
	}
	
	for(i=0;i<n;i++)
		free(p[i]);
	end = clock();
	cpu_time_used = ((double)(end -start))/CLOCKS_PER_SEC;
	printf("Run time is %f\n", cpu_time_used); 
}

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

int o_open_write()
{
	char *p1 = malloc(10);
	strcpy(p1,"overflowtesting");
	int filedesc = open("testfile.txt", O_RDWR | O_APPEND | O_CREAT);
 
    if (filedesc < 0) {
        return -1;
    }
 
    if (write(filedesc, "This will be output to testfile.txt\n", 36) != 36) {
        write(2, "There was an error writing to testfile.txt\n", 43);
        return -1;
    }
    free(p1);
}

void fork_test()
{
	char *p1 = malloc(10);
	// strcpy(p1,"overflowtesting");
	strcpy(p1,"ove");
	fork();
	printf("Forking in the heap overflow\n"); 
	free(p1);
}

void chmod_test()
{
	char *p1 = malloc(10);
	strcpy(p1,"overflowtesting");
	const char *path;
  	path = "test.c";
	chmod(path, S_IRUSR|S_IRGRP|S_IROTH);
	free(p1);
}

int execve_test()
{
	char *p1 = malloc(10);
	strcpy(p1,"overflowtesting");
	printf("execve test starts\n");
	char * argv[ ]={"./test","test_sample",(char *)0};
    char * envp[ ]={0};
    execve("./test",argv,envp);
    free(p1);
 	return 1;
}

//https://www.linuxquestions.org/questions/programming-9/how-to-use-mount-function-from-c-920210/
int mount_test()
{
	char *p1 = malloc(10);
	strcpy(p1,"overflowtesting");
	const char* src  = "none";
	const char* trgt = "/var/tmp";
	const char* type = "tmpfs";
	const unsigned long mntflags = 0;
	const char* opts = "mode=7777,uid=1000";   /* 65534 is the uid of nobody */
	int result = mount(src, trgt, type, mntflags, opts);
	if (result == 0)
	{
	    printf("Mount created at %s...\n", trgt);
	    printf("Press <return> to unmount the volume: ");
	    getchar();
	    umount(trgt);
	}
	else
	{
	    printf("Error : Failed to mount %s\n"
	           "Reason: %s [%d]\n",
	           src, strerror(errno), errno);
	    return -1;
	}
	free(p1);
	return 0;
}

int main(){

	printf("Please input the number of allocation commands:\n");
    int c;
    scanf("%d", &c);
	printf("c is %d\n", c);
	syscall(360);

	//performance test 
	performance(c);

	//overflow with free

	// overflow();
	// overflow();

	//overflow test with open, write test
	
	// o_open_write();

    //fork

    // fork_test();

    //chmod

    // chmod_test();

    //execve

    // execve_test();

    //mount
    // mount_test();

	return 0;
}
