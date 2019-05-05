#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <string.h>
#include <errno.h>
#include <sys/mount.h>

int o_open_write()
{
	char *p1 = malloc(5);
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

int main()
{
	syscall(360);
	printf("High Risk Function Open Testing\n");
	o_open_write();
	return 0;
}