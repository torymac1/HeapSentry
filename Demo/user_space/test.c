#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <string.h>

void test1(){
	printf("malloc p1...\n");
	void *p1 = malloc(10);
	printf("malloc p2...\n");
	void *p2 = malloc(10);
	printf("malloc p3...\n");
	void *p3 = malloc(10);
	printf("malloc p4...\n");
	void *p4 = malloc(10);
	printf("malloc p5...\n");
	void *p5 = malloc(10);
	printf("malloc p6...\n");
	void *p6 = malloc(10);
	printf("malloc p7...\n");
	void *p7 = malloc(10);

	printf("free p1...\n");
	free(p1);
	printf("free p2...\n");
	free(p2);
	printf("free p3...\n");
	free(p3);
	printf("free p4...\n");
	free(p4);
	printf("free p5...\n");
	free(p5);
	printf("free p6...\n");
	free(p6);
	printf("free p7...\n");
	free(p7);

}

void test2(){
	// size_t s = 10;
	printf("malloc p1...\n");
	void *p1 = malloc(10);
	printf("calloc p2...\n");
	void *p2 = calloc(9, sizeof(int));
	printf("free p2...\n");
	free(p2);
	printf("malloc p3...\n");
	void *p3 = malloc(8);
	printf("realloc p1...\n");
	p1 = realloc(p1, 20);
	printf("calloc p4...\n");
	void *p4 = calloc(10, 4);
	printf("malloc p5...\n");
	void *p5 = malloc(50);
	printf("malloc p6...\n");
	void *p6 = malloc(30);
	
	
	printf("free p3...\n");
	free(p3);
	printf("free p1...\n");
	free(p1);
	printf("free p6...\n");
	free(p6);
	printf("free p4...\n");
	free(p4);
	printf("free p5...\n");
	free(p5);
}

int test3(){
	int filedesc = open("testfile.txt", O_WRONLY | O_APPEND);
    if(filedesc < 0)
        return 1;
 
    if(write(filedesc,"This will be output to testfile.txt\n", 36) != 36)
    {
        write(2,"There was an error writing to testfile.txt\n");    // strictly not an error, it is allowable for fewer characters than requested to be written.
        return 1;
    }
 
    return 0;
}

int test4(int argc, char *argv[]){
	char *p1;
	char *p2;
	char *p3;
	char *p4;
	if (argc < 2){
		fprintf(stderr, "Error. Usage: %s <string>\n", argv[0]);
		exit(-1);
	}

	p1 = malloc(3);
	printf("p1 address is %p\n", p1);
	p2 = malloc(40);
	printf("p2 address is %p\n", p2);
	p3 = malloc(40);
	printf("p3 address is %p\n", p3);
	p4 = malloc(40);
	printf("p4 address is %p\n", p4);

	free(p3);

	strcpy(p2, "Important stuff right here");
	strcpy(p1,argv[1]);
	printf("p1 : %s\np2: %s\n", p1,p2);
	
	int filedesc = open("testfile.txt", O_WRONLY | O_APPEND);
    // if(filedesc < 0)
    //     return 1;

	free(p1);
	free(p2);

	filedesc = open("testfile.txt", O_WRONLY | O_APPEND);
	free(p4);
	// free(p3);
	// free(p4);

 
	return 0;
}


int main(int argc, char *argv[]){
	printf("test executing\n");
	// syscall(360);
	// test1();
	// test2();
	// test3();
	// test4(argc, argv);
	return 0;
}