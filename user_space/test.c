#include <stdio.h>
#include <stdlib.h>

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

int main(){
	test1();
	return 0;
}