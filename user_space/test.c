#include <stdio.h>
#include <stdlib.h>

int main(){
	// size_t s = 10;
	void *p1 = malloc(10);
	void *p2 = malloc(9);
	void *p3 = malloc(8);
	void *p4 = malloc(8);
	
	
	
	free(p1);
	free(p2);
	free(p3);
	free(p4);

	return 0;
}