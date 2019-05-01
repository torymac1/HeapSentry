#define MAX_PID 32768


typedef struct Canary{
	int canary_val;
	size_t block_addr; 
	size_t block_size; //original size + size of canary
}Canary;