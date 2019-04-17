

typedef struct Block_with_canary{
	int *canary_addr;
	size_t *block_addr;
	size_t block_size;
}Block_with_canary;

typedef struct Canary{
	int canary_val;
	size_t block_addr;
	size_t block_size;
}Canary;