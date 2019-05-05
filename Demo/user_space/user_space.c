#define _GNU_SOURCE

#include <stdio.h>
#include <unistd.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <time.h> 
#include "../heapsentry.h"
#include <sys/syscall.h>
#include <sys/types.h>
#include <pthread.h>



pthread_mutex_t mutex = PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP; // mutex lock

int *buf_cnt = NULL; // a pointer stores number of elements in alloc_buf
int *free_cnt = NULL; // a pointer stores number of elements in free_buf
int *need_free = NULL; // a flag that will be set to 1 when high-risk syscalls are detected in kernel to inform HeapSentry-U to free the blocks in free_buf

Canary *alloc_buf = NULL; // canary buffer for memory allocation functions
size_t *free_buf = NULL; // pointer buffer for free()

const Canary empty_canary = {-1, -1, -1}; // default value of empty canary

// declare original library functions
static void* (*real_malloc)(size_t) = NULL;
static void (*real_free)(void *) = NULL;
static void* (*real_calloc)(int, size_t) = NULL;
static void* (*real_realloc)(void *, size_t) = NULL;

void add_canary2free(void *);
void release_free_buf();
/*Override memory allocation functions and initialize a common buffer for all of them*/
static void override_alloc(void){
    real_malloc = dlsym(RTLD_NEXT, "malloc");
    real_calloc = dlsym(RTLD_NEXT, "calloc");
    real_realloc = dlsym(RTLD_NEXT, "realloc");
    //error handle
    if (NULL == real_malloc) {
        fprintf(stderr, "[ERROR] Error in `dlsym` malloc(): %s\n", dlerror());
    }

    if (NULL == real_calloc) {
        fprintf(stderr, "[ERROR] Error in `dlsym` calloc(): %s\n", dlerror());
    }

    if (NULL == real_realloc) {
        fprintf(stderr, "[ERROR] Error in `dlsym` realloc(): %s\n", dlerror());
    }

    srand((unsigned)time(NULL)); // initialize seed for random integer generation
    // initialize alloc_buf
    if(alloc_buf == NULL){
        alloc_buf = real_malloc(CANARY_BUF_SIZE * sizeof(Canary));
        buf_cnt = real_malloc(sizeof(int));
        *buf_cnt = 0;
        int i;
        for(i = 0; i < CANARY_BUF_SIZE; i++)
            alloc_buf[i] = empty_canary;
        syscall(361, alloc_buf, buf_cnt); // pass addresses of alloc_buf and buf_cnt to the kernel to help kernel pull info from userspace
        printf("[INFO] alloc_buf initialized.\n");
    }
}

// Override free function and initialize free_buf
static void override_free(){
    real_free = dlsym(RTLD_NEXT, "free");
    if (NULL == real_free) {
        fprintf(stderr, "[ERROR] Error in `dlsym` free(): %s\n", dlerror());
    }
    free_buf = real_malloc(CANARY_BUF_SIZE * sizeof(size_t));
    free_cnt = real_malloc(sizeof(int));
    need_free = real_malloc(sizeof(int));
    *free_cnt = 0;
    *need_free = 0;
    syscall(362, free_buf, free_cnt, need_free); // pass addresses of free_buf and free_cnt to the kernel to help kernel pull info from userspace

    int i;
    for(i = 0; i < CANARY_BUF_SIZE; i++){
        free_buf[i] = 0;
    }

    printf("[INFO] free_buf initialized.\n");
}

/*Add new canary to alloc_buf*/
void add_canary_alloc(void *ptr, size_t size){
    pthread_mutex_lock(&mutex);

    int canary_val = rand(); // Set a fresh random integer as the canary value
    int *canary_addr = (int *)(ptr+size);
    *canary_addr = canary_val;

    Canary tmp = {canary_val, (size_t) ptr, size + sizeof(int)};
    printf("[INFO] Add canary val = %d, addr = %p, at alloc_buf[%d]\n", tmp.canary_val, (void *)tmp.block_addr, *buf_cnt);

    
    alloc_buf[*buf_cnt] = tmp;
    *buf_cnt = *buf_cnt + 1; // update the conuter pointer

    // push canaries in alloc_buf to kernel space when the buffer is full
    if(*buf_cnt == CANARY_BUF_SIZE){
        printf("[INFO] alloc_buf is full, pushing canaries to kernel...\n");
        syscall(369);
        *buf_cnt = 0;
    }
    pthread_mutex_unlock(&mutex);
}

/*Check and remove canaries in alloc_buf when free() is called*/
void remove_canary(void *ptr){
    pthread_mutex_lock(&mutex);
    // printf("[INFO] addr = %p, *need_free = %d\n", ptr, *need_free);
    // high-risk syscall detected in kernel, free all the blocks in free_buf if canary check succeeds in kernel
    if(*need_free != 0){
        // printf("[INFO] need_free is set to %d\n", *need_free);
        release_free_buf();
    }

    // Find and check canaries in alloc_buf
    int found = 0;
    int i;
    for(i = 0; i < *buf_cnt; i++){
        if(alloc_buf[i].block_addr == (size_t)ptr){
            int *canary_addr=NULL; 
            canary_addr = (int *) (alloc_buf[i].block_addr + alloc_buf[i].block_size - sizeof(int));
            if(alloc_buf[i].canary_val !=  *canary_addr){ // check fail, terminate the process
                printf("[ERROR] Wrong Canary at %p (in user space)\n", (void *) alloc_buf[i].block_addr);
                exit(7);
            }
            // if found, remove the canary and deallocate the block
            real_free(ptr);
            printf("[INFO] Remove Canary addr = %p (verified in user space)\n", (void *)ptr);
            found = 1;
            *buf_cnt = *buf_cnt - 1;
            alloc_buf[i] = alloc_buf[*buf_cnt];
            alloc_buf[*buf_cnt] = empty_canary;
            break;
        }
    }
    // if not found, add the pointer to free_buf
    if(found == 0)
        add_canary2free(ptr);
        

    pthread_mutex_unlock(&mutex);
}

/* Add canaries to free_buf */
void add_canary2free(void *ptr){

    pthread_mutex_lock(&mutex);
    printf("[INFO] Add pointer: %p to free_buf[%d]\n", ptr, *free_cnt);

    free_buf[*free_cnt] = (size_t)ptr;
    *free_cnt = *free_cnt + 1;

    // push pointers in free_buf when the buffer is full
    if(*free_cnt == CANARY_BUF_SIZE){
        printf("[INFO] free_buf is full, pushing ptrs to kernel...\n");
        int verify_free_buf = syscall(370); // syscall that informs kernel of new set of free_buf
        if(verify_free_buf == 0){ // canary value checks succeeded in kernel, free blocks in free_buf
            release_free_buf();
        }
        else if(verify_free_buf == -1){ // kernel failed to get access to free_buf, reset free_cnt
            printf("[INFO] Access to free_buf failed.\n");
            *free_cnt = 0;
        }
    
    }

    pthread_mutex_unlock(&mutex);
}

// deallocate the blocks in free_buf
void release_free_buf(){
    pthread_mutex_lock(&mutex);
    int i;
    for(i=0; i<*free_cnt; i++){
        printf("[INFO] Remove Canary addr = %p (verified in kernel)\n", (void *)free_buf[i]);
        real_free((void *)free_buf[i]);
    }
    *free_cnt = 0;
    *need_free = 0;
    pthread_mutex_unlock(&mutex);
}

/*Redefine malloc*/
void *malloc(size_t size){
    // intercept memory allocation functions and initialize buffer when any one of them first occurs in a process
    if(real_malloc == NULL) {
        override_alloc();
    }

    void *ptr = NULL;
    ptr = real_malloc(size + sizeof(int)); // return a block with 4 bytes larger
    add_canary_alloc(ptr, size); // add a new canary to alloc_buf
    return ptr;
}

/* Redefine calloc*/
void *calloc(size_t num, size_t size){
    if(real_calloc == NULL)
        override_alloc();

    void *ptr = real_malloc(num * size + sizeof(int));
    add_canary_alloc(ptr, num*size);
    return ptr;
}

/*Redefine realloc*/
void *realloc(void *ptr, size_t size){
    if(real_realloc == NULL)
        override_alloc();

    ptr = real_realloc(ptr, size + sizeof(int));
    add_canary_alloc(ptr, size);
    return ptr;
}

/*Redefine free*/
void free(void *ptr){
    if(real_free == NULL){
        override_free();
    }
    remove_canary(ptr); // remove and check canary
    return;
}