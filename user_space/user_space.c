#define _GNU_SOURCE

#include <stdio.h>
#include <unistd.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <time.h> 
#include "../heapsentry.h"
#include <sys/syscall.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <pthread.h>

#define CANARY_BUF_SIZE 100

pthread_mutex_t mutex = PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;

int buf_cnt = 0, free_cnt = 0;

Canary *alloc_buf = NULL;
void* *free_buf = NULL;

const Canary empty_canary = {-1, -1, -1};

static void* (*real_malloc)(size_t) = NULL;
static void (*real_free)(void *) = NULL;
static void* (*real_calloc)(int, size_t);
static void* (*real_realloc)(void *, size_t);

void add_canary2free(void *);

/*Override memory allocation functions and initialize one buffer for all of them*/
static void override_alloc(void){
    real_malloc = dlsym(RTLD_NEXT, "malloc");
    real_calloc = dlsym(RTLD_NEXT, "calloc");
    real_realloc = dlsym(RTLD_NEXT, "realloc");
    if (NULL == real_malloc) {
        fprintf(stderr, "Error in `dlsym` malloc(): %s\n", dlerror());
    }

    if (NULL == real_calloc) {
        fprintf(stderr, "Error in `dlsym` calloc(): %s\n", dlerror());
    }

    if (NULL == real_realloc) {
        fprintf(stderr, "Error in `dlsym` realloc(): %s\n", dlerror());
    }

    srand((unsigned)time(NULL));
    if(alloc_buf == NULL){
        alloc_buf = real_malloc(CANARY_BUF_SIZE * sizeof(Canary));
        int i;
        for(i = 0; i < CANARY_BUF_SIZE; i++){
            alloc_buf[i] = empty_canary;
        }
    printf("alloc_buf initialized.\n");
    }

}

// Override free function and initialize free_buf
static void override_free(){
    real_free = dlsym(RTLD_NEXT, "free");
    if (NULL == real_free) {
        fprintf(stderr, "Error in `dlsym` free(): %s\n", dlerror());
    }
    free_buf = real_malloc(CANARY_BUF_SIZE * sizeof(void *));
    int i;
    for(i = 0; i < CANARY_BUF_SIZE; i++){
        free_buf[i] = NULL;
    }
    printf("free_buf initialized.\n");
}


void add_canary_alloc(void *ptr, size_t size){
    pthread_mutex_lock(&mutex);

    int canary_val = rand();
    int *canary_addr = (int *)(ptr+size);
    *canary_addr = canary_val;

    Canary tmp = {canary_val, (size_t) ptr, size + sizeof(int)};
    printf("Add canary val = %d, addr = %p, buf_cnt: %d\n", tmp.canary_val, (void *)tmp.block_addr, buf_cnt);

    /*Solution 1: avail_p*/
    // if(avail_p != -1){  // if there exists position available, add this canary into the buffer, update avail_p 
    //     alloc_buf[avail_p] = tmp;
    //     // buf_cnt++;
    //     int i;
    //     for(i = 0; i < CANARY_BUF_SIZE; i++){
    //         if(alloc_buf[i].block_addr = -1)
    //             break;
    //     }
    //     avail_p = ((i < CANARY_BUF_SIZE)? i: -1);
    // }

    // else{ // No available position, push all the canaries into kernel space
    //     // Add canaries in buffer into kernel space one by one (slow)
    //     // for(int i = 0; i < CANARY_BUF_SIZE; i++)
    //         // syscall(361, alloc_buf[i].pid, alloc_buf[i].canary_val, alloc_buf[i].block_addr, alloc_buf[i].block_size); 
            
    //     // use only one system call to pass the whole buffer to kernel space
    //     syscall(361, alloc_buf); 
    //     // Kernel code need modifying
    //     alloc_buf[0] = tmp;
    //     for(int i = 1; i < CANARY_BUF_SIZE; i++)
    //         alloc_buf[i] = empty_canary;
    //     avail_p = 1;
    // }

    /*---------------------------------------------------------------------------------------------------------------------------*/
    /*Solution 2: */
    if(buf_cnt == CANARY_BUF_SIZE){
        printf("alloc_buf is full, pushing canaries to kernel...\n");
        // syscall(361, alloc_buf);
        alloc_buf[0] = tmp;
        int i;
        for(i = 1; i < CANARY_BUF_SIZE; i++)
            alloc_buf[i] = empty_canary;
        buf_cnt = 1;
    }
    else{
        alloc_buf[buf_cnt] = tmp;
        buf_cnt++;
    }

    pthread_mutex_unlock(&mutex);
}

void remove_canary(void *ptr){
    printf("Remove Canary addr = %p\n", ptr);
    pthread_mutex_lock(&mutex);
    // /* Solution 1: avail_p*/
    // // First, find target in buffer
    // int i;
    // for(i = 0; i < CANARY_BUF_SIZE; i++){
    //     if(alloc_buf[i].block_addr == ptr){
    //         alloc_buf[i] = empty_canary;
    //         avail_p = i;
    //         break;
    //         }
    //     }
    // if(i == CANARY_BUF_SIZE)
    //     syscall(362, (size_t *) ptr);

/*---------------------------------------------------------------------------------------------------------------------------*/
    /*Solution 2: */
    int found = 0;
    int i;
    for(i = 0; i < buf_cnt; i++){
        if(alloc_buf[i].block_addr == (size_t)ptr){
            found = 1;
            alloc_buf[i] = alloc_buf[--buf_cnt];
            alloc_buf[buf_cnt] = empty_canary;
            // printf("canary removed.\n");
            break;
        }
    }
    if(!found)
        add_canary2free(ptr);

    pthread_mutex_unlock(&mutex);
}

void add_canary2free(void *ptr){
    pthread_mutex_lock(&mutex);
    printf("Add pointer: %p to free_buf[%d]\n", ptr, free_cnt);
    if(free_cnt == CANARY_BUF_SIZE){
        printf("free_buf is full, pushing ptrs to kernel...\n");
        // syscall(362, free_buf);
        free_buf[0] = ptr;
        int i;
        for(i = 1; i < CANARY_BUF_SIZE; i++){
            free_buf[i] = NULL;
        free_cnt = 1;
        }
    }
    else{
        free_buf[free_cnt++] = ptr;
    }

    pthread_mutex_unlock(&mutex);
}

void *malloc(size_t size){
    if(real_malloc == NULL) {
        override_alloc();
    }

    void *ptr = NULL;
    ptr = real_malloc(size + sizeof(int));
    add_canary_alloc(ptr, size);
    // fprintf(stderr, "malloc(%d) = ", size);
    // fprintf(stderr, "%p\n", ptr);
    return ptr;
}

void *calloc(size_t num, size_t size){
    if(real_calloc == NULL)
        override_alloc();

    void *ptr = real_malloc(num * size + sizeof(int));
    add_canary_alloc(ptr, num*size);
    return ptr;
}

void *realloc(void *ptr, size_t size){
    if(real_realloc == NULL)
        override_alloc();

    remove_canary(ptr);
    ptr = real_realloc(ptr, size + sizeof(int));
    add_canary_alloc(ptr, size);
    return ptr;
}

void free(void *ptr){
    if(real_free == NULL){
        override_free();
    }
    // fprintf(stderr, "free %p\n", ptr);
    remove_canary(ptr);
    real_free(ptr);
    return;
}
