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

#define CANARY_BUF_SIZE 3

pthread_mutex_t mutex = PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;

int buf_cnt = 0, free_cnt = 0;

Canary *alloc_buf = NULL;
size_t *free_buf = NULL;



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
    free_buf = real_malloc(CANARY_BUF_SIZE * sizeof(size_t));
    int i;
    for(i = 0; i < CANARY_BUF_SIZE; i++){
        free_buf[i] = 0;
    }
    printf("free_buf initialized.\n");
}


void add_canary_alloc(void *ptr, size_t size){
    pthread_mutex_lock(&mutex);

    int canary_val = rand();
    int *canary_addr = (int *)(ptr+size);
    *canary_addr = canary_val;

    Canary tmp = {canary_val, (size_t) ptr, size + sizeof(int)};
    printf("Add canary val = %d, addr = %p, at alloc_buf[%d]\n", tmp.canary_val, (void *)tmp.block_addr, buf_cnt);

    alloc_buf[buf_cnt++] = tmp;

    if(buf_cnt == CANARY_BUF_SIZE){
        printf("alloc_buf is full, pushing canaries to kernel...\n");
        syscall(369, alloc_buf, buf_cnt);
        // int i;
        // for(i = 1; i < CANARY_BUF_SIZE; i++)
            // alloc_buf[i] = empty_canary;
        buf_cnt = 0;
    }
    // else{
    //     alloc_buf[buf_cnt] = tmp;
    //     buf_cnt++;
    // }

    pthread_mutex_unlock(&mutex);
}

void remove_canary(void *ptr){
    printf("Remove Canary addr = %p\n", ptr);
    pthread_mutex_lock(&mutex);

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

    free_buf[free_cnt++] = (size_t)ptr;

    if(free_cnt == CANARY_BUF_SIZE){
        printf("free_buf is full, pushing ptrs to kernel...\n");
        syscall(370, free_buf, free_cnt);
        // int i;
        // for(i = 1; i < CANARY_BUF_SIZE; i++){
        //     free_buf[i] = NULL;
        // }
        free_cnt = 0;
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