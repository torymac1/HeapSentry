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

#define MAX_CANARY 100
Canary *canary_buf = NULL;
int canary_num = 0;
const Canary empty_canary = {-1, -1, -1};

static void* (*real_malloc)(size_t)=NULL;
static void (*real_free)(void *)=NULL;


static void override_init(void){
    real_malloc = dlsym(RTLD_NEXT, "malloc");
    real_free = dlsym(RTLD_NEXT, "free");
    if (NULL == real_malloc) {
        fprintf(stderr, "Error in `dlsym` malloc(): %s\n", dlerror());
    }

    if (NULL == real_free) {
        fprintf(stderr, "Error in `dlsym` free(): %s\n", dlerror());
    }
    srand((unsigned)time(NULL));
    canary_buf = real_malloc(MAX_CANARY * sizeof(Canary));
    int i;
    for(i=0; i<MAX_CANARY; i++){
        canary_buf[i] = empty_canary;
    }

}


void add_canary(void *ptr, size_t size){
    int canary_val = rand();
    int *canary_addr = (int *)(ptr+size);
    *canary_addr = canary_val;

    Canary tmp = {canary_val, (size_t) ptr, size + sizeof(int)};
    printf("Add canary at block pos %x\n", tmp.block_addr);
    syscall(361, tmp.canary_val, tmp.block_addr, tmp.block_size);

    // if(canary_num < MAX_CANARY){
    //     int i;
    //     for(i=0; i<MAX_CANARY; i++){
    //         if(canary_buf[i].block_addr == -1){
    //             canary_buf[i] = tmp;
    //             break;
    //         }
    //     }
        
    //     printf("Add canary at block pos = %x, addr = 0x%x, val = %d\n", i, canary_buf[i].block_addr, canary_buf[i].canary_val);   
    //     canary_num++;
    // }

    // if(canary_num == MAX_CANARY){
    //     //sent_canary_to_kernel();
    //     int i;
    //     for(i = 0; i<canary_num; i++){
    //         canary_buf[i]= empty_canary;
    //     }
    //     canary_num = 0;
    // }
    
}

void remove_canary(void *ptr){
    printf("remove %x\n", (size_t) ptr);
    syscall(362, (size_t) ptr);
    // if(canary_num == 0){
    //     printf("No canary!");
    // }
    // int i;
    // for(i=0; i<MAX_CANARY; i++){
    //     //Move the last canary to the deleted canary's position
    //     if(canary_buf[i].block_addr == (size_t) ptr){
    //         int cur_canary = *(int *)(ptr + canary_buf[i].block_size - sizeof(int));
    //         //remove_canary_from_kernel();
    //         printf("Remove canary pos = %d, addr = 0x%x, val = %d\n", i, canary_buf[i].block_addr, cur_canary);
    //         canary_buf[i] = empty_canary;
    //         canary_num--;
    //         break;
    //     }
    // }

}

void *malloc(size_t size){
    if(real_malloc == NULL) {
        override_init();
    }

    void *ptr = NULL;
    ptr = real_malloc(size + sizeof(int));
    add_canary(ptr, size);
    // fprintf(stderr, "malloc(%d) = ", size);
    // fprintf(stderr, "%p\n", ptr);
    return ptr;
}

void free(void *ptr){
    if(real_free == NULL){
        override_init();
    }
    // fprintf(stderr, "free %p\n", ptr);
    remove_canary(ptr);
    real_free(ptr);
    return;
}
