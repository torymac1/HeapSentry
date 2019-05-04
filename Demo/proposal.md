# Proposal

## Summary 
This project, the HeapSentry, aims to detect and prevent malicious heap overflows by adding canaries at the end of each heap object and checking by the kernel before system calls executed. The attacker model of HeapSentry includes both Control-data attacks and Non-control-data-attacks. The implementation of HeapSentry can be divided into two components: *HeapSentry-U* and *HeapSentry-K*.
HeapSentry-U works in user space and intercepts memory allocation functions. It adds cannaries in each allocated block, then passes the address and value of the canary to HeapSentry-K. HeapSentry-K works in kernel space and stores the information of canaries. It will only be loaded when a system call is generated, including implemented system calls such as *fork* and unimplemented system calls which is used for the communication between HeapSentry-U and HeapSentry-K. HeapSentry-K compares current canary with oringinal one and decides whether to terminate the calling process or not.

## Design


HeapSentry-U

- Heap block structure:
  - *block_addr
  - *canary_addr
  - canary (value)

- Rewrite allocate/deallocate functions
  - malloc()
  - realloc()
  - calloc()
  - free()
  
- Canary functions:
  - initialization() // initialize canary buffer
  - add_canary() // add canaries to buffer when necessary
  - generate_syscall() // communicate with kernel, push canaries info to HeapSentry-K
  - recycle_buffer() // clear buffer after flushing

HeapSentry-K:
- Loadable Kernel Module
- Store the original canaries location and value in the kernel's heap
- Allows up to a **user-configurable** maximum number of tracked canaries
- The system call classification

Optimizations:
1. Categorize system calls by risk level. We do canaries checking only system calls with medium or higher risk level are invoked to prevent frequently interrupting the kernel.
2. Temporarily store canaries information in a user space buffer and push it to HeapSentry-K when the buffer is full to improve effciency. Besides, we create a separate buffer for *free* operation to avoid false positive.


## Task division
- HeapSentry-U: Sangtian Wang
- HeapSentry-K: Xiao Zheng, Yifan Zhai
- Debug and test the whole system: Sangtian Wang, Xiao Zheng
- Report: Yifan Zhai

## Questions 

- How to use unimplemented system call numbers to pass information?
- Do we need to detect attempts to access memory from Ring 3 to Ring 0? (hardware-level isolation)
- How to make the maximum number of tracked canaries user-configurable?