# HeapSentry

### Introduction

This project, the HeapSentry, aims to detect and prevent malicious heap overflows by adding canaries at the end of each heap object and checking by the kernel before system calls executed. The attacker model of HeapSentry includes both Control-data attacks and Non-control-data-attacks. The implementation of HeapSentry can be divided into two components: *HeapSentry-U* and *HeapSentry-K*.

HeapSentry-U works in user space and intercepts memory allocation functions. It adds cannaries in each allocated block, then passes the address and value of the canary to HeapSentry-K. HeapSentry-K works in kernel space and stores the information of canaries. It will only be loaded when a system call is generated, including implemented system calls such as *fork* and unimplemented system calls which is used for the communication between HeapSentry-U and HeapSentry-K. HeapSentry-K compares current canary with oringinal one and decides whether to terminate the calling process or not.

### How to run

Our project was developed and tested under Ubuntu 14.04.6 LTS 32-bit system, and the kernel version is Linux 4.4.0. We recommand you use same environment with us. You can download it [here](http://releases.ubuntu.com/14.04/ubuntu-14.04.6-desktop-i386.iso).

After deploying the operating system, pull/download this repo. Then open a new terminal and run following commad to display kernel messages. 

```
tail -f /var/log/{messages,kernel,dmesg,syslog}
```

Then open another new terminal. We recommand you step into Demo folder first. Codes in  Demo set more print functions, which will help you understand how user and kernel space work. 

```
cd Demo
```

Next, compile kernel space code and install HeapSentry-K module with following commands.

```
cd kernel_space
sudo make
sudo insmod kernel_space.ko
```

If the module is successfully installed, the system call table address will be printed in kernel message.

Then, compile user space code and run test cases. Make sure you use "LD\_PRELOAD" every time you run a test program. 

```
cd ../user_space
make
make test_p
LD_PRELOAD=./user_space.so ./test_p
```

Now you can see how HeapSentry works!

We provide several different test cases for you to run :)

```
make test_p
LD_PRELOAD=./user_space.so ./test_p
make test1
LD_PRELOAD=./user_space.so ./test1
make test2
LD_PRELOAD=./user_space.so ./test2
make test3
LD_PRELOAD=./user_space.so ./test3
make test4
LD_PRELOAD=./user_space.so ./test4
make test5
LD_PRELOAD=./user_space.so ./test5
```

To exit, simply remove HeapSentry-K module from kernel.

```
sudo rmmod kernel_space
```

If you don't need these printed information in terminal, you can just ignore the first command "cd Demo", and run other commands shown above.

### More details

Please check [our project report](./RuntimeError_Project_Report_HeapSentry.pdf) and the original paper [HeapSentry: Kernel-assisted Protection against Heap Overflows](https://www.securitee.org/files/heapsentry_dimva2013.pdf) by [Prof. Nick Nikiforakis](https://www.securitee.org) for more details. 

