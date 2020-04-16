# WWW

This task was part of the 'PWN' category at the 2020 Hexion CTF (during 11-13 April 2020).
It was solved by [or523](https://github.com/or523), in [The Maccabees](https://ctftime.org/team/60231) team.

My full solution is available [here](solve.py).

## The challenge

The challenge is a very simple pwning challenge. We get a netcat access to a server running the following code:

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void write(char what, long long int where, char* buf) {
    buf[where] = what;
}

char what() {
    char what;
    scanf("%c", &what);
    getchar();
    return what;
}

long long int where() {
    long long int where;
    scanf("%lld", &where);
    getchar();
    return where;
}

int main(void) {
	setvbuf(stdout, NULL, _IONBF, 0);
    int amount = 1;
    char buf[] = "Hello World!";
    while (amount--) {
        write(what(), where(), buf);
    }
    printf(buf);
}
```

Basically, we get here a write primitive of a controlled byte-value, to a controlled offset from some buffer on the stack.
When the function finishes, this buffer on the stack is used as the first argument for `printf` (as a format string).

The goal is, of course - to execute arbitrary code on the server.

## The solution

### Observations

Some simple initial observations:

1. The binary itself is not randomized (but `libc` and the stack are).
2. The order to the `what()` and `where()` invocations swapped in compilation (parameters to a function are not evaluated in a defined order in C).

### Improving the write primitive

The main thing holding us back is that we can only use the primitive once - the `amount` variable is initialized to 1. But in the compiled binary, this variable is also stored on the stack (in offset of `-7` bytes from `buffer`) - which mean we can use our first write primitive in order to overwrite the `amount` variable.
Meaning - we can improve the primitive in order to gain as many WWW primitives as we want.

### Leaking addresses

Now that we have the ability to write as many bytes as we want - we understand that we need to leak addresses of the memory space: leaking the stack would allow us to convert our relative-write primitive to absolute-write (because we would know the base of the write); and leaking `libc` would give us the addresses of useful gadgets for code executions.

Leaking these addresses can be used by abusing the fact we control the format string to the `printf` function. For example - we can abuse the `"%15$p"` feature of format-strings, in order to leak the "15th argument" of `printf` (meaning we can just leak data from any offset of the stack we want). By trial-and-error, we get to the following conclusions:

1. `"%13$p"` is the return address of the `main` address, which is an address inside `libc` - of the `__libc_start_main` function.
2. `"%15p"` is an address of the stack, which is in constant offset from `buffer`.

### Resuming execution after leak

Notice a caveat in the leaking primitive - the `printf` function is called only after we finish the loop of write primitives. In order to keep using the write primitives after we finish, we can control execution and jump back to the `_start` function - which will cause the program to re-start again.

There are 2 ways we control the execution to reuse the write primitive after a leak:

1. Override the return address (constant offset from `buffer` on the stack).
2. If we have an absolute-write primitive (after we've leaked a stack address) - we can overwrite the `__stack_chk_fail` GOT entry to our own address, and then overwrite the stack cookie of the `main` function with some wrong value.

We can't rely only on the first method, because one of the addresses we want to leak **is **the return address, and if we'll overwrite it - the `printf` obviously won't be able to leak the original value.

### Code execution

After leaking the addresses of both `libc` and the stack, we can just write our ROP chain to the stack. This is a rather simple ROP chain, which ends of calling `execv("/bin/sh", {"/bin/sh", NULL})` (using our write primitive and addresses from libc).

### Final Exploit Flow

1. First session:
   1. Increase write-primitive amount by overwriting `amount` variable.
   2. Write `"%15p"` to the format string in order to leak a stack address.
   3. Write `_start` address to the return address to start a new session of WWW primitives.
   4. Finish loop and leak stack address! (now we have absolute R/W primitive).
2. Second session:
   1. Increase write-primitive amount by overwriting `amount` variable.
   2. Write `"%13p"` to the format string in order to leak a `libc` address.
   3. Write `_start` address to the GOT entry of `__stack_chk_fail`.
   4. Write 0 on the stack cookie.
   5. Finish loop and leak libc address!
3. Third session:
   1. Increase write-primitive amount by overwriting `amount` variable.
   2. Write necessary information (like `argv`) to a data cave in the `.data` section.
   3. Construct `execv("/bin/sh", {"/bin/sh", NULL})` ROP chain and write it on the stack.
   4.  Finish loop to achieve code execution!

After running shell, we can `cat` the flag from a file, which is: `hexCTF{wh0_wh1ch_why_wh3n?}`.



## Aftermath

After reading some write-ups, turns out my solution is way more complex than it should be (this was also my assumption during the CTF).

My mistake was overlooking some offsets that could allow me to leak `libc` while still overwriting the return address (such as `%29$p`), allowing me to skip the third session. I think the reason this offset didn't work for me is that I tried to make the exploit generic to both my own and the remote `libc`, and the stack offsets beyond the `main` function has changed too much to be consistent.



Thanks for reading!

~ **or523**