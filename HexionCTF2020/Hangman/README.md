# Hangman

This task was part of the 'Pwn' category at the 2020 Hexion CTF (during 11-13 April 2020).

It was solved [The Maccabees](https://ctftime.org/team/60231) team.

Full solution is available [here](solve.py).



## The challenge

The challenge description:

![](hangman.png)

```
nc challenges1.hexionteam.com 3000
Note: flag is in ./flag
```

The challenge contains a ZIP archive with 3 files:

1. `hangman` - executable ELF (`hangman: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=9aa2f65b307cb0f388c44f89bb73a8b1bc4aa263, for GNU/Linux 3.2.0, not stripped`).
2. `hangman.c` - source code for `hangman`.
3. `words.list` - a 17-lines ASCII files that contains english words. Used by the `hangman` binary.

The binary itself (which we have access to interacting with it using netcat) is a game of hangman. This game is based on guessing a word, letter-by-letter. The prompt printed when running the game:

```
Welcome to the Hangman game!!!
In this game, you have to guess the word
Else... YOU WILL BE HANGED!!!
Good Luck! UwU

 ___________.._______
| .__________))______|
| | / /      ||
| |/ /       ||
| | /        ||.-''.
| |/         |/  _  \
| |          ||  `/,|
| |          (\\`_.'
| |         .-`--'.
| |        /Y . . Y\
| |       // |   | \\
| |      //  | . |  \\
| |     ')   |   |   (`
| |          ||'||
| |          || ||
| |          || ||
| |          || ||
| |         / | | \
""""""""""|_`-' `-' |"""|
|"|"""""""\ \       '"|"|
| |        \ \        | |
: :         \ \       : :
. .          `'       . .

Lives: 5
________

1 - Guess letter
2 - Guess word
3 - Give up
Enter choice: 
```

Because we are also given the source code, it's easy to inspect it and find a vulnerability.



## The vulnerability

We will go over the code structure, trying to explain the relevant parts and the vulnerability.

The `main` function prints a prompt and calls the `gameLoop` function.

The `gameLoop` function allocates the following `struct hangmanGame` on the stack, and calls `initHangmanGame` on it to initialize it:

```c
struct hangmanGame
{
    char word[WORD_MAX_LEN];
    char *realWord;
    char buffer[WORD_MAX_LEN];
    int wordLen;
    int hp;
};
```

```c
void gameLoop()
{
    struct hangmanGame game;
    char choice = 0;
    int exit = FALSE;

    initHangmanGame(&game);
    
	... // actual game loop is here
        
    delHangmanGame(&game);
}   
```

The `initHangmanGame` function does some initilizations, the important one for us being:

```c
#define WORD_MAX_LEN 32
...
void initHangmanGame(struct hangmanGame *game)
{
	...
	game->wordLen = WORD_MAX_LEN;
    ...
}
```

Afterwards, the main game loops runs; it excepts to get from the user a choice for command; in the exploit - the vulnerability resides in the guess word command (character `'2'`) - which calls the `guessWord(&game)` function:

```c
int guessWord(struct hangmanGame *game)
{
    int i = 0;
    int len = game->wordLen;

    for (i = 0; i <= len; i++)
    {
        game->buffer[i] = (char)getchar();
        if (game->buffer[i] == '\n')
        {
            break;
        }
    }
    game->buffer[i] = 0;
    fflush(stdin);

    ...
} 
```

This is an off-by-one (actually off-by-two) vulnerability: the `game->buffer` is in size `WORD_MAX_LEN` (which is `32`) - but the for loop counts from 0 to `len` (which was initialized to `32`) with a condition of `i <= len` - meaning this loop will run 33 iterations (if we keep feeding characters other than `'\n`'). In addition, after the for loop ends, another NULL bytes is written after the last index (meaning we can write in offset 34 from the 32-byte `buffer`).

Because how the `struct hangmanGame` looks like - right after `buffer` we have the `int wordLen` variable - which is exactly the limit we are looping on in this loop.

So we can gain overflow on the stack in two steps:

1. Call `guessWord`, overflow the `wordLen` with the value of `0xff` (255).
2. Call `guessWord` again - now the loop reads `0x100` (256) bytes (instead of just `32` before) - this is enough to overflow the entire `struct hangmanGame` and afterwards. Because the struct is allocated on the stack of the `gameLoop` function - we can overflow the stack there and control the return address of this function.

Notice that this binary is compiled without stack cookies - we can just directly overflow the return address and saved registers.

 

## The exploit

Given the overflow in the stack and the return address - we now need to exploit this primitive to a full code execution.

We have a few problems here:

1. Everything is randomized (stack addresses and `libc`) except our own binary (which is in constant address).
2. We don't know the version of the target machine `libc` (so leaking `libc` base isn't enough - we need to leak its version).



### Finding useful gadgets

The binary is very small, and it doesn't contain and useful gadgets for us by its own (no `execve`/`system`/syscall gadgets). In order to control interesting registers (some of the calling convention arguments - `rdi, rsi, rdx, rcx, r8, r9`), we use 2 useful gadgets in the binary, which are both in the `__libc_csu_init` function. The two gadgets are:

```assembly
pop     rbx
pop     rbp
pop     r12
pop     r13
pop     r14
pop     r15
retn
```

```asm
mov     rdx, r14
mov     rsi, r13
mov     edi, r12d
call    qword ptr [r15+rbx*8]
...
```

Chaining these 2 gadgets, we can gain a control over `rdx`, `rsi` and `edi` (and `r12-r15` and `rbx`/`rbp` with some limitations).

In addition - using these `__libc_csu_init` gadgets - we can put the address of a GOT entry in `r15` in order to call any function in the GOT.



### Constructing a leak primitive

In order to leak an address, we will construct a ROP chain in the following manner:

1. Using the above gadgets, call the `puts` function (which has a GOT entry) with a parameter we control. We will set this parameter to a be a GOT entry as-well, in order to leak the address of some `libc` functions.
2. Return to the `_start` function of the binary, re-starting execution of the whole hangman game - allowing us to overflow the stack again and continue to overflow the stack - but now with a leak.



### Identifying target `libc`

Equipped with our new leak primitive, we will use it a few times (in a separate connections) in order to leak addresses of a few functions in `libc` (using their GOT entries). Then, we'll use the [libc database search](https://libc.blukat.me/) website - that allows us to input the 3 lowest nibbles (bottom 12-bits - which doesn't randomize upon ASLR) of a few functions from a specific `libc`, in order to find it in the database.

After inputing 3 functions we got the result that our `libc` version is `libc6_2.27-3ubuntu1_amd64.so`, and a download link for this library (attached in the git repository).



### Getting code execution

Now we can just do the following:

1. Start with the leak ROP chain to leak the address of `puts`. Because we know the `libc` version now, we can calculate the `libc` base.
2. Because the leak now runs the `_start` function, we can trigger the vulnerability again, overflow the stack, and generate a ROP chain that runs `execv("/bin/sh", NULL)` using `libc` gadgets (both `execv` function and `"/bin/sh/"` string are present in `libc` itself).
3. We gain code execution! 



Now we can just inspect the filesystem using the shell and find the flag: `hexCTF{e1th3r_y0u_gu3ss_0r_y0u_h4ng}`.

Full exploit code is available [here](solve.py).



Thanks for reading!
