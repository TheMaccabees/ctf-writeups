# Back to the BASICs

This task was part of the 'RE' category at the 2018 Google CTF Quals round (during 23-24 June 2018).

It was solved by [NotWearingPants](https://github.com/NotWearingPants), in [The Maccabees](https://ctftime.org/team/60231) team.

## The challenge

The description given in the website reads:
```
You won't find any assembly in this challenge, only C64 BASIC. Once you get the password, the flag is CTF{password}. P.S. The challenge has been tested on the VICE emulator.
```
Along with this **[attachment](https://github.com/TheMaccabees/ctf-writeups/GoogleCTF2018Quals/back-to-the-basics/attachment.zip)**.

## Exploring the Attachment

From the title & description of this challenge it's quite obvious the challenge has something to do with the **BASIC language**,
and a quick google search reveals that "C64" refers to the famous ancient computer, the **Commodore 64**.

Inside the attached zip there's a single file called `crackme.prg` .
I know that `prg` usually just stands for `program`, so the extension tells me nothing here.

As BASIC is a textual language, I open the file in my favorite text editor expecting to find BASIC code, but to my surprise, the file appears to be a binary file.

I open the file in a hex editor, and I see mostly ASCII letters and digits, mixed with some non-ASCII characters.
I don't really know BASIC, but I expected to see a `PRINT` statement which I know exists, but I couldn't find one in the file.

IDA didn't understand the file either, so I searched for "c64 basic disassemblers" and found a program called *"PRG studio"* which claims it can work with `.prg` files.

So maybe the `.prg` file extension does mean anything - searching for "C64 basic prg file" came up with [this](http://fileformats.archiveteam.org/wiki/Tokenized_BASIC) and [this](https://c64-wiki.com/wiki/BASIC_token).
Apparently a `.prg` file is BASIC code with known tokens replaced with single bytes to save space, this format is called "tokenized BASIC".

This matched up with the string `\xB2\xB2\xB2 BACK \xA4 BASICS \xB2\xB2\xB2` that appears at the beginning of the file, as `\xB2` maps to the `=` operator, and `\xA4` maps to the `TO` keyword, which results in `=== BACK TO BASICS ===`, and that looks about right.

Another thing the links mention is that the rest of the characters are part of a character set called [PETSCII](https://en.wikipedia.org/wiki/PETSCII#Character_set), not regular ASCII.

As I didn't want to run some random executable from the internet, and the tokenized BASIC format seemed pretty straightforward, I attempted to write my own [detokenizer](decode_tokenized_basic.py) and it [almost worked](my_detokenizer_output.txt).

So I ended up using "[C64 BASIC Lister](https://www.luigidifraia.com/c64/index.htm#BL)" to open the file, and [it worked!](initial_extracted_basic_code.txt)
I was able to get the original BASIC code from this binary.

## Understanding the Code

Given the [BASIC code we got](initial_extracted_basic_code.txt), we now have to figure out the password that was mentioned in the challenge description, while using [the C64 wiki](https://www.c64-wiki.com/) to understand the language.

The colons are probably used to separate multiple statements on the same line, though I couldn't verify this fact online.

Looking at the code it's hard to miss the statement `PRINT "PASSWORD PLEASE?" CHR$(5)` on line #70, which is followed by `INPUT ""; P$`.

The wiki says `CHR$()` converts a number to an ASCII character. 5 isn't a printable character in ASCII, and in PETSCII it doesn't seem to mean anything either, so let's just ignore it. Also, it looks like string concatenation is done by simply putting the two strings next to each other.

As separating statements is done with colons, I assume semicolon doesn't separate statements, so the `P$` is probably part of the `INPUT` statement, and is probably the variable that stores the result - but the only place `P$` is used is on line #200 where its length is checked:

```basic
IF LEN(P$) = 30 THEN GOTO 250
```

I see the `PRINT "VERDICT: NOPE"` at the bottom and understand I don't want to reach line #31337. At line #220 there's a `GOTO 31337` so I want to skip that either - the only place jumping over line #220 is the `IF` with `P$` I mentioned before, so I guess the password's length should be 30, otherwise "NOPE" will be printed.

The only other way of reaching the NOPE is from the line before, line #2010, which contains a `GOTO 2001` which is the line before it.
But line #2001 is just a comment, isn't this an infinite loop?

The code is weird, and since it's not that long, I decide to just go over the entire file and figure out what's happening.

As I get to `POKE` instructions, I learn that they are used to write to memory.
I know that usually with devices that are running without a modern operating system, writing to memory could be a way of [communicating with hardware](https://en.wikipedia.org/wiki/Memory-mapped_I/O).
So I search for a memory map of the Commodore 64 - I find the [memory map](https://www.c64-wiki.com/wiki/Memory_Map) on the wiki, and [a more detailed but clunky one](http://sta.c64.org/cbm64mem.html) on some other website.

Using the knowledge I've gathered I could understand and document most of the code, resulting in this **[documented code](documented_initial_code.txt)**.

There was only one one line I had trouble understanding - `2010   POKE 03397, 00199 : POKE 03398, 00013 : GOTO 2001`.
According to the memory map, this is writing stuff inside the "Free BASIC program storage area".
I guess it's free memory for the program to use, but no other part uses it.

I still couldn't find the password check, so I decided to try another detokenizer to get a second opinion on the file contents, so I found `petcat` - a CLI that's apparently part of the VICE emulator, the emulator that was mentioned in the challenge description.

I downloaded [VICE](http://vice-emu.sourceforge.net) and ran `petcat` on the `.prg` file, which resulted in the same output. 
Well, since I just downloaded an emulator, might as well run the program on it, no?

## Testing on the Emulator

I launched the VICE emulator, and after it booted (I showed it to my dad for some nostalgia, and then) I played around with the BASIC interpreter, and finally loaded `crackme.prg`.

It took forever to load, and then displayed the "BACK TO THE BASICS" banner as I saw in the code beforehand, then asked for the password.

I entered a 30 character password, and it showed a progress bar that slowly began to fill up with icons.
Nowhere in the code was the progress bar filled other than the first character slot, so I searched online if progress bars are a built-in thing in C64, but they weren't.

Hmm... So apparently, the VICE emulator also comes with a built-in debugger that can show me the computer's memory (the command `m`).
Viewing memory at address 3397 (0xd45) which is where the mysteryious `POKE` wrote showed something familiar - a part of the `.prg` file was there in memory! And the program was... changing it?

## Self-Modifying Code

Well... It turns out that what we're dealing with is a self-modifying BASIC program. Wat.

This explains how the emulator was running logic that wasn't in the code I extracted initially.
This also means that the Commodore 64 must be interpreting and running the tokenized BASIC as-is from memory, it doesn't first detokenize it, or first turn it into assembly and jump to it.

I tried to modify the bytes in the `.prg` file like the `POKE` statement did using a hex editor so that `petcat` would show where execution jumps to next, but it didn't quite work.

In the hex editor I saw the last source line I had decoded ended at 0x5C2, but after that position was obviously more tokenized BASIC code, but there we're a few NULL bytes after the original program and before the continuation, so I just deleted bytes until `petcat` agreed to decode the rest of the program :)
Specifically, deleting the `00 00 00 00 8F 00` at 0x5C2 does the trick.

We now have [more code](more_code.txt)!

## More Self-Modifying Code

The line at the end looks real scary, but let's go line by line.

The first new line we got has the number 2001, which is an already existing line, and also in line #2010 there's a `GOTO 2001`.
So I guess that's not actually an infinite loop, it jumps to this new line.

The new code first does some more self-modifying (line #2001), and then tinkers with the 2nd character of the progress bar - this is really what's been messing with our progress bar.

Then comes a loop which seems to poke a lot more in the program memory:

```basic
2004 es = 03741 : ee = 04981 : ek = 148
2005 for i = es to ee : k = ( peek(i) + ek ) and 255 : poke i, k : next i
```

This loop adds 148 to all bytes in memory in the range {3741..4981} (inclusive).

Using the memory viewer in VICE's debugger I figure out that our `.prg` file was loaded at address `0x801`, which matches the first 2 bytes of the file that happen to be the "load address" (little endian).

With a bit of math (`es - load_address + sizeof(load_address)`), we can figure out this means that the loop is dealing with bytes {0x69E..0xB77} (exclusive) in the original file.
After doing the addition in the file myself using a hex editor, many bytes are now printable characters, looks about right. NOTE: don't forget to take into account the deleted 6 bytes if you are dealing with the modified file.

Running `petcat` again on the modified `.prg` file we get [more more code!](more_more_code.txt)

## Woah, Math

The first new line we got is:

```basic
2010 v = 0.6666666666612316235641 - 0.00000000023283064365386962890625 : g = 0
```

And then we see another use of our password variable, `P$`:

```basic
2020 ba = asc( mid$(p$, 1, 1) )
2021 bb = asc( mid$(p$, 2, 1) )
```

According to the wiki, `mid$` extacts a substring from a string, so these two lines get the first character of the password into `ba`, and the second character into `bb`.

Then there's a bunch of *math*, and after that we get to the actual checks:

```basic
2100 t0 = k = g : a = 86 : b = 10
2200 if t0 = -1 then a = 83 : b = 5
...
2905 poke 1024 + chkoff + 1, a : poke 55296 + chkoff + 1, b
```

I couldn't quite figure out the PETSCII here, but from observing the first progress bar character in the emulator and the length check on `P$` I can infer that `86 is the red X`, and `83 is the green heart`.

Assuming I want the heart, because who doesn't, I want `a` to be `83`, so I want the `IF` on line #2200 to succeed.

Line #2100 seems to assign to `t0` the result of whether `k` is equal to `g`. After playing around with the BASIC interpreter in the emulator, it turns out that `2 = 3` is `0`, and `2 = 2` is `-1`. Wat.

Ok then, so we want `k` to equal `g` and then we get a heart. Simple.

```basic
2010 v = 0.6666666666612316235641 - 0.00000000023283064365386962890625 : g = 0
2020 ba = asc( mid$(p$, 1, 1) )
2021 bb = asc( mid$(p$, 2, 1) )
2025 p0 = 0 : p1 = 0 : p2 = 0 : p3 = 0 : p4 = 0 : p5 = 0 : p6 = 0 : p7 = 0 : p8 = 0 : p9 = 0 : pa = 0 : pb = 0 : pc = 0
2030 if ba and 1 then p0 = 0.062500000001818989403545856475830078125
2031 if ba and 2 then p1 = 0.0156250000004547473508864641189575195312
2032 if ba and 4 then p2 = 0.0039062500001136868377216160297393798828
2033 if ba and 8 then p3 = 0.0009765625000284217094304040074348449707
2034 if ba and 16 then p4 = 0.0002441406250071054273576010018587112427
2035 if ba and 32 then p5 = 0.0000610351562517763568394002504646778107
2036 if ba and 64 then p6 = 0.0000152587890629440892098500626161694527
2037 if ba and 128 then p7 = 0.0000038146972657360223024625156540423632
2040 if bb and 1 then p8 = 0.0000009536743164340055756156289135105908
2031 if bb and 2 then p9 = 0.0000002384185791085013939039072283776477
2032 if bb and 4 then pa = 0.0000000596046447771253484759768070944119
2033 if bb and 8 then pb = 0.000000014901161194281337118994201773603
2034 if bb and 16 then pc = 0.0000000037252902985703342797485504434007
2050 k = v + p0 + p1 + p2 + p3 + p4 + p5 + p6 + p7 + p8 + p9 + pa + pb + pc
2060 g = 0.671565706376017
```

It appears that individual bits of the bytes in the password are checked, and then numbers that look like negative powers of 4 - `{4^(-4)..4^(-14)}` (inclusive) - get summed up with `v`, and that sum should equal `g`.

The numbers aren't exactly powers of 4 because any computer can't accurately represent all numbers, so the numbers were probably rounded to fit whatever floating-point representation the Commodore 64 uses.

Because the values that are being added are all different powers of 4 that when summed should equal the difference between `g` and `v`, this means we're looking for the **base-4 representation** of `(g-v)`.
And because any number in any natural-number base (except base 1) has a unique representation using a finite amount of digits (I think), we can gurantee that if we get a bit-pattern that works, then it is the only one that works.

Note that there are also values of `(g-v)` that won't work with any bit-pattern, because we're dealing with powers of 4, so to be able to represent all numbers all `p` values should be multiplied with a digit between `0` and `3`, and in binary we have just `0` and `1`.
We can just assume this is solveable, otherwise there would be no valid password :P

It's likely that the Commodore 64 and python represent floating point numbers differently, but while hoping that it wouldn't affect much, we can quickly write a script that will get the desired bits:

```python
v = 0.6666666666612316235641 - 0.00000000023283064365386962890625
g = 0.671565706376017
p_values = [
    0.062500000001818989403545856475830078125,
    0.0156250000004547473508864641189575195312,
    0.0039062500001136868377216160297393798828,
    0.0009765625000284217094304040074348449707,
    0.0002441406250071054273576010018587112427,
    0.0000610351562517763568394002504646778107,
    0.0000152587890629440892098500626161694527,
    0.0000038146972657360223024625156540423632,
    0.0000009536743164340055756156289135105908,
    0.0000002384185791085013939039072283776477,
    0.0000000596046447771253484759768070944119,
    0.000000014901161194281337118994201773603,
    0.0000000037252902985703342797485504434007,
]

# this algorithm works because `p_values` are powers of 4 in descending order:

# for each `p` value
for p in p_values:
    # if we won't go over the goal by adding this `p`
    if v + p <= g:
        # then add it, and the next bit should be 1
        v += p
        print(1)
    else:
        # otherwise don't add it, and the next bit should be 0
        print(0)
```

Running this results in the bits `[0,0,1,1,0,0,1,0,1,0,0,1,0]` - looking back on the BASIC code the first bit (which adds the first `p` value) is the LSB in the first password character, and so on.
That means the first character of the password is `0b01001100`, or - capital `L`.
Yay! It's printable and it's a letter! So it's probably right.

We got the first 13 bits of the password from this script, and the first 8 compose the first character, so that leaves 5 bits we have from the second character - `0b???01001`. Assuming this is a letter or a digit, it can only be capital `I` = `0b01001001`.

Great success - the flag is about `CTF{LI????????????????????????????}` (remember the password is of length 30).

## More More Self-Modifying Code

Alright, we know the drill, let's get more bits - the code after the math part is:

```basic
2210 poke 1024 + chkoff + 1, 90
2500 rem
2900 for i = es to ee : k = ( peek(i) + ek ) and 255 : poke i, k : next i
2905 poke 1024 + chkoff + 1, a:poke 55296 + chkoff + 1, b
2910 poke 03397, 00029 : poke 03398, 00020 : goto 2001
```

Well, the loop is there, but I don't see where `es`, `ee`, and `ek` are defined like last time. This means it just uses the same values from before. I seriously doubt that adding `148` a second time will result in valid tokenized BASIC again.

Looking at the `.prg` in a hex editor again, I can still see more readable (not encrypted) code, but there's that `00 00 00 00 8F 00` in the way again. I guess it's either opcodes that `petcat` doesn't recognize (although it has flags to switch the version of BASIC its decoding and one might help), or that the weird `poke` statement at the end is somehow modifying it or skipping it. The easy solution I go with is again - deleting the annoying bytes and re-running `petcat`.

[Success](more_more_more_code.txt), now we got the following:

```basic
2004 es = 05363 : ee = 06632 : ek = 152
2005 for i = es to ee : k = ( peek(i) + ek ) and 255 : poke i, k : next i
```

We know the drill, opening this gives [another one of these floating point math challenges](more_more_more_more_code.txt).

Looks like the pattern is always:

- Delete the `00 00 00 00 8F 00`
- Find the values of `es`, `ee`, and `ek`
- Decode the next part with them

And if we count the spaces in the progress bar:

```
PRINT "[                    ]"
```

there are 20 spaces, so if this pattern continues until the end it will require decoding 19 times. I sure ain't doing it manually.

So let's write [a script to do that](decrypt_entire_prg.py).

It searches for the regex pattern `'ES = (\d+) : EE = (\d+) : EK = (\d+)'` in the `.prg` file (but with tokenized BASIC's `'\xB2'` instead of `'='`), decodes the file accordingly, and then repeats with the next occourence of the pattern, until there are none left.

After its done it deletes all occourences of `00 00 00 00 8F 00`. It's better than doing it while decrypting as we would need to account for the deleted bytes in the offset calculation.

The script takes an input file and an output file, and it prints:

```
Load address: 0x0801
decryption #01: ADDing from 0x0e9d to 0x1375 with 0x94
decryption #02: ADDing from 0x14f3 to 0x19e8 with 0x98
decryption #03: ADDing from 0x1b66 to 0x201b with 0xa5
decryption #04: ADDing from 0x2199 to 0x268c with 0xb8
decryption #05: ADDing from 0x280a to 0x2cdb with 0xc7
decryption #06: ADDing from 0x2e59 to 0x3333 with 0xf0
decryption #07: ADDing from 0x34b1 to 0x39a8 with 0xf9
decryption #08: ADDing from 0x3b26 to 0x3fdf with 0x84
decryption #09: ADDing from 0x415d to 0x4637 with 0xba
decryption #10: ADDing from 0x47b8 to 0x4cb1 with 0xd6
decryption #11: ADDing from 0x4e34 to 0x5311 with 0xf5
decryption #12: ADDing from 0x5494 to 0x598b with 0xcb
decryption #13: ADDing from 0x5b0e to 0x6008 with 0xdf
decryption #14: ADDing from 0x618b to 0x6642 with 0xed
decryption #15: ADDing from 0x67c5 to 0x6cbd with 0xc0
decryption #16: ADDing from 0x6e40 to 0x731f with 0x9d
decryption #17: ADDing from 0x74a2 to 0x797d with 0x9e
decryption #18: ADDing from 0x7b00 to 0x7ff9 with 0xeb
decryption #19: ADDing from 0x817c to 0x863f with 0x8f
deleting weird stuff
```

and we get our [fully decrypted PRG file](decrypted.prg)!

We can now run it through `petcat` and get [the entire BASIC source code](entire_code.txt), woohoo!

## Many, Many Math

If you scroll to the very bottom of the [entire code](entire_code.txt) we got, you'll see the lines:

```basic
31337 t = t0 + t1 + t2 + t3 + t4 + t5 + t6 + t7 + t8 + t9 + ta + tb + tc + td + te + tf + tg + th + tj
31338 if t = -19 then goto 31340
31339 print : print "verdict: nope" : goto 31345
31340 print : print "verdict: correct"
31345 goto 31345
```

If you recall, `t0` is the check of whether `v + p0 + p1 + ... = g`,
so this checks if we got all **19 challenges** right, and then prints `"VERDICT: CORRECT"` if so.

Going through the source it looks like all the 19 challenges are mostly the same:

- They start with some `v` value (not the same for all)
- They check the next 13 bits of the password and add the same powers of 4
- They check we've reached a certain `g` value (again, not the same for all)

Note that 19 challenges that give 13 bits each is 7 bits more than 30 characters, but looking at the last challenge it seems like we don't have control over those final 7 bits (they come from `bx` which isn't defined anywhere), so they're probably just 0 and don't matter to our password.

So we modify our script to get all the `v` and `g` values after it decrypts the PRG, and solve for all of the bits of the password, like we solved the first challenge.

We could also copy the values from the textual output of `petcat` to a separate script but I want to have a script that works given the original attachment and doesn't rely on VICE.

We now have [a script that solves all the challenges and extracts the password](decrypt_and_solve.py)!

The script only takes in an input file, and prints:

```
Load address: 0x0801
decryption #01: ADDing from 0x0e9d to 0x1375 with 0x94
decryption #02: ADDing from 0x14f3 to 0x19e8 with 0x98
decryption #03: ADDing from 0x1b66 to 0x201b with 0xa5
decryption #04: ADDing from 0x2199 to 0x268c with 0xb8
decryption #05: ADDing from 0x280a to 0x2cdb with 0xc7
decryption #06: ADDing from 0x2e59 to 0x3333 with 0xf0
decryption #07: ADDing from 0x34b1 to 0x39a8 with 0xf9
decryption #08: ADDing from 0x3b26 to 0x3fdf with 0x84
decryption #09: ADDing from 0x415d to 0x4637 with 0xba
decryption #10: ADDing from 0x47b8 to 0x4cb1 with 0xd6
decryption #11: ADDing from 0x4e34 to 0x5311 with 0xf5
decryption #12: ADDing from 0x5494 to 0x598b with 0xcb
decryption #13: ADDing from 0x5b0e to 0x6008 with 0xdf
decryption #14: ADDing from 0x618b to 0x6642 with 0xed
decryption #15: ADDing from 0x67c5 to 0x6cbd with 0xc0
decryption #16: ADDing from 0x6e40 to 0x731f with 0x9d
decryption #17: ADDing from 0x74a2 to 0x797d with 0x9e
decryption #18: ADDing from 0x7b00 to 0x7ff9 with 0xeb
decryption #19: ADDing from 0x817c to 0x863f with 0x8f
deleting weird stuff
solved #00: 0.666666666428401 -> 0.671565706376017 by [0, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 1, 0]
solved #01: 0.666666666428401 -> 0.68261235812682 by [0, 1, 0, 0, 1, 1, 1, 0, 0, 1, 0, 1, 1]
solved #02: 0.6666666666612316 -> 0.682552023325146 by [0, 1, 0, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0]
solved #03: 0.666666666428401 -> 0.667647300753773 by [0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 1]
solved #04: 0.6666666666612316 -> 0.68231080332774 by [0, 1, 0, 0, 0, 0, 1, 1, 0, 0, 1, 0, 0]
solved #05: 0.6666666661955704 -> 0.67063873494047 by [0, 0, 1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 0]
solved #06: 0.6666666661955704 -> 0.729427094105661 by [1, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 1, 0]
solved #07: 0.6666666666612316 -> 0.683334092143953 by [0, 1, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 1]
solved #08: 0.666666666428401 -> 0.729182238224924 by [1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 1, 0]
solved #09: 0.6666666671268929 -> 0.682352954987467 by [0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 1]
solved #10: 0.6666666661955704 -> 0.745769257191599 by [1, 1, 0, 1, 0, 0, 0, 0, 1, 0, 1, 1, 0]
solved #11: 0.666666666428401 -> 0.66674321750182 by [0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1]
solved #12: 0.6666666668940623 -> 0.682352764997662 by [0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0]
solved #13: 0.6666666666612316 -> 0.670634204987467 by [0, 0, 1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 1]
solved #14: 0.666666666428401 -> 0.733381925616444 by [1, 0, 1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 1]
solved #15: 0.666666666428401 -> 0.66764801228422 by [0, 0, 0, 1, 0, 0, 0, 1, 1, 0, 0, 1, 0]
solved #16: 0.666666666428401 -> 0.749690691474855 by [1, 1, 1, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0]
solved #17: 0.666666666428401 -> 0.682356773410023 by [0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 1]
solved #18: 0.666666666428401 -> 0.670817057136476 by [0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0]
PASSWORD: b'LINK\x05D-LHSTS\xcdAND.40-BHd-FLOATS'
```

## WE GOT PASSWORD!

So the password is `'LINK\x05D-LHSTS\xcdAND.40-BHd-FLOATS'`.

That looks, well, wrong :O

But it looks like we got close to right - the errors are probably because of different representations of floating point numbers between the Commodore 64 and python.

I searched online for any info on how the C64 represents floating point numbers (it has an 8-bit 6510 processor) so I could emulate it in python, but I could not find anything.

I can write my own BASIC program to run on the VICE emulator that would solve it correcly for me. I guess the VICE emulator has a BASIC tokenizer, but I don't want to write all that logic in BASIC :(

And since there's only 15 minutes left until the CTF ends, let's **guess the password**!

I see `LINKED-LISTS-AND-40-BAD-FLOATS`, but it doesn't work on the CTF website. Maybe `LINKED-LISTS-AND-40-BIG-FLOATS`? Nope.

I run the PRG on the emulator and enter this password, and after waiting 5 minutes (the emulator is slow as hell), I see from the hearts and X's on the progress bar that I only got wrong the "IG" in "BIG".

So I google ["3 letter words that start with B"](https://www.morewords.com/wordsbylength/3b/) and find nothing, so I ask my team and [or523](https://github.com/or523) guesses its "40 **bit** floats", and it works! :)

The flag is `CTF{LINKED-LISTS-AND-40-BIT-FLOATS}` !

## Afterthought

Phew, we got the flag in time, with guessing, but how can I change my script to actually get the correct password?

- TODO: I went over everything until "More Self-Modifying Code", go over the rest
- TODO: add images - Wat, progress bar fail, progress bar success, hex editor, meme "solve all the math"
