---
title: 「CTF」Pwn - ゼロからはじめるPWN生活
date: 2021-11-21 21:51:51
tags: ['CTF', 'Pwn', ]
categories: ['CTF']
authors: [nova]
index_img: https://novanoir.moe/img/ctf_logo_2.png
banner_img: https://novanoir.moe/img/ctf_logo_2.png

---

## 0x10 前言

还是准备系统全面的学习一下PWN，于是记录一下环境安装与基础知识，防止我记完就忘。

<!--truncate-->

## 0x20 环境

### Linux

我一开始用的是wsl2，但是wsl2调用gdb并不理想，具体原因**好像**[^1]是因为wsl2不支持多窗口什么的，所以开不了多个terminal来调试

所以更换了[VMWare Workstation pro 16](https://www.vmware.com/cn/products/workstation-pro/workstation-pro-evaluation.html)

~~使用的是[Ubuntu16.04LTS](https://releases.ubuntu.com/16.04.7/?_ga=2.87612568.127924487.1637498771-872950043.1635429738)中的`ubuntu-16.04.7-desktop-amd64.iso `~~

我死都不想再配一遍Ubuntu16了，所以记录一下Ubuntu20的配置过程。

{% note info %}

~~[ubuntu-16.04.7-desktop-amd64.iso](https://releases.ubuntu.com/16.04.7/ubuntu-16.04.7-desktop-amd64.iso)下载~~

[ubuntu-20.04.3-desktop-amd64.iso](https://releases.ubuntu.com/focal/ubuntu-20.04.3-desktop-amd64.iso)下载

{% endnote %}

#### 初始化

Ubuntu20的安装过程不再赘述

首先进行换源

在[清华大学开源软件镜像站](https://mirror.tuna.tsinghua.edu.cn/help/ubuntu/)中找到Ubuntu20.04 LTS，使用指令

```shell
sudo nano /etc/apt/sources.list
```

并把内容删除并重新输入保存

```shell
# 默认注释了源码镜像以提高 apt update 速度，如有需要可自行取消注释
deb https://mirrors.tuna.tsinghua.edu.cn/ubuntu/ focal main restricted universe multiverse
# deb-src https://mirrors.tuna.tsinghua.edu.cn/ubuntu/ focal main restricted universe multiverse
deb https://mirrors.tuna.tsinghua.edu.cn/ubuntu/ focal-updates main restricted universe multiverse
# deb-src https://mirrors.tuna.tsinghua.edu.cn/ubuntu/ focal-updates main restricted universe multiverse
deb https://mirrors.tuna.tsinghua.edu.cn/ubuntu/ focal-backports main restricted universe multiverse
# deb-src https://mirrors.tuna.tsinghua.edu.cn/ubuntu/ focal-backports main restricted universe multiverse
deb https://mirrors.tuna.tsinghua.edu.cn/ubuntu/ focal-security main restricted universe multiverse
# deb-src https://mirrors.tuna.tsinghua.edu.cn/ubuntu/ focal-security main restricted universe multiverse

# 预发布软件源，不建议启用
# deb https://mirrors.tuna.tsinghua.edu.cn/ubuntu/ focal-proposed main restricted universe multiverse
# deb-src https://mirrors.tuna.tsinghua.edu.cn/ubuntu/ focal-proposed main restricted universe multiverse
```

然后进行一手

```shell
sudo apt-get update
sudo apt-get upgrade
```

这时候却报错证书验证出错

```shell
Err:5 https://mirrors.tuna.tsinghua.edu.cn/ubuntu focal Release
  Certificate verification failed: The certificate is NOT trusted. The certificate chain uses expired certificate.  Could not handshake: Error in the certificate verification. [IP: 101.6.15.130 443]
Err:6 https://mirrors.tuna.tsinghua.edu.cn/ubuntu focal-updates Release
  Certificate verification failed: The certificate is NOT trusted. The certificate chain uses expired certificate.  Could not handshake: Error in the certificate verification. [IP: 101.6.15.130 443]
Err:7 https://mirrors.tuna.tsinghua.edu.cn/ubuntu focal-backports Release
  Certificate verification failed: The certificate is NOT trusted. The certificate chain uses expired certificate.  Could not handshake: Error in the certificate verification. [IP: 101.6.15.130 443]
Err:8 https://mirrors.tuna.tsinghua.edu.cn/ubuntu focal-security Release
  Certificate verification failed: The certificate is NOT trusted. The certificate chain uses expired certificate.  Could not handshake: Error in the certificate verification. [IP: 101.6.15.130 443]
Reading package lists... Done
E: The repository 'https://mirrors.tuna.tsinghua.edu.cn/ubuntu focal Release' does not have a Release file.
N: Updating from such a repository can't be done securely, and is therefore disabled by default.
N: See apt-secure(8) manpage for repository creation and user configuration details.
E: The repository 'https://mirrors.tuna.tsinghua.edu.cn/ubuntu focal-updates Release' does not have a Release file.
```

解决方法：更改源中的`https`为`http`即可

> 更新[官方解决方法](https://github.com/tuna/issues/issues/1342)

推测是 let's encrypt 的 DST Root CA X3 不再被系统信任（过期了）

先将`https`换为`http`

运行

```shell
sudo apt-get update
sudo apt-get install --only-upgrade ca-certificates
```

就可以更新升级ca-certificates了

此时可以再把https换回来



接下来配置一下32位

在16和18中，我使用的命令都是

```shell
sudo apt-get install  lib32ncurses5 lib32z1
```

但是这玩意在20中没了，搜索找到以下代码

```shell
sudo dpkg --add-architecture i386
sudo apt -y install libc6:i386 libstdc++6:i386
sudo apt-get update
sudo apt -y install libncurses5-dev lib32z1
```

(可能把`lib32ncurses5`改成`lib32ncurses5-dev`就可以了吧())

#### Anaconda

在[Anaconda Download](https://www.anaconda.com/products/individual)找到Linux下的`64-Bit(x86) Installer`并下载

安装

```shell
sudo bash Anaconda3-2021.11-Linux-x86_64.sh
# 这里的bash我在Ubuntu18安装的时候使用sh会出Syntax Error: "(" unexpected (expecting ")";不知道20是什么样子的，大概是一样的吧
```

懒得配置一路回车下去就好了



...

然后就忘记让他自动配置环境变量了

```shell
sudo gedit ~/.bashrc
```

输入

```shell
export PATH=~/anaconda3/bin:$PATH # 自行根据安装目录更改
```

保存后输入

```shell
source ~/.bashrc
```

即可

#### Pwntools & Pwndbg

先使用conda创建一个2.7的环境和一个3.9的环境
这边还顺带推荐换一手源

```shell
conda config --add channels https://mirrors.tuna.tsinghua.edu.cn/anaconda/pkgs/free/
conda config --add channels https://mirrors.tuna.tsinghua.edu.cn/anaconda/pkgs/main/
conda config --add channels https://mirrors.tuna.tsinghua.edu.cn/anaconda/cloud/conda-forge/
conda config --add channels https://mirrors.tuna.tsinghua.edu.cn/anaconda/cloud/pytorch/
conda config --set show_channel_urls yes
conda config --set ssl_verify yes
```

（两个版本配置情况相同所以下文只写出3.9的配置过程）

```shell
# 可以自行修改你的环境名称，不再赘述:>
conda create -n py3 python=3.9
conda activate py3

pip install pwntools
conda install -c conda-forge gdb # 必须安装conda的gdb而不能使用自带的

# pwndbg的安装
git clone https://github.com/pwndbg/pwndbg
cd pwndbg
./setup.sh
```

没有git的话自己安一哈就好了嘛，笨比

```shell
sudo apt-get -y install git
```

git换源的话也顺带发一下了:<

```shell
sudo nano /etc/hosts
```

懒得写直接抄了:>

> 在hosts文件内添加以下三条语句
>
> >192.30.255.112  github.com git
> >185.31.16.184    github.global.ssl.fastly.net
> >140.82.112.10 codeload.github.com
>
> IP经常会更新，需要去以下地址查询每行的英文部分后进行更新，如果在以后从GitHub上下载时出现卡顿，也可通过IP更新提速
> https://github.com.ipaddress.com/
>
> 重启网络
>
> > sudo /etc/init.d/networking restart

之后他们更新网络配置这个我并没有成功，提示没有这个指令

右上角直接把网络关了再开就好了（有UI不用，亏辣）



#### pycharm

就补一下桌面图标`Pycharm.desktop`

```shell
[Desktop Entry]
Version=1.0
Type=Application
Name=Pycharm
Icon=/home/nova/pycharm-2021.3/bin/pycharm.png
Exec=/home/nova/pycharm-2021.3/bin/pycharm.sh
MimeType=application/x-py;
Name[en_US]=pycharm
```

至此，基本上能用了，不够用的后面再安装就好了嘛

## 0x30 知识

### 栈

运行时内存上的一个连续片段，内存地址从高到低，压栈时候内存地址变小，退栈时变大。

函数调用时，Caller的状态被保存在栈内（如左），Callee的状态被压入栈顶（如右）

在函数调用结束后，Callee从栈顶弹出，恢复Caller的状态。

![Stack](https://cdn.novanoir.moe/img/v2-8d5649c36458080223084d77abbd554a_r.jpg)

### 寄存器

在32位中，有8个通用寄存器，分别是*eax, ebx, ecx, edx, esi, edi, ebp, esp*

在64位中，有16个通用寄存器，分别是*rax, rbx, rcx, rdx, rsi, rdi, rbp, rsp, r8, r9, ..., r15*

{% note info %}

在64位中，前八个寄存器的低32位仍然可以使用`e_`开头的相应寄存器，后八个的低32位则用d指定

{% endnote %}



![寄存器比较](https://cdn.novanoir.moe/img/20160428232504330)

为了方便入门，无特殊说明，下文中均以32位架构为准。

> EAX: 累加器(Accumulator)，一般用于储存传参，返回值等
>
> EBX: 基地址寄存器(Base Register)
>
> ECX: 计数寄存器(Count Register)，位运算中移位多位和循环/字符串操作时使用
>
> EDX: 数据寄存器(Data Register)
>
> ESI|EDI: 变址寄存器(Index Register)，它们主要用于存放存储单元在段内的偏移量
>
> **EBP**: 基指针寄存器(Base Pointer)，当前堆栈的最后单元（栈底），可以直接存取栈堆数据
>
> **ESI**:  堆栈指针寄存器(Stack Pointer)，指向当前栈顶

![寄存器](https://cdn.novanoir.moe/img/271639137915732.jpg)

在进行函数调用时，一般是嵌套的，同一个时间栈堆里有可能有多个函数信息，每个未完成运行的函数占用一个独立的连续区域，称作栈帧(Stack Frame)。

栈帧的边界由*EBP*和*ESP*界定，*EBP*在栈内位置固定，*ESP*则会随着栈操作而改变。



函数调用时的入栈顺序由图可看出：`实参N~1 -> Caller Return Address -> Callee EBP -> 局部变量1~N  `

![函数调用的典型内存布局](https://cdn.novanoir.moe/img/271644419475745.jpg)

> 其中，主调函数将参数按照调用约定依次入栈(图中为从右到左)，然后将指令指针EIP入栈以保存主调函数的返回地址(下一条待执行指令的地址)。进入被调函数时，被调函数将主调函数的帧基指针EBP入栈，并将主调函数的栈顶指针ESP值赋给被调函数的EBP(作为被调函数的栈底)，接着改变ESP值来为函数局部变量预留空间。此时被调函数帧基指针指向被调函数的栈底。以该地址为基准，向上(栈底方向)可获取主调函数的返回地址、参数值，向下(栈顶方向)能获取被调函数的局部变量值，而该地址处又存放着上一层主调函数的帧基指针值。本级调用结束后，将EBP指针值赋给ESP，使ESP再次指向被调函数栈底以释放局部变量；再将已压栈的主调函数帧基指针弹出到EBP，并弹出返回地址到EIP。ESP继续上移越过参数，最终回到函数调用前的状态，即恢复原来主调函数的栈帧。如此递归便形成函数调用栈。

### 函数调用

 函数调用时的具体步骤如下：

1. 主调函数将被调函数所要求的参数，根据相应的函数调用约定，保存在运行时栈中。该操作会改变程序的栈指针。

   > 注：x86平台将参数压入调用栈中。而x86_64平台具有16个通用64位寄存器，故调用函数时前6个参数通常由寄存器传递，其余参数才通过栈传递。

2. 主调函数将控制权移交给被调函数(使用call指令)。函数的返回地址(待执行的下条指令地址)保存在程序栈中(压栈操作隐含在call指令中)。

3. 若有必要，被调函数会设置帧基指针，并保存被调函数希望保持不变的寄存器值。

4. 被调函数通过修改栈顶指针的值，为自己的局部变量在运行时栈中分配内存空间，并从帧基指针的位置处向低地址方向存放被调函数的局部变量和临时变量。

5. 被调函数执行自己任务，此时可能需要访问由主调函数传入的参数。若被调函数返回一个值，该值通常保存在一个指定寄存器中(如EAX)。

6. 一旦被调函数完成操作，为该函数局部变量分配的栈空间将被释放。这通常是步骤4的逆向执行。

7. 恢复步骤3中保存的寄存器值，包含主调函数的帧基指针寄存器。

8. 被调函数将控制权交还主调函数(使用ret指令)。根据使用的函数调用约定，该操作也可能从程序栈上清除先前传入的参数。

9. 主调函数再次获得控制权后，可能需要将先前的参数从栈上清除。在这种情况下，对栈的修改需要将帧基指针值恢复到步骤1之前的值。

> 压栈(push)：ESP减小4个字节；以字节为单位将寄存器数据(四字节，不足补零)压入堆栈，从高到低按字节依次将数据存入ESP-1、ESP-2、ESP-3、ESP-4指向的地址单元，寄存器原内容不变。

> 出栈(pop)：ESP指向的栈中数据被取回到寄存器；ESP增加4个字节。

![push&pop](https://cdn.novanoir.moe/img/271656343069114.jpg)



## 参考

[C语言函数调用栈(一)](https://www.cnblogs.com/clover-toeic/p/3755401.html)

[手把手教你栈溢出从入门到放弃（上）](https://zhuanlan.zhihu.com/p/25816426)

[64位和32位的寄存器和汇编的比较](https://blog.csdn.net/Nec22019/article/details/73195992)

## 脚注

[^1]: 存疑的消息来源。