---

title: 「PWN」【HGAME2023】 Pwn WP
tags: ['CTF', 'Pwn', ]
categories: ['CTF']
authors: [nova]
---

附件 及 exp: [HGAME2023](https://github.com/Nova-Noir/NovaNo1r-pwn-challenges/tree/main/HGame2023)

官方 exp: [HGAME2023_Writeup](https://github.com/vidar-team/HGAME2023_Writeup)

<!--truncate-->

## Week1

基础赛，misc blockchain ioT 啥的也做了一下，但是懒得发了。

### test_nc

直接 nc 拿 shell

### easy_overflow

关闭了 stdout，有后门，有栈溢出。

这里使用 `exec 1>&0 ` 命令将输出重定向到 stdout（see [understanding bash "exec 1>&2" command](https://stackoverflow.com/questions/8888251/understanding-bash-exec-12-command)）

[exp](https://github.com/Nova-Noir/NovaNo1r-pwn-challenges/blob/main/HGame2023/week1/pwn/easy_overflow/exp.py)

### choose_the_seat

`signed int` 类型只检查了正数，存在负数绕过任意地址读写。

改写 `exit` GOT 表为`vuln` 函数地址，第一遍泄露 `printf` 地址算 libc，第二遍改写 `puts` GOT 表拿 shell

[exp](https://github.com/Nova-Noir/NovaNo1r-pwn-challenges/blob/main/HGame2023/week1/pwn/choose_the_seat/exp.py)

### orw

栈迁移 + ORW 模板题

[exp](https://github.com/Nova-Noir/NovaNo1r-pwn-challenges/blob/main/HGame2023/week1/pwn/orw/exp.py)

### simple_shellcode

shellcode ORW，程序运行了 `mmap((void *)0xCAFE0000LL, 0x1000uLL, 7, 33, -1, 0LL)` 改写了权限，直接在这里写就好。

[exp](https://github.com/Nova-Noir/NovaNo1r-pwn-challenges/blob/main/HGame2023/week1/pwn/simple_shellcode/exp.py)



## Week 2

### YukkuriSay

挺有意思的格式化字符串题，格式化字符串在 bss 上。在 Say 的时候可以泄露栈的地址。

![image-20230203153007716](https://cdn.novanoir.moe/img/image-20230203153007716.png)

然后下面格式化字符串用于泄露 canary 和 libc 基址，修改返回地址到 `vuln` 函数，不过没用上 canary 就是了。

之后在栈上布置 `printf` GOT 的指针，改 `printf` 为 `system` 然后再修改返回地址到 `read(0, str, 0x100uLL)` 这里布置 `/bin/sh\x00` 执行 `system('/bin/sh')`

（我看了好久我这个 exp 才看懂，这个写的真抽象，不知道 fmtstr_payload 在这里面怎么用了）

[exp](https://github.com/Nova-Noir/NovaNo1r-pwn-challenges/blob/main/HGame2023/week2/pwn/YukkuriSay/exp.py)

```python
payload_padding = sorted([('%8$hn', system_addr & 0xffff),	# 修改最后两位 <-> p64(printf_got)
                          ('%9$hhn', (system_addr & 0xff0000) >> 16),	# 修改倒数第三位 <-> p64(printrf_got+2)
                          ('%10$hn', vuln_read_addr & 0xffff),	# 举一反三...
                          ('%11$hn',((vuln_read_addr & 0xff0000) >> 16)),
                          ('%12$hn', 0)], key=lambda x: x[1])

payload = ''
nums = 0
for i in payload_padding:
    payload += f'%{i[1]-nums}c{i[0]}' if i[1] != nums else f'{i[0]}'
    nums = i[1]

print(hex(payload))
# 真的有人看得懂吗，不过倒是可以复用，写的挺好的（笑
```

### editable_note

接下来的堆题就全是模板题了，没清指针，UAF。

填满 tcache 顺手造个 unsorted_bin 泄露 libc，然后直接改 fd 连到 __free_hook 上改 system 拿 shell

[exp](https://github.com/Nova-Noir/NovaNo1r-pwn-challenges/blob/main/HGame2023/week2/pwn/editable_note/exp.py)

### fast_note

libc 2.23

Fastbin attack Double Free，在 `__malloc_hook-0x23` 的地方布置 fake chunk，在 __malloc_hook 处填充 one_gadget。

测试之后发现不满足 og 的条件，修改 __malloc_hook 为 realloc 调整寄存器，修改 \_\_realloc_hook 为 one_gadget

[exp](https://github.com/Nova-Noir/NovaNo1r-pwn-challenges/blob/main/HGame2023/week2/pwn/fast_note/exp.py)

### new_fast_note

libc 2.31

填满 tcache 之后利用 unsorted_bin 泄露 libc。

利用堆块重叠的思想，修改 tcache 的 fd 为 __free_hook。

> 我们首先填充 0~6 这 7 个 0x90 大小的 tcache
>
> | idx  | size | type            |
> | ---- | ---- | --------------- |
> | ...  | 0x90 | tcache_bin      |
> | 7    | 0x90 | allocated_chunk |
> | 8    | 0x90 | unsorted_bin    |
>
> 此时我们将 *7* free 掉，它会与 *8* 一起合并成新的 unsorted_bin
>
> 我们再取出一个相同大小的 chunk，则会从 0x90 大小的 tcache 链表上取出一个。
>
> 此时，如果我们再 free 一次 *8*，则它会链入 0x90 大小的 tcache 上
>
> 我们再取出一个 >= 0xB0 大小的 chunk，它会从 *7* 所在的地址开始，取出我们所要的大小，其中自然也包括了 *8* 的 `prev_size`、`size`、`fd`、`bk` 等



当然，这里其实是我想复杂了（我以为还是像前面一样在 add 的时候会检查 `notes[i]` 存不存在，一算发现不够）。直接在 fastbin 里造个 double_free 然后清空 tcache 即可将 fastbin 放入 tcache，直接拿就好了。

[exp](https://github.com/Nova-Noir/NovaNo1r-pwn-challenges/blob/main/HGame2023/week2/pwn/new_fast_note/exp.py)



## Week3

### safe_note

2.32 的 Safe-unlinking 机制的绕过，不过依旧是模板题。简而言之，它会把 fd 指针进行加密，流程如下：

`e->next = &e->next >> 12 ^ tcache->entries[tc_idx]`

我们放入第一个 tcache 时， `tcache->entries[tc_idx] ` 为 0，所以我们只需要将第一个 tcache_chunk 的 fd 泄露，左移 12 位即可泄露出 heap_base

之后修改 fd 的时候进行一个加密就好 `fd = &e->next >> 12 ^ fd`

之后的就是 tcache poisoning 模板题

[exp](https://github.com/Nova-Noir/NovaNo1r-pwn-challenges/blob/main/HGame2023/week3/pwn/safe_note/exp.py)

### large_note

2.32，利用 largebin attack 将 `&mp_+80` 的地方写入一个很大的值，这里是 `mp_` 结构体里 `.tcache_bins = TCACHE_MAX_BINS,` 的地方。

功效类似于 `global_max_fast`，改了之后打和 safe_note 一样打就好。

[exp](https://github.com/Nova-Noir/NovaNo1r-pwn-challenges/blob/main/HGame2023/week3/pwn/large_note/exp.py)

### note_context

2.32，利用 `setcontext+61` 的 gadget 实现 ORW

因为现在 `setcontext` 用的是 rdx 寄存器，所以还利用了一个 magic_gadget

``` assembly
mov rdx, qword ptr [rdi + 8]
mov qword ptr [rsp], rax
call qword ptr [rdx + 0x20];
```

[exp](https://github.com/Nova-Noir/NovaNo1r-pwn-challenges/blob/main/HGame2023/week3/pwn/note_context/exp.py)



## Week4

### without_hook

2.36 版本，larginbin 打 IO 结构体。用了 [house_of_cat](https://bbs.kanxue.com/thread-273895.htm) 这个链子，当然用 apple 啥的也行。

[exp](https://github.com/Nova-Noir/NovaNo1r-pwn-challenges/blob/main/HGame2023/week4/pwn/without_hook/exp.py)

### 4nswer's gift

2.36 版本

直接在 `_IO_list_all` 这里写了堆地址，并且打印出了 libc 地址。然后 `exit` 触发 `_IO_flush_all_lockp` 可以进行 FSOP，但是因为没有堆地址所以链子都用不上。

一开始注意到 size 为 0 可以堆溢出，思考利用 IO 泄露堆地址，但是又不能控制程序流，卡了很久。

后来 ayoung 说 malloc 一个很大的值就可以了，思考一下想起来应该是 `sysmalloc` 重新开了一个内存，会落在 libc 附近，这个偏移应该是不会变的。

测试之后确实如此，那就直接继续打 IO 就好。

[exp]()
