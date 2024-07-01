## Week1

During the basic competition, I also worked on miscellaneous blockchain and ioT, but I didn't bother to publish it.

### test_nc

Directly use nc to obtain shell.

### easy_overflow

Stdout is disabled, with a backdoor and stack overflow.

Here, the `exec 1>&0` command is used to redirect output to stdout (see [understanding bash "exec 1>&2" command](https://stackoverflow.com/questions/8888251/understanding-bash-exec-12-command)).

[exp](https://github.com/MuelNova/NovaNo1r-pwn-challenges/blob/main/HGame2023/week1/pwn/easy_overflow/exp.py)

### choose_the_seat

`signed int` type only checks for positive numbers, allowing negative numbers to bypass arbitrary address read/write.

Modify the `exit` GOT table to the `vuln` function address, leak `printf` address for libc calculation in the first round, rewrite `puts` GOT table to get shell in the second round.

[exp](https://github.com/MuelNova/NovaNo1r-pwn-challenges/blob/main/HGame2023/week1/pwn/choose_the_seat/exp.py)

### orw

Stack migration + ORW template question.

[exp](https://github.com/MuelNova/NovaNo1r-pwn-challenges/blob/main/HGame2023/week1/pwn/orw/exp.py)

### simple_shellcode

Shellcode ORW, the program runs `mmap((void *)0xCAFE0000LL, 0x1000uLL, 7, 33, -1, 0LL)` to change permissions, just write here.

[exp](https://github.com/MuelNova/NovaNo1r-pwn-challenges/blob/main/HGame2023/week1/pwn/simple_shellcode/exp.py)



## Week 2

### YukkuriSay

An interesting format string question with the format string on bss. Can leak stack address when Saying.

![image-20230203153007716](https://cdn.ova.moe/img/image-20230203153007716.png)

Then use the below format string to leak canary and libc base, change return address to `vuln` function, but without using the canary.

Then setup `printf` GOT pointer on the stack, change `printf` to `system` and then modify return address to `read(0, str, 0x100uLL)` to set up `/bin/sh\x00` and execute `system('/bin/sh')`.

(I had to look at my own exploit for a long time to understand this, it's really abstract, don't know how fmtstr_payload is used here)

[exp](https://github.com/MuelNova/NovaNo1r-pwn-challenges/blob/main/HGame2023/week2/pwn/YukkuriSay/exp.py)

```python
payload_padding = sorted([('%8$hn', system_addr & 0xffff),	# Modify the last two digits <-> p64(printf_got)
                          ('%9$hhn', (system_addr & 0xff0000) >> 16),	# Modify the third from the end <-> p64(printrf_got+2)
                          ('%10$hn', vuln_read_addr & 0xffff),	# Same...
                          ('%11$hn',((vuln_read_addr & 0xff0000) >> 16)),
                          ('%12$hn', 0)], key=lambda x: x[1])

payload = ''
nums = 0
for i in payload_padding:
    payload += f'%{i[1]-nums}c{i[0]}' if i[1] != nums else f'{i[0]}'
    nums = i[1]

print(hex(payload))
# Can anyone really understand this, but can be reused, written quite well (laughs)
``` 

### editable_note

All the following heap questions are template questions, no pointer cleaning, UAF.

Fill up tcache and conveniently create an unsorted bin to leak libc, then directly change fd to point to `__free_hook` and change it to `system` to get shell.

[exp](https://github.com/MuelNova/NovaNo1r-pwn-challenges/blob/main/HGame2023/week2/pwn/editable_note/exp.py)

### fast_note

Libc 2.23

Fastbin attack Double Free, place a fake chunk at `__malloc_hook-0x23`, use the one_gadget filled in `__realloc_hook`.

After testing, found that the condition for og is not met, modify `__malloc_hook` to realloc to adjust the registers, then modify `__realloc_hook` to the one_gadget.

[exp](https://github.com/MuelNova/NovaNo1r-pwn-challenges/blob/main/HGame2023/week2/pwn/fast_note/exp.py)

### new_fast_note

Libc 2.31

Fill up tcache and leak libc using unsorted bin.

Utilize the concept of heap chunk overlap to modify tcache fd to `__free_hook`.

> We first fill the 7 bin size 0x90
>
> | idx  | size | type            |
> | ---- | ---- | --------------- |
> | ...  | 0x90 | tcache_bin      |
> | 7    | 0x90 | allocated_chunk |
> | 8    | 0x90 | unsorted_bin    |
>
> At this point, when we free *7*, it will merge with *8* to form a new unsorted_bin
>
> If we take out a chunk of the same size again, it will take from the linked list of 0x90 tcache.
>
> Now, if we free *8* again, it will link to the 0x90 tcache list.
>
> Finally, when we take out a chunk >= 0xB0, it will start from the address of *7*, including what we need, which naturally includes parts of *8* such as `prev_size`, `size`, `fd`, `bk`, etc.

I actually overcomplicated this (I thought it would still check if `notes[i]` exists like before, but after calculating I found it's not enough). Simply create a double_free in fastbin, then clear tcache to put fastbin into tcache and directly retrieve it.

[exp](https://github.com/MuelNova/NovaNo1r-pwn-challenges/blob/main/HGame2023/week2/pwn/new_fast_note/exp.py)



## Week3

### safe_note

Bybass the Safe-unlinking mechanism of 2.32, but still a template question. In short, it encrypts the fd pointer, the process is as follows:

`e->next = &e->next >> 12 ^ tcache->entries[tc_idx]`

When the first tcache is put in, `tcache->entries[tc_idx]` is 0, so we only need to leak the fd of the first tcache_chunk, left shift by 12 bits to leak the heap_base.

Then, when modifying fd, perform encryption `fd = &e->next >> 12 ^ fd`

After that, it's just a template question for tcache poisoning.

[exp](https://github.com/MuelNova/NovaNo1r-pwn-challenges/blob/main/HGame2023/week3/pwn/safe_note/exp.py)

### large_note

2.32, exploit largebin attack to write a very large value at `&mp_+80`, where it is the location of `.tcache_bins = TCACHE_MAX_BINS,` in the `mp_` structure.

Similar to `global_max_fast`, once changed, proceed with the same steps as safe_note.

[exp](https://github.com/MuelNova/NovaNo1r-pwn-challenges/blob/main/HGame2023/week3/pwn/large_note/exp.py)

### note_context

2.32, use the `setcontext+61` gadget to achieve ORW.

Since `setcontext` now uses the rdx register, utilize a magic_gadget as well.

``` assembly
mov rdx, qword ptr [rdi + 8]
mov qword ptr [rsp], rax
call qword ptr [rdx + 0x20];
```

[exp](https://github.com/MuelNova/NovaNo1r-pwn-challenges/blob/main/HGame2023/week3/pwn/note_context/exp.py)



## Week4

### without_hook

Version 2.36, bypass larginbin to hit the IO structure. Used [house_of_cat](https://bbs.kanxue.com/thread-273895.htm) exploit chain, but can also use apple's.

[exp](https://github.com/MuelNova/NovaNo1r-pwn-challenges/blob/main/HGame2023/week4/pwn/without_hook/exp.py)

### 4nswer's gift

Version 2.36

Write the heap address directly at `_IO_list_all`, and print out the libc address. Then use `exit` to trigger `_IO_flush_all_lockp` for FSOP, but since there is no heap address, the chains cannot be utilized.

Initially noticed that size 0 can cause heap overflow, pondered using IO to leak heap address, but couldn't control the program flow, got stuck for a long time.

Later, ayoung said just malloc a very large value, and suddenly remembered that `sysmalloc` will open a new memory near libc, and this offset is unlikely to change.

After testing, it indeed worked, then continue to hit the IO.

[exp](https://github.com/MuelNova/NovaNo1r-pwn-challenges/blob/main/HGame2023/week4/pwn/4nswer's%20gift/exp.py)

<!-- AI -->
