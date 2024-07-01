# 「PWN」【DASCTF2023 Binary Specialization June】Writeup WP Reproduction

This PWN challenge is of high quality, but there were too many tasks and I was busy preparing for an exam, so I didn't spend much time on it. Here is a brief reproduction.

## a_dream

This is a challenge involving stack migration in multithreading.

Key points:

- The sandbox opened by the main thread after creating a sub-thread does not affect the sub-thread.
- The stack of the sub-thread is allocated using `mmap`, with the same offset as libc.
- Both the sub-thread and the parent thread use the same GOT / PLT table.

Attack train of thought:

1. Migrate the stack to `bss`, and change the `write` function's GOT entry to the `read` function in the parent thread.
2. Utilize `puts` to leak libc information, and then obtain the sub-thread stack address.
3. Perform ret2libc attack.

Points to note:

- After modifying the `write` GOT entry, we can only overflow by 0x10 bytes; however, at this point, the place of `rbp - 0x10` coincides with the return address of the `read` function. Therefore, we can control up to 0x20 bytes, which is enough to write `pop rdi + got['puts'] + plt['puts'] + magic_read`.
- Even after obtaining the sub-thread stack address from the libc address, `magic_read` can still only overflow by 0x10 bytes, so we need to migrate to the high address of the stack.

Points of confusion:

- ~~After modifying the `write` GOT entry, because the `write` function is called every 1 second (waiting for stdin input), I'm not sure if it's a pwndbg issue or constantly being interrupted, so I can only break at that point. I can't use `si/n/c`, as they will crash, making debugging very complex. Later on, I had to rely on continuously changing the breakpoint position to step through the code (laughs)~~

  Set GDB `set scheduler-locking step` to resolve this issue.

Exploit script (not suitable for remote, using local libc 2.35):

[Translated Python script...]

![image-20230623124315352](https://cdn.ova.moe/img/image-20230623124315352.png)

<!-- AI -->
