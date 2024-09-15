---
title: 「Rust Kernel」从 0 开始造一个内核
authors: [nova]
tags: [kernel, rust]
date: 2024-09-12
last_update:
  author: nova
  date: 2024-09-15

---

## 在此之前

我们会在 [rCore](https://github.com/rcore-os/rCore-Tutorial-v3) 的基础上，完成我们自定义的内核。

我们使用 Docker 版本进行开发

即

```bash
make docker
```

你可能需要的一些知识前置：

- 操作系统

- Rust

- RISC-V ISA

<!--truncate-->

## 0x00、How OS Binary Works

简单来说，OS 之所以能作为 OS，就是因为它直接与裸机（Bare-metal）进行交互，而不依赖于任何标准库。

```bash
root@dd6bc06ddb03:/mnt/novaos# rustc --version -v
rustc 1.80.0-nightly (f705de596 2024-04-30)
binary: rustc
commit-hash: f705de59625bb76067a5d102edc1575ff23b8845
commit-date: 2024-04-30
host: x86_64-unknown-linux-gnu
release: 1.80.0-nightly
LLVM version: 18.1.4
```

至于什么是标准库，我觉得可以把它理解为 OS < - > App 之间的再一层抽象，用于在 OS 提供的函数的抽象上再进一步抽象成用户库函数，例如上述里的 host 中的 linux-gnu 的 GNU，就是在 Linux Kernel 上再抽象出一个 libc 来，从而在用户态提前的对一些系统调用进行包装、检查等。

> All problems in computer science can be solved by another level of indirection@David Wheeler

例如 [unix 的 stdio.rs](https://github.com/rust-lang/rust/blob/master/library/std/src/sys/pal/unix/stdio.rs)，以及 [windows 的 stdio.rs](https://github.com/rust-lang/rust/blob/master/library/std/src/sys/pal/windows/stdio.rs)，便是不同系统的不同包装，而在这层之上，还有一层运行时库的包装，例如 `GNU` 和 `musl` 便是两个不同的 runtime library，它们便可能在封装细节上有区别，因此要对它们做分别的规定。



因此，如果我们想要制作一个操作系统，那么我们就不能使用 runtime library，也不能指定操作系统 —— 这也意味着我们不能使用大多数 rust 提供的封装 —— rust 就像是运行时库的再上一层抽象，它把运行时库再进行抽象包装。

幸运的是，rust 作为一门面向操作系统的语言，它还有一个 `core` 库，它是几乎与操作系统无关的，主要用于实现 rust 的一些算术操作、错误处理、迭代器等特征

因此，在开发 rust os 的时候，我们显然需要使用 `#![no_std]` 来禁用 std。



## 0x01、My First Bare-Metal Binary

我们接下来将会基于 riscv 进行开发，因此让我们添加 riscv 的 toolchain 以及设置默认 build config

```bash
rustup target add riscv64gc-unknown-none-elf
mkdir .cargo
echo -e "[build]\ntarget = \"riscv64gc-unknown-none-elf\"" > .cargo/config.toml
```

:::info riscv64gc-unknown-none-elf 代表什么？

我们可以给出另一个 target 名称：`x86_64-unknown-linux-gnu`，现在你应该能够理解了这个名称了

`riscv64gc` 是指令集的名称，它是 riscv 的 64 位，拓展了 GC 两个指令集（i.e. 基本整数指令集 I，再加上整数乘除法指令集 M，原子指令集 A，单双精度浮点数指令集 F/D（IMAFD 共同构成了指令集 G），以及压缩指令拓展集 C）

`unknown` 则代表 CPU 厂商未知

`none` 则代表没有操作系统

`elf` 则代表没有运行时库

:::

现在，按照我们上面所说，我们创建一个新的操作系统

```bash
cargo new --bin novaos
```

我们简单将 `println!` macro 去掉，并增加 `#![no_std]` shebang。

```rust
#![no_std]

fn main() {
}

```

结果报错了，嘿嘿

```bash
   Compiling novaos v0.1.0 (/mnt/novaos)
error: `#[panic_handler]` function required, but not found

error: could not compile `novaos` (bin "novaos") due to 1 previous error
```

提示我们需要一个 panic_handler，但是没得 panic_handler

因此我们显然需要自己实现一个 panic_handler，观察原本的 panic_handler，把它的函数签名拿过来，我们直接循环就完事了 —— 这何尝不是一种 panic handling 呢 —— 只要无限循环不就不会再出错了（笑）

```rust title="src/lang_items.rs"
#[panic_handler]
fn panic_handler(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
```

接下来，继续修改 `main.rs`，添加这个 submodule

```rust title="src/main.rs"
#![no_std]

mod lang_items;

fn main() {
}
```

然后还是报错噢：

```bash
  Compiling novaos v0.1.0 (/mnt/novaos)
error: using `fn main` requires the standard library
  |
  = help: use `#![no_main]` to bypass the Rust generated entrypoint and declare a platform specific entrypoint yourself, usually with `#[no_mangle]`

error: could not compile `novaos` (bin "novaos") due to 1 previous error
```

它和我们说，用 `fn main` 作为入口点就需要一个标准库 —— 回想 GNU 下的运行，它会利用 `__start` 和 `__libc_start_main `来做初始化，包括设定程序 envp envc 以及一些随机值等等，因此这个也是能够理解的。

好嘛，继续改呗，按着他的提示，我们可以写出以下代码

```rust title="src/main.rs"
#![no_std]
#![no_main]

mod lang_items;

#[no_mangle]
fn _start() -> ! {
    loop {}
}

```

编译成功了！虽然它完全跑不起来，哈哈。

## 0x02、Run My First Bare-Metal Binary (AKA OS) using QEMU

残存着一点点对 [jyy OS](https://jyywiki.cn/OS/2024/) 课程的印象，我们仍然能记得，硬件起电后，固件会设置 PC 到固定的地址找 bootloader，然后 bootloader 做完初始化后又会跳到某个固定的地址起内核。

因此，显然我们需要一个 bootloader 来加载我们的内核，[rustsbi](https://github.com/rustsbi/rustsbi) 可以满足我们的要求，我们可以在 rCore 的 bootloader 文件夹下找到它。



我们简单更新一下我们的内核代码，使其将 `t0` 寄存器一直自加

```rust title="src/main.rs"
#![no_std]
#![no_main]

mod lang_items;


core::arch::global_asm!(
    ".section .text",
    ".global _start",
    "_start:",
        "li t0, 0",
        "1:",
        "addi t0, t0, 1",
        "j 1b"
);

```

简单编译一下，我们用 `readelf` 观察它的段：

```bash
root@dd6bc06ddb03:/mnt/novaos# readelf -S target/riscv64gc-unknown-none-elf/release/novaos
There are 7 section headers, starting at offset 0x2f0:

Section Headers:
  [Nr] Name              Type             Address           Offset
       Size              EntSize          Flags  Link  Info  Align
  [ 0]                   NULL             0000000000000000  00000000
       0000000000000000  0000000000000000           0     0     0
  [ 1] .text             PROGBITS         0000000000011158  00000158
       0000000000000006  0000000000000000  AX       0     0     2
```

可以看到，.text 段在 0x11158 的位置，一般来说，qemu 会把内核放在 `0x80200000` 的位置，这就导致我们 RustSBI 没有办法启动内核 —— `0x80200000` 的位置只有一些 bytes

![image-20240915165446361](https://oss.nova.gal/img/image-20240915165446361.png)

那么这就是链接器要做的一些事情了，我们使用链接脚本来固定这些位置
```ld title="src/linker.ld"
OUTPUT_ARCH(riscv)
ENTRY(_start)

SECTIONS {
    . = 0x80200000;

    .text : {
        *(.text._start)
        *(.text*)
    }
}
```

这里，`.` 设定了程序起始地址，并且将 `_start` 作为入口点

接着，我们设置 Compiler Flag 使其使用我们的链接脚本

```toml title=".cargo/config.toml"
[build]
target = "riscv64gc-unknown-none-elf"

 [target.riscv64gc-unknown-none-elf]
 rustflags = [
     "-Clink-arg=-Tsrc/linker.ld"
 ]
```

再次编译，啊哈，.text 已经设置好了！

```bash
root@5e14f37e4db2:/mnt/novaos# readelf -S target/riscv64gc-unknown-none-elf/release/novaos
There are 7 section headers, starting at offset 0x1198:

Section Headers:
  [Nr] Name              Type             Address           Offset
       Size              EntSize          Flags  Link  Info  Align
  [ 0]                   NULL             0000000000000000  00000000
       0000000000000000  0000000000000000           0     0     0
  [ 1] .text             PROGBITS         0000000080200000  00001000
       0000000000000006  0000000000000000  AX       0     0     2
```



我们直接编写一个 Makefile 来方便测试一下

```makefile
run:
	@echo "Running the application..."
	qemu-system-riscv64 \
		-M virt \
		-nographic \
		-bios ../bootloader/rustsbi-qemu.bin \
		-kernel target/riscv64gc-unknown-none-elf/release/novaos \
		-s -S

dbg:
	@echo "Debugging the application..."
	riscv64-unknown-elf-gdb \
    	-ex 'file target/riscv64gc-unknown-none-elf/release/novaos' \
    	-ex 'set arch riscv:rv64' \
    	-ex 'target remote localhost:1234'
```

```bash
# Session 1
make run

# Session 2
make dbg
```

一进来我们就到了 `0x1000` 的位置，这是 firmware 相关的东西，紧接着他就会到 `0x80000000` 开始跑 rustsbi 的东西，紧接着，开始跳转！

好吧也不紧接着，我 si 了一会还是没到，直接 `b *0x80200000` 了

![image-20240915171734319](https://oss.nova.gal/img/image-20240915171734319.png)

可以看到也是非常成功，那么我们的内核就搭建完成了，也是可以给这篇文章划上一个句号了...吗？



如果你简单思考一下，你就会发现我们 rust 的作用约等于无，内核还是我用 asm 来写的啊？那我用 python 都能搞一个内核出来，这不骗哥们吗？



好吧，于是怀着这种怨念，我们进入下一部分，让我们的内核有更多功能，支持函数调用。



