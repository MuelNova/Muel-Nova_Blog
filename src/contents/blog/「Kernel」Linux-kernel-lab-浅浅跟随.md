---
title: 「Kernel」Linux kernel lab 浅浅跟随
authors: [nova]
tags: [kernel]
date: 2024-07-14
last_update:
  author: nova
  date: 2024-07-22
---

## 在此之前

在这篇文章中，我们将跟随 [Linux Kernel Teaching](https://linux-kernel-labs.github.io/refs/heads/master/index.html)，进行由浅入深的内核学习，以适应未来（可能出现的）内核开发工作。

值得注意的是，这个课程也拥有 [中文版本](https://linux-kernel-labs-zh.xyz/index.html)，你可以在 [linux-kernel-labs-zh/docs-linux-kernel-labs-zh-cn](https://github.com/linux-kernel-labs-zh/docs-linux-kernel-labs-zh-cn) 进行 star 以支持他们的工作。



在接下来的博客中，我可能仅对 课程 部分进行简述，重复抄写已有内容而不加自己的思考总是没有意义的。我们的重点将放在 实验 部分。

<!--truncate-->

## 基础设施

在这一节中，我们将准备实验环境。我使用 WSL2 内的 Docker 作为实验环境，这无疑是非常方便的。

```bash
curl -LO https://raw.githubusercontent.com/linux-kernel-labs-zh/so2-labs/main/local.sh
chmod +x ./local.sh
sudo ./local.sh docker interactive
```

之后，通过设置环境变量 `LABS`，使用 `make skels` 即可生成不同的实验骨架。例如：

```bash
root@MuelNova-Laptop:/linux/tools/labs# LABS=kernel_modules make skels -j$(nproc)
mkdir -p skels
cd templates && find kernel_modules -type f | xargs ./generate_skels.py --output ../skels --todo 0
skel kernel_modules/5-oops-mod/oops_mod.c
skel kernel_modules/5-oops-mod/Kbuild
skel kernel_modules/3-error-mod/err_mod.c
skel kernel_modules/3-error-mod/Kbuild
skel kernel_modules/1-2-test-mod/hello_mod.c
skel kernel_modules/1-2-test-mod/Kbuild
skel kernel_modules/9-dyndbg/dyndbg.c
skel kernel_modules/9-dyndbg/Kbuild
skel kernel_modules/8-kdb/hello_kdb.c
skel kernel_modules/8-kdb/Kbuild
skel kernel_modules/7-list-proc/list_proc.c
skel kernel_modules/7-list-proc/Kbuild
skel kernel_modules/4-multi-mod/mod1.c
skel kernel_modules/4-multi-mod/mod2.c
skel kernel_modules/4-multi-mod/Kbuild
skel kernel_modules/6-cmd-mod/cmd_mod.c
skel kernel_modules/6-cmd-mod/Kbuild
rm -f skels/Kbuild
root@MuelNova-Laptop:/linux/tools/labs# ls skels/kernel_modules/
1-2-test-mod  3-error-mod  4-multi-mod  5-oops-mod  6-cmd-mod  7-list-proc  8-kdb  9-dyndbg
```

具体说明可以看 https://github.com/linux-kernel-labs-zh/so2-labs

### VS-Code 开发环境

我建立了一个 vsc 的环境。首先 VSC 可以直接用 dev contained 连容器，然后装 clangd

#### Method1

在容器环境里，装 clang 和 bear

```bash
root@MuelNova-Laptop:/linux# apt install -y bear clang
```

之后生成 `compile_commands.json`

```bash
root@MuelNova-Laptop:/linux# bear make CC=clang
```

然后打开 remote 的 settings.json，加这么一句

```json
{
    "clangd.arguments": [
        // highlight-next-line
        "--compile-commands-dir=/linux"
    ]
}
```



注意你需要再重新 make 一下，不然里面环境就炸了。

#### Method2

下起来太麻烦了，直接创一个 compile_commands.json

写入

```json
[
    {
        "arguments": [
            "clang",
            "-c",
            "-Wp,-MMD,scripts/mod/.empty.o.d",
            "-nostdinc",
            "-isystem",
            "/usr/lib/llvm-10/lib/clang/10.0.0/include",
            "-I./arch/x86/include",
            "-I./arch/x86/include/generated",
            "-I./include",
            "-I./arch/x86/include/uapi",
            "-I./arch/x86/include/generated/uapi",
            "-I./include/uapi",
            "-I./include/generated/uapi",
            "-include",
            "./include/linux/kconfig.h",
            "-include",
            "./include/linux/compiler_types.h",
            "-D__KERNEL__",
            "-Qunused-arguments",
            "-fmacro-prefix-map=./=",
            "-Wall",
            "-Wundef",
            "-Werror=strict-prototypes",
            "-Wno-trigraphs",
            "-fno-strict-aliasing",
            "-fno-common",
            "-fshort-wchar",
            "-fno-PIE",
            "-Werror=implicit-function-declaration",
            "-Werror=implicit-int",
            "-Werror=return-type",
            "-Wno-format-security",
            "-std=gnu89",
            "-no-integrated-as",
            "-Werror=unknown-warning-option",
            "-mno-sse",
            "-mno-mmx",
            "-mno-sse2",
            "-mno-3dnow",
            "-mno-avx",
            "-m32",
            "-msoft-float",
            "-mregparm=3",
            "-freg-struct-return",
            "-fno-pic",
            "-mstack-alignment=4",
            "-march=i686",
            "-Wa,-mtune=generic32",
            "-ffreestanding",
            "-Wno-sign-compare",
            "-fno-asynchronous-unwind-tables",
            "-mretpoline-external-thunk",
            "-fno-delete-null-pointer-checks",
            "-Wno-address-of-packed-member",
            "-O2",
            "-Wframe-larger-than=1024",
            "-fstack-protector-strong",
            "-Wno-format-invalid-specifier",
            "-Wno-gnu",
            "-mno-global-merge",
            "-Wno-unused-const-variable",
            "-fno-omit-frame-pointer",
            "-fno-optimize-sibling-calls",
            "-g",
            "-gdwarf-4",
            "-Wdeclaration-after-statement",
            "-Wvla",
            "-Wno-pointer-sign",
            "-Wno-array-bounds",
            "-fno-strict-overflow",
            "-fno-stack-check",
            "-Werror=date-time",
            "-Werror=incompatible-pointer-types",
            "-fcf-protection=none",
            "-Wno-initializer-overrides",
            "-Wno-format",
            "-Wno-sign-compare",
            "-Wno-format-zero-length",
            "-Wno-tautological-constant-out-of-range-compare",
            "-DKBUILD_MODFILE=\"scripts/mod/empty\"",
            "-DKBUILD_BASENAME=\"empty\"",
            "-DKBUILD_MODNAME=\"empty\"",
            "-o",
            "scripts/mod/empty.o",
            "scripts/mod/empty.c"
        ],
        "directory": "/linux",
        "file": "scripts/mod/empty.c"
    }
]
```



然后打开 remote 的 settings.json，加这么一句

```json
{
    "clangd.arguments": [
        // highlight-next-line
        "--compile-commands-dir=/linux/tools/lab"
    ]
}
```

## Kernel Modules

> https://linux-kernel-labs-zh.xyz/labs/kernel_modules.html

### 实验目标

- [x] 创建简单的模块
- [x] 描述内核模块编译的过程
- [x] 展示如何在内核中使用模块
- [x] 简单的内核调试方法

### 0. 引言

> 使用 cscope 或 LXR 在 Linux 内核源代码中查找以下符号的定义：
>
> - `module_init()` 和 `module_exit()`
>   这两个宏的作用是什么？ `init_module` 和 `cleanup_module` 是什么？
> - `ignore_loglevel`
>   这个变量用于什么？

Docker 已经配好了虚拟机，所以可以直接用 cscope 来搜。

```bash
vim -t module_init
```

但是这样搜出来的都是引用而不是定义，所以我们还是用 [Linux source code (v6.9.9) - Bootlin](https://elixir.bootlin.com/linux/latest/source) 搜吧

```c
/* Each module must use one module_init(). */
#define module_init(initfn)					\
	static inline initcall_t __maybe_unused __inittest(void)		\
	{ return initfn; }					\
	int init_module(void) __copy(initfn)			\
		__attribute__((alias(#initfn)));		\
	___ADDRESSABLE(init_module, __initdata);

/* This is only required if you want to be unloadable. */
#define module_exit(exitfn)					\
	static inline exitcall_t __maybe_unused __exittest(void)		\
	{ return exitfn; }					\
	void cleanup_module(void) __copy(exitfn)		\
		__attribute__((alias(#exitfn)));		\
	___ADDRESSABLE(cleanup_module, __exitdata);

#endif
```

宏真是难看。这里定义了一个 __inittest 函数，返回我们传入的 initfn 指针，在模块插入后作为入口函数调用。之后，它定义了一个 int 类型的函数 init_module，这里 `__copy` 宏设置了 `__copy__` 属性，同时设置了别名为 #initfn，这些用于给编译器提供信息。

`module_exit` 也是类似，我们不再解释。



对于 `ignore_loglevel`，字面意义，就是忽略日志等级，全部输出。

```c
static bool __read_mostly ignore_loglevel;

static bool suppress_message_printing(int level)
{
	return (level >= console_loglevel && !ignore_loglevel);
}
```



### 1. 内核模块

> 使用 make console 启动虚拟机，并执行以下任务：
>
> - 加载内核模块。
> - 列出内核模块并检查当前模块是否存在。
> - 卸载内核模块。
> - 使用 dmesg 命令查看加载/卸载内核模块时显示的消息。

首先我们生成骨架

```bash
LABS=kernel_modules make skels
```

注意有一个 skels 是 error-mod，意味着它有错误，因此我们先去删除它，等到后面修复了我们再生成它。

```bash
root@MuelNova-Laptop:/linux/tools/labs# rm skels/kernel_modules/3-error-mod/ -r
root@MuelNova-Laptop:/linux/tools/labs# make build
root@MuelNova-Laptop:/linux/tools/labs# make console
```

按理来说 make console 就可以直接进入了，但是我按回车没用。于是我们先 make copy 将驱动复制进入虚拟机，make boot 生成虚拟机，然后再手动连接

```bash
# tmux 1
make boot
# tmux 2
minicom -D serial.pts
# <回车>
Poky (Yocto Project Reference Distro) 2.3 qemux86 /dev/hvc0

qemux86 login: root
```

![image-20240714220741790](https://cdn.ova.moe/img/image-20240714220741790.png)

```bash
root@qemux86:~/skels/kernel_modules/1-2-test-mod# insmod hello_mod.ko
Hello!
root@qemux86:~/skels/kernel_modules/1-2-test-mod# lsmod
    Tainted: G
hello_mod 16384 0 - Live 0xd085f000 (O)
root@qemux86:~/skels/kernel_modules/1-2-test-mod# rmmod hello_mod.ko
Goodbye!
```



### 2. Printk

> 观察虚拟机控制台。为什么消息直接显示在虚拟机控制台上？
>
> 配置系统，使消息不直接显示在串行控制台上，只能使用 dmesg 命令来查看。

观察代码，可以看到它是 pr_debug，也就是 loglevel=7，我们可以查看 `/proc/sys/kernel/printk` 的等级

```bash
root@qemux86:~# cat /proc/sys/kernel/printk
15      4       1       7
```

可以看到当前等级是 14，默认输出的日志等级是 4，最低等级是 1，默认控制台日志等级为 7

我们直接把他改成 4 就好

```bash
root@qemux86:~# insmod skels/kernel_modules/1-2-test-mod/hello_mod.ko
Hello!
root@qemux86:~# rmmod skels/kernel_modules/1-2-test-mod/hello_mod.ko
Goodbye!
root@qemux86:~# echo 4 > /proc/sys/kernel/printk
root@qemux86:~# insmod skels/kernel_modules/1-2-test-mod/hello_mod.ko
root@qemux86:~# rmmod skels/kernel_modules/1-2-test-mod/hello_mod.ko
root@qemux86:~#
```



### 3. 错误

> 生成名为 3-error-mod 的任务的框架。编译源代码并得到相应的内核模块。
>
> 为什么会出现编译错误? 提示: 这个模块与前一个模块有什么不同？
>
> 修改该模块以解决这些错误的原因，然后编译和测试该模块。

生成它的代码

```bash
LABS=kernel_modules/3-error-mod make skels
```

首先我们对它进行编译，看看报错是什么

```bash
/linux/tools/labs/skels/./kernel_modules/3-error-mod/err_mod.c:5:20: error: expected declaration specifiers or '...' before string constant
    5 | MODULE_DESCRIPTION("Error module");
      |                    ^~~~~~~~~~~~~~
/linux/tools/labs/skels/./kernel_modules/3-error-mod/err_mod.c:6:15: error: expected declaration specifiers or '...' before string constant
    6 | MODULE_AUTHOR("Kernel Hacker");
      |               ^~~~~~~~~~~~~~~
/linux/tools/labs/skels/./kernel_modules/3-error-mod/err_mod.c:7:16: error: expected declaration specifiers or '...' before string constant
    7 | MODULE_LICENSE("GPL");
```

可以看到，似乎是这些函数的入参出了问题，那么很有可能是没引入头。

在 1 的里面是

```c title=""skels/kernel_modules/1-2-test-mod/hello_mod.c""
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
```

在 3 的里面少了一个 `<linux/module.h>`

```c title="skels/kernel_modules/3-error-mod/err_mod.c"
#include <linux/init.h>
#include <linux/kernel.h>
```

查询这些宏定义，可以发现都是来自于 `include/linux/module.h`，因此我们加入这个头就好

```c title="skels/kernel_modules/3-error-mod/err_mod.c"
// highlight-next-line
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
```

```bash
root@qemux86:~/skels/kernel_modules/3-error-mod# ls err_mod.ko
root@qemux86:~/skels/kernel_modules/3-error-mod# insmod err_mod.ko
err_mod: loading out-of-tree module taints kernel.
n1 is 1, n2 is 2
```



### 4. 子模块

> 查看 4-multi-mod/ 目录中的 C 源代码文件 mod1.c 和 mod2.c。模块 2 仅包含模块 1 使用的函数的定义。
>
> 修改 Kbuild 文件，从这两个 C 源文件创建 multi_mod.ko 模块。

我们可以发现 4 里面没有 obj-m 规则。

```bash
root@MuelNova-Laptop:/linux/tools/labs/skels/kernel_modules/4-multi-mod# cat Kbuild
ccflags-y = -Wno-unused-function -Wno-unused-label -Wno-unused-variable

# TODO: add rules to create a multi object module
root@MuelNova-Laptop:/linux/tools/labs/skels/kernel_modules/4-multi-mod# cat ../1-2-test-mod/Kbuild
ccflags-y = -Wno-unused-function -Wno-unused-label -Wno-unused-variable -DDEBUG

obj-m = hello_mod.o
```

既然我们想要模块 2 和模块 1 一起编译，那么我们首先要将它们链接到一起 (`$(module_name)-y`)，然后再编译 `obj-m`

```makefile title="Kbuild"
ccflags-y = -Wno-unused-function -Wno-unused-label -Wno-unused-variable

# TODO: add rules to create a multi object module
# highlight-start
multi-y = mod1.o mod2.o
obj-m = multi.o 
# highlight-end
```

再编译，可以看到 4 已经成功编译，并且运行正常。

```bash title="minicom"
root@qemux86:~/skels/kernel_modules/4-multi-mod# insmod multi.ko                                    
multi: loading out-of-tree module taints kernel.                                                     
n1 is 1, n2 is 2       
root@qemux86:~/skels/kernel_modules/4-multi-mod# rmmod multi.ko         
sum is 3
```



### 5. 内核 oops

> 内核 oops 是内核检测到的无效操作，只可能由内核生成。对于稳定的内核版本，这几乎可以肯定意味着模块含有错误。在 oops 出现后，内核仍将继续工作。

> 进入任务目录 5-oops-mod 并检查 C 源代码文件。注意问题将在哪里发生。在 Kbuild 文件中添加编译标记 -g。
>
> 

看它的源代码，看着就有一个空指针。

```c title="oops_mod.c"
static int my_oops_init(void)
{
        char *p = 0;

        pr_info("before init\n");
        *p = 'a';
        pr_info("after init\n");

        return 0;
}
```

我们 ins 一下看看 dmsg

```bash
Oops: 0002 [#1] SMP
CPU: 0 PID: 238 Comm: insmod Tainted: G           O      5.10.14+ #1
Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.13.0-1ubuntu1.1 04/01/2014
EIP: my_oops_init+0xd/0x22 [oops_mod]
Code: Unable to access opcode bytes at RIP 0xd0865fe3.
EAX: 0000000b EBX: 00000000 ECX: cfdc9d6c EDX: 0133efa3
ESI: d0866000 EDI: 00000002 EBP: c2a81dd8 ESP: c2a81dd4
DS: 007b ES: 007b FS: 00d8 GS: 00e0 SS: 0068 EFLAGS: 00000282
CR0: 80050033 CR2: d0865fe3 CR3: 04362000 CR4: 00000690
Call Trace:
 do_one_initcall+0x57/0x2d0
 ? rcu_read_lock_sched_held+0x47/0x80                                                                                                                                                                              ? kmem_cache_alloc_trace+0x2ed/0x370
 ? do_init_module+0x1f/0x210
 do_init_module+0x4e/0x210
 load_module+0x20a4/0x2580
 __ia32_sys_init_module+0xed/0x130
 do_int80_syscall_32+0x2c/0x40
 entry_INT80_32+0xf7/0xf7
EIP: 0x44902cc2
Code: 06 89 8a 84 01 00 00 c3 55 57 56 53 8b 6c 24 2c 8b 7c 24 28 8b 74 24 24 8b 54 24 20 8b 4c 24 1c 8b 5c 24 18 8b 44 24 14 cd 80 <5b> 5e 5f 5d 3d 01 f0 ff ff 0f 83 bf 76 f4 ff c3 66 90 66 90 66 90
EAX: ffffffda EBX: 09a8b050 ECX: 0001cfd8 EDX: 09a8b008
ESI: 00000000 EDI: bfcc3dec EBP: 00000000 ESP: bfcc3c4c
DS: 007b ES: 007b FS: 0000 GS: 0033 SS: 007b EFLAGS: 00000206
Modules linked in: oops_mod(O+)
CR2: 0000000000000000
---[ end trace a8efa95c8be6f1d2 ]---
EIP: my_oops_init+0xd/0x22 [oops_mod]
Code: Unable to access opcode bytes at RIP 0xd0865fe3.
EAX: 0000000b EBX: 00000000 ECX: cfdc9d6c EDX: 0133efa3
ESI: d0866000 EDI: 00000002 EBP: c2a81dd8 ESP: c2a81dd4
DS: 007b ES: 007b FS: 00d8 GS: 00e0 SS: 0068 EFLAGS: 00000282
CR0: 80050033 CR2: d0865fe3 CR3: 04362000 CR4: 00000690
```

可以看出是无效内存写入（OOPS 代码为 2，即第一位是 1，是写入，第 2 位是 0，是内核模式，第 0 位是 0，代表找不到页面）

:::info

想要看 oops 代码，可以看 `arch/x86/include/asm/trap_pf.h`

```c
/*
 * Page fault error code bits:
 *
 *   bit 0 ==	 0: no page found	1: protection fault
 *   bit 1 ==	 0: read access		1: write access
 *   bit 2 ==	 0: kernel-mode access	1: user-mode access
 *   bit 3 ==				1: use of reserved bit detected
 *   bit 4 ==				1: fault was an instruction fetch
 *   bit 5 ==				1: protection keys block access
 *   bit 6 ==				1: shadow stack access fault
 *   bit 15 ==				1: SGX MMU page-fault
 *   bit 31 ==				1: fault was due to RMP violation
 */
enum x86_pf_error_code {
	X86_PF_PROT	=		BIT(0),
	X86_PF_WRITE	=		BIT(1),
	X86_PF_USER	=		BIT(2),
	X86_PF_RSVD	=		BIT(3),
	X86_PF_INSTR	=		BIT(4),
	X86_PF_PK	=		BIT(5),
	X86_PF_SHSTK	=		BIT(6),
	X86_PF_SGX	=		BIT(15),
	X86_PF_RMP	=		BIT(31),
};
```

:::

我们使用 addr2line 看它哪里有问题 `EIP: my_oops_init+0xd/0x22 [oops_mod]`

```bash
root@MuelNova-Laptop:/linux/tools/labs# addr2line -e skels/kernel_modules/5-oops-mod/oops_mod.o 0xd
/linux/tools/labs/skels/./kernel_modules/5-oops-mod/oops_mod.c:15
```

看到是 15 行，我们看看是哪个

```c title="5-oops-mod/oops_mod.c" showLineNumbers {15}
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/slab.h>

MODULE_DESCRIPTION("Oops generating module");
MODULE_AUTHOR("So2rul Esforever");
MODULE_LICENSE("GPL");

static int my_oops_init(void)
{
        char *p = 0;

        pr_info("before init\n");
        *p = 'a';
        pr_info("after init\n");

        return 0;
}

static void my_oops_exit(void)
{
        pr_info("module goes all out\n");
}
```

和我们想的一样。更进一步，我们看看具体是哪条指令。

我们添加 -g 标志

```makefile title="skels/kernel_modules/5-oops-mod/Kbuild" {2}
# TODO: add flags to generate debug information
EXTRA_CFLAGS = -g

obj-m = oops_mod.o
```

:::note

不知道为什么，我这里加了之后还是不会出现 DEBUG-INFORMATION
:::

但是我们可以直接来看这个汇编，一眼有问题。

```bash
root@MuelNova-Laptop:/linux/tools/labs# objdump -dS --adjust-vma=0xd0866000 skels/kernel_modules/5-oops-mod/oops_mod.ko
d086600d:       c6 05 00 00 00 00 61    movb   $0x61,0x0
```

### 6. 模块参数
>  进入任务目录 6-cmd-mod 并检查 C 源代码文件 cmd_mod.c。编译并复制相关的模块，然后加载内核模块以查看 printk 消息。然后从内核中卸载该模块。
>
> 在不修改源代码的情况下，加载内核模块以显示消息 Early bird gets tired。

```c title="skels/kernel_modules/6-cmd-mod/cmd_mod.c"
static char *str = "the worm";

module_param(str, charp, 0000);
MODULE_PARM_DESC(str, "A simple string");

static int __init cmd_init(void)
{      
    pr_info("Early bird gets %s\n", str);                                                          
    return 0;
}
```

显然我们需要更换 str，那么查询 module_param 这个宏。

```c
/**
 * module_param - typesafe helper for a module/cmdline parameter
 * @name: the variable to alter, and exposed parameter name.
 * @type: the type of the parameter
 * @perm: visibility in sysfs.
 *
 * @name becomes the module parameter, or (prefixed by KBUILD_MODNAME and a
 * ".") the kernel commandline parameter.  Note that - is changed to _, so
 * the user can use "foo-bar=1" even for variable "foo_bar".
 *
 * @perm is 0 if the variable is not to appear in sysfs, or 0444
 * for world-readable, 0644 for root-writable, etc.  Note that if it
 * is writable, you may need to use kernel_param_lock() around
 * accesses (esp. charp, which can be kfreed when it changes).
 *
 * The @type is simply pasted to refer to a param_ops_##type and a
 * param_check_##type: for convenience many standard types are provided but
 * you can create your own by defining those variables.
 *
 * Standard types are:
 *	byte, hexint, short, ushort, int, uint, long, ulong
 *	charp: a character pointer
 *	bool: a bool, values 0/1, y/n, Y/N.
 *	invbool: the above, only sense-reversed (N = true).
 */
#define module_param(name, type, perm)				\
	module_param_named(name, name, type, perm)

```



显然它需要传入一个 str="tired" 的参数。

```bash
root@qemux86:~/skels/kernel_modules/6-cmd-mod# insmod cmd_mod.ko str="tired"
cmd_mod: loading out-of-tree module taints kernel.
Early bird gets tired
```



### 7. 进程信息

>
> 检查名为 7-list-proc 的任务的框架。添加代码来显示当前进程的进程 ID（ PID ）和可执行文件名。
>
> 按照标记为 TODO 的命令进行操作。在加载和卸载模块时，必须显示这些信息。

```c
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
/* TODO: add missing headers */

MODULE_DESCRIPTION("List current processes");
MODULE_AUTHOR("Kernel Hacker");
MODULE_LICENSE("GPL");

static int my_proc_init(void)
{
        struct task_struct *p;

        /* TODO: print current process pid and its name */

        /* TODO: print the pid and name of all processes */

        return 0;
}

static void my_proc_exit(void)
{
        /* TODO: print current process pid and name */
}

module_init(my_proc_init);
module_exit(my_proc_exit);
```

我们一个 TODO TODO 来做

第一个就是要加缺少的头，我们可以查一下 task_struct 是哪里定义的，来自 `include/linux/sched.h` (CSCOPE 不好用，查不懂)



第二个要 print current process pid 和 name，查询资料后我们知道 sched.h 里有一个宏 `current` 会返回一个当前进程的 task_struct 指针。

pid 是一个 pid_t 的成员，其实就是 signed int 的别名，所以我们可以直接输出

name 则是 comm 这个字符数组

我们于是可以写出这样的代码

```c
static int my_proc_init(void)
{
    // hightlight-start
        struct task_struct *p;
        p = current;
        pr_info("[I] Current PID: %d\n", p->pid);
        pr_info("            Name: %s\n", p->comm);
        /* TODO: print current process pid and its name */
    // highlight-end

        /* TODO: print the pid and name of all processes */

        return 0;
}
```

```bash
root@qemux86:~/skels/kernel_modules/7-list-proc# insmod list_proc.ko
list_proc: loading out-of-tree module taints kernel.
[I] Current PID: 240
            Name: insmod
```

测试，证明是可以用的。



第三个 TODO，我们要打印所有进程的，那么我们推测应该是有一个链表之类的保存了所有的进程的 task_struct，我们只需要找到他，然后遍历他就好了。得益于大模型，我们信息搜集到了一个 `for_each_process` 的宏，它可以遍历所有的进程。

:::info

它在 `include/linux/sched/signal.h` 里，见 [这里](https://elixir.bootlin.com/linux/v6.9.9/source/include/linux/sched/signal.h#L637)

:::

因此，我们利用这个宏，即可遍历完成。



最终代码：

```c
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
/* TODO: add missing headers */

MODULE_DESCRIPTION("List current processes");
MODULE_AUTHOR("Kernel Hacker");
MODULE_LICENSE("GPL");

static int my_proc_init(void)
{
        struct task_struct *p;
        p = current;
        pr_info("[I] Current PID: %d\n", p->pid);
        pr_info("            Name: %s\n", p->comm);
        /* TODO: print current process pid and its name */

        for_each_process(p) {
            pr_info("[I] Current PID: %d\n", p->pid);
            pr_info("            Name: %s\n", p->comm);
        }
        /* TODO: print the pid and name of all processes */

        return 0;
}

static void my_proc_exit(void)
{
        struct task_struct* p = current;
        pr_info("[I] Current PID: %d\n", p->pid);
        pr_info("            Name: %s\n", p->comm);
}

module_init(my_proc_init);
module_exit(my_proc_exit);
```

```bash
            Name: kswapd0
[I] Current PID: 42
            Name: cifsiod
[I] Current PID: 43                                                                                                                                                                                                           Name: smb3decryptd
[I] Current PID: 44
            Name: cifsfileinfoput
[I] Current PID: 45
            Name: cifsoplockd
[I] Current PID: 47
            Name: acpi_thermal_pm
[I] Current PID: 48
            Name: kworker/u2:1
[I] Current PID: 49
            Name: khvcd
[I] Current PID: 50
            Name: kworker/0:2
[I] Current PID: 51
            Name: ipv6_addrconf
[I] Current PID: 52
            Name: kmemleak
[I] Current PID: 53
            Name: jbd2/vda-8
[I] Current PID: 54
            Name: ext4-rsv-conver
[I] Current PID: 192
            Name: udhcpc
[I] Current PID: 203
            Name: syslogd
[I] Current PID: 206
            Name: klogd
[I] Current PID: 212
            Name: getty
[I] Current PID: 213
            Name: sh
[I] Current PID: 214
            Name: getty
[I] Current PID: 215
            Name: getty
[I] Current PID: 216                                                                                                                                                                                                          Name: getty
[I] Current PID: 217
            Name: getty
[I] Current PID: 238
            Name: insmod
[I] Current PID: 242
            Name: rmmod
```

很有精神！



### Ex1. KDB

```bash
echo hvc0 > /sys/module/kgdboc/parameters/kgdboc
echo g > /proc/sysrq-trigger
# 或者用 Ctrl+O g
```

![image-20240715233154679](https://cdn.ova.moe/img/image-20240715233154679.png)

我这里有 BUG，显示不全，就这样吧。

利用 echo 写入就会直接进入 KDB 里

![image-20240715233319670](https://cdn.ova.moe/img/image-20240715233319670.png)

看堆栈 bt 就可以知道是 dummy_func1+0x8 的地方出了问题。还可以看到 current=0xc42b2b40，我们用 lsmod 可以看到基地址 0xd0880000。但是我们 bt 的时候看不到回溯栈，所以就搁置了。



接下来就是 gdb add-symbol-file 把它导入，然后设置基地址，看看指令是什么了，也是比较简单就不看了



### Ex2. PS 模块

前面 7. proc-info 写完了



### Ex3. 内存信息

> 创建一个内核模块，显示当前进程的虚拟内存区域；对于每个内存区域，它将显示起始地址和结束地址。

内存区域由类型为 struct vm_area_struct 的结构表示，那么我们就可以开始写内核模块了。

```c title="skels/kernel_modules/10-proc/proc.c"
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>

MODULE_AUTHOR("Muel Nova");
MODULE_DESCRIPTION("SHOW MEM");
MODULE_LICENSE("GPL");

static int mem_init(void) {
        return 0;
}

static void mem_exit(void) {
}

module_init(mem_init);
module_exit(mem_exit);
```

```makefile title="skels/kernel_modules/10-proc/Kbuild"
ccflags-y = -Wno-unused-function -Wno-unused-label -Wno-unused-variable -DDEBUG

obj-m = proc.o
```



框架大概就是这样，接下来，我们查询 vm_area_struct 的用法。它被定义在 `include/linux/mm_types.h` 里，那么我们可以直接利用 vm_start 和 vm_end 来表示大小，它也是一个链表，用 vm_next 就可以找到下一个。

那么我们就需要知道如何找到当前进程的所有 vm_area_struct 结构体了。我们可以想到用 current 去找，翻一下可以看到 task_struct->mm 是一个 mm_struct 的结构体指针，那么我们继续去翻 mm_struct，第一个就是 struct vm_area_struct 的字段 mmap

:::info

内核版本 v5.10.14，在最新的内核里，我们已经看不到这个 mmap 字段了。在 [mm: remove the vma linked list · torvalds/linux@763ecb0 (github.com)](https://github.com/torvalds/linux/commit/763ecb035029f500d7e6dc99acd1ad299b7726a1#diff-dc57f7b72015cf5f95444ec4f8a60f85d773f40b96ac59bf55b281cd63c06142) 中被删除了。

在新版本中，我们应该使用 mapleTree 来拿，也就是从 mm->mm_mt 里拿。

> ```c
> struct maple_tree *mt = &mm->mm_mt;
> struct vm_area_struct *vma_mt;
> 
> MA_STATE(mas, mt, 0, 0);
> 
> mas_for_each(&mas, vma_mt, ULONG_MAX) {
>     // do sth...
> }
> ```
>
> 根据 diff 找到的新的用法

:::



因此最终的代码：

```c
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/mm_types.h>

MODULE_AUTHOR("Muel Nova");
MODULE_DESCRIPTION("SHOW MEM");
MODULE_LICENSE("GPL");

static int mem_init(void) {
    struct task_struct* p = current;
    struct mm_struct* mm = p->mm;
    struct vm_area_struct* vma = mm->mmap;
    while (vma) {
        printk("0x%lx - 0x%lx\n", vma->vm_start, vma->vm_end);
        vma = vma->vm_next;
    }
    return 0;
}
```

```bash
root@qemux86:~/skels/kernel_modules/10-proc# insmod proc.ko
proc: loading out-of-tree module taints kernel.
0x8048000 - 0x80c2000
0x80c2000 - 0x80c3000
0x80c3000 - 0x80c4000
0x80c4000 - 0x80c6000
0x84c9000 - 0x84ea000
0x4480c000 - 0x4482e000
0x4482e000 - 0x4482f000
0x4482f000 - 0x44830000
0x44832000 - 0x449a9000
0x449a9000 - 0x449ab000
0x449ab000 - 0x449ac000
0x449ac000 - 0x449af000
0x449b1000 - 0x44a09000
0x44a09000 - 0x44a0a000
0x44a0a000 - 0x44a0b000
0xb7f28000 - 0xb7f4d000
0xb7f4d000 - 0xb7f51000
0xb7f51000 - 0xb7f53000
0xbffcc000 - 0xbffed000
```



### Ex4. 动态调试

首先先 mount debugfs

```bash
mkdir /debug
mount -t debugfs none /debug
```

然后没找到 /debug/dynamic_debug，估计是内核没开吧，跑路



## Kernel API

### 0. 简介

在 Linux 内核中查找以下符号的定义：

- `struct list_head`：感觉大概看上去就是一个双向链表

  ```c
  struct list_head {
  	struct list_head *next, *prev;
  };
  ```

- INIT_LIST_HEAD()：初始化链表头。

  ```c
  static inline void INIT_LIST_HEAD(struct list_head *list)
  {
  	WRITE_ONCE(list->next, list);
  	WRITE_ONCE(list->prev, list);
  }
  ```

- list_add()：就是把 new 插入到 prev 和 next 中间
  这里用 WRITE_ONCE 好像是为了进程安全并且保证顺序性

  ```c
  static inline void __list_add(struct list_head *new,
  			      struct list_head *prev,
  			      struct list_head *next)
  {
  	if (!__list_add_valid(new, prev, next))
  		return;
  
  	next->prev = new;
  	new->next = next;
  	new->prev = prev;
  	WRITE_ONCE(prev->next, new);
  }
  ```

- list_for_each：就是一个循环的包装。

  ```c
  /**
   * list_for_each	-	iterate over a list
   * @pos:	the &struct list_head to use as a loop cursor.
   * @head:	the head for your list.
   */
  #define list_for_each(pos, head) \
  	for (pos = (head)->next; !list_is_head(pos, (head)); pos = pos->next)
  ```

- list_entry

- ```c
  /**
   * list_entry - get the struct for this entry
   * @ptr:	the &struct list_head pointer.
   * @type:	the type of the struct this is embedded in.
   * @member:	the name of the list_head within the struct.
   */
  #define list_entry(ptr, type, member) \
  	container_of(ptr, type, member)
  ```

- `container_of`

  比较复杂，但是简单来说就是把一个已知是 member 类型的 ptr，也知道它属于某个 type 结构体，反查 type 结构体的指针。

  ```c
  /**
   * container_of - cast a member of a structure out to the containing structure
   * @ptr:	the pointer to the member.
   * @type:	the type of the container struct this is embedded in.
   * @member:	the name of the member within the struct.
   *
   * WARNING: any const qualifier of @ptr is lost.
   */
  #define container_of(ptr, type, member) ({				\
  	void *__mptr = (void *)(ptr);					\
  	static_assert(__same_type(*(ptr), ((type *)0)->member) ||	\
  		      __same_type(*(ptr), void),			\
  		      "pointer type mismatch in container_of()");	\
  	((type *)(__mptr - offsetof(type, member))); })
  ```

- offsetof

- 字面意思。看这个是一个包装。

  ```C
  #undef offsetof
  #define offsetof(TYPE, MEMBER)	__builtin_offsetof(TYPE, MEMBER)
  ```

### 1. Linux 内核中的内存分配

生成名为 **1-mem** 的任务骨架，并浏览 `mem.c` 文件的内容。观察使用 `kmalloc()` 函数进行内存分配的情况。

> 1. 编译源代码并使用 **insmod** 加载 `mem.ko` 模块。
> 2. 使用 **dmesg** 命令查看内核消息。
> 3. 使用 **rmmod mem** 命令卸载内核模块。

```c
mem = kmalloc(4096 * sizeof(*mem), GFP_KERNEL);
```

搞了 4K 个字符的 buf。

打印出来都是 Z，就是 90，也就是 0x5a，神秘。

### 2. 在原子上下文中睡眠

生成名为 **2-sched-spin** 的任务骨架，并浏览 `sched-spin.c` 文件的内容。

> 1. 根据上述信息编译源代码并加载模块（使用命令 **make build** 和 **make copy** ）。
> 2. 注意：插入顺序完成之前需要等待 5 秒时间。
> 3. 卸载内核模块。
> 4. 查找标记为：`TODO 0` 的行以创建原子段（atomic section）。重新编译源代码并将模块重新加载到内核。

现在你应该会遇到一个错误。查看堆栈跟踪。错误的原因是什么？



一开始的显然是可抢占的内核。我们要做的操作就是把 schedule_timeout 改成 atomic 的

```cpp
	spin_lock(&lock);

	set_current_state(TASK_INTERRUPTIBLE);
	/* Try to sleep for 5 seconds. */
	schedule_timeout(5 * HZ);

	spin_unlock(&lock);
```

毫无疑问的会报错：

```bash
root@qemux86:~/skels/kernel_api/2-sched-spin# insmod sched-spin.ko
sched_spin: loading out-of-tree module taints kernel.              
BUG: scheduling while atomic: insmod/322/0x00000002                1 lock held by insmod/322:
```

因为我们 schedule 了，这在原子段里肯定是不允许的



### 3. 使用内核内存

为名为 **3-memory** 的任务生成骨架，并浏览 `memory.c` 文件的内容。请注意带有 `TODO` 标记的注释。你需要分配 4 个类型为 `struct task_info` 的结构体并将其初始化（在 `memory_init()` 中），然后打印并释放它们（在 `memory_exit()` 中）。

1. （TODO 1）为 `struct task_info` 结构体分配内存并初始化其字段：

   - 将 `pid` 字段设置为作为参数传递的 PID 值；
   - 将 `timestamp` 字段设置为 `jiffies` 变量的值，该变量存储了自系统启动以来发生的滴答数（tick）。

2. （TODO 2）为当前进程、父进程、下一个进程和下一个进程的下一个进程分别分配 `struct task_info`，并获取以下信息：

   - 当前进程的 PID，其可以从 `struct task_struct` 结构体中检索到，该结构体由 `current` 宏返回。

   :::tip

   在 `task_struct` 中搜索 `pid`。

   - 当前进程的父进程的 PID。

   :::

   在 `struct task_struct` 结构体中搜索相关字段。查找“parent”。

   - 相对于当前进程，进程列表中的下一个进程的 PID。

   :::tip

   使用 `next_task` 宏，该宏返回指向下一个进程的指针（即 `struct task_struct` 结构体）。

   - 相对于当前进程，下一个进程的下一个进程的 PID。

   :::

   调用 `next_task` 宏 2 次。

3. （TODO 3）显示这四个结构体。

   - 使用 `printk()` 显示它们的两个字段：`pid` 和 `timestamp`。

4. （TODO 4）释放结构体占用的内存（使用 `kfree()`）。

:::tip

- 你可以使用 `current` 宏访问当前进程。
- 在 `struct task_struct` 结构体中查找相关字段（`pid`、`parent`）。
- 使用 `next_task` 宏。该宏返回指向下一个进程的指针（即 `struct task_struct*` 结构体）。

:::



TODO1

```c
#include <linux/jiffies.h>

static struct task_info *task_info_alloc(int pid)
{
	struct task_info *ti;

	/* TODO 1: allocated and initialize a task_info struct */
	ti = kmalloc(sizeof(struct task_info), GFP_KERNEL);
    if (ti == NULL)
		return NULL;
	ti->pid = pid;
	ti->timestamp = jiffies;

	return ti;
}
```

TODO2

```c
static int memory_init(void)
{	
	struct task_struct* cur = get_current();
	ti1 = task_info_alloc(cur->pid);
	ti2 = task_info_alloc(cur->parent->pid);
	ti3 = task_info_alloc(next_task(cur)->pid);
	ti4 = task_info_alloc(next_task(next_task(cur))->pid);
	
	/* TODO 2: call task_info_alloc for current pid */

	/* TODO 2: call task_info_alloc for parent PID */

	/* TODO 2: call task_info alloc for next process PID */

	/* TODO 2: call task_info_alloc for next process of the next process */

	return 0;
}
```

TODO3、4

```c
static void memory_exit(void)
{

	/* TODO 3: print ti* field values */
	printk("[task_info] Current:\n\tPID:%d\n\ttimestamp:%lu\n\n", ti1->pid, ti1->timestamp);
	printk("[task_info] Parent:\n\tPID:%d\n\ttimestamp:%lu\n\n", ti2->pid, ti2->timestamp);
	printk("[task_info] Next:\n\tPID:%d\n\ttimestamp:%lu\n\n", ti3->pid, ti3->timestamp);
	printk("[task_info] Next(Next):\n\tPID:%d\n\ttimestamp:%lu\n", ti4->pid, ti4->timestamp);

	/* TODO 4: free ti* structures */
	kfree(ti1);
	kfree(ti2);
	kfree(ti3);
	kfree(ti4);
}
```

```bash
root@qemux86:~/skels/kernel_api/3-memory# rmmod memory.ko
[task_info] Current:                                                       PID:241                                                            timestamp:4294910496
                                                                   [task_info] Parent:                                                        PID:213                                                            timestamp:4294910496
                                                                   [task_info] Next:                                                          PID:0                                                              timestamp:4294910496
                                                                   [task_info] Next(Next):                                                    PID:1                                                              timestamp:4294910496
root@qemux86:~/skels/kernel_api/3-memory# insmod memory.ko
root@qemux86:~/skels/kernel_api/3-memory# rmmod memory.ko
[task_info] Current:                                                       PID:245                                                            timestamp:4294912218
                                                                   [task_info] Parent:                                                        PID:213                                                            timestamp:4294912218
                                                                   [task_info] Next:                                                          PID:0                                                              timestamp:4294912218
                                                                   [task_info] Next(Next):                                                    PID:1                                                              timestamp:4294912218
```

对的对的

### 4. 使用内核列表

生成名为 **4-list** 的任务骨架。浏览 `list.c` 文件的内容，并注意标有 `TODO` 的注释。当前的进程将在列表中添加前面练习中的四个结构体。列表将在加载模块时在 `task_info_add_for_current()` 函数中构建。列表将在 `list_exit()` 函数和 `task_info_purge_list()` 函数中打印和删除。

> 1. (TODO 1) 补全 `task_info_add_to_list()` 函数，此函数会分配 `struct task_info` 结构体，并将其添加到列表中。
> 2. (TODO 2) 补全 `task_info_purge_list()` 函数，此函数会删除列表中的所有元素。
> 3. 编译内核模块。按照内核显示的消息加载和卸载模块。

就是前面那个变成一个 list，随便写写

TODO1

```c
static void task_info_add_to_list(int pid)
{
	struct task_info *ti;

	/* TODO 1: Allocate task_info and add it to list */
	ti = task_info_alloc(pid);
	if (ti == NULL)
		return;
	list_add(&ti->list, &head);
}
```

TODO2

注意这里是要删除，所以得要一个 nxt 存下一个

```c
static void task_info_purge_list(void)
{
	struct list_head *p, *q;
	struct task_info *ti;

	/* TODO 2: Iterate over the list and delete all elements */
	list_for_each_safe(p, q, &head) {
		ti = list_entry(p, struct task_info, list);
		list_del(p);
		kfree(ti);
	}
}
```

没毛病哦

```bash
root@qemux86:~/skels/kernel_api/4-list# rmmod list.ko
before exiting: [
(1, 66185)
(0, 66185)
(213, 66185)
(296, 66185)
]
```



### 5. 使用内核列表进行进程处理

生成名为 **5-list-full** 的任务骨架。浏览 `list-full.c` 文件的内容，并注意标有 `TODO` 的注释。除了 `4-list` 的功能外，我们还添加了以下内容：

- 一个 `count` 字段，显示一个进程被“添加”到列表中的次数。

- 如果一个进程被“添加”了多次，则不会在列表中创建新的条目，而是：

  > - 更新 `timestamp` 字段。
  > - 增加 `count`。

- 为了实现计数器功能，请添加一个 `task_info_find_pid()` 函数，用于在现有列表中搜索 pid。

- 如果找到，则返回对 `task_info` 结构的引用。如果没有找到，则返回 `NULL`。

- 过期处理功能。如果一个进程从被添加到现在已超过 3 秒，并且它的 `count` 不大于 5，则被视为过期并从列表中删除。

- 过期处理功能已经在 `task_info_remove_expired()` 函数中实现。

1. (TODO 1) 实现 `task_info_find_pid()` 函数。

2. (TODO 2) 更改列表中的一个项目的字段，使其不会过期。它不应满足 `task_info_remove_expired()` 中的任何过期条件。

   :::tip

   要想完成 `TODO 2`，可以从列表中提取第一个元素（由 `head.next` 引用），并将其 `count` 字段设置为足够大的值。使用 `atomic_set()` 函数。

   :::

3. 编译、复制、加载和卸载内核模块，这个过程中请遵从显示的消息来操作。加载内核模块需要一些时间，因为 `schedule_timeout()` 函数会调用 `sleep()`。



这个遍历也是很简单，扫一遍链表就可以。第二个也是给了提示了，count 设置成 5 就可以。

TODO1

```c
static struct task_info *task_info_find_pid(int pid)
{
	struct list_head *p;
	struct task_info *ti;

	/* TODO 1: Look for pid and return task_info or NULL if not found */
	list_for_each(p, &head) {
		ti = list_entry(p, struct task_info, list);
		if (ti->pid == pid)
			return ti;
	}

	return NULL;
}
```

TODO2

```c
static void list_full_exit(void)
{
	struct task_info *ti;

	/* TODO 2: Ensure that at least one task is not deleted */

	ti = list_entry(head.next, struct task_info, list);

	atomic_set(&ti->count, 5);
	task_info_print_list("after removing expired");
	task_info_remove_expired();
	task_info_print_list("after removing expired");
	task_info_purge_list();
}
```

我们保了一个存活，也就是 next next。

```bash
root@qemux86:~/skels/kernel_api/5-list-full# insmod list-full.ko
list_full: loading out-of-tree module taints kernel.
after first add: [
(1, 4294915575)
(0, 4294915575)
(214, 4294915575)
(243, 4294915575)
]

root@qemux86:~/skels/kernel_api/5-list-full# rmmod list-full.ko
after removing expired: [
(1, 4294915575)
]
```

### 6. 同步列表工作

为名为 **6-list-sync** 的任务生成骨架。

> 1. 浏览代码并查找``TODO 1``字符串。
> 2. 使用自旋锁或读写锁来同步对列表的访问。
> 3. 编译、加载和卸载内核模块。

:::tip 重要

始终锁定数据，而不是代码！

:::



又到了我最喜欢的并发编程环节

```c
/*
 * Linux API lab
 *
 * list-sync.c - Synchronize access to a list
 */

#include <linux/spinlock.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/sched/signal.h>

MODULE_DESCRIPTION("Full list processing with synchronization");
MODULE_AUTHOR("SO2");
MODULE_LICENSE("GPL");

struct task_info {
	pid_t pid;
	unsigned long timestamp;
	atomic_t count;
	struct list_head list;
};

static struct list_head head;

/* TODO 1: you can use either a spinlock or rwlock, define it here */
// 写互斥，读并行，没毛病哦老铁们。
DEFINE_RWLOCK(lock);

static struct task_info *task_info_alloc(int pid)
{
	struct task_info *ti;

	ti = kmalloc(sizeof(*ti), GFP_KERNEL);
	if (ti == NULL)
		return NULL;
	ti->pid = pid;
	ti->timestamp = jiffies;
	atomic_set(&ti->count, 0);

	return ti;
}

static struct task_info *task_info_find_pid(int pid)
{
	struct list_head *p;
	struct task_info *ti;

	list_for_each(p, &head) {
		ti = list_entry(p, struct task_info, list);
		if (ti->pid == pid) {
			return ti;
		}
	}

	return NULL;
}

static void task_info_add_to_list(int pid)
{
	struct task_info *ti;

	/* TODO 1: Protect list, is this read or write access? */
    // find_pid 会读，那肯定拿读锁
	read_lock(&lock);
	ti = task_info_find_pid(pid);
	if (ti != NULL) {
         // 注意这里，如果找到了那就先释放读锁，准备写。等所有读都解锁了在写。
		read_unlock(&lock);
         write_lock(&lock);
		ti->timestamp = jiffies;
		atomic_inc(&ti->count);
         write_unlock(&lock);
		/* TODO: Guess why this comment was added  here */

		return;
	}
	read_unlock(&lock);
	
	/* TODO 1: critical section ends here */
    
	ti = task_info_alloc(pid);
	// 这里注意，alloc 因为有 GFP_KERNEL FLAG，因此是可抢占的，我们不能在上一句里面拿锁！！
	write_lock(&lock);
	/* TODO 1: protect list access, is this read or write access? */
	list_add(&ti->list, &head);
	write_unlock(&lock);
	/* TODO 1: critical section ends here */
}

void task_info_add_for_current(void)
{
	task_info_add_to_list(current->pid);
	task_info_add_to_list(current->parent->pid);
	task_info_add_to_list(next_task(current)->pid);
	task_info_add_to_list(next_task(next_task(current))->pid);
}
/* TODO 2: Export the kernel symbol */
EXPORT_SYMBOL(task_info_add_for_current);

void task_info_print_list(const char *msg)
{
	struct list_head *p;
	struct task_info *ti;

	pr_info("%s: [ ", msg);

	/* TODO 1: Protect list, is this read or write access? */
    // 这个没必要写在循环里，拿锁贵的
	read_lock(&lock);
	list_for_each(p, &head) {
		
		ti = list_entry(p, struct task_info, list);
		pr_info("(%d, %lu) ", ti->pid, ti->timestamp);
		
	}
    read_unlock(&lock);
	
	/* TODO 1: Critical section ends here */
	pr_info("]\n");
}
/* TODO 2: Export the kernel symbol */
EXPORT_SYMBOL(task_info_print_list);

void task_info_remove_expired(void)
{
	struct list_head *p, *q;
	struct task_info *ti;

	/* TODO 1: Protect list, is this read or write access? */
    // 这里 list_del 是写操作，我们可以直接拿写锁，不需要再拿读锁读完再拿写锁了
	write_lock(&lock);
	list_for_each_safe(p, q, &head) {
		ti = list_entry(p, struct task_info, list);
		if (jiffies - ti->timestamp > 3 * HZ && atomic_read(&ti->count) < 5) {
			list_del(p);
			kfree(ti);
		}
	}
	write_unlock(&lock);
	/* TODO 1: Critical section ends here */
}
/* TODO 2: Export the kernel symbol */
EXPORT_SYMBOL(task_info_remove_expired);

static void task_info_purge_list(void)
{
	struct list_head *p, *q;
	struct task_info *ti;

	/* TODO 1: Protect list, is this read or write access? */
    // 写操作
	write_lock(&lock);
	list_for_each_safe(p, q, &head) {
		ti = list_entry(p, struct task_info, list);
		list_del(p);
		kfree(ti);
	}
	write_unlock(&lock);
	/* TODO 1: Critical sections ends here */
}

static int list_sync_init(void)
{
	INIT_LIST_HEAD(&head);

	task_info_add_for_current();
	task_info_print_list("after first add");

	set_current_state(TASK_INTERRUPTIBLE);
	schedule_timeout(5 * HZ);

	return 0;
}

static void list_sync_exit(void)
{
	struct task_info *ti;

	ti = list_entry(head.prev, struct task_info, list);
	atomic_set(&ti->count, 10);

	task_info_remove_expired();
	task_info_print_list("after removing expired");
	task_info_purge_list();
}

module_init(list_sync_init);
module_exit(list_sync_exit);

```



### 7. 在我们的列表模块中测试模块调用

为名为 **7-list-test** 的任务生成骨架，并浏览 `list-test.c` 文件的内容。我们将使用它作为测试模块。它将调用由 **6-list-sync** 任务导出的函数。在 `list-test.c` 文件中，已经用 **extern** 标记出了导出的函数。

取消注释 `7-list-test.c` 中的注释代码。查找 `TODO 1`。

要从位于 `6-list-sync/` 目录中的模块导出上述函数，需要执行以下步骤：

> 1. 函数不能是静态的。
> 2. 使用 `EXPORT_SYMBOL` 宏导出内核符号。例如：`EXPORT_SYMBOL(task_info_remove_expired);`。该宏必须在函数定义后使用。浏览代码并查找 `list-sync.c` 中的 `TODO 2` 字符串。
> 3. 从 **6-list-sync** 模块中删除避免列表项过期的代码（它与我们的练习相矛盾）。
> 4. 编译并加载 `6-list-sync/` 中的模块。一旦加载，它会公开导出的函数，使其可以被测试模块使用。你可以通过分别在加载模块之前和之后在 `/proc/kallsyms` 中搜索函数名称来检查这一点。
> 5. 编译测试模块，然后加载它。
> 6. 使用 **lsmod** 命令检查这两个模块是否已加载。你注意到了什么？
> 7. 卸载内核测试模块。

两个模块（来自 **6-list-sync** 的模块和测试模块）的卸载顺序应该是什么？如果使用其他顺序会发生什么？



这个没啥好说的，就是一个测试。

6. ```c
   list_test 16384 0 - Live 0xd0896000 (O)
   list_sync 16384 1 list_test, Live 0xd086c000 (O)
   ```

肯定是先 sync 再 test，然后卸载反过来。不然就 undefined 啦

结束，Kernel API



## 字符设备驱动程序

到了我最爱的设备，在这里就可以写一些笔记了。我们都知道 linux 使用特殊的设备文件访问硬件设备，操作系统会对针对这些文件的系统调用重定向到关联的设备驱动程序上。

### 分类与鉴别

按照速率、容量和数据的组织方式，我们可以把设备分为块设备和字符设备两类。

- 对于字符设备而言，它仅处理少量的数据，并且不需要频繁的搜索这些数据。例如说键盘、鼠标等等，通常来说，这些设备的读取写入也是按字节顺序逐个执行的。
- 对于块设备而言，它处理大量的数据，例如说硬盘、RAM 等等，还是比较明确的。

Linux 对两种设备提供了不同的 API。如果是字符设备，那么系统调用就会直接传递给设备驱动程序；如果是块设备，那么就要通过文件管理子系统和块设备子系统进行交互。（猜测是为了性能，譬如说 DMA 之类的？）



设备一般用 <主设备号><次设备号> 的形式标识，其中主设备号一般用于标识设备类型，次设备号就是本身。一个例子就是 hda1、hda2、ttyS0、ttyS1

```bash
❯ ls -la /dev/tty?
crw--w---- 1 root tty 4, 0 Jul 24 18:25 /dev/tty0
crw--w---- 1 root tty 4, 1 Jul 24 18:25 /dev/tty1
crw--w---- 1 root tty 4, 2 Jul 24 18:25 /dev/tty2
crw--w---- 1 root tty 4, 3 Jul 24 18:25 /dev/tty3
crw--w---- 1 root tty 4, 4 Jul 24 18:25 /dev/tty4
crw--w---- 1 root tty 4, 5 Jul 24 18:25 /dev/tty5
crw--w---- 1 root tty 4, 6 Jul 24 18:25 /dev/tty6
crw--w---- 1 root tty 4, 7 Jul 24 18:25 /dev/tty7
crw--w---- 1 root tty 4, 8 Jul 24 18:25 /dev/tty8
crw--w---- 1 root tty 4, 9 Jul 24 18:25 /dev/tty9
```

可以看到第一位就是 c 代表 `char dev`，而自然块设备第一位就是 `b`。其中，主设备号是 4，次设备号依次递增。



### 创建设备

我们可以使用 `mknod` 命令创建一个新设备，他也需要提供一些参数，例如名字、类型、主设备号、次设备号等等。一个简单的例子如下，它创建了一个名为 `muelnova` 的字符设备，主设备号为 114，次设备号为 514

```bash
[root@MuelNova-Laptop nova]# mknod /dev/muelnova c 114 514
[root@MuelNova-Laptop nova]# ls -la /dev/muelnova
crw-r--r-- 1 root root 114, 514 Jul 24 19:03 /dev/muelnova
```



内核使用 [`struct cdev`](https://elixir.bootlin.com/linux/v6.10/source/include/linux/cdev.h#L14) 来注册字符设备。一般而言，驱动程序还会利用以下几个结构：

- `struct file_operations`：实现特定于文件的系统调用，例如 `open`、`close`、`read`、`mmap` 等。

  ```c
  struct file_operations {
      struct module *owner;
      loff_t (*llseek) (struct file *, loff_t, int);
      ssize_t (*read) (struct file *, char __user *, size_t, loff_t *);
      ssize_t (*write) (struct file *, const char __user *, size_t, loff_t *);
      [...]
      long (*unlocked_ioctl) (struct file *, unsigned int, unsigned long);
      [...]
      int (*open) (struct inode *, struct file *);
      int (*flush) (struct file *, fl_owner_t id);
      int (*release) (struct inode *, struct file *);
      [...]
  ```

  你可以注意到，这些函数的入参和原本是不一样的，多了两个用户态下不常见的 `struct file` 和 `struct inode`。


  简单来说，file 和 inode 有点像进程和程序的区别。file 具有状态，而 inode 只包括有一些静态映像。

- `struct file`：包含了打开标记、关联操作 等

  ```c
  struct file {
  	union {
  		/* fput() uses task work when closing and freeing file (default). */
  		struct callback_head 	f_task_work;
  		/* fput() must use workqueue (most kernel threads). */
  		struct llist_node	f_llist;
  		unsigned int 		f_iocb_flags;
  	};
  
  	/*
  	 * Protects f_ep, f_flags.
  	 * Must not be taken from IRQ context.
  	 */
  	spinlock_t		f_lock;
  	fmode_t			f_mode;
  	atomic_long_t		f_count;
  	struct mutex		f_pos_lock;
  	loff_t			f_pos;
  	unsigned int		f_flags;
  	struct fown_struct	f_owner;
  	const struct cred	*f_cred;
  	struct file_ra_state	f_ra;
  	struct path		f_path;
  	struct inode		*f_inode;	/* cached value */
  	const struct file_operations	*f_op;
  
  	u64			f_version;
  #ifdef CONFIG_SECURITY
  	void			*f_security;
  #endif
  	/* needed for tty driver, and maybe others */
  	void			*private_data;
  
  #ifdef CONFIG_EPOLL
  	/* Used by fs/eventpoll.c to link all the hooks to this file */
  	struct hlist_head	*f_ep;
  #endif /* #ifdef CONFIG_EPOLL */
  	struct address_space	*f_mapping;
  	errseq_t		f_wb_err;
  	errseq_t		f_sb_err; /* for syncfs */
  } __randomize_layout
    __attribute__((aligned(4)));	/* lest something weird decides that 2 is OK */
  ```

- `struct inode`：包含了许多字段，例如 `i_cdev`，它就指向一个定义字符设备结构的指针。

  ```c
  struct inode {
  	umode_t			i_mode;
  	unsigned short		i_opflags;
  	kuid_t			i_uid;
  	kgid_t			i_gid;
  	unsigned int		i_flags;
  
  #ifdef CONFIG_FS_POSIX_ACL
  	struct posix_acl	*i_acl;
  	struct posix_acl	*i_default_acl;
  #endif
  
  	const struct inode_operations	*i_op;
  	struct super_block	*i_sb;
  	struct address_space	*i_mapping;
  
  #ifdef CONFIG_SECURITY
  	void			*i_security;
  #endif
  
  	/* Stat data, not accessed from path walking */
  	unsigned long		i_ino;
  	/*
  	 * Filesystems may only read i_nlink directly.  They shall use the
  	 * following functions for modification:
  	 *
  	 *    (set|clear|inc|drop)_nlink
  	 *    inode_(inc|dec)_link_count
  	 */
  	union {
  		const unsigned int i_nlink;
  		unsigned int __i_nlink;
  	};
  	dev_t			i_rdev;
  	loff_t			i_size;
  	struct timespec64	__i_atime;
  	struct timespec64	__i_mtime;
  	struct timespec64	__i_ctime; /* use inode_*_ctime accessors! */
  	spinlock_t		i_lock;	/* i_blocks, i_bytes, maybe i_size */
  	unsigned short          i_bytes;
  	u8			i_blkbits;
  	enum rw_hint		i_write_hint;
  	blkcnt_t		i_blocks;
  
  #ifdef __NEED_I_SIZE_ORDERED
  	seqcount_t		i_size_seqcount;
  #endif
  
  	/* Misc */
  	unsigned long		i_state;
  	struct rw_semaphore	i_rwsem;
  
  	unsigned long		dirtied_when;	/* jiffies of first dirtying */
  	unsigned long		dirtied_time_when;
  
  	struct hlist_node	i_hash;
  	struct list_head	i_io_list;	/* backing dev IO list */
  #ifdef CONFIG_CGROUP_WRITEBACK
  	struct bdi_writeback	*i_wb;		/* the associated cgroup wb */
  
  	/* foreign inode detection, see wbc_detach_inode() */
  	int			i_wb_frn_winner;
  	u16			i_wb_frn_avg_time;
  	u16			i_wb_frn_history;
  #endif
  	struct list_head	i_lru;		/* inode LRU list */
  	struct list_head	i_sb_list;
  	struct list_head	i_wb_list;	/* backing dev writeback list */
  	union {
  		struct hlist_head	i_dentry;
  		struct rcu_head		i_rcu;
  	};
  	atomic64_t		i_version;
  	atomic64_t		i_sequence; /* see futex */
  	atomic_t		i_count;
  	atomic_t		i_dio_count;
  	atomic_t		i_writecount;
  #if defined(CONFIG_IMA) || defined(CONFIG_FILE_LOCKING)
  	atomic_t		i_readcount; /* struct files open RO */
  #endif
  	union {
  		const struct file_operations	*i_fop;	/* former ->i_op->default_file_ops */
  		void (*free_inode)(struct inode *);
  	};
  	struct file_lock_context	*i_flctx;
  	struct address_space	i_data;
  	struct list_head	i_devices;
  	union {
  		struct pipe_inode_info	*i_pipe;
  		struct cdev		*i_cdev;
  		char			*i_link;
  		unsigned		i_dir_seq;
  	};
  
  	__u32			i_generation;
  
  #ifdef CONFIG_FSNOTIFY
  	__u32			i_fsnotify_mask; /* all events this inode cares about */
  	struct fsnotify_mark_connector __rcu	*i_fsnotify_marks;
  #endif
  
  #ifdef CONFIG_FS_ENCRYPTION
  	struct fscrypt_inode_info	*i_crypt_info;
  #endif
  
  #ifdef CONFIG_FS_VERITY
  	struct fsverity_info	*i_verity_info;
  #endif
  
  	void			*i_private; /* fs or device private pointer */
  } __randomize_layout;
  ```

  

### 0. 简介

使用 [LXR](http://elixir.free-electrons.com/linux/latest/source) 查找 Linux 内核中以下符号的定义：

  > - `struct file`
  > - `struct file_operations`
  > - `generic_ro_fops`
  > - `vfs_read()`

前两个看过了，现在就看看  generic_ro_fops 和 vfs_read 吧

  ```c
  const struct file_operations generic_ro_fops = {
  	.llseek		= generic_file_llseek,
  	.read_iter	= generic_file_read_iter,
  	.mmap		= generic_file_readonly_mmap,
  	.splice_read	= filemap_splice_read,
  };
  ```

这显然定义了一个通用的 readonly file operations。

  ```c
  ssize_t vfs_read(struct file *file, char __user *buf, size_t count, loff_t *pos)
  {
  	ssize_t ret;
  
  	if (!(file->f_mode & FMODE_READ))
  		return -EBADF;
  	if (!(file->f_mode & FMODE_CAN_READ))
  		return -EINVAL;
  	if (unlikely(!access_ok(buf, count)))
  		return -EFAULT;
  
  	ret = rw_verify_area(READ, file, pos, count);
  	if (ret)
  		return ret;
  	if (count > MAX_RW_COUNT)
  		count =  MAX_RW_COUNT;
  
  	if (file->f_op->read)
  		ret = file->f_op->read(file, buf, count, pos);
  	else if (file->f_op->read_iter)
  		ret = new_sync_read(file, buf, count, pos);
  	else
  		ret = -EINVAL;
  	if (ret > 0) {
  		fsnotify_access(file);
  		add_rchar(current, ret);
  	}
  	inc_syscr(current);
  	return ret;
  }
  ```

这个首先确认我们有权限读，然后就去检查从 file 的 pos 开始，是不是能读 count 个。之后它就去尝试用不同的方法去读。读完之后，就去通知访问过，更新计数（current + ret），然后增加系统调用的计数。

### 1. 注册/注销[¶](https://linux-kernel-labs-zh.xyz/labs/device_drivers.html#section-14)

驱动程序控制一个具有 `MY_MAJOR` 主设备号和 `MY_MINOR` 次设备号的设备（这些宏定义在 kernel/so2_cdev.c 文件中）。

1. 使用 **mknod** 创建 **/dev/so2_cdev** 字符设备节点。

2. 在 init 和 exit 模块函数中实现设备的注册和注销，设备名称应为 `so2_cdev`。实现 **TODO 1**。

3. 通过 `pr_info` 函数使得在注册和注销操作后显示一条消息，以确认它们是否成功。然后将模块加载到内核中：

```bash
$ insmod so2_cdev.ko
```

并查看 `/proc/devices` 中的字符设备：

```bash
$ cat /proc/devices | less
```

确定使用主设备号 42 注册的设备类型。请注意，`/proc/devices` 仅包含设备类型（主设备号），而不包含实际设备（即次设备号）。

:::info

/dev 中的条目不会通过加载模块来创建。可以通过两种方式创建：

- 手动使用 `mknod` 命令，就像我们上面所做的那样。

- 使用 udev 守护进程自动创建

:::

4. 卸载内核模块

```bash
rmmod so2_cdev
```



观察 so2_cdev.c 文件，我们可以看到它是 42,0，那我们就创一个

```bash
root@qemux86:~/.ash_history/kernel# mknod /dev/so2_cdev c 42 0
```

TODO 1

```c
static int so2_cdev_init(void)
{
	int err;
	int i;

	/* TODO 1: register char device region for MY_MAJOR and NUM_MINORS starting at MY_MINOR */
	register_chrdev_region(MKDEV(MY_MAJOR, MY_MINOR), NUM_MINORS, MODULE_NAME);

	for (i = 0; i < NUM_MINORS; i++) {
#ifdef EXTRA
		/* TODO 7: extra tasks, for home */
#else
		/*TODO 4: initialize buffer with MESSAGE string */
		/* TODO 3: set access variable to 0, use atomic_set */
#endif
		/* TODO 7: extra tasks for home */
		/* TODO 2: init and add cdev to kernel core */
	}

	return 0;
}

static void so2_cdev_exit(void)
{
	int i;

	for (i = 0; i < NUM_MINORS; i++) {
		/* TODO 2: delete cdev from kernel core */
	}

	/* TODO 1: unregister char device region, for MY_MAJOR and NUM_MINORS starting at MY_MINOR */
	unregister_chrdev_region(MKDEV(MY_MAJOR, MY_MINOR), NUM_MINORS);
}
```

要加 info 也是很简单，就不说了。但是不知道为什么我这写反了么还是什么，第一次 ins 的时候没有东西，第一次 rm 的时候提示 Register，后面 ins 则提示 unRegister，神秘。

```c
pr_info("WHOW, YOU unREGISTERED %d DEVICES!!!!", NUM_MINORS);
```

```c
root@qemux86:~/.ash_history/kernel# insmod so2_cdev.ko
WHOW, YOU unREGISTERED 1 DEVICES!!!!
root@qemux86:~/.ash_history/kernel# rmmod so2_cdev.ko
WHOW, YOU REGISTERED 1 DEVICES!!!!
```



### 2. 注册一个已注册的主设备号[¶](https://linux-kernel-labs-zh.xyz/labs/device_drivers.html#section-15)

修改 **MY_MAJOR**，使其指向已经使用的主设备号。

提示

查看 `/proc/devices` 来获取一个已分配的主设备号。

参考 [errno-base.h](http://elixir.free-electrons.com/linux/v4.9/source/include/uapi/asm-generic/errno-base.h) 并找出错误码的含义。恢复模块的初始配置。



```c
root@qemux86:~/.ash_history/kernel# cat /proc/devices
Character devices:
  1 mem
  2 pty
  3 ttyp
  4 /dev/vc/0
  4 tty
  5 /dev/tty
  5 /dev/console
  5 /dev/ptmx
  7 vcs
 10 misc
 13 input
128 ptm
136 pts
229 hvc
253 virtio-portsdev
254 bsg
```



我们把它改成 4 试试看，咋没报错呢。哈哈，原来是我们没有处理报错。改成这样

```c
err = register_chrdev_region(MKDEV(MY_MAJOR, MY_MINOR), NUM_MINORS, MODULE_NAME);
	if (err < 0) {
		pr_err("Failed to register char device: %d", err);
		return err;
	}
	pr_info("WHOW, YOU REGISTERED %d DEVICES!!!!", NUM_MINORS);
```

有报错了：insmod: can't insert 'so2_cdev.ko': Device or resource busy

### 3. 打开和关闭[¶](https://linux-kernel-labs-zh.xyz/labs/device_drivers.html#section-16)

运行 `cat /dev/so2_cdev` ，从我们的字符设备中读取数据。由于驱动程序没有实现打开函数，因此读取操作无法正常工作。按照标记为 TODO 2 的注释进行操作并实现以下内容。

> 1. 初始化设备
>    - 在 `so2_device_data` 结构体中添加一个 cdev 字段。
>    - 阅读实验中的 [字符设备的注册和注销](https://linux-kernel-labs-zh.xyz/labs/device_drivers.html#section-7) 部分。
> 2. 在驱动程序中实现打开和释放函数。
> 3. 在打开和释放函数中显示一条消息。
> 4. 再次读取 `/dev/so2_cdev` 文件。按照内核显示的消息进行操作。由于尚未实现 `read` 函数，因此仍会出现错误。



cdev 是 `struct cdev` 类型，不是指针。

```c
struct so2_device_data {
	/* TODO 2: add cdev member */
	struct cdev cdev;
	/* TODO 4: add buffer with BUFSIZ elements */
	/* TODO 7: extra members for home */
	/* TODO 3: add atomic_t access variable to keep track if file is opened */
};

static int so2_cdev_open(struct inode *inode, struct file *file)
{
	struct so2_device_data *data;

	/* TODO 2: print message when the device file is open. */
	pr_info("Whow, the device file is open!!!!");
    
static int
so2_cdev_release(struct inode *inode, struct file *file)
{
	/* TODO 2: print message when the device file is closed. */
	pr_info("No!!! You closed the device, you evil!");
    
static const struct file_operations so2_fops = {
	.owner = THIS_MODULE,
/* TODO 2: add open and release functions */
	.open = so2_cdev_open,
	.release = so2_cdev_release,
    

static int so2_cdev_init(void)
{
	int err;
	int i;

	/* TODO 1: register char device region for MY_MAJOR and NUM_MINORS starting at MY_MINOR */
	err = register_chrdev_region(MKDEV(MY_MAJOR, MY_MINOR), NUM_MINORS, MODULE_NAME);
	if (err < 0) {
		pr_err("Failed to register char device: %d", err);
		return err;
	}
	pr_info("WHOW, YOU REGISTERED %d DEVICES!!!!", NUM_MINORS);

	for (i = 0; i < NUM_MINORS; i++) {
#ifdef EXTRA
		/* TODO 7: extra tasks, for home */
#else
		/*TODO 4: initialize buffer with MESSAGE string */
		/* TODO 3: set access variable to 0, use atomic_set */
#endif
		/* TODO 7: extra tasks for home */
		/* TODO 2: init and add cdev to kernel core */
		cdev_init(&devs[i].cdev, &so2_fops);
		cdev_add(&devs[i].cdev, MKDEV(MY_MAJOR, i), 1);
	}
    
    
static void so2_cdev_exit(void)
{
	int i;

	for (i = 0; i < NUM_MINORS; i++) {
		/* TODO 2: delete cdev from kernel core */
		cdev_del(&devs[i].cdev);
	}
```

```bash
root@qemux86:~/.ash_history/kernel# cat /dev/so2_cdev
WHOW, YOU REGISTERED 1 DEVICES!!!!
cat: read error: Invalid argument
Whow, the device file is open!!!!
root@qemux86:~/.ash_history/kernel# cat /dev/so2_cdev
No!!! You closed the device, you evil!
cat: read error: Invalid argument
Whow, the device file is open!!!!
```

非常好！



### 4. 访问限制[¶](https://linux-kernel-labs-zh.xyz/labs/device_drivers.html#section-17)

使用原子变量限制设备访问，以便一次只能有一个进程打开该设备。其他进程将收到“设备忙”错误 (`-EBUSY`)。限制访问将在驱动程序中的打开函数中完成。按照标记为 **TODO 3** 的注释进行操作并实现以下内容。

> 1. 在设备结构体中添加 `atomic_t` 变量。
> 2. 在模块初始化时对该变量进行初始化。
> 3. 在打开函数中使用该变量限制对设备的访问。我们建议使用 `atomic_cmpxchg()`。
> 4. 在释放函数中重置该变量以恢复对设备的访问权限。
> 5. 要测试你的部署，你需要模拟对设备的长期使用。要模拟休眠，请在设备打开操作的末尾调用调度器：

```c
set_current_state(TASK_INTERRUPTIBLE);
schedule_timeout(1000);
```

注解

atomic_cmpxchg 函数的优点在于它可以在一个原子操作中检查变量的旧值并将其设置为新值。详细了解 [atomic_cmpxchg](https://www.khronos.org/registry/OpenCL/sdk/1.1/docs/man/xhtml/atomic_cmpxchg.html)。这里有一个使用示例 http://elixir.free-electrons.com/linux/v4.9/source/lib/dump_stack.c#L24 。



练练手

```c
/*
 * Character device drivers lab
 *
 * All tasks
 */

#include <asm/atomic.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/wait.h>

#include "../include/so2_cdev.h"

MODULE_DESCRIPTION("SO2 character device");
MODULE_AUTHOR("SO2");
MODULE_LICENSE("GPL");

#define LOG_LEVEL	KERN_INFO

#define MY_MAJOR		42
#define MY_MINOR		0
#define NUM_MINORS		1
#define MODULE_NAME		"so2_cdev"
#define MESSAGE			"hello\n"
#define IOCTL_MESSAGE		"Hello ioctl"

#ifndef BUFSIZ
#define BUFSIZ		4096
#endif


struct so2_device_data {
	/* TODO 2: add cdev member */
	struct cdev cdev;
	/* TODO 4: add buffer with BUFSIZ elements */
	/* TODO 7: extra members for home */
	/* TODO 3: add atomic_t access variable to keep track if file is opened */
	atomic_t access;
};

struct so2_device_data devs[NUM_MINORS];

static int so2_cdev_open(struct inode *inode, struct file *file)
{
	struct so2_device_data *data;

	/* TODO 2: print message when the device file is open. */
	pr_info("Whow, the device file is open!!!!");

	/* TODO 3: inode->i_cdev contains our cdev struct, use container_of to obtain a pointer to so2_device_data */
	data = container_of(inode->i_cdev, struct so2_device_data, cdev);

	file->private_data = data;

#ifndef EXTRA
	/* TODO 3: return immediately if access is != 0, use atomic_cmpxchg */
	if (atomic_cmpxchg(&data->access, 0, 1) != 0) {
		pr_info("I'm using the device!!!!");
		return -EBUSY;
	}
#endif

	set_current_state(TASK_INTERRUPTIBLE);
	schedule_timeout(10 * HZ);

	return 0;
}

static int
so2_cdev_release(struct inode *inode, struct file *file)
{
	/* TODO 2: print message when the device file is closed. */
	pr_info("No!!! You closed the device, you evil!");

#ifndef EXTRA
	struct so2_device_data *data =
		(struct so2_device_data *) file->private_data;

	/* TODO 3: reset access variable to 0, use atomic_set */
	atomic_set(&data->access, 0);
#endif
	return 0;
}

static ssize_t
so2_cdev_read(struct file *file,
		char __user *user_buffer,
		size_t size, loff_t *offset)
{
	struct so2_device_data *data =
		(struct so2_device_data *) file->private_data;
	size_t to_read;

#ifdef EXTRA
	/* TODO 7: extra tasks for home */
#endif

	/* TODO 4: Copy data->buffer to user_buffer, use copy_to_user */

	return to_read;
}

static ssize_t
so2_cdev_write(struct file *file,
		const char __user *user_buffer,
		size_t size, loff_t *offset)
{
	struct so2_device_data *data =
		(struct so2_device_data *) file->private_data;


	/* TODO 5: copy user_buffer to data->buffer, use copy_from_user */
	/* TODO 7: extra tasks for home */

	return size;
}

static long
so2_cdev_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct so2_device_data *data =
		(struct so2_device_data *) file->private_data;
	int ret = 0;
	int remains;

	switch (cmd) {
	/* TODO 6: if cmd = MY_IOCTL_PRINT, display IOCTL_MESSAGE */
	/* TODO 7: extra tasks, for home */
	default:
		ret = -EINVAL;
	}

	return ret;
}

static const struct file_operations so2_fops = {
	.owner = THIS_MODULE,
/* TODO 2: add open and release functions */
	.open = so2_cdev_open,
	.release = so2_cdev_release,
/* TODO 4: add read function */
/* TODO 5: add write function */
/* TODO 6: add ioctl function */
};

static int so2_cdev_init(void)
{
	int err;
	int i;

	/* TODO 1: register char device region for MY_MAJOR and NUM_MINORS starting at MY_MINOR */
	err = register_chrdev_region(MKDEV(MY_MAJOR, MY_MINOR), NUM_MINORS, MODULE_NAME);
	if (err < 0) {
		pr_err("Failed to register char device: %d", err);
		return err;
	}
	pr_info("WHOW, YOU REGISTERED %d DEVICES!!!!", NUM_MINORS);

	for (i = 0; i < NUM_MINORS; i++) {
#ifdef EXTRA
		/* TODO 7: extra tasks, for home */
#else
		/*TODO 4: initialize buffer with MESSAGE string */
		/* TODO 3: set access variable to 0, use atomic_set */
		atomic_set(&devs[i].access, 0);
#endif
		/* TODO 7: extra tasks for home */
		/* TODO 2: init and add cdev to kernel core */
		cdev_init(&devs[i].cdev, &so2_fops);
		cdev_add(&devs[i].cdev, MKDEV(MY_MAJOR, i), 1);
	}

	return 0;
}

static void so2_cdev_exit(void)
{
	int i;

	for (i = 0; i < NUM_MINORS; i++) {
		/* TODO 2: delete cdev from kernel core */
		cdev_del(&devs[i].cdev);
	}

	/* TODO 1: unregister char device region, for MY_MAJOR and NUM_MINORS starting at MY_MINOR */
	
	unregister_chrdev_region(MKDEV(MY_MAJOR, MY_MINOR), NUM_MINORS);
	pr_info("WHOW, YOU REGISTERED %d DEVICES!!!!", NUM_MINORS);
}

module_init(so2_cdev_init);
module_exit(so2_cdev_exit);

```

虽然输出和我们想的不一样，但是还是能跑的，哈哈

```bash
root@qemux86:~/.ash_history/kernel# cat /dev/so2_cdev & cat /dev/so2_cdev &
root@qemux86:~/.ash_history/kernel# Whow, the device file is open!!!!
Whow, the device file is open!!!!
cat: can't open '/dev/so2_cdev': Device or resource busy

[2]+  Done(1)                    cat /dev/so2_cdev
root@qemux86:~/.ash_history/kernel# cat: read error: Invalid argument
I'm using the device!!!!

[1]+  Done(1)                    cat /dev/so2_cdev
```

### 5. 读操作[¶](https://linux-kernel-labs-zh.xyz/labs/device_drivers.html#section-18)

在驱动程序中实现读取函数。按照标有 `TODO 4` 的注释并实现以下步骤：

> 1. 在 `so2_device_data` 结构中保持一个缓冲区，并用 `MESSAGE` 宏的值进行初始化。缓冲区的初始化在模块的 `init` 函数中完成。
> 2. 在读取调用时，将内核空间缓冲区的内容复制到用户空间缓冲区。
>    - 使用 `copy_to_user()` 函数将信息从内核空间复制到用户空间。
>    - 暂时忽略大小和偏移参数。可以假设用户空间的缓冲区足够大，不需要检查读取函数的大小参数的有效性。
>    - 读取调用返回的值是从内核空间缓冲区传输到用户空间缓冲区的字节数。
> 3. 实现完成后，使用 `cat /dev/so2_cdev` 进行测试。

:::info

命令 `cat /dev/so2_cdev` 不会结束（使用Ctrl+C）。请阅读 [读取和写入](https://linux-kernel-labs-zh.xyz/labs/device_drivers.html#section-10) 和 [访问进程地址空间](https://linux-kernel-labs-zh.xyz/labs/device_drivers.html#section-8) 部分。如果要显示偏移值，请使用以下形式的构造: `pr_info("Offset: %lld \n", *offset)`；偏移值的数据类型 `loff_t` 是 `long long int` 的 typedef。

:::

`cat` 命令一直读取到文件的末尾，文件通过读取返回值为 0 来表示读到末尾了。因此，为了正确实现，你需要更新并使用读函数中接收的偏移参数，并在用户达到缓冲区末尾时返回 0。

修改驱动程序以使 `cat` 命令结束：

> 1. 使用大小参数。
> 2. 对于每次读取，相应地更新偏移参数。
> 3. 确保读取函数返回已复制到用户缓冲区的字节数。

:::info

通过解引用偏移参数，可以读取并移动在文件中的当前位置。每次成功进行读取后都需要更新其值。

:::



我们首先测试第一个，忽略 Offset 的

```c
/*
 * Character device drivers lab
 *
 * All tasks
 */

#include <asm/atomic.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/wait.h>

#include "../include/so2_cdev.h"

MODULE_DESCRIPTION("SO2 character device");
MODULE_AUTHOR("SO2");
MODULE_LICENSE("GPL");

#define LOG_LEVEL	KERN_INFO

#define MY_MAJOR		42
#define MY_MINOR		0
#define NUM_MINORS		1
#define MODULE_NAME		"so2_cdev"
#define MESSAGE			"hello\n"
#define IOCTL_MESSAGE		"Hello ioctl"

#ifndef BUFSIZ
#define BUFSIZ		4096
#endif


struct so2_device_data {
	/* TODO 2: add cdev member */
	struct cdev cdev;
	/* TODO 4: add buffer with BUFSIZ elements */
	char buffer[BUFSIZ];
	/* TODO 7: extra members for home */
	/* TODO 3: add atomic_t access variable to keep track if file is opened */
	atomic_t access;
};

struct so2_device_data devs[NUM_MINORS];

static int so2_cdev_open(struct inode *inode, struct file *file)
{
	struct so2_device_data *data;

	/* TODO 2: print message when the device file is open. */
	pr_info("Whow, the device file is open!!!!");

	/* TODO 3: inode->i_cdev contains our cdev struct, use container_of to obtain a pointer to so2_device_data */
	data = container_of(inode->i_cdev, struct so2_device_data, cdev);

	file->private_data = data;

#ifndef EXTRA
	/* TODO 3: return immediately if access is != 0, use atomic_cmpxchg */
	if (atomic_cmpxchg(&data->access, 0, 1) != 0) {
		pr_info("I'm using the device!!!!");
		return -EBUSY;
	}
#endif

	// set_current_state(TASK_INTERRUPTIBLE);
	// schedule_timeout(10 * HZ);

	return 0;
}

static int
so2_cdev_release(struct inode *inode, struct file *file)
{
	/* TODO 2: print message when the device file is closed. */
	pr_info("No!!! You closed the device, you evil!");

#ifndef EXTRA
	struct so2_device_data *data =

		(struct so2_device_data *) file->private_data;

	/* TODO 3: reset access variable to 0, use atomic_set */
	atomic_set(&data->access, 0);
#endif
	return 0;
}

static ssize_t
so2_cdev_read(struct file *file,
		char __user *user_buffer,
		size_t size, loff_t *offset)
{
	struct so2_device_data *data =
		(struct so2_device_data *) file->private_data;
	size_t to_read;

#ifdef EXTRA
	/* TODO 7: extra tasks for home */
#endif

	/* TODO 4: Copy data->buffer to user_buffer, use copy_to_user */
	int err = copy_to_user(user_buffer, data->buffer, strlen(data->buffer));
	if (err) {
		pr_err("Failed to copy data to user space\n");
		return -EFAULT;
	}
	to_read = strlen(data->buffer);
	pr_info("size: %d, to_read: %d", size, to_read);
	pr_info("Content: %s", data->buffer);

	return to_read;
}

static ssize_t
so2_cdev_write(struct file *file,
		const char __user *user_buffer,
		size_t size, loff_t *offset)
{
	struct so2_device_data *data =
		(struct so2_device_data *) file->private_data;


	/* TODO 5: copy user_buffer to data->buffer, use copy_from_user */
	/* TODO 7: extra tasks for home */

	return size;
}

static long
so2_cdev_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct so2_device_data *data =
		(struct so2_device_data *) file->private_data;
	int ret = 0;
	int remains;

	switch (cmd) {
	/* TODO 6: if cmd = MY_IOCTL_PRINT, display IOCTL_MESSAGE */
	/* TODO 7: extra tasks, for home */
	default:
		ret = -EINVAL;
	}

	return ret;
}

static const struct file_operations so2_fops = {
	.owner = THIS_MODULE,
/* TODO 2: add open and release functions */
	.open = so2_cdev_open,
	.release = so2_cdev_release,
/* TODO 4: add read function */
	.read = so2_cdev_read,
/* TODO 5: add write function */
/* TODO 6: add ioctl function */
};

static int so2_cdev_init(void)
{
	int err;
	int i;

	/* TODO 1: register char device region for MY_MAJOR and NUM_MINORS starting at MY_MINOR */
	err = register_chrdev_region(MKDEV(MY_MAJOR, MY_MINOR), NUM_MINORS, MODULE_NAME);
	if (err < 0) {
		pr_err("Failed to register char device: %d", err);
		return err;
	}
	pr_info("WHOW, YOU REGISTERED %d DEVICES!!!!", NUM_MINORS);

	for (i = 0; i < NUM_MINORS; i++) {
#ifdef EXTRA
		/* TODO 7: extra tasks, for home */
#else
		/*TODO 4: initialize buffer with MESSAGE string */
		strncpy(devs[i].buffer, MESSAGE, strlen(MESSAGE));
		/* TODO 3: set access variable to 0, use atomic_set */
		atomic_set(&devs[i].access, 0);
#endif
		/* TODO 7: extra tasks for home */
		/* TODO 2: init and add cdev to kernel core */
		cdev_init(&devs[i].cdev, &so2_fops);
		cdev_add(&devs[i].cdev, MKDEV(MY_MAJOR, i), 1);
	}

	return 0;
}

static void so2_cdev_exit(void)
{
	int i;

	for (i = 0; i < NUM_MINORS; i++) {
		/* TODO 2: delete cdev from kernel core */
		cdev_del(&devs[i].cdev);
	}

	/* TODO 1: unregister char device region, for MY_MAJOR and NUM_MINORS starting at MY_MINOR */
	
	unregister_chrdev_region(MKDEV(MY_MAJOR, MY_MINOR), NUM_MINORS);
	pr_info("WHOW, YOU REGISTERED %d DEVICES!!!!", NUM_MINORS);
}

module_init(so2_cdev_init);
module_exit(so2_cdev_exit);

```

在这里，我们就读取一点点 :P 然后它就一直在传



然后我们继续改一下，让他没问题

```c
static ssize_t
so2_cdev_read(struct file *file,
		char __user *user_buffer,
		size_t size, loff_t *offset)
{
	struct so2_device_data *data =
		(struct so2_device_data *) file->private_data;
	size_t to_read;

#ifdef EXTRA
	/* TODO 7: extra tasks for home */
#endif

	/* TODO 4: Copy data->buffer to user_buffer, use copy_to_user */
	to_read = min(size, (unsigned int)(strlen(data->buffer) - *offset));
	if (to_read <= 0) return 0;
	if (copy_to_user(user_buffer, data->buffer + *offset, to_read)) {
		pr_err("Failed to copy data to user space\n");
		return -EFAULT;
	}
	*offset += to_read;
	return to_read;
}
```

```bash
root@qemux86:~/.ash_history/kernel# cat /dev/so2_cdev
WHOW, YOU REGISTERED 1 DEVICES!!!!
hello
Whow, the device file is open!!!!
```

### 6. 写操作[¶](https://linux-kernel-labs-zh.xyz/labs/device_drivers.html#section-19)

添加将消息写入内核缓冲区以替换预定义消息的功能。在驱动程序中实现写函数。按照标有 `TODO 5` 的注释进行操作。

此时忽略偏移参数。你可以假设驱动程序缓冲区足够大。你无需检查写函数大小参数的有效性。

注意

设备驱动程序操作的原型位于 file_operations 结构中。使用以下命令进行测试：

```
echo "arpeggio"> /dev/so2_cdev
cat /dev/so2_cdev
```

请阅读 [读取和写入](https://linux-kernel-labs-zh.xyz/labs/device_drivers.html#section-10) 小节和 [访问进程地址空间](https://linux-kernel-labs-zh.xyz/labs/device_drivers.html#section-8) 小节。



简单简单

```c
static const struct file_operations so2_fops = {
	.owner = THIS_MODULE,
/* TODO 2: add open and release functions */
	.open = so2_cdev_open,
	.release = so2_cdev_release,
/* TODO 4: add read function */
	.read = so2_cdev_read,
/* TODO 5: add write function */
	.write = so2_cdev_write,
/* TODO 6: add ioctl function */
};

static ssize_t
so2_cdev_write(struct file *file,
		const char __user *user_buffer,
		size_t size, loff_t *offset)
{
	struct so2_device_data *data =
		(struct so2_device_data *) file->private_data;


	/* TODO 5: copy user_buffer to data->buffer, use copy_from_user */
	copy_from_user(data->buffer, user_buffer, size);
	data->buffer[size] = '\0';
	/* TODO 7: extra tasks for home */

	return size;
}
```

### 7. ioctl 操作[¶](https://linux-kernel-labs-zh.xyz/labs/device_drivers.html#ioctl-2)

对于这个练习，我们希望在驱动程序中添加 ioctl `MY_IOCTL_PRINT` 来显示来自宏 `IOCTL_MESSAGE` 的消息。按照标有 `TODO 6` 的注释进行操作。

为此：

> 1. 在驱动程序中实现 ioctl 函数。
> 2. 我们需要使用 `user/so2_cdev_test.c` 调用 ioctl 函数，并传递适当的参数。
> 3. 为了进行测试，我们将使用一个用户空间程序 (`user/so2_cdev_test.c`) 来调用具有所需参数的 `ioctl` 函数。

:::tip

宏 `MY_IOCTL_PRINT` 在文件 `include/so2_cdev.h` 中定义，该文件在内核模块和用户空间程序之间共享。

请阅读实验中的 [ioctl](https://linux-kernel-labs-zh.xyz/labs/device_drivers.html#ioctl) 章节。
:::

:::tip

用户空间代码在 `make build` 时会自动编译，并在 `make copy` 时被复制。

由于我们需要为 32 位的 qemu 机器编译程序，如果你的主机是 64 位的，那么你需要安装 `gcc-multilib` 软件包。

:::



```c title="so2_cdev_ioctl.c"
static long
so2_cdev_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct so2_device_data *data =
		(struct so2_device_data *) file->private_data;
	int ret = 0;
	int remains;

	switch (cmd) {
	/* TODO 6: if cmd = MY_IOCTL_PRINT, display IOCTL_MESSAGE */
	case MY_IOCTL_PRINT:
		pr_info("%s\n", IOCTL_MESSAGE);
		break;
	/* TODO 7: extra tasks, for home */
	default:
		ret = -EINVAL;
	}

	return ret;
}

static const struct file_operations so2_fops = {
	.owner = THIS_MODULE,
/* TODO 2: add open and release functions */
	.open = so2_cdev_open,
	.release = so2_cdev_release,
/* TODO 4: add read function */
	.read = so2_cdev_read,
/* TODO 5: add write function */
	.write = so2_cdev_write,
/* TODO 6: add ioctl function */
	.unlocked_ioctl = so2_cdev_ioctl
};
```

```bash
root@qemux86:~/skels/device_drivers/user# ./so2_cdev_test p
WHOW, YOU REGISTERED 1 DEVICES!!!!
Whow, the device file is open!!!!
Hello ioctl
```

### Ex1. 带消息的 ioctl[¶](https://linux-kernel-labs-zh.xyz/labs/device_drivers.html#ioctl-3)

为驱动程序添加两个 ioctl 操作，用于修改与驱动程序关联的消息。应使用固定长度的缓冲区（BUFFER_SIZE）。

1. 在驱动程序的 ioctl 函数中添加以下操作：
   - `MY_IOCTL_SET_BUFFER`：用于向设备写入消息；
   - `MY_IOCTL_GET_BUFFER`：用于从设备读取消息。
2. 为进行测试，将所需的命令行参数传递给用户空间程序。



以 SET_BUFFER 为例，我们可以看到它会 ioctl 传一个 char[] 过去

差不多就这个样子吧，我虚拟机打不开了。

```c
static long
so2_cdev_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct so2_device_data *data =
		(struct so2_device_data *) file->private_data;
	int ret = 0;
	int remains;

	switch (cmd) {
	/* TODO 6: if cmd = MY_IOCTL_PRINT, display IOCTL_MESSAGE */
	case MY_IOCTL_PRINT:
		pr_info("%s\n", IOCTL_MESSAGE);
		break;
	/* TODO 7: extra tasks, for home */
	case MY_IOCTL_SET_BUFFER:
		if (copy_to_user(data->buffer, (char __user *)arg, BUFSIZ)) {
			pr_err("ERR!!!");
			return -EFAULT;
		}
		data->buffer[BUFSIZ - 1] = '\0';
		pr_info("I set %s", data->buffer);
		break;
	case MY_IOCTL_GET_BUFFER:
		if(copy_to_user((char __user *) arg, data->buffer, strlen(data->buffer))) {
			pr_err("ERR!!!");
			return -EFAULT;
		}
		pr_info("I put %s to 0x%lx", data->buffer, arg);
		break;
	default:
		ret = -EINVAL;
	}

	return ret;
}
```

