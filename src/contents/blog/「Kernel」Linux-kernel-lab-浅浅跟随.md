---
title: 「Kernel」Linux kernel lab 浅浅跟随
authors: [nova]
tags: [kernel]
date: 2024-07-14
last_update:
  author: nova
  date: 2024-07-16
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

