---
title: Linux 内核的简述
---

## 内核态 vs 用户态（x86_64）
### 更多的寄存器
在内核态下，我们有更多的寄存器可以使用，且它们有不同的功能
- **FS.base**: 保存了 fs 的基地址
- **GS.base**: 保存了 gs 的基地址
- **KernelGSBase**：在用户态和内核态切换时保存 gs_base 的值
- **CR0**、**CR2**、**CR3**、**CR4**、**CR8**：控制寄存器，主要是一些属性或者功能的开关。
- ...

:::info

更多信息及细节，可以参考：[CPU Registers x86-64 - OSDev Wiki](https://wiki.osdev.org/CPU_Registers_x86-64#FS.base.2C_GS.base)

:::



### 更多的指令

- **HLT**: 使CPU进入低功耗模式直到下一个外部中断被触发。
- **IN/OUT**: 访问I/O端口，用于与硬件设备的直接数据传输。
- **CLI/STI**: 禁用或启用中断。
- **LGDT/LIDT**: 加载全局描述符表（GDT）或中断描述符表（IDT）的基地址和界限。
- **LTR**: 加载任务寄存器，用于任务切换。
- **MOV 到 CR0/CR3/CR4 等控制寄存器**: 修改控制寄存器，这些寄存器控制着内存管理、分页和缓存机制等关键功能。

当然，这其中的某些指令在用户态满足一定条件的情况下也可被调用。例如：**RDTSC** 这个用于读取 TimeStampCounter 的指令，在 `CR4` 寄存器的 `TSD` 标志未被设置时，即可在用户态下被调用。



## 内核态利用结果

- **提权（Privilege Escalation）/ 权限维持（Privilege Persistence）**：可能的 Payload：`commit_creds(prepare_kernel_cred(0))`
- **SECCOMP 沙箱逃逸**：可能的 Payload：`current->thread_info.flags &= ~(1 « TIF_SECCOMP)`



## 内核保护机制

### KASLR

内核基址的偏移

### FG-KASLR

对于每一个函数的基址，都进行偏移

### Kernel Stack Canary

与 Userspace Canary 相同，每一个 TASK 仅包含一个 Canary

### SMEP(Supervisor Mode Execution Prevention)

禁止内核执行用户态代码

### SMAP(Supervisor Mode Access Prevention)

禁止内核访问用户态内存



