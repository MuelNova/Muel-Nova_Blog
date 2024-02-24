---
title: Module 相关
---

module 都有一个 fp 结构体，用于表示不同 OPERATOR 时调用哪个函数。

```c
static struct file_operations module_fops =
{
    .owner   = THIS_MODULE,
    .read    = module_read,
    .write   = module_write,
    .open    = module_open,
    .release = module_close,
};
```



### cheatsheet

```bash
sudo insmod <module_name.ko>  # Load a module
sudo rmmod <module_name>  # Unload a module
lsmod  # List modules
```

