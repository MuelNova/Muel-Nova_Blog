---
title: 「PWN」【XCTF-final 7th】Pwn Writeup WP Reproduction
authors: [nova]
tags: ["CTF", "Pwn", "writeup", "wp"]
---

import Link from '@docusaurus/Link';

First offline competition? All thanks to the senior brother's guidance, ranked second on the first day of the problem-solving competition, but unfortunately lost at the King of Hill on the second day and only got the first prize in the end.

~~To be precise, it seems that this award has nothing to do with me (laughs)~~

But I learned a lot.

<!--truncate-->

## Let's play shellgame

Misc Pwn, with 6 solutions in the Misc branch.
Luckily got the first blood.

There are many tricks in the whole problem, and there are many optimizations in the final exp. However, during the competition, there wasn't much time to consider them.

### Program Analysis

![image-20230409233807386](https://oss.nova.gal/img/image-20230409233807386.png)

Firstly, let's analyze the logic: Change the permissions of memory from 0 to 0x1000 to RWX, then run the code in this memory, so it is inferred that shellcode needs to be written.

![image-20230409234142546](https://oss.nova.gal/img/image-20230409234142546.png)

In `init_env`, the `name` is filled with 160 random numbers, and the first ten random numbers are output. Noticing that `seed` is only 256, so we can actually brute force the initial seed, and then complete all 160 bits of the name.

![image-20230409234335295](https://oss.nova.gal/img/image-20230409234335295.png)

![image-20230409234421662](https://oss.nova.gal/img/image-20230409234421662.png)

Observe the `getnumber` function, it reads in 0x14 bytes of content to the `buffer`, but the `buffer` size is 0x10, which can overflow to cover the following `seed`, but the effect is not clear for now.

![image-20230409234626691](https://oss.nova.gal/img/image-20230409234626691.png)

In the `playgame` function, the random number seed is reset, so in the `getnumber` function we can directly set the random number seed, thereby controlling it to some extent.

Continuing to look at `playgame`, it changes `name[i]` as well as `name[i-1]` and `name[i+1]`, so we can consider such operations:

- Knowing `name[i] = y`, if you want to set `name[i]` to a specific value x, you can use a specific random number seed by specifying `name[i+1]`, making `rand()%256` as `x-y`.
- Then, `name[i+1]` will also increase by another `rand() % 256`, `name[i+2]` will also increase.
- Afterwards, we can repeat this process, setting `name[i+2]` to determine `name[i+1]` to a specific value.
- Finally, using n+1 names, we can control the values of `name[0, 1, ..., n]`, noting that n+2 will also change.

![image-20230409235536471](https://oss.nova.gal/img/image-20230409235536471.png)

Let's look at the next condition. First, it ensures that `name[i]` is between 47 and 122, meaning our name needs to be visible. Of course, we can bypass its check on the rest of the text by setting `name[n]` to 0.

Assuming there is no `messstr` function, we can set the name to this format, avoiding the need to set the entire 160 bytes of the name, not needing to consider if n+1 and n+2 are visible after adding random values to the first n names, and only setting `name[n] = \x00`.

```
-----------------------------------------------------
| visible shellcode | \x00 | \xde \xad \xbe \xef ..|
-----------------------------------------------------
```

![image-20230410000029657](https://oss.nova.gal/img/image-20230410000029657.png)

Finally, it is `messstr()`, where many teams likely got stuck. In simple terms, it permutes the name via the program's PID as the random number seed.

Instead of forcibly reversing this function, we determined through fuzzing methods, by setting the name to `'aaaaaaaaaaaaaaa...'`, that it was a permutation rather than some form of encryption.

Therefore, we can think: if we know the permutation rules for a certain PID (during debugging, we can set the rax register to a specific value after the `getpid()` function returns to set the return value), then we only need to use its inverse permutation to deduce the order of the name.

The problem is: generally, when we start a program, its PID usually changes. If we want to crack it, we can only obtain the permutation rules for one PID first, then iterate over the possibilities until the program PID matches the value we set. This brute force space is very large, and I reckon many teams had difficulties here.

Before writing the exploit, we happened to check the Dockerfile.

![image-20230410000627857](https://oss.nova.gal/img/image-20230410000627857.png)

Noticing that it uses the pwn.red/jail image, upon investigation, we found it is an entirely isolated sandbox environment. This prompted us to think: if it uses a method similar to spawning child processes, will `getpid()` fetch the PID of its parent process? So when repeatedly opening processes, since the parent process is not terminated, the PID remains constant.

Subsequently, we wrote a program to print the PID, and by modifying the dockerfile, we placed it in the sandbox for execution.

```c
#include <unistd.h>
#include <stdio.h>

int main(int argc, char const *argv[])
{
    /* code */
    printf("%d\n", getpid());
    return 0;
}

```

After testing, we found that this function always returns 1, making the brute force problem much simpler.

Finally, is how to write visible shellcode.

Because we have only 157 (the last three bits are used to bypass 0) bytes in length, it is not feasible to use existing visible shellcode to obtain a shell (it has 160+ bytes in length). Therefore, our approach was to generate a read shellcode according to [Alphanumeric shellcode - NetSec](https://nets.ec/Alphanumeric_shellcode), read in a large number of bytes (presumably without setting rdx, and rax may not need to be set either, which would simplify things a lot, but later we found that both needed to be set haha), and then slide through nop sleds to the getshell shellcode.

:::info

Actually, we didn't manually write the shellcode; instead, we used [veritas501/ae64: basic amd64 alphanumeric shellcode encoder (github.com)](https://github.com/veritas501/ae64) to directly generate the shellcode. It seems that hand-coding would be quite cumbersome, but it may be shorter?

:::

### Script Writing

Script writing is quite complex. Because there was a timeout issue in the on-site environment, we chose a precomputed approach, printing the random number seeds for the first number of `0~255` and the next two random numbers used to set the name. After testing the permutation table locally, the permutation order was printed out (a table of 145 bytes, with zeros padded for incomplete entries).

After receiving the `gift`, through brute forcing the random number seed for `0~255`, determining the random number, and obtaining the complete name for backup.

Next is setting the name, the implementation at that time was quite crude and not optimized, so please bear with it (laughs).

The overall exploit was not very satisfactory, as the name involved data types, and Python did not handle it very well. Numpy's `np.int8` was used, but not fully understood, resulting in low efficiency. In this type of competition, time is indeed precious, so I feel like I need to learn about data processing in Python or just write in C.

~~Fortunately, I still got the first blood~~

Final Exploit:

```python
# Exploit code translated as-is
```

<!-- AI -->
