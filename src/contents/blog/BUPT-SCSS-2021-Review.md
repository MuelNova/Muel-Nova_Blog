---
title: BUPT-SCSS-2021-Review
date: 2021-12-31
tags: ["SCSS", "Study", cheatsheet]
authors: [nova]
---

# BUPT-SCSS-2021 大一上网安导论复习笔记

## 01 网络空间安全导论-基本理论及技术体系框架

<!--truncate-->

### 网络空间

继**海、陆、空、太空**之后的**第五空间**

动态虚拟空间，包括了**各种计算系统**、**网络**、**硬件软件**、**数据**和**信息**

### 网络空间安全

研究**信息**在产生、传输、储存、处理的过程中和**网络和系统**面临的**威胁和防御**措施

### 信息安全的主要特征

#### _机密性 Confidentiality_

**信息安全诞生就有的性质**

确保信息不能被非授权访问，即使被非授权访问也不能使用

#### _完整性 Integrity_

**维护了信息的一致性**

确保信息在产生、传输、储存、处理过程中不发生人为或非人为的非授权篡改

#### _可用性 Availability_

**保障信息随时可提供服务的能力**

确保信息能被授权用户根据需要随时访问

#### 不可否认性

信息真实的同一性

确保信息在事后无法被用户否认生成、签发、接收

#### 可控制性

信息、信息系统的监控

信息传播及内容的控制

#### 可审查性

使用审计、监控、签名等手段使得用户的行为有证可查

有利于事后追责

### 网络空间安全的主要内容

#### 物理安全

**基础设施的安全**

设备安全、电磁安全

#### 运行安全

**信息系统的安全**

系统安全、网络安全

#### 数据安全

**信息自身的安全**
加密保护

#### 内容安全

**信息利用的安全**

内容识别、大数据隐私

### 网络空间安全的目标

- **进不来**（访问控制机制）
- **拿不走**（授权机制）
- **看不懂**（加密机制）
- **改不了**（数据完整性机制）
- **逃不掉**（审计、监控、签名机制）
- **打不垮**（数据备份与灾难恢复机制）

### APPDRR 动态安全模型

> PPDR、PDRR - > APPDRR

#### Assessment 风险分析

掌握网络安全面临的风险信息，进而采取必要的处置措施

#### Policy 安全策略

**原则性的指导地位**

应根据风险评估及安全的需要做相应的更新

#### Protection 系统防护

主动安全防护体系

防火墙、访问控制、数据加密

#### Detection 实时监测

网络安全事件检测

入侵检测、流量分析

#### Reaction 实时响应

**恶意代码防范与应急响应技术**

对 DDOS、僵尸网络等资源消耗型攻击的抵御

#### Restoration 灾难恢复

**提高网络与信息系统的生存性、抗毁性和可靠性**

数据远程备份及快速恢复

灾难迁移与恢复

## 02 网络空间安全导论-密码 V2

### 密码系统的组成

#### 明文(Plaintext)

信息的原始形式

#### 密文(Ciphertext)

明文经过编码变换所生成的

#### 加密算法

对明文经过编码变换的过程叫做**加密（Encryption）**，编码的规则叫做**加密算法**

#### 解密算法

将密文恢复出明文的过程叫做**解密（Decryption）**，恢复的规则叫做**解密算法**

#### 密钥

控制明文与密文之间相互转换的，分为*加密密钥*和*解密密钥*

### 密码体制的分类

#### 按数据处理特点分类

- 分组密码：加密数据以组为单位
- 序列密码：以比特为单位

#### 按密码发展阶段分类

- 传统密码（古典密码）
  - 置换密码：打乱明文顺序（滚筒密码）
  - 代换密码：改变明文的字母（凯撒密码）
- 现代密码

#### 按密码特点分类

- 对称密码
- 非对称密码（公钥密码）

> 分组密码和序列密码可以看作是对称密码的分类

### 密码设备应具有的要素

安全、性能、易用、成本

### 分组的设计思想及其含义

#### 混乱

密钥、密文、明文之间的依赖关系复杂，使密码分析者难以利用

#### 扩散

明文的每一位数字影响密文的很多位数字，隐蔽明文数字统计特征

密钥的每一位数字影响密文的很多位数字，防止对密钥逐段破解

### Enigma 密码机

#### 接线板

增加密钥量

#### 转子

增加算法复杂度

#### 反射器

加解密算法相同

#### 每日密钥

密钥加密密钥

#### 通信密钥

会话密钥

#### 密码本

密码本是核心。

密码算法公开，安全依赖密钥

#### 五要素

- **明文**：明文
- **密文**：密文
- **加密算法**：单表代换+多表代换
- **解密算法**：相同
- **密钥**：接线板设置、转子排序、转子位置

### ~DES 加密算法

分组密码，将明文**64bits**分组，以**56bits**的**密钥**，生成**48bits**的**子密钥**加密，生成**64bits**的密文分组

#### 子密钥生成算法

简单、生成快

密钥的所有 bit 对每个子密钥 bit 的影响大致相同

#### 轮函数

- **非线性**：体现算法复杂度
- **可逆性**：实现解密
- **雪崩效应**

### 序列密码中密码序列产生器的要求

- 种子密钥长度长
- 极大周期
- 随机性
- 不可逆性
- 雪崩效应
- 密钥序列不可预测（知道前半段不能推后半段）

### 对称密码

#### 优点

运算速度快

密钥相对比较短

无数据拓展

#### 缺点

密钥分发难以实现

需秘密保存的密钥量大，难以维护

难以实现数字签名和认证的功能

### 公钥密码

#### 意义

**公钥密码体制**是**现代密码学的一个标志**，是目前为止密码学史上最大且唯一真正的革命

#### 思想

加密密钥是**公钥**

解密密钥是**私钥**

![image-20211227135423637](https://oss.nova.gal/img/image-20211227135423637.png)

#### 优点

密钥分发容易

需秘密保存的密钥量小

可以实现数字签名和认证的功能

#### 不足

运算速度慢

密钥长度长

有数据拓展

> 来自哈希和认证： 在没有证书的情况下无法确认对方获得公钥的身份

### ~Diffie-Hellman 密钥交换

#### 方案

公开协商 p 和 g

Alice 和 Bob 各自选取一个数 a, b

计算`g^a mod p = Ka` 和 `g^b mod p = Kb`传送给对方

有`Ka^b mod p = Kb^a mod p = K`

K 就是密钥

#### 成就

解决了*不可能的问题*

#### 不足

必须同时在线

### RSA 公钥密码

#### 单项陷门函数

已知 P 和 M，计算 C=P(M)容易

已知 C 不知 S，计算 M 困难

已知 C 和 S，计算 M=S(C)容易

#### ~算法

- 选取两个大素数 p 和 q

- 计算 n=p\*q

- 选取 e，满足 gcd(e,φ(n))=1
- d\*e ≡1（mod φ(n)）

p 和 q 保密

e 和 n 为公钥

d 为私钥

Ø 加密算法：c=E(m)≡m^e(mod n)

Ø 解密算法：m=D(c)≡c^d(mod n)

#### 简评

- **第一个**实用的**公开密钥算法**。
- 目前**使用最多**的一种公钥密码算法。
- RSA 的理论基础是数论的**欧拉定理**。
- RSA 的安全性依赖于**大数的素因子分解的困难性**。
- 密码分析者**既不能证明也不能否定** RSA 的安全性。
- 既能用于**加密**也能用于数字签名。
- 目前密钥长度**1024 位**是安全的。

### 基于公钥密码的密钥分配

看不懂，是不是说 Ks(Ks(N1)) = D ?

![image-20211227141202870](https://oss.nova.gal/img/image-20211227141202870.png)

#### 中间人攻击

C 替换了 B 的公钥为 C 的公钥，

劫持 A 发送给 B 的消息（实际上用了 C 的公钥加密），

使用 C 的私钥解密读取信息，

再使用 B 的公钥加密信息再发送给 B

## 03 网络空间安全导论-哈希和认证

### Hash 函数的性质

#### 特点

- 输入任意长
- 输出定长
- 容易计算
- 单向性

#### 安全性

- 抗弱碰撞

- 抗强碰撞

- 雪崩效应

### Hash 函数的实现基本过程

以 SHA-1 为例

初始值和消息分组 M0 作为 Hash 的参数传入，得到一个 160bits 的 output1

将输出与 M1 作为 Hash 的参数传入，得到一个 160bits 的 output2

...

最后得到 Hash 值

![image-20211227143712004](https://oss.nova.gal/img/image-20211227143712004.png)

### 消息认证

#### 目的

- 消息源认证：来源真实
- 消息完整性认证：未被篡改

#### 消息认证码(Messages Authentication Codes)

与单向哈希函数类似，但多了一个密钥作为参数，不同的密钥会产生不同的 hash 值。即可以在确定消息未被篡改的同时验证发送者

![image-20211227144247481](https://oss.nova.gal/img/image-20211227144247481.png)

### 数字签名

#### 特点

- **签名是可信的**：任何人都可以验证
- **签名是不可伪造的**：除了消息发送者任何人伪造签名都是困难的
- **签名是不可复制的**：一个消息的签名不可用于另一个消息
- **签名的消息是不可篡改的**：签名后的消息被篡改后任何人都可以发现
- **签名是不可抵赖的**：签名者不能抵赖自己的签名

#### 签名方案的组成

五元空间\{P, S, K, Sig, Ver\}

- P：明文空间
- S：签名空间
- K：密钥空间
- Sig：签名算法
- Ver：验证算法

#### 签名过程

- **系统初始化过程**：生成签名者的公私钥对等（上面的五元空间）
- **签名生成过程**：利用私钥使用签名算法对消息产生签名
- **签名验证过程**：利用公钥使用验证算法对消息验证

![image-20211227145439619](https://oss.nova.gal/img/image-20211227145439619.png)

### 消息认证与数字签名的区别

|                  | 消息认证           | 数字签名                   |
| ---------------- | ------------------ | -------------------------- |
| **发送者**       | 用对称密钥计算 MAC | 用私钥生成签名             |
| **接受者**       | 用对称密钥计算 MAC | 用公钥验证签名             |
| **密钥分发问题** | 存在               | 不存在，但公钥需要另外认证 |
| **效率**         | 高                 | 低                         |
| **完整性**       | 支持               | 支持                       |
| **认证性**       | 支持(仅限通信双方) | 支持(可适用于任何第三方)   |
| **不可否认性**   | 不支持             | 支持                       |

### 数字证书

将证书持有者的公钥及身份信息进行绑定的文件

#### 内容

- **版本号**
- **序列号**：CA 分配的唯一编号
- **认证机构表示**
- **主体标识**：证书持有者的名字
- **主体公钥**
- **证书有效期**：分为开始有效期和失效期
- **证书用途**
- **扩展内容**：证书附加信息
- **发证机构签名**：以以上内容用发证机关的**私钥**生成的签名

#### 特点

- 证书是文件，可复制
- 任何具有 CA 公钥的人都可以进行认证
- 除了 CA 外不能伪造、篡改证书
- 证书安全性依赖于 CA 的私钥

## 04 网络空间安全导论-恶意代码与计算机病毒

### 恶意代码

#### 含义

**未经授权**在信息系统中**安装执行**达到**不正当目的**的**程序**

**狭义**：计算机病毒、木马、后门、逻辑炸弹等恶意编制的计算机代码

**广义**：狭义的基础上，可能造成影响或隐患的垃圾软件、广告软件等

#### 特征

- **可执行代码**：嵌入正常程序 \ 独立程序
- **恶意目的**：经济利益 \ 成就感
- **强制安装**：漏洞 \ “误”操作
- **难以卸载**：不提供通用卸载方法，甚至可能复活
- **破坏性**

### 计算机病毒

#### 含义

编制者在计算机程序中插入的**破坏计算机功能或数据**、**影响计算机使用**并且能够**自我复制**的一组**计算机指令或者程序代码**

#### 特征

- **_传染性_**：病毒的基本、必备特征
- **执行性**：一段可执行程序，但一般不是完整的程序
- **寄生性**：嵌入到宿主程序中、依赖宿主程序
- **非授权性**：病毒的执行是对用户未知的
- **隐蔽性**：自身及传染过程是隐蔽的
- **衍生性**：逃避查杀可以有多个变种
- **破坏性**

#### 生命周期

- **创造期**
- **感染期**：传播过程
- **_传播期_**：**复制与传播过程**
- **发病期**
- **发现期**
- **根除期**
- **灭绝**

#### 主要组成

- **引导模块**：随系统或程序的执行进入内存
- **传染模块**：实现感染
- **表现模块**：实施破坏

#### 关键点

- **传播方式**
- 寄生方式：动态（内存中） | 静态（磁盘等介质上）；消灭静态病毒就不会出现动态病毒
- 激活方式

#### 发展趋势

- 计算机网络（互联网、物联网）成为计算机病毒的主要传播途径
- 计算机病毒变形的速度快并向混合型、多样化发展
- 传播方式和运行方式的隐蔽性
- 计算机病毒技术与黑客技术将日益融合
- 物质利益或特殊目的将成为推动计算机病毒发展的最大动力。

### 木马

#### 含义

附着在应用程序或单独存在的**恶意程序**

一般利用**TCP/IP**协议，采用**C/S（Client / Server)**结构，实现对感染计算机的**控制**

#### 组成

- **服务端（Server）**

- **客户端（Client）**

  ![image-20211227160625831](https://oss.nova.gal/img/image-20211227160625831.png)

#### 技术手段

- **植入技术**
  - **主动**：利用漏洞或病毒
  - **被动**：诱骗下载
- 自动启动技术
- 隐蔽技术
- **远程监控技术**

#### 与病毒的区别

|              | 病毒           | 木马             |
| ------------ | -------------- | ---------------- |
| **主要区别** | **具有传染性** | **不能自我复制** |
| 目标         | 进行破坏行为   | 以偷盗为主       |

## 新 05-+网络攻击

### 攻击技术

#### 攻击的含义

**任何非授权**的行为

#### 网络攻击的含义

**任何非授权**的攻击者通过**计算机网络** **入侵**目标系统的行为，包括查看、偷取、修改、控制、破坏等

### 攻击方法

#### 攻击

- **物理攻击**：断电、断网
- **非物理攻击**：网络的远程攻击

#### 网络攻击

从网络的**安全属性**看，可分为

- **被动攻击**：截取攻击（收集信息）：针对**机密性**；流量分析
- **主动攻击**：
  - 阻断攻击：针对**可用性**；DOS 攻击
  - 篡改攻击：针对**完整性**；替换攻击
  - 伪造攻击：针对**真实性**；欺骗攻击
  - 重放攻击

### DNS

Domain Name System，IP 和域名相互映射的分布式数据库

### DoS

#### 含义

拒绝服务攻击

阻止或拒绝合法使用者存取网络服务的一种破坏性攻击手段

#### 原理

**正常 TCP 三次握手**：

- ->SYN 请求
- &lt;-SYN/ACK 响应
- ->ACK 数据包

**DoS 攻击**：

- 提供虚假的 IP 源地址的 SYN
- 服务器响应，向虚假 IP 发送 SYN/ACK 并保持连接等待 ACK
- 无响应，服务器重试并等待一段时间

**DDoS:**

利用僵尸网络分布式进行拒绝服务攻击

- **探测**：扫描有漏洞的主机
- **植入**：向有漏洞的主机上植入木马
- **管理**：选出 MasterServer，放置守护程序
- **命令**：发送给 MasterServer 命令，准备启动攻击
- **实施**：MasterServer 发送攻击信号给其他主机，开始攻击
- **结果**：目标系统被伪造请求淹没，无法相应正常用户请求

### ~APT 攻击

#### 定义

高级持续性攻击

## 新 06+网络防御(防火墙)

### 防火墙

#### 含义

一种高级**访问控制**设备，置于不同网络安全域之间，通过**安全策略**来控制（**允许、拒绝、记录**）进出网络的访问行为

#### 功能

基于时间

基于流量

NAT 功能

VPN 功能

日志审计

#### 不足

- **传输延迟**、瓶颈和**单点失效**
- 不能实现一些安全功能
  - 内部的攻击
  - 不通过防火墙的连接
  - 利用标准协议缺陷的攻击
  - 数据驱动式的攻击（缓存区溢出）
  - 策略配置不当的威胁
  - 本身安全漏洞的威胁

#### 趋势

- 多功能化
- 性能优化
- 分布式防火墙
- 强大审计和自动分析
- 与其他网络安全技术结合

### 包过滤

基于 IP 地址来监视和过滤网络上流入和流出的 IP 包，只允许与指定的 IP 通信

### NAT

#### 含义

Network Address Translation，网络地址转换

一对一和多对一的地址转换

#### 好处

- 缓解 IP 地址匮乏
- 内部网络可以使用私有 IP 地址
- 隐藏内部网络结构，提高安全性

### VPN

#### 含义

Virtual Private Network，虚拟专用网

通过一个**公共网络**建立一个临时、安全的连接，是一条穿过混乱的公用网络的安全和稳定的隧道，能提供与**专用网络**一样的安全和功能保障

#### 好处

- **数据完整性**：通过公共网络传输的信息不可篡改
- **数据保密性**：信息即使被截获也不会泄密
- **身份认证**：验证用户身份；限制非授权用户的访问；用户对资源的访问控制
- **多协议支持**（透明性）：能够嵌入公共网络的常用协议

### 入侵检测（IDS）

#### 含义

**记录**数据、**分析**异常数据、透过伪装**抓住**实际内容

### 入侵防御检测(IPS)

#### 含义

检测入侵的发生、通过一定的响应中止入侵的发生和发展

使得 IDS 和防火墙走向统一

### 漏洞扫描系统

#### 含义

自动检测远程或本地主机在安全性方面**弱点和隐患**的程序包

### 漏洞

#### 含义

硬件、软件或策略上存在的安全缺陷，从而使得攻击者能够在未授权的情况下访问、控制系统。

### 安全漏洞

#### 含义

为堵塞安全漏洞而开发的原软件升级或结合的程序

## 07 信息系统安全-身份认证技术

### 信息系统安全

#### 内容

**软件**

- **信息系统自身安全**
  - 身份认证
    - **作用**：确保资源只被授权的人使用
    - **意义**：信息系统安全的第一道防线
  - 访问控制
  - 安全审计
  - 数据备份
- 网络安全
- 操作系统安全

**硬件**

- 硬件安全
- 环境安全

### 零知识证明

在不提供任何有用的信息的情况下，向 V 证明某个论断是正确的。

> Alice 告诉 Bob 她有房间的钥匙，但她不把钥匙展示出来。
>
> 取而代之的，她取出了只有房间里才有的一件物品，Bob 不得不相信她有钥匙，但是 Bob 始终没有办法看到钥匙。

### 基于 Hash 函数的口令认证

#### 好处

- 口令不存放在任何地方
- 口令以散列值的形式存储
- 口令不会被管理员知道

#### 更改口令

1. 使用原口令的 hash 值作为密钥加密新口令的哈希值
2. 使用数据库中原口令的哈希值解密密文得到新口令的哈希值
3. 替换哈希值

![image-20211227203543397](https://oss.nova.gal/img/image-20211227203543397.png)

#### 认证过程

1. 生成一个随机数，作为提问值。以随机数和口令的哈希值作为参数生成新哈希值
2. 随机数与数据库的哈希以同样的方式生成哈希值，与传输的哈希值进行匹配

![](https://oss.nova.gal/img/image-20211227203407556.png)

### 基于密码技术的单向身份认证

#### 基于对称密码的单向身份认证

> A 和 B 的互相认证：A 发出请求后 A 认证 B，认证后的发送让 B 认证 A

1. IDA 和 rA 通过公开信道传输给 B
2. B 收到后生成 Ks 和 rB，利用 Kab 加密发送加密后的 Ks，IDB，rA，rB 给 A
3. A 使用 Kab 解密得到明文的 Ks，IDB，rA 和 rB，确认 rA=rA，证明消息来源于 B，A 认证 B 成功。Ks 加密 rB 发送给 B
4. B 使用 Ks 解密 rB，确认 rB=rB，B 认证 A 成功

![image-20211227204019932](https://oss.nova.gal/img/image-20211227204019932.png)

#### ~~基于证书的单向身份认证~~（没看懂）

1. A 生成 Ks，rA，使用 B 的公钥加密 Ks，对 rA，IDA，IDB 签名，给 B 发送加密后的 Ks、A 的证书和签名

2. B 验证 A 的证书获取 A 的公钥，验证 S 的有效性后认证 A 是 A，使用私钥解密得到 Ks

3. B 选取 rB，使用 Ks 加密 rB 发送给

![image-20211227204439162](https://oss.nova.gal/img/image-20211227204439162.png)

### 指纹身份认证

#### 重要安全指标

- 错误接受率：本应拒绝的而接受了
- 错误拒绝率

#### 主要方式

- **辨识**：一对多
- **验证**：一对一

### 访问控制

#### 简介

实现既定安全策略的系统安全技术，通过某种方法管理者所有资源的访问请求。

### 安全审计

#### 简介

最后一道防线

对与安全有关的相关信息进行识别、记录、存储、分析
