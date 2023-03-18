---
title: 如何使用自己的域名替换TS自建服务器的IP
date: 2021-11-30
tags: ['teamspeak']
categories: ['investigate']
banner_img: https://www.teamspeak.com/user/themes/teamspeak/images/logo_inverse.svg
index_img: https://www.teamspeak.com/user/themes/teamspeak/images/logo_inverse.svg
---
# TeamSpeak3 自建服务器使用域名替换IP

## 准备工作

- 一个已经安装过[Teamspeak3 Server](https://www.teamspeak.com/en/downloads/#server)的服务器
- 一个域名

<!--truncate-->

## 操作步骤(以[GoDaddy](https://www.godaddy.com/)的DNS控制为例)

### 1.添加A记录 
- 在`名称`处填写主机头(例如，对于我的域名[novanoir.moe](https://novanoir.moe)我想使用`ts.novanoir.moe`登录Teamspeak，则填写`ts`)
- 在`值`处填写对应服务器IP(即原来登录Teamspeak所使用的IP)

### 2.添加SRV记录
- 以`_ts3`作为服务
- 以`_udp`作为协议
- 以`1`处填写的`主机头`为名称
- 以**完整的域名**为目标
- 以`Teamspeak端口`为端口(默认为`9987`)
- 设置`权重`为5, `优先级`为0（或1）
- 你可以设置TTL为1800秒，因为这是ts3服务器刷新的时长

保存设置后，你的两个记录应该是这个样子的：（请自行替换其中的内容）

| 类型 | 名称 | 值 | TTL |
| ---- | ---- | ---- | ---- |
| A | ts | 127.0.0.1 | 3600秒 | 
| SRV | _ts3._udp.ts | 0 5 9987 ts.novanoir.moe | 1800秒 |

## 大功告成
现在，你可以尝试使用所设置的域名连接至Teamspeak了！
如果失败的话，你可以等待半个小时左右再次连接尝试。

## 一些注意事项
我也不知道，嘿嘿