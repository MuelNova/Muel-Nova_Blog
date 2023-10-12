<div align="center">
  <img src="#PLACEHOLDER" width="180" height="180" alt="MuelNova - Banner">
  <br>
  <p><img src="#PLACEHOLDER" width="240" alt="MuelNova - Text"></p>
</div>


<div align="center">

# MuelNova Blog

_✨ MuelNova [博客](https://n.ova.moe)的备份 ✨_
<p>
<a href="./LICENSE">
    <img src="https://img.shields.io/github/license/MuelNova/Muel-Nova_Blog.svg" alt="license">
</a>
<a href="https://n.ova.moe">
  <img alt="n.ova.moe" src="https://img.shields.io/website?down_color=lightgrey&down_message=Offline&label=n.ova.moe&logo=Glitch&logoColor=white&style=for-the-badge&up_color=blue&up_message=Online&url=https%3A%2F%2Fn.ova.moe">
</a>
<a href="https://www.npmjs.com/package/@docusaurus/core">
	<img src="https://img.shields.io/npm/v/@docusaurus/core.svg?style=flat" alt="npm version">
</a>
</p>

<p>
<img alt="GitHub last commit" src="https://img.shields.io/github/last-commit/MuelNova/Muel-Nova_Blog?logo=github&style=for-the-badge">
</p>
</div>

## 部署流程

请先确保有 **yarn, golang** 安装

```sh
git clone https://github.com/MuelNova/Muel-Nova_Blog
cd Muel-Nova_Blog
yarn
```

编辑 .env

```sh
cp .env.example .env
vim .env  # or `nano`, or whatever you like
```

开始部署

```sh
yarn build
```



## Caddy 配置

将 `caddy/Caddyfile` 内的内容整合到你的 `Caddyfile` 内

设置环境变量 `CLOUDFLARE_TOKEN` 为你的 [cloudflare_token](https://dash.cloudflare.com/profile/api-tokens)

重载 caddy

> :rocket: This README.md is still editing.



## 自动 Hook 配置

克隆并参考 [Go-GitHub-Webhooks](https://github.com/MuelNova/go-github-webhooks)

在 `EXTRA_COMMAND` 内使用 `yarn build`