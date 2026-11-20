# 残業 · 五阶段 Web 密室

一个单容器的多阶段 Web 靶场。零第三方依赖，纯 Node 内置模块，镜像约 62MB。

> 打卡、工资单、头像上传、链接预览、日志检索 —— 五个功能页面，一条链，五个阶段。

## 运行

```bash
# 直接跑
PORT=3000 node server.js

# 或 Docker
docker run --rm -p 3000:3000 -e CTF_FLAG='flag{your_flag_here}' ghcr.io/OWNER/zangyo-ctf:latest
```

打开 http://localhost:3000

## 配置

| 环境变量 | 默认值 | 说明 |
|---|---|---|
| `PORT` | `3000` | 服务端口 |
| `CTF_FLAG` | 内置示例值 | 动态 flag。也兼容 `CTF-FLAG`、`GZCTF_FLAG`、`FLAG`、`DASCTF_FLAG` 等写法 |
| `CTF_SECRET` | 等于 flag | 会话签名密钥。换 flag 会自动换密钥，玩家旧进度失效；想换 flag 又保留进度，就单独固定它 |
| `INNER_PORT` | `9999` | 内部服务端口，被占用时自动顺延 |

flag 会被均分成 5 段，五个阶段各暴露一段。**只完成部分阶段看不到完整 flag**，需要五段齐了再访问结束页。

## 状态与并发

玩家进度**不存服务端** —— 签名后存在浏览器 cookie 里（HMAC-SHA256，14 天）。因此：

- 刷新、关页面、容器重启、换实例都不丢进度
- 篡改 cookie 会验签失败，按新会话处理
- 不同玩家天然隔离，不需要任何存储或粘性会话
- 可以水平扩展，也能部署在会休眠的免费容器上

## 部署到容器平台

镜像发布在 `ghcr.io/OWNER/zangyo-ctf`（由 GitHub Actions 自动构建）。任何支持 Docker 的平台都能跑：

- **Render / Koyeb / Fly.io**：新建 Web Service，镜像填 `ghcr.io/OWNER/zangyo-ctf:latest`，端口 `3000`
- **VPS**：`docker run -d --restart=always -p 80:3000 -e CTF_FLAG='...' ghcr.io/OWNER/zangyo-ctf:latest`
- **CTF 平台（GZCTF 等）**：镜像 tag 填同一个地址，http 端口 `3000`，环境变量 `CTF_FLAG`，静态答案关闭

> 不适合 Vercel / Netlify / GitHub Pages —— 它们是静态托管或函数式运行时，本项目需要常驻监听端口。

## 许可

仅供学习与自建靶场使用。
