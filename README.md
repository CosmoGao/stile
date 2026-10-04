# Stile

Stile（Secure Terminals via Isolated Login Entry）是一个开源、轻量的项目。

当前仓库里的 Go 程序只是能构建的占位：监听健康检查。第一版功能还没写，它还不是堡垒机。

## 第一版范围（尚未实现）

只有网页：

- 本地账号，可选 TOTP
- 资产
- 可复用的密码或 SSH 私钥
- 授权给用户或用户组
- 网页里的 SSH 和 RDP
- 会话开始和结束日志

## 不做

命令行、AI、MCP、登录日志、命令记录、会话录像、文件盘、批量命令、Kubernetes、Telnet、VNC、LDAP、租户。

`guacd` 1.4.0 使用外部镜像 `guacamole/guacd:1.4.0`，不进本仓库源码。浏览器不直连 guacd。

## 本机启动

在仓库根目录执行：

```bash
docker compose up --build
```

这会在本机拉起两个容器：`stile`（用本仓库构建）和 `guacd`（官方镜像）。这不是部署到某台宿主机。

占位程序默认监听 `:8080`，`/healthz` 返回 `ok`。环境变量 `STILE_ADDR` 可改监听地址。`GUACD_ADDRESS` 只是预留给以后，占位程序不会连接 guacd。

## 镜像

推送到 `main` 时，GitHub Actions 把镜像发到 `ghcr.io/cosmoga/stile`，标签为 `latest` 和该次提交的 SHA。Pull request 只构建、不推送。这也只是发布镜像，不是部署到宿主机。
