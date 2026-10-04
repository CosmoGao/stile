# Stile

Stile（Secure Terminals via Isolated Login Entry）是一个开源、轻量的项目。协议 Apache-2.0。

当前这个程序提供网页登录、本地账号，以及管理员登记资产和凭据。它还不是完整的堡垒机：不授权，不开 SSH 或 RDP，不连接目标机，也不写登录日志。

## 网页

空库第一次打开网页时，只能创建第一个管理员。创建完成后这个入口关闭，没有公开注册。

之后可以：

- 用口令登录、登出
- 管理员创建普通用户、停用用户、清除锁定
- 用户自己启用 TOTP（不强制）。启用前要提交一次正确的当前验证码，种子只在那一次显示。管理员可以关掉某个用户的 TOTP，并删掉种子密文
- 口令错误，以及已经启用 TOTP 时验证码错误，会计入失败次数。达到配置里的次数后，账号在配置的时长内不能登录
- 停用或锁定会删掉该用户已经发出的登录凭证

登录凭证放在 HttpOnly cookie 里，不是 JWT。库里只存它的 SHA-256。有效期、失败次数和锁定时长只来自配置，代码里没有产品默认值。

管理员可以登记资产和凭据：

- 资产是 Linux/SSH 或 Windows/RDP。字段有 id、名称、协议、主机、端口、可空的凭据 id、可空的 SSH 主机密钥指纹和时间。端口留空时 SSH 用 22，RDP 用 3389。主机密钥指纹只是一列，不探测，也不连接目标。资产行上没有口令、私钥或 nonce。
- 凭据和资产分开。种类是密码或 SSH 私钥，登录名在凭据上。同一条凭据可以绑到多台资产。仍被引用时不能删除，解除引用之后可以删。
- 口令和私钥用配置里的那把 32 字节主密钥做 AES-256-GCM。每条单独生成 12 字节 nonce，附加认证数据是凭据 id。密文在库里，主密钥不进 SQLite，也不进仓库。
- 列表、创建和替换的页面不带口令或私钥。管理员在凭据页单独打开查看，这一次才看到明文。普通用户打不开凭据页和管理资产页，也不能查看。查看不写登录日志，也没有另外的审计表。
- 导入的私钥如果自带口令，只在提交时解开。库存解开后的材料，密钥口令不入库。列表可以显示公钥的 SHA256 指纹，不显示私钥本身。
- 还没有授权。普通用户的资产对象不带 credential_id，页面上也不列出资产。

`/healthz` 返回 `ok`。

二进制启动起来就是这个服务，没有子命令。

## 不做

命令行、AI、MCP、用户组、授权、主机密钥探测、打开 SSH 或 RDP、登录日志、命令记录、会话录像、文件盘、批量命令、Kubernetes、Telnet、VNC、LDAP、租户。

`guacd` 1.4.0 使用外部镜像 `guacamole/guacd:1.4.0`，不进本仓库源码。当前程序不会连接 guacd。浏览器不直连 guacd。

## 配置

配置文件路径用环境变量 `STILE_CONFIG`。没设置时，如果 `/etc/Stile/stile.conf` 存在就读它。环境变量里的同名项会覆盖文件。

登录凭证有效期、失败锁定次数和锁定时长没有写进代码的默认值。示例里的数字只是例子，注释写明尚未确定。见 `config.example`。

主密钥是 32 字节的文件，路径由 `master_key` 指定。它不进数据库，也不进仓库。文件不存在时，进程启动时生成。这不是子命令。

环境变量：

- `STILE_ADDR` 或 `STILE_LISTEN`：监听地址。两个都有时用 `STILE_LISTEN`
- `STILE_DATABASE`：SQLite 路径
- `STILE_MASTER_KEY`：主密钥路径
- `STILE_SESSION_TTL`：登录凭证有效期，例如 `8h`
- `STILE_LOCKOUT_FAILURES`：失败多少次后锁定
- `STILE_LOCKOUT_DURATION`：锁定多久，例如 `10m`
- `STILE_CONFIG`：配置文件路径
- `GUACD_ADDRESS`：预留给以后，当前程序不连接 guacd

## 页面

- `/setup`：创建第一个管理员
- `/login`、`/logout`：登录和登出
- `/`：登录后的首页
- `/admin/users`：用户
- `/account/totp`：自己的二次验证
- `/admin/assets`：管理员登记资产
- `/admin/credentials`：管理员登记凭据。列表不带秘密
- `/admin/credentials/{id}`：管理员查看这一条凭据的明文

## 本机启动

先把 `config.example` 里的数据库和主密钥路径改成进程用户能写的位置，再执行：

```bash
go build -o stile ./cmd/stile
STILE_CONFIG=./config.example ./stile
```

也可以：

```bash
docker compose up --build
```

这会在本机拉起两个容器：`stile`（用本仓库构建）和 `guacd`（官方镜像）。这不是部署到某台宿主机。容器里的锁定次数和时长写在 `docker-compose.yml`，同样只是示例，不是产品规则。

## 镜像

推送到 `main` 时，GitHub Actions 把镜像发到 `ghcr.io/cosmoga/stile`，标签为 `latest` 和该次提交的 SHA。Pull request 只构建、不推送。这也只是发布镜像，不是部署到宿主机。
