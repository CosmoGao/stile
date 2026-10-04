# Stile

Stile（Secure Terminals in a Lightweight Enclosure）是一个开源、轻量的项目。协议 Apache-2.0。

当前这个程序提供网页登录、本地账号、资产、凭据、用户组、授权、网页 SSH 和网页 RDP。这是第一版的全部。普通用户只能看到直接授给自己的资产，以及授给自己所在组的资产。打开 SSH 或 RDP 之前要检查登录状态、授权、协议和凭据。没通过就不解密，也不连接目标或 guacd。不写登录日志。

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

- 资产是 Linux/SSH 或 Windows/RDP。字段有 id、名称、协议、主机、端口、可空的凭据 id、可空的 SSH 主机密钥指纹和时间。端口留空时 SSH 用 22，RDP 用 3389。资产行上没有口令、私钥或 nonce。
- 管理员可以读取一台 SSH 资产的主机密钥指纹。这一步只做 TCP 连接和 SSH 密钥交换，显示指纹后断开。不读取凭据，不做用户认证，不写会话。确认之后才写入 `ssh_host_key_fingerprint`，也可以改写已有指纹。没登记指纹的 SSH 资产，打开时不连接。
- 凭据和资产分开。种类是密码或 SSH 私钥，登录名在凭据上。同一条凭据可以绑到多台资产。仍被引用时不能删除，解除引用之后可以删。
- 口令和私钥用配置里的那把 32 字节主密钥做 AES-256-GCM。每条单独生成 12 字节 nonce，附加认证数据是凭据 id。密文在库里，主密钥不进 SQLite，也不进仓库。
- 列表、创建和替换的页面不带口令或私钥。管理员在凭据页单独打开查看，这一次才看到明文。普通用户打不开凭据页和管理资产页，也不能查看。查看不写登录日志，也没有另外的审计表。
- 导入的私钥如果自带口令，只在提交时解开。库存解开后的材料，密钥口令不入库。列表可以显示公钥的 SHA256 指纹，不显示私钥本身。
- 授权把资产授给用户或用户组。同一资产、同一主体只有一行，没有上传、下载、编辑、删除、重命名、复制粘贴这些细项。
- 普通用户的资产列表是直接授权和组授权的并集，资产对象不带 credential_id。没授权的不在列表里。管理员看得到全部资产，资产对象可以带 credential_id，仍然不带口令或私钥。两种角色都要有授权才能打开；管理员没有被授到的资产也打不开。
- 删除用户或用户组时，成员关系一起删除。删除用户组时，授给该组的授权删除。删除用户时，授给该用户的授权删除。删除资产时，对应授权删除。
- 打开 SSH 时按这个顺序检查：cookie 仍有效且用户未停用、未锁定；资产在授权并集里，管理员也不跳过；协议是 SSH；已经绑定凭据；已经登记主机密钥指纹。任一步失败都不解密，也不发送口令或私钥。指纹不符就断开，而且尚未发送口令或私钥。比对通过才代填，向 Linux 申请 PTY。不申请端口转发，不走 guacd。
- 网页终端用 xterm.js，经同源 websocket 连到这个进程。登录凭证是 HttpOnly cookie，页面脚本读不到，也不会把 token、口令或私钥写进页面。
- 打开 RDP 时按同一串检查，到协议为止必须是 RDP，并且凭据必须是密码。绑了 SSH 私钥的 RDP 资产打不开，也不连 guacd。通过之后才解密。浏览器按 Guacamole 协议连回这个进程，不直连 guacd。主机、端口、账号、密码由这个进程代填给外部 guacd 1.4.0。不开启磁盘和文件传输。口令和私钥不进 RDP 会话页面。
- 网页画面用 guacamole-common-js，经同源 websocket 连到这个进程。这是浏览器库，不是 guacd 源码。登录凭证仍是 HttpOnly cookie，不写进页面脚本。
- 连接建立之后才写网页会话：只有 user_id、asset_id、started_at、ended_at。SSH 和 RDP 用同一张表。没有命令、输出、录像或客户端地址。页面关闭或远端断开时写结束。没有会话列表，没有断开按钮，没有空闲超时，没有最长时长。打开失败不写一行。

`/healthz` 返回 `ok`。

二进制启动起来就是这个服务，没有子命令。

## 不做

命令行、AI、MCP、登录日志、命令记录、会话录像、会话列表、强制断开、空闲超时、文件盘、磁盘和文件传输、批量命令、Kubernetes、Telnet、VNC、LDAP、租户。授权没有上传、下载、编辑、删除、重命名、复制粘贴这些细项。不重写 guacd。

`guacd` 1.4.0 使用外部镜像 `guacamole/guacd:1.4.0`，不进本仓库源码，也不打进 Stile 镜像。网页 RDP 由这个进程连接它。网页 SSH 不经过它。guacd 没启动时，网页 SSH 仍然可以打开。浏览器不直连 guacd。

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
- `GUACD_ADDRESS`：外部 guacd 1.4.0 的地址，例如 `127.0.0.1:4822`。配置文件里的键是 `guacd`，这个环境变量会覆盖它。不设置时网页 RDP 连不上，网页 SSH 不受影响

## 页面

- `/setup`：创建第一个管理员
- `/login`、`/logout`：登录和登出
- `/`：登录后的首页
- `/admin/users`：用户
- `/account/totp`：自己的二次验证
- `/assets`：已登录用户的资产列表。普通用户只看到授权并集，不带 credential_id。管理员看到全部资产，可以带 credential_id
- `/assets/{id}/open`：已授权的 SSH 打开 xterm.js；已授权且凭据是密码的 RDP 打开画面。没授权、协议不对、没凭据、RDP 绑了 SSH 私钥，或 SSH 没指纹，都不连接
- `/assets/{id}/ssh`：SSH 的同源 websocket。浏览器带上 HttpOnly cookie，页面里没有登录凭证
- `/assets/{id}/rdp`：RDP 的同源 websocket，Guacamole 协议。浏览器带上 HttpOnly cookie，不直连 guacd，请求里没有密码
- `/admin/assets/{id}/probe`：管理员读取主机密钥指纹。只做密钥交换
- `/static/xterm.js`、`/static/xterm.css`、`/static/xterm-addon-fit.js`：打进二进制的终端库。xterm.js 是 MIT，许可见 `internal/web/static/xterm.LICENSE`。运行时不跑 npm
- `/static/guacamole-common.js`：打进二进制的 Guacamole 浏览器库，版本 1.4.0，Apache-2.0，许可见 `internal/web/static/guacamole-common.LICENSE`。不是 guacd 源码
- `/admin/assets`：管理员登记资产
- `/admin/credentials`：管理员登记凭据。列表不带秘密
- `/admin/credentials/{id}`：管理员查看这一条凭据的明文
- `/admin/groups`：用户组。`/admin/groups/{id}` 管理成员
- `/admin/grants`：把资产授给用户或用户组，或取消授权

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

这会在本机拉起两个容器。`stile` 用当前源码构建，并打上 `ghcr.io/cosmogao/stile:latest`。`guacd` 用外部镜像 `guacamole/guacd:1.4.0`，源码不在本仓库，也不进 Stile 镜像。这不是部署到某台宿主机。容器里的锁定次数和时长写在 `docker-compose.yml`，同样只是示例，不是产品规则。

## 镜像

推送到 `main` 时，GitHub Actions 把镜像发到 `ghcr.io/cosmogao/stile`，标签为 `latest` 和该次提交的 SHA。Pull request 只构建、不推送。这也只是发布镜像，不是部署到宿主机。
