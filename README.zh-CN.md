# turnlite

[English](README.md)

`turnlite` 是一个基于 Go 和 `pion/turn/v4` 编写的轻量级单二进制 STUN/TURN 与 TURNS 中继服务，内置 TURN REST（`static-auth-secret`）临时凭据签发、按文件 `mtime` 缓存的 TLS 证书热加载，以及开箱即用的 SSRF 目标地址防护。

## 核心特性

- **单文件部署，零运行时依赖**：同时支持 UDP/TCP STUN+TURN（`:3478`）与 TURN over TLS（`:5349`）。
- **TURN REST（`static-auth-secret`）**：兼容 `coturn` 及 WebRTC `iceServers` HMAC-SHA1 临时凭据协议，并提供独立的 Go 库包 `github.com/Everless321/turnlite/turnrest`。
- **内置 SSRF 防护**：使用 Go `net/netip`（含 `Addr.Unmap()` 规范化 `::ffff:...` IPv4 映射地址），默认拦截回环、RFC1918 内网、云厂商元数据链路本地地址（`169.254.0.0/16`）、CGNAT（`100.64.0.0/10`）、组播与 IPv6 ULA/链路本地地址。
- **TLS 证书热加载**：内存中缓存 `tls.Certificate` 并在握手时按 `mtime` 检查变更，Let's Encrypt 自动续期后无需重启进程。
- **命令行发证工具（`-mint`）**：一键输出可直接用于 WebRTC `iceServers` 的 JSON 凭据。

## 快速开始

### 1. 安装或编译并生成共享密钥

```sh
go install github.com/Everless321/turnlite@latest
# 或从源码编译：
# go build -trimpath -ldflags="-s -w" -o turnlite .

openssl rand -hex 32 | tee turn-secret
chmod 600 turn-secret
```

### 2. 启动服务

```sh
./turnlite \
  -public-ip 203.0.113.10 \
  -listen-ip 0.0.0.0 \
  -secret-file ./turn-secret \
  -cert /path/to/fullchain.pem \
  -key /path/to/privkey.pem \
  -realm turn.example.com
```

本地调试（禁用 TLS 并允许私网地址）：

```sh
TURN_SECRET="dev-secret-change-me" ./turnlite \
  -public-ip 127.0.0.1 \
  -listen-ip 127.0.0.1 \
  -tls-port 0 \
  -allow-private
```

### 3. 签发临时凭据

```sh
./turnlite -secret-file ./turn-secret -realm turn.example.com -mint alice -mint-ttl 1h
```

输出示例：

```json
{
  "username": "1735689600:alice",
  "credential": "k8+...",
  "ttl_seconds": 3600,
  "urls": [
    "stun:turn.example.com:3478",
    "turn:turn.example.com:3478?transport=udp",
    "turn:turn.example.com:3478?transport=tcp",
    "turns:turn.example.com:5349?transport=tcp"
  ]
}
```

前端 WebRTC 直接接入：

```js
const pc = new RTCPeerConnection({
  iceServers: [
    {
      urls: minted.urls,
      username: minted.username,
      credential: minted.credential,
    },
  ],
});
```

## 生产部署

### systemd + Let's Encrypt

1. 将编译好的二进制放到 `/usr/local/bin/turnlite`。
2. 将共享密钥存入 `/etc/turnlite/turn-secret`（权限 `600`）。
3. 将运行用户可读的证书链与私钥放入 `/etc/turnlite/tls/`（certbot 续期后会自动触发热加载）。
4. 安装 [`deploy/relay.service`](deploy/relay.service)，修改 `-public-ip` 与 `-realm`，并在防火墙放行 `3478/udp`、`3478/tcp`、`5349/tcp` 与 `49160-49359/udp`。

```sh
sudo systemctl enable --now relay
```

### Docker

```sh
docker build -t turnlite .
docker run --rm --net=host \
  -e TURN_SECRET="$(cat turn-secret)" \
  -v /etc/letsencrypt/live/turn.example.com:/tls:ro \
  turnlite \
  -public-ip 203.0.113.10 \
  -cert /tls/fullchain.pem \
  -key /tls/privkey.pem \
  -realm turn.example.com
```

> 建议为 TURN 容器启用 `--net=host`，避免大范围 UDP 中继端口经过 Docker NAT 造成连接跟踪表膨胀。

## 作为 Go 库调用（`turnrest`）

信令或鉴权后端可直接引用 `turnrest` 包签发凭据：

```go
import (
    "time"

    "github.com/Everless321/turnlite/turnrest"
)

cred, err := turnrest.Mint([]byte(secret), "session-42", time.Now(), 8*time.Hour)
if err != nil {
    panic(err)
}
```

## SSRF 安全模型

所有中继对端地址都会经过 `allowPeer` 校验：

- 始终拒绝未指定地址（`0.0.0.0`、`::`）和组播地址。
- 先调用 `addr.Unmap()` 将 `::ffff:10.0.0.1` 还原为 IPv4 再做网段匹配，防止利用 IPv4 映射 IPv6 绕过拦截。
- 默认模式（`-allow-private=false`）拦截回环、RFC1918 私网、链路本地与云元数据（`169.254.0.0/16`、`fe80::/10`）、CGNAT（`100.64.0.0/10`）与 IPv6 ULA（`fc00::/7`）。
- 仅在受信任的本地开发环境开启 `-allow-private`。

## 命令行参数

| 参数 | 默认值 | 说明 |
|---|---|---|
| `-public-ip` | `""` | 对外宣告的公网中继 IP（非 `-mint` 模式必填） |
| `-listen-ip` | `0.0.0.0` | 本地监听与中继网卡 IP |
| `-port` | `3478` | STUN/TURN UDP 与 TCP 监听端口 |
| `-tls-port` | `5349` | TURN over TLS TCP 端口（设为 `0` 禁用） |
| `-cert` | `""` | TLS 证书链 PEM 路径（按 `mtime` 自动热重载） |
| `-key` | `""` | TLS 私钥 PEM 路径 |
| `-realm` | `turnlite` | TURN 认证域 |
| `-secret-file` | `""` | TURN REST 共享密钥文件路径（回退读取环境变量 `TURN_SECRET`） |
| `-min-port` | `49160` | UDP 中继端口起始值 |
| `-max-port` | `49359` | UDP 中继端口结束值 |
| `-user-quota` | `8` | 每个凭据最大并发分配数（`0` 为不限制） |
| `-allow-private` | `false` | 允许向私网/CGNAT/回环地址中继（仅限开发测试） |
| `-mint` | `""` | 为指定 ID 签发 TURN REST 凭据 JSON 并退出 |
| `-mint-ttl` | `8h` | `-mint` 签发凭据的有效期 |

## 开源协议

[MIT](LICENSE)
