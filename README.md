# turnlite

[简体中文](README.zh-CN.md)

`turnlite` is a lightweight, single-binary STUN/TURN and TURNS relay written in Go on top of `pion/turn/v4`. It implements the TURN REST (`static-auth-secret`) ephemeral credential protocol, mtime-cached TLS certificate hot-reload, and strict SSRF peer filtering out of the box.

## Features

- **Single binary, zero runtime dependencies**: UDP/TCP STUN+TURN (`:3478`) and TURN over TLS (`:5349`).
- **TURN REST (`static-auth-secret`)**: Compatible with `coturn` / WebRTC `iceServers` ephemeral HMAC-SHA1 credentials, plus a reusable Go subpackage (`github.com/Everless321/turnlite/turnrest`).
- **SSRF protection built in**: Uses Go `net/netip` (including `Addr.Unmap()` for IPv4-mapped IPv6 `::ffff:...` addresses) to block loopback, RFC1918 private networks, link-local (`169.254.0.0/16` cloud metadata), CGNAT (`100.64.0.0/10`), multicast, and unique-local/link-local IPv6 peers.
- **Hot-reloading TLS certificates**: Caches the parsed `tls.Certificate` and checks file `mtime` on handshake, picking up renewed Let's Encrypt certificates without restarts or per-handshake disk reads.
- **CLI credential minter (`-mint`)**: Generates ready-to-paste JSON credentials and WebRTC `iceServers` URIs for quick testing.

## Quick Start

### 1. Install or build and generate a shared secret

```sh
go install github.com/Everless321/turnlite@latest
# or build from source:
# go build -trimpath -ldflags="-s -w" -o turnlite .

openssl rand -hex 32 | tee turn-secret
chmod 600 turn-secret
```

### 2. Run the server

```sh
./turnlite \
  -public-ip 203.0.113.10 \
  -listen-ip 0.0.0.0 \
  -secret-file ./turn-secret \
  -cert /path/to/fullchain.pem \
  -key /path/to/privkey.pem \
  -realm turn.example.com
```

For local LAN/dev testing without TLS:

```sh
TURN_SECRET="dev-secret-change-me" ./turnlite \
  -public-ip 127.0.0.1 \
  -listen-ip 127.0.0.1 \
  -tls-port 0 \
  -allow-private
```

### 3. Mint ephemeral credentials

```sh
./turnlite -secret-file ./turn-secret -realm turn.example.com -mint alice -mint-ttl 1h
```

Example output:

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

Use that JSON directly in WebRTC `RTCPeerConnection`:

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

## Production Deployment

### systemd + Let's Encrypt

1. Copy the binary to `/usr/local/bin/turnlite`.
2. Store the shared secret in `/etc/turnlite/turn-secret` (`chmod 600`).
3. Copy TLS certificates readable by the `turnlite` service user into `/etc/turnlite/tls/` (update them via certbot deploy hook — `turnlite` reloads on `mtime` change automatically).
4. Install [`deploy/relay.service`](deploy/relay.service), set `-public-ip` and `-realm`, and open ports `3478/udp`, `3478/tcp`, `5349/tcp`, and `49160-49359/udp` in your firewall.

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

> `--net=host` is recommended for TURN servers so relay UDP port ranges (`-min-port`..`-max-port`) do not overwhelm Docker NAT tracking.

## Go Library Usage (`turnrest`)

Your signaling or auth backend can mint credentials directly without shelling out to `-mint`:

```go
import (
    "time"

    "github.com/Everless321/turnlite/turnrest"
)

cred, err := turnrest.Mint([]byte(secret), "session-42", time.Now(), 8*time.Hour)
if err != nil {
    panic(err)
}
// cred.Username -> "<expiryUnix>:session-42"
// cred.Password -> base64(HMAC-SHA1(secret, cred.Username))
```

## SSRF Security Model

Every `CreatePermission` / relay destination check goes through `allowPeer`:

- Unspecified (`0.0.0.0`, `::`) and multicast addresses are always rejected.
- `addr.Unmap()` normalizes IPv4-mapped IPv6 addresses (`::ffff:10.0.0.1` -> `10.0.0.1`) before checking ranges so attackers cannot bypass IPv4 blocks with IPv6 wrapping.
- By default (`-allow-private=false`), loopback (`127.0.0.0/8`, `::1`), RFC1918 private (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), link-local/cloud-metadata (`169.254.0.0/16`, `fe80::/10`), CGNAT (`100.64.0.0/10`), and IPv6 ULA (`fc00::/7`) are rejected.
- Enable `-allow-private` only for trusted local development or self-contained private networks.

## CLI Flags

| Flag | Default | Description |
|---|---|---|
| `-public-ip` | `""` | Public IP announced as relay address (required unless `-mint`) |
| `-listen-ip` | `0.0.0.0` | Local interface IP to listen and relay on |
| `-port` | `3478` | STUN/TURN UDP & TCP port |
| `-tls-port` | `5349` | TURN over TLS TCP port (`0` disables TLS listener) |
| `-cert` | `""` | TLS certificate chain PEM path (hot-reloaded on `mtime` change) |
| `-key` | `""` | TLS private key PEM path |
| `-realm` | `turnlite` | TURN authentication realm |
| `-secret-file` | `""` | Shared TURN REST secret file path (fallback: `TURN_SECRET` env) |
| `-min-port` | `49160` | Start of UDP relay port range |
| `-max-port` | `49359` | End of UDP relay port range |
| `-user-quota` | `8` | Max concurrent allocations per credential (`0` = unlimited) |
| `-allow-private` | `false` | Allow relaying to private/CGNAT/loopback peers (dev only) |
| `-mint` | `""` | Print TURN REST credentials JSON for this ID and exit |
| `-mint-ttl` | `8h` | TTL used with `-mint` |

## License

[MIT](LICENSE)
