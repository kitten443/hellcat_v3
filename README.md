# HellCat v3

[English](README.md) · [Русский](README.ru.md) · [Changelog](CHANGELOG.md)

> **Authorized testing only.** HellCat generates heavy traffic through proxy
> servers. Use it only on infrastructure you own or have explicit written
> permission to test. You are responsible for complying with the law and with
> your provider's acceptable-use policy.

HellCat is a proxy bandwidth and stress tester written in Go. It starts one or
more [Xray-core](https://github.com/XTLS/Xray-core) processes, gives each one a
local SOCKS5 listener, and drives many parallel HTTP downloads through the
proxies to measure throughput, stability and error rates.

It is built for headless Linux servers: no UI, no interactive prompts, one
process tree, clean shutdown, systemd support and predictable resource use.

---

## How it works

```
 share links (vless/vmess/ss/trojan/hysteria2)
                    │
                    ▼
            link parser (parser/)
                    │  one Xray outbound per link
                    ▼
   ┌──────────────────────────────────────┐
   │ Xray #1  SOCKS5 127.0.0.1:port ──────┼──┐
   │ Xray #2  SOCKS5 127.0.0.1:port ──────┼──┼──► worker goroutines
   │ ...                                  │  │      │
   └──────────────────────────────────────┘  │      ▼
                                             └──► HTTP(S) targets
                                                  (speed test files or web pages)
```

1. Each share link becomes one Xray outbound configuration.
2. HellCat writes a temporary config with a SOCKS5 inbound on a random local
   port and starts an Xray process.
3. Workers perform HTTP GETs through `socks5h://127.0.0.1:<port>` and discard
   the response body, counting bytes, requests and errors.
4. A CPU monitor can add a small delay between bursts to keep the server below
   the configured CPU target.
5. On exit, workers are cancelled, Xray processes receive `SIGTERM`, and all
   temporary configs are removed.

---

## Features

- **Protocols:** VLESS, VMess, Shadowsocks, Trojan, Hysteria 2.
- **Transports:** TCP/RAW, WebSocket, gRPC, XHTTP (`xhttp`/`splithttp`),
  HTTPUpgrade, mKCP.
- **Security:** TLS and REALITY, including the modern `pcs`/`vcn` certificate
  pinning parameters.
- **VMess:** both the classic `vmess://<base64(JSON)>` payload and the newer
  `vmess://uuid@host:port?...` URI form.
- **Shadowsocks:** SIP002 (base64 or plain userinfo) and legacy base64 links.
- **Hysteria 2:** native Xray `hysteria` outbound; Salamander obfuscation is
  supported through Xray's `finalmask` on Xray 26+.
- **Server-friendly runtime:** per-run temp directory, stale-file cleanup,
  captured Xray diagnostics, parent-death signal, file-descriptor warning,
  graceful shutdown and a systemd unit.
- **Safe credential handling:** `--fakelogin` rotates credentials on a private
  deep copy of the config; the loaded links are never modified in place.

---

## Requirements

| Component | Requirement |
|-----------|-------------|
| OS | Linux (x86_64, arm64 and 32-bit ARM are handled by the installer) |
| Go | 1.22 or newer (build only) |
| Xray | current release (2026+ builds recommended; see [compatibility](#xray-compatibility)) |
| Privileges | none for a user-local install; root/sudo for `/usr/local` and systemd |

The installer downloads Go and Xray if they are missing. You only need `curl`
or `wget` and `unzip` to bootstrap.

---

## Quick start

### 1. Install

```bash
git clone https://github.com/kitten443/hellcat_v3.git
cd hellcat_v3
sudo ./install.sh
```

User-local install (no root):

```bash
./install.sh --user
export PATH="$HOME/.local/bin:$PATH"
```

Other installer options:

```bash
sudo ./install.sh --no-deps      # build and install hellcat only
sudo ./install.sh --no-build     # install Go + Xray only
sudo ./install.sh --prefix /opt  # install to /opt/bin
```

### 2. Build manually (optional)

```bash
go mod tidy
make build            # produces ./hellcat
# or:
go build -trimpath -ldflags "-s -w -X main.version=$(git describe --tags --always)" -o hellcat .
```

### 3. Run

```bash
# Single link
hellcat --url 'vless://uuid@example.com:443?type=ws&security=tls&host=cdn.example.com&path=%2Fws#node'

# A file with one link per line
hellcat --list links.txt --instances 20 --threads 200

# Standard input
cat links.txt | hellcat --list - --stealth

# Short measured run with a custom target
hellcat --list links.txt --duration 120 --target https://speed.cloudflare.com/__down?bytes=10737418240
```

Progress is printed every 3 seconds:

```text
[hellcat] 🌊 412.7 MB/s | total 24.6 GiB | req 8421 | err 12 | workers 200 | inflight 1834/10000 | cpu 68% | throttle 120ms
```

---

## Upgrading from the previous version

See [CHANGELOG.md](CHANGELOG.md) for the full list of changes.

- `--threads` now means **total workers**, not workers per proxy. Lower it if
  you previously used large values with many instances.
- TUIC links are now rejected with an explicit error instead of producing an
  Xray config that cannot start.
- Xray's current schema is generated by default. Pass `--legacy-insecure` only
  if your Xray binary still accepts `allowInsecure`.
- Temporary configs moved from the working directory to `$TMPDIR/hellcat-*`;
  stale directories are removed automatically.
- New: `--list -` (stdin), `--verbose`, `--legacy-insecure`, and `--cpu -1`
  (disable throttling).

---

## Supported link formats

| Scheme | Transports | Security | Notes |
|--------|------------|----------|-------|
| `vless://` | tcp/raw, ws, grpc, xhttp, httpupgrade, kcp | none, tls, reality | `flow=xtls-rprx-vision` only with tcp + tls/reality |
| `vmess://` | tcp, ws, grpc, xhttp, httpupgrade, kcp | none, tls, reality | base64 JSON and URI formats |
| `ss://` | direct | — | AEAD and `2022-blake3-*` ciphers; SIP003 plugins are not supported |
| `trojan://` | tcp, ws, grpc, xhttp, httpupgrade, kcp | tls (default), reality, none | password may contain `:` |
| `hysteria2://`, `hy2://` | Hysteria 2 / QUIC | tls | maps to Xray `hysteria`; `obfs=salamander` supported on Xray 26+ |
| `tuic://` | — | — | **not supported:** Xray-core has no TUIC outbound |

Common share-link parameters are understood: `sni`, `host`, `path`,
`serviceName`, `authority`, `mode`, `alpn`, `fp`, `allowInsecure`/`insecure`,
`pcs`, `vcn`, `ech`, `pbk`, `sid`, `spx`, `pqv`, `fm`, and `extra` for XHTTP.

---

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--url` | — | Single proxy link. |
| `--list` | — | File with one link per line; `-` reads stdin. Blank lines and `#` comments are ignored. |
| `--max-proxies` | `100000` | Maximum number of links loaded (hard cap `100000`). |
| `--instances` | `20` | Number of Xray processes. Links are reused round-robin if there are fewer links than instances. |
| `--threads` | `200` | **Total** worker goroutines, distributed across ready instances. `--insane` doubles this. |
| `--duration` | `0` | Run time in seconds; `0` means until `Ctrl+C`/`SIGTERM`. |
| `--target` | — | Custom `http(s)` URL used for every request instead of the built-in target lists. |
| `--stealth` | `false` | Request normal web pages with a 20s timeout instead of large downloads (40s). |
| `--insane` | `false` | Double the worker count and use burst size 6 instead of 3. |
| `--cpu` | `0` | CPU target: `0` auto (70%, 85% in insane mode), `-1` disable throttling, or a positive percentage. |
| `--inflight` | `10000` | Maximum concurrent HTTP requests (hard cap `100000`). |
| `--fakelogin` | `false` | After every 1000 requests per instance, rotate credentials and restart that Xray process. |
| `--legacy-insecure` | `false` | Emit `tlsSettings.allowInsecure`. Use **only** with older Xray. |
| `--verbose` | `false` | Stream Xray stdout/stderr to the terminal instead of capturing a short error tail. |
| `--version` | — | Print the build version. |

`--threads` is a total, not a per-proxy value. With `--instances 20 --threads
200`, each ready instance gets 10 workers. If there are more instances than
threads, each instance still gets at least one worker.

---

## Examples

**Test a single VLESS/REALITY node**

```bash
hellcat --url 'vless://uuid@example.com:443?type=tcp&security=reality&pbk=PUBLIC_KEY&sni=cdn.example.com&sid=abcd&fp=chrome&flow=xtls-rprx-vision' \
        --instances 10 --threads 200 --duration 300
```

**Large list, CPU-aware**

```bash
hellcat --list links.txt --max-proxies 5000 --instances 50 --threads 500 --cpu 75
```

**Low-impact checks (web pages, no CPU throttling)**

```bash
hellcat --list links.txt --stealth --threads 100 --inflight 2000 --cpu -1
```

**Rotate credentials to test auth handling**

```bash
hellcat --list links.txt --fakelogin --duration 600
```

**Old Xray binary that still accepts `allowInsecure`**

```bash
hellcat --list links.txt --legacy-insecure
```

---

## Server deployment (systemd)

```bash
sudo ./install.sh

sudo mkdir -p /etc/hellcat /var/lib/hellcat
sudo cp deploy/links.example /etc/hellcat/links.txt
sudo cp deploy/hellcat.env.example /etc/hellcat/hellcat.env
sudo cp deploy/hellcat.service /etc/systemd/system/hellcat.service

sudo editor /etc/hellcat/links.txt
sudo editor /etc/hellcat/hellcat.env

sudo chmod 0640 /etc/hellcat/links.txt /etc/hellcat/hellcat.env
sudo systemctl daemon-reload
sudo systemctl enable --now hellcat
journalctl -u hellcat -f
```

`deploy/hellcat.env.example` contains the extra CLI arguments:

```ini
HELLCAT_ARGS=--instances 20 --threads 200 --inflight 10000 --cpu 65
```

The unit sets `LimitNOFILE=1048576`, restarts on failure and keeps temporary
Xray configs in a private `/tmp`. For production, uncomment the `User=` block
and run HellCat as an unprivileged account; Xray needs no special capabilities.

To stop the service:

```bash
sudo systemctl stop hellcat
```

---

## Tuning for servers

Start conservatively and watch `cpu`, `inflight`, memory, and error counts.

| Server | Starting point |
|--------|----------------|
| 1–2 vCPU VPS | `--instances 5 --threads 100 --inflight 2000 --cpu 50` |
| 4–8 vCPU | `--instances 20 --threads 300 --inflight 10000 --cpu 65` |
| 16+ vCPU | `--instances 40 --threads 800 --inflight 30000 --cpu 75` |
| Very large | scale `--instances` with links and `--threads` with CPU, keep `--inflight` below the descriptor budget |

Rules of thumb:

- Each Xray process costs roughly 20–50 MB of RAM. `--instances 100` can mean
  several gigabytes.
- Each in-flight request uses several sockets (worker ↔ local SOCKS, Xray
  outbound, target). Keep `LimitNOFILE` comfortably above
  `2 × inflight + instances × 32`.
- `--cpu` throttles between request bursts, not inside a transfer. On a busy
  server, lower `--threads`/`--inflight` or use systemd `CPUQuota`.
- Prefer `--stealth` when you need modest traffic. Prefer the default heavy
  mode when you need to saturate bandwidth.
- Use `--target` to select a fast, well-connected download endpoint in the
  same region as the proxies.
- The default socket option is `domainStrategy: UseIP`: Xray resolves target
  domains locally before connecting. This keeps behavior predictable on
  servers without special DNS assumptions.

The service logs a warning when the soft `RLIMIT_NOFILE` is below the
recommended value.

---

## Xray compatibility

HellCat targets current Xray-core and adapts to protocol changes:

- **Current Xray releases removed `tlsSettings.allowInsecure` (2026).** Use links with `pcs`
  (certificate SHA-256 pin) or `vcn` (verify by name), or pass
  `--legacy-insecure` only when running an older Xray binary.
- **HTTP/2 (`type=http`) and QUIC (`type=quic`) transports were removed.**
  Such links are rejected with a clear error; migrate to `type=xhttp`.
- **REALITY** supports RAW/TCP, XHTTP and gRPC. WS + REALITY links are
  rejected.
- **Hysteria 2** is provided by Xray's `hysteria` protocol. Salamander
  obfuscation needs Xray 26+'s `finalmask`; other obfs modes are rejected.
- **mKCP** defaults are used. Xray 26's config builder no longer exposes
  seed/header options, so those link parameters are ignored.
- **TUIC** has no Xray outbound and is always rejected.

---

## Troubleshooting

| Symptom | Cause / fix |
|---------|-------------|
| `'xray' binary not found in PATH` | Run `install.sh` or install Xray and add it to `PATH`. |
| `no Xray instance could be started` | Check disk space and that the Xray binary is executable. |
| `no SOCKS proxy became ready` | The link is invalid for the installed Xray. Re-run with `--verbose`; the captured error tail is printed. |
| `The feature "allowInsecure" has been removed` | Add `pcs`/`vcn` to the link, or use `--legacy-insecure` with an older Xray. |
| `vless without TLS or other encryption is prohibited` | Current Xray only allows `security=none` for private/loopback addresses. Use TLS/REALITY. |
| `HTTP/2 transport ... removed` | Replace `type=http` with `type=xhttp` (or use an older Xray). |
| `tuic:// is not supported` | Expected: convert the node to a supported protocol or run a sing-box based tool. |
| `too many open files` | Raise `LimitNOFILE`/`ulimit -n`; reduce `--inflight`. |
| CPU is always near 100% | Lower `--cpu`, `--threads` or `--inflight`; check for many failing connections. |
| Many errors, low throughput | Verify the proxy works outside HellCat, the target is reachable, and DNS works on the server. |
| Xray prints WebSocket/gRPC deprecation warnings | Harmless; those transports still work. |

Logs are written to stderr. Under systemd use `journalctl -u hellcat -f`.
Temporary configs are created in `$TMPDIR/hellcat-*` and removed on exit; stale
directories older than 24 hours are cleaned at startup.

---

## Project layout

```text
.
├── main.go                 CLI, list loading, flag validation, signals
├── config/                 temporary Xray config generation and cleanup
├── parser/                 share-link parsing, validation and deep clone
│   ├── parser.go           dispatch and common helpers
│   ├── transport.go        transport/security mapping
│   ├── vless.go            VLESS
│   ├── vmess.go            VMess (JSON + URI)
│   ├── shadowsocks.go      Shadowsocks
│   ├── trojan.go           Trojan
│   ├── hysteria.go         Hysteria 2 + TUIC diagnostics
│   └── clone.go            deep copy for per-instance configs
├── stressor/               Xray lifecycle, workers, CPU monitor, stats
├── deploy/                 systemd unit, env and link examples
├── install.sh              dependency/bootstrap/build installer
└── Makefile                build, vet, install
```

---

## Development

```bash
make check          # gofmt + go vet
make build
```

---

## Limitations

- TUIC links are rejected (no Xray outbound).
- Shadowsocks SIP003 plugins (`obfs-local`, `v2ray-plugin`, ...) are not
  supported.
- Legacy `allowInsecure` is opt-in and only for old Xray binaries.
- HTTP/2 and QUIC transports are rejected because current Xray removed them.
- Reported speed is HTTP body bytes observed by the Go workers. It excludes
  proxy/TLS overhead and is not a line-rate measurement.
- Very large lists are still held in memory; use `--max-proxies` on small VPS.

---

## License

MIT. See [LICENSE](LICENSE).
