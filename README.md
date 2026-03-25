# yuzu

A TUN-based VPN that tunnels all traffic through TLS on port 443. Single Rust binary, two commands.

To network observers, yuzu traffic is indistinguishable from regular HTTPS browsing. Unauthenticated probes receive a real `200 OK` HTML page — the server looks like any other website.

## How it works

```
┌──────────────────────────────────────────────────────────────────┐
│ Client                                                           │
│                                                                  │
│  all traffic ──→ TUN (10.66.0.2) ──→ length-prefixed frames     │
│                                         │                        │
│                                    TLS :443                      │
└─────────────────────────────────────────┼────────────────────────┘
                                          │
                                          ▼
┌─────────────────────────────────────────┼────────────────────────┐
│ Server                                  │                        │
│                                    TLS :443                      │
│                                         │                        │
│              ┌──────────────────────────┴──────────────┐         │
│              │                                         │         │
│         secret matches                          wrong / no       │
│              │                                    secret         │
│              ▼                                         │         │
│    TUN (10.66.0.1) ──→ NAT ──→ internet               ▼         │
│                                                 cover website    │
│                                                 (200 OK HTML)    │
└──────────────────────────────────────────────────────────────────┘
```

The client creates a TUN interface, captures all system traffic (TCP, UDP, DNS, ICMP), wraps each IP packet in a length-prefixed frame, and sends it over a single TLS connection to port 443. The server authenticates with a pre-shared secret using constant-time comparison, unwraps the frames, and forwards packets to the internet via NAT.

If someone connects without the correct secret — a port scanner, a censor, a curious browser — they get a minimal HTML page with a `200 OK` response. The server header says `nginx`.

## Features

- **Single binary** — `yuzu server`, `yuzu client`, `yuzu secret`
- **Full tunnel** — all IP traffic (TCP, UDP, DNS, ICMP) through one TLS connection
- **Port 443 only** — looks like normal HTTPS; nothing unusual on the wire
- **Cover website** — wrong or missing secret serves a real HTML page
- **ACME certificates** — automatic Let's Encrypt via DNS-01 (Bunny.net or Cloudflare)
- **Traffic camouflage** — optional decoy HTTPS requests to popular sites
- **Cross-platform** — macOS (utun) and Linux (tun)
- **SSH/ET passthrough** — optionally proxy SSH and Eternal Terminal connections

## Install

```bash
# From source
git clone https://github.com/jlxq0/yuzu.git
cd yuzu
cargo build --release
sudo cp target/release/yuzu /usr/local/bin/
```

Requires Rust 2024 edition (1.85+).

## Quick start

### 1. Generate a shared secret

```bash
yuzu secret > secret.txt
```

This produces 64 hex characters (256 bits). Copy the file to both server and client.

### 2. Start the server

```bash
# With automatic Let's Encrypt certificate (Bunny.net DNS):
export BUNNY_API_KEY="your-api-key"
sudo yuzu server --domain example.com --secret secret.txt --acme-dns bunny

# With automatic Let's Encrypt certificate (Cloudflare DNS):
export CLOUDFLARE_API_TOKEN="your-api-token"
sudo yuzu server --domain example.com --secret secret.txt --acme-dns cloudflare

# With your own certificate:
sudo yuzu server --domain example.com --secret secret.txt --cert cert.pem --key key.pem
```

The server requires `sudo` because it creates a TUN interface and configures NAT (iptables on Linux, pf on macOS).

### 3. Connect the client

```bash
sudo yuzu client --server example.com --secret secret.txt
```

All traffic now flows through the tunnel. Your public IP changes to the server's IP. Press Ctrl-C to disconnect — routes and DNS are restored automatically.

#### Self-signed certificates

For testing, skip TLS verification:

```bash
sudo yuzu client --server example.com --secret secret.txt --insecure
```

## Usage reference

```
yuzu server [OPTIONS] --domain <DOMAIN> --secret <SECRET>

Options:
  -l, --listen <ADDR>           Listen address [default: 0.0.0.0:443]
  -d, --domain <DOMAIN>         Domain name (for TLS and cover page)
  -s, --secret <PATH>           Path to shared secret file
      --cert <PATH>             TLS certificate PEM (omit for ACME)
      --key <PATH>              TLS private key PEM (omit for ACME)
      --acme-dns <PROVIDER>     DNS provider: bunny or cloudflare
      --acme-dns-token <TOKEN>  DNS API token (or use env var)
      --acme-staging            Use Let's Encrypt staging
      --acme-dir <PATH>         ACME state directory [default: ~/.yuzu]
      --ssh <ADDR>              Proxy SSH to this backend (e.g. 127.0.0.1:22)
      --et <ADDR>               Proxy ET to this backend (e.g. 127.0.0.1:2022)
      --camouflage              Enable decoy HTTPS traffic
  -v, --verbose                 Verbose logging (-v, -vv, -vvv)
```

```
yuzu client [OPTIONS] --server <HOST[:PORT]> --secret <PATH>

Options:
      --server <HOST[:PORT]>    Server address [default port: 443]
      --secret <PATH>           Path to shared secret file
      --camouflage              Enable decoy HTTPS requests
      --insecure                Skip TLS certificate verification
  -v, --verbose                 Verbose logging (-v, -vv, -vvv)
```

```
yuzu secret                     Generate a new 256-bit shared secret
```

## Security model

**Authentication.** The client sends the 64-byte hex secret immediately after the TLS handshake. The server compares it using constant-time equality (`subtle::ConstantTimeEq`). No timing side-channel.

**Encryption.** All traffic is inside a standard TLS 1.3 connection (rustls with ring). The TLS certificate is either user-provided or automatically provisioned from Let's Encrypt.

**Censorship resistance.** Port 443, standard TLS handshake, real SNI, valid certificate. An observer sees ordinary HTTPS to a domain that serves a real website. The `--camouflage` flag adds periodic decoy HTTPS requests to popular sites (Google, Wikipedia, Apple, etc.) to make traffic patterns look more like normal browsing.

**What this is not.** yuzu is a personal anti-censorship tool, not a hardened anonymity system. It does not attempt to defeat traffic analysis at the level of Tor or fully obfuscated transports. The threat model is network-level blocking and casual inspection.

## Network details

| Parameter | Value |
|---|---|
| TUN subnet | `10.66.0.0/24` |
| Server TUN IP | `10.66.0.1` |
| Client TUN IP | `10.66.0.2` |
| MTU | 1400 (room for TLS + framing) |
| Framing | `[length: u16 BE][IP packet]` |
| DNS (client, Linux) | Overrides `/etc/resolv.conf` to `8.8.8.8` / `1.1.1.1` |
| NAT (Linux) | iptables MASQUERADE |
| NAT (macOS) | pf |

Client-side routing uses the `0.0.0.0/1` + `128.0.0.0/1` split to capture all traffic without replacing the default route, with an explicit host route to the server IP via the original gateway.

## Compared to alternatives

| | yuzu | WireGuard | OpenVPN | Shadowsocks |
|---|---|---|---|---|
| Runs on port 443 | Yes (TLS) | No (UDP) | Optional | Optional |
| Looks like HTTPS | Yes | No | Partially | No |
| Cover website | Yes | No | No | No |
| Auto TLS certs | Yes (ACME) | N/A | No | No |
| Protocol | TUN over TLS | Kernel module | TUN/TAP | SOCKS proxy |
| Setup | 1 binary, 1 secret | Key exchange | PKI + config | Server + client |
| Traffic analysis resistance | Basic | None | None | Moderate |
| Performance | Good | Excellent | Good | Good |

WireGuard is faster and more mature for general VPN use. yuzu exists for situations where the network actively blocks non-HTTPS traffic or inspects connections for VPN signatures.

## Tested on

- **Server:** Linux ARM64 (Hetzner cax11, Debian) -- verified: client IP changes, ping/DNS/curl all work through tunnel, cover page served on wrong secret
- **Client:** Linux ARM64, macOS (Apple Silicon)

## Project structure

```
src/
├── main.rs              CLI (clap), argument parsing, ACME orchestration
├── server/mod.rs        TLS listener, secret auth, cover page, connection handling
├── client/mod.rs        TLS connect, TUN setup, route configuration
├── tunnel/mod.rs        TUN device, NAT, routing, packet relay (framing)
├── transport/mod.rs     TLS acceptor/connector, bidirectional stream relay
├── protocol/mod.rs      Secret generation/loading, frame types
├── acme/mod.rs          Let's Encrypt certificate provisioning (DNS-01)
├── acme/dns.rs          DNS providers (Bunny.net, Cloudflare)
└── camouflage/mod.rs    Decoy HTTPS traffic to popular sites
```

## License

MIT
