# shadowsocks-zig

Zig port of `../shadowsocks-libev`, organized around the current
`shadowsocks-rust` architecture.

Current state:

- Classic and shadowsocks-rust-style extended JSON config parsing. Classic
  libev configs support a single `server`, a `server` array with optional
  per-address ports, and manager-style `port_password` multi-port entries.
- Multiple `servers` in server mode and multiple `locals` in local mode are
  started from shadowsocks-rust-style extended JSON configs. Local mode honors
  per-server `tcp_weight` and `udp_weight` values with separate TCP and UDP
  round-robin selectors; a zero weight excludes that server for the protocol.
- SOCKS5, SOCKS4/4a, HTTP proxy, and Shadowsocks address codecs.
- SIP004 AEAD primitives for `aes-128-gcm`, `aes-256-gcm`,
  `chacha20-ietf-poly1305`, and `xchacha20-ietf-poly1305`, backed by Zig
  `std.crypto`.
- AEAD-2022 TCP and UDP framing for `2022-blake3-aes-128-gcm`,
  `2022-blake3-aes-256-gcm`, and `2022-blake3-chacha20-poly1305`, including
  SIP022 base64 master-key decoding.
- Non-AEAD legacy stream ciphers are intentionally unsupported.
- TCP `ss-local` protocol-specific local listeners for `protocol = "socks"` and
  `protocol = "http"` with supported ciphers.
- TCP and UDP tunnel local mode via `protocol = "tunnel"` with
  `forward_address` and `forward_port`, matching shadowsocks-rust's local
  tunnel configuration shape and libev `ss-tunnel` behavior.
- TCP and UDP transparent redir local mode via `protocol = "redir"` with
  shadowsocks-rust-compatible `tcp_redir`/`udp_redir` config parsing. The
  current relay wiring supports Linux TCP `redirect`/`tproxy` and UDP `tproxy`
  sockets through the libuv-backed POSIX socket layer. TCP `pf` is wired for
  macOS/iOS and FreeBSD through `/dev/pf` `DIOCNATLOOK`, OpenBSD `pf` uses the
  accepted socket local address, and TCP `ipfw` uses the socket local address
  on macOS/iOS/FreeBSD. UDP `pf` on macOS/iOS binds normal UDP sockets and
  recovers the original destination from `/dev/pf` state lookup. FreeBSD and
  OpenBSD UDP `pf` use `recvmsg` original-destination control messages with
  the platform-specific bind-any socket options.
- TCP and UDP DNS local mode via `protocol = "dns"` with
  `remote_dns_address`/`remote_dns_port` and optional
  `local_dns_address`/`local_dns_port`. DNS locals default to
  `mode = "tcp_and_udp"` and use ACL rules to send proxied names to remote DNS
  through Shadowsocks while bypassed names go directly to local DNS.
- TCP and UDP fake-DNS local mode via `protocol = "fake-dns"` with
  `fake_dns_ipv4_network`, `fake_dns_ipv6_network`, and
  `fake_dns_record_expire_duration`. The current implementation allocates
  A/AAAA mappings, persists them to `fake_dns_database_path`, and substitutes
  mapped fake IP targets back to domains in SOCKS/HTTP local paths. Default
  builds keep the existing JSON fallback; `zig build -Drocksdb=true` enables
  the shadowsocks-rust-compatible RocksDB/BSON key layout.
- TCP `ss-server` path for supported ciphers.
- UDP `ss-local` SOCKS5 UDP ASSOCIATE path for supported ciphers.
- UDP `ss-server` path for supported ciphers.
- Libev-style `ss-local`, `ss-server`, `ss-manager`, `ss-redir`, and
  `ss-tunnel` executable aliases plus shadowsocks-rust-style `sslocal`,
  `ssserver`, and `ssmanager` aliases. Alias names infer the process mode
  and local protocol while explicit `--local`, `--server`, `--manager`, and
  `--check` flags remain supported. Common libev flags such as `-s`, `-p`,
  `-b`, `-l`, `-k`, `-m`, `-u`, `-U`, `-L`, `--plugin`, `--plugin-opts`,
  `--acl`, and `--manager-address` can build or override config at startup.
- UDP association timeout and capacity controls via `udp_timeout` and
  `udp_max_associations`, matching shadowsocks-rust's global config names.
- TCP SIP003 plugin process handling via `plugin`, `plugin_opts`,
  `plugin_args`, and `plugin_mode`, using the standard `SS_REMOTE_*`,
  `SS_LOCAL_*`, and `SS_PLUGIN_OPTIONS` environment contract. TCP-only,
  UDP-only, and TCP+UDP SIP003u plugin modes are wired through the plugin
  endpoint.
- Local ACL parsing and direct-bypass handling for `[proxy_all]`,
  `[bypass_all]`, `[bypass_list]`, `[proxy_list]`, exact-domain, subdomain, and
  IP/CIDR rules, with host regex rules compiled and matched through RE2.
- Server-side ACL enforcement for accepted/rejected clients and outbound
  block/allow rules on TCP and UDP relay paths.
- Manager control API via `--manager` and `manager_address` for
  ss-manager-style `add`, `list`, `remove`, `stat`, and `ping` commands. The
  manager supports both IP UDP addresses such as `127.0.0.1:6001` and libev's
  Unix-domain datagram socket address form. It writes generated per-port
  configs under `.zig-cache/ss-zig-manager` and starts/stops child
  `ss-zig --server` processes for managed ports. Managed servers periodically
  report relayed traffic back to the manager, and `ping` returns the latest
  per-port byte totals.
- Network handling owns nonblocking POSIX TCP/UDP sockets and uses libuv
  readiness polling through a narrow C ABI wrapper. `std.Io` is still used for
  process/file/random/DNS helper APIs.
- Server-side AEAD salt replay rejection with a shared rotating replay filter.
- SOCKS5 username/password authentication for TCP local mode via
  `socks5_auth_config_path`.

Build and test with Zig 0.16.0:

```sh
.tools/zig-aarch64-macos-0.16.0/zig build test
.tools/zig-aarch64-macos-0.16.0/zig build
```

Native dependencies are linked through `pkg-config`: `re2` for ACL regex
handling and `libuv` for TCP/UDP readiness polling. `rocksdb` is optional and
is linked only for `zig build -Drocksdb=true`, which enables
shadowsocks-rust-compatible fake-DNS persistence. Crypto uses Zig `std.crypto`
where the required primitives are available.

Interop smoke test used:

```sh
python3 -m http.server 18080 --bind 127.0.0.1

# Zig server with libev local
zig-out/bin/ss-zig --server -c ../shadowsocks-libev/tests/aes-gcm.json
../shadowsocks-libev/build/shared/bin/ss-local -c ../shadowsocks-libev/tests/aes-gcm.json -v
curl --max-time 5 --socks5-hostname 127.0.0.1:1081 http://127.0.0.1:18080/

# libev server with Zig local
../shadowsocks-libev/build/shared/bin/ss-server -c ../shadowsocks-libev/tests/aes-gcm.json -v
zig-out/bin/ss-zig --local -c ../shadowsocks-libev/tests/aes-gcm.json
curl --max-time 5 --socks5-hostname 127.0.0.1:1081 http://127.0.0.1:18080/
```

UDP interop smoke tests use [tests/aes-gcm-udp.json](tests/aes-gcm-udp.json)
with a UDP echo target on `127.0.0.1:18081`. Both directions were verified:

- Zig `--local` with libev `ss-server`.
- libev `ss-local` with Zig `--server`.

Replay regression checks were also run against Zig `--server`:

- Re-sending an identical AEAD UDP datagram produces one response, then the
  replay is dropped.
- Re-sending an identical AEAD TCP first packet on a new connection produces one
  response, then the replay is dropped.

SOCKS5 auth smoke tests use [tests/aes-gcm-auth.json](tests/aes-gcm-auth.json)
and [tests/socks5-auth.json](tests/socks5-auth.json):

- No-auth greeting is rejected when users are configured.
- Wrong RFC1929 username/password credentials are rejected.
- Valid credentials tunnel HTTP through Zig `--local`.
- Valid credentials also tunnel HTTP through Zig `--local` with libev
  `ss-server` as the remote.

SOCKS4/4a smoke tests use [tests/aes-gcm-udp.json](tests/aes-gcm-udp.json)
with an HTTP target on `127.0.0.1:18083`:

- Raw SOCKS4 IPv4 CONNECT through Zig `--local` and Zig `--server`.
- Raw SOCKS4a domain CONNECT through Zig `--local` and Zig `--server`.
- SOCKS4 is rejected with `0x5b` when SOCKS5 auth users are configured, matching
  shadowsocks-rust's auth-gating behavior.
- SOCKS5 CONNECT was rechecked after the first-byte dispatch change.

HTTP proxy smoke tests use [tests/aes-gcm-http.json](tests/aes-gcm-http.json)
with an HTTP target on `127.0.0.1:18084`:

- `curl --proxy http://127.0.0.1:1095 http://127.0.0.1:18084/` tunnels an
  absolute-form HTTP request through Zig `--local` and Zig `--server`.
- `curl --proxy http://127.0.0.1:1095 --proxytunnel http://127.0.0.1:18084/`
  verifies HTTP CONNECT tunneling.
- Raw origin-form HTTP with a `Host` header is accepted and proxied.
- HTTP is rejected/closed when SOCKS5 auth users are configured, matching
  shadowsocks-rust's auth-gating behavior.

Latest libuv/Zig 0.16 smoke checks:

- `zig-out/bin/ss-zig --check -c tests/aes-gcm-udp.json`
- `zig-out/bin/ss-zig --check -c tests/aes-gcm-http.json`
- `zig-out/bin/ss-zig --check -c tests/aes-gcm-auth.json`
- Zig `--local` plus Zig `--server` successfully proxied:
  - SOCKS5 TCP to `127.0.0.1:18084`.
  - HTTP absolute-form proxy requests to `127.0.0.1:18084`.
  - HTTP CONNECT requests to `127.0.0.1:18084`.
  - SOCKS5 UDP ASSOCIATE to a UDP echo target on `127.0.0.1:18085`.
- Zig `--local` plus Zig `--server` with SIP003 TCP plugins on both sides
  successfully proxied SOCKS5 TCP to `127.0.0.1:18086` using
  [tests/fake-sip003-plugin.py](tests/fake-sip003-plugin.py), including
  `plugin_args` pass-through in the local and server configs.
- Zig `--local` with [tests/aes-gcm-acl-bypass.json](tests/aes-gcm-acl-bypass.json)
  successfully bypassed `127.0.0.1/8` directly to `127.0.0.1:18087` while no
  Shadowsocks server was running on the configured remote port.
- Zig `--server` with [tests/aes-gcm-server-acl-block.json](tests/aes-gcm-server-acl-block.json)
  blocked outbound TCP and UDP targets in `127.0.0.0/8` before the target echo
  services received traffic.
- Zig `--manager` with [tests/aes-gcm-manager.json](tests/aes-gcm-manager.json)
  replied to real UDP `ping`, `list`, `add`, `stat`, and `remove` datagrams on
  `127.0.0.1:6001`.
- Manager dynamic process smoke: `add` for port `8396` spawned a child
  `ss-zig --server`, [tests/aes-gcm-manager-dynamic-local.json](tests/aes-gcm-manager-dynamic-local.json)
  tunneled HTTP through that managed server to `127.0.0.1:18090`, and `remove`
  stopped the managed server.
- Manager traffic stat smoke: [tests/aes-gcm-manager.json](tests/aes-gcm-manager.json)
  started a managed server on `8395`; after a SOCKS5 HTTP request through the
  managed server, `ping` moved from `stat: {"8395":0}` to a non-zero byte total.
- Manager Unix-domain socket smoke: [tests/aes-gcm-manager-unix.json](tests/aes-gcm-manager-unix.json)
  bound `/tmp/ss-zig-manager-test.sock`, replied to bound Unix-datagram `ping`
  and `list` clients, proxied HTTP through the managed server on `8397`, and
  reported non-zero traffic via Unix-datagram `stat`.
- SIP003u plugin smoke: [tests/aes-gcm-plugin-udp-local.json](tests/aes-gcm-plugin-udp-local.json)
  and [tests/aes-gcm-plugin-udp-server.json](tests/aes-gcm-plugin-udp-server.json)
  ran the fake plugin with `plugin_mode = "tcp_and_udp"` on both sides. SOCKS5
  UDP ASSOCIATE reached a UDP echo target through the plugin chain, and SOCKS5
  TCP still proxied HTTP through the same plugin setup.
- AEAD-2022 TCP smoke: [tests/aead2022-aes128-tcp.json](tests/aead2022-aes128-tcp.json)
  ran Zig `--local` plus Zig `--server` and proxied SOCKS5 HTTP to
  `127.0.0.1:18092`.
- AEAD-2022 UDP smoke: [tests/aead2022-aes128-udp.json](tests/aead2022-aes128-udp.json)
  ran Zig `--local` plus Zig `--server`; SOCKS5 UDP ASSOCIATE reached a UDP
  echo target on `127.0.0.1:18096`.
- `xchacha20-ietf-poly1305` AEAD TCP/UDP smoke:
  [tests/xchacha20-ietf-poly1305.json](tests/xchacha20-ietf-poly1305.json)
  ran Zig `--local` plus Zig `--server`; SOCKS5 TCP reached an HTTP target on
  `127.0.0.1:18111`, and SOCKS5 UDP ASSOCIATE reached a UDP echo target on
  `127.0.0.1:18112`.
- Tunnel local smoke: [tests/aes-gcm-tunnel.json](tests/aes-gcm-tunnel.json)
  ran Zig `--local` plus Zig `--server`; raw TCP to `127.0.0.1:1094` reached
  the configured HTTP forward target on `127.0.0.1:18100`, and raw UDP to
  `127.0.0.1:1094` reached a UDP echo target on the same forward address.
- DNS local smoke: [tests/aes-gcm-dns.json](tests/aes-gcm-dns.json) ran Zig
  `--local` plus Zig `--server`; UDP and TCP DNS-framed payloads sent to
  `127.0.0.1:1102` reached a DNS echo target on `127.0.0.1:18105` through the
  Shadowsocks server.
- Split DNS local smoke:
  [tests/aes-gcm-dns-split.json](tests/aes-gcm-dns-split.json) used
  [tests/dns-split.acl](tests/dns-split.acl) to send `remote.example` to remote
  DNS through Shadowsocks and `local.example` directly to local DNS for both UDP
  and TCP DNS framing.
- Fake-DNS smoke: [tests/aes-gcm-fake-dns.json](tests/aes-gcm-fake-dns.json)
  validates the config shape with `--check`; unit coverage verifies DNS A
  response generation, stable fake IPv4/IPv6 allocation, fake IP to domain
  rewrite mapping, and JSON database reload. Live Zig `--local` plus Zig
  `--server` returned a fake address from `10.255.0.0/16` for a UDP DNS A query
  to `127.0.0.1:1107`, then rewrote a SOCKS5 TCP CONNECT to that fake IPv4
  through `127.0.0.1:1108` back to `127.0.0.1:18113` and reached the HTTP
  target through Shadowsocks. A UDP DNS AAAA query also returned an address from
  `fc00::/7`, and a SOCKS5 IPv6 CONNECT to that fake IPv6 was rewritten back to
  the same HTTP target.
- Redir local config smoke: [tests/aes-gcm-redir.json](tests/aes-gcm-redir.json),
  [tests/aes-gcm-redir-udp.json](tests/aes-gcm-redir-udp.json), and
  [tests/aes-gcm-redir-pf.json](tests/aes-gcm-redir-pf.json), and
  [tests/aes-gcm-redir-pf-udp.json](tests/aes-gcm-redir-pf-udp.json) validate
  `protocol = "redir"`, Linux `tcp_redir = "redirect"`, Linux
  `udp_redir = "tproxy"`, and BSD/macOS `pf` redir config with `--check`.
  GitHub CI also starts Linux TCP redir and sudo-starts Linux UDP TPROXY redir
  long enough to verify the sockets bind and wait for traffic.
- Multi-instance smoke:
  [tests/aes-gcm-multi-local.json](tests/aes-gcm-multi-local.json) started one
  SOCKS local listener and one HTTP local listener in the same `--local`
  process. [tests/aes-gcm-multi-server.json](tests/aes-gcm-multi-server.json)
  started two server listeners in the same `--server` process; one local client
  config with both servers reached both server ports through the round-robin
  outbound selector.
- Weighted multi-server smoke:
  [tests/aes-gcm-weighted-local.json](tests/aes-gcm-weighted-local.json)
  configured one absent server with `tcp_weight = 0` and one running server
  with `tcp_weight = 1`; repeated SOCKS5 requests through Zig `--local`
  reached the running server without selecting the zero-weight entry.

Remaining high-level port work:

- Remaining specialized local protocol work from shadowsocks-rust/libev:
  full BSD/macOS pf/ipfw integration tests with kernel rules.
