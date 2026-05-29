# shadowsocks-zig Architecture

This repository ports `../shadowsocks-libev` behavior into Zig while using the
current `shadowsocks-rust` service layout as the architectural guide.

Reference points used for this foundation:

- `../shadowsocks-libev/src/crypto.c` and `aead.c`: legacy key derivation and
  AEAD framing behavior.
- `shadowsocks-rust v1.24.0`: crate boundaries and protocol ownership:
  `config`, `crypto`, `relay/socks5`, `relay/tcprelay`, `relay/udprelay`, and
  service-local/server managers.

Current Zig modules:

- `config`: JSON config parsing for classic single-server and extended
  multi-server shapes. Extended `servers` and `locals` entries with
  `disabled = true` are skipped before per-entry validation, matching
  shadowsocks-rust's disabled-entry semantics.
- `crypto`: cipher metadata, OpenSSL-compatible MD5 `EVP_BytesToKey`, HKDF-SHA1
  subkey derivation, `std.crypto` AEAD operations, v1 AEAD chunk framing, and
  AEAD-2022 TCP/UDP framing.
- `protocol`: SOCKS5, SOCKS4/4a, HTTP proxy, and Shadowsocks address wire
  codecs.
- `relay`: TCP and UDP local/server services plus shared relay constants.
- `manager`: ss-manager-style control-plane command parser and UDP control
  socket.
- `security`: shared replay protection for server-side AEAD salts/nonces.

The relay network layer owns nonblocking POSIX TCP/UDP sockets directly and
delegates readable/writable readiness waits to libuv through a narrow C ABI
wrapper. Zig 0.16's `std.Io.Evented` surface is not used for sockets because
the available 0.16 Evented backends do not yet provide the complete TCP/UDP
surface needed here. `std.Io` remains in use for process, file, random, and DNS
helper APIs.

UDP association lifecycle follows the shadowsocks-rust global config fields:
`udp_timeout` defaults to 300 seconds and `udp_max_associations` is optional.
Local SOCKS5 UDP associations are retired after idleness or worker closure.
Server-side target-to-client mappings are expired by the same timeout and evict
the oldest mapping when a configured capacity is reached.

SIP003 TCP plugins are spawned as child processes when a server has `plugin`
configured. `plugin_args` are appended to the plugin process argv. The process
environment follows the SIP003 contract:
`SS_REMOTE_HOST`, `SS_REMOTE_PORT`, `SS_LOCAL_HOST`, `SS_LOCAL_PORT`, and
optional `SS_PLUGIN_OPTIONS`. In local mode, TCP Shadowsocks connections target
the plugin's loopback listener while UDP continues to use the direct server
address when `plugin_mode` is `tcp_only`; when `plugin_mode` includes UDP,
the local UDP relay sends encrypted UDP packets to the plugin's loopback
listener. In server mode, protocols covered by `plugin_mode` are owned by the
plugin on the public port while the Zig Shadowsocks TCP and/or UDP relays bind
the loopback internal port. This covers classic SIP003 TCP-only plugins and
SIP003u UDP-capable plugins.

ACL parsing lives in `security/acl.zig` and follows the shadowsocks-rust/libev
section names. The implemented local path supports `[proxy_all]`,
`[bypass_all]`, `[bypass_list]`, `[proxy_list]`, exact-domain rules (`|name`),
subdomain rules (`||name`), IP addresses, CIDR ranges, and arbitrary host
regular expressions compiled through RE2. Local TCP requests that ACL marks as
bypassed connect directly to the target instead of opening a Shadowsocks tunnel.
Server TCP and UDP paths enforce client accept/reject rules and outbound
block/allow rules before connecting or forwarding target traffic.

Manager mode is entered with `--manager` and requires `manager_address` in the
JSON config. The implementation supports both IP UDP addresses such as
`127.0.0.1:6001` and libev-style Unix-domain datagram socket paths such as
`/tmp/ss-manager.sock`. It handles libev-compatible `add`, `list`, `remove`,
`stat`, and `ping` datagrams. Managed entries own generated per-port config
files under `.zig-cache/ss-zig-manager` and child `ss-zig --server` processes.
`add` checks TCP/UDP bind availability with POSIX bind/close before spawning,
and `remove` kills the managed child process and deletes its generated config.
Server mode maintains an atomic traffic counter for bytes relayed through TCP
and UDP server paths; when `manager_address` is configured, a periodic reporter
sends libev-style `stat: {"port":bytes}` datagrams back to the manager over the
same IP UDP or Unix-datagram transport.

Server mode starts every parsed `servers` entry as its own listener group,
including per-server ACL, plugin, replay, UDP association, and traffic reporter
state. Local mode starts every parsed `locals` entry as its own listener group;
all local entries share a round-robin outbound selector over the configured
servers. The selector has independent TCP and UDP cursors, and UDP chooses once
when a client association is created so replies stay pinned to the selected
server. This is intentionally simpler than shadowsocks-rust's ping balancer,
but keeps the same service ownership boundary and no longer collapses extended
server configs to the first entry.

The libev `ipv6_first` / `-6` option is stored on both server and local
listener configs. Server configs use it when resolving configured server
endpoints in local mode and when resolving outbound domain targets in server
mode. Local configs use it for direct-bypass target connects and local DNS
forwards.

Libev TCP buffer size options are also stored on both server and local listener
configs. `tcp_incoming_sndbuf` / `tcp_incoming_rcvbuf` are applied to accepted
TCP sockets from clients. `tcp_outgoing_sndbuf` / `tcp_outgoing_rcvbuf` are
applied before outbound TCP connects to configured Shadowsocks servers or
direct target sockets.

In server mode, libev's `local_address`, `local_ipv4_address`, and
`local_ipv6_address` map to outbound TCP bind addresses, matching
shadowsocks-rust's server-side `local_address` meaning. The bind is selected by
target address family and applied before the nonblocking connect to the remote
TCP target.

SOCKS5 username/password authentication follows shadowsocks-rust's
`socks5_auth_config_path` convention. The file is parsed as:

```json
{
  "password": {
    "users": [
      {"user_name": "USER_NAME", "password": "PASSWORD"}
    ]
  }
}
```

SOCKS4/4a support is local TCP CONNECT only. It follows shadowsocks-rust's
server dispatch rule: when SOCKS5 password users are configured, SOCKS4 is
rejected instead of being allowed to bypass authentication. SOCKS4 BIND is not
implemented.

Local listener protocol dispatch follows shadowsocks-rust's `protocol` field.
The default `protocol = "socks"` accepts SOCKS5 and SOCKS4/4a only. `protocol =
"http"` accepts HTTP/1.x CONNECT and traditional HTTP proxy requests only.
Unknown protocols are rejected during config parsing. When SOCKS5 password users
are configured, HTTP is rejected instead of being allowed to bypass
authentication.

Tunnel local support follows shadowsocks-rust's `protocol = "tunnel"` local
shape and libev `ss-tunnel`: `forward_address` and `forward_port` define the
single Shadowsocks target. TCP tunnel listeners forward raw streams to that
target, and UDP tunnel listeners wrap each raw datagram with the fixed target
address before encryption, then strip the source address from server replies
before returning raw datagrams to the client.

Redir local support follows shadowsocks-rust's `protocol = "redir"` config
surface with `tcp_redir` and `udp_redir` values. The current implementation
parses the upstream type names and wires Linux TCP `redirect`/`tproxy` and UDP
`tproxy` into the same target relay used by tunnel mode. TCP `redirect`
retrieves the original destination with `SO_ORIGINAL_DST`, TCP `tproxy` uses
the accepted socket local address after binding with `IP_TRANSPARENT`, and UDP
`tproxy` receives original-destination control messages with `recvmsg` before
sending responses from transparent sockets bound to the original destination.
For BSD-style TCP redir, macOS/iOS and FreeBSD `pf` use `/dev/pf`
`DIOCNATLOOK` with layouts pinned to shadowsocks-rust's bindgen output,
OpenBSD `pf` uses the accepted socket local address, and `ipfw` uses the
accepted socket local address on macOS/iOS/FreeBSD. For macOS/iOS UDP `pf`,
the listener receives from a normal UDP socket and then scans `/dev/pf`
`DIOCGETSTATES` state records to recover the original gateway destination,
matching shadowsocks-rust's PacketFilter lookup strategy. FreeBSD UDP `pf`
uses `IP_BINDANY`, `IP_RECVORIGDSTADDR`, and `IPV6_RECVORIGDSTADDR`; OpenBSD
UDP `pf` uses `SO_BINDANY`, `IP_RECVDSTADDR`/`IP_RECVDSTPORT`, and
`IPV6_PKTINFO`/`IPV6_RECVDSTPORT`.

Fake-DNS local support follows shadowsocks-rust's `protocol = "fake-dns"`
configuration keys for IPv4/IPv6 pools, database path, and record expiration.
The current runtime implements IPv4/IPv6 pools for A and AAAA queries and
shares those mappings with other local listeners in the process, so SOCKS/HTTP
requests to fake IP addresses are rewritten back to the original domain before
ACL checks and Shadowsocks tunnel setup. When `fake_dns_database_path` is set,
default builds persist records in a small JSON cache and reload them on
restart. Builds made with `-Drocksdb=true` use RocksDB and BSON records with
the same key names as shadowsocks-rust, including
`shadowsocks_fakedns_meta`, `shadowsocks_fakedns_name2ip_*`, and
`shadowsocks_fakedns_ip2name_*`.

The supported cipher surface is AEAD-only. SIP004 methods include
`aes-128-gcm`, `aes-256-gcm`, `chacha20-ietf-poly1305`, and
`xchacha20-ietf-poly1305`; AEAD-2022 methods include
`2022-blake3-aes-128-gcm`, `2022-blake3-aes-256-gcm`, and
`2022-blake3-chacha20-poly1305`. Non-AEAD legacy stream methods such as
AES-CFB, AES-CTR, RC4-MD5, Salsa20, and plain ChaCha20 are intentionally not
accepted by config parsing. Libev-compatible raw base64 keys are accepted from
the JSON `key` field and from the CLI `--key` override; when a password
override is supplied without `--key`, any configured raw key is cleared so key
derivation uses the new password.
