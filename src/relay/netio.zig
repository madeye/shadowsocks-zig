const std = @import("std");
const builtin = @import("builtin");
const config = @import("../config.zig");
const libuv = @import("../deps/libuv.zig");

pub const net = std.Io.net;
const infinite_timeout_ms = std.math.maxInt(u64);

pub const UdpPacket = struct {
    from: net.IpAddress,
    len: usize,
};

pub const UdpRedirPacket = struct {
    from: net.IpAddress,
    to: net.IpAddress,
    len: usize,
};

pub const TcpListener = struct {
    fd: std.posix.socket_t,

    pub fn close(self: *const TcpListener) void {
        closeFd(self.fd);
    }

    pub fn accept(self: *const TcpListener) !TcpStream {
        while (true) {
            if (!try libuv.waitReadable(self.fd, infinite_timeout_ms)) continue;
            const fd = acceptPosixSocket(self.fd) catch |err| switch (err) {
                error.WouldBlock => continue,
                else => |e| return e,
            };
            errdefer closeFd(fd);
            try setNonblocking(fd);
            return .{ .fd = fd };
        }
    }
};

pub const TcpStream = struct {
    fd: std.posix.socket_t,

    pub fn close(self: *const TcpStream) void {
        closeFd(self.fd);
    }

    pub fn peerAddress(self: *const TcpStream) !net.IpAddress {
        return try socketPeerAddress(self.fd);
    }

    pub fn setNoDelay(self: *const TcpStream) void {
        setTcpNoDelay(self.fd);
    }

    pub fn read(self: *TcpStream, out: []u8) !usize {
        while (true) {
            if (!try libuv.waitReadable(self.fd, infinite_timeout_ms)) continue;
            return recvTcp(self.fd, out) catch |err| switch (err) {
                error.WouldBlock => continue,
                else => |e| return e,
            };
        }
    }

    pub fn writeAll(self: *TcpStream, bytes: []const u8) !void {
        var offset: usize = 0;
        while (offset < bytes.len) {
            if (!try libuv.waitWritable(self.fd, infinite_timeout_ms)) continue;
            const written = sendTcp(self.fd, bytes[offset..]) catch |err| switch (err) {
                error.WouldBlock => continue,
                else => |e| return e,
            };
            if (written == 0) return error.SocketNotConnected;
            offset += written;
        }
    }
};

pub fn setTcpNoDelay(fd: std.posix.socket_t) void {
    var one: c_int = 1;
    std.posix.setsockopt(fd, std.posix.IPPROTO.TCP, 1, std.mem.asBytes(&one)) catch {};
}

pub const UdpSocket = struct {
    fd: std.posix.socket_t,
    redir_type: config.RedirType = .not_supported,

    pub fn close(self: *const UdpSocket) void {
        closeFd(self.fd);
    }

    pub fn receiveFrom(self: *UdpSocket, out: []u8) !UdpPacket {
        while (true) {
            if (!try libuv.waitReadable(self.fd, infinite_timeout_ms)) continue;
            return recvUdp(self.fd, out) catch |err| switch (err) {
                error.WouldBlock => continue,
                else => |e| return e,
            };
        }
    }

    pub fn receiveRedirFrom(self: *UdpSocket, out: []u8) !UdpRedirPacket {
        while (true) {
            if (!try libuv.waitReadable(self.fd, infinite_timeout_ms)) continue;
            return recvUdpRedir(self.fd, self.redir_type, out) catch |err| switch (err) {
                error.WouldBlock => continue,
                else => |e| return e,
            };
        }
    }

    pub fn receiveFromTimeout(self: *UdpSocket, out: []u8, timeout_ms: u64) !?UdpPacket {
        while (true) {
            if (!try libuv.waitReadable(self.fd, timeout_ms)) return null;
            return recvUdp(self.fd, out) catch |err| switch (err) {
                error.WouldBlock => continue,
                else => |e| return e,
            };
        }
    }

    pub fn sendTo(self: *UdpSocket, packet: []const u8, address: net.IpAddress) !usize {
        while (true) {
            if (!try libuv.waitWritable(self.fd, infinite_timeout_ms)) continue;
            return sendUdp(self.fd, packet, address) catch |err| switch (err) {
                error.WouldBlock => continue,
                else => |e| return e,
            };
        }
    }
};

pub fn listenTcp(host: []const u8, port: u16, reuse_port: bool) !TcpListener {
    const address = try net.IpAddress.parse(host, port);
    return listenTcpAddress(address, .{ .reuse_port = reuse_port });
}

pub fn listenTcpRedir(host: []const u8, port: u16, redir_type: config.RedirType, reuse_port: bool) !TcpListener {
    const address = try net.IpAddress.parse(host, port);
    return switch (redir_type) {
        .redirect, .tproxy => {
            if (builtin.os.tag != .linux) return error.RedirectionUnsupported;
            return listenTcpAddress(address, .{ .transparent = redir_type == .tproxy, .reuse_port = reuse_port });
        },
        .pf => {
            switch (builtin.os.tag) {
                .macos, .ios, .freebsd, .openbsd => return listenTcpAddress(address, .{ .reuse_port = reuse_port }),
                else => return error.RedirectionUnsupported,
            }
        },
        .ipfw => {
            switch (builtin.os.tag) {
                .macos, .ios, .freebsd => return listenTcpAddress(address, .{ .reuse_port = reuse_port }),
                else => return error.RedirectionUnsupported,
            }
        },
        .not_supported => error.RedirectionUnsupported,
    };
}

const TcpListenOptions = struct {
    transparent: bool = false,
    reuse_port: bool = false,
};

fn listenTcpAddress(address: net.IpAddress, options: TcpListenOptions) !TcpListener {
    var storage = ipAddressToPosix(address);
    const fd = try openPosixSocket(posixAddressFamily(address), std.posix.SOCK.STREAM);
    errdefer closeFd(fd);
    try setNonblocking(fd);
    if (options.transparent) try setIpTransparent(fd, address);
    var one: c_int = 1;
    std.posix.setsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.REUSEADDR, std.mem.asBytes(&one)) catch {};
    if (options.reuse_port) try setReusePort(fd);
    try bindPosixSocket(fd, &storage.any, posixAddressLen(address));
    try listenPosixSocket(fd, 128);
    return .{ .fd = fd };
}

pub fn tcpRedirDestination(stream: TcpStream, redir_type: config.RedirType) !net.IpAddress {
    return switch (redir_type) {
        .redirect => try tcpOriginalDestination(stream.fd),
        .tproxy => try socketLocalAddress(stream.fd),
        .pf => switch (builtin.os.tag) {
            .macos, .ios => try pfNatlookDarwinTcp(stream.fd),
            .freebsd => try pfNatlookFreeBsdTcp(stream.fd),
            .openbsd => try socketLocalAddress(stream.fd),
            else => error.RedirectionUnsupported,
        },
        .ipfw => switch (builtin.os.tag) {
            .macos, .ios, .freebsd => try socketLocalAddress(stream.fd),
            else => error.RedirectionUnsupported,
        },
        .not_supported => error.RedirectionUnsupported,
    };
}

pub fn reserveTcpPort(host: []const u8) !u16 {
    return reservePortForSocket(host, std.posix.SOCK.STREAM);
}

pub fn reserveUdpPort(host: []const u8) !u16 {
    return reservePortForSocket(host, std.posix.SOCK.DGRAM);
}

pub fn reservePort(host: []const u8, mode: config.Mode) !u16 {
    if (mode.enableTcp()) {
        var attempts: usize = 0;
        while (attempts < 64) : (attempts += 1) {
            const port = try reserveTcpPort(host);
            if (!mode.enableUdp() or try canBindUdp(host, port)) return port;
        }
        return error.AddressInUse;
    }
    if (mode.enableUdp()) return try reserveUdpPort(host);
    return error.InvalidMode;
}

fn reservePortForSocket(host: []const u8, socket_type: u32) !u16 {
    const address = try net.IpAddress.parse(host, 0);
    var storage = ipAddressToPosix(address);
    const len = posixAddressLen(address);
    const family = posixAddressFamily(address);
    const fd = try openPosixSocket(family, socket_type);
    defer closeFd(fd);
    try bindPosixSocket(fd, &storage.any, len);
    return try socketLocalPort(fd);
}

pub fn canBindTcp(host: []const u8, port: u16) !bool {
    return canBindPosix(host, port, std.posix.SOCK.STREAM);
}

pub fn canBindUdp(host: []const u8, port: u16) !bool {
    return canBindPosix(host, port, std.posix.SOCK.DGRAM);
}

pub fn connectTcp(host: []const u8, port: u16) !TcpStream {
    const address = try resolveIp(host, port);
    return try connectTcpAddress(address);
}

pub fn connectTcpAddress(address: net.IpAddress) !TcpStream {
    var storage = ipAddressToPosix(address);
    const fd = try openPosixSocket(posixAddressFamily(address), std.posix.SOCK.STREAM);
    errdefer closeFd(fd);
    try setNonblocking(fd);
    connectPosixSocket(fd, &storage.any, posixAddressLen(address)) catch |err| switch (err) {
        error.WouldBlock => {
            if (!try libuv.waitWritable(fd, infinite_timeout_ms)) return error.ConnectionTimedOut;
            try checkConnectResult(fd);
        },
        else => |e| return e,
    };
    return .{ .fd = fd };
}

pub fn bindUdp(host: []const u8, port: u16, reuse_port: bool) !UdpSocket {
    const address = try net.IpAddress.parse(host, port);
    return try bindUdpAddress(address, .{ .reuse_port = reuse_port });
}

pub fn bindUdpRedirListen(host: []const u8, port: u16, redir_type: config.RedirType, reuse_port: bool) !UdpSocket {
    const address = try net.IpAddress.parse(host, port);
    return switch (redir_type) {
        .tproxy => {
            if (builtin.os.tag != .linux) return error.RedirectionUnsupported;
            var socket = try bindUdpAddress(address, .{
                .transparent = true,
                .receive_original_destination = true,
                .reuse_port = reuse_port,
            });
            socket.redir_type = redir_type;
            return socket;
        },
        .pf => {
            switch (builtin.os.tag) {
                .macos, .ios => {
                    var socket = try bindUdpAddress(address, .{
                        .disable_fragmentation = true,
                        .reuse_port = reuse_port,
                    });
                    socket.redir_type = redir_type;
                    return socket;
                },
                .freebsd => {
                    var socket = try bindUdpAddress(address, .{
                        .bind_any = true,
                        .receive_original_destination = true,
                        .disable_fragmentation = true,
                        .reuse_port = reuse_port,
                    });
                    socket.redir_type = redir_type;
                    return socket;
                },
                .openbsd => {
                    var socket = try bindUdpAddress(address, .{
                        .bind_any = true,
                        .receive_original_destination = true,
                        .reuse_port = reuse_port,
                    });
                    socket.redir_type = redir_type;
                    return socket;
                },
                else => return error.RedirectionUnsupported,
            }
        },
        else => error.RedirectionUnsupported,
    };
}

pub fn bindUdpRedirResponse(address: net.IpAddress, redir_type: config.RedirType) !UdpSocket {
    return switch (redir_type) {
        .tproxy => {
            if (builtin.os.tag != .linux) return error.RedirectionUnsupported;
            return try bindUdpAddress(address, .{
                .transparent = true,
                .reuse_port = true,
            });
        },
        .pf => {
            return switch (builtin.os.tag) {
                .macos, .ios => try bindUdpAddress(address, .{
                    .disable_fragmentation = true,
                    .reuse_port = true,
                }),
                .freebsd => try bindUdpAddress(address, .{
                    .bind_any = true,
                    .receive_original_destination = true,
                    .disable_fragmentation = true,
                    .reuse_port = true,
                }),
                .openbsd => try bindUdpAddress(address, .{
                    .bind_any = true,
                    .receive_original_destination = true,
                    .reuse_port = true,
                }),
                else => error.RedirectionUnsupported,
            };
        },
        else => error.RedirectionUnsupported,
    };
}

const UdpBindOptions = struct {
    transparent: bool = false,
    bind_any: bool = false,
    receive_original_destination: bool = false,
    reuse_port: bool = false,
    disable_fragmentation: bool = false,
};

fn bindUdpAddress(address: net.IpAddress, options: UdpBindOptions) !UdpSocket {
    var storage = ipAddressToPosix(address);
    const fd = try openPosixSocket(posixAddressFamily(address), std.posix.SOCK.DGRAM);
    errdefer closeFd(fd);
    if (options.transparent) try setIpTransparent(fd, address);
    if (options.bind_any) try setUdpBindAny(fd, address);
    if (options.receive_original_destination) try setUdpOriginalDestinationOptions(fd, address);
    if (options.disable_fragmentation) try setUdpDisableFragmentation(fd, address);
    try setNonblocking(fd);
    var one: c_int = 1;
    std.posix.setsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.REUSEADDR, std.mem.asBytes(&one)) catch {};
    if (options.reuse_port) {
        try setReusePort(fd);
    }
    try bindPosixSocket(fd, &storage.any, posixAddressLen(address));
    return .{ .fd = fd };
}

fn setReusePort(fd: std.posix.socket_t) !void {
    var one: c_int = 1;
    std.posix.setsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.REUSEPORT, std.mem.asBytes(&one)) catch |err| switch (err) {
        error.InvalidProtocolOption => {},
        else => |e| return e,
    };
}

pub fn openUdp(address: net.IpAddress) !UdpSocket {
    const fd = try openPosixSocket(posixAddressFamily(address), std.posix.SOCK.DGRAM);
    errdefer closeFd(fd);
    try setNonblocking(fd);
    return .{ .fd = fd };
}

pub fn resolveIp(host: []const u8, port: u16) !net.IpAddress {
    if (net.IpAddress.parse(host, port)) |address| return address else |_| {}

    var threaded = std.Io.Threaded.init(std.heap.smp_allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const host_name = try net.HostName.init(host);
    var lookup_buffer: [32]net.HostName.LookupResult = undefined;
    var lookup_queue: std.Io.Queue(net.HostName.LookupResult) = .init(&lookup_buffer);
    try host_name.lookup(io, &lookup_queue, .{ .port = port });

    while (lookup_queue.getOne(io)) |result| switch (result) {
        .address => |address| return address,
        .canonical_name => continue,
    } else |err| switch (err) {
        error.Closed => return error.UnknownHostName,
        else => |e| return e,
    }
}

pub fn shadowToIp(address: @import("../protocol/address.zig").Address) !net.IpAddress {
    return switch (address) {
        .ipv4 => |v| .{ .ip4 = .{ .bytes = v.ip, .port = v.port } },
        .ipv6 => |v| .{ .ip6 = .{ .bytes = v.ip, .port = v.port, .interface = .none } },
        .domain => |d| try resolveIp(d.name, d.port),
    };
}

pub fn ipToShadow(address: net.IpAddress) !@import("../protocol/address.zig").Address {
    return switch (address) {
        .ip4 => |ip4| .{ .ipv4 = .{ .ip = ip4.bytes, .port = ip4.port } },
        .ip6 => |ip6| .{ .ipv6 = .{ .ip = ip6.bytes, .port = ip6.port } },
    };
}

pub fn addressHash(address: net.IpAddress) u64 {
    var hasher = std.hash.Wyhash.init(0);
    switch (address) {
        .ip4 => |ip4| {
            hasher.update(&.{@intFromEnum(net.IpAddress.Family.ip4)});
            hasher.update(&ip4.bytes);
            hasher.update(&std.mem.toBytes(ip4.port));
        },
        .ip6 => |ip6| {
            hasher.update(&.{@intFromEnum(net.IpAddress.Family.ip6)});
            hasher.update(&ip6.bytes);
            hasher.update(&std.mem.toBytes(ip6.port));
        },
    }
    return hasher.final();
}

pub fn eqlAddress(a: net.IpAddress, b: net.IpAddress) bool {
    return a.eql(&b);
}

const PosixAddress = extern union {
    any: std.posix.sockaddr,
    in: std.posix.sockaddr.in,
    in6: std.posix.sockaddr.in6,
};

fn posixAddressFamily(address: net.IpAddress) std.posix.sa_family_t {
    return switch (address) {
        .ip4 => std.posix.AF.INET,
        .ip6 => std.posix.AF.INET6,
    };
}

fn posixAddressLen(address: net.IpAddress) std.posix.socklen_t {
    return switch (address) {
        .ip4 => @sizeOf(std.posix.sockaddr.in),
        .ip6 => @sizeOf(std.posix.sockaddr.in6),
    };
}

fn ipAddressToPosix(address: net.IpAddress) PosixAddress {
    var storage: PosixAddress = undefined;
    switch (address) {
        .ip4 => |ip4| storage.in = .{
            .port = std.mem.nativeToBig(u16, ip4.port),
            .addr = @bitCast(ip4.bytes),
        },
        .ip6 => |ip6| storage.in6 = .{
            .port = std.mem.nativeToBig(u16, ip6.port),
            .flowinfo = ip6.flow,
            .addr = ip6.bytes,
            .scope_id = ip6.interface.index,
        },
    }
    return storage;
}

fn canBindPosix(host: []const u8, port: u16, socket_type: u32) !bool {
    const address = try net.IpAddress.parse(host, port);
    var storage = ipAddressToPosix(address);
    const len = posixAddressLen(address);
    const family = posixAddressFamily(address);
    const fd = try openPosixSocket(family, socket_type);
    defer closeFd(fd);
    bindPosixSocket(fd, &storage.any, len) catch |err| switch (err) {
        error.AddressInUse => return false,
        else => |e| return e,
    };
    return true;
}

fn openPosixSocket(family: std.posix.sa_family_t, socket_type: u32) !std.posix.socket_t {
    while (true) {
        const rc = std.posix.system.socket(family, socket_type, 0);
        switch (std.posix.errno(rc)) {
            .SUCCESS => return @intCast(rc),
            .INTR => continue,
            .AFNOSUPPORT => return error.AddressFamilyUnsupported,
            .INVAL => return error.ProtocolUnsupportedBySystem,
            .MFILE => return error.ProcessFdQuotaExceeded,
            .NFILE => return error.SystemFdQuotaExceeded,
            .NOBUFS, .NOMEM => return error.SystemResources,
            .PROTONOSUPPORT => return error.ProtocolUnsupportedByAddressFamily,
            else => |err| return std.posix.unexpectedErrno(err),
        }
    }
}

fn setIpTransparent(fd: std.posix.socket_t, address: net.IpAddress) !void {
    if (builtin.os.tag != .linux) return error.RedirectionUnsupported;

    const SOL_IP: c_int = 0;
    const SOL_IPV6: c_int = 41;
    const IP_TRANSPARENT: u32 = 19;
    const IPV6_TRANSPARENT: u32 = 75;

    const transparent_opt = switch (address) {
        .ip4 => .{ SOL_IP, IP_TRANSPARENT },
        .ip6 => .{ SOL_IPV6, IPV6_TRANSPARENT },
    };
    var one: c_int = 1;
    try std.posix.setsockopt(fd, transparent_opt[0], transparent_opt[1], std.mem.asBytes(&one));
}

fn setUdpOriginalDestinationOptions(fd: std.posix.socket_t, address: net.IpAddress) !void {
    const IPPROTO_IP: c_int = 0;
    const IPPROTO_IPV6: c_int = 41;
    const opt = switch (builtin.os.tag) {
        .linux => switch (address) {
            .ip4 => .{ IPPROTO_IP, @as(u32, 20) },
            .ip6 => .{ IPPROTO_IPV6, @as(u32, 74) },
        },
        .freebsd => switch (address) {
            .ip4 => .{ IPPROTO_IP, @as(u32, 27) },
            .ip6 => .{ IPPROTO_IPV6, @as(u32, 72) },
        },
        .openbsd => switch (address) {
            .ip4 => .{ IPPROTO_IP, @as(u32, 7) },
            .ip6 => .{ IPPROTO_IPV6, @as(u32, 36) },
        },
        else => return error.RedirectionUnsupported,
    };

    var one: c_int = 1;
    try std.posix.setsockopt(fd, opt[0], opt[1], std.mem.asBytes(&one));

    if (builtin.os.tag == .openbsd) {
        const port_opt = switch (address) {
            .ip4 => .{ IPPROTO_IP, @as(u32, 33) },
            .ip6 => .{ IPPROTO_IPV6, @as(u32, 64) },
        };
        try std.posix.setsockopt(fd, port_opt[0], port_opt[1], std.mem.asBytes(&one));
    }

    if (builtin.os.tag != .linux) return;

    const mtu_opt = switch (address) {
        .ip4 => .{ IPPROTO_IP, @as(u32, 10) },
        .ip6 => .{ IPPROTO_IPV6, @as(u32, 23) },
    };
    var pmtu: c_int = 2;
    try std.posix.setsockopt(fd, mtu_opt[0], mtu_opt[1], std.mem.asBytes(&pmtu));
}

fn setUdpBindAny(fd: std.posix.socket_t, address: net.IpAddress) !void {
    const IPPROTO_IP: c_int = 0;
    const IPPROTO_IPV6: c_int = 41;
    const SOL_SOCKET_BINDANY: u32 = 0x1000;

    const opt = switch (builtin.os.tag) {
        .freebsd => switch (address) {
            .ip4 => .{ IPPROTO_IP, @as(u32, 24) },
            .ip6 => .{ IPPROTO_IPV6, @as(u32, 64) },
        },
        .openbsd => .{ std.posix.SOL.SOCKET, SOL_SOCKET_BINDANY },
        else => return error.RedirectionUnsupported,
    };
    var one: c_int = 1;
    try std.posix.setsockopt(fd, opt[0], opt[1], std.mem.asBytes(&one));
}

fn setUdpDisableFragmentation(fd: std.posix.socket_t, address: net.IpAddress) !void {
    const IPPROTO_IP: c_int = 0;
    const IPPROTO_IPV6: c_int = 41;
    const opt = switch (builtin.os.tag) {
        .macos, .ios => switch (address) {
            .ip4 => .{ IPPROTO_IP, @as(u32, 67) },
            .ip6 => .{ IPPROTO_IPV6, @as(u32, 62) },
        },
        .freebsd => switch (address) {
            .ip4 => .{ IPPROTO_IP, @as(u32, 67) },
            .ip6 => .{ IPPROTO_IPV6, @as(u32, 62) },
        },
        else => return error.RedirectionUnsupported,
    };
    var one: c_int = 1;
    std.posix.setsockopt(fd, opt[0], opt[1], std.mem.asBytes(&one)) catch |err| switch (err) {
        error.InvalidProtocolOption => {},
        else => |e| return e,
    };
}

fn setNonblocking(fd: std.posix.socket_t) !void {
    while (true) {
        const rc = std.posix.system.fcntl(fd, std.posix.F.GETFL, @as(c_int, 0));
        switch (std.posix.errno(rc)) {
            .SUCCESS => {
                const flags: c_int = @intCast(rc);
                const nonblock: c_int = @intCast(@as(u32, @bitCast(std.posix.O{ .NONBLOCK = true })));
                while (true) {
                    const set_rc = std.posix.system.fcntl(fd, std.posix.F.SETFL, @as(c_int, flags | nonblock));
                    switch (std.posix.errno(set_rc)) {
                        .SUCCESS => return,
                        .INTR => continue,
                        .BADF => return error.SocketNotConnected,
                        .INVAL => return error.InvalidArgument,
                        else => |err| return std.posix.unexpectedErrno(err),
                    }
                }
            },
            .INTR => continue,
            .BADF => return error.SocketNotConnected,
            .INVAL => return error.InvalidArgument,
            else => |err| return std.posix.unexpectedErrno(err),
        }
    }
}

fn bindPosixSocket(fd: std.posix.socket_t, address: *const std.posix.sockaddr, len: std.posix.socklen_t) !void {
    while (true) {
        switch (std.posix.errno(std.posix.system.bind(fd, address, len))) {
            .SUCCESS => return,
            .INTR => continue,
            .ACCES => return error.AccessDenied,
            .ADDRINUSE => return error.AddressInUse,
            .AFNOSUPPORT => return error.AddressFamilyUnsupported,
            .ADDRNOTAVAIL => return error.AddressUnavailable,
            .BADF => return error.SocketNotConnected,
            .INVAL => return error.InvalidArgument,
            .NOTSOCK => return error.SocketNotConnected,
            .NOMEM => return error.SystemResources,
            else => |err| return std.posix.unexpectedErrno(err),
        }
    }
}

fn listenPosixSocket(fd: std.posix.socket_t, backlog: u32) !void {
    while (true) {
        switch (std.posix.errno(std.posix.system.listen(fd, backlog))) {
            .SUCCESS => return,
            .INTR => continue,
            .ADDRINUSE => return error.AddressInUse,
            .BADF => return error.SocketNotConnected,
            .DESTADDRREQ => return error.AddressNotAvailable,
            .INVAL => return error.InvalidArgument,
            .NOTSOCK => return error.SocketNotConnected,
            .OPNOTSUPP => return error.OperationNotSupported,
            else => |err| return std.posix.unexpectedErrno(err),
        }
    }
}

fn acceptPosixSocket(fd: std.posix.socket_t) !std.posix.socket_t {
    while (true) {
        const rc = std.posix.system.accept(fd, null, null);
        switch (std.posix.errno(rc)) {
            .SUCCESS => return @intCast(rc),
            .INTR => continue,
            .AGAIN => return error.WouldBlock,
            .BADF => return error.SocketNotConnected,
            .CONNABORTED => return error.ConnectionAborted,
            .INVAL => return error.InvalidArgument,
            .MFILE => return error.ProcessFdQuotaExceeded,
            .NFILE => return error.SystemFdQuotaExceeded,
            .NOBUFS, .NOMEM => return error.SystemResources,
            .NOTSOCK => return error.SocketNotConnected,
            .OPNOTSUPP => return error.OperationNotSupported,
            else => |err| return std.posix.unexpectedErrno(err),
        }
    }
}

fn connectPosixSocket(fd: std.posix.socket_t, address: *const std.posix.sockaddr, len: std.posix.socklen_t) !void {
    while (true) {
        switch (std.posix.errno(std.posix.system.connect(fd, address, len))) {
            .SUCCESS => return,
            .INTR => continue,
            .AGAIN, .INPROGRESS, .ALREADY => return error.WouldBlock,
            .ACCES => return error.AccessDenied,
            .ADDRINUSE => return error.AddressInUse,
            .ADDRNOTAVAIL => return error.AddressUnavailable,
            .AFNOSUPPORT => return error.AddressFamilyUnsupported,
            .BADF => return error.SocketNotConnected,
            .CONNREFUSED => return error.ConnectionRefused,
            .HOSTUNREACH, .NETUNREACH => return error.NetworkUnreachable,
            .ISCONN => return,
            .TIMEDOUT => return error.ConnectionTimedOut,
            .INVAL => return error.InvalidArgument,
            .NOTSOCK => return error.SocketNotConnected,
            else => |err| return std.posix.unexpectedErrno(err),
        }
    }
}

fn checkConnectResult(fd: std.posix.socket_t) !void {
    var err_value: c_int = 0;
    var len: std.posix.socklen_t = @sizeOf(c_int);
    while (true) {
        switch (std.posix.errno(std.posix.system.getsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.ERROR, &err_value, &len))) {
            .SUCCESS => break,
            .INTR => continue,
            .BADF => return error.SocketNotConnected,
            .INVAL => return error.InvalidArgument,
            .NOTSOCK => return error.SocketNotConnected,
            else => |err| return std.posix.unexpectedErrno(err),
        }
    }
    if (err_value == 0) return;
    return switch (@as(std.posix.E, @enumFromInt(err_value))) {
        .CONNREFUSED => error.ConnectionRefused,
        .HOSTUNREACH, .NETUNREACH => error.NetworkUnreachable,
        .TIMEDOUT => error.ConnectionTimedOut,
        else => error.ConnectFailed,
    };
}

fn recvTcp(fd: std.posix.socket_t, out: []u8) !usize {
    while (true) {
        const rc = std.posix.system.recv(fd, out.ptr, out.len, @as(c_int, 0));
        switch (std.posix.errno(rc)) {
            .SUCCESS => return @intCast(rc),
            .INTR => continue,
            .AGAIN => return error.WouldBlock,
            .BADF => return error.SocketNotConnected,
            .CONNRESET => return error.ConnectionResetByPeer,
            .INVAL => return error.InvalidArgument,
            .NOTCONN => return error.SocketNotConnected,
            .NOTSOCK => return error.SocketNotConnected,
            else => |err| return std.posix.unexpectedErrno(err),
        }
    }
}

fn sendTcp(fd: std.posix.socket_t, bytes: []const u8) !usize {
    while (true) {
        const rc = std.posix.system.send(fd, bytes.ptr, bytes.len, @as(u32, 0));
        switch (std.posix.errno(rc)) {
            .SUCCESS => return @intCast(rc),
            .INTR => continue,
            .AGAIN => return error.WouldBlock,
            .BADF => return error.SocketNotConnected,
            .CONNRESET => return error.ConnectionResetByPeer,
            .INVAL => return error.InvalidArgument,
            .NOTCONN => return error.SocketNotConnected,
            .NOTSOCK => return error.SocketNotConnected,
            .PIPE => return error.BrokenPipe,
            else => |err| return std.posix.unexpectedErrno(err),
        }
    }
}

fn recvUdp(fd: std.posix.socket_t, out: []u8) !UdpPacket {
    var storage: PosixAddress = undefined;
    var len: std.posix.socklen_t = @sizeOf(PosixAddress);
    while (true) {
        const rc = std.posix.system.recvfrom(fd, out.ptr, out.len, @as(u32, 0), &storage.any, &len);
        switch (std.posix.errno(rc)) {
            .SUCCESS => return .{ .from = try posixToIpAddress(&storage), .len = @intCast(rc) },
            .INTR => continue,
            .AGAIN => return error.WouldBlock,
            .BADF => return error.SocketNotConnected,
            .INVAL => return error.InvalidArgument,
            .NOTSOCK => return error.SocketNotConnected,
            else => |err| return std.posix.unexpectedErrno(err),
        }
    }
}

fn recvUdpRedir(fd: std.posix.socket_t, redir_type: config.RedirType, out: []u8) anyerror!UdpRedirPacket {
    if (builtin.os.tag == .macos or builtin.os.tag == .ios) {
        if (redir_type != .pf) return error.RedirectionUnsupported;
        const packet = try recvUdp(fd, out);
        return .{
            .from = packet.from,
            .to = try pfNatlookDarwinUdp(try socketLocalAddress(fd), packet.from),
            .len = packet.len,
        };
    }

    const parser: OriginalDestinationParser = switch (builtin.os.tag) {
        .linux => if (redir_type == .tproxy) .linux_tproxy else return error.RedirectionUnsupported,
        .freebsd => if (redir_type == .pf) .freebsd_pf else return error.RedirectionUnsupported,
        .openbsd => if (redir_type == .pf) .openbsd_pf else return error.RedirectionUnsupported,
        else => return error.RedirectionUnsupported,
    };

    var source: PosixAddress = undefined;
    var iov = std.posix.iovec{ .base = out.ptr, .len = out.len };
    var control_buf: [128]u8 align(@alignOf(std.c.cmsghdr)) = undefined;
    var msg = std.posix.msghdr{
        .name = &source.any,
        .namelen = @sizeOf(PosixAddress),
        .iov = @ptrCast(&iov),
        .iovlen = 1,
        .control = &control_buf,
        .controllen = control_buf.len,
        .flags = 0,
    };

    while (true) {
        const rc = std.posix.system.recvmsg(fd, &msg, @as(u32, 0));
        switch (std.posix.errno(rc)) {
            .SUCCESS => return .{
                .from = try posixToIpAddress(&source),
                .to = try originalDestinationFromControl(&msg, parser),
                .len = @intCast(rc),
            },
            .INTR => continue,
            .AGAIN => return error.WouldBlock,
            .BADF => return error.SocketNotConnected,
            .INVAL => return error.InvalidArgument,
            .NOTSOCK => return error.SocketNotConnected,
            else => |err| return std.posix.unexpectedErrno(err),
        }
    }
}

const OriginalDestinationParser = enum {
    linux_tproxy,
    freebsd_pf,
    openbsd_pf,
};

fn originalDestinationFromControl(msg: *const std.posix.msghdr, parser: OriginalDestinationParser) !net.IpAddress {
    var current = firstControlMessage(msg);
    while (current) |cmsg| {
        if (!validControlMessage(msg, cmsg)) return error.RedirectionOriginalDestinationMissing;
        if (fullSockaddrOriginalDestination(cmsg, parser)) |address| {
            return address;
        } else |_| {}

        if (parser == .openbsd_pf) {
            if (openBsdSplitOriginalDestination(msg)) |address| return address else |_| {}
            break;
        }
        current = nextControlMessage(msg, cmsg);
    }

    return error.RedirectionOriginalDestinationMissing;
}

fn fullSockaddrOriginalDestination(cmsg: *const std.c.cmsghdr, parser: OriginalDestinationParser) !net.IpAddress {
    const IPPROTO_IP: c_int = 0;
    const IPPROTO_IPV6: c_int = 41;
    const types: struct { c_int, c_int } = switch (parser) {
        .linux_tproxy => .{ @as(c_int, 20), @as(c_int, 74) },
        .freebsd_pf => .{ @as(c_int, 27), @as(c_int, 72) },
        .openbsd_pf => return error.RedirectionOriginalDestinationMissing,
    };
    const ipv4_type: c_int = types[0];
    const ipv6_type: c_int = types[1];

    switch (cmsg.level) {
        IPPROTO_IP => if (cmsg.type == ipv4_type) {
            var storage: PosixAddress = undefined;
            const data = controlMessageData(cmsg);
            if (data.len < @sizeOf(std.posix.sockaddr.in)) return error.RedirectionOriginalDestinationMissing;
            @memcpy(std.mem.asBytes(&storage.in), data[0..@sizeOf(std.posix.sockaddr.in)]);
            return posixToIpAddress(&storage);
        },
        IPPROTO_IPV6 => if (cmsg.type == ipv6_type) {
            var storage: PosixAddress = undefined;
            const data = controlMessageData(cmsg);
            if (data.len < @sizeOf(std.posix.sockaddr.in6)) return error.RedirectionOriginalDestinationMissing;
            @memcpy(std.mem.asBytes(&storage.in6), data[0..@sizeOf(std.posix.sockaddr.in6)]);
            return posixToIpAddress(&storage);
        },
        else => {},
    }
    return error.RedirectionOriginalDestinationMissing;
}

fn openBsdSplitOriginalDestination(msg: *const std.posix.msghdr) !net.IpAddress {
    const IPPROTO_IP: c_int = 0;
    const IPPROTO_IPV6: c_int = 41;
    const IP_RECVDSTADDR: c_int = 7;
    const IP_RECVDSTPORT: c_int = 33;
    const IPV6_PKTINFO: c_int = 46;
    const IPV6_RECVDSTPORT: c_int = 64;

    var ip4_addr: ?u32 = null;
    var ip4_port: ?u16 = null;
    var ip6_addr: ?[16]u8 = null;
    var ip6_port: ?u16 = null;

    var current = firstControlMessage(msg);
    while (current) |cmsg| {
        const data = controlMessageData(cmsg);
        switch (cmsg.level) {
            IPPROTO_IP => switch (cmsg.type) {
                IP_RECVDSTADDR => {
                    if (data.len >= 4) ip4_addr = std.mem.readInt(u32, data[0..4], .native);
                },
                IP_RECVDSTPORT => {
                    if (data.len >= 2) ip4_port = std.mem.readInt(u16, data[0..2], .native);
                },
                else => {},
            },
            IPPROTO_IPV6 => switch (cmsg.type) {
                IPV6_PKTINFO => if (data.len >= 16) {
                    var addr: [16]u8 = undefined;
                    @memcpy(&addr, data[0..16]);
                    ip6_addr = addr;
                },
                IPV6_RECVDSTPORT => {
                    if (data.len >= 2) ip6_port = std.mem.readInt(u16, data[0..2], .native);
                },
                else => {},
            },
            else => {},
        }
        current = nextControlMessage(msg, cmsg);
    }

    if (ip4_addr) |addr| {
        if (ip4_port) |port| {
            var storage: PosixAddress = undefined;
            storage.in = .{ .addr = addr, .port = port };
            return posixToIpAddress(&storage);
        }
    }
    if (ip6_addr) |addr| {
        if (ip6_port) |port| {
            var storage: PosixAddress = undefined;
            storage.in6 = .{ .addr = addr, .port = port, .flowinfo = 0, .scope_id = 0 };
            return posixToIpAddress(&storage);
        }
    }
    return error.RedirectionOriginalDestinationMissing;
}

fn firstControlMessage(msg: *const std.posix.msghdr) ?*std.c.cmsghdr {
    const control = msg.control orelse return null;
    if (msg.controllen < @sizeOf(std.c.cmsghdr)) return null;
    return @ptrCast(@alignCast(control));
}

fn nextControlMessage(msg: *const std.posix.msghdr, cmsg: *std.c.cmsghdr) ?*std.c.cmsghdr {
    if (!validControlMessage(msg, cmsg)) return null;
    const base_raw: [*]u8 = @ptrCast(msg.control orelse return null);
    const current_raw: [*]u8 = @ptrCast(cmsg);
    const current_offset = @intFromPtr(current_raw) - @intFromPtr(base_raw);
    const next_offset = current_offset + controlMessageAlign(@intCast(cmsg.len));
    if (next_offset + @sizeOf(std.c.cmsghdr) > msg.controllen) return null;
    return @ptrCast(@alignCast(base_raw + next_offset));
}

fn validControlMessage(msg: *const std.posix.msghdr, cmsg: *const std.c.cmsghdr) bool {
    const base = msg.control orelse return false;
    const base_addr = @intFromPtr(base);
    const cmsg_addr = @intFromPtr(cmsg);
    if (cmsg_addr < base_addr) return false;
    const offset = cmsg_addr - base_addr;
    if (offset + @sizeOf(std.c.cmsghdr) > msg.controllen) return false;
    const cmsg_len: usize = @intCast(cmsg.len);
    if (cmsg_len < @sizeOf(std.c.cmsghdr)) return false;
    if (offset + cmsg_len > msg.controllen) return false;
    return true;
}

fn controlMessageData(cmsg: *const std.c.cmsghdr) []const u8 {
    const raw: [*]const u8 = @ptrCast(cmsg);
    const offset = controlMessageAlign(@sizeOf(std.c.cmsghdr));
    const cmsg_len: usize = @intCast(cmsg.len);
    const len = if (cmsg_len > offset) cmsg_len - offset else 0;
    return raw[offset..][0..len];
}

fn controlMessageAlign(len: usize) usize {
    return std.mem.alignForward(usize, len, @sizeOf(usize));
}

fn sendUdp(fd: std.posix.socket_t, packet: []const u8, address: net.IpAddress) !usize {
    var storage = ipAddressToPosix(address);
    while (true) {
        const rc = std.posix.system.sendto(fd, packet.ptr, packet.len, @as(u32, 0), &storage.any, posixAddressLen(address));
        switch (std.posix.errno(rc)) {
            .SUCCESS => return @intCast(rc),
            .INTR => continue,
            .AGAIN => return error.WouldBlock,
            .ACCES => return error.AccessDenied,
            .ADDRNOTAVAIL => return error.AddressUnavailable,
            .AFNOSUPPORT => return error.AddressFamilyUnsupported,
            .BADF => return error.SocketNotConnected,
            .HOSTUNREACH, .NETUNREACH => return error.NetworkUnreachable,
            .INVAL => return error.InvalidArgument,
            .MSGSIZE => return error.MessageTooBig,
            .NOTSOCK => return error.SocketNotConnected,
            else => |err| return std.posix.unexpectedErrno(err),
        }
    }
}

fn closeFd(fd: std.posix.fd_t) void {
    switch (std.posix.errno(std.posix.system.close(fd))) {
        .SUCCESS, .INTR => {},
        else => {},
    }
}

fn socketLocalPort(fd: std.posix.socket_t) !u16 {
    var storage: PosixAddress = undefined;
    var len: std.posix.socklen_t = @sizeOf(PosixAddress);
    while (true) {
        switch (std.posix.errno(std.posix.system.getsockname(fd, &storage.any, &len))) {
            .SUCCESS => break,
            .INTR => continue,
            .BADF => return error.SocketNotConnected,
            .INVAL => return error.InvalidArgument,
            .NOTSOCK => return error.SocketNotConnected,
            .NOBUFS => return error.SystemResources,
            else => |err| return std.posix.unexpectedErrno(err),
        }
    }
    return switch (storage.any.family) {
        std.posix.AF.INET => std.mem.bigToNative(u16, storage.in.port),
        std.posix.AF.INET6 => std.mem.bigToNative(u16, storage.in6.port),
        else => error.UnsupportedAddressFamily,
    };
}

fn socketPeerAddress(fd: std.posix.socket_t) !net.IpAddress {
    var storage: PosixAddress = undefined;
    var len: std.posix.socklen_t = @sizeOf(PosixAddress);
    while (true) {
        switch (std.posix.errno(std.posix.system.getpeername(fd, &storage.any, &len))) {
            .SUCCESS => break,
            .INTR => continue,
            .BADF => return error.SocketNotConnected,
            .INVAL => return error.InvalidArgument,
            .NOTCONN => return error.SocketNotConnected,
            .NOTSOCK => return error.SocketNotConnected,
            .NOBUFS => return error.SystemResources,
            else => |err| return std.posix.unexpectedErrno(err),
        }
    }
    return posixToIpAddress(&storage);
}

fn socketLocalAddress(fd: std.posix.socket_t) !net.IpAddress {
    var storage: PosixAddress = undefined;
    var len: std.posix.socklen_t = @sizeOf(PosixAddress);
    while (true) {
        switch (std.posix.errno(std.posix.system.getsockname(fd, &storage.any, &len))) {
            .SUCCESS => break,
            .INTR => continue,
            .BADF => return error.SocketNotConnected,
            .INVAL => return error.InvalidArgument,
            .NOTSOCK => return error.SocketNotConnected,
            .NOBUFS => return error.SystemResources,
            else => |err| return std.posix.unexpectedErrno(err),
        }
    }
    return posixToIpAddress(&storage);
}

fn tcpOriginalDestination(fd: std.posix.socket_t) !net.IpAddress {
    if (builtin.os.tag != .linux) return error.RedirectionUnsupported;

    const SOL_IP: c_int = 0;
    const SOL_IPV6: c_int = 41;
    const SO_ORIGINAL_DST: u32 = 80;
    const IP6T_SO_ORIGINAL_DST: u32 = 80;

    var storage: PosixAddress = undefined;
    var len: std.posix.socklen_t = @sizeOf(PosixAddress);
    switch (std.posix.errno(std.posix.system.getsockopt(fd, SOL_IPV6, IP6T_SO_ORIGINAL_DST, &storage.any, &len))) {
        .SUCCESS => return posixToIpAddress(&storage),
        .NOPROTOOPT, .NOENT, .OPNOTSUPP => {},
        else => |err| return std.posix.unexpectedErrno(err),
    }

    storage = undefined;
    len = @sizeOf(PosixAddress);
    switch (std.posix.errno(std.posix.system.getsockopt(fd, SOL_IP, SO_ORIGINAL_DST, &storage.any, &len))) {
        .SUCCESS => return posixToIpAddress(&storage),
        .NOPROTOOPT, .NOENT, .OPNOTSUPP => return error.RedirectionUnsupported,
        else => |err| return std.posix.unexpectedErrno(err),
    }
}

const PfAddr = extern struct {
    words: [4]u32,
};

const PfPort = extern union {
    port: u16,
    call_id: u16,
    spi: u32,
};

const PfiocNatlookDarwin = extern struct {
    saddr: PfAddr,
    daddr: PfAddr,
    rsaddr: PfAddr,
    rdaddr: PfAddr,
    sxport: PfPort,
    dxport: PfPort,
    rsxport: PfPort,
    rdxport: PfPort,
    af: u8,
    proto: u8,
    proto_variant: u8,
    direction: u8,
};

const PfiocNatlookFreeBsd = extern struct {
    saddr: PfAddr,
    daddr: PfAddr,
    rsaddr: PfAddr,
    rdaddr: PfAddr,
    sport: u16,
    dport: u16,
    rsport: u16,
    rdport: u16,
    af: u8,
    proto: u8,
    direction: u8,
};

const PfiocStates = extern struct {
    ps_len: c_int,
    ps_u: extern union {
        psu_buf: [*]u8,
    },
};

const darwin_pfsync_state_size = 297;
const darwin_pfsync_lan_addr_offset = 24;
const darwin_pfsync_lan_port_offset = 40;
const darwin_pfsync_gwy_addr_offset = 48;
const darwin_pfsync_gwy_port_offset = 64;
const darwin_pfsync_ext_gwy_addr_offset = 96;
const darwin_pfsync_ext_gwy_port_offset = 112;
const darwin_pfsync_af_gwy_offset = 283;
const darwin_pfsync_proto_offset = 284;

fn pfNatlookDarwinTcp(fd: std.posix.socket_t) !net.IpAddress {
    if (builtin.os.tag != .macos and builtin.os.tag != .ios) return error.RedirectionUnsupported;

    const local = try socketLocalAddress(fd);
    const peer = try socketPeerAddress(fd);
    var lookup: PfiocNatlookDarwin = std.mem.zeroes(PfiocNatlookDarwin);
    try fillPfLookupAddress(&lookup.daddr, &lookup.dxport.port, &lookup.af, local);
    try fillPfLookupAddress(&lookup.saddr, &lookup.sxport.port, &lookup.af, peer);
    lookup.proto = 6;
    lookup.direction = 2;

    try pfNatlookIoctl(PfiocNatlookDarwin, &lookup);
    return pfNatlookResult(lookup.af, lookup.rdaddr, lookup.rdxport.port);
}

fn pfNatlookFreeBsdTcp(fd: std.posix.socket_t) !net.IpAddress {
    if (builtin.os.tag != .freebsd) return error.RedirectionUnsupported;

    const local = try socketLocalAddress(fd);
    const peer = try socketPeerAddress(fd);
    var lookup: PfiocNatlookFreeBsd = std.mem.zeroes(PfiocNatlookFreeBsd);
    try fillPfLookupAddress(&lookup.daddr, &lookup.dport, &lookup.af, local);
    try fillPfLookupAddress(&lookup.saddr, &lookup.sport, &lookup.af, peer);
    lookup.proto = 6;
    lookup.direction = 2;

    try pfNatlookIoctl(PfiocNatlookFreeBsd, &lookup);
    return pfNatlookResult(lookup.af, lookup.rdaddr, lookup.rdport);
}

fn pfNatlookDarwinUdp(bind_addr: net.IpAddress, peer_addr: net.IpAddress) !net.IpAddress {
    if (builtin.os.tag != .macos and builtin.os.tag != .ios) return error.RedirectionUnsupported;

    var bind_pf_addr: PfAddr = std.mem.zeroes(PfAddr);
    var bind_port: u16 = 0;
    var bind_family: u8 = 0;
    try fillPfLookupAddress(&bind_pf_addr, &bind_port, &bind_family, bind_addr);

    var peer_pf_addr: PfAddr = std.mem.zeroes(PfAddr);
    var peer_port: u16 = 0;
    var peer_family: u8 = 0;
    try fillPfLookupAddress(&peer_pf_addr, &peer_port, &peer_family, peer_addr);
    if (bind_family != peer_family) return error.AddressFamilyUnsupported;

    const allocator = std.heap.smp_allocator;
    var state_bytes = try allocator.alloc(u8, 8192);
    defer allocator.free(state_bytes);

    const fd = try std.posix.openatZ(std.posix.AT.FDCWD, "/dev/pf", .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    defer closeFd(fd);

    while (true) {
        var states = PfiocStates{
            .ps_len = @intCast(state_bytes.len),
            .ps_u = .{ .psu_buf = state_bytes.ptr },
        };
        const req = ioctlReadWrite('D', 25, PfiocStates);
        switch (std.posix.errno(std.c.ioctl(fd, req, &states))) {
            .SUCCESS => {},
            .ACCES, .PERM => return error.AccessDenied,
            .BADF => return error.SocketNotConnected,
            .INVAL => return error.RedirectionOriginalDestinationMissing,
            .NOENT => return error.RedirectionOriginalDestinationMissing,
            .NXIO => return error.RedirectionUnsupported,
            else => |err| return std.posix.unexpectedErrno(err),
        }
        if (states.ps_len <= state_bytes.len) {
            const used = @as(usize, @intCast(states.ps_len));
            return try pfNatlookDarwinUdpFromStates(
                state_bytes[0..used],
                bind_pf_addr,
                std.mem.bigToNative(u16, bind_port),
                peer_pf_addr,
                std.mem.bigToNative(u16, peer_port),
            );
        }
        state_bytes = try allocator.realloc(state_bytes, @intCast(states.ps_len));
    }
}

fn pfNatlookDarwinUdpFromStates(
    states: []const u8,
    bind_addr: PfAddr,
    bind_port: u16,
    peer_addr: PfAddr,
    peer_port: u16,
) !net.IpAddress {
    const IPPROTO_UDP: u8 = 17;
    const count = states.len / darwin_pfsync_state_size;
    var i: usize = 0;
    while (i < count) : (i += 1) {
        const state = states[i * darwin_pfsync_state_size ..][0..darwin_pfsync_state_size];
        if (state[darwin_pfsync_proto_offset] != IPPROTO_UDP) continue;
        if (!std.mem.eql(u8, state[darwin_pfsync_lan_addr_offset..][0..16], std.mem.asBytes(&bind_addr.words))) continue;
        if (!std.mem.eql(u8, state[darwin_pfsync_ext_gwy_addr_offset..][0..16], std.mem.asBytes(&peer_addr.words))) continue;
        if (std.mem.readInt(u16, state[darwin_pfsync_lan_port_offset..][0..2], .native) != bind_port) continue;
        if (std.mem.readInt(u16, state[darwin_pfsync_ext_gwy_port_offset..][0..2], .native) != peer_port) continue;

        var actual_addr: PfAddr = std.mem.zeroes(PfAddr);
        @memcpy(std.mem.asBytes(&actual_addr.words), state[darwin_pfsync_gwy_addr_offset..][0..16]);
        const actual_port = std.mem.readInt(u16, state[darwin_pfsync_gwy_port_offset..][0..2], .native);
        return pfNatlookResultHostPort(state[darwin_pfsync_af_gwy_offset], actual_addr, actual_port);
    }
    return error.RedirectionOriginalDestinationMissing;
}

fn fillPfLookupAddress(addr: *PfAddr, port: *u16, family: *u8, address: net.IpAddress) !void {
    switch (address) {
        .ip4 => |ip4| {
            const af = @as(u8, @intCast(std.posix.AF.INET));
            if (family.* != 0 and family.* != af) return error.AddressFamilyUnsupported;
            family.* = af;
            @memcpy(std.mem.asBytes(&addr.words)[0..4], &ip4.bytes);
            port.* = std.mem.nativeToBig(u16, ip4.port);
        },
        .ip6 => |ip6| {
            const af = @as(u8, @intCast(std.posix.AF.INET6));
            if (family.* != 0 and family.* != af) return error.AddressFamilyUnsupported;
            family.* = af;
            @memcpy(std.mem.asBytes(&addr.words)[0..16], &ip6.bytes);
            port.* = std.mem.nativeToBig(u16, ip6.port);
        },
    }
}

fn pfNatlookResult(family: u8, addr: PfAddr, port: u16) !net.IpAddress {
    return pfNatlookResultHostPort(family, addr, std.mem.bigToNative(u16, port));
}

fn pfNatlookResultHostPort(family: u8, addr: PfAddr, port: u16) !net.IpAddress {
    if (family == @as(u8, @intCast(std.posix.AF.INET))) {
        var bytes: [4]u8 = undefined;
        @memcpy(&bytes, std.mem.asBytes(&addr.words)[0..4]);
        return .{ .ip4 = .{ .bytes = bytes, .port = port } };
    }
    if (family == @as(u8, @intCast(std.posix.AF.INET6))) {
        var bytes: [16]u8 = undefined;
        @memcpy(&bytes, std.mem.asBytes(&addr.words)[0..16]);
        return .{ .ip6 = .{ .bytes = bytes, .port = port, .interface = .none } };
    }
    return error.UnsupportedAddressFamily;
}

fn pfNatlookIoctl(comptime Lookup: type, lookup: *Lookup) !void {
    const fd = try std.posix.openatZ(std.posix.AT.FDCWD, "/dev/pf", .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    defer closeFd(fd);

    const req = ioctlReadWrite('D', 23, Lookup);
    switch (std.posix.errno(std.c.ioctl(fd, req, lookup))) {
        .SUCCESS => return,
        .ACCES, .PERM => return error.AccessDenied,
        .BADF => return error.SocketNotConnected,
        .INVAL => return error.RedirectionOriginalDestinationMissing,
        .NOENT => return error.RedirectionOriginalDestinationMissing,
        .NXIO => return error.RedirectionUnsupported,
        else => |err| return std.posix.unexpectedErrno(err),
    }
}

fn ioctlReadWrite(comptime group: u8, comptime number: u8, comptime Payload: type) c_int {
    const IOC_INOUT: u32 = 0xc0000000;
    const request = IOC_INOUT | (@as(u32, @sizeOf(Payload)) << 16) | (@as(u32, group) << 8) | @as(u32, number);
    return @as(c_int, @bitCast(request));
}

fn posixToIpAddress(storage: *const PosixAddress) !net.IpAddress {
    return switch (storage.any.family) {
        std.posix.AF.INET => .{ .ip4 = .{
            .bytes = @bitCast(storage.in.addr),
            .port = std.mem.bigToNative(u16, storage.in.port),
        } },
        std.posix.AF.INET6 => .{ .ip6 = .{
            .bytes = storage.in6.addr,
            .port = std.mem.bigToNative(u16, storage.in6.port),
            .flow = storage.in6.flowinfo,
            .interface = .{ .index = storage.in6.scope_id },
        } },
        else => error.UnsupportedAddressFamily,
    };
}

test "pf natlook ABI layouts match upstream bindgen" {
    try std.testing.expectEqual(@as(usize, 16), @sizeOf(PfAddr));
    try std.testing.expectEqual(@as(usize, 4), @alignOf(PfAddr));
    try std.testing.expectEqual(@as(usize, 4), @sizeOf(PfPort));
    try std.testing.expectEqual(@as(usize, 4), @alignOf(PfPort));

    try std.testing.expectEqual(@as(usize, 84), @sizeOf(PfiocNatlookDarwin));
    try std.testing.expectEqual(@as(usize, 4), @alignOf(PfiocNatlookDarwin));
    try std.testing.expectEqual(@as(usize, 64), @offsetOf(PfiocNatlookDarwin, "sxport"));
    try std.testing.expectEqual(@as(usize, 68), @offsetOf(PfiocNatlookDarwin, "dxport"));
    try std.testing.expectEqual(@as(usize, 76), @offsetOf(PfiocNatlookDarwin, "rdxport"));
    try std.testing.expectEqual(@as(usize, 80), @offsetOf(PfiocNatlookDarwin, "af"));
    try std.testing.expectEqual(@as(usize, 83), @offsetOf(PfiocNatlookDarwin, "direction"));

    try std.testing.expectEqual(@as(usize, 76), @sizeOf(PfiocNatlookFreeBsd));
    try std.testing.expectEqual(@as(usize, 4), @alignOf(PfiocNatlookFreeBsd));
    try std.testing.expectEqual(@as(usize, 64), @offsetOf(PfiocNatlookFreeBsd, "sport"));
    try std.testing.expectEqual(@as(usize, 66), @offsetOf(PfiocNatlookFreeBsd, "dport"));
    try std.testing.expectEqual(@as(usize, 70), @offsetOf(PfiocNatlookFreeBsd, "rdport"));
    try std.testing.expectEqual(@as(usize, 72), @offsetOf(PfiocNatlookFreeBsd, "af"));
    try std.testing.expectEqual(@as(usize, 74), @offsetOf(PfiocNatlookFreeBsd, "direction"));

    try std.testing.expectEqual(@as(usize, 16), @sizeOf(PfiocStates));
    try std.testing.expectEqual(@as(usize, 8), @alignOf(PfiocStates));
    try std.testing.expectEqual(@as(usize, 8), @offsetOf(PfiocStates, "ps_u"));
    try std.testing.expectEqual(@as(usize, 297), darwin_pfsync_state_size);
    try std.testing.expectEqual(@as(usize, 24), darwin_pfsync_lan_addr_offset);
    try std.testing.expectEqual(@as(usize, 48), darwin_pfsync_gwy_addr_offset);
    try std.testing.expectEqual(@as(usize, 96), darwin_pfsync_ext_gwy_addr_offset);
    try std.testing.expectEqual(@as(usize, 283), darwin_pfsync_af_gwy_offset);
    try std.testing.expectEqual(@as(usize, 284), darwin_pfsync_proto_offset);
}

test "pf natlook address helpers preserve bytes and network order ports" {
    var addr: PfAddr = std.mem.zeroes(PfAddr);
    var port: u16 = 0;
    var family: u8 = 0;

    try fillPfLookupAddress(&addr, &port, &family, .{ .ip4 = .{ .bytes = .{ 192, 0, 2, 10 }, .port = 5353 } });
    try std.testing.expectEqual(@as(u8, @intCast(std.posix.AF.INET)), family);
    try std.testing.expectEqual(std.mem.nativeToBig(u16, 5353), port);
    try std.testing.expectEqualSlices(u8, &.{ 192, 0, 2, 10 }, std.mem.asBytes(&addr.words)[0..4]);

    const restored = try pfNatlookResult(family, addr, port);
    try std.testing.expect(restored.eql(&.{ .ip4 = .{ .bytes = .{ 192, 0, 2, 10 }, .port = 5353 } }));

    addr = std.mem.zeroes(PfAddr);
    port = 0;
    family = 0;
    try fillPfLookupAddress(&addr, &port, &family, .{ .ip6 = .{ .bytes = .{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x53 }, .port = 5354, .interface = .none } });
    try std.testing.expectEqual(@as(u8, @intCast(std.posix.AF.INET6)), family);
    try std.testing.expectEqual(std.mem.nativeToBig(u16, 5354), port);
    try std.testing.expectEqualSlices(u8, &.{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x53 }, std.mem.asBytes(&addr.words)[0..16]);

    const restored_v6 = try pfNatlookResult(family, addr, port);
    try std.testing.expect(restored_v6.eql(&.{ .ip6 = .{ .bytes = .{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x53 }, .port = 5354, .interface = .none } }));
}

test "darwin pf UDP state parser recovers gateway destination" {
    var bind_addr: PfAddr = std.mem.zeroes(PfAddr);
    var bind_port_be: u16 = 0;
    var bind_family: u8 = 0;
    try fillPfLookupAddress(&bind_addr, &bind_port_be, &bind_family, .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 1097 } });

    var peer_addr: PfAddr = std.mem.zeroes(PfAddr);
    var peer_port_be: u16 = 0;
    var peer_family: u8 = 0;
    try fillPfLookupAddress(&peer_addr, &peer_port_be, &peer_family, .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 2 }, .port = 53000 } });

    var actual_addr: PfAddr = std.mem.zeroes(PfAddr);
    var actual_port_be: u16 = 0;
    var actual_family: u8 = 0;
    try fillPfLookupAddress(&actual_addr, &actual_port_be, &actual_family, .{ .ip4 = .{ .bytes = .{ 198, 51, 100, 7 }, .port = 53 } });

    var state = [_]u8{0} ** darwin_pfsync_state_size;
    @memcpy(state[darwin_pfsync_lan_addr_offset..][0..16], std.mem.asBytes(&bind_addr.words));
    @memcpy(state[darwin_pfsync_ext_gwy_addr_offset..][0..16], std.mem.asBytes(&peer_addr.words));
    @memcpy(state[darwin_pfsync_gwy_addr_offset..][0..16], std.mem.asBytes(&actual_addr.words));
    std.mem.writeInt(u16, state[darwin_pfsync_lan_port_offset..][0..2], std.mem.bigToNative(u16, bind_port_be), .native);
    std.mem.writeInt(u16, state[darwin_pfsync_ext_gwy_port_offset..][0..2], std.mem.bigToNative(u16, peer_port_be), .native);
    std.mem.writeInt(u16, state[darwin_pfsync_gwy_port_offset..][0..2], std.mem.bigToNative(u16, actual_port_be), .native);
    state[darwin_pfsync_af_gwy_offset] = actual_family;
    state[darwin_pfsync_proto_offset] = 17;

    const restored = try pfNatlookDarwinUdpFromStates(
        &state,
        bind_addr,
        std.mem.bigToNative(u16, bind_port_be),
        peer_addr,
        std.mem.bigToNative(u16, peer_port_be),
    );
    try std.testing.expect(restored.eql(&.{ .ip4 = .{ .bytes = .{ 198, 51, 100, 7 }, .port = 53 } }));
}

test "darwin pf UDP state parser recovers IPv6 gateway destination" {
    const bind_ip = [_]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10 };
    const peer_ip = [_]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x20 };
    const actual_ip = [_]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x35 };

    var bind_addr: PfAddr = std.mem.zeroes(PfAddr);
    var bind_port_be: u16 = 0;
    var bind_family: u8 = 0;
    try fillPfLookupAddress(&bind_addr, &bind_port_be, &bind_family, .{ .ip6 = .{ .bytes = bind_ip, .port = 1097, .interface = .none } });

    var peer_addr: PfAddr = std.mem.zeroes(PfAddr);
    var peer_port_be: u16 = 0;
    var peer_family: u8 = 0;
    try fillPfLookupAddress(&peer_addr, &peer_port_be, &peer_family, .{ .ip6 = .{ .bytes = peer_ip, .port = 53000, .interface = .none } });

    var actual_addr: PfAddr = std.mem.zeroes(PfAddr);
    var actual_port_be: u16 = 0;
    var actual_family: u8 = 0;
    try fillPfLookupAddress(&actual_addr, &actual_port_be, &actual_family, .{ .ip6 = .{ .bytes = actual_ip, .port = 53, .interface = .none } });

    var state = [_]u8{0} ** darwin_pfsync_state_size;
    @memcpy(state[darwin_pfsync_lan_addr_offset..][0..16], std.mem.asBytes(&bind_addr.words));
    @memcpy(state[darwin_pfsync_ext_gwy_addr_offset..][0..16], std.mem.asBytes(&peer_addr.words));
    @memcpy(state[darwin_pfsync_gwy_addr_offset..][0..16], std.mem.asBytes(&actual_addr.words));
    std.mem.writeInt(u16, state[darwin_pfsync_lan_port_offset..][0..2], std.mem.bigToNative(u16, bind_port_be), .native);
    std.mem.writeInt(u16, state[darwin_pfsync_ext_gwy_port_offset..][0..2], std.mem.bigToNative(u16, peer_port_be), .native);
    std.mem.writeInt(u16, state[darwin_pfsync_gwy_port_offset..][0..2], std.mem.bigToNative(u16, actual_port_be), .native);
    state[darwin_pfsync_af_gwy_offset] = actual_family;
    state[darwin_pfsync_proto_offset] = 17;

    const restored = try pfNatlookDarwinUdpFromStates(
        &state,
        bind_addr,
        std.mem.bigToNative(u16, bind_port_be),
        peer_addr,
        std.mem.bigToNative(u16, peer_port_be),
    );
    try std.testing.expect(restored.eql(&.{ .ip6 = .{ .bytes = actual_ip, .port = 53, .interface = .none } }));
}

test "FreeBSD UDP original destination parser reads sockaddr control message" {
    var storage = ipAddressToPosix(.{ .ip4 = .{ .bytes = .{ 203, 0, 113, 10 }, .port = 5353 } });
    var control_buf: [128]u8 align(@alignOf(std.c.cmsghdr)) = undefined;
    const used = writeTestControlMessage(&control_buf, 0, 0, 27, std.mem.asBytes(&storage.in));
    var msg = testControlMessage(&control_buf, used);

    const restored = try originalDestinationFromControl(&msg, .freebsd_pf);
    try std.testing.expect(restored.eql(&.{ .ip4 = .{ .bytes = .{ 203, 0, 113, 10 }, .port = 5353 } }));
}

test "FreeBSD UDP original destination parser reads IPv6 sockaddr control message" {
    const dst_ip = [_]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x77 };
    var storage = ipAddressToPosix(.{ .ip6 = .{ .bytes = dst_ip, .port = 5353, .interface = .none } });
    var control_buf: [160]u8 align(@alignOf(std.c.cmsghdr)) = undefined;
    const used = writeTestControlMessage(&control_buf, 0, 41, 72, std.mem.asBytes(&storage.in6));
    var msg = testControlMessage(&control_buf, used);

    const restored = try originalDestinationFromControl(&msg, .freebsd_pf);
    try std.testing.expect(restored.eql(&.{ .ip6 = .{ .bytes = dst_ip, .port = 5353, .interface = .none } }));
}

test "OpenBSD UDP original destination parser combines split address and port control messages" {
    var control_buf: [128]u8 align(@alignOf(std.c.cmsghdr)) = undefined;
    const addr_bytes = [_]u8{ 198, 51, 100, 8 };
    var port_bytes: [2]u8 = undefined;
    std.mem.writeInt(u16, &port_bytes, 5354, .big);
    var used = writeTestControlMessage(&control_buf, 0, 0, 7, &addr_bytes);
    used = writeTestControlMessage(&control_buf, used, 0, 33, &port_bytes);
    var msg = testControlMessage(&control_buf, used);

    const restored = try originalDestinationFromControl(&msg, .openbsd_pf);
    try std.testing.expect(restored.eql(&.{ .ip4 = .{ .bytes = .{ 198, 51, 100, 8 }, .port = 5354 } }));
}

test "OpenBSD UDP original destination parser combines split IPv6 address and port control messages" {
    var control_buf: [160]u8 align(@alignOf(std.c.cmsghdr)) = undefined;
    const addr_bytes = [_]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x88 };
    var port_bytes: [2]u8 = undefined;
    std.mem.writeInt(u16, &port_bytes, 5355, .big);
    var pktinfo = [_]u8{0} ** 20;
    @memcpy(pktinfo[0..16], &addr_bytes);
    var used = writeTestControlMessage(&control_buf, 0, 41, 46, &pktinfo);
    used = writeTestControlMessage(&control_buf, used, 41, 64, &port_bytes);
    var msg = testControlMessage(&control_buf, used);

    const restored = try originalDestinationFromControl(&msg, .openbsd_pf);
    try std.testing.expect(restored.eql(&.{ .ip6 = .{ .bytes = addr_bytes, .port = 5355, .interface = .none } }));
}

test "UDP original destination parser rejects truncated control message" {
    var control_buf: [64]u8 align(@alignOf(std.c.cmsghdr)) = undefined;
    const header: *std.c.cmsghdr = @ptrCast(@alignCast(&control_buf));
    header.* = .{
        .len = @sizeOf(std.c.cmsghdr) + 32,
        .level = 0,
        .type = 27,
    };
    var msg = testControlMessage(&control_buf, @sizeOf(std.c.cmsghdr) + 4);

    try std.testing.expectError(error.RedirectionOriginalDestinationMissing, originalDestinationFromControl(&msg, .freebsd_pf));
}

fn writeTestControlMessage(buffer: []align(@alignOf(std.c.cmsghdr)) u8, offset: usize, level: c_int, cmsg_type: c_int, data: []const u8) usize {
    const header_offset = controlMessageAlign(offset);
    const data_offset = header_offset + controlMessageAlign(@sizeOf(std.c.cmsghdr));
    const cmsg_len = data_offset - header_offset + data.len;
    const header: *std.c.cmsghdr = @ptrCast(@alignCast(buffer[header_offset..].ptr));
    header.* = .{
        .len = @intCast(cmsg_len),
        .level = level,
        .type = cmsg_type,
    };
    @memcpy(buffer[data_offset..][0..data.len], data);
    return header_offset + controlMessageAlign(cmsg_len);
}

fn testControlMessage(buffer: []align(@alignOf(std.c.cmsghdr)) u8, len: usize) std.posix.msghdr {
    var iov = std.posix.iovec{ .base = buffer.ptr, .len = 0 };
    return .{
        .name = null,
        .namelen = 0,
        .iov = @ptrCast(&iov),
        .iovlen = 1,
        .control = buffer.ptr,
        .controllen = @intCast(len),
        .flags = 0,
    };
}
