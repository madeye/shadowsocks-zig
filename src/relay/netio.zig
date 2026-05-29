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

pub fn listenTcp(host: []const u8, port: u16) !TcpListener {
    const address = try net.IpAddress.parse(host, port);
    return listenTcpAddress(address, false);
}

pub fn listenTcpRedir(host: []const u8, port: u16, redir_type: config.RedirType) !TcpListener {
    const address = try net.IpAddress.parse(host, port);
    return switch (redir_type) {
        .redirect, .tproxy => {
            if (builtin.os.tag != .linux) return error.RedirectionUnsupported;
            return listenTcpAddress(address, redir_type == .tproxy);
        },
        .pf => {
            switch (builtin.os.tag) {
                .macos, .ios, .freebsd, .openbsd => return listenTcpAddress(address, false),
                else => return error.RedirectionUnsupported,
            }
        },
        .ipfw => {
            switch (builtin.os.tag) {
                .macos, .ios, .freebsd => return listenTcpAddress(address, false),
                else => return error.RedirectionUnsupported,
            }
        },
        .not_supported => error.RedirectionUnsupported,
    };
}

fn listenTcpAddress(address: net.IpAddress, transparent: bool) !TcpListener {
    var storage = ipAddressToPosix(address);
    const fd = try openPosixSocket(posixAddressFamily(address), std.posix.SOCK.STREAM);
    errdefer closeFd(fd);
    try setNonblocking(fd);
    if (transparent) try setIpTransparent(fd, address);
    var one: c_int = 1;
    std.posix.setsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.REUSEADDR, std.mem.asBytes(&one)) catch {};
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

pub fn bindUdp(host: []const u8, port: u16) !UdpSocket {
    const address = try net.IpAddress.parse(host, port);
    return try bindUdpAddress(address, .{});
}

pub fn bindUdpRedirListen(host: []const u8, port: u16, redir_type: config.RedirType) !UdpSocket {
    const address = try net.IpAddress.parse(host, port);
    return switch (redir_type) {
        .tproxy => {
            if (builtin.os.tag != .linux) return error.RedirectionUnsupported;
            var socket = try bindUdpAddress(address, .{
                .transparent = true,
                .receive_original_destination = true,
            });
            socket.redir_type = redir_type;
            return socket;
        },
        .pf => {
            if (builtin.os.tag != .macos and builtin.os.tag != .ios) return error.RedirectionUnsupported;
            var socket = try bindUdpAddress(address, .{
                .disable_fragmentation = true,
            });
            socket.redir_type = redir_type;
            return socket;
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
            if (builtin.os.tag != .macos and builtin.os.tag != .ios) return error.RedirectionUnsupported;
            return try bindUdpAddress(address, .{
                .disable_fragmentation = true,
                .reuse_port = true,
            });
        },
        else => error.RedirectionUnsupported,
    };
}

const UdpBindOptions = struct {
    transparent: bool = false,
    receive_original_destination: bool = false,
    reuse_port: bool = false,
    disable_fragmentation: bool = false,
};

fn bindUdpAddress(address: net.IpAddress, options: UdpBindOptions) !UdpSocket {
    var storage = ipAddressToPosix(address);
    const fd = try openPosixSocket(posixAddressFamily(address), std.posix.SOCK.DGRAM);
    errdefer closeFd(fd);
    if (options.transparent) try setIpTransparent(fd, address);
    if (options.receive_original_destination) try setUdpOriginalDestinationOptions(fd, address);
    if (options.disable_fragmentation) try setUdpDisableFragmentation(fd, address);
    try setNonblocking(fd);
    var one: c_int = 1;
    std.posix.setsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.REUSEADDR, std.mem.asBytes(&one)) catch {};
    if (options.reuse_port) {
        std.posix.setsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.REUSEPORT, std.mem.asBytes(&one)) catch |err| switch (err) {
            error.InvalidProtocolOption => {},
            else => |e| return e,
        };
    }
    try bindPosixSocket(fd, &storage.any, posixAddressLen(address));
    return .{ .fd = fd };
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
    if (builtin.os.tag != .linux) return error.RedirectionUnsupported;

    const SOL_IP: c_int = 0;
    const SOL_IPV6: c_int = 41;
    const IP_RECVORIGDSTADDR: u32 = 20;
    const IPV6_RECVORIGDSTADDR: u32 = 74;
    const IP_MTU_DISCOVER: u32 = 10;
    const IPV6_MTU_DISCOVER: u32 = 23;
    const IP_PMTUDISC_DO: c_int = 2;

    const recv_opt = switch (address) {
        .ip4 => .{ SOL_IP, IP_RECVORIGDSTADDR },
        .ip6 => .{ SOL_IPV6, IPV6_RECVORIGDSTADDR },
    };
    var one: c_int = 1;
    try std.posix.setsockopt(fd, recv_opt[0], recv_opt[1], std.mem.asBytes(&one));

    const mtu_opt = switch (address) {
        .ip4 => .{ SOL_IP, IP_MTU_DISCOVER },
        .ip6 => .{ SOL_IPV6, IPV6_MTU_DISCOVER },
    };
    var pmtu: c_int = IP_PMTUDISC_DO;
    try std.posix.setsockopt(fd, mtu_opt[0], mtu_opt[1], std.mem.asBytes(&pmtu));
}

fn setUdpDisableFragmentation(fd: std.posix.socket_t, address: net.IpAddress) !void {
    if (builtin.os.tag != .macos and builtin.os.tag != .ios) return error.RedirectionUnsupported;

    const IPPROTO_IP: c_int = 0;
    const IPPROTO_IPV6: c_int = 41;
    const IP_DONTFRAG: u32 = 67;
    const IPV6_DONTFRAG: u32 = 62;

    const opt = switch (address) {
        .ip4 => .{ IPPROTO_IP, IP_DONTFRAG },
        .ip6 => .{ IPPROTO_IPV6, IPV6_DONTFRAG },
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

    if (builtin.os.tag != .linux or redir_type != .tproxy) return error.RedirectionUnsupported;

    var source: PosixAddress = undefined;
    var iov = std.posix.iovec{ .base = out.ptr, .len = out.len };
    var control_buf: [128]u8 align(@alignOf(std.os.linux.cmsghdr)) = undefined;
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
                .to = try originalDestinationFromControl(&msg),
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

fn originalDestinationFromControl(msg: *const std.posix.msghdr) !net.IpAddress {
    const SOL_IP: c_int = 0;
    const SOL_IPV6: c_int = 41;
    const IP_RECVORIGDSTADDR: c_int = 20;
    const IPV6_RECVORIGDSTADDR: c_int = 74;

    var current = firstControlMessage(msg);
    while (current) |cmsg| {
        switch (cmsg.level) {
            SOL_IP => if (cmsg.type == IP_RECVORIGDSTADDR) {
                var storage: PosixAddress = undefined;
                const data = controlMessageData(cmsg);
                @memcpy(std.mem.asBytes(&storage.in), data[0..@sizeOf(std.posix.sockaddr.in)]);
                return posixToIpAddress(&storage);
            },
            SOL_IPV6 => if (cmsg.type == IPV6_RECVORIGDSTADDR) {
                var storage: PosixAddress = undefined;
                const data = controlMessageData(cmsg);
                @memcpy(std.mem.asBytes(&storage.in6), data[0..@sizeOf(std.posix.sockaddr.in6)]);
                return posixToIpAddress(&storage);
            },
            else => {},
        }
        current = nextControlMessage(msg, cmsg);
    }

    return error.RedirectionOriginalDestinationMissing;
}

fn firstControlMessage(msg: *const std.posix.msghdr) ?*std.os.linux.cmsghdr {
    const control = msg.control orelse return null;
    if (msg.controllen < @sizeOf(std.os.linux.cmsghdr)) return null;
    return @ptrCast(@alignCast(control));
}

fn nextControlMessage(msg: *const std.posix.msghdr, cmsg: *std.os.linux.cmsghdr) ?*std.os.linux.cmsghdr {
    const base_raw: [*]u8 = @ptrCast(msg.control orelse return null);
    const current_raw: [*]u8 = @ptrCast(cmsg);
    const current_offset = @intFromPtr(current_raw) - @intFromPtr(base_raw);
    const next_offset = current_offset + controlMessageAlign(cmsg.len);
    if (next_offset + @sizeOf(std.os.linux.cmsghdr) > msg.controllen) return null;
    return @ptrCast(@alignCast(base_raw + next_offset));
}

fn controlMessageData(cmsg: *const std.os.linux.cmsghdr) []const u8 {
    const raw: [*]const u8 = @ptrCast(cmsg);
    const offset = controlMessageAlign(@sizeOf(std.os.linux.cmsghdr));
    const len = if (cmsg.len > offset) cmsg.len - offset else 0;
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
