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
            return recvUdpRedir(self.fd, out) catch |err| switch (err) {
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
    switch (redir_type) {
        .redirect, .tproxy => {},
        .pf, .ipfw, .not_supported => return error.RedirectionUnsupported,
    }
    if (builtin.os.tag != .linux) return error.RedirectionUnsupported;

    const address = try net.IpAddress.parse(host, port);
    return listenTcpAddress(address, redir_type == .tproxy);
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
        .pf, .ipfw, .not_supported => error.RedirectionUnsupported,
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
    if (redir_type != .tproxy) return error.RedirectionUnsupported;
    if (builtin.os.tag != .linux) return error.RedirectionUnsupported;

    const address = try net.IpAddress.parse(host, port);
    return try bindUdpAddress(address, .{
        .transparent = true,
        .receive_original_destination = true,
    });
}

pub fn bindUdpRedirResponse(address: net.IpAddress, redir_type: config.RedirType) !UdpSocket {
    if (redir_type != .tproxy) return error.RedirectionUnsupported;
    if (builtin.os.tag != .linux) return error.RedirectionUnsupported;

    return try bindUdpAddress(address, .{
        .transparent = true,
        .reuse_port = true,
    });
}

const UdpBindOptions = struct {
    transparent: bool = false,
    receive_original_destination: bool = false,
    reuse_port: bool = false,
};

fn bindUdpAddress(address: net.IpAddress, options: UdpBindOptions) !UdpSocket {
    var storage = ipAddressToPosix(address);
    const fd = try openPosixSocket(posixAddressFamily(address), std.posix.SOCK.DGRAM);
    errdefer closeFd(fd);
    if (options.transparent) try setIpTransparent(fd, address);
    if (options.receive_original_destination) try setUdpOriginalDestinationOptions(fd, address);
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

fn recvUdpRedir(fd: std.posix.socket_t, out: []u8) anyerror!UdpRedirPacket {
    if (builtin.os.tag != .linux) return error.RedirectionUnsupported;

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
