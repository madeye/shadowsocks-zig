const std = @import("std");

pub const CryptoError = error{
    AuthenticationFailed,
    BufferTooSmall,
    InvalidCipher,
    InvalidKeyLength,
    PacketTooLong,
    RepeatedNonce,
    UnsupportedCipher,
} || std.mem.Allocator.Error || std.Io.RandomSecureError;

pub const CipherCategory = enum {
    none,
    stream,
    aead,
    aead2022,
};

pub const CipherKind = enum {
    none,
    aes_128_gcm,
    aes_256_gcm,
    chacha20_ietf_poly1305,
    aes_128_cfb,
    aes_256_cfb,
    aes_128_ctr,
    aes_256_ctr,
    rc4_md5,
    chacha20_ietf,
    xchacha20_ietf_poly1305,
    aead2022_blake3_aes_128_gcm,
    aead2022_blake3_aes_256_gcm,
    aead2022_blake3_chacha20_poly1305,

    pub fn parse(method_name: []const u8) CryptoError!CipherKind {
        inline for (@typeInfo(CipherKind).@"enum".fields) |field| {
            const kind: CipherKind = @enumFromInt(field.value);
            if (std.ascii.eqlIgnoreCase(kind.name(), method_name)) return kind;
        }
        return error.InvalidCipher;
    }

    pub fn name(self: CipherKind) []const u8 {
        return switch (self) {
            .none => "none",
            .aes_128_gcm => "aes-128-gcm",
            .aes_256_gcm => "aes-256-gcm",
            .chacha20_ietf_poly1305 => "chacha20-ietf-poly1305",
            .aes_128_cfb => "aes-128-cfb",
            .aes_256_cfb => "aes-256-cfb",
            .aes_128_ctr => "aes-128-ctr",
            .aes_256_ctr => "aes-256-ctr",
            .rc4_md5 => "rc4-md5",
            .chacha20_ietf => "chacha20-ietf",
            .xchacha20_ietf_poly1305 => "xchacha20-ietf-poly1305",
            .aead2022_blake3_aes_128_gcm => "2022-blake3-aes-128-gcm",
            .aead2022_blake3_aes_256_gcm => "2022-blake3-aes-256-gcm",
            .aead2022_blake3_chacha20_poly1305 => "2022-blake3-chacha20-poly1305",
        };
    }

    pub fn category(self: CipherKind) CipherCategory {
        return switch (self) {
            .none => .none,
            .aes_128_gcm, .aes_256_gcm, .chacha20_ietf_poly1305, .xchacha20_ietf_poly1305 => .aead,
            .aes_128_cfb, .aes_256_cfb, .aes_128_ctr, .aes_256_ctr, .rc4_md5, .chacha20_ietf => .stream,
            .aead2022_blake3_aes_128_gcm,
            .aead2022_blake3_aes_256_gcm,
            .aead2022_blake3_chacha20_poly1305,
            => .aead2022,
        };
    }

    pub fn keyLen(self: CipherKind) usize {
        return switch (self) {
            .none => 0,
            .aes_128_gcm, .aead2022_blake3_aes_128_gcm => 16,
            .aes_256_gcm,
            .chacha20_ietf_poly1305,
            .xchacha20_ietf_poly1305,
            .aead2022_blake3_aes_256_gcm,
            .aead2022_blake3_chacha20_poly1305,
            => 32,
            .aes_128_cfb, .aes_128_ctr => 16,
            .aes_256_cfb, .aes_256_ctr, .chacha20_ietf => 32,
            .rc4_md5 => 16,
        };
    }

    pub fn saltLen(self: CipherKind) usize {
        return switch (self) {
            .aes_128_gcm => 16,
            .aes_256_gcm, .chacha20_ietf_poly1305, .xchacha20_ietf_poly1305 => 32,
            .aes_128_cfb, .aes_256_cfb, .aes_128_ctr, .aes_256_ctr, .rc4_md5 => 16,
            .chacha20_ietf => 12,
            .aead2022_blake3_aes_128_gcm => 16,
            .aead2022_blake3_aes_256_gcm,
            .aead2022_blake3_chacha20_poly1305,
            => 32,
            else => 0,
        };
    }

    pub fn nonceLen(self: CipherKind) usize {
        return switch (self) {
            .aes_128_gcm,
            .aes_256_gcm,
            .chacha20_ietf_poly1305,
            => 12,
            .xchacha20_ietf_poly1305,
            => 24,
            .aead2022_blake3_aes_128_gcm,
            .aead2022_blake3_aes_256_gcm,
            .aead2022_blake3_chacha20_poly1305,
            => 12,
            else => 0,
        };
    }

    pub fn tagLen(self: CipherKind) usize {
        return switch (self) {
            .aes_128_gcm,
            .aes_256_gcm,
            .chacha20_ietf_poly1305,
            .xchacha20_ietf_poly1305,
            .aead2022_blake3_aes_128_gcm,
            .aead2022_blake3_aes_256_gcm,
            .aead2022_blake3_chacha20_poly1305,
            => 16,
            else => 0,
        };
    }

    pub fn isImplemented(self: CipherKind) bool {
        return self == .none or isImplementedStreamCipher(self) or self.category() == .aead or self.category() == .aead2022;
    }
};

pub fn deriveKey(password: []const u8, out: []u8) void {
    var last: [16]u8 = undefined;
    var last_len: usize = 0;
    var written: usize = 0;

    while (written < out.len) {
        var md5 = std.crypto.hash.Md5.init(.{});
        if (last_len != 0) md5.update(last[0..last_len]);
        md5.update(password);
        md5.final(&last);
        last_len = last.len;

        const n = @min(out.len - written, last.len);
        @memcpy(out[written..][0..n], last[0..n]);
        written += n;
    }

    std.crypto.secureZero(u8, &last);
}

pub fn deriveMasterKey(method: CipherKind, password: []const u8, out: []u8) CryptoError!void {
    if (out.len != method.keyLen()) return error.InvalidKeyLength;
    if (method.category() != .aead2022) {
        deriveKey(password, out);
        return;
    }

    const encoded = if (std.mem.lastIndexOfScalar(u8, password, ':')) |idx| password[idx + 1 ..] else password;
    try decodeBase64Key(encoded, out);
}

fn decodeBase64Key(encoded: []const u8, out: []u8) CryptoError!void {
    if (try decodeBase64KeyWith(std.base64.standard.Decoder, encoded, out)) return;
    if (try decodeBase64KeyWith(std.base64.standard_no_pad.Decoder, encoded, out)) return;
    return error.InvalidKeyLength;
}

fn decodeBase64KeyWith(decoder: std.base64.Base64Decoder, encoded: []const u8, out: []u8) CryptoError!bool {
    const decoded_len = decoder.calcSizeForSlice(encoded) catch return false;
    if (decoded_len != out.len) return false;
    decoder.decode(out, encoded) catch return false;
    return true;
}

pub fn hkdfSha1(out: []u8, key: []const u8, salt: []const u8, info: []const u8) void {
    const HmacSha1 = std.crypto.auth.hmac.HmacSha1;
    var prk: [HmacSha1.mac_length]u8 = undefined;
    HmacSha1.create(&prk, key, salt);

    var t: [HmacSha1.mac_length]u8 = undefined;
    var t_len: usize = 0;
    var written: usize = 0;
    var counter: u8 = 1;
    while (written < out.len) : (counter += 1) {
        var hmac = HmacSha1.init(&prk);
        if (t_len != 0) hmac.update(t[0..t_len]);
        hmac.update(info);
        hmac.update((&counter)[0..1]);
        hmac.final(&t);
        t_len = t.len;

        const n = @min(out.len - written, t_len);
        @memcpy(out[written..][0..n], t[0..n]);
        written += n;
    }

    std.crypto.secureZero(u8, &prk);
    std.crypto.secureZero(u8, &t);
}

pub fn blake3Derive(out: []u8, context: []const u8, key: []const u8, salt: []const u8) void {
    var hasher = std.crypto.hash.Blake3.initKdf(context, .{});
    hasher.update(key);
    hasher.update(salt);
    hasher.final(out);
}

fn isAesCfbCipher(method: CipherKind) bool {
    return method == .aes_128_cfb or method == .aes_256_cfb;
}

fn isAesCtrCipher(method: CipherKind) bool {
    return method == .aes_128_ctr or method == .aes_256_ctr;
}

fn isImplementedStreamCipher(method: CipherKind) bool {
    return isAesCfbCipher(method) or isAesCtrCipher(method) or method == .rc4_md5 or method == .chacha20_ietf;
}

pub const AeadCipher = struct {
    method: CipherKind,
    key: [32]u8,
    nonce: [24]u8 = [_]u8{0} ** 24,

    pub fn init(method: CipherKind, master_key: []const u8, salt: []const u8) CryptoError!AeadCipher {
        if (method.category() != .aead) return error.UnsupportedCipher;
        if (master_key.len != method.keyLen()) return error.InvalidKeyLength;
        if (salt.len != method.saltLen()) return error.InvalidKeyLength;

        var self = AeadCipher{
            .method = method,
            .key = [_]u8{0} ** 32,
        };
        hkdfSha1(self.key[0..method.keyLen()], master_key, salt, "ss-subkey");
        return self;
    }

    pub fn encryptChunk(self: *AeadCipher, allocator: std.mem.Allocator, plain: []const u8) CryptoError![]u8 {
        if (plain.len > 0x3fff) return error.PacketTooLong;
        const tag_len = self.method.tagLen();
        const out = try allocator.alloc(u8, 2 + tag_len + plain.len + tag_len);
        errdefer allocator.free(out);

        var len_plain = [_]u8{ @intCast((plain.len >> 8) & 0xff), @intCast(plain.len & 0xff) };
        try self.encryptDetached(out[0..2], out[2..][0..tag_len], &len_plain);
        self.incrementNonce();

        const data_off = 2 + tag_len;
        try self.encryptDetached(out[data_off..][0..plain.len], out[data_off + plain.len ..][0..tag_len], plain);
        self.incrementNonce();
        return out;
    }

    pub fn decryptChunk(self: *AeadCipher, allocator: std.mem.Allocator, packet: []const u8) CryptoError![]u8 {
        const tag_len = self.method.tagLen();
        if (packet.len < 2 + tag_len + tag_len) return error.AuthenticationFailed;

        const len = try self.decryptLength(packet[0 .. 2 + tag_len]);
        if (packet.len != 2 + tag_len + len + tag_len) return error.AuthenticationFailed;

        const data_off = 2 + tag_len;
        return self.decryptPayload(allocator, packet[data_off .. data_off + len + tag_len], len);
    }

    pub fn decryptLength(self: *AeadCipher, sealed_len: []const u8) CryptoError!usize {
        const tag_len = self.method.tagLen();
        if (sealed_len.len != 2 + tag_len) return error.AuthenticationFailed;
        var len_plain: [2]u8 = undefined;
        var length_tag: [16]u8 = undefined;
        @memcpy(&length_tag, sealed_len[2..][0..tag_len]);
        self.decryptDetached(&len_plain, sealed_len[0..2], length_tag) catch return error.AuthenticationFailed;
        self.incrementNonce();
        const len = (@as(usize, len_plain[0]) << 8) | len_plain[1];
        if (len > 0x3fff) return error.PacketTooLong;
        return len;
    }

    pub fn decryptPayload(self: *AeadCipher, allocator: std.mem.Allocator, sealed_payload: []const u8, len: usize) CryptoError![]u8 {
        const tag_len = self.method.tagLen();
        if (len > 0x3fff) return error.PacketTooLong;
        if (sealed_payload.len != len + tag_len) return error.AuthenticationFailed;
        const out = try allocator.alloc(u8, len);
        errdefer allocator.free(out);
        var data_tag: [16]u8 = undefined;
        @memcpy(&data_tag, sealed_payload[len..][0..tag_len]);
        self.decryptDetached(out, sealed_payload[0..len], data_tag) catch return error.AuthenticationFailed;
        self.incrementNonce();
        return out;
    }

    fn encryptDetached(self: *AeadCipher, dst: []u8, tag: []u8, plain: []const u8) CryptoError!void {
        switch (self.method) {
            .aes_128_gcm => {
                const k = self.key[0..16].*;
                const n = self.nonce[0..12].*;
                std.crypto.aead.aes_gcm.Aes128Gcm.encrypt(dst, tag[0..16], plain, "", n, k);
            },
            .aes_256_gcm => {
                const k = self.key[0..32].*;
                const n = self.nonce[0..12].*;
                std.crypto.aead.aes_gcm.Aes256Gcm.encrypt(dst, tag[0..16], plain, "", n, k);
            },
            .chacha20_ietf_poly1305 => {
                const k = self.key[0..32].*;
                const n = self.nonce[0..12].*;
                std.crypto.aead.chacha_poly.ChaCha20Poly1305.encrypt(dst, tag[0..16], plain, "", n, k);
            },
            .xchacha20_ietf_poly1305 => {
                const k = self.key[0..32].*;
                const n = self.nonce[0..24].*;
                std.crypto.aead.chacha_poly.XChaCha20Poly1305.encrypt(dst, tag[0..16], plain, "", n, k);
            },
            else => unreachable,
        }
    }

    fn decryptDetached(self: *AeadCipher, dst: []u8, cipher: []const u8, tag: [16]u8) !void {
        switch (self.method) {
            .aes_128_gcm => {
                const k = self.key[0..16].*;
                const n = self.nonce[0..12].*;
                try std.crypto.aead.aes_gcm.Aes128Gcm.decrypt(dst, cipher, tag, "", n, k);
            },
            .aes_256_gcm => {
                const k = self.key[0..32].*;
                const n = self.nonce[0..12].*;
                try std.crypto.aead.aes_gcm.Aes256Gcm.decrypt(dst, cipher, tag, "", n, k);
            },
            .chacha20_ietf_poly1305 => {
                const k = self.key[0..32].*;
                const n = self.nonce[0..12].*;
                try std.crypto.aead.chacha_poly.ChaCha20Poly1305.decrypt(dst, cipher, tag, "", n, k);
            },
            .xchacha20_ietf_poly1305 => {
                const k = self.key[0..32].*;
                const n = self.nonce[0..24].*;
                try std.crypto.aead.chacha_poly.XChaCha20Poly1305.decrypt(dst, cipher, tag, "", n, k);
            },
            else => unreachable,
        }
    }

    fn incrementNonce(self: *AeadCipher) void {
        var i: usize = 0;
        while (i < self.method.nonceLen()) : (i += 1) {
            self.nonce[i] +%= 1;
            if (self.nonce[i] != 0) break;
        }
    }
};

pub const Aead2022StreamType = enum(u8) {
    client = 0,
    server = 1,
};

pub const Aead2022UdpSocketType = enum(u8) {
    client = 0,
    server = 1,
};

pub const Aead2022UdpControl = struct {
    client_session_id: u64 = 0,
    server_session_id: u64 = 0,
    packet_id: u64 = 0,
};

pub const Aead2022UdpPacket = struct {
    control: Aead2022UdpControl,
    timestamp: u64,
    plain: []u8,
};

pub const Aead2022Header = struct {
    stream_type: Aead2022StreamType,
    timestamp: u64,
    request_salt: ?[]const u8,
    data_len: usize,
};

pub const Aead2022TcpCipher = struct {
    pub const key_context = "shadowsocks 2022 session subkey";
    pub const max_packet_size: usize = 0xffff;

    method: CipherKind,
    key: [32]u8,
    nonce: [24]u8 = [_]u8{0} ** 24,

    pub fn init(method: CipherKind, master_key: []const u8, salt: []const u8) CryptoError!Aead2022TcpCipher {
        if (method.category() != .aead2022) return error.UnsupportedCipher;
        if (master_key.len != method.keyLen()) return error.InvalidKeyLength;
        if (salt.len != method.saltLen()) return error.InvalidKeyLength;

        var self = Aead2022TcpCipher{
            .method = method,
            .key = [_]u8{0} ** 32,
        };
        blake3Derive(self.key[0..method.keyLen()], key_context, master_key, salt);
        return self;
    }

    pub fn encryptFirstPayload(
        self: *Aead2022TcpCipher,
        allocator: std.mem.Allocator,
        stream_type: Aead2022StreamType,
        request_salt: ?[]const u8,
        plain: []const u8,
        timestamp: u64,
    ) CryptoError![]u8 {
        const request_salt_len = if (request_salt) |salt| salt.len else 0;
        if (request_salt) |salt| {
            if (salt.len != self.method.saltLen()) return error.InvalidKeyLength;
        }
        if (plain.len > max_packet_size) return error.PacketTooLong;

        const tag_len = self.method.tagLen();
        const header_len = 1 + 8 + request_salt_len + 2;
        const out = try allocator.alloc(u8, header_len + tag_len + plain.len + tag_len);
        errdefer allocator.free(out);

        out[0] = @intFromEnum(stream_type);
        std.mem.writeInt(u64, out[1..9], timestamp, .big);
        var cursor: usize = 9;
        if (request_salt) |salt| {
            @memcpy(out[cursor..][0..salt.len], salt);
            cursor += salt.len;
        }
        std.mem.writeInt(u16, out[cursor..][0..2], @intCast(plain.len), .big);
        try self.encryptDetached(out[0..header_len], out[header_len..][0..tag_len], out[0..header_len]);
        self.incrementNonce();

        const data_off = header_len + tag_len;
        try self.encryptDetached(out[data_off..][0..plain.len], out[data_off + plain.len ..][0..tag_len], plain);
        self.incrementNonce();
        return out;
    }

    pub fn decryptHeader(
        self: *Aead2022TcpCipher,
        allocator: std.mem.Allocator,
        sealed_header: []const u8,
        expect_stream_type: Aead2022StreamType,
        request_salt_len: usize,
    ) CryptoError!Aead2022Header {
        const tag_len = self.method.tagLen();
        const header_plain_len = 1 + 8 + request_salt_len + 2;
        if (sealed_header.len != header_plain_len + tag_len) return error.AuthenticationFailed;

        const plain = try allocator.alloc(u8, header_plain_len);
        defer allocator.free(plain);
        var tag: [16]u8 = undefined;
        @memcpy(&tag, sealed_header[header_plain_len..][0..tag_len]);
        self.decryptDetached(plain, sealed_header[0..header_plain_len], tag) catch return error.AuthenticationFailed;
        self.incrementNonce();

        const stream_type: Aead2022StreamType = switch (plain[0]) {
            0 => .client,
            1 => .server,
            else => return error.AuthenticationFailed,
        };
        if (stream_type != expect_stream_type) return error.AuthenticationFailed;
        const timestamp = std.mem.readInt(u64, plain[1..9], .big);
        const request_salt = if (request_salt_len == 0) null else try allocator.dupe(u8, plain[9..][0..request_salt_len]);
        errdefer if (request_salt) |salt| allocator.free(salt);
        const len_off = 9 + request_salt_len;
        const data_len = std.mem.readInt(u16, plain[len_off..][0..2], .big);
        return .{
            .stream_type = stream_type,
            .timestamp = timestamp,
            .request_salt = request_salt,
            .data_len = data_len,
        };
    }

    pub fn encryptChunk(self: *Aead2022TcpCipher, allocator: std.mem.Allocator, plain: []const u8) CryptoError![]u8 {
        if (plain.len > max_packet_size) return error.PacketTooLong;
        const tag_len = self.method.tagLen();
        const out = try allocator.alloc(u8, 2 + tag_len + plain.len + tag_len);
        errdefer allocator.free(out);

        std.mem.writeInt(u16, out[0..2], @intCast(plain.len), .big);
        try self.encryptDetached(out[0..2], out[2..][0..tag_len], out[0..2]);
        self.incrementNonce();

        const data_off = 2 + tag_len;
        try self.encryptDetached(out[data_off..][0..plain.len], out[data_off + plain.len ..][0..tag_len], plain);
        self.incrementNonce();
        return out;
    }

    pub fn decryptLength(self: *Aead2022TcpCipher, sealed_len: []const u8) CryptoError!usize {
        const tag_len = self.method.tagLen();
        if (sealed_len.len != 2 + tag_len) return error.AuthenticationFailed;
        var len_plain: [2]u8 = undefined;
        var tag: [16]u8 = undefined;
        @memcpy(&tag, sealed_len[2..][0..tag_len]);
        self.decryptDetached(&len_plain, sealed_len[0..2], tag) catch return error.AuthenticationFailed;
        self.incrementNonce();
        return std.mem.readInt(u16, &len_plain, .big);
    }

    pub fn decryptPayload(self: *Aead2022TcpCipher, allocator: std.mem.Allocator, sealed_payload: []const u8, len: usize) CryptoError![]u8 {
        const tag_len = self.method.tagLen();
        if (sealed_payload.len != len + tag_len) return error.AuthenticationFailed;
        const out = try allocator.alloc(u8, len);
        errdefer allocator.free(out);
        var tag: [16]u8 = undefined;
        @memcpy(&tag, sealed_payload[len..][0..tag_len]);
        self.decryptDetached(out, sealed_payload[0..len], tag) catch return error.AuthenticationFailed;
        self.incrementNonce();
        return out;
    }

    fn encryptDetached(self: *Aead2022TcpCipher, dst: []u8, tag: []u8, plain: []const u8) CryptoError!void {
        switch (self.method) {
            .aead2022_blake3_aes_128_gcm => {
                const k = self.key[0..16].*;
                const n = self.nonce[0..12].*;
                std.crypto.aead.aes_gcm.Aes128Gcm.encrypt(dst, tag[0..16], plain, "", n, k);
            },
            .aead2022_blake3_aes_256_gcm => {
                const k = self.key[0..32].*;
                const n = self.nonce[0..12].*;
                std.crypto.aead.aes_gcm.Aes256Gcm.encrypt(dst, tag[0..16], plain, "", n, k);
            },
            .aead2022_blake3_chacha20_poly1305 => {
                const k = self.key[0..32].*;
                const n = self.nonce[0..12].*;
                std.crypto.aead.chacha_poly.ChaCha20Poly1305.encrypt(dst, tag[0..16], plain, "", n, k);
            },
            else => unreachable,
        }
    }

    fn decryptDetached(self: *Aead2022TcpCipher, dst: []u8, cipher: []const u8, tag: [16]u8) !void {
        switch (self.method) {
            .aead2022_blake3_aes_128_gcm => {
                const k = self.key[0..16].*;
                const n = self.nonce[0..12].*;
                try std.crypto.aead.aes_gcm.Aes128Gcm.decrypt(dst, cipher, tag, "", n, k);
            },
            .aead2022_blake3_aes_256_gcm => {
                const k = self.key[0..32].*;
                const n = self.nonce[0..12].*;
                try std.crypto.aead.aes_gcm.Aes256Gcm.decrypt(dst, cipher, tag, "", n, k);
            },
            .aead2022_blake3_chacha20_poly1305 => {
                const k = self.key[0..32].*;
                const n = self.nonce[0..12].*;
                try std.crypto.aead.chacha_poly.ChaCha20Poly1305.decrypt(dst, cipher, tag, "", n, k);
            },
            else => unreachable,
        }
    }

    fn incrementNonce(self: *Aead2022TcpCipher) void {
        var i: usize = 0;
        while (i < self.method.nonceLen()) : (i += 1) {
            self.nonce[i] +%= 1;
            if (self.nonce[i] != 0) break;
        }
    }
};

pub const StreamCipher = struct {
    method: CipherKind,
    key: [32]u8,
    nonce: [16]u8,
    position: u64 = 0,
    cfb_offset: usize = 0,
    cfb_stream: [16]u8 = [_]u8{0} ** 16,
    rc4_state: [256]u8 = undefined,
    rc4_i: u8 = 0,
    rc4_j: u8 = 0,

    pub fn init(method: CipherKind, master_key: []const u8, nonce: []const u8) CryptoError!StreamCipher {
        if (!isImplementedStreamCipher(method)) return error.UnsupportedCipher;
        if (master_key.len != method.keyLen()) return error.InvalidKeyLength;
        if (nonce.len != method.saltLen()) return error.InvalidKeyLength;

        var self = StreamCipher{
            .method = method,
            .key = [_]u8{0} ** 32,
            .nonce = [_]u8{0} ** 16,
        };
        @memcpy(self.key[0..master_key.len], master_key);
        @memcpy(self.nonce[0..nonce.len], nonce);
        if (method == .rc4_md5) self.initRc4Md5(master_key, nonce);
        return self;
    }

    pub fn encrypt(self: *StreamCipher, allocator: std.mem.Allocator, input: []const u8) CryptoError![]u8 {
        const out = try allocator.alloc(u8, input.len);
        errdefer allocator.free(out);
        try self.encryptInto(allocator, out, input);
        return out;
    }

    pub fn decrypt(self: *StreamCipher, allocator: std.mem.Allocator, input: []const u8) CryptoError![]u8 {
        const out = try allocator.alloc(u8, input.len);
        errdefer allocator.free(out);
        try self.decryptInto(allocator, out, input);
        return out;
    }

    fn encryptInto(self: *StreamCipher, allocator: std.mem.Allocator, out: []u8, input: []const u8) CryptoError!void {
        if (isAesCfbCipher(self.method)) {
            self.applyAesCfb(out, input, .encrypt);
            return;
        }
        if (isAesCtrCipher(self.method)) {
            self.applyAesCtr(out, input);
            return;
        }
        if (self.method == .rc4_md5) {
            self.applyRc4(out, input);
            return;
        }
        try self.applyChaCha20Ietf(allocator, out, input);
    }

    fn decryptInto(self: *StreamCipher, allocator: std.mem.Allocator, out: []u8, input: []const u8) CryptoError!void {
        if (isAesCfbCipher(self.method)) {
            self.applyAesCfb(out, input, .decrypt);
            return;
        }
        if (isAesCtrCipher(self.method)) {
            self.applyAesCtr(out, input);
            return;
        }
        if (self.method == .rc4_md5) {
            self.applyRc4(out, input);
            return;
        }
        try self.applyChaCha20Ietf(allocator, out, input);
    }

    fn applyChaCha20Ietf(self: *StreamCipher, allocator: std.mem.Allocator, out: []u8, input: []const u8) CryptoError!void {
        if (out.len != input.len) return error.BufferTooSmall;
        const block_offset: usize = @intCast(self.position % 64);
        const block_counter_u64 = self.position / 64;
        const block_counter = std.math.cast(u32, block_counter_u64) orelse return error.PacketTooLong;
        const key = self.key[0..32].*;
        const nonce = self.nonce[0..12].*;

        if (block_offset == 0) {
            std.crypto.stream.chacha.ChaCha20IETF.xor(out, input, block_counter, key, nonce);
        } else {
            const padded_len = block_offset + input.len;
            const padded_in = try allocator.alloc(u8, padded_len);
            defer allocator.free(padded_in);
            const padded_out = try allocator.alloc(u8, padded_len);
            defer allocator.free(padded_out);
            @memset(padded_in[0..block_offset], 0);
            @memcpy(padded_in[block_offset..], input);
            std.crypto.stream.chacha.ChaCha20IETF.xor(padded_out, padded_in, block_counter, key, nonce);
            @memcpy(out, padded_out[block_offset..]);
        }
        self.position += input.len;
    }

    fn applyAesCtr(self: *StreamCipher, out: []u8, input: []const u8) void {
        std.debug.assert(out.len == input.len);
        const block_offset: usize = @intCast(self.position % 16);
        const block_counter = self.position / 16;
        var counter = self.nonce;
        addAesCtrCounter(&counter, block_counter);

        var index: usize = 0;
        var offset = block_offset;
        while (index < input.len) {
            var stream: [16]u8 = undefined;
            self.encryptAesBlock(&stream, counter);
            while (offset < stream.len and index < input.len) : ({
                offset += 1;
                index += 1;
            }) {
                out[index] = input[index] ^ stream[offset];
            }
            if (offset == stream.len) {
                incrementAesCtrCounter(&counter);
                offset = 0;
            }
        }

        self.position += input.len;
    }

    fn addAesCtrCounter(iv: *[16]u8, blocks: u64) void {
        var carry: u16 = 0;
        var remaining = blocks;
        var i = iv.len;
        while (i > 0) {
            i -= 1;
            const addend: u16 = @as(u16, @intCast(remaining & 0xff)) + carry;
            const sum: u16 = @as(u16, iv[i]) + addend;
            iv[i] = @intCast(sum & 0xff);
            carry = sum >> 8;
            remaining >>= 8;
        }
    }

    fn incrementAesCtrCounter(iv: *[16]u8) void {
        var i = iv.len;
        while (i > 0) {
            i -= 1;
            iv[i] +%= 1;
            if (iv[i] != 0) break;
        }
    }

    const AesCfbOperation = enum {
        encrypt,
        decrypt,
    };

    fn applyAesCfb(self: *StreamCipher, out: []u8, input: []const u8, operation: AesCfbOperation) void {
        std.debug.assert(out.len == input.len);
        for (input, 0..) |byte, i| {
            if (self.cfb_offset == 0) self.encryptAesBlock(&self.cfb_stream, self.nonce);
            const value = byte ^ self.cfb_stream[self.cfb_offset];
            out[i] = value;
            self.nonce[self.cfb_offset] = switch (operation) {
                .encrypt => value,
                .decrypt => byte,
            };
            self.cfb_offset = (self.cfb_offset + 1) % 16;
        }
    }

    fn encryptAesBlock(self: *const StreamCipher, out: *[16]u8, input: [16]u8) void {
        const aes = std.crypto.core.aes;
        switch (self.method) {
            .aes_128_cfb, .aes_128_ctr => {
                const ctx = aes.Aes128.initEnc(self.key[0..16].*);
                ctx.encrypt(out, &input);
            },
            .aes_256_cfb, .aes_256_ctr => {
                const ctx = aes.Aes256.initEnc(self.key[0..32].*);
                ctx.encrypt(out, &input);
            },
            else => unreachable,
        }
    }

    fn initRc4Md5(self: *StreamCipher, master_key: []const u8, nonce: []const u8) void {
        var key_nonce: [32]u8 = undefined;
        @memcpy(key_nonce[0..16], master_key[0..16]);
        @memcpy(key_nonce[16..32], nonce[0..16]);
        var rc4_key: [16]u8 = undefined;
        std.crypto.hash.Md5.hash(&key_nonce, &rc4_key, .{});
        self.initRc4(&rc4_key);
    }

    fn initRc4(self: *StreamCipher, key: []const u8) void {
        for (&self.rc4_state, 0..) |*slot, i| slot.* = @intCast(i);
        self.rc4_i = 0;
        self.rc4_j = 0;

        var j: u8 = 0;
        var i: usize = 0;
        while (i < self.rc4_state.len) : (i += 1) {
            j +%= self.rc4_state[i];
            j +%= key[i % key.len];
            std.mem.swap(u8, &self.rc4_state[i], &self.rc4_state[@as(usize, j)]);
        }
    }

    fn applyRc4(self: *StreamCipher, out: []u8, input: []const u8) void {
        std.debug.assert(out.len == input.len);
        for (input, 0..) |byte, idx| {
            self.rc4_i +%= 1;
            self.rc4_j +%= self.rc4_state[@as(usize, self.rc4_i)];
            std.mem.swap(u8, &self.rc4_state[@as(usize, self.rc4_i)], &self.rc4_state[@as(usize, self.rc4_j)]);
            const key_index = self.rc4_state[@as(usize, self.rc4_i)] +% self.rc4_state[@as(usize, self.rc4_j)];
            out[idx] = byte ^ self.rc4_state[@as(usize, key_index)];
        }
    }
};

pub const TcpCipher = union(enum) {
    stream: StreamCipher,
    aead: AeadCipher,
    aead2022: Aead2022TcpCipher,

    pub fn init(method: CipherKind, master_key: []const u8, salt: []const u8) CryptoError!TcpCipher {
        return switch (method.category()) {
            .stream => .{ .stream = try StreamCipher.init(method, master_key, salt) },
            .aead => .{ .aead = try AeadCipher.init(method, master_key, salt) },
            .aead2022 => .{ .aead2022 = try Aead2022TcpCipher.init(method, master_key, salt) },
            else => error.UnsupportedCipher,
        };
    }

    pub fn kind(self: *const TcpCipher) CipherKind {
        return switch (self.*) {
            .stream => |cipher| cipher.method,
            .aead => |cipher| cipher.method,
            .aead2022 => |cipher| cipher.method,
        };
    }

    pub fn encryptChunk(self: *TcpCipher, allocator: std.mem.Allocator, plain: []const u8) CryptoError![]u8 {
        return switch (self.*) {
            .stream => |*cipher| try cipher.encrypt(allocator, plain),
            .aead => |*cipher| try cipher.encryptChunk(allocator, plain),
            .aead2022 => |*cipher| try cipher.encryptChunk(allocator, plain),
        };
    }

    pub fn decryptLength(self: *TcpCipher, sealed_len: []const u8) CryptoError!usize {
        return switch (self.*) {
            .stream => error.UnsupportedCipher,
            .aead => |*cipher| try cipher.decryptLength(sealed_len),
            .aead2022 => |*cipher| try cipher.decryptLength(sealed_len),
        };
    }

    pub fn decryptPayload(self: *TcpCipher, allocator: std.mem.Allocator, sealed_payload: []const u8, len: usize) CryptoError![]u8 {
        return switch (self.*) {
            .stream => |*cipher| try cipher.decrypt(allocator, sealed_payload[0..len]),
            .aead => |*cipher| try cipher.decryptPayload(allocator, sealed_payload, len),
            .aead2022 => |*cipher| try cipher.decryptPayload(allocator, sealed_payload, len),
        };
    }
};

pub fn encryptUdpPacket(
    allocator: std.mem.Allocator,
    io: std.Io,
    method: CipherKind,
    master_key: []const u8,
    plain: []const u8,
) CryptoError![]u8 {
    if (method.category() == .stream) return encryptStreamUdpPacket(allocator, io, method, master_key, plain);
    if (method.category() != .aead) return error.UnsupportedCipher;
    if (master_key.len != method.keyLen()) return error.InvalidKeyLength;

    const salt_len = method.saltLen();
    const tag_len = method.tagLen();
    const out = try allocator.alloc(u8, salt_len + plain.len + tag_len);
    errdefer allocator.free(out);

    try io.randomSecure(out[0..salt_len]);
    var cipher = try AeadCipher.init(method, master_key, out[0..salt_len]);
    try cipher.encryptDetached(out[salt_len..][0..plain.len], out[salt_len + plain.len ..][0..tag_len], plain);
    return out;
}

pub fn decryptUdpPacket(
    allocator: std.mem.Allocator,
    method: CipherKind,
    master_key: []const u8,
    packet: []const u8,
) CryptoError![]u8 {
    if (method.category() == .stream) return decryptStreamUdpPacket(allocator, method, master_key, packet);
    if (method.category() != .aead) return error.UnsupportedCipher;
    if (master_key.len != method.keyLen()) return error.InvalidKeyLength;

    const salt_len = method.saltLen();
    const tag_len = method.tagLen();
    if (packet.len <= salt_len + tag_len) return error.AuthenticationFailed;

    const cipher_len = packet.len - salt_len - tag_len;
    const out = try allocator.alloc(u8, cipher_len);
    errdefer allocator.free(out);

    var tag: [16]u8 = undefined;
    @memcpy(&tag, packet[salt_len + cipher_len ..][0..tag_len]);
    var cipher = try AeadCipher.init(method, master_key, packet[0..salt_len]);
    cipher.decryptDetached(out, packet[salt_len..][0..cipher_len], tag) catch return error.AuthenticationFailed;
    return out;
}

pub fn encryptAead2022UdpPacket(
    allocator: std.mem.Allocator,
    io: std.Io,
    method: CipherKind,
    master_key: []const u8,
    socket_type: Aead2022UdpSocketType,
    control: Aead2022UdpControl,
    plain: []const u8,
    timestamp: u64,
) CryptoError![]u8 {
    if (method.category() != .aead2022) return error.UnsupportedCipher;
    if (master_key.len != method.keyLen()) return error.InvalidKeyLength;

    const tag_len = method.tagLen();
    const nonce_len = aead2022UdpNonceLen(method);
    const padding_len = try aead2022UdpPaddingLen(io, plain);
    const server_extra: usize = if (socket_type == .server) 8 else 0;
    const body_len = 8 + 8 + 1 + 8 + server_extra + 2 + padding_len + plain.len;
    const out = try allocator.alloc(u8, nonce_len + body_len + tag_len);
    errdefer allocator.free(out);

    if (nonce_len != 0) try io.randomSecure(out[0..nonce_len]);
    const data = out[nonce_len .. nonce_len + body_len];
    std.mem.writeInt(u64, data[0..8], switch (socket_type) {
        .client => control.client_session_id,
        .server => control.server_session_id,
    }, .big);
    std.mem.writeInt(u64, data[8..16], control.packet_id, .big);
    data[16] = @intFromEnum(socket_type);
    std.mem.writeInt(u64, data[17..25], timestamp, .big);
    var cursor: usize = 25;
    if (socket_type == .server) {
        std.mem.writeInt(u64, data[cursor..][0..8], control.client_session_id, .big);
        cursor += 8;
    }
    std.mem.writeInt(u16, data[cursor..][0..2], @intCast(padding_len), .big);
    cursor += 2;
    if (padding_len != 0) {
        try io.randomSecure(data[cursor..][0..padding_len]);
        cursor += padding_len;
    }
    @memcpy(data[cursor..][0..plain.len], plain);

    try aead2022UdpEncryptMessage(method, master_key, out, nonce_len, body_len, tag_len);
    return out;
}

pub fn decryptAead2022UdpPacket(
    allocator: std.mem.Allocator,
    method: CipherKind,
    master_key: []const u8,
    packet: []const u8,
    expect_socket_type: Aead2022UdpSocketType,
) CryptoError!Aead2022UdpPacket {
    if (method.category() != .aead2022) return error.UnsupportedCipher;
    if (master_key.len != method.keyLen()) return error.InvalidKeyLength;

    const tag_len = method.tagLen();
    const nonce_len = aead2022UdpNonceLen(method);
    const min_len = nonce_len + 8 + 8 + 1 + 8 + 2 + tag_len;
    if (packet.len < min_len) return error.AuthenticationFailed;

    const data = try aead2022UdpDecryptMessage(allocator, method, master_key, packet, nonce_len, tag_len);
    errdefer allocator.free(data);

    if (data.len < 8 + 8 + 1 + 8 + 2) return error.AuthenticationFailed;
    const session_id = std.mem.readInt(u64, data[0..8], .big);
    const packet_id = std.mem.readInt(u64, data[8..16], .big);
    const socket_type: Aead2022UdpSocketType = switch (data[16]) {
        0 => .client,
        1 => .server,
        else => return error.AuthenticationFailed,
    };
    if (socket_type != expect_socket_type) return error.AuthenticationFailed;
    const timestamp = std.mem.readInt(u64, data[17..25], .big);

    var control = Aead2022UdpControl{ .packet_id = packet_id };
    var cursor: usize = 25;
    switch (socket_type) {
        .client => control.client_session_id = session_id,
        .server => {
            control.server_session_id = session_id;
            if (data.len < cursor + 8 + 2) return error.AuthenticationFailed;
            control.client_session_id = std.mem.readInt(u64, data[cursor..][0..8], .big);
            cursor += 8;
        },
    }

    const padding_len = std.mem.readInt(u16, data[cursor..][0..2], .big);
    cursor += 2;
    if (data.len < cursor + padding_len) return error.AuthenticationFailed;
    cursor += padding_len;

    const plain = try allocator.dupe(u8, data[cursor..]);
    allocator.free(data);
    return .{ .control = control, .timestamp = timestamp, .plain = plain };
}

pub fn saltFromUdpPacket(method: CipherKind, packet: []const u8) CryptoError![]const u8 {
    const salt_len = method.saltLen();
    if (method.category() == .stream) {
        if (packet.len < salt_len) return error.AuthenticationFailed;
        return packet[0..salt_len];
    }
    if (packet.len <= salt_len + method.tagLen()) return error.AuthenticationFailed;
    return packet[0..salt_len];
}

fn encryptStreamUdpPacket(
    allocator: std.mem.Allocator,
    io: std.Io,
    method: CipherKind,
    master_key: []const u8,
    plain: []const u8,
) CryptoError![]u8 {
    if (!isImplementedStreamCipher(method)) return error.UnsupportedCipher;
    if (master_key.len != method.keyLen()) return error.InvalidKeyLength;
    const nonce_len = method.saltLen();
    const out = try allocator.alloc(u8, nonce_len + plain.len);
    errdefer allocator.free(out);
    try io.randomSecure(out[0..nonce_len]);
    var cipher = try StreamCipher.init(method, master_key, out[0..nonce_len]);
    const encrypted = try cipher.encrypt(allocator, plain);
    defer allocator.free(encrypted);
    @memcpy(out[nonce_len..], encrypted);
    return out;
}

fn decryptStreamUdpPacket(
    allocator: std.mem.Allocator,
    method: CipherKind,
    master_key: []const u8,
    packet: []const u8,
) CryptoError![]u8 {
    if (!isImplementedStreamCipher(method)) return error.UnsupportedCipher;
    if (master_key.len != method.keyLen()) return error.InvalidKeyLength;
    const nonce_len = method.saltLen();
    if (packet.len < nonce_len) return error.AuthenticationFailed;
    var cipher = try StreamCipher.init(method, master_key, packet[0..nonce_len]);
    return try cipher.decrypt(allocator, packet[nonce_len..]);
}

fn aead2022UdpNonceLen(method: CipherKind) usize {
    return switch (method) {
        .aead2022_blake3_aes_128_gcm, .aead2022_blake3_aes_256_gcm => 0,
        .aead2022_blake3_chacha20_poly1305 => 24,
        else => unreachable,
    };
}

fn aead2022UdpPaddingLen(io: std.Io, plain: []const u8) CryptoError!usize {
    if (plain.len != 0) return 0;
    var bytes: [2]u8 = undefined;
    try io.randomSecure(&bytes);
    return std.mem.readInt(u16, &bytes, .big) % 901;
}

fn aead2022UdpDeriveSessionKey(out: []u8, master_key: []const u8, session_id: u64) void {
    var session_bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &session_bytes, session_id, .big);
    blake3Derive(out, Aead2022TcpCipher.key_context, master_key, &session_bytes);
}

fn aead2022UdpEncryptMessage(
    method: CipherKind,
    master_key: []const u8,
    packet: []u8,
    nonce_len: usize,
    body_len: usize,
    tag_len: usize,
) CryptoError!void {
    const data = packet[nonce_len .. nonce_len + body_len];
    const tag = packet[nonce_len + body_len ..][0..tag_len];
    switch (method) {
        .aead2022_blake3_aes_128_gcm, .aead2022_blake3_aes_256_gcm => {
            const session_id = std.mem.readInt(u64, data[0..8], .big);
            var key: [32]u8 = undefined;
            aead2022UdpDeriveSessionKey(key[0..method.keyLen()], master_key, session_id);
            const nonce = data[4..16].*;
            switch (method) {
                .aead2022_blake3_aes_128_gcm => {
                    const k = key[0..16].*;
                    std.crypto.aead.aes_gcm.Aes128Gcm.encrypt(data[16..], tag[0..16], data[16..], "", nonce, k);
                    aesEncryptBlock128(master_key[0..16].*, data[0..16]);
                },
                .aead2022_blake3_aes_256_gcm => {
                    const k = key[0..32].*;
                    std.crypto.aead.aes_gcm.Aes256Gcm.encrypt(data[16..], tag[0..16], data[16..], "", nonce, k);
                    aesEncryptBlock256(master_key[0..32].*, data[0..16]);
                },
                else => unreachable,
            }
        },
        .aead2022_blake3_chacha20_poly1305 => {
            const key = master_key[0..32].*;
            const nonce = packet[0..24].*;
            std.crypto.aead.chacha_poly.XChaCha20Poly1305.encrypt(data, tag[0..16], data, "", nonce, key);
        },
        else => unreachable,
    }
}

fn aead2022UdpDecryptMessage(
    allocator: std.mem.Allocator,
    method: CipherKind,
    master_key: []const u8,
    packet: []const u8,
    nonce_len: usize,
    tag_len: usize,
) CryptoError![]u8 {
    const data_len = packet.len - nonce_len - tag_len;
    const data = try allocator.alloc(u8, data_len);
    errdefer allocator.free(data);
    @memcpy(data, packet[nonce_len..][0..data_len]);
    var tag: [16]u8 = undefined;
    @memcpy(&tag, packet[nonce_len + data_len ..][0..tag_len]);

    switch (method) {
        .aead2022_blake3_aes_128_gcm, .aead2022_blake3_aes_256_gcm => {
            if (data.len < 16) return error.AuthenticationFailed;
            switch (method) {
                .aead2022_blake3_aes_128_gcm => aesDecryptBlock128(master_key[0..16].*, data[0..16]),
                .aead2022_blake3_aes_256_gcm => aesDecryptBlock256(master_key[0..32].*, data[0..16]),
                else => unreachable,
            }
            const session_id = std.mem.readInt(u64, data[0..8], .big);
            var key: [32]u8 = undefined;
            aead2022UdpDeriveSessionKey(key[0..method.keyLen()], master_key, session_id);
            const nonce = data[4..16].*;
            switch (method) {
                .aead2022_blake3_aes_128_gcm => {
                    const k = key[0..16].*;
                    std.crypto.aead.aes_gcm.Aes128Gcm.decrypt(data[16..], data[16..], tag, "", nonce, k) catch return error.AuthenticationFailed;
                },
                .aead2022_blake3_aes_256_gcm => {
                    const k = key[0..32].*;
                    std.crypto.aead.aes_gcm.Aes256Gcm.decrypt(data[16..], data[16..], tag, "", nonce, k) catch return error.AuthenticationFailed;
                },
                else => unreachable,
            }
        },
        .aead2022_blake3_chacha20_poly1305 => {
            const key = master_key[0..32].*;
            const nonce = packet[0..24].*;
            std.crypto.aead.chacha_poly.XChaCha20Poly1305.decrypt(data, data, tag, "", nonce, key) catch return error.AuthenticationFailed;
        },
        else => unreachable,
    }
    return data;
}

fn aesEncryptBlock128(key: [16]u8, block: []u8) void {
    var in: [16]u8 = block[0..16].*;
    var out: [16]u8 = undefined;
    const ctx = std.crypto.core.aes.Aes128.initEnc(key);
    ctx.encrypt(&out, &in);
    @memcpy(block[0..16], &out);
}

fn aesDecryptBlock128(key: [16]u8, block: []u8) void {
    var in: [16]u8 = block[0..16].*;
    var out: [16]u8 = undefined;
    const ctx = std.crypto.core.aes.Aes128.initDec(key);
    ctx.decrypt(&out, &in);
    @memcpy(block[0..16], &out);
}

fn aesEncryptBlock256(key: [32]u8, block: []u8) void {
    var in: [16]u8 = block[0..16].*;
    var out: [16]u8 = undefined;
    const ctx = std.crypto.core.aes.Aes256.initEnc(key);
    ctx.encrypt(&out, &in);
    @memcpy(block[0..16], &out);
}

fn aesDecryptBlock256(key: [32]u8, block: []u8) void {
    var in: [16]u8 = block[0..16].*;
    var out: [16]u8 = undefined;
    const ctx = std.crypto.core.aes.Aes256.initDec(key);
    ctx.decrypt(&out, &in);
    @memcpy(block[0..16], &out);
}

test "cipher names parse rust/libev strings" {
    try std.testing.expectEqual(CipherKind.aes_128_gcm, try CipherKind.parse("aes-128-gcm"));
    try std.testing.expectEqual(CipherKind.chacha20_ietf_poly1305, try CipherKind.parse("chacha20-ietf-poly1305"));
    try std.testing.expectEqual(CipherKind.xchacha20_ietf_poly1305, try CipherKind.parse("xchacha20-ietf-poly1305"));
    try std.testing.expectEqual(CipherKind.aes_256_ctr, try CipherKind.parse("aes-256-ctr"));
    try std.testing.expectEqualStrings("2022-blake3-aes-256-gcm", CipherKind.aead2022_blake3_aes_256_gcm.name());
    try std.testing.expect(CipherKind.aes_128_cfb.isImplemented());
    try std.testing.expect(CipherKind.aes_256_ctr.isImplemented());
    try std.testing.expect(CipherKind.rc4_md5.isImplemented());
    try std.testing.expect(CipherKind.chacha20_ietf.isImplemented());
    try std.testing.expect(CipherKind.xchacha20_ietf_poly1305.isImplemented());
    try std.testing.expectEqual(CipherCategory.aead, CipherKind.xchacha20_ietf_poly1305.category());
    try std.testing.expectEqual(@as(usize, 32), CipherKind.xchacha20_ietf_poly1305.saltLen());
    try std.testing.expectEqual(@as(usize, 24), CipherKind.xchacha20_ietf_poly1305.nonceLen());
    try std.testing.expectEqual(@as(usize, 16), CipherKind.aes_128_ctr.keyLen());
    try std.testing.expectEqual(@as(usize, 16), CipherKind.aes_256_ctr.saltLen());
}

test "EVP_BytesToKey compatible MD5 derivation is deterministic" {
    var key: [32]u8 = undefined;
    deriveKey("password", &key);
    try std.testing.expectEqualSlices(u8, &[_]u8{
        0x5f, 0x4d, 0xcc, 0x3b, 0x5a, 0xa7, 0x65, 0xd6,
        0x1d, 0x83, 0x27, 0xde, 0xb8, 0x82, 0xcf, 0x99,
    }, key[0..16]);
}

test "AEAD-2022 master key decodes base64 password" {
    var aes128: [16]u8 = undefined;
    try deriveMasterKey(.aead2022_blake3_aes_128_gcm, "3L69X4PF2eSL/JSLkoWnXg==", &aes128);
    try std.testing.expectEqualSlices(u8, &[_]u8{
        0xdc, 0xbe, 0xbd, 0x5f, 0x83, 0xc5, 0xd9, 0xe4,
        0x8b, 0xfc, 0x94, 0x8b, 0x92, 0x85, 0xa7, 0x5e,
    }, &aes128);

    var chacha20: [32]u8 = undefined;
    try deriveMasterKey(.aead2022_blake3_chacha20_poly1305, "identity:VUw3mGWIpil2z2DKiyauE2Sp9KyE2ab8dulciawe74o", &chacha20);
    try std.testing.expectEqualSlices(u8, &[_]u8{
        0x55, 0x4c, 0x37, 0x98, 0x65, 0x88, 0xa6, 0x29,
        0x76, 0xcf, 0x60, 0xca, 0x8b, 0x26, 0xae, 0x13,
        0x64, 0xa9, 0xf4, 0xac, 0x84, 0xd9, 0xa6, 0xfc,
        0x76, 0xe9, 0x5c, 0x89, 0xac, 0x1e, 0xef, 0x8a,
    }, &chacha20);
}

test "AEAD chunk encrypt/decrypt round trip" {
    var master: [32]u8 = undefined;
    deriveKey("secret", &master);
    const salt = [_]u8{1} ** 32;

    var enc = try AeadCipher.init(.aes_256_gcm, &master, &salt);
    const packet = try enc.encryptChunk(std.testing.allocator, "hello shadowsocks");
    defer std.testing.allocator.free(packet);

    var dec = try AeadCipher.init(.aes_256_gcm, &master, &salt);
    const plain = try dec.decryptChunk(std.testing.allocator, packet);
    defer std.testing.allocator.free(plain);

    try std.testing.expectEqualStrings("hello shadowsocks", plain);
}

test "XChaCha20-Poly1305 AEAD chunk encrypt/decrypt round trip" {
    var master: [32]u8 = undefined;
    deriveKey("secret", &master);
    const salt = [_]u8{2} ** 32;

    var enc = try AeadCipher.init(.xchacha20_ietf_poly1305, &master, &salt);
    const packet = try enc.encryptChunk(std.testing.allocator, "hello xchacha shadowsocks");
    defer std.testing.allocator.free(packet);

    var dec = try AeadCipher.init(.xchacha20_ietf_poly1305, &master, &salt);
    const plain = try dec.decryptChunk(std.testing.allocator, packet);
    defer std.testing.allocator.free(plain);

    try std.testing.expectEqualStrings("hello xchacha shadowsocks", plain);
}

test "AEAD UDP packet encrypt/decrypt round trip" {
    var master: [32]u8 = undefined;
    deriveKey("secret", &master);

    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const packet = try encryptUdpPacket(std.testing.allocator, io, .aes_256_gcm, &master, "\x03\x0bexample.com\x01\xbbpayload");
    defer std.testing.allocator.free(packet);
    try std.testing.expectEqual(@as(usize, 32 + 1 + 1 + 11 + 2 + 7 + 16), packet.len);

    const plain = try decryptUdpPacket(std.testing.allocator, .aes_256_gcm, &master, packet);
    defer std.testing.allocator.free(plain);
    try std.testing.expectEqualStrings("\x03\x0bexample.com\x01\xbbpayload", plain);
}

test "XChaCha20-Poly1305 AEAD UDP packet encrypt/decrypt round trip" {
    var master: [32]u8 = undefined;
    deriveKey("secret", &master);

    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const packet = try encryptUdpPacket(std.testing.allocator, io, .xchacha20_ietf_poly1305, &master, "\x03\x0bexample.com\x01\xbbpayload");
    defer std.testing.allocator.free(packet);
    try std.testing.expectEqual(@as(usize, 32 + 1 + 1 + 11 + 2 + 7 + 16), packet.len);

    const replay_key = try saltFromUdpPacket(.xchacha20_ietf_poly1305, packet);
    try std.testing.expectEqual(@as(usize, 32), replay_key.len);

    const plain = try decryptUdpPacket(std.testing.allocator, .xchacha20_ietf_poly1305, &master, packet);
    defer std.testing.allocator.free(plain);
    try std.testing.expectEqualStrings("\x03\x0bexample.com\x01\xbbpayload", plain);
}

test "chacha20-ietf stream cipher handles uneven chunk boundaries" {
    var master: [32]u8 = undefined;
    deriveKey("secret", &master);
    const nonce = [_]u8{0x42} ** 12;

    var enc = try StreamCipher.init(.chacha20_ietf, &master, &nonce);
    const first = try enc.encrypt(std.testing.allocator, "hello ");
    defer std.testing.allocator.free(first);
    const second = try enc.encrypt(std.testing.allocator, "shadowsocks");
    defer std.testing.allocator.free(second);

    var sealed = std.ArrayList(u8).empty;
    defer sealed.deinit(std.testing.allocator);
    try sealed.appendSlice(std.testing.allocator, first);
    try sealed.appendSlice(std.testing.allocator, second);

    var dec = try StreamCipher.init(.chacha20_ietf, &master, &nonce);
    const plain_a = try dec.decrypt(std.testing.allocator, sealed.items[0..3]);
    defer std.testing.allocator.free(plain_a);
    const plain_b = try dec.decrypt(std.testing.allocator, sealed.items[3..]);
    defer std.testing.allocator.free(plain_b);

    try std.testing.expectEqualStrings("hel", plain_a);
    try std.testing.expectEqualStrings("lo shadowsocks", plain_b);
}

test "AES-CFB stream cipher matches NIST vectors and uneven chunk boundaries" {
    const cases = [_]struct {
        method: CipherKind,
        key: []const u8,
        iv: [16]u8,
        plain: []const u8,
        cipher: []const u8,
    }{
        .{
            .method = .aes_128_cfb,
            .key = &[_]u8{
                0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
            },
            .iv = [_]u8{
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            },
            .plain = &[_]u8{
                0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
                0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
                0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
                0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
            },
            .cipher = &[_]u8{
                0x3b, 0x3f, 0xd9, 0x2e, 0xb7, 0x2d, 0xad, 0x20,
                0x33, 0x34, 0x49, 0xf8, 0xe8, 0x3c, 0xfb, 0x4a,
                0xc8, 0xa6, 0x45, 0x37, 0xa0, 0xb3, 0xa9, 0x3f,
                0xcd, 0xe3, 0xcd, 0xad, 0x9f, 0x1c, 0xe5, 0x8b,
            },
        },
        .{
            .method = .aes_256_cfb,
            .key = &[_]u8{
                0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
                0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
                0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
                0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,
            },
            .iv = [_]u8{
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            },
            .plain = &[_]u8{
                0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
                0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
                0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
                0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
            },
            .cipher = &[_]u8{
                0xdc, 0x7e, 0x84, 0xbf, 0xda, 0x79, 0x16, 0x4b,
                0x7e, 0xcd, 0x84, 0x86, 0x98, 0x5d, 0x38, 0x60,
                0x39, 0xff, 0xed, 0x14, 0x3b, 0x28, 0xb1, 0xc8,
                0x32, 0x11, 0x3c, 0x63, 0x31, 0xe5, 0x40, 0x7b,
            },
        },
    };

    for (cases) |case| {
        var key: [32]u8 = [_]u8{0} ** 32;
        @memcpy(key[0..case.key.len], case.key);

        var enc = try StreamCipher.init(case.method, key[0..case.method.keyLen()], &case.iv);
        const first = try enc.encrypt(std.testing.allocator, case.plain[0..7]);
        defer std.testing.allocator.free(first);
        const second = try enc.encrypt(std.testing.allocator, case.plain[7..]);
        defer std.testing.allocator.free(second);

        var sealed = std.ArrayList(u8).empty;
        defer sealed.deinit(std.testing.allocator);
        try sealed.appendSlice(std.testing.allocator, first);
        try sealed.appendSlice(std.testing.allocator, second);
        try std.testing.expectEqualSlices(u8, case.cipher, sealed.items);

        var dec = try StreamCipher.init(case.method, key[0..case.method.keyLen()], &case.iv);
        const plain_a = try dec.decrypt(std.testing.allocator, sealed.items[0..13]);
        defer std.testing.allocator.free(plain_a);
        const plain_b = try dec.decrypt(std.testing.allocator, sealed.items[13..]);
        defer std.testing.allocator.free(plain_b);

        var opened = std.ArrayList(u8).empty;
        defer opened.deinit(std.testing.allocator);
        try opened.appendSlice(std.testing.allocator, plain_a);
        try opened.appendSlice(std.testing.allocator, plain_b);
        try std.testing.expectEqualSlices(u8, case.plain, opened.items);
    }
}

test "AES-CTR stream cipher matches NIST vectors and uneven chunk boundaries" {
    const cases = [_]struct {
        method: CipherKind,
        key: []const u8,
        iv: [16]u8,
        plain: []const u8,
        cipher: []const u8,
    }{
        .{
            .method = .aes_128_ctr,
            .key = &[_]u8{
                0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
            },
            .iv = [_]u8{
                0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
                0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
            },
            .plain = &[_]u8{
                0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
                0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
                0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
                0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
            },
            .cipher = &[_]u8{
                0x87, 0x4d, 0x61, 0x91, 0xb6, 0x20, 0xe3, 0x26,
                0x1b, 0xef, 0x68, 0x64, 0x99, 0x0d, 0xb6, 0xce,
                0x98, 0x06, 0xf6, 0x6b, 0x79, 0x70, 0xfd, 0xff,
                0x86, 0x17, 0x18, 0x7b, 0xb9, 0xff, 0xfd, 0xff,
            },
        },
        .{
            .method = .aes_256_ctr,
            .key = &[_]u8{
                0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
                0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
                0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
                0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,
            },
            .iv = [_]u8{
                0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
                0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
            },
            .plain = &[_]u8{
                0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
                0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
                0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
                0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
            },
            .cipher = &[_]u8{
                0x60, 0x1e, 0xc3, 0x13, 0x77, 0x57, 0x89, 0xa5,
                0xb7, 0xa7, 0xf5, 0x04, 0xbb, 0xf3, 0xd2, 0x28,
                0xf4, 0x43, 0xe3, 0xca, 0x4d, 0x62, 0xb5, 0x9a,
                0xca, 0x84, 0xe9, 0x90, 0xca, 0xca, 0xf5, 0xc5,
            },
        },
    };

    for (cases) |case| {
        var key: [32]u8 = [_]u8{0} ** 32;
        @memcpy(key[0..case.key.len], case.key);

        var enc = try StreamCipher.init(case.method, key[0..case.method.keyLen()], &case.iv);
        const first = try enc.encrypt(std.testing.allocator, case.plain[0..5]);
        defer std.testing.allocator.free(first);
        const second = try enc.encrypt(std.testing.allocator, case.plain[5..19]);
        defer std.testing.allocator.free(second);
        const third = try enc.encrypt(std.testing.allocator, case.plain[19..]);
        defer std.testing.allocator.free(third);

        var sealed = std.ArrayList(u8).empty;
        defer sealed.deinit(std.testing.allocator);
        try sealed.appendSlice(std.testing.allocator, first);
        try sealed.appendSlice(std.testing.allocator, second);
        try sealed.appendSlice(std.testing.allocator, third);
        try std.testing.expectEqualSlices(u8, case.cipher, sealed.items);

        var dec = try StreamCipher.init(case.method, key[0..case.method.keyLen()], &case.iv);
        const plain_a = try dec.decrypt(std.testing.allocator, sealed.items[0..11]);
        defer std.testing.allocator.free(plain_a);
        const plain_b = try dec.decrypt(std.testing.allocator, sealed.items[11..]);
        defer std.testing.allocator.free(plain_b);

        var opened = std.ArrayList(u8).empty;
        defer opened.deinit(std.testing.allocator);
        try opened.appendSlice(std.testing.allocator, plain_a);
        try opened.appendSlice(std.testing.allocator, plain_b);
        try std.testing.expectEqualSlices(u8, case.plain, opened.items);
    }
}

test "RC4 core matches public test vector" {
    var cipher = StreamCipher{
        .method = .rc4_md5,
        .key = [_]u8{0} ** 32,
        .nonce = [_]u8{0} ** 16,
    };
    cipher.initRc4("Key");
    var out: [9]u8 = undefined;
    cipher.applyRc4(&out, "Plaintext");
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xbb, 0xf3, 0x16, 0xe8, 0xd9, 0x40, 0xaf, 0x0a, 0xd3 }, &out);
}

test "RC4-MD5 stream cipher handles uneven chunk boundaries" {
    var master: [16]u8 = undefined;
    deriveKey("secret", &master);
    const nonce = [_]u8{0x24} ** 16;

    var enc = try StreamCipher.init(.rc4_md5, &master, &nonce);
    const first = try enc.encrypt(std.testing.allocator, "hello ");
    defer std.testing.allocator.free(first);
    const second = try enc.encrypt(std.testing.allocator, "shadowsocks");
    defer std.testing.allocator.free(second);

    var sealed = std.ArrayList(u8).empty;
    defer sealed.deinit(std.testing.allocator);
    try sealed.appendSlice(std.testing.allocator, first);
    try sealed.appendSlice(std.testing.allocator, second);

    var dec = try StreamCipher.init(.rc4_md5, &master, &nonce);
    const plain_a = try dec.decrypt(std.testing.allocator, sealed.items[0..5]);
    defer std.testing.allocator.free(plain_a);
    const plain_b = try dec.decrypt(std.testing.allocator, sealed.items[5..]);
    defer std.testing.allocator.free(plain_b);

    try std.testing.expectEqualStrings("hello", plain_a);
    try std.testing.expectEqualStrings(" shadowsocks", plain_b);
}

test "chacha20-ietf UDP packet encrypt/decrypt round trip" {
    var master: [32]u8 = undefined;
    deriveKey("secret", &master);

    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const packet = try encryptUdpPacket(std.testing.allocator, io, .chacha20_ietf, &master, "\x03\x0bexample.com\x01\xbbpayload");
    defer std.testing.allocator.free(packet);
    try std.testing.expectEqual(@as(usize, 12 + 1 + 1 + 11 + 2 + 7), packet.len);

    const replay_key = try saltFromUdpPacket(.chacha20_ietf, packet);
    try std.testing.expectEqual(@as(usize, 12), replay_key.len);

    const plain = try decryptUdpPacket(std.testing.allocator, .chacha20_ietf, &master, packet);
    defer std.testing.allocator.free(plain);
    try std.testing.expectEqualStrings("\x03\x0bexample.com\x01\xbbpayload", plain);
}

test "AES-CFB UDP packet encrypt/decrypt round trip" {
    const methods = [_]CipherKind{ .aes_128_cfb, .aes_256_cfb };
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    for (methods) |method| {
        var master: [32]u8 = undefined;
        deriveKey("secret", master[0..method.keyLen()]);

        const packet = try encryptUdpPacket(std.testing.allocator, io, method, master[0..method.keyLen()], "\x03\x0bexample.com\x01\xbbpayload");
        defer std.testing.allocator.free(packet);
        try std.testing.expectEqual(@as(usize, method.saltLen() + 1 + 1 + 11 + 2 + 7), packet.len);

        const replay_key = try saltFromUdpPacket(method, packet);
        try std.testing.expectEqual(@as(usize, 16), replay_key.len);

        const plain = try decryptUdpPacket(std.testing.allocator, method, master[0..method.keyLen()], packet);
        defer std.testing.allocator.free(plain);
        try std.testing.expectEqualStrings("\x03\x0bexample.com\x01\xbbpayload", plain);
    }
}

test "AES-CTR UDP packet encrypt/decrypt round trip" {
    const methods = [_]CipherKind{ .aes_128_ctr, .aes_256_ctr };
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    for (methods) |method| {
        var master: [32]u8 = undefined;
        deriveKey("secret", master[0..method.keyLen()]);

        const packet = try encryptUdpPacket(std.testing.allocator, io, method, master[0..method.keyLen()], "\x03\x0bexample.com\x01\xbbpayload");
        defer std.testing.allocator.free(packet);
        try std.testing.expectEqual(@as(usize, method.saltLen() + 1 + 1 + 11 + 2 + 7), packet.len);

        const replay_key = try saltFromUdpPacket(method, packet);
        try std.testing.expectEqual(@as(usize, 16), replay_key.len);

        const plain = try decryptUdpPacket(std.testing.allocator, method, master[0..method.keyLen()], packet);
        defer std.testing.allocator.free(plain);
        try std.testing.expectEqualStrings("\x03\x0bexample.com\x01\xbbpayload", plain);
    }
}

test "RC4-MD5 UDP packet encrypt/decrypt round trip" {
    var master: [16]u8 = undefined;
    deriveKey("secret", &master);

    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const packet = try encryptUdpPacket(std.testing.allocator, io, .rc4_md5, &master, "\x03\x0bexample.com\x01\xbbpayload");
    defer std.testing.allocator.free(packet);
    try std.testing.expectEqual(@as(usize, 16 + 1 + 1 + 11 + 2 + 7), packet.len);

    const replay_key = try saltFromUdpPacket(.rc4_md5, packet);
    try std.testing.expectEqual(@as(usize, 16), replay_key.len);

    const plain = try decryptUdpPacket(std.testing.allocator, .rc4_md5, &master, packet);
    defer std.testing.allocator.free(plain);
    try std.testing.expectEqualStrings("\x03\x0bexample.com\x01\xbbpayload", plain);
}

test "AEAD-2022 UDP packets round trip" {
    const methods = [_]CipherKind{
        .aead2022_blake3_aes_128_gcm,
        .aead2022_blake3_aes_256_gcm,
        .aead2022_blake3_chacha20_poly1305,
    };

    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    for (methods) |method| {
        var master: [32]u8 = undefined;
        @memset(&master, 0x44);
        const key = master[0..method.keyLen()];

        const client_control = Aead2022UdpControl{ .client_session_id = 0x0102030405060708, .packet_id = 1 };
        const client_packet = try encryptAead2022UdpPacket(
            std.testing.allocator,
            io,
            method,
            key,
            .client,
            client_control,
            "\x03\x0bexample.com\x01\xbbpayload",
            1_700_000_000,
        );
        defer std.testing.allocator.free(client_packet);

        const decoded_client = try decryptAead2022UdpPacket(std.testing.allocator, method, key, client_packet, .client);
        defer std.testing.allocator.free(decoded_client.plain);
        try std.testing.expectEqual(client_control.client_session_id, decoded_client.control.client_session_id);
        try std.testing.expectEqual(client_control.packet_id, decoded_client.control.packet_id);
        try std.testing.expectEqual(@as(u64, 1_700_000_000), decoded_client.timestamp);
        try std.testing.expectEqualStrings("\x03\x0bexample.com\x01\xbbpayload", decoded_client.plain);

        const server_control = Aead2022UdpControl{
            .client_session_id = decoded_client.control.client_session_id,
            .server_session_id = 0x1112131415161718,
            .packet_id = 7,
        };
        const server_packet = try encryptAead2022UdpPacket(
            std.testing.allocator,
            io,
            method,
            key,
            .server,
            server_control,
            "\x01\x7f\x00\x00\x01\x23\x45response",
            1_700_000_001,
        );
        defer std.testing.allocator.free(server_packet);

        const decoded_server = try decryptAead2022UdpPacket(std.testing.allocator, method, key, server_packet, .server);
        defer std.testing.allocator.free(decoded_server.plain);
        try std.testing.expectEqual(server_control.client_session_id, decoded_server.control.client_session_id);
        try std.testing.expectEqual(server_control.server_session_id, decoded_server.control.server_session_id);
        try std.testing.expectEqual(server_control.packet_id, decoded_server.control.packet_id);
        try std.testing.expectEqual(@as(u64, 1_700_000_001), decoded_server.timestamp);
        try std.testing.expectEqualStrings("\x01\x7f\x00\x00\x01\x23\x45response", decoded_server.plain);
    }
}

test "AEAD-2022 TCP first payload and chunks round trip" {
    const methods = [_]CipherKind{
        .aead2022_blake3_aes_128_gcm,
        .aead2022_blake3_aes_256_gcm,
        .aead2022_blake3_chacha20_poly1305,
    };
    for (methods) |method| {
        var master: [32]u8 = undefined;
        @memset(&master, 0x11);
        const salt = [_]u8{0x22} ** 32;
        const request_salt = [_]u8{0x33} ** 32;

        var enc = try Aead2022TcpCipher.init(method, master[0..method.keyLen()], salt[0..method.saltLen()]);
        const first = try enc.encryptFirstPayload(
            std.testing.allocator,
            .server,
            request_salt[0..method.saltLen()],
            "first response",
            1_700_000_000,
        );
        defer std.testing.allocator.free(first);

        var dec = try Aead2022TcpCipher.init(method, master[0..method.keyLen()], salt[0..method.saltLen()]);
        const header_len = 1 + 8 + method.saltLen() + 2 + method.tagLen();
        const header = try dec.decryptHeader(
            std.testing.allocator,
            first[0..header_len],
            .server,
            method.saltLen(),
        );
        defer if (header.request_salt) |value| std.testing.allocator.free(value);
        try std.testing.expectEqual(Aead2022StreamType.server, header.stream_type);
        try std.testing.expectEqual(@as(u64, 1_700_000_000), header.timestamp);
        try std.testing.expectEqual(@as(usize, "first response".len), header.data_len);
        try std.testing.expectEqualSlices(u8, request_salt[0..method.saltLen()], header.request_salt.?);

        const payload = try dec.decryptPayload(
            std.testing.allocator,
            first[header_len..],
            header.data_len,
        );
        defer std.testing.allocator.free(payload);
        try std.testing.expectEqualStrings("first response", payload);

        const chunk = try enc.encryptChunk(std.testing.allocator, "next");
        defer std.testing.allocator.free(chunk);
        const len = try dec.decryptLength(chunk[0 .. 2 + method.tagLen()]);
        const next = try dec.decryptPayload(std.testing.allocator, chunk[2 + method.tagLen() ..], len);
        defer std.testing.allocator.free(next);
        try std.testing.expectEqualStrings("next", next);
    }
}
