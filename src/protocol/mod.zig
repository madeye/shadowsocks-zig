pub const address = @import("address.zig");
pub const dns = @import("dns.zig");
pub const http = @import("http.zig");
pub const socks4 = @import("socks4.zig");
pub const socks5 = @import("socks5.zig");

test {
    _ = address;
    _ = dns;
    _ = http;
    _ = socks4;
    _ = socks5;
}
