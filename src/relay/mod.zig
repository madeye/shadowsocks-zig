pub const fake_dns = @import("fake_dns.zig");
pub const tcp = @import("tcp.zig");
pub const traffic = @import("traffic.zig");
pub const tun = @import("tun.zig");
pub const udp = @import("udp.zig");

test {
    _ = fake_dns;
    _ = tcp;
    _ = traffic;
    _ = tun;
    _ = udp;
}
