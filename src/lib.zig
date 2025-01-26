const testing = @import("std").testing;

pub const message = @import("message.zig");

test {
    testing.refAllDecls(@This());
}
