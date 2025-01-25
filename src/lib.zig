const testing = @import("std").testing;

test {
    testing.refAllDecls(@This());
}
