/// HTTP message
pub const Message = struct {
    version: Version,
    method: Method,
    uri: []const u8,
    headers: []const Header,
    body: []const u8,
};

/// HTTP method
const Method = enum {
    GET,
};

/// HTTP protocol version
const Version = enum {
    V1_0,
    V1_1,
    V2_0,
};

/// HTTP header
const Header = struct {
    name: []const u8,
    value: []const u8,
};
