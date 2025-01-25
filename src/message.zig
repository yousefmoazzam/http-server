/// HTTP message
pub const Message = struct {
    version: Version,
    method: Method,
    uri: []u8,
    headers: []u8,
    body: []u8,
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
