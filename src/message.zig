const std = @import("std");

const CLRF = "\r\n";
const COLON_SPACE = ": ";
const HTTP_STR = "HTTP";

/// HTTP message
pub const Message = struct {
    version: Version,
    method: Method,
    uri: []const u8,
    headers: []const Header,
    body: []const u8,

    /// Serialise HTTP message
    pub fn serialise(self: Message, allocator: std.mem.Allocator) std.mem.Allocator.Error![]u8 {
        const version = switch (self.version) {
            .V1_1 => "1.1",
            else => undefined,
        };
        const method = switch (self.method) {
            .GET => "GET",
        };
        const request_line_len = method.len + 1 + self.uri.len + 1 + HTTP_STR.len + 1 + version.len + CLRF.len;
        var headers_len: usize = 0;
        for (self.headers) |header| {
            headers_len += header.name.len + COLON_SPACE.len + header.value.len + CLRF.len;
        }
        const slc = try allocator.alloc(u8, request_line_len + headers_len + self.body.len);

        @memcpy(slc[0..method.len], method[0..]);
        slc[method.len] = ' ';
        @memcpy(slc[method.len + 1 .. method.len + 1 + self.uri.len], self.uri);
        slc[method.len + 1 + self.uri.len] = ' ';
        @memcpy(
            slc[method.len + 1 + self.uri.len + 1 .. method.len + 1 + self.uri.len + 1 + HTTP_STR.len],
            HTTP_STR[0..],
        );
        slc[method.len + 1 + self.uri.len + 1 + HTTP_STR.len] = '/';
        @memcpy(
            slc[method.len + 1 + self.uri.len + 1 + HTTP_STR.len + 1 .. method.len + 1 + self.uri.len + 1 + HTTP_STR.len + 1 + version.len],
            version[0..],
        );
        @memcpy(
            slc[method.len + 1 + self.uri.len + 1 + HTTP_STR.len + 1 + version.len .. method.len + 1 + self.uri.len + 1 + HTTP_STR.len + 1 + version.len + CLRF.len],
            CLRF[0..],
        );

        const headers_start = request_line_len;
        var line_start: usize = 0;
        for (self.headers) |header| {
            @memcpy(
                slc[headers_start + line_start .. headers_start + line_start + header.name.len],
                header.name,
            );
            @memcpy(
                slc[headers_start + line_start + header.name.len .. headers_start + line_start + header.name.len + COLON_SPACE.len],
                COLON_SPACE[0..],
            );
            @memcpy(
                slc[headers_start + line_start + header.name.len + COLON_SPACE.len .. headers_start + line_start + header.name.len + COLON_SPACE.len + header.value.len],
                header.value,
            );
            @memcpy(
                slc[headers_start + line_start + header.name.len + COLON_SPACE.len + header.value.len .. headers_start + line_start + header.name.len + COLON_SPACE.len + header.value.len + CLRF.len],
                CLRF[0..],
            );
            const len = header.name.len + COLON_SPACE.len + header.value.len + CLRF.len;
            line_start += len;
        }

        return slc;
    }
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

test "serialise GET request message" {
    const allocator = std.testing.allocator;
    const version = Version.V1_1;
    const method = Method.GET;
    const uri = "/contact";
    const headers = [3]Header{
        Header{ .name = "Host", .value = "example.com" },
        Header{ .name = "User-Agent", .value = "curl/8.6.0" },
        Header{ .name = "Accept", .value = "*/*" },
    };
    const body = "";
    const msg = Message{
        .version = version,
        .method = method,
        .uri = uri,
        .headers = headers[0..],
        .body = body,
    };
    const REQUEST_LINE_LEN = 23;
    const HEADER_LINES_LEN = 56;
    var expected_data: [79]u8 = undefined;
    var request_line: [REQUEST_LINE_LEN]u8 = undefined;
    var header_lines: [HEADER_LINES_LEN]u8 = undefined;
    @memcpy(request_line[0..4], ("GET" ++ " ")[0..]);
    @memcpy(request_line[4 .. 4 + uri.len + 1], (uri ++ " ")[0..]);
    @memcpy(request_line[4 + uri.len + 1 .. 4 + uri.len + 1 + 10], ("HTTP/1.1" ++ CLRF)[0..]);
    @memcpy(expected_data[0..request_line.len], &request_line);

    var start: usize = 0;
    for (headers) |header| {
        const len = header.name.len + COLON_SPACE.len + header.value.len + CLRF.len;
        var line = try allocator.alloc(u8, len);
        defer allocator.free(line);
        @memcpy(line[0..header.name.len], header.name);
        @memcpy(line[header.name.len .. header.name.len + COLON_SPACE.len], COLON_SPACE[0..]);
        @memcpy(
            line[header.name.len + COLON_SPACE.len .. header.name.len + COLON_SPACE.len + header.value.len],
            header.value,
        );
        @memcpy(line[header.name.len + COLON_SPACE.len + header.value.len ..], CLRF[0..]);
        @memcpy(header_lines[start .. start + line.len], line);
        start += line.len;
    }
    @memcpy(expected_data[REQUEST_LINE_LEN..], header_lines[0..]);

    const data = try msg.serialise(allocator);
    defer allocator.free(data);
    try std.testing.expectEqualSlices(u8, expected_data[0..], data);
}
