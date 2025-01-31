const std = @import("std");

const CLRF = "\r\n";
const COLON_SPACE = ": ";
const HTTP_STR = "HTTP";

/// Errors that can occur when deserialising data to `Message`
const DeserialiseError = error{
    EmptyRequestLine,
    InvalidProtocolVersion,
    InvalidRequestLine,
    InvalidRequestTarget,
    MalformedProtocol,
    MissingLineDelimiter,
    UnrecognisedMethod,
    UnsupportedProtocolVersion,
};

/// HTTP message
pub const Message = struct {
    version: Version,
    method: Method,
    request_target: RequestTarget,
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
            .POST => "POST",
        };
        const request_target = self.request_target.data();
        const request_target_len = self.request_target.len();
        const request_line_len = method.len + 1 + request_target_len + 1 + HTTP_STR.len + 1 + version.len + CLRF.len;
        var headers_len: usize = 0;
        for (self.headers) |header| {
            headers_len += header.name.len + COLON_SPACE.len + header.value.len + CLRF.len;
        }
        var msg_len = request_line_len + headers_len + self.body.len;
        if (self.body.len > 0) {
            // Account for newline character that needs to be inserted between headers and body
            msg_len += 1;
        }
        const slc = try allocator.alloc(u8, msg_len);

        @memcpy(slc[0..method.len], method);
        slc[method.len] = ' ';
        @memcpy(slc[method.len + 1 .. method.len + 1 + request_target_len], request_target);
        slc[method.len + 1 + request_target_len] = ' ';
        @memcpy(
            slc[method.len + 1 + request_target_len + 1 .. method.len + 1 + request_target_len + 1 + HTTP_STR.len],
            HTTP_STR,
        );
        slc[method.len + 1 + request_target_len + 1 + HTTP_STR.len] = '/';
        @memcpy(
            slc[method.len + 1 + request_target_len + 1 + HTTP_STR.len + 1 .. method.len + 1 + request_target_len + 1 + HTTP_STR.len + 1 + version.len],
            version,
        );
        @memcpy(
            slc[method.len + 1 + request_target_len + 1 + HTTP_STR.len + 1 + version.len .. method.len + 1 + request_target_len + 1 + HTTP_STR.len + 1 + version.len + CLRF.len],
            CLRF,
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
                COLON_SPACE,
            );
            @memcpy(
                slc[headers_start + line_start + header.name.len + COLON_SPACE.len .. headers_start + line_start + header.name.len + COLON_SPACE.len + header.value.len],
                header.value,
            );
            @memcpy(
                slc[headers_start + line_start + header.name.len + COLON_SPACE.len + header.value.len .. headers_start + line_start + header.name.len + COLON_SPACE.len + header.value.len + CLRF.len],
                CLRF,
            );
            const len = header.name.len + COLON_SPACE.len + header.value.len + CLRF.len;
            line_start += len;
        }

        if (self.body.len > 0) {
            slc[headers_start + line_start] = '\n';
            @memcpy(slc[headers_start + line_start + 1 ..], self.body);
        }

        return slc;
    }

    /// Deserialise data from `reader` into `Message`
    pub fn deserialise(allocator: std.mem.Allocator, reader: std.io.AnyReader) (DeserialiseError || anyerror)!Message {
        const request_line = try reader.readUntilDelimiterOrEofAlloc(allocator, '\n', 100) orelse return DeserialiseError.EmptyRequestLine;
        defer allocator.free(request_line);
        try validate_request_line(request_line);
        std.debug.panic("TODO", .{});
    }

    fn validate_request_line(data: []const u8) DeserialiseError!void {
        var len: usize = 0;
        var iter = std.mem.splitSequence(u8, data, " ");
        while (iter.next()) |_| {
            len += 1;
        }
        if (len != 3) return DeserialiseError.InvalidRequestLine;

        iter.reset();
        if (data[data.len - 1] != '\r') return DeserialiseError.MissingLineDelimiter;
        const method_str = iter.next().?;
        _ = try Method.deserialise(method_str);

        const request_target = iter.next().?;
        _ = try Message.parse_request_target(request_target);

        const protocol_str = iter.next().?;
        _ = try Message.parse_protocol(protocol_str);
        std.debug.panic("TODO", .{});
    }

    fn parse_request_target(str: []const u8) DeserialiseError!RequestTarget {
        if (str[0] != '/') return DeserialiseError.InvalidRequestTarget;
        return RequestTarget{ .OriginForm = str };
    }

    fn parse_protocol(str: []const u8) DeserialiseError!Version {
        var iter = std.mem.splitSequence(u8, str, "/");
        var len: usize = 0;
        while (iter.next()) |_| {
            len += 1;
        }
        if (len != 2) return DeserialiseError.MalformedProtocol;

        iter.reset();
        // Unwrapping is safe here because execution reaching here means that the length must
        // be 2 (and thus the very first element isn't `null`)
        const first = iter.next().?;
        if (!std.mem.eql(u8, first, "HTTP")) return DeserialiseError.MalformedProtocol;

        // If execution reaches here, the second element can't be `null` either
        const second = iter.next().?;
        if (std.mem.eql(u8, second[0 .. second.len - 1], "1.0")) {
            std.debug.panic("TODO", .{});
        } else if (std.mem.eql(u8, second[0 .. second.len - 1], "1.1")) {
            std.debug.panic("TODO", .{});
        } else if (std.mem.eql(u8, second[0 .. second.len - 1], "2.0")) {
            return DeserialiseError.UnsupportedProtocolVersion;
        } else {
            return DeserialiseError.InvalidProtocolVersion;
        }
        std.debug.panic("TODO", .{});
    }
};

/// HTTP method
const Method = enum {
    GET,
    POST,

    fn deserialise(str: []const u8) DeserialiseError!Method {
        if (std.mem.eql(u8, str, "GET")) {
            return Method.GET;
        } else if (std.mem.eql(u8, str, "POST")) {
            return Method.POST;
        } else {
            return DeserialiseError.UnrecognisedMethod;
        }
    }
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

/// Request target
///
/// See the following link for more information on the possible values:
/// https://developer.mozilla.org/en-US/docs/Web/HTTP/Messages#request_targets
const RequestTarget = union(enum) {
    OriginForm: []const u8,

    fn data(self: RequestTarget) []const u8 {
        switch (self) {
            .OriginForm => |val| return val,
        }
    }

    fn len(self: RequestTarget) usize {
        switch (self) {
            .OriginForm => |val| return val.len,
        }
    }
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
        .request_target = RequestTarget{ .OriginForm = uri },
        .headers = headers[0..],
        .body = body,
    };
    const REQUEST_LINE_LEN = 23;
    const HEADER_LINES_LEN = 56;
    var expected_data: [79]u8 = undefined;
    var header_lines: [HEADER_LINES_LEN]u8 = undefined;
    @memcpy(expected_data[0..4], "GET" ++ " ");
    @memcpy(expected_data[4 .. 4 + uri.len + 1], uri ++ " ");
    @memcpy(expected_data[4 + uri.len + 1 .. 4 + uri.len + 1 + 10], "HTTP/1.1" ++ CLRF);

    var start: usize = 0;
    for (headers) |header| {
        const len = header.name.len + COLON_SPACE.len + header.value.len + CLRF.len;
        var line = try allocator.alloc(u8, len);
        defer allocator.free(line);
        @memcpy(line[0..header.name.len], header.name);
        @memcpy(line[header.name.len .. header.name.len + COLON_SPACE.len], COLON_SPACE);
        @memcpy(
            line[header.name.len + COLON_SPACE.len .. header.name.len + COLON_SPACE.len + header.value.len],
            header.value,
        );
        @memcpy(line[header.name.len + COLON_SPACE.len + header.value.len ..], CLRF);
        @memcpy(header_lines[start .. start + line.len], line);
        start += line.len;
    }
    @memcpy(expected_data[REQUEST_LINE_LEN..], &header_lines);

    const data = try msg.serialise(allocator);
    defer allocator.free(data);
    try std.testing.expectEqualSlices(u8, expected_data[0..], data);
}

test "serialise POST request message with non-empty body" {
    const allocator = std.testing.allocator;
    const version = Version.V1_1;
    const method = Method.POST;
    const uri = "/users";
    const headers = [3]Header{
        Header{ .name = "Host", .value = "example.com" },
        Header{ .name = "Content-Type", .value = "application/x-www-form-urlencoded" },
        Header{ .name = "Content-Length", .value = "50" },
    };
    const body = "name=FirstName%20LastName&email=bsmth%40example.com";
    const msg = Message{
        .version = version,
        .method = method,
        .request_target = RequestTarget{ .OriginForm = uri },
        .headers = headers[0..],
        .body = body,
    };
    const REQUEST_LINE_LEN = 22;
    const HEADER_LINES_LEN = 88;
    var expected_data: [REQUEST_LINE_LEN + HEADER_LINES_LEN + 1 + body.len]u8 = undefined;
    var header_lines: [HEADER_LINES_LEN]u8 = undefined;
    @memcpy(expected_data[0..5], "POST" ++ " ");
    @memcpy(expected_data[5 .. 5 + uri.len + 1], uri ++ " ");
    @memcpy(expected_data[5 + uri.len + 1 .. 5 + uri.len + 1 + 10], "HTTP/1.1" ++ CLRF);

    var start: usize = 0;
    for (headers) |header| {
        const len = header.name.len + COLON_SPACE.len + header.value.len + CLRF.len;
        var line = try allocator.alloc(u8, len);
        defer allocator.free(line);
        @memcpy(line[0..header.name.len], header.name);
        @memcpy(line[header.name.len .. header.name.len + COLON_SPACE.len], COLON_SPACE);
        @memcpy(
            line[header.name.len + COLON_SPACE.len .. header.name.len + COLON_SPACE.len + header.value.len],
            header.value,
        );
        @memcpy(line[header.name.len + COLON_SPACE.len + header.value.len ..], CLRF);
        @memcpy(header_lines[start .. start + line.len], line);
        start += line.len;
    }
    @memcpy(expected_data[REQUEST_LINE_LEN .. REQUEST_LINE_LEN + HEADER_LINES_LEN], &header_lines);
    expected_data[REQUEST_LINE_LEN + HEADER_LINES_LEN] = '\n';
    @memcpy(expected_data[REQUEST_LINE_LEN + HEADER_LINES_LEN + 1 ..], body);

    const data = try msg.serialise(allocator);
    defer allocator.free(data);
    try std.testing.expectEqualSlices(u8, expected_data[0..], data);
}

test "return error if request line is empty" {
    const allocator = std.testing.allocator;
    const data = "";
    var stream = std.io.fixedBufferStream(data);
    const reader = stream.reader().any();
    const ret = Message.deserialise(allocator, reader);
    try std.testing.expectError(DeserialiseError.EmptyRequestLine, ret);
}

test "return error if request line contains less than three values" {
    const allocator = std.testing.allocator;
    const data = "GET /users\r\n";
    var stream = std.io.fixedBufferStream(data);
    const reader = stream.reader().any();
    const ret = Message.deserialise(allocator, reader);
    try std.testing.expectError(DeserialiseError.InvalidRequestLine, ret);
}

test "return error if request line contains more than three values" {
    const allocator = std.testing.allocator;
    const data = "GET /users HTTP/1.1 Foo\r\n";
    var stream = std.io.fixedBufferStream(data);
    const reader = stream.reader().any();
    const ret = Message.deserialise(allocator, reader);
    try std.testing.expectError(DeserialiseError.InvalidRequestLine, ret);
}

test "return error if request line doens't end with CRLF" {
    const allocator = std.testing.allocator;
    const data = "GET /users HTTP/1.1";
    var stream = std.io.fixedBufferStream(data);
    const reader = stream.reader().any();
    const ret = Message.deserialise(allocator, reader);
    try std.testing.expectError(DeserialiseError.MissingLineDelimiter, ret);
}

test "return error if unrecognised method" {
    const allocator = std.testing.allocator;
    const data = "FOO /users HTTP/1.1\r\n";
    var stream = std.io.fixedBufferStream(data);
    const reader = stream.reader().any();
    const ret = Message.deserialise(allocator, reader);
    try std.testing.expectError(DeserialiseError.UnrecognisedMethod, ret);
}

test "return error if request target isn't in 'origin form'" {
    const allocator = std.testing.allocator;
    const data = "GET users HTTP/1.1\r\n";
    var stream = std.io.fixedBufferStream(data);
    const reader = stream.reader().any();
    const ret = Message.deserialise(allocator, reader);
    try std.testing.expectError(DeserialiseError.InvalidRequestTarget, ret);
}

test "return error if missing '/' separator in protocol part of request line" {
    const allocator = std.testing.allocator;
    const data = "GET /users HTTP-1.1\r\n";
    var stream = std.io.fixedBufferStream(data);
    const reader = stream.reader().any();
    const ret = Message.deserialise(allocator, reader);
    try std.testing.expectError(DeserialiseError.MalformedProtocol, ret);
}

test "return error if 'HTTP' not in protocol part of request line" {
    const allocator = std.testing.allocator;
    const data = "GET /users HTTQ/1.1\r\n";
    var stream = std.io.fixedBufferStream(data);
    const reader = stream.reader().any();
    const ret = Message.deserialise(allocator, reader);
    try std.testing.expectError(DeserialiseError.MalformedProtocol, ret);
}

test "return error if invalid HTTP protocol version in request line" {
    const allocator = std.testing.allocator;
    const data = "GET /users HTTP/1.2\r\n";
    var stream = std.io.fixedBufferStream(data);
    const reader = stream.reader().any();
    const ret = Message.deserialise(allocator, reader);
    try std.testing.expectError(DeserialiseError.InvalidProtocolVersion, ret);
}

test "return error if unsupported HTTP protocol version in request line" {
    const allocator = std.testing.allocator;
    const data = "GET /users HTTP/2.0\r\n";
    var stream = std.io.fixedBufferStream(data);
    const reader = stream.reader().any();
    const ret = Message.deserialise(allocator, reader);
    try std.testing.expectError(DeserialiseError.UnsupportedProtocolVersion, ret);
}
