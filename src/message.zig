const std = @import("std");

const CLRF = "\r\n";
const COLON_SPACE = ": ";
const HTTP_STR = "HTTP";

/// Errors that can occur when deserialising data to `Message`
const DeserialiseError = error{
    InvalidProtocolVersion,
    InvalidRequestLine,
    InvalidRequestTarget,
    MalformedProtocol,
    MalformedHeader,
    MissingLineDelimiter,
    UnexpectedEof,
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

    allocator: std.mem.Allocator,

    pub fn init(
        allocator: std.mem.Allocator,
        version: Version,
        method: Method,
        request_target: RequestTarget,
        headers: []const Header,
        body: []const u8,
    ) Message {
        return Message{
            .allocator = allocator,
            .version = version,
            .method = method,
            .request_target = request_target,
            .headers = headers,
            .body = body,
        };
    }

    pub fn deinit(self: Message) void {
        self.request_target.free(self.allocator);
        for (self.headers) |header| header.deinit(self.allocator);
        self.allocator.free(self.headers);
        self.allocator.free(self.body);
    }

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

    fn get_line(
        allocator: std.mem.Allocator,
        reader: std.io.AnyReader,
    ) DeserialiseError![]const u8 {
        const line = reader.readUntilDelimiterAlloc(allocator, '\r', 100) catch |err| switch (err) {
            anyerror.EndOfStream => return DeserialiseError.UnexpectedEof,
            else => std.debug.panic("TODO", .{}),
        };
        errdefer allocator.free(line);
        const char = reader.readByte() catch return DeserialiseError.UnexpectedEof;
        if (char != '\n') return DeserialiseError.MissingLineDelimiter;
        return line;
    }

    /// Deserialise data from `reader` into `Message`
    pub fn deserialise(
        allocator: std.mem.Allocator,
        reader: std.io.AnyReader,
    ) (DeserialiseError || anyerror)!*Message {
        const request_line = try Message.get_line(allocator, reader);
        defer allocator.free(request_line);
        const message = try validate_request_line(allocator, request_line);
        errdefer {
            message.*.request_target.free(allocator);
            allocator.destroy(message);
        }

        if (try parse_headers(allocator, reader)) |headers| {
            message.*.headers = headers;
        } else {
            message.*.headers = try allocator.alloc(Header, 0);
        }
        message.*.body = try allocator.alloc(u8, 0);

        return message;
    }

    fn validate_request_line(
        allocator: std.mem.Allocator,
        data: []const u8,
    ) (DeserialiseError || std.mem.Allocator.Error)!*Message {
        var len: usize = 0;
        var iter = std.mem.splitSequence(u8, data, " ");
        while (iter.next()) |_| {
            len += 1;
        }
        if (len != 3) return DeserialiseError.InvalidRequestLine;

        iter.reset();
        const method_str = iter.next().?;
        const method = try Method.deserialise(method_str);

        const request_target_str = iter.next().?;
        const request_target = try RequestTarget.deserialise(allocator, request_target_str);
        errdefer request_target.free(allocator);

        const protocol_str = iter.next().?;
        const protocol = try Version.deserialise(protocol_str);

        const message = try allocator.create(Message);
        message.* = Message{
            .allocator = allocator,
            .version = protocol,
            .method = method,
            .request_target = request_target,
            .headers = undefined,
            .body = undefined,
        };
        return message;
    }

    fn parse_headers(
        allocator: std.mem.Allocator,
        reader: std.io.AnyReader,
    ) (DeserialiseError || anyerror)!?[]Header {
        const line = try Message.get_line(allocator, reader);
        defer allocator.free(line);
        if (std.mem.eql(u8, line, "")) return null;
        var headers = try allocator.alloc(Header, 1);
        errdefer allocator.free(headers);
        headers[0] = try Header.deserialise(allocator, line);
        const next_line = try Message.get_line(allocator, reader);
        defer allocator.free(next_line);
        if (std.mem.eql(u8, next_line, "")) return headers;
        return null;
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

    fn deserialise(str: []const u8) DeserialiseError!Version {
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
        if (std.mem.eql(u8, second, "1.0")) {
            std.debug.panic("TODO", .{});
        } else if (std.mem.eql(u8, second, "1.1")) {
            return Version.V1_1;
        } else if (std.mem.eql(u8, second, "2.0")) {
            return DeserialiseError.UnsupportedProtocolVersion;
        } else {
            return DeserialiseError.InvalidProtocolVersion;
        }
        std.debug.panic("TODO", .{});
    }
};

/// HTTP header
const Header = struct {
    name: []const u8,
    value: []const u8,

    fn deserialise(
        allocator: std.mem.Allocator,
        str: []const u8,
    ) (DeserialiseError || std.mem.Allocator.Error)!Header {
        var parts = std.mem.splitSequence(u8, str, ": ");
        var len: usize = 0;
        while (parts.next()) |_| len += 1;
        if (len != 2) return DeserialiseError.MalformedHeader;
        parts.reset();
        // Safe to unwrap as have confirmed the iterator has length 2
        const name_data = parts.next().?;
        const name = try allocator.alloc(u8, name_data.len);
        @memcpy(name, name_data);
        // Safe to unwrap as have confirmed the iterator has length 2
        const value_data = parts.next().?;
        const value = try allocator.alloc(u8, value_data.len);
        @memcpy(value, value_data);
        return Header{ .name = name, .value = value };
    }

    fn deinit(self: Header, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        allocator.free(self.value);
    }
};

/// Request target
///
/// See the following link for more information on the possible values:
/// https://developer.mozilla.org/en-US/docs/Web/HTTP/Messages#request_targets
const RequestTarget = union(enum) {
    OriginForm: []const u8,

    fn deserialise(
        alllocator: std.mem.Allocator,
        str: []const u8,
    ) (DeserialiseError || std.mem.Allocator.Error)!RequestTarget {
        if (str[0] != '/') return DeserialiseError.InvalidRequestTarget;
        const slc = try alllocator.alloc(u8, str.len);
        @memcpy(slc, str);
        return RequestTarget{ .OriginForm = slc };
    }

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

    fn free(self: RequestTarget, allocator: std.mem.Allocator) void {
        switch (self) {
            .OriginForm => allocator.free(self.OriginForm),
        }
    }
};

test "serialise GET request message" {
    const allocator = std.testing.allocator;
    const version = Version.V1_1;
    const method = Method.GET;
    const uri = "/contact";
    const uri_heap = try allocator.alloc(u8, uri.len);
    @memcpy(uri_heap, uri);
    const header_one_name = "Host";
    const header_one_name_heap = try allocator.alloc(u8, header_one_name.len);
    @memcpy(header_one_name_heap, header_one_name);
    const header_one_value = "example.com";
    const header_one_value_heap = try allocator.alloc(u8, header_one_value.len);
    @memcpy(header_one_value_heap, header_one_value);
    const header_two_name = "User-Agent";
    const header_two_name_heap = try allocator.alloc(u8, header_two_name.len);
    @memcpy(header_two_name_heap, header_two_name);
    const header_two_value = "curl/8.6.0";
    const header_two_value_heap = try allocator.alloc(u8, header_two_value.len);
    @memcpy(header_two_value_heap, header_two_value);
    const header_three_name = "Accept";
    const header_three_name_heap = try allocator.alloc(u8, header_three_name.len);
    @memcpy(header_three_name_heap, header_three_name);
    const header_three_value = "*/*";
    const header_three_value_heap = try allocator.alloc(u8, header_three_value.len);
    @memcpy(header_three_value_heap, header_three_value);
    const headers = [3]Header{
        Header{ .name = header_one_name_heap, .value = header_one_value_heap },
        Header{ .name = header_two_name_heap, .value = header_two_value_heap },
        Header{ .name = header_three_name_heap, .value = header_three_value_heap },
    };
    const headers_heap = try allocator.alloc(Header, headers.len);
    @memcpy(headers_heap, &headers);
    const body_heap = try allocator.alloc(u8, 0);
    const msg = Message.init(
        allocator,
        version,
        method,
        RequestTarget{ .OriginForm = uri_heap },
        headers_heap,
        body_heap,
    );
    defer msg.deinit();
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
    const uri_heap = try allocator.alloc(u8, uri.len);
    @memcpy(uri_heap, uri);
    const header_one_name = "Host";
    const header_one_name_heap = try allocator.alloc(u8, header_one_name.len);
    @memcpy(header_one_name_heap, header_one_name);
    const header_one_value = "example.com";
    const header_one_value_heap = try allocator.alloc(u8, header_one_value.len);
    @memcpy(header_one_value_heap, header_one_value);
    const header_two_name = "Content-Type";
    const header_two_name_heap = try allocator.alloc(u8, header_two_name.len);
    @memcpy(header_two_name_heap, header_two_name);
    const header_two_value = "application/x-www-form-urlencoded";
    const header_two_value_heap = try allocator.alloc(u8, header_two_value.len);
    @memcpy(header_two_value_heap, header_two_value);
    const header_three_name = "Content-Length";
    const header_three_name_heap = try allocator.alloc(u8, header_three_name.len);
    @memcpy(header_three_name_heap, header_three_name);
    const header_three_value = "50";
    const header_three_value_heap = try allocator.alloc(u8, header_three_value.len);
    const headers = [3]Header{
        Header{ .name = header_one_name_heap, .value = header_one_value_heap },
        Header{ .name = header_two_name_heap, .value = header_two_value_heap },
        Header{ .name = header_three_name_heap, .value = header_three_value_heap },
    };
    const headers_heap = try allocator.alloc(Header, headers.len);
    @memcpy(headers_heap, &headers);
    const body = "name=FirstName%20LastName&email=bsmth%40example.com";
    const body_heap = try allocator.alloc(u8, body.len);
    @memcpy(body_heap, body);
    const msg = Message.init(
        allocator,
        version,
        method,
        RequestTarget{ .OriginForm = uri_heap },
        headers_heap,
        body_heap,
    );
    defer msg.deinit();
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
    try std.testing.expectError(DeserialiseError.UnexpectedEof, ret);
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
    try std.testing.expectError(DeserialiseError.UnexpectedEof, ret);
}

test "return error if request line ends with CR but not LF" {
    const allocator = std.testing.allocator;
    const data = "GET /users HTTP/1.1\r";
    var stream = std.io.fixedBufferStream(data);
    const reader = stream.reader().any();
    const ret = Message.deserialise(allocator, reader);
    try std.testing.expectError(DeserialiseError.UnexpectedEof, ret);
}

test "return error if char at end of request line after CR isn't LF" {
    const allocator = std.testing.allocator;
    const data = "GET /users HTTP/1.1\ra";
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

test "correct message produced from valid request line and no header or body" {
    const allocator = std.testing.allocator;
    const data = "GET /users HTTP/1.1\r\n\r\n";
    var stream = std.io.fixedBufferStream(data);
    const reader = stream.reader().any();
    const message = try Message.deserialise(allocator, reader);
    defer {
        message.deinit();
        allocator.destroy(message);
    }

    const expected_headers = try allocator.alloc(Header, 0);
    const expected_body = try allocator.alloc(u8, 0);
    const expected_uri = "/users";
    const expected_uri_heap = try allocator.alloc(u8, expected_uri.len);
    @memcpy(expected_uri_heap, expected_uri);
    const expected_message = Message.init(
        allocator,
        Version.V1_1,
        Method.GET,
        RequestTarget{ .OriginForm = expected_uri_heap },
        expected_headers,
        expected_body,
    );
    defer expected_message.deinit();

    var buf: [16]u8 = undefined;
    @memset(&buf, 0);
    const leftover = reader.read(buf[0..]);
    try std.testing.expectEqual(0, leftover);

    try std.testing.expectEqual(expected_message.version, message.*.version);
    try std.testing.expectEqual(expected_message.method, message.*.method);
    try std.testing.expectEqualSlices(Header, expected_message.headers, message.*.headers);
    try std.testing.expectEqualStrings(expected_message.body, message.*.body);
    switch (expected_message.request_target) {
        .OriginForm => try std.testing.expectEqualStrings(
            expected_message.request_target.data(),
            message.*.request_target.data(),
        ),
    }
}

test "return error if header doesn't end with CRLF" {
    const allocator = std.testing.allocator;
    const data = "GET /users HTTP/1.1\r\nUser-Agent: curl/7.74.0";
    var stream = std.io.fixedBufferStream(data);
    const reader = stream.reader().any();
    const ret = Message.deserialise(allocator, reader);
    var buf: [16]u8 = undefined;
    @memset(&buf, 0);
    const leftover = reader.read(buf[0..]);
    try std.testing.expectEqual(0, leftover);
    try std.testing.expectError(DeserialiseError.UnexpectedEof, ret);
}

test "return error if header ends with CR but not LF" {
    const allocator = std.testing.allocator;
    const data = "GET /users HTTP/1.1\r\nUser-Agent: curl/7.74.0\r";
    var stream = std.io.fixedBufferStream(data);
    const reader = stream.reader().any();
    const ret = Message.deserialise(allocator, reader);
    var buf: [16]u8 = undefined;
    @memset(&buf, 0);
    const leftover = reader.read(buf[0..]);
    try std.testing.expectEqual(0, leftover);
    try std.testing.expectError(DeserialiseError.UnexpectedEof, ret);
}

test "return error if char at end of header line after CR isn't LF" {
    const allocator = std.testing.allocator;
    const data = "GET /users HTTP/1.1\r\nUser-Agent: curl/7.74.0\ra";
    var stream = std.io.fixedBufferStream(data);
    const reader = stream.reader().any();
    const ret = Message.deserialise(allocator, reader);
    var buf: [16]u8 = undefined;
    @memset(&buf, 0);
    const leftover = reader.read(buf[0..]);
    try std.testing.expectEqual(0, leftover);
    try std.testing.expectError(DeserialiseError.MissingLineDelimiter, ret);
}

test "return error if header line missing colon char" {
    const allocator = std.testing.allocator;
    const data = "GET /users HTTP/1.1\r\nUser-Agent curl/7.74.0\r\n";
    var stream = std.io.fixedBufferStream(data);
    const reader = stream.reader().any();
    const ret = Message.deserialise(allocator, reader);
    var buf: [16]u8 = undefined;
    @memset(&buf, 0);
    const leftover = reader.read(buf[0..]);
    try std.testing.expectEqual(0, leftover);
    try std.testing.expectError(DeserialiseError.MalformedHeader, ret);
}

test "correct message with single header" {
    const allocator = std.testing.allocator;
    const data = "GET /users HTTP/1.1\r\nUser-Agent: curl/7.74.0\r\n\r\n";
    var stream = std.io.fixedBufferStream(data);
    const reader = stream.reader().any();
    const message = try Message.deserialise(allocator, reader);
    defer {
        message.deinit();
        allocator.destroy(message);
    }

    const expected_headers = try allocator.alloc(Header, 1);
    const header_name = "User-Agent";
    const header_name_heap = try allocator.alloc(u8, header_name.len);
    @memcpy(header_name_heap, header_name);
    const header_value = "curl/7.74.0";
    const header_value_heap = try allocator.alloc(u8, header_value.len);
    @memcpy(header_value_heap, header_value);
    expected_headers[0] = Header{ .name = header_name_heap, .value = header_value_heap };
    const expected_body = try allocator.alloc(u8, 0);
    const expected_uri = "/users";
    const expected_uri_heap = try allocator.alloc(u8, expected_uri.len);
    @memcpy(expected_uri_heap, expected_uri);
    const expected_message = Message.init(
        allocator,
        Version.V1_1,
        Method.GET,
        RequestTarget{ .OriginForm = expected_uri_heap },
        expected_headers,
        expected_body,
    );
    defer expected_message.deinit();

    var buf: [16]u8 = undefined;
    @memset(&buf, 0);
    const leftover = reader.read(buf[0..]);
    try std.testing.expectEqual(0, leftover);

    try std.testing.expectEqual(expected_message.version, message.*.version);
    try std.testing.expectEqual(expected_message.method, message.*.method);
    try std.testing.expectEqual(message.*.headers.len, 1);
    try std.testing.expectEqualSlices(u8, expected_message.headers[0].name, message.*.headers[0].name);
    try std.testing.expectEqualSlices(u8, expected_message.headers[0].value, message.*.headers[0].value);
    try std.testing.expectEqualStrings(expected_message.body, message.*.body);
    switch (expected_message.request_target) {
        .OriginForm => try std.testing.expectEqualStrings(
            expected_message.request_target.data(),
            message.*.request_target.data(),
        ),
    }
}
