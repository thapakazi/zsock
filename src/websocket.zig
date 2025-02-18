const std = @import("std");

const net = std.net;
const base64 = std.base64;
const Sha1 = std.crypto.hash.Sha1;

const WebSocketGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

const MAX_HEADER_SIZE = 8192;
const MAX_PAYLOAD_SIZE = 65536;

pub fn handleClient(allocator: std.mem.Allocator, stream: net.Stream) !void {
    var buf: [MAX_HEADER_SIZE]u8 = undefined;
    const bytes_read = try stream.read(&buf);
    if (bytes_read == 0) return error.ConnectionClosed;

    const headers = buf[0..bytes_read];

    // Simple HTTP request parsing to get WebSocket key
    const key_prefix = "Sec-WebSocket-Key: ";
    var lines = std.mem.split(u8, headers, "\r\n");
    var ws_key: ?[]const u8 = null;

    while (lines.next()) |line| {
        if (std.mem.startsWith(u8, line, key_prefix)) {
            ws_key = line[key_prefix.len..];
            break;
        }
    }

    if (ws_key == null) return error.WebSocketKeyNotFound;

    // Generate accept key
    var sha1 = Sha1.init(.{});
    sha1.update(ws_key.?);
    sha1.update(WebSocketGUID);
    var sha1_output: [Sha1.digest_length]u8 = undefined;
    sha1.final(&sha1_output);

    var accept_key_buf: [base64.standard.Encoder.calcSize(Sha1.digest_length)]u8 = undefined;
    const accept_key = base64.standard.Encoder.encode(&accept_key_buf, &sha1_output);

    // Send WebSocket handshake response
    const response = try std.fmt.allocPrint(allocator, "HTTP/1.1 101 Switching Protocols\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Accept: {s}\r\n\r\n", .{accept_key});
    defer allocator.free(response);

    try stream.writeAll(response);
    std.log.info("WebSocket handshake complete", .{});

    // Main WebSocket communication loop
    while (true) {
        var frame_header: [14]u8 = undefined; // Maximum header size
        const frame_header_size = try stream.read(frame_header[0..2]);
        if (frame_header_size < 2) return error.ConnectionClosed;

        // Parse basic frame info
        const fin = (frame_header[0] & 0x80) != 0;
        const opcode = @as(u4, @truncate(frame_header[0] & 0x0F));
        const masked = (frame_header[1] & 0x80) != 0;
        const payload_len = @as(u7, @truncate(frame_header[1] & 0x7F));

        var header_offset: usize = 2;
        var actual_payload_len: u64 = payload_len;

        // Handle extended payload length
        if (payload_len == 126) {
            const len_bytes = try stream.read(frame_header[header_offset .. header_offset + 2]);
            if (len_bytes < 2) return error.ConnectionClosed;
            actual_payload_len = (@as(u16, frame_header[header_offset]) << 8) | frame_header[header_offset + 1];
            header_offset += 2;
        } else if (payload_len == 127) {
            const len_bytes = try stream.read(frame_header[header_offset .. header_offset + 8]);
            if (len_bytes < 8) return error.ConnectionClosed;
            var i: usize = 0;
            actual_payload_len = 0;
            while (i < 8) : (i += 1) {
                actual_payload_len = (actual_payload_len << 8) | frame_header[header_offset + i];
            }
            header_offset += 8;
        }

        if (actual_payload_len > MAX_PAYLOAD_SIZE) return error.PayloadTooLarge;

        // Read masking key if present
        var masking_key = [_]u8{0} ** 4;
        if (masked) {
            const mask_bytes = try stream.read(frame_header[header_offset .. header_offset + 4]);
            if (mask_bytes < 4) return error.ConnectionClosed;
            @memcpy(&masking_key, frame_header[header_offset .. header_offset + 4]);
            header_offset += 4;
        } else if (opcode != 0x8) { // Not a close frame
            // All client frames must be masked per WebSocket Protocol
            return error.UnmaskedFrame;
        }

        // Read payload
        var payload = try allocator.alloc(u8, @intCast(actual_payload_len));
        defer allocator.free(payload);

        if (actual_payload_len > 0) {
            const payload_bytes = try stream.read(payload);
            if (payload_bytes < payload.len) return error.ConnectionClosed;

            // Unmask payload if needed
            if (masked) {
                for (payload, 0..) |_, i| {
                    payload[i] ^= masking_key[i % 4];
                }
            }
        }

        // Handle different frame types
        switch (opcode) {
            0x1 => { // Text frame
                if (!fin) {
                    // For simplicity, we don't handle fragmented messages
                    continue;
                }
                std.log.info("Received text message: {s}", .{payload});

                // Echo back the message
                try sendTextFrame(allocator, stream, payload);
            },
            0x8 => { // Close frame
                // Send close frame back
                try sendCloseFrame(allocator, stream);
                return;
            },
            0x9 => { // Ping frame
                // Respond with pong
                try sendPongFrame(allocator, stream, payload);
            },
            0xA => { // Pong frame
                // Just log it
                std.log.info("Received pong", .{});
            },
            else => {
                std.log.warn("Unhandled frame type: {}", .{opcode});
            },
        }
    }
}

fn sendFrame(allocator: std.mem.Allocator, stream: net.Stream, fin: bool, opcode: u4, payload: []const u8) !void {
    const fin_bit: u8 = if (fin) 0x80 else 0;
    const first_byte = fin_bit | @as(u8, opcode);

    var header_buf: [14]u8 = undefined;
    var header_len: usize = 2;

    header_buf[0] = first_byte;

    // Set payload length
    if (payload.len < 126) {
        header_buf[1] = @intCast(payload.len);
    } else if (payload.len <= 65535) {
        header_buf[1] = 126;
        header_buf[2] = @intCast((payload.len >> 8) & 0xFF);
        header_buf[3] = @intCast(payload.len & 0xFF);
        header_len += 2;
    } else {
        header_buf[1] = 127;
        var i: usize = 0;
        var len_copy = payload.len;
        while (i < 8) : (i += 1) {
            header_buf[9 - i] = @intCast(len_copy & 0xFF);
            len_copy >>= 8;
        }
        header_len += 8;
    }

    const frame = try allocator.alloc(u8, header_len + payload.len);
    defer allocator.free(frame);

    @memcpy(frame, header_buf[0..header_len]);
    @memcpy(frame[header_len..], payload);

    try stream.writeAll(frame);
}

fn sendTextFrame(allocator: std.mem.Allocator, stream: net.Stream, payload: []const u8) !void {
    try sendFrame(allocator, stream, true, 0x1, payload);
}

fn sendPongFrame(allocator: std.mem.Allocator, stream: net.Stream, payload: []const u8) !void {
    try sendFrame(allocator, stream, true, 0xA, payload);
}

fn sendCloseFrame(allocator: std.mem.Allocator, stream: net.Stream) !void {
    const payload = [_]u8{ 0x03, 0xE8 }; // 1000 (normal closure) in network byte order
    try sendFrame(allocator, stream, true, 0x8, &payload);
}
