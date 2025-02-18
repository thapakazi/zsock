const std = @import("std");
const websocket = @import("websocket.zig");

const net = std.net;
const base64 = std.base64;
const Sha1 = std.crypto.hash.Sha1;

const WebSocketGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const MAX_HEADER_SIZE = 8192;
const MAX_PAYLOAD_SIZE = 65536;
const PORT = 8090;

const WebSocketFrameType = enum {
    Continuation,
    Text,
    Binary,
    Close,
    Ping,
    Pong,
};

const WebSocketFrame = struct {
    fin: bool,
    opcode: u4,
    mask: bool,
    payload_len: u64,
    masking_key: [4]u8,
    payload: []u8,
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const address = try net.Address.resolveIp("0.0.0.0", PORT);
    var server = try address.listen(.{
        .reuse_address = true,
    });
    defer server.deinit();

    std.log.info("WebSocket server listening on {}", .{address});

    while (true) {
        var conn = try server.accept();
        defer conn.stream.close();

        // const client_addr = try conn.stream.getLocalAddress();
        std.log.info("Client connected", .{});

        websocket.handleClient(allocator, conn.stream) catch |err| {
            std.log.err("Error handling client: {}", .{err});
        };
    }
}
