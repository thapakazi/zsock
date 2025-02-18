const std = @import("std");
const Sha1 = std.crypto.hash.Sha1;
const base64 = std.base64;

const WEB_SOCKET_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

pub fn secAcceptKey(ws_key: []const u8) ![]const u8 {
    var sha1 = Sha1.init(.{});
    sha1.update(ws_key);
    sha1.update(WEB_SOCKET_GUID);
    var sha1_output: [Sha1.digest_length]u8 = undefined;
    sha1.final(&sha1_output);

    var accept_key_buf: [base64.standard.Encoder.calcSize(Sha1.digest_length)]u8 = undefined;
    const accept_key = base64.standard.Encoder.encode(&accept_key_buf, &sha1_output);

    return accept_key;
}
