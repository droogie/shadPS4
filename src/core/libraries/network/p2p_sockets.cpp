// SPDX-FileCopyrightText: Copyright 2024-2026 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#include <algorithm>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <map>
#include <set>
#include <utility>
#include <vector>
#include <common/assert.h>
#include <common/config.h>
#include <common/logging/log.h>
#include <common/sha1.h>
#include <queue>
#include "core/libraries/kernel/file_system.h"
#include "core/libraries/kernel/kernel.h"
#include "core/libraries/network/kernel_p2p.h"
#include "core/libraries/network/stun_client.h"
#include "net.h"
#include "net_error.h"
#include "sockets.h"

#ifndef _WIN32
#include <sys/ioctl.h>
#include <unistd.h>
#endif

namespace Libraries::Net {

// PS4 P2P sockets multiplex multiple virtual ports (sin_vport) over a single UDP port.
// We emulate this with one real UDP socket (the "shared transport") bound to the signaling
// port. All P2PSocket instances share this socket.
//
// The PS4 kernel prepends a 4-byte header to each P2P UDP packet on the wire:
//   [0xFF] [flags] [src_vport_u8] [dst_vport_u8] [payload...]
//
// Flags byte breakdown:
//   bit 7 (0x80): always set for P2P packets
//   bit 6 (0x40): vport size -- 1 = single-byte vports (4-byte header),
//                               0 = two-byte vports (6-byte header)
//   bit 5 (0x20): comid present (adds 4 bytes after vports)
//   bits 3-0:     packet type -- 3-6 for direct P2P,
//                                7-10 for tunnel/relay
//
// Type 3 (flags=0xC3) is used for plaintext game data (no encryption, no HMAC).
// See docs/ps4_p2p_protocol.md for full protocol details.
static constexpr size_t P2P_HEADER_SIZE = 4;
static constexpr u8 P2P_MAGIC = 0xFF;
static constexpr u8 P2P_FLAGS_DATA = 0xC3; // 0x80 | 0x40 | 0x03 = P2P, 1-byte vports, type 3
static constexpr u16 DEFAULT_SIGNALING_PORT = 3658; // default signaling port

// HMAC-SHA1 key used by signaling protocol.
// The kernel uses the first 16 bytes for HMAC-SHA1 verification.
static constexpr u8 P2P_HMAC_KEY[20] = {0xa0, 0x07, 0x0e, 0x61, 0xad, 0x3f, 0xca, 0x50, 0x6d, 0xb5,
                                        0xad, 0x3d, 0x57, 0x13, 0x32, 0xce, 0xa7, 0x32, 0x0d, 0x9e};
static constexpr size_t P2P_HMAC_KEY_LEN = 16; // kernel uses first 16 bytes
static constexpr size_t P2P_HMAC_SIG_LEN = 4;  // truncated HMAC

// Tunnel packet types that require HMAC-SHA1 verification.
// Tunnel packet types 5, 6, 9, 10 require HMAC verification.
static bool TunnelTypeNeedsHmac(u8 type_bits) {
    // Bit mask: types 5(0x20), 6(0x40), 9(0x200), 10(0x400) = 0x660
    return type_bits <= 10 && ((1u << type_bits) & 0x660u) != 0;
}

// HMAC-SHA1 using the sha1::SHA1 class available in shadPS4.
// HMAC(K, m) = H((K' ^ opad) || H((K' ^ ipad) || m))
static void HmacSha1(const u8* key, size_t key_len, const u8* data, size_t data_len, u8 out[20]) {
    static constexpr size_t BLOCK_SIZE = 64;
    u8 k_pad[BLOCK_SIZE];

    // If key > block size, hash it first (won't happen with our 16-byte key)
    u8 key_hash[20];
    if (key_len > BLOCK_SIZE) {
        sha1::SHA1 hasher;
        hasher.processBytes(key, key_len);
        hasher.getDigestBytes(key_hash);
        key = key_hash;
        key_len = 20;
    }

    // Pad key to block size
    std::memset(k_pad, 0, BLOCK_SIZE);
    std::memcpy(k_pad, key, key_len);

    // Inner hash: H((K' ^ ipad) || m)
    u8 inner_key[BLOCK_SIZE];
    for (size_t i = 0; i < BLOCK_SIZE; i++)
        inner_key[i] = k_pad[i] ^ 0x36;

    sha1::SHA1 inner;
    inner.processBytes(inner_key, BLOCK_SIZE);
    inner.processBytes(data, data_len);
    u8 inner_hash[20];
    inner.getDigestBytes(inner_hash);

    // Outer hash: H((K' ^ opad) || inner_hash)
    u8 outer_key[BLOCK_SIZE];
    for (size_t i = 0; i < BLOCK_SIZE; i++)
        outer_key[i] = k_pad[i] ^ 0x5c;

    sha1::SHA1 outer;
    outer.processBytes(outer_key, BLOCK_SIZE);
    outer.processBytes(inner_hash, 20);
    outer.getDigestBytes(out);
}

#ifdef _WIN32
#ifndef MSG_DONTWAIT
#define MSG_DONTWAIT 0 // Windows uses non-blocking sockets instead of per-call flags
#endif
#define P2P_ERROR_CASE(errname)                                                                    \
    case (WSA##errname):                                                                           \
        *Libraries::Kernel::__Error() = ORBIS_NET_##errname;                                       \
        return -1;
#else
#define P2P_ERROR_CASE(errname)                                                                    \
    case (errname):                                                                                \
        *Libraries::Kernel::__Error() = ORBIS_NET_##errname;                                       \
        return -1;
#endif

static int ConvertReturnErrorCode(int retval) {
    if (retval < 0) {
#ifdef _WIN32
        switch (WSAGetLastError()) {
#else
        switch (errno) {
#endif
#ifndef _WIN32
            P2P_ERROR_CASE(EPERM)
            P2P_ERROR_CASE(ENOENT)
            P2P_ERROR_CASE(ENOMEM)
            P2P_ERROR_CASE(EEXIST)
            P2P_ERROR_CASE(ENODEV)
            P2P_ERROR_CASE(ENFILE)
            P2P_ERROR_CASE(ENOSPC)
            P2P_ERROR_CASE(EPIPE)
            P2P_ERROR_CASE(ECANCELED)
            P2P_ERROR_CASE(ENODATA)
#endif
            P2P_ERROR_CASE(EINTR)
            P2P_ERROR_CASE(EBADF)
            P2P_ERROR_CASE(EACCES)
            P2P_ERROR_CASE(EFAULT)
            P2P_ERROR_CASE(EINVAL)
            P2P_ERROR_CASE(EMFILE)
            P2P_ERROR_CASE(EWOULDBLOCK)
            P2P_ERROR_CASE(EINPROGRESS)
            P2P_ERROR_CASE(EALREADY)
            P2P_ERROR_CASE(ENOTSOCK)
            P2P_ERROR_CASE(EDESTADDRREQ)
            P2P_ERROR_CASE(EMSGSIZE)
            P2P_ERROR_CASE(EPROTOTYPE)
            P2P_ERROR_CASE(ENOPROTOOPT)
            P2P_ERROR_CASE(EPROTONOSUPPORT)
#if defined(__APPLE__) || defined(_WIN32)
            P2P_ERROR_CASE(EOPNOTSUPP)
#endif
            P2P_ERROR_CASE(EAFNOSUPPORT)
            P2P_ERROR_CASE(EADDRINUSE)
            P2P_ERROR_CASE(EADDRNOTAVAIL)
            P2P_ERROR_CASE(ENETDOWN)
            P2P_ERROR_CASE(ENETUNREACH)
            P2P_ERROR_CASE(ENETRESET)
            P2P_ERROR_CASE(ECONNABORTED)
            P2P_ERROR_CASE(ECONNRESET)
            P2P_ERROR_CASE(ENOBUFS)
            P2P_ERROR_CASE(EISCONN)
            P2P_ERROR_CASE(ENOTCONN)
            P2P_ERROR_CASE(ETIMEDOUT)
            P2P_ERROR_CASE(ECONNREFUSED)
            P2P_ERROR_CASE(ELOOP)
            P2P_ERROR_CASE(ENAMETOOLONG)
            P2P_ERROR_CASE(EHOSTUNREACH)
            P2P_ERROR_CASE(ENOTEMPTY)
        }
        *Libraries::Kernel::__Error() = ORBIS_NET_EINTERNAL;
        return -1;
    }
    return retval;
}

// ====== Shared P2P Transport ======
// One real UDP socket per process, shared by all P2PSocket instances.
// Packets are demultiplexed by the dst_vport field in the VPORT header.
namespace {

struct BufferedPacket {
    std::vector<u8> payload;
    sockaddr_in from_addr;
    u16 src_vport;
};

struct SharedTransport {
    net_socket fd =
#ifdef _WIN32
        INVALID_SOCKET;
#else
        -1;
#endif
    u16 bound_port_nbo = 0;
    int refcount = 0;
    std::mutex mutex;

    // Learned peers: tracks (IP, port) pairs we've seen packets from.
    // Used only for logging -- SendPacket resolves ports via KernelP2PSubsystem.
    std::set<std::pair<u32, u16>> learned_peers; // (IP NBO, port NBO)
    std::map<u16, std::queue<BufferedPacket>> vport_queues;
    std::set<u16> bound_vports; // vports with active game sockets (NBO)

    // Peers that have sent data on a bound vport (e.g., vport 40).
    // Used to distinguish PS4 peers (only vport 30) from shadPS4 peers
    // (both vport 30 and 40). The kernel handler should only intercept
    // unbound vport traffic from PS4 peers -- shadPS4 peers communicate
    // on the bound vport directly and their vport 30 traffic should be
    // dropped to avoid dual-channel conflicts.
    // Keyed by (IP, port) to support multiple peers on the same IP
    // (e.g., multiple emulator instances on one machine).
    std::set<std::pair<u32, u16>> peers_on_bound_vport; // (peer IP NBO, port NBO)

    bool IsValid() const {
#ifdef _WIN32
        return fd != INVALID_SOCKET;
#else
        return fd >= 0;
#endif
    }

    // Drain all available packets from the shared socket into per-vport queues.
    // Must be called with mutex held.
    void Drain() {
        if (!IsValid())
            return;
        u8 buf[65536];
        for (;;) {
            sockaddr_in from{};
            socklen_t fromlen = sizeof(from);
            int n = ::recvfrom(fd, reinterpret_cast<char*>(buf), sizeof(buf), MSG_DONTWAIT,
                               reinterpret_cast<sockaddr*>(&from), &fromlen);
            if (n <= 0)
                break;

            if (n < static_cast<int>(P2P_HEADER_SIZE)) {
                LOG_WARNING(Lib_Net, "P2P: runt packet ({} bytes), dropping", n);
                continue;
            }

            // Check for STUN response (first 2 bytes = 0x0101 binding response).
            // When sharing the P2P socket with the STUN client, STUN server
            // responses arrive here. Route them to the STUN client's queue.
            if (n >= 20 && buf[0] == 0x01 && buf[1] == 0x01) {
                auto* stun = KernelP2PSubsystem::Instance().GetStunClient();
                if (stun) {
                    stun->PushReceivedPacket(buf, static_cast<size_t>(n), from);
                    LOG_INFO(Lib_Net, "P2P: routed STUN response ({} bytes) to StunClient", n);
                }
                continue;
            }

            // Check for relay-tagged packet: [0xFE][npid_len][npid_bytes][0xFF P2P...]
            // The STUN server prepends this header when forwarding relay packets,
            // tagging each with the sender's NpId for multi-peer disambiguation.
            // Receive-side only: the client never sends these tags. If the server
            // enables relay, it handles routing transparently.
            if (buf[0] == 0xFE && n >= 3) {
                u8 npid_len = buf[1];
                int relay_hdr = 2 + npid_len;
                if (npid_len > 0 && npid_len <= 16 &&
                    n >= relay_hdr + static_cast<int>(P2P_HEADER_SIZE)) {
                    std::string sender_npid(reinterpret_cast<const char*>(&buf[2]), npid_len);
                    u32 peer_addr = 0;
                    u16 peer_port = 0;
                    if (KernelP2PSubsystem::Instance().TranslateRelaySourceByNpid(
                            sender_npid, &peer_addr, &peer_port)) {
                        from.sin_addr.s_addr = peer_addr;
                        from.sin_port = peer_port;
                        // Force-classify relay peers as shadPS4 immediately.
                        // All relay peers are shadPS4 -- they send on both vport 30 and 40.
                        peers_on_bound_vport.emplace(peer_addr, peer_port);
                        // Also clear any stale PS4 classification from early untagged packets
                        KernelP2PSubsystem::Instance().ClearPS4PeerClassification(peer_addr);
                        LOG_INFO(Lib_Net, "P2P RELAY TAG: npid='{}' -> peer {:#x}:{}", sender_npid,
                                 ntohl(peer_addr), ntohs(peer_port));
                    } else {
                        // No matching peer -- drop (stale or unknown sender)
                        continue;
                    }
                    // Strip relay header -- shift to the original P2P packet
                    std::memmove(buf, buf + relay_hdr, n - relay_hdr);
                    n -= relay_hdr;
                    // Fall through -- buf[0] is now 0xFF
                } else {
                    continue; // malformed relay tag
                }
            }

            // Parse PS4 P2P header: [0xFF] [flags] [src_vport_u8] [dst_vport_u8]
            if (buf[0] != P2P_MAGIC) {
                // Check for ActivatePacket (32 bytes, type=5 at offset 0).
                // These are server-mediated signaling handshake packets sent by
                // sceNpSignalingActivateConnection. The peer receives this and
                // confirms to the server, completing bilateral activation.
                u32 pkt_type = 0;
                if (n == 32) {
                    std::memcpy(&pkt_type, buf, 4);
                }
                if (n == 32 && pkt_type == 5) {
                    u32 peer_conn_id = 0, ctx_tag = 0;
                    std::memcpy(&peer_conn_id, buf + 4, 4);
                    std::memcpy(&ctx_tag, buf + 8, 4);
                    LOG_WARNING(Lib_Net,
                                "P2P: ActivatePacket received! from={:#x}:{} conn_id={} ctx_tag={}",
                                ntohl(from.sin_addr.s_addr), ntohs(from.sin_port), peer_conn_id,
                                ctx_tag);
                    // Fire-and-forget: POST /np/signaling/confirm to server
                    KernelP2PSubsystem::Instance().HandleActivatePacket(
                        from.sin_addr.s_addr, from.sin_port, peer_conn_id, ctx_tag);
                } else {
                    LOG_WARNING(Lib_Net, "P2P: non-P2P packet ({} bytes) from {:#x}:{} magic={:#x}",
                                n, ntohl(from.sin_addr.s_addr), ntohs(from.sin_port), buf[0]);
                }
                continue;
            }

            u8 flags = buf[1];
            if (!(flags & 0x80)) {
                LOG_WARNING(Lib_Net, "P2P: flags byte {:#x} missing bit 7, dropping", flags);
                continue;
            }

            // Echo probes: [FF 83 FF FD ...] -- detect by raw bytes before vport parsing.
            // flags=0x83, followed by FF FD which are the 1-byte src/dst vport values.
            // The kernel treats these identically to any other vport packet.
            if (n >= 4 && buf[2] == 0xFF && buf[3] == 0xFD) {
                // Strip the 4-byte wire header, pass payload to echo handler
                LOG_INFO(Lib_Net, "P2P Drain: echo probe detected! {} bytes from {:#x}:{}", n,
                         ntohl(from.sin_addr.s_addr), ntohs(from.sin_port));
                KernelP2PSubsystem::Instance().ProcessEchoProbe(from.sin_addr.s_addr, from.sin_port,
                                                                &buf[4], n - 4);
                continue;
            }

            u8 type_bits = flags & 0x0F;
            int header_size;
            int vport_offset = 2; // offset where vports start

            // Check for comid field (4 bytes after magic+flags, before vports)
            bool has_comid = (flags & 0x20) != 0;
            if (has_comid) {
                vport_offset += 4;
            }

            u16 src_vp, dst_vp;

            if (flags & 0x40) {
                // 1-byte vports (common case)
                // Kernel stores as: rol.w(zx.w(byte), 8) -> e.g. 0x1e -> 0x1e00 (NBO)
                if (n < vport_offset + 2) {
                    LOG_WARNING(Lib_Net, "P2P: packet too short for 1-byte vports ({} bytes)", n);
                    continue;
                }
                src_vp = static_cast<u16>(buf[vport_offset]) << 8;
                dst_vp = static_cast<u16>(buf[vport_offset + 1]) << 8;
                header_size = vport_offset + 2;
            } else {
                // 2-byte vports (for vport values > 255)
                if (n < vport_offset + 4) {
                    LOG_WARNING(Lib_Net, "P2P: 2-byte vport packet too short ({} bytes)", n);
                    continue;
                }
                memcpy(&src_vp, &buf[vport_offset], 2);
                memcpy(&dst_vp, &buf[vport_offset + 2], 2);
                header_size = vport_offset + 4;
            }

            // For tunnel types with HMAC (5,6,9,10), verify and strip signature
            if (TunnelTypeNeedsHmac(type_bits)) {
                if (n < header_size + static_cast<int>(P2P_HMAC_SIG_LEN)) {
                    LOG_WARNING(Lib_Net, "P2P: HMAC packet too short ({} bytes, need {} + {})", n,
                                header_size, P2P_HMAC_SIG_LEN);
                    continue;
                }

                // HMAC signature is right after the header, before payload
                const u8* sig = &buf[header_size];
                const u8* payload = &buf[header_size + P2P_HMAC_SIG_LEN];
                int payload_len = n - header_size - P2P_HMAC_SIG_LEN;

                // Compute HMAC-SHA1 over the payload
                u8 computed_hmac[20];
                HmacSha1(P2P_HMAC_KEY, P2P_HMAC_KEY_LEN, payload, payload_len, computed_hmac);

                // Compare truncated HMAC (first 4 bytes)
                if (std::memcmp(sig, computed_hmac, P2P_HMAC_SIG_LEN) != 0) {
                    LOG_WARNING(Lib_Net,
                                "P2P: HMAC verification FAILED for type {} packet "
                                "({} bytes), dropping",
                                type_bits, n);
                    continue;
                }

                LOG_INFO(Lib_Net, "P2P: HMAC verified OK for type {} packet ({} bytes payload)",
                         type_bits, payload_len);

                // Adjust: skip the HMAC signature to get to payload
                header_size += P2P_HMAC_SIG_LEN;
            }

            int plen = n - header_size;
            if (plen < 0 || header_size > n) {
                LOG_ERROR(Lib_Net, "P2P drain: malformed packet -- header_size={} > n={}, dropping",
                          header_size, n);
                continue;
            }

            BufferedPacket pkt;
            pkt.payload.assign(&buf[header_size], &buf[header_size] + plen);
            pkt.from_addr = from;
            pkt.src_vport = src_vp;

            LOG_INFO(Lib_Net, "P2P drain: {} bytes from {:#x}:{} src_vp={} dst_vp={} flags={:#x}",
                     plen, ntohl(from.sin_addr.s_addr), ntohs(from.sin_port), ntohs(src_vp),
                     ntohs(dst_vp), flags);

            // Track peers we've received packets from (by IP+port).
            // On real PS4, each peer has a unique IP. On dev machines,
            // multiple instances may share an IP with different ports.
            {
                u32 peer_ip = from.sin_addr.s_addr;
                u16 peer_port = from.sin_port;
                auto key = std::make_pair(peer_ip, peer_port);
                if (learned_peers.count(key) == 0) {
                    learned_peers.emplace(peer_ip, peer_port);
                    LOG_INFO(Lib_Net, "P2P: learned peer {:#x}:{} (first packet)", ntohl(peer_ip),
                             ntohs(peer_port));
                }

                // Notify KernelP2P that we received a packet from this peer.
                // On LAN (no STUN), this provides bilateral confirmation for
                // MUTUAL_ACTIVATED -- receipt of a P2P packet proves the remote
                // peer's tunnel is active.
                KernelP2PSubsystem::Instance().OnPeerPacketReceived(peer_ip);
            }

            u32 sender_ip = from.sin_addr.s_addr;

            // Drop vport 0 / 0-payload packets AFTER peer tracking but BEFORE
            // game socket delivery. NAT punch probes [FF C3 00 00] must reach
            // OnPeerPacketReceived (creates NAT mapping confirmation) but must
            // NOT be queued to the game socket (causes ACCESS_VIOLATION in
            // the game from uninitialized P2P state).
            if (dst_vp == 0 && plen == 0) {
                continue;
            }

            if (bound_vports.find(dst_vp) != bound_vports.end()) {
                // Track peer on bound vport (needed for vport30 forwarding).
                peers_on_bound_vport.insert({sender_ip, from.sin_port});
                vport_queues[dst_vp].push(std::move(pkt));
            } else {
                // Unbound vport -- buffer for later delivery or forward to PS4 peer handler.
                //
                // On real PS4, the kernel buffers ALL incoming P2P packets regardless
                // of vport binding state. The game's recvfrom picks them up when the
                // socket is bound. In our HLE, we emulate this by queueing to the
                // vport's queue even if no socket is bound yet. When the game later
                // binds the vport (Bind -> OnVportBound), the buffered packets are
                // available immediately.
                //
                // This is critical for WAN connections: the HOST's SocketState sends
                // handshake data on vport 30 BEFORE the GUEST has called JoinRoom
                // (which creates the vport 30 socket). Without buffering, the
                // handshake is lost and the ConnObj can never complete.
                // Intentional fall-through for both shadPS4 and PS4 peers:
                // ShouldForwardUnboundPacket below handles vport translation.
                // shadPS4 peers (in peers_on_bound_vport) and PS4 peers both
                // need the same path -- the grace period classifies them.

                // Vport translation: forward the entire payload (including
                // game-level framing) to the first bound vport. The kernel
                // delivers payload with framing intact after stripping the
                // 4-byte wire header.
                bool should_forward =
                    KernelP2PSubsystem::Instance().ShouldForwardUnboundPacket(dst_vp, from);

                if (should_forward) {
                    for (u16 bound_vp : bound_vports) {
                        if (bound_vp != dst_vp) {
                            BufferedPacket fwd;
                            // Forward entire payload with framing intact.
                            fwd.payload = pkt.payload;
                            fwd.from_addr = from;
                            // Set src_vport to the bound vport so the game
                            // sees this as normal vport 40 traffic.
                            fwd.src_vport = bound_vp;
                            LOG_INFO(Lib_Net,
                                     "P2P vport xlat: {} bytes from PS4 peer "
                                     "vport {} -> game vport {} (payload intact)",
                                     pkt.payload.size(), ntohs(dst_vp), ntohs(bound_vp));
                            vport_queues[bound_vp].push(std::move(fwd));
                            break;
                        }
                    }
                }
            }
        }
    }
};

// Single shared transport -- all vports (30, 40, echo 0xFFFD) multiplex over
// one UDP socket on the signaling port.  The wire header [FF C3 src dst]
// carries vport information; Drain() demuxes into per-vport queues.
// This matches the real PS4 kernel's architecture (one tunnel per peer,
// kernel-internal vport demux) and avoids the need for separate NAT
// mappings per port.
static constexpr int NUM_TRANSPORTS = 1;
static SharedTransport s_transports[NUM_TRANSPORTS];
static auto& s_transport = s_transports[0];

static u16 GetSignalingPort() {
    const char* env = std::getenv("SHADPS4_SIGNALING_PORT");
    if (env) {
        int port = std::atoi(env);
        if (port > 0 && port < 65536)
            return static_cast<u16>(port);
    }
    int cfg = Config::GetSignalingPort();
    if (cfg > 0 && cfg < 65536)
        return static_cast<u16>(cfg);
    return DEFAULT_SIGNALING_PORT;
}

// Initialize the single shared transport socket.
// Must be called with s_transport.mutex held.
static bool EnsureTransport() {
    if (s_transport.IsValid())
        return true;

    net_socket fd = ::socket(AF_INET, SOCK_DGRAM, 0);
#ifdef _WIN32
    if (fd == INVALID_SOCKET) {
#else
    if (fd < 0) {
#endif
        LOG_ERROR(Lib_Net, "P2P: failed to create shared UDP socket");
        return false;
    }

    // Allow port reuse for restart scenarios
    int one = 1;
    ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&one), sizeof(one));
#ifdef SO_REUSEPORT
    ::setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, reinterpret_cast<const char*>(&one), sizeof(one));
#endif

    u16 sig_port = GetSignalingPort();
    sockaddr_in bind_addr{};
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port = htons(sig_port);
    bind_addr.sin_addr.s_addr = INADDR_ANY;

    if (::bind(fd, reinterpret_cast<sockaddr*>(&bind_addr), sizeof(bind_addr)) < 0) {
        LOG_ERROR(Lib_Net, "P2P: failed to bind transport to port {}, trying ephemeral", sig_port);
        bind_addr.sin_port = 0;
        if (::bind(fd, reinterpret_cast<sockaddr*>(&bind_addr), sizeof(bind_addr)) < 0) {
#ifdef _WIN32
            closesocket(fd);
#else
            ::close(fd);
#endif
            return false;
        }
    }

    sockaddr_in actual{};
    socklen_t actual_len = sizeof(actual);
    ::getsockname(fd, reinterpret_cast<sockaddr*>(&actual), &actual_len);

    int nb = 1;
#ifdef _WIN32
    ioctlsocket(fd, FIONBIO, (u_long*)&nb);
#else
    ioctl(fd, FIONBIO, &nb);
#endif

    s_transport.fd = fd;
    s_transport.bound_port_nbo = actual.sin_port;

    // Share socket with STUN client for NAT mapping
    auto* stun = KernelP2PSubsystem::Instance().GetStunClient();
    if (stun) {
        stun->SetSharedSocket(static_cast<int>(fd));
    }

    LOG_INFO(Lib_Net, "P2P transport: bound to port {} (fd={})", ntohs(s_transport.bound_port_nbo),
             fd);
    return true;
}

} // anonymous namespace

// Force-create the shared transport early (before STUN probe) so the STUN
// client can share the same socket and NAT mapping as game P2P traffic.
void EnsureP2PTransport() {
    std::scoped_lock tlock{s_transport.mutex};
    EnsureTransport();
}

// ====== P2PSocket implementation ======

P2PSocket::P2PSocket(int domain, int type, int protocol) : Socket(domain, type, protocol) {
    // Initialize shared transport eagerly so IsValid()/Native() work immediately.
    // sys_socketex checks IsValid() right after construction and rejects if false.
    std::scoped_lock tlock{s_transport.mutex};
    if (EnsureTransport()) {
        sock_ = s_transport.fd;
        s_transport.refcount++;
        LOG_INFO(Lib_Net, "P2P socket handle created (shared fd={}, refcount={})", sock_,
                 s_transport.refcount);
    } else {
#ifdef _WIN32
        sock_ = INVALID_SOCKET;
#else
        sock_ = -1;
#endif
        LOG_ERROR(Lib_Net, "P2P socket handle creation failed (shared transport unavailable)");
    }
}

bool P2PSocket::IsValid() const {
#ifdef _WIN32
    return sock_ != INVALID_SOCKET;
#else
    return sock_ >= 0;
#endif
}

int P2PSocket::Close() {
    std::scoped_lock lock{m_mutex};
    if (!IsValid())
        return 0;

    LOG_INFO(Lib_Net, "Closing P2P socket (vport={})", ntohs(bound_vport_.load()));

    {
        std::scoped_lock tlock{s_transport.mutex};
        s_transport.vport_queues.erase(bound_vport_);
        s_transport.bound_vports.erase(bound_vport_);
        s_transport.refcount--;
        if (s_transport.IsValid() && s_transport.refcount <= 0) {
            LOG_INFO(Lib_Net, "P2P transport: closing (fd={})", s_transport.fd);
#ifdef _WIN32
            closesocket(s_transport.fd);
            s_transport.fd = INVALID_SOCKET;
#else
            ::close(s_transport.fd);
            s_transport.fd = -1;
#endif
            s_transport.bound_port_nbo = 0;
            s_transport.refcount = 0;
            s_transport.vport_queues.clear();
            s_transport.peers_on_bound_vport.clear();
        }
    }

#ifdef _WIN32
    sock_ = INVALID_SOCKET;
#else
    sock_ = -1;
#endif
    bound_vport_ = 0;
    return 0;
}

int P2PSocket::Bind(const OrbisNetSockaddr* addr, u32 addrlen) {
    std::scoped_lock lock{m_mutex};

    if (!IsValid()) {
        *Libraries::Kernel::__Error() = ORBIS_NET_EBADF;
        return -1;
    }

    const auto* orbis_addr = reinterpret_cast<const OrbisNetSockaddrIn*>(addr);
    bound_vport_ = orbis_addr->sin_vport;

    // All vports share the single transport -- no migration needed.
    {
        std::scoped_lock tlock{s_transport.mutex};
        s_transport.vport_queues[bound_vport_];
        s_transport.bound_vports.insert(bound_vport_);
    }

    KernelP2PSubsystem::Instance().OnVportBound(bound_vport_);

    LOG_INFO(Lib_Net, "P2P socket bound: port={} vport={}", ntohs(s_transport.bound_port_nbo),
             ntohs(bound_vport_.load()));
    return 0;
}

int P2PSocket::SendPacket(const void* msg, u32 len, int flags, const OrbisNetSockaddr* to,
                          u32 tolen) {
    std::scoped_lock lock{m_mutex};
    if (!IsValid()) {
        *Libraries::Kernel::__Error() = ORBIS_NET_EBADF;
        return -1;
    }
    if (to == nullptr) {
        *Libraries::Kernel::__Error() = ORBIS_NET_EDESTADDRREQ;
        return -1;
    }

    const auto* orbis_to = reinterpret_cast<const OrbisNetSockaddrIn*>(to);

    // On real PS4, the kernel's P2P subsystem manages tunnels and resolves
    // the destination UDP port from its internal tunnel table, ignoring sin_port
    // from the game's sendto() call. The game fills sin_port from signaling data
    // (e.g., the NpSignaling port), which may differ from the actual P2P data port.
    //
    // We emulate this in two steps:
    // 1. Resolve addr=0/port=0 to the active peer (game sends to "default peer")
    // 2. Override sin_port with the peer's ACTUAL port learned from incoming packets
    //    (this is the key fix -- the game may provide a wrong port from signaling data)
    OrbisNetSockaddrIn resolved_to = *orbis_to;
    if (orbis_to->sin_addr == 0 && orbis_to->sin_port == 0) {
        int peer_count = KernelP2PSubsystem::Instance().GetActivePeerCount();
        if (peer_count > 1) {
            LOG_WARNING(Lib_Net,
                        "P2P sendto: game sent to 0.0.0.0:0 with {} active peers -- "
                        "GetActivePeerAddr returns first match only, may misroute!",
                        peer_count);
        }
        u32 peer_addr = 0;
        u16 peer_port = 0;
        if (KernelP2PSubsystem::Instance().GetActivePeerAddr(&peer_addr, &peer_port)) {
            resolved_to.sin_addr = peer_addr;
            resolved_to.sin_port = peer_port;
            LOG_INFO(Lib_Net, "P2P sendto: resolved 0.0.0.0:0 -> {:#x}:{} via KernelP2P",
                     ntohl(peer_addr), ntohs(peer_port));
        }
    }

    // Step 2: Override port with the peer's actual P2P port learned from incoming
    // packets. On real PS4, the kernel discovers this during NAT traversal. In our
    // HLE, we learn it from the first packet received from each peer (Drain records
    // source port). This corrects the port when the game fills sin_port from
    // signaling data (which may be the NpSignaling port, not the P2P data port).
    // On console, the kernel resolves the destination port from its peer
    // tunnel table (populated by the peer registration ioctl). We trust
    // the port from the game/signaling data.
    //
    // NOTE: The previous learned_peer_ports override (keyed on IP only)
    // broke multi-peer on same IP (e.g., multiple instances on one machine)
    // by applying the first peer's port to ALL peers at that IP.
    orbis_to = &resolved_to;

    // Build framed packet with PS4 kernel P2P header.
    // Default: type 3 (0xC3) = plaintext, no HMAC.
    // If peer requires tunnel format, use type 9 (0xC9) with HMAC-SHA1.
    //
    // TODO: Add per-peer tunnel mode flag when PS4 peers need it.
    // For now, always use type 3 (direct P2P, no HMAC) which works
    // for both emulator-to-emulator and emulator-to-console on the same network.
    constexpr bool use_tunnel_hmac = false;
    const u8 flags_byte = use_tunnel_hmac ? 0xC9 : P2P_FLAGS_DATA;

    if (len > 65536) {
        LOG_ERROR(Lib_Net, "P2P SendPacket: len={} exceeds max (65536), dropping", len);
        *Libraries::Kernel::__Error() = ORBIS_NET_EMSGSIZE;
        return -1;
    }

    size_t frame_size = P2P_HEADER_SIZE + len;
    if (use_tunnel_hmac)
        frame_size += P2P_HMAC_SIG_LEN;

    std::vector<u8> framed(frame_size);
    framed[0] = P2P_MAGIC;
    framed[1] = flags_byte;
    framed[2] = static_cast<u8>(ntohs(bound_vport_));        // NBO u16 -> host -> u8
    framed[3] = static_cast<u8>(ntohs(orbis_to->sin_vport)); // NBO u16 -> host -> u8

    // Vport is encoded in the wire header -- single UDP socket carries all vports.

    if (use_tunnel_hmac) {
        // Compute HMAC-SHA1 over payload, place truncated sig after header
        u8 hmac_full[20];
        HmacSha1(P2P_HMAC_KEY, P2P_HMAC_KEY_LEN, static_cast<const u8*>(msg), len, hmac_full);
        memcpy(&framed[P2P_HEADER_SIZE], hmac_full, P2P_HMAC_SIG_LEN);
        memcpy(&framed[P2P_HEADER_SIZE + P2P_HMAC_SIG_LEN], msg, len);
    } else {
        memcpy(&framed[P2P_HEADER_SIZE], msg, len);
    }

    // Build native destination (addr + port only; vport is in the wire header).
    // Single-port: all vports go to the same peer port.
    sockaddr_in native_to{};
    native_to.sin_family = AF_INET;
    native_to.sin_port = orbis_to->sin_port;
    memcpy(&native_to.sin_addr, &orbis_to->sin_addr, 4);

    int native_flags = 0;
#ifndef _WIN32
    if (flags & ORBIS_NET_MSG_DONTWAIT)
        native_flags |= MSG_DONTWAIT;
#endif

    net_socket fd;
    {
        std::scoped_lock tlock{s_transport.mutex};
        fd = s_transport.fd;
    }

    LOG_INFO(Lib_Net,
             "P2P sendto: attempting {} bytes to addr={:#x} ({}.{}.{}.{}) port={} vport={} "
             "src_vport={} fd={} native_flags={:#x}",
             len, ntohl(orbis_to->sin_addr), (ntohl(orbis_to->sin_addr) >> 24) & 0xff,
             (ntohl(orbis_to->sin_addr) >> 16) & 0xff, (ntohl(orbis_to->sin_addr) >> 8) & 0xff,
             ntohl(orbis_to->sin_addr) & 0xff, ntohs(orbis_to->sin_port),
             ntohs(orbis_to->sin_vport), ntohs(bound_vport_), fd, native_flags);

    // NOTE: VP40 loopback was investigated but is not needed here.
    // On real PS4, VP40 never appears on the wire (pcap-confirmed). The kernel
    // routes VP40 internally via the INIT_SELF tunnel (127.0.0.1). However,
    // the SigDataNotifyPool notification fires from the registration
    // path (registerSubEntryCallback -> P2P thread ring buffer dispatch), NOT
    // from VP40 data arrival. The SocketState handshake (states 7-9) exchanges
    // VP40 data with peers and completes independently.
    // VP40 data continues to flow over the network in our emulator, matching
    // the game's native sendto() calls. This differs from real PS4 (which
    // blocks VP40 at kernel level) but doesn't affect functionality.

    int res = ::sendto(fd, reinterpret_cast<const char*>(framed.data()), framed.size(),
                       native_flags, reinterpret_cast<sockaddr*>(&native_to), sizeof(native_to));
    if (res < 0) {
#ifdef _WIN32
        int err = WSAGetLastError();
#else
        int err = errno;
#endif
        LOG_ERROR(Lib_Net,
                  "P2P sendto FAILED: err={} dst_addr={:#x} ({}.{}.{}.{}) "
                  "dst_port={} dst_vport={} src_vport={} len={} fd={}",
                  err, ntohl(orbis_to->sin_addr), (ntohl(orbis_to->sin_addr) >> 24) & 0xff,
                  (ntohl(orbis_to->sin_addr) >> 16) & 0xff, (ntohl(orbis_to->sin_addr) >> 8) & 0xff,
                  ntohl(orbis_to->sin_addr) & 0xff, ntohs(orbis_to->sin_port),
                  ntohs(orbis_to->sin_vport), ntohs(bound_vport_), len, fd);
        return ConvertReturnErrorCode(res);
    }

    // Return payload bytes sent (the game's original payload size).
    // framed includes the P2P header, but the game expects to see just
    // the payload byte count.
    int payload_sent = static_cast<int>(len);

    LOG_INFO(Lib_Net, "P2P sendto OK: {} bytes to {:#x}:{} vport={}", payload_sent,
             ntohl(orbis_to->sin_addr), ntohs(orbis_to->sin_port), ntohs(orbis_to->sin_vport));

    // Hex dump first 16 bytes of vport 30/40 sends for P2P command diagnosis
    {
        u16 vp = ntohs(orbis_to->sin_vport);
        if ((vp == 30 || vp == 40) && len > 0) {
            std::string hex;
            int dump_len = std::min(static_cast<int>(len), 16);
            const auto* p = reinterpret_cast<const u8*>(msg);
            for (int i = 0; i < dump_len; i++) {
                char tmp[4];
                snprintf(tmp, sizeof(tmp), "%02x ", p[i]);
                hex += tmp;
            }
            LOG_INFO(Lib_Net, "P2P vport{} SEND[0:{}]: {}", vp, dump_len, hex);
        }
    }

    return payload_sent;
}

int P2PSocket::ReceivePacket(void* buf, u32 len, int flags, OrbisNetSockaddr* from, u32* fromlen) {
    std::scoped_lock lock{receive_mutex};
    if (!IsValid()) {
        *Libraries::Kernel::__Error() = ORBIS_NET_EBADF;
        return -1;
    }

    std::scoped_lock tlock{s_transport.mutex};

    // Drain all available packets into per-vport queues
    s_transport.Drain();

    auto it = s_transport.vport_queues.find(bound_vport_);
    if (it == s_transport.vport_queues.end() || it->second.empty()) {
        *Libraries::Kernel::__Error() = ORBIS_NET_EWOULDBLOCK;
        return -1;
    }

    auto& pkt = it->second.front();

    // Copy payload to user buffer (use size_t to avoid signed truncation
    // when len > INT_MAX -- casting large u32 to int wraps negative -> memcpy UB)
    size_t copy_len = std::min(pkt.payload.size(), static_cast<size_t>(len));
    memcpy(buf, pkt.payload.data(), copy_len);

    // Fill in source address with vport from the wire header.
    // Single-port: all vports arrive on the same UDP socket, so the source
    // port is always the peer's signaling port. The NXRV framework hashes
    // (addr, port, vport) to find channels.
    if (from != nullptr) {
        auto* orbis_from = reinterpret_cast<OrbisNetSockaddrIn*>(from);
        memset(orbis_from, 0, sizeof(OrbisNetSockaddrIn));
        orbis_from->sin_len = sizeof(OrbisNetSockaddrIn);
        orbis_from->sin_family = AF_INET;
        orbis_from->sin_port = pkt.from_addr.sin_port;
        memcpy(&orbis_from->sin_addr, &pkt.from_addr.sin_addr, 4);
        orbis_from->sin_vport = pkt.src_vport;

        if (fromlen) {
            *fromlen = sizeof(OrbisNetSockaddrIn);
        }
    }

    u16 actual_dst_vp = it->first;
    LOG_INFO(Lib_Net, "P2P recvfrom: {} bytes from {:#x}:{} src_vp={} dst_vp={}", copy_len,
             ntohl(pkt.from_addr.sin_addr.s_addr), ntohs(pkt.from_addr.sin_port),
             ntohs(pkt.src_vport), ntohs(actual_dst_vp));

    // Hex dump first 16 bytes of vport 30/40 payloads for P2P command diagnosis
    {
        u16 vp = ntohs(actual_dst_vp);
        if ((vp == 30 || vp == 40) && copy_len > 0) {
            std::string hex;
            size_t dump_len = std::min(copy_len, size_t(16));
            const auto* p = reinterpret_cast<const u8*>(buf);
            for (size_t i = 0; i < dump_len; i++) {
                char tmp[4];
                snprintf(tmp, sizeof(tmp), "%02x ", p[i]);
                hex += tmp;
            }
            LOG_INFO(Lib_Net, "P2P vport{} payload[0:{}]: {}", vp, dump_len, hex);
        }
    }

    if (!(flags & ORBIS_NET_MSG_PEEK)) {
        it->second.pop();
    }

    return static_cast<int>(copy_len);
}

int P2PSocket::SetSocketOptions(int level, int optname, const void* optval, u32 optlen) {
    std::scoped_lock lock{m_mutex};

    if (level == ORBIS_NET_SOL_SOCKET) {
        switch (optname) {
        case ORBIS_NET_SO_NBIO: {
            if (optlen < sizeof(int)) {
                *Libraries::Kernel::__Error() = ORBIS_NET_EINVAL;
                return -1;
            }
            memcpy(&sockopt_so_nbio_, optval, sizeof(int));
            LOG_INFO(Lib_Net, "P2P SO_NBIO = {}", sockopt_so_nbio_);
            // Shared socket is always non-blocking; we handle blocking semantics per-socket
            return 0;
        }
        case ORBIS_NET_SO_BROADCAST: {
            if (!IsValid())
                return 0;
            std::scoped_lock tlock{s_transport.mutex};
            return ConvertReturnErrorCode(
                setsockopt(s_transport.fd, SOL_SOCKET, SO_BROADCAST, (const char*)optval, optlen));
        }
        case ORBIS_NET_SO_SNDBUF: {
            if (!IsValid())
                return 0;
            std::scoped_lock tlock{s_transport.mutex};
            return ConvertReturnErrorCode(
                setsockopt(s_transport.fd, SOL_SOCKET, SO_SNDBUF, (const char*)optval, optlen));
        }
        case ORBIS_NET_SO_RCVBUF: {
            if (!IsValid())
                return 0;
            std::scoped_lock tlock{s_transport.mutex};
            return ConvertReturnErrorCode(
                setsockopt(s_transport.fd, SOL_SOCKET, SO_RCVBUF, (const char*)optval, optlen));
        }
        case ORBIS_NET_SO_REUSEADDR: {
            // Shared socket already has SO_REUSEADDR set
            LOG_INFO(Lib_Net, "P2P SO_REUSEADDR (shared transport, no-op)");
            return 0;
        }
        case ORBIS_NET_SO_SNDTIMEO:
        case ORBIS_NET_SO_RCVTIMEO: {
            // Shared socket is always non-blocking; timeouts handled per-socket if needed
            LOG_INFO(Lib_Net, "P2P SO_{} (shared transport, stored locally)",
                     (optname == ORBIS_NET_SO_SNDTIMEO) ? "SNDTIMEO" : "RCVTIMEO");
            return 0;
        }
        default:
            LOG_WARNING(Lib_Net, "P2P setsockopt: unhandled SOL_SOCKET option {:#x}", optname);
            return 0;
        }
    }

    LOG_WARNING(Lib_Net, "P2P setsockopt: unhandled level={} optname={:#x}", level, optname);
    return 0;
}

int P2PSocket::GetSocketOptions(int level, int optname, void* optval, u32* optlen) {
    std::scoped_lock lock{m_mutex};

    if (level == ORBIS_NET_SOL_SOCKET) {
        switch (optname) {
        case ORBIS_NET_SO_NBIO: {
            if (*optlen < sizeof(int)) {
                *optlen = sizeof(int);
                *Libraries::Kernel::__Error() = ORBIS_NET_EFAULT;
                return -1;
            }
            *optlen = sizeof(int);
            *(int*)optval = sockopt_so_nbio_;
            return 0;
        }
        case ORBIS_NET_SO_ERROR: {
            if (!IsValid()) {
                *(int*)optval = 0;
                *optlen = sizeof(int);
                return 0;
            }
            std::scoped_lock tlock{s_transport.mutex};
            socklen_t optlen_temp = *optlen;
            auto retval = ConvertReturnErrorCode(
                getsockopt(s_transport.fd, SOL_SOCKET, SO_ERROR, (char*)optval, &optlen_temp));
            *optlen = optlen_temp;
            return retval;
        }
        case ORBIS_NET_SO_TYPE: {
            if (*optlen >= sizeof(int)) {
                *(int*)optval = socket_type;
                *optlen = sizeof(int);
            }
            return 0;
        }
        default:
            LOG_WARNING(Lib_Net, "P2P getsockopt: unhandled SOL_SOCKET option {:#x}", optname);
            if (*optlen >= sizeof(int)) {
                *(int*)optval = 0;
                *optlen = sizeof(int);
            }
            return 0;
        }
    }

    LOG_WARNING(Lib_Net, "P2P getsockopt: unhandled level={} optname={:#x}", level, optname);
    return 0;
}

int P2PSocket::GetSocketAddress(OrbisNetSockaddr* name, u32* namelen) {
    std::scoped_lock lock{m_mutex};
    if (!IsValid() || name == nullptr) {
        return 0;
    }

    // Return the shared transport's bound address with this socket's vport
    auto* orbis_addr = reinterpret_cast<OrbisNetSockaddrIn*>(name);
    memset(orbis_addr, 0, sizeof(OrbisNetSockaddrIn));
    orbis_addr->sin_len = sizeof(OrbisNetSockaddrIn);
    orbis_addr->sin_family = AF_INET;

    {
        std::scoped_lock tlock{s_transport.mutex};
        sockaddr_in native_addr{};
        socklen_t native_len = sizeof(native_addr);
        if (::getsockname(s_transport.fd, reinterpret_cast<sockaddr*>(&native_addr), &native_len) ==
            0) {
            orbis_addr->sin_port = native_addr.sin_port;
            memcpy(&orbis_addr->sin_addr, &native_addr.sin_addr, 4);
        }
    }

    orbis_addr->sin_vport = bound_vport_;

    if (namelen) {
        *namelen = sizeof(OrbisNetSockaddrIn);
    }

    return 0;
}

int P2PSocket::Connect(const OrbisNetSockaddr* addr, u32 namelen) {
    // P2P UDP sockets don't truly connect -- connectionless datagram
    LOG_INFO(Lib_Net, "P2P Connect called (no-op for UDP P2P)");
    return 0;
}

int P2PSocket::Listen(int backlog) {
    LOG_WARNING(Lib_Net, "P2P Listen called (not applicable for DGRAM)");
    return 0;
}

int P2PSocket::SendMessage(const OrbisNetMsghdr* msg, int flags) {
    LOG_ERROR(Lib_Net, "(STUBBED) P2P SendMessage called");
    *Libraries::Kernel::__Error() = ORBIS_NET_EAGAIN;
    return -1;
}

int P2PSocket::ReceiveMessage(OrbisNetMsghdr* msg, int flags) {
    LOG_ERROR(Lib_Net, "(STUBBED) P2P ReceiveMessage called");
    *Libraries::Kernel::__Error() = ORBIS_NET_EAGAIN;
    return -1;
}

SocketPtr P2PSocket::Accept(OrbisNetSockaddr* addr, u32* addrlen) {
    LOG_ERROR(Lib_Net, "P2P Accept called (not applicable for DGRAM)");
    *Libraries::Kernel::__Error() = ORBIS_NET_EOPNOTSUPP;
    return nullptr;
}

int P2PSocket::GetPeerName(OrbisNetSockaddr* addr, u32* namelen) {
    LOG_WARNING(Lib_Net, "(STUBBED) P2P GetPeerName called");
    return 0;
}

int P2PSocket::fstat(Libraries::Kernel::OrbisKernelStat* sb) {
    if (sb) {
        sb->st_mode = 0000777u | 0140000u;
    }
    return 0;
}

bool P2PSocket::HasQueuedData() {
    std::scoped_lock tlock{s_transport.mutex};
    s_transport.Drain();

    auto it = s_transport.vport_queues.find(bound_vport_);
    return it != s_transport.vport_queues.end() && !it->second.empty();
}

void DrainP2PTransport() {
    std::scoped_lock lock{s_transport.mutex};
    s_transport.Drain();
}

void ClearP2PSessionState() {
    std::scoped_lock lock{s_transport.mutex};
    // Clear learned peer and peer classification state so stale entries
    // from a previous session don't interfere with the next one.
    // Do NOT flush vport_queues -- the game may still read buffered data
    // during session teardown (after LeaveRoom but before next session).
    s_transport.learned_peers.clear();
    s_transport.peers_on_bound_vport.clear();
    LOG_INFO(Lib_Net, "P2P: cleared peer state for session cleanup");
}

void P2PFlushPacketsFromPeer(u32 peer_addr_nbo, u16 peer_port_nbo) {
    // Flush buffered P2P packets from a departed peer. Without this, the game
    // receives stale data from the departed peer AFTER processing MemberLeft,
    // detects inconsistency, and exits with penalty/notify_multi_play_error.
    // Reference implementation: called from sceNpSignalingDeactivateConnection.
    {
        std::scoped_lock lock{s_transport.mutex};

        // Drain OS socket buffer first to catch in-flight packets
        s_transport.Drain();

        int flushed = 0;
        for (auto& [vport, queue] : s_transport.vport_queues) {
            std::queue<BufferedPacket> filtered;
            while (!queue.empty()) {
                auto pkt = std::move(queue.front());
                queue.pop();
                if (pkt.from_addr.sin_addr.s_addr == peer_addr_nbo &&
                    pkt.from_addr.sin_port == peer_port_nbo) {
                    ++flushed;
                } else {
                    filtered.push(std::move(pkt));
                }
            }
            queue = std::move(filtered);
        }

        if (flushed > 0) {
            LOG_INFO(Lib_Net,
                     "P2PFlushPacketsFromPeer: peer={:#x}:{} flushed {} packets from transport",
                     ntohl(peer_addr_nbo), ntohs(peer_port_nbo), flushed);
        }
    }
}

} // namespace Libraries::Net
