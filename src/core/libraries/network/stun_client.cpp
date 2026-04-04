// SPDX-FileCopyrightText: Copyright 2026 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#include <cstdlib>
#include <cstring>
#include <random>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#include "common/config.h"
#include "common/logging/log.h"
#include "core/libraries/network/stun_client.h"

#ifdef _WIN32
// Windows compatibility shims for POSIX socket APIs used below.
// Winsock is initialized globally in emulator.cpp (WSAStartup).
using ssize_t = ptrdiff_t;
using socklen_t = int;
static std::string sock_strerror() {
    int e = WSAGetLastError();
    char buf[256] = {};
    if (!FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, e, 0,
                        buf, sizeof(buf), nullptr)) {
        snprintf(buf, sizeof(buf), "WSA error %d", e);
    }
    return std::string(buf);
}

inline int stun_close(SOCKET fd) {
    return closesocket(fd);
}

inline ssize_t stun_sendto(SOCKET fd, const void* buf, size_t len, int flags, const sockaddr* to,
                           int tolen) {
    return ::sendto(fd, reinterpret_cast<const char*>(buf), static_cast<int>(len), flags, to,
                    tolen);
}

inline ssize_t stun_recvfrom(SOCKET fd, void* buf, size_t len, int flags, sockaddr* from,
                             socklen_t* fromlen) {
    return ::recvfrom(fd, reinterpret_cast<char*>(buf), static_cast<int>(len), flags, from,
                      fromlen);
}

inline int stun_poll(WSAPOLLFD* fds, unsigned long nfds, int timeout) {
    return WSAPoll(fds, nfds, timeout);
}
#define poll stun_poll
#define pollfd WSAPOLLFD
#else
inline int stun_close(int fd) {
    return ::close(fd);
}
#define stun_sendto ::sendto
#define stun_recvfrom ::recvfrom
static std::string sock_strerror() {
    return strerror(errno);
}
#endif

// --- Standalone HMAC-SHA1 (avoids OpenSSL dependency) ---

namespace {

// SHA-1 implementation (RFC 3174)
struct Sha1Ctx {
    u32 state[5];
    u64 count;
    u8 buffer[64];
};

static void sha1_init(Sha1Ctx* ctx) {
    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xEFCDAB89;
    ctx->state[2] = 0x98BADCFE;
    ctx->state[3] = 0x10325476;
    ctx->state[4] = 0xC3D2E1F0;
    ctx->count = 0;
}

static u32 sha1_rotl(u32 x, int n) {
    return (x << n) | (x >> (32 - n));
}

static void sha1_transform(u32 state[5], const u8 block[64]) {
    u32 w[80];
    for (int i = 0; i < 16; i++) {
        w[i] = (u32(block[i * 4]) << 24) | (u32(block[i * 4 + 1]) << 16) |
               (u32(block[i * 4 + 2]) << 8) | u32(block[i * 4 + 3]);
    }
    for (int i = 16; i < 80; i++) {
        w[i] = sha1_rotl(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    }

    u32 a = state[0], b = state[1], c = state[2], d = state[3], e = state[4];
    for (int i = 0; i < 80; i++) {
        u32 f, k;
        if (i < 20) {
            f = (b & c) | (~b & d);
            k = 0x5A827999;
        } else if (i < 40) {
            f = b ^ c ^ d;
            k = 0x6ED9EBA1;
        } else if (i < 60) {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8F1BBCDC;
        } else {
            f = b ^ c ^ d;
            k = 0xCA62C1D6;
        }
        u32 temp = sha1_rotl(a, 5) + f + e + k + w[i];
        e = d;
        d = c;
        c = sha1_rotl(b, 30);
        b = a;
        a = temp;
    }
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
}

static void sha1_update(Sha1Ctx* ctx, const u8* data, size_t len) {
    size_t idx = ctx->count % 64;
    ctx->count += len;
    for (size_t i = 0; i < len; i++) {
        ctx->buffer[idx++] = data[i];
        if (idx == 64) {
            sha1_transform(ctx->state, ctx->buffer);
            idx = 0;
        }
    }
}

static void sha1_final(Sha1Ctx* ctx, u8 digest[20]) {
    u64 bits = ctx->count * 8;
    u8 pad = 0x80;
    sha1_update(ctx, &pad, 1);
    pad = 0;
    while (ctx->count % 64 != 56) {
        sha1_update(ctx, &pad, 1);
    }
    u8 bits_be[8];
    for (int i = 7; i >= 0; i--) {
        bits_be[i] = bits & 0xFF;
        bits >>= 8;
    }
    sha1_update(ctx, bits_be, 8);
    for (int i = 0; i < 5; i++) {
        digest[i * 4] = (ctx->state[i] >> 24) & 0xFF;
        digest[i * 4 + 1] = (ctx->state[i] >> 16) & 0xFF;
        digest[i * 4 + 2] = (ctx->state[i] >> 8) & 0xFF;
        digest[i * 4 + 3] = ctx->state[i] & 0xFF;
    }
}

static void hmac_sha1(const u8* key, size_t key_len, const u8* data, size_t data_len, u8 out[20]) {
    u8 k_ipad[64], k_opad[64];
    u8 tk[20];

    if (key_len > 64) {
        Sha1Ctx ctx;
        sha1_init(&ctx);
        sha1_update(&ctx, key, key_len);
        sha1_final(&ctx, tk);
        key = tk;
        key_len = 20;
    }

    std::memset(k_ipad, 0x36, 64);
    std::memset(k_opad, 0x5C, 64);
    for (size_t i = 0; i < key_len; i++) {
        k_ipad[i] ^= key[i];
        k_opad[i] ^= key[i];
    }

    // inner hash
    Sha1Ctx ictx;
    sha1_init(&ictx);
    sha1_update(&ictx, k_ipad, 64);
    sha1_update(&ictx, data, data_len);
    u8 inner[20];
    sha1_final(&ictx, inner);

    // outer hash
    Sha1Ctx octx;
    sha1_init(&octx);
    sha1_update(&octx, k_opad, 64);
    sha1_update(&octx, inner, 20);
    sha1_final(&octx, out);
}

} // anonymous namespace

namespace Libraries::Net {

// HMAC-SHA1 key used by the signaling protocol (first 16 bytes used)
static constexpr u8 SONY_HMAC_KEY[] = {
    0xa0, 0x07, 0x0e, 0x61, 0xad, 0x3f, 0xca, 0x50, 0x6d, 0xb5, 0xad, 0x3d, 0x57, 0x13, 0x32, 0xce,
};

StunClient::StunClient() {
    // Priority: env var > config.toml > default (stun.playstation.net:3478)
    auto parse_host_port = [this](const std::string& s, const char* source) {
        auto colon = s.find(':');
        if (colon != std::string::npos) {
            server_host_ = s.substr(0, colon);
            server_port_ = static_cast<u16>(std::stoi(s.substr(colon + 1)));
        } else {
            server_host_ = s;
        }
        LOG_INFO(Lib_Net, "STUN server ({}): {}:{}", source, server_host_, server_port_);
    };

    // Check config.toml stunServer setting
    std::string cfg = Config::GetStunServer();
    if (!cfg.empty()) {
        parse_host_port(cfg, "config");
    }

    // Env var overrides config
    const char* env = std::getenv("SHADPS4_STUN_SERVER");
    if (env && *env) {
        parse_host_port(std::string(env), "env");
    }
}

void StunClient::SetSharedSocket(int fd) {
    sock_fd_ = fd;
    shared_socket_ = true;
    LOG_INFO(Lib_Net, "STUN: using shared P2P socket fd={}", fd);
}

void StunClient::PushReceivedPacket(const u8* data, size_t len, const sockaddr_in& from) {
    if (shutting_down_.load())
        return;

    // Route by transaction ID:
    //   1. Extract txn_id from bytes 4-20 of the STUN response header
    //   2. Match against pending_requests_ (registered by SendRecv callers)
    //      - Found: parse and fulfill promise -> caller gets its response
    //   3. No match: check for USERNAME attribute
    //      - Has USERNAME: push to relay_queue_ (incoming OFFER/ACCEPT from peer)
    //      - No USERNAME: discard (keepalive response or stale probe response)

    if (len < STUN_HEADER_SIZE) {
        return; // Too short to be STUN
    }

    // Extract txn_id from header
    const u8* pkt_txn = data + 4;

    // Try to match against a pending request
    {
        std::lock_guard lock(pending_mutex_);
        for (auto it = pending_requests_.begin(); it != pending_requests_.end(); ++it) {
            if (std::memcmp(it->txn_id, pkt_txn, 16) == 0) {
                // Found matching pending request -- parse and fulfill
                auto result = ParseResponse(data, len, pkt_txn);
                it->promise.set_value(result);
                pending_requests_.erase(it);
                return;
            }
        }
    }

    // No pending match -- check for USERNAME (relay from peer)
    std::string username;
    u8 any_txn[16];
    std::memcpy(any_txn, pkt_txn, 16);
    auto result = ParseResponse(data, len, any_txn, &username);

    if (!username.empty()) {
        // Unsolicited relay with USERNAME -> push to relay queue
        QueuedMsg msg;
        msg.data.assign(data, data + len);
        msg.from = from;
        msg.username = username;
        {
            std::lock_guard lock(relay_mutex_);
            relay_queue_.push_back(std::move(msg));
            relay_cv_.notify_one();
        }
    }
    // else: no USERNAME, no pending match -> discard (keepalive response, stale probe)
}

StunClient::~StunClient() {
    // Signal all waiters to stop BEFORE touching any mutexes.
    // This prevents use-after-free: WaitForRelay may be blocked on relay_cv_
    // inside relay_mutex_, and destroying the mutex while held is UB
    // (corrupts SRWLOCK/CONDITION_VARIABLE on Windows -> heap corruption).
    shutting_down_.store(true);

    // Wake any thread blocked in WaitForRelay so it sees shutting_down_
    {
        std::lock_guard lock(relay_mutex_);
        relay_cv_.notify_all();
    }

    // Cancel any pending requests
    {
        std::lock_guard lock(pending_mutex_);
        for (auto& req : pending_requests_) {
            req.promise.set_value(StunBindingResult{}); // empty/failed
        }
        pending_requests_.clear();
    }

    if (sock_fd_ >= 0 && !shared_socket_) {
        stun_close(sock_fd_);
    }
}

std::future<StunBindingResult> StunClient::RegisterPending(const u8* txn_id) {
    std::lock_guard lock(pending_mutex_);
    PendingRequest req;
    std::memcpy(req.txn_id, txn_id, 16);
    auto future = req.promise.get_future();
    pending_requests_.push_back(std::move(req));
    return future;
}

void StunClient::UnregisterPending(const u8* txn_id) {
    std::lock_guard lock(pending_mutex_);
    for (auto it = pending_requests_.begin(); it != pending_requests_.end(); ++it) {
        if (std::memcmp(it->txn_id, txn_id, 16) == 0) {
            it->promise.set_value(StunBindingResult{}); // fulfill with empty
            pending_requests_.erase(it);
            return;
        }
    }
}

void StunClient::SetServer(const std::string& host, u16 port) {
    server_host_ = host;
    server_port_ = port;
}

u32 StunClient::GetMappedAddr() const {
    std::lock_guard lock(mutex_);
    return mapped_addr_;
}

u16 StunClient::GetMappedPort() const {
    std::lock_guard lock(mutex_);
    return mapped_port_;
}

std::string StunClient::GetLastRelayUsername() const {
    std::lock_guard lock(mutex_);
    return last_relay_username_;
}

u32 StunClient::ResolveServer() {
    struct addrinfo hints{}, *res = nullptr;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;

    int ret = getaddrinfo(server_host_.c_str(), nullptr, &hints, &res);
    if (ret != 0 || !res) {
#ifdef _WIN32
        LOG_ERROR(Lib_Net, "STUN: failed to resolve '{}': {}", server_host_, gai_strerrorA(ret));
#else
        LOG_ERROR(Lib_Net, "STUN: failed to resolve '{}': {}", server_host_, gai_strerror(ret));
#endif
        return 0;
    }

    u32 addr = reinterpret_cast<struct sockaddr_in*>(res->ai_addr)->sin_addr.s_addr;
    freeaddrinfo(res);

    char buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr, buf, sizeof(buf));
    LOG_INFO(Lib_Net, "STUN: resolved '{}' -> {}", server_host_, buf);
    return addr;
}

void StunClient::GenerateTxnId(u8* out) {
    static thread_local std::mt19937 rng(std::random_device{}());
    for (int i = 0; i < 16; i += 4) {
        u32 val = rng();
        std::memcpy(out + i, &val, 4);
    }
}

std::vector<u8> StunClient::BuildAddrAttr(u32 addr_nbo, u16 port_nbo) {
    std::vector<u8> v(8);
    v[0] = 0x00;            // reserved
    v[1] = 0x01;            // family = IPv4
    u16 port_be = port_nbo; // already NBO
    std::memcpy(&v[2], &port_be, 2);
    std::memcpy(&v[4], &addr_nbo, 4);
    return v;
}

std::vector<u8> StunClient::ComputeHmac(const u8* data, size_t len) {
    u8 mac[20];
    hmac_sha1(SONY_HMAC_KEY, sizeof(SONY_HMAC_KEY), data, len, mac);
    return std::vector<u8>(mac, mac + 20);
}

std::vector<u8> StunClient::BuildRequest(const u8* txn_id, u32 response_addr, u16 response_port,
                                         u32 change_flags, const std::vector<u8>& username,
                                         const std::vector<u8>& signaling) {
    // Build attribute payload first, then prepend header
    std::vector<u8> attrs;

    auto append_attr = [&](u16 type, const u8* val, size_t val_len) {
        u16 type_be = htons(type);
        u16 len_be = htons(static_cast<u16>(val_len));
        attrs.insert(attrs.end(), reinterpret_cast<u8*>(&type_be),
                     reinterpret_cast<u8*>(&type_be) + 2);
        attrs.insert(attrs.end(), reinterpret_cast<u8*>(&len_be),
                     reinterpret_cast<u8*>(&len_be) + 2);
        if (val_len > 0) {
            attrs.insert(attrs.end(), val, val + val_len);
            // Pad to 4-byte boundary
            size_t pad = (4 - val_len % 4) % 4;
            for (size_t i = 0; i < pad; i++) {
                attrs.push_back(0);
            }
        }
    };

    // 1. RESPONSE-ADDRESS (if relay mode)
    if (response_addr != 0) {
        auto addr_val = BuildAddrAttr(response_addr, response_port);
        append_attr(STUN_ATTR_RESPONSE_ADDRESS, addr_val.data(), addr_val.size());
    }

    // 2. CHANGE-REQUEST
    if (change_flags != 0) {
        u32 flags_be = htonl(change_flags);
        append_attr(STUN_ATTR_CHANGE_REQUEST, reinterpret_cast<u8*>(&flags_be), 4);
    }

    // 2b. Attribute 0x0021 -- empty attribute required between CHANGE-REQUEST and USERNAME.
    append_attr(STUN_ATTR_ORBIS_UNKNOWN_0021, nullptr, 0);

    // 3. USERNAME
    if (!username.empty()) {
        append_attr(STUN_ATTR_USERNAME, username.data(), username.size());
    }

    // 4. Proprietary signaling attribute
    if (!signaling.empty()) {
        append_attr(STUN_ATTR_ORBIS_SIGNALING, signaling.data(), signaling.size());
    }

    // 5. MESSAGE-INTEGRITY (HMAC-SHA1)
    // Compute over header (with adjusted length) + all preceding attributes
    {
        size_t integrity_len = attrs.size() + 24; // attrs + MI TLV (4+20)
        std::vector<u8> hmac_input;
        // Build temporary header with adjusted length
        u16 msg_type_be = htons(STUN_BINDING_REQUEST);
        u16 adj_len_be = htons(static_cast<u16>(integrity_len));
        hmac_input.insert(hmac_input.end(), reinterpret_cast<u8*>(&msg_type_be),
                          reinterpret_cast<u8*>(&msg_type_be) + 2);
        hmac_input.insert(hmac_input.end(), reinterpret_cast<u8*>(&adj_len_be),
                          reinterpret_cast<u8*>(&adj_len_be) + 2);
        hmac_input.insert(hmac_input.end(), txn_id, txn_id + 16);
        hmac_input.insert(hmac_input.end(), attrs.begin(), attrs.end());

        auto mac = ComputeHmac(hmac_input.data(), hmac_input.size());
        append_attr(STUN_ATTR_MESSAGE_INTEGRITY, mac.data(), mac.size());
    }

    // Build final packet: header + attributes
    std::vector<u8> packet;
    u16 msg_type_be = htons(STUN_BINDING_REQUEST);
    u16 msg_len_be = htons(static_cast<u16>(attrs.size()));
    packet.insert(packet.end(), reinterpret_cast<u8*>(&msg_type_be),
                  reinterpret_cast<u8*>(&msg_type_be) + 2);
    packet.insert(packet.end(), reinterpret_cast<u8*>(&msg_len_be),
                  reinterpret_cast<u8*>(&msg_len_be) + 2);
    packet.insert(packet.end(), txn_id, txn_id + 16);
    packet.insert(packet.end(), attrs.begin(), attrs.end());

    return packet;
}

StunBindingResult StunClient::ParseResponse(const u8* data, size_t len, const u8* expected_txn,
                                            std::string* out_username) {
    StunBindingResult result{};

    if (len < STUN_HEADER_SIZE) {
        return result;
    }

    u16 msg_type, msg_len;
    std::memcpy(&msg_type, data, 2);
    std::memcpy(&msg_len, data + 2, 2);
    msg_type = ntohs(msg_type);
    msg_len = ntohs(msg_len);

    if (msg_type != STUN_BINDING_RESPONSE) {
        LOG_WARNING(Lib_Net, "STUN: unexpected msg_type {:#06x}", msg_type);
        return result;
    }

    // Verify transaction ID
    if (std::memcmp(data + 4, expected_txn, 16) != 0) {
        LOG_WARNING(Lib_Net, "STUN: transaction ID mismatch");
        return result;
    }

    if (len < STUN_HEADER_SIZE + msg_len) {
        LOG_WARNING(Lib_Net, "STUN: response truncated");
        return result;
    }

    bool has_mapped = false, has_source = false, has_changed = false;
    size_t offset = STUN_HEADER_SIZE;
    size_t end = STUN_HEADER_SIZE + msg_len;

    // Extract USERNAME for relay peer identification
    std::string username_str;

    while (offset + 4 <= end) {
        u16 attr_type, attr_len;
        std::memcpy(&attr_type, data + offset, 2);
        std::memcpy(&attr_len, data + offset + 2, 2);
        attr_type = ntohs(attr_type);
        attr_len = ntohs(attr_len);
        offset += 4;

        if (offset + attr_len > end)
            break;

        const u8* val = data + offset;

        auto parse_addr = [](const u8* v, u16 len, u32* addr, u16* port) -> bool {
            if (len < 8)
                return false;
            if (v[1] != 0x01)
                return false;            // not IPv4
            std::memcpy(port, v + 2, 2); // already NBO
            std::memcpy(addr, v + 4, 4); // already NBO
            return true;
        };

        switch (attr_type) {
        case STUN_ATTR_MAPPED_ADDRESS:
            if (parse_addr(val, attr_len, &result.mapped_addr, &result.mapped_port)) {
                has_mapped = true;
            }
            break;

        case STUN_ATTR_XOR_MAPPED_ADDRESS:
            if (attr_len >= 8 && val[1] == 0x01) {
                u16 xport;
                u32 xaddr;
                std::memcpy(&xport, val + 2, 2);
                std::memcpy(&xaddr, val + 4, 4);
                // XOR with transaction ID
                u16 txn_u16;
                u32 txn_u32;
                std::memcpy(&txn_u16, expected_txn, 2);
                std::memcpy(&txn_u32, expected_txn, 4);
                result.mapped_port = xport ^ txn_u16;
                result.mapped_addr = xaddr ^ txn_u32;
                has_mapped = true;
            }
            break;

        case STUN_ATTR_SOURCE_ADDRESS:
            if (parse_addr(val, attr_len, &result.source_addr, &result.source_port)) {
                has_source = true;
            }
            break;

        case STUN_ATTR_CHANGED_ADDRESS:
            if (parse_addr(val, attr_len, &result.changed_addr, &result.changed_port)) {
                has_changed = true;
            }
            break;

        case STUN_ATTR_USERNAME:
            // Extract USERNAME -- contains peer NpId (up to 16 bytes, null-padded)
            if (attr_len > 0) {
                // Find null terminator or use full length
                size_t str_len = 0;
                while (str_len < attr_len && val[str_len] != 0)
                    str_len++;
                username_str = std::string(reinterpret_cast<const char*>(val), str_len);
                LOG_INFO(Lib_Net, "STUN: parsed USERNAME='{}' ({} bytes)", username_str, attr_len);
            }
            break;

        case STUN_ATTR_ORBIS_SIGNALING:
            LOG_INFO(Lib_Net, "STUN: parsed signaling attribute ({} bytes)", attr_len);
            break;

        case STUN_ATTR_MESSAGE_INTEGRITY:
            // TODO: Verify HMAC (for now, trust the server)
            break;

        default:
            LOG_DEBUG(Lib_Net, "STUN: ignoring attr {:#06x} ({} bytes)", attr_type, attr_len);
            break;
        }

        // Advance past padded attribute
        offset += (attr_len + 3) & ~3;
    }

    result.success = has_mapped && has_source && has_changed;

    // Return extracted USERNAME to caller via out parameter.
    // Also store in last_relay_username_ for GetLastRelayUsername() callers.
    if (!username_str.empty()) {
        if (out_username) {
            *out_username = username_str;
        }
        std::lock_guard lock(mutex_);
        last_relay_username_ = username_str;
    }

    if (result.success) {
        char mapped_buf[INET_ADDRSTRLEN], source_buf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &result.mapped_addr, mapped_buf, sizeof(mapped_buf));
        inet_ntop(AF_INET, &result.source_addr, source_buf, sizeof(source_buf));
        LOG_INFO(Lib_Net, "STUN: mapped={}:{} source={}:{}", mapped_buf, ntohs(result.mapped_port),
                 source_buf, ntohs(result.source_port));
    }

    return result;
}

StunBindingResult StunClient::SendRecv(const std::vector<u8>& request, const u8* txn_id,
                                       u32 timeout_ms, int max_retries) {
    if (sock_fd_ < 0) {
        sock_fd_ = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock_fd_ < 0) {
            LOG_ERROR(Lib_Net, "STUN: failed to create socket");
            return {};
        }
        // Bind to any port
        struct sockaddr_in local{};
        local.sin_family = AF_INET;
        local.sin_addr.s_addr = INADDR_ANY;
        local.sin_port = 0;
        if (bind(sock_fd_, reinterpret_cast<struct sockaddr*>(&local), sizeof(local)) < 0) {
            LOG_ERROR(Lib_Net, "STUN: failed to bind socket");
            stun_close(sock_fd_);
            sock_fd_ = -1;
            return {};
        }
    }

    u32 server_ip = ResolveServer();
    if (server_ip == 0)
        return {};

    struct sockaddr_in server{};
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = server_ip;
    server.sin_port = htons(server_port_);

    // When using shared socket, register our txn_id so PushReceivedPacket
    // routes the response directly to us via the promise/future.
    std::future<StunBindingResult> response_future;
    if (shared_socket_) {
        response_future = RegisterPending(txn_id);
    }

    // Exponential backoff retry loop (PS4: 11 iterations, 0-10)
    u32 backoff_ms = 200; // Start at 200ms like PS4

    for (int retry = 0; retry <= max_retries; retry++) {
        if (shutting_down_.load())
            return {};

        ssize_t sent = stun_sendto(sock_fd_, request.data(), request.size(), 0,
                                   reinterpret_cast<struct sockaddr*>(&server), sizeof(server));
        if (sent < 0) {
            LOG_ERROR(Lib_Net, "STUN: sendto failed: {}", sock_strerror());
            if (shared_socket_)
                UnregisterPending(txn_id);
            return {};
        }

        if (shared_socket_) {
            // Wait on the future -- PushReceivedPacket will fulfill it when
            // a response with our txn_id arrives from Drain().
            auto status = response_future.wait_for(std::chrono::milliseconds(backoff_ms));
            if (status == std::future_status::ready) {
                auto result = response_future.get();
                if (result.success) {
                    return result;
                }
                // Got a response but it wasn't successful -- re-register for next retry
                response_future = RegisterPending(txn_id);
            }
        } else {
            // Direct socket read (no shared transport)
            u8 recv_buf[2048];
            pollfd pfd{};
            pfd.fd = sock_fd_;
            pfd.events = POLLIN;

            int poll_ret = poll(&pfd, 1, static_cast<int>(backoff_ms));
            if (poll_ret > 0 && (pfd.revents & POLLIN)) {
                struct sockaddr_in from{};
                socklen_t from_len = sizeof(from);
                ssize_t received =
                    stun_recvfrom(sock_fd_, recv_buf, sizeof(recv_buf), 0,
                                  reinterpret_cast<struct sockaddr*>(&from), &from_len);
                if (received > 0) {
                    auto result = ParseResponse(recv_buf, static_cast<size_t>(received), txn_id);
                    if (result.success) {
                        return result;
                    }
                }
            }
        }

        // Exponential backoff: 200ms -> 400ms -> 800ms -> 1600ms (max)
        backoff_ms = std::min(backoff_ms * 2, u32(1600));
    }

    // Clean up pending registration on timeout
    if (shared_socket_) {
        UnregisterPending(txn_id);
    }

    LOG_WARNING(Lib_Net, "STUN: no response after {} retries", max_retries);
    return {};
}

void StunClient::SendKeepalive() {
    if (sock_fd_ < 0)
        return;
    u32 server_ip = GetServerAddrCached();
    if (server_ip == 0) {
        server_ip = ResolveServer(); // first-time fallback
        if (server_ip == 0)
            return;
    }

    u8 txn_id[16];
    GenerateTxnId(txn_id);
    auto request = BuildRequest(txn_id);

    struct sockaddr_in server{};
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = server_ip;
    server.sin_port = htons(server_port_);

    stun_sendto(sock_fd_, request.data(), request.size(), 0,
                reinterpret_cast<struct sockaddr*>(&server), sizeof(server));
    // Response will arrive on socket -- WaitForRelay will see it but discard
    // (no USERNAME = not a relay, wrong txn_id for any pending SendRecv).
}

StunBindingResult StunClient::SendBinding(u32 change_flags) {
    u8 txn_id[16];
    GenerateTxnId(txn_id);

    auto request = BuildRequest(txn_id, 0, 0, change_flags);
    auto result = SendRecv(request, txn_id);

    if (result.success) {
        std::lock_guard lock(mutex_);
        mapped_addr_ = result.mapped_addr;
        mapped_port_ = result.mapped_port;
    }

    return result;
}

StunNatProbeResult StunClient::NatProbe() {
    LOG_INFO(Lib_Net, "STUN: starting 3-round NAT probe to {}:{}", server_host_, server_port_);

    StunNatProbeResult probe{};

    // Round 1: Basic binding -- get our mapped address
    auto r1 = SendBinding(0);
    if (!r1.success) {
        LOG_ERROR(Lib_Net, "STUN: NAT probe round 1 failed");
        return probe;
    }
    probe.mapped_addr = r1.mapped_addr;
    probe.mapped_port = r1.mapped_port;

    // Round 2: Another binding -- compare mapped ports.
    // NOTE: This sends to the same server address as round 1. Symmetric NAT
    // (which allocates per-destination) will return the same mapped port, so
    // symmetric NAT is never detected here. True detection requires sending
    // to CHANGED-ADDRESS from round 1 (different server IP), which our server
    // doesn't support. Server-side relay handles this transparently at runtime.
    auto r2 = SendBinding(0);
    if (!r2.success) {
        LOG_WARNING(Lib_Net, "STUN: NAT probe round 2 failed, assuming moderate NAT");
        probe.success = true;
        probe.nat_type = StunNatType::Moderate;
        return probe;
    }

    if (r1.mapped_port != r2.mapped_port) {
        // Different mapped ports -> symmetric NAT
        probe.nat_type = StunNatType::Strict;
        LOG_INFO(Lib_Net, "STUN: symmetric NAT detected (ports differ: {} vs {})",
                 ntohs(r1.mapped_port), ntohs(r2.mapped_port));
    } else {
        // Same mapped port -> cone NAT (open or restricted)
        probe.nat_type = StunNatType::Open;
        LOG_INFO(Lib_Net, "STUN: cone NAT detected (consistent mapped port)");
    }

    // Round 3: Change port test
    auto r3 = SendBinding(0x00000002); // CHANGE-REQUEST: change port
    if (!r3.success) {
        // Server couldn't respond from different port -- restricted cone
        if (probe.nat_type == StunNatType::Open) {
            probe.nat_type = StunNatType::Moderate;
            LOG_INFO(Lib_Net, "STUN: port-restricted cone NAT (change-port failed)");
        }
    }

    probe.success = true;

    char buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &probe.mapped_addr, buf, sizeof(buf));
    LOG_INFO(Lib_Net, "STUN: NAT probe complete: mapped={}:{} type={}", buf,
             ntohs(probe.mapped_port), static_cast<int>(probe.nat_type));

    return probe;
}

StunBindingResult StunClient::SendOffer(u32 peer_addr, u16 peer_port,
                                        const std::vector<u8>& username_data,
                                        const std::vector<u8>& signaling_data) {
    // OFFER exchange:
    //   Round 1: Normal binding -> get our mapped address
    //   Round 2: Binding with RESPONSE-ADDRESS=peer -> server relays to peer
    //            (no response comes back to us -- the server sends it to RESPONSE-ADDRESS)
    //   Wait:    recvfrom for incoming ACCEPT from peer (handled by SignalingThreadFunc)

    // Step 1: Get our mapped address.
    // Use cached result from NatProbe if available (avoids re-probing which
    // can fail due to Drain() timing when using shared socket).
    StunBindingResult binding{};
    {
        std::lock_guard lock(mutex_);
        if (mapped_addr_ != 0) {
            binding.success = true;
            binding.mapped_addr = mapped_addr_;
            binding.mapped_port = mapped_port_;
        }
    }
    if (!binding.success) {
        binding = SendBinding(0);
        if (!binding.success) {
            LOG_ERROR(Lib_Net, "STUN OFFER: initial binding failed");
            return {};
        }
    }

    // Step 2: Send OFFER with RESPONSE-ADDRESS pointing to peer.
    // The STUN server relays the response to the peer -- we don't get a response.
    // Just sendto() without waiting (fire-and-forget to the server).
    if (sock_fd_ < 0) {
        LOG_ERROR(Lib_Net, "STUN OFFER: no socket");
        return binding; // Return binding result even if relay fails
    }

    u8 txn_id[16];
    GenerateTxnId(txn_id);
    auto offer_req = BuildRequest(txn_id, peer_addr, peer_port,
                                  0, // No CHANGE-REQUEST for relay
                                  username_data, signaling_data);

    u32 server_ip = ResolveServer();
    if (server_ip == 0) {
        return binding;
    }

    struct sockaddr_in server{};
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = server_ip;
    server.sin_port = htons(server_port_);

    ssize_t sent = stun_sendto(sock_fd_, offer_req.data(), offer_req.size(), 0,
                               reinterpret_cast<struct sockaddr*>(&server), sizeof(server));

    char peer_buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &peer_addr, peer_buf, sizeof(peer_buf));
    if (sent > 0) {
        LOG_INFO(Lib_Net,
                 "STUN OFFER: sent relay request to server for peer {}:{} "
                 "(our mapped={}:{})",
                 peer_buf, ntohs(peer_port), "", ntohs(binding.mapped_port));
    } else {
        LOG_ERROR(Lib_Net, "STUN OFFER: sendto failed for peer {}:{}: {}", peer_buf,
                  ntohs(peer_port), sock_strerror());
    }

    return binding;
}

StunBindingResult StunClient::SendAccept(u32 peer_addr, u16 peer_port,
                                         const std::vector<u8>& username_data,
                                         const std::vector<u8>& signaling_data) {
    // ACCEPT exchange: single binding request with RESPONSE-ADDRESS=offering_peer.
    // Server relays the response to the peer (fire-and-forget, no response back).

    if (sock_fd_ < 0) {
        LOG_ERROR(Lib_Net, "STUN ACCEPT: no socket");
        return {};
    }

    u8 txn_id[16];
    GenerateTxnId(txn_id);
    auto accept_req = BuildRequest(txn_id, peer_addr, peer_port,
                                   0, // No CHANGE-REQUEST for ACCEPT
                                   username_data, signaling_data);

    u32 server_ip = ResolveServer();
    if (server_ip == 0) {
        return {};
    }

    struct sockaddr_in server{};
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = server_ip;
    server.sin_port = htons(server_port_);

    ssize_t sent = stun_sendto(sock_fd_, accept_req.data(), accept_req.size(), 0,
                               reinterpret_cast<struct sockaddr*>(&server), sizeof(server));

    StunBindingResult result{};
    char peer_buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &peer_addr, peer_buf, sizeof(peer_buf));
    if (sent > 0) {
        result.success = true;
        LOG_INFO(Lib_Net, "STUN ACCEPT: sent relay request to server for peer {}:{}", peer_buf,
                 ntohs(peer_port));
    } else {
        LOG_ERROR(Lib_Net, "STUN ACCEPT: sendto failed for peer {}:{}: {}", peer_buf,
                  ntohs(peer_port), sock_strerror());
    }

    return result;
}

StunBindingResult StunClient::WaitForRelay(u32 timeout_ms) {
    if (shutting_down_.load())
        return {};

    // With txn-id routing, relay_queue_ receives ONLY unsolicited STUN
    // responses with USERNAME (incoming OFFER/ACCEPT from peers).
    // No dual-path socket reading needed -- PushReceivedPacket handles routing.
    std::unique_lock lock(relay_mutex_);
    if (relay_cv_.wait_for(lock, std::chrono::milliseconds(timeout_ms),
                           [this] { return !relay_queue_.empty() || shutting_down_.load(); })) {
        if (shutting_down_.load())
            return {};
        auto msg = std::move(relay_queue_.front());
        relay_queue_.pop_front();
        lock.unlock();

        // Parse with the packet's own txn_id (relaxed -- we accept any txn for relays)
        u8 any_txn[16] = {};
        if (msg.data.size() >= STUN_HEADER_SIZE) {
            std::memcpy(any_txn, msg.data.data() + 4, 16);
        }
        return ParseResponse(msg.data.data(), msg.data.size(), any_txn);
    }
    return {};
}

u32 StunClient::GetServerAddrCached() {
    if (cached_server_addr_ != 0)
        return cached_server_addr_;
    cached_server_addr_ = ResolveServer();
    return cached_server_addr_;
}

} // namespace Libraries::Net
