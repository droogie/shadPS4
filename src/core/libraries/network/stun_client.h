// SPDX-FileCopyrightText: Copyright 2026 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

// STUN client (RFC 3489) for NpSignaling: NAT probing, OFFER/ACCEPT relay,
// and HMAC-SHA1 message integrity. See docs/psn_stun_signaling_protocol.md.

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <future>
#include <mutex>
#include <string>
#include <vector>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <netinet/in.h>
#endif

#include "common/types.h"

namespace Libraries::Net {

// STUN message types
constexpr u16 STUN_BINDING_REQUEST = 0x0001;
constexpr u16 STUN_BINDING_RESPONSE = 0x0101;
constexpr u16 STUN_BINDING_ERROR = 0x0111;

// STUN header size (msg_type + msg_len + 16-byte txn_id)
constexpr size_t STUN_HEADER_SIZE = 20;

// Standard STUN attributes (RFC 3489)
constexpr u16 STUN_ATTR_MAPPED_ADDRESS = 0x0001;
constexpr u16 STUN_ATTR_RESPONSE_ADDRESS = 0x0002;
constexpr u16 STUN_ATTR_CHANGE_REQUEST = 0x0003;
constexpr u16 STUN_ATTR_SOURCE_ADDRESS = 0x0004;
constexpr u16 STUN_ATTR_CHANGED_ADDRESS = 0x0005;
constexpr u16 STUN_ATTR_USERNAME = 0x0006;
constexpr u16 STUN_ATTR_MESSAGE_INTEGRITY = 0x0008;

// Proprietary attributes
constexpr u16 STUN_ATTR_ORBIS_UNKNOWN_0021 = 0x0021;
constexpr u16 STUN_ATTR_XOR_MAPPED_ADDRESS = 0x8020;
constexpr u16 STUN_ATTR_ORBIS_SIGNALING = 0x8099;

// NAT type results
enum class StunNatType {
    Unknown = 0,
    Open = 1,     // No NAT / full cone
    Moderate = 2, // Restricted cone / port-restricted cone
    Strict = 3,   // Symmetric NAT
};

// Result of a STUN binding response
struct StunBindingResult {
    bool success{false};
    u32 mapped_addr{0}; // IPv4 in network byte order
    u16 mapped_port{0}; // port in network byte order
    u32 source_addr{0}; // server's source address
    u16 source_port{0};
    u32 changed_addr{0}; // server's alternate address
    u16 changed_port{0};
    std::string username;  // USERNAME attribute extracted from the response.
                           // Required because multiple relay responses can
                           // queue up in rapid succession (4+ peer sessions);
                           // a shared last_relay_username_ global loses the
                           // per-packet association and misroutes the relay.
};

// Result of NAT probing
struct StunNatProbeResult {
    bool success{false};
    StunNatType nat_type{StunNatType::Unknown};
    u32 mapped_addr{0}; // our reflexive address (NBO)
    u16 mapped_port{0}; // our reflexive port (NBO)
};

// TLV attribute for building/parsing STUN messages
struct StunAttr {
    u16 type;
    std::vector<u8> value;
};

class StunClient {
public:
    StunClient();
    ~StunClient();

    // Configure the STUN server address.
    // Default: "stun.playstation.net" port 3478.
    // Can be overridden via SHADPS4_STUN_SERVER env var.
    void SetServer(const std::string& host, u16 port = 3478);

    // Perform a 3-round NAT probe (blocking).
    // Returns the mapped address and NAT type.
    StunNatProbeResult NatProbe();

    // Send a single STUN binding request and get the response (blocking).
    // change_flags: CHANGE-REQUEST flags (0=none, 2=change port, 4=change IP, 6=both)
    StunBindingResult SendBinding(u32 change_flags = 0);

    // Send OFFER to a peer via STUN relay (blocking).
    // The STUN server will forward the response to the peer's address.
    // Returns the mapped address from the response.
    StunBindingResult SendOffer(u32 peer_addr, u16 peer_port,
                                const std::vector<u8>& username_data = {},
                                const std::vector<u8>& signaling_data = {});

    // Send ACCEPT to a peer via STUN relay (blocking).
    StunBindingResult SendAccept(u32 peer_addr, u16 peer_port,
                                 const std::vector<u8>& username_data = {},
                                 const std::vector<u8>& signaling_data = {});

    // Wait for an incoming STUN response (from a peer's OFFER/ACCEPT relay).
    // Listens on the same socket used for SendBinding.
    // Returns parsed result, or failure after timeout.
    StunBindingResult WaitForRelay(u32 timeout_ms = 3000);

    // Get the last known mapped address (from most recent probe/binding).
    u32 GetMappedAddr() const;
    u16 GetMappedPort() const;
    int GetSocketFd() const {
        return sock_fd_;
    }
    u16 GetServerPort() const {
        return server_port_;
    }
    u32 GetServerAddrCached();

    // Send a binding request to the STUN server without waiting for response.
    // Used as NAT keepalive -- the response arrives on the socket and gets
    // discarded by WaitForRelay (wrong txn_id or no USERNAME).
    void SendKeepalive();

    // Get the USERNAME extracted from the last received relay response.
    // Returns the peer's NpId string (up to 16 bytes, null-trimmed).
    // Used by SignalingThreadFunc to identify which peer sent the OFFER.
    std::string GetLastRelayUsername() const;

private:
    // Build a STUN Binding Request packet.
    std::vector<u8> BuildRequest(const u8* txn_id, u32 response_addr = 0, u16 response_port = 0,
                                 u32 change_flags = 0, const std::vector<u8>& username = {},
                                 const std::vector<u8>& signaling = {});

    // Parse a STUN Binding Response. Extracts USERNAME into out_username if non-null.
    StunBindingResult ParseResponse(const u8* data, size_t len, const u8* expected_txn,
                                    std::string* out_username = nullptr);

    // Build an address attribute value (MAPPED-ADDRESS format).
    static std::vector<u8> BuildAddrAttr(u32 addr_nbo, u16 port_nbo);

    // Compute HMAC-SHA1 over the message.
    static std::vector<u8> ComputeHmac(const u8* data, size_t len);

    // Generate random transaction ID.
    static void GenerateTxnId(u8* out);

    // Resolve server hostname to IP address.
    u32 ResolveServer();

    // Send a request and wait for matching response with retries (PS4: 11 iterations).
    StunBindingResult SendRecv(const std::vector<u8>& request, const u8* txn_id,
                               u32 timeout_ms = 2000, int max_retries = 5);

    // Register a pending transaction and return a future for the result.
    // PushReceivedPacket routes responses by txn_id to the correct waiter.
    std::future<StunBindingResult> RegisterPending(const u8* txn_id);

    // Remove a pending request (on timeout/completion).
    void UnregisterPending(const u8* txn_id);

    std::string server_host_{"stun.playstation.net"};
    u16 server_port_{3478};
    int sock_fd_{-1};
    bool shared_socket_{false}; // true = socket owned externally (don't close)

    // Transaction-ID based routing.
    // PushReceivedPacket matches incoming STUN responses against pending requests
    // by txn_id. Matched responses fulfill the caller's promise. Unmatched
    // responses with USERNAME are relayed (incoming OFFER/ACCEPT from peers).
    struct QueuedMsg {
        std::vector<u8> data;
        sockaddr_in from;
        std::string username; // Extracted USERNAME (peer NpId) if present
    };

    struct PendingRequest {
        u8 txn_id[16];
        std::promise<StunBindingResult> promise;
    };
    std::mutex pending_mutex_;
    std::vector<PendingRequest> pending_requests_;

    // Relay queue -- unsolicited STUN responses with USERNAME (incoming OFFER/ACCEPT).
    std::mutex relay_mutex_;
    std::condition_variable relay_cv_;
    std::deque<QueuedMsg> relay_queue_;

    // Cached results
    mutable std::mutex mutex_;
    u32 mapped_addr_{0};
    u16 mapped_port_{0};
    StunNatType nat_type_{StunNatType::Unknown};
    std::string last_relay_username_;        // USERNAME from last received relay
    u32 cached_server_addr_{0};              // Cached resolved server IP (NBO)
    std::atomic<bool> shutting_down_{false}; // Signals WaitForRelay/PushReceivedPacket to stop

public:
    // Set an external shared socket (owned by P2P transport).
    // STUN sends/receives through this socket. The P2P transport's receive
    // loop routes STUN packets to PushReceivedPacket().
    void SetSharedSocket(int fd);

    // Called by P2P transport when it receives a non-P2P packet (STUN response).
    void PushReceivedPacket(const u8* data, size_t len, const sockaddr_in& from);
};

} // namespace Libraries::Net
