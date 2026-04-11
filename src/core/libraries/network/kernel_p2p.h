// SPDX-FileCopyrightText: Copyright 2025-2026 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

// KernelP2PSubsystem -- Centralized P2P peer tracking and event delivery.
// Replaces scattered connection logic across NpSignaling/NpMatching2 HLE.

#include <atomic>
#include <chrono>
#include <deque>
#include <functional>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <netinet/in.h>
#endif

#include "common/types.h"

namespace Libraries::Net {

class StunClient;

// Signaling event callback type (matches OrbisNpSignalingHandler signature).
using SignalingEventCallback = std::function<void(s32 conn_id, s32 event)>;

// Connection info types for sceNpSignalingGetConnectionInfo.
enum OrbisNpSignalingConnInfoType : s32 {
    CONN_INFO_RTT = 1,
    CONN_INFO_BANDWIDTH = 2,
    CONN_INFO_PEER_NP_ID = 3,
    CONN_INFO_PEER_ADDR = 4,
    CONN_INFO_MAPPED_ADDR = 5,
    CONN_INFO_PACKET_LOSS = 6,
};

// Address written by PEER_ADDR / MAPPED_ADDR info types.
struct OrbisNetSignalingAddr {
    u32 addr;
    u16 port;
    u8 _pad[2];
};

class KernelP2PSubsystem {
public:
    static KernelP2PSubsystem& Instance();

    // === Ioctl Interface (called by sceNetIoctl HLE) ===
    int HandleIoctl(int fd, u32 code, void* buf);

    // === Peer/Connection Management ===

    // Activate a peer connection. Returns conn_id (positive) on success.
    // If a connection already exists for this npid, returns existing conn_id (idempotent).
    // If peer data (addr/port) is available, transitions immediately to ACTIVE and
    // schedules ESTABLISHED event. Otherwise, stays PENDING until peer data arrives.
    s32 ActivatePeer(s32 ctx_id, const std::string& npid);

    // Deactivate a peer connection. Marks as INACTIVE but preserves the entry.
    int DeactivatePeer(s32 conn_id);

    // Remove a peer connection entirely by NpId (for rejoin support).
    // Erases from both connections_ and npid_to_conn_ so that a subsequent
    // ActivatePeer for the same NpId creates a completely fresh connection.
    void RemoveConnectionByNpid(const std::string& npid);

    // Get connection status and peer address.
    // Returns ORBIS_NP_SIGNALING_CONN_STATUS_* values.
    // Firmware behavior: immediate state read, no gates or delays.
    int GetConnectionStatus(s32 conn_id, s32* status_out, u32* addr_out, u16* port_out);

    // Get connection info by type (RTT, bandwidth, peer NpId, peer addr, etc.)
    int GetConnectionInfo(s32 conn_id, s32 info_type, void* info);

    // Count of active remote peers (non-local, non-zero address).
    // Used to detect multi-peer sessions for routing decisions.
    int GetActivePeerCount() const;

    // Get any active remote peer (for P2P address resolution when game sends to 0.0.0.0:0).
    // Skips the local address to find the REMOTE peer.
    // WARNING: Returns first match only — unreliable with 2+ peers.
    bool GetActivePeerAddr(u32* addr_out, u16* port_out);

    // Resolve a peer's P2P port by address from the tunnel table.
    // Returns true if a matching peer was found and port_out was set.
    bool ResolvePeerPort(u32 addr, u16* port_out);

    u16 GetMyMemberId() const {
        return my_member_id_;
    }

    // Send a raw signaling packet to a peer (used for ActivatePacket).
    void SendSignalingPacket(const u8* data, size_t len, u32 peer_addr_nbo, u16 peer_port_nbo);

    // Handle incoming ActivatePacket from a peer.
    // Posts /np/signaling/confirm to the server to complete bilateral handshake.
    void HandleActivatePacket(u32 from_addr, u16 from_port, u32 peer_conn_id, u32 ctx_tag);

    // === Peer Data Updates ===

    // Set peer info when a room member's network data becomes available.
    // If a PENDING connection exists for this npid, transitions to ACTIVE and fires ESTABLISHED.
    // established_delay_ms: when > 0 and peer is non-self, defer ESTABLISHED event by this
    // amount (emulates STUN/NAT traversal delay). 0 = fire immediately (self, HOST).
    void SetPeerInfo(u16 member_id, u32 addr, u16 port, const std::string& npid,
                     u32 established_delay_ms = 0);

    // Remove a specific peer (on room member departure).
    // Fires DEAD event for any active connection to this peer.
    void RemovePeer(u16 member_id);

    // Clear all connections and peer data (on LeaveRoom / session cleanup).
    void ClearAll();

    // Get the memberId for a connection. Returns 0 if not found.
    // Used by NpSignaling event bridge to translate connId -> memberId.
    u16 GetMemberIdForConn(s32 conn_id) const;

    // Read-only lookup: translate NpId -> conn_id without side effects.
    // Returns 0 if no connection exists for this NpId.
    // Used by sceNpMatching2SignalingGetConnectionStatus (pure read).
    s32 GetConnIdByNpid(const std::string& npid) const;

    // Get the npid for a kernel conn_id. Returns empty string if not found.
    // Used by KernelEventBridge to map kernel events to NpSignaling connections.
    std::string GetNpidForConn(s32 conn_id) const;

    // === Local Identity ===

    // Set local player's signaling address (for self-connection fast path).
    // Called during NpSignaling context creation.
    void SetLocalIdentity(u32 addr, u16 port, const std::string& npid);
    u32 GetLocalAddr() const;
    u16 GetLocalPort() const;

    // === Signaling Callback Registration ===

    // Register the NpSignaling callback for event delivery.
    // The kernel subsystem delivers events through this callback instead of
    // having scattered HLE code fire events at arbitrary points.
    void RegisterSignalingCallback(
        s32 ctx_id, std::function<void(s32 ctx_id, s32 conn_id, s32 event, u32 delay_ms)> callback);
    void UnregisterSignalingCallback(s32 ctx_id);
    void ClearSignalingCallbacks();

    // === Ioctl Gate ===

    // Enable the signaling gate (from ioctl Initialize with byte 0x23=0x02).
    // Must be enabled for signaling events to be delivered.
    void EnableGate();
    bool IsGateEnabled() const;

    // === Session Lifecycle ===

    // Notify kernel subsystem of room join (updates internal session state).
    void OnRoomJoined(u64 room_id, u16 my_member_id);
    void OnRoomLeft();

    // === State Query ===
    u64 GetCurrentRoomId() const;

    // === STUN Signaling Integration ===

    // Inject the STUN client for OFFER/ACCEPT signaling.
    // Called during NpSignaling context creation.
    void SetStunClient(StunClient* client);

    // Get the STUN client (for NpMatching2 to send mapped addr in requests).
    StunClient* GetStunClient() const;

    // Check if STUN exchange is complete for a connection.
    bool IsStunComplete(s32 conn_id) const;

    // Notify that a P2P packet was received from a peer address.
    // On LAN (no STUN), this provides bilateral confirmation:
    // receiving a packet from the peer proves their tunnel is active,
    // triggering MUTUAL_ACTIVATED.
    void OnPeerPacketReceived(u32 peer_addr);

    // Start the signaling thread for NAT probe, STUN OFFER/ACCEPT, and keepalives.
    // Called from sceNpSignalingInitialize.
    void StartSignalingThread();

    // Stop the signaling thread.
    // Called from sceNpSignalingTerminate.
    void StopSignalingThread();

    // Queue a STUN OFFER for processing by the signaling thread.
    // Called from SetPeerInfo instead of spawning a detached thread.
    void QueueStunOffer(s32 ctx_id, s32 conn_id, u32 peer_addr, u16 peer_port,
                        const std::string& peer_npid);

    // Translate relay source using the sender's NpId from FD-tagged packets.
    // The STUN server tags each forwarded packet with the sender's NpId in a
    // [0xFE][len][npid] header. This function looks up the correct peer by
    // exact NpId match, supporting multi-peer relay disambiguation.
    bool TranslateRelaySourceByNpid(const std::string& sender_npid, u32* peer_addr_out,
                                    u16* peer_port_out);

    // === Kernel P2P Vport Translation (cross-platform) ===

    // Check if a packet on an unbound vport should be forwarded to a bound vport.
    // Each vport is independently demultiplexed in the kernel. For cross-platform
    // play, the console sends on vport 30 but our game only binds vport 40.
    // We translate inbound vport 30 -> deliver to vport 40 with full payload intact.
    // Returns true if the packet should be forwarded to a bound vport.
    bool ShouldForwardUnboundPacket(u16 vport_nbo, const sockaddr_in& from);

    // Check if a peer is a console peer (communicates only on unbound vports).
    // Used by SendPacket for outbound vport translation (vport 40 -> vport 30).
    bool IsPS4Peer(u32 peer_addr) const;

    // Clear console peer classification for a specific peer.
    // Called when a relay tag confirms the peer is an emulator (not console).
    void ClearPS4PeerClassification(u32 peer_addr);

    // Notify that a game socket has bound a vport (kernel handler yields).
    void OnVportBound(u16 vport_nbo);

    // === Reset (for Terminate) ===
    void Reset();

private:
    KernelP2PSubsystem() = default;

    // Connection state machine: INACTIVE -> PENDING -> ACTIVE
    // Matches the kernel's internal state tracking.
    enum class ConnState {
        INACTIVE = 0,
        PENDING = 1, // ActivatePeer called, but peer addr not yet known
        ACTIVE = 2,  // Peer addr known, ESTABLISHED event delivered
    };

    // STUN NAT traversal state for a peer connection.
    // Tracks whether STUN OFFER/ACCEPT exchange has completed, providing
    // verified NAT-mapped addresses for remote play across NATs.
    enum class StunState {
        NONE,     // Self-connection or STUN disabled (LAN mode)
        PENDING,  // OFFER sent, waiting for ACCEPT
        COMPLETE, // STUN exchange succeeded -- use mapped addr
        FAILED,   // STUN timed out -- fallback to server-reported addr
    };

    struct PeerConnection {
        s32 conn_id{0};
        s32 ctx_id{0};
        u32 addr{0};        // IPv4 in network byte order (server-reported)
        u16 port{0};        // port in network byte order (server-reported)
        u32 mapped_addr{0}; // STUN-resolved external address (NBO)
        u16 mapped_port{0}; // STUN-resolved external port (NBO)
        std::string npid;
        ConnState state{ConnState::INACTIVE};
        ConnState prev_state{ConnState::INACTIVE}; // firmware pattern: sub_4089f0 saves old state
        StunState stun_state{StunState::NONE};

        // Event tracking flags (orthogonal concerns, see Phase 3 audit).
        bool events_fired{false}; // ESTABLISHED callback has been delivered
        bool mutual_fired{false}; // MUTUAL_ACTIVATED callback has been delivered
        bool game_activated{false}; // game called sceNpSignalingActivateConnection

        // Firmware-style timestamps (sub_4089f0 pattern: records time of each state change).
        std::chrono::steady_clock::time_point state_changed_at{}; // when state last changed
        std::chrono::steady_clock::time_point last_event_time{};  // when last event was fired

        // Echo probe state for bilateral connectivity confirmation.
        // Firmware: SceNpMatching2SigEcho thread, 200ms tick (callout 0x30d40 us),
        // 60s keepalive after ESTABLISHED, 30s connection timeout.
        bool echo_started{false};       // probes are being sent
        int echo_probes_sent{0};        // total probes sent
        int echo_responses_received{0}; // responses from peer
        bool echo_bilateral{false};     // bilateral confirmation achieved (>= 3 responses)
        std::chrono::steady_clock::time_point last_echo_sent{};
        std::chrono::steady_clock::time_point echo_start_at{}; // when probing began
        s32 rtt_us{0};        // measured round-trip time in microseconds
        s32 bandwidth_bps{0}; // computed bandwidth in bytes/sec
        std::chrono::steady_clock::time_point last_echo_recv{};
    };

    struct PeerInfo {
        u16 member_id{0};
        u32 addr{0};
        u16 port{0};
        std::string npid;
    };

    // Fire ESTABLISHED event for a connection (via registered callback).
    void FireEstablished(s32 ctx_id, s32 conn_id, u32 delay_ms);
    // Fire DEAD event for a connection.
    void FireDead(s32 ctx_id, s32 conn_id, u32 delay_ms);
    // Fire MUTUAL_ACTIVATED event (both peers have P2P tunnel up).
    void FireMutualActivated(s32 ctx_id, s32 conn_id, u32 delay_ms);

    mutable std::mutex mutex_;

    // Connection tracking (replaces NpSignaling's s_connections + s_npid_to_conn)
    std::map<s32, PeerConnection> connections_; // conn_id -> connection
    std::map<std::string, s32> npid_to_conn_;   // npid -> conn_id (dedup)
    s32 next_conn_id_{1};

    // Peer info (replaces NpSignaling's s_peers)
    std::map<u16, PeerInfo> peers_; // member_id -> peer info

    // Local identity (for self-connection fast path)
    u32 local_addr_{0x0100007f}; // 127.0.0.1 NBO default
    u16 local_port_{0x4A0E};     // 3658 NBO (ORBIS_NP_PORT)
    std::string local_npid_;

    // Signaling callbacks (one per context, replaces NpSignaling's callback dispatch)
    struct CallbackInfo {
        std::function<void(s32 ctx_id, s32 conn_id, s32 event, u32 delay_ms)> callback;
    };
    std::map<s32, CallbackInfo> sig_callbacks_;

    // Session state
    u64 current_room_id_{0};
    u16 my_member_id_{0};
    bool gate_enabled_{false};

    // STUN signaling -- single signaling thread for echo/STUN/keepalive
    std::atomic<StunClient*> stun_client_{nullptr};
    std::thread signaling_thread_;
    std::atomic<bool> signaling_shutdown_{false};
    std::atomic<bool> nat_probe_succeeded_{false};

    // Signaling thread main function.
    // Phase A: NAT probe (blocking, one-shot)
    // Phase B: processing loop -- dequeue offers, echo probes, keepalive
    void SignalingThreadFunc();

    // Process a single STUN OFFER synchronously (called from signaling thread).
    void ProcessStunOffer(s32 ctx_id, s32 conn_id, u32 peer_addr, u16 peer_port,
                          const std::string& peer_npid);

    // Echo probe processing for bilateral connectivity confirmation.
    // Sends type 0x06 probes, processes type 0x07 responses.
    // When both sides have responded, fires ESTABLISHED + MUTUAL_ACTIVATED.
    void SendEchoProbes();
    static constexpr u16 ECHO_VPORT = 0xFFFD; // kernel-reserved vport for echo probes

public:
    // Called from P2P transport Drain() when an echo probe packet arrives.
    void ProcessEchoProbe(u32 from_addr, u16 from_port, const u8* data, size_t len);

private:
    // Pending OFFER queue -- SetPeerInfo pushes, signaling thread processes.
    // Protected by mutex_ (consolidated from separate offer_queue_mutex_).
    struct PendingOffer {
        s32 ctx_id;
        s32 conn_id;
        u32 peer_addr;
        u16 peer_port;
        std::string peer_npid;
    };
    std::deque<PendingOffer> offer_queue_;

    // Peer classification state (console vs emulator).
    // Emulator peers send on both vport 30 and vport 40; console peers only vport 30.
    // Grace period before classifying lets Drain() see vport 40 traffic.
    struct PeerClassification {
        std::chrono::steady_clock::time_point first_seen_at{};
        bool classified{false}; // true = confirmed console peer (vport 30 only)
    };
    std::map<u32, PeerClassification> peer_classifications_; // peer_ip(NBO) -> state
    std::set<u16> bound_vports_;                             // vports claimed by game sockets (NBO)
};

} // namespace Libraries::Net
