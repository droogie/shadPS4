// SPDX-FileCopyrightText: Copyright 2025 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include <string>
#include "common/types.h"

namespace Libraries::Net {
class StunClient;
}

namespace Core::Loader {
class SymbolsResolver;
}

namespace Libraries::Np::NpSignaling {

// NpSignaling HLE -- delegates connection state to KernelP2PSubsystem.
// Handles PS4 API compatibility, callback delivery, and context management.

using OrbisNpSignalingHandler = PS4_SYSV_ABI void (*)(u32 ctxId, u32 connId, s32 event,
                                                      s32 errorCode, void* userArg);

constexpr s32 ORBIS_NP_SIGNALING_EVENT_DEAD = 0;
constexpr s32 ORBIS_NP_SIGNALING_EVENT_ESTABLISHED = 1;
constexpr s32 ORBIS_NP_SIGNALING_EVENT_NETINFO_ERROR = 2;
constexpr s32 ORBIS_NP_SIGNALING_EVENT_NETINFO_RESULT = 3;
constexpr s32 ORBIS_NP_SIGNALING_EVENT_PEER_ACTIVATED = 10;
constexpr s32 ORBIS_NP_SIGNALING_EVENT_PEER_DEACTIVATED = 11;
constexpr s32 ORBIS_NP_SIGNALING_EVENT_MUTUAL_ACTIVATED = 12;

constexpr s32 ORBIS_NP_SIGNALING_CONN_STATUS_INACTIVE = 0;
constexpr s32 ORBIS_NP_SIGNALING_CONN_STATUS_PENDING = 1;
constexpr s32 ORBIS_NP_SIGNALING_CONN_STATUS_ACTIVE = 2;

constexpr s32 ORBIS_NP_SIGNALING_CONN_INFO_RTT = 1;
constexpr s32 ORBIS_NP_SIGNALING_CONN_INFO_BANDWIDTH = 2;
constexpr s32 ORBIS_NP_SIGNALING_CONN_INFO_PEER_NP_ID = 3;
constexpr s32 ORBIS_NP_SIGNALING_CONN_INFO_PEER_ADDR = 4;
constexpr s32 ORBIS_NP_SIGNALING_CONN_INFO_MAPPED_ADDR = 5;
constexpr s32 ORBIS_NP_SIGNALING_CONN_INFO_PACKET_LOSS = 6;

struct OrbisNpSignalingNetInfo {
    u64 size;       // +0x00: must be sizeof(OrbisNpSignalingNetInfo) = 0x18
    u32 localAddr;  // +0x08
    u32 mappedAddr; // +0x0C
    s32 natStatus;  // +0x10
    u32 _pad_14;    // +0x14
};
static_assert(sizeof(OrbisNpSignalingNetInfo) == 0x18);

// --- Peer info API (delegates to KernelP2PSubsystem) ---

struct NpSignalingPeerInfo {
    u32 addr = 0; // IPv4 in network byte order
    u16 port = 0; // port in network byte order
    s32 status = ORBIS_NP_SIGNALING_CONN_STATUS_INACTIVE;
    u16 member_id = 0;
    std::string online_id; // PSN online ID for NpId matching
};

// Set peer info -- delegates to KernelP2PSubsystem::SetPeerInfo().
void SetPeerInfo(u16 member_id, u32 addr, u16 port, const std::string& online_id = "",
                 u32 established_delay_ms = 0);

// Get peer info for signaling status queries (thin wrapper over kernel subsystem).
NpSignalingPeerInfo GetPeerInfo(u16 member_id = 0);

// Get any active peer (delegates to KernelP2PSubsystem::GetActivePeerAddr()).
NpSignalingPeerInfo GetAnyActivePeer();

// Clear all connection state (delegates to KernelP2PSubsystem::ClearAll()).
void ClearConnections();

// Set/get local signaling address (delegates to KernelP2PSubsystem::SetLocalIdentity()).
void SetLocalAddr(u32 addr, u16 port);
u32 GetLocalAddr();
u16 GetLocalPort();

// Connection state machine driven by echo probes and server bilateral confirmation.
// Maps to API status: 0xa=ACTIVE(2), 0=IDLE(0), else=PENDING(1).
constexpr s32 SIG_STATE_IDLE = 0;
constexpr s32 SIG_STATE_PENDING = 1;
constexpr s32 SIG_STATE_STUN_BIND = 3;
constexpr s32 SIG_STATE_STUN_KEEPALIVE = 4;
constexpr s32 SIG_STATE_ECHO_PROBE = 5;
constexpr s32 SIG_STATE_PEER_INFO_WAIT = 6;
constexpr s32 SIG_STATE_PEER_INFO_RECV = 7;
constexpr s32 SIG_STATE_ESTABLISHING = 8;
constexpr s32 SIG_STATE_ESTABLISHING_BILATERAL = 9;
constexpr s32 SIG_STATE_ACTIVE = 0xa;

// Set ALL connections for a peer to IDLE (called on member departure).
void SetConnectionInactive(const std::string& npid);

// Ensure a sig connection exists for a peer (creates if needed).
void EnsureSigConnection(s32 ctx_id, const std::string& npid);

// Remove all connections for a peer entirely (erases entry for clean rejoin).
void RemoveConnection(const std::string& npid);

// Get conn_id for a peer npid. Returns 0 if not found.
s32 GetSignalingConnId(const std::string& npid);

// Get npid for a conn_id. Returns empty string if not found.
std::string GetNpidForConnId(s32 conn_id);

// Get connection status. Returns 0 if found (status/addr/port filled), non-zero if not found.
s32 GetSignalingStatus(s32 connId, s32* status, u32* addr, u16* port);

// Set server_confirmed flag on a connection (called from HandleSignalingEstablished).
// Advances the state machine if in an appropriate state.
void SetServerConfirmed(const std::string& npid);

// Tick a connection's state machine (called from KernelEventBridge).
// echo_event: 1=ESTABLISHED (echo bilateral), 0xc=MUTUAL_ACTIVATED, -1=tick only
void TickConnection(s32 conn_id, s32 echo_event);

// --- PS4 API functions ---

s32 PS4_SYSV_ABI sceNpSignalingActivateConnection(s32 ctxId, void* npId, s32* connId);
s32 PS4_SYSV_ABI sceNpSignalingActivateConnectionA();
s32 PS4_SYSV_ABI sceNpSignalingCancelPeerNetInfo();
s32 PS4_SYSV_ABI sceNpSignalingCreateContext(const void* npId, void* handler, void* arg,
                                             s32* context_id);
s32 PS4_SYSV_ABI sceNpSignalingCreateContextA();
s32 PS4_SYSV_ABI sceNpSignalingDeactivateConnection(s32 ctxId, s32 connId);
s32 PS4_SYSV_ABI sceNpSignalingDeleteContext(s32 ctxId);
s32 PS4_SYSV_ABI sceNpSignalingGetConnectionFromNpId();
s32 PS4_SYSV_ABI sceNpSignalingGetConnectionFromPeerAddress();
s32 PS4_SYSV_ABI sceNpSignalingGetConnectionFromPeerAddressA();
s32 PS4_SYSV_ABI sceNpSignalingGetConnectionInfo(s32 ctxId, s32 connId, s32 infoType, void* info);
s32 PS4_SYSV_ABI sceNpSignalingGetConnectionInfoA();
s32 PS4_SYSV_ABI sceNpSignalingGetConnectionStatistics();
s32 PS4_SYSV_ABI sceNpSignalingGetConnectionStatus(s32 ctxId, s32 connId, s32* connStatus,
                                                   u32* peerAddr, u16* peerPort);
s32 PS4_SYSV_ABI sceNpSignalingGetContextOption();
s32 PS4_SYSV_ABI sceNpSignalingGetLocalNetInfo(s32 ctxId, OrbisNpSignalingNetInfo* info);
s32 PS4_SYSV_ABI sceNpSignalingGetMemoryInfo();
s32 PS4_SYSV_ABI sceNpSignalingGetPeerNetInfo();
s32 PS4_SYSV_ABI sceNpSignalingGetPeerNetInfoA();
s32 PS4_SYSV_ABI sceNpSignalingGetPeerNetInfoResult();
s32 PS4_SYSV_ABI sceNpSignalingInitialize();
s32 PS4_SYSV_ABI sceNpSignalingSetContextOption();
s32 PS4_SYSV_ABI sceNpSignalingTerminate();
s32 PS4_SYSV_ABI sceNpSignalingTerminateConnection();

// Access the STUN client (for NpMatching2 signaling integration).
Libraries::Net::StunClient& GetStunClient();

// API call counters for diagnostics.
struct SignalingApiStats {
    int activate_calls;
    int gcs_calls;
    int deactivate_calls;
};
SignalingApiStats GetApiStats();

// Drain ready signaling events and fire callbacks. Called from sceNpCheckCallback.
void DrainSignalingEvents();

// Deliver a signaling event to the game's callback.
void DeliverSignalingEvent(s32 ctx_id, s32 conn_id, u32 event_type, u32 delay_ms = 0);

void RegisterLib(Core::Loader::SymbolsResolver* sym);
} // namespace Libraries::Np::NpSignaling
