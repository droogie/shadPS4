// SPDX-FileCopyrightText: Copyright 2025 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

// NpSignaling HLE -- thin API layer over KernelP2PSubsystem.
// Handles PS4 API signatures, context/callback management, and event delivery.

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <deque>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include <httplib.h>

#include "common/config.h"
#include "common/logging/log.h"
#include "core/libraries/error_codes.h"
#include "core/libraries/kernel/threads.h"
#include "core/libraries/libs.h"
#include "core/libraries/network/kernel_p2p.h"
#include "core/libraries/network/sockets.h"
#include "core/libraries/network/stun_client.h"
#include "core/libraries/np/np_matching2.h"
#include "core/libraries/np/np_signaling.h"

namespace Libraries::Np::NpSignaling {

// --- Context management (callback registration) ---
// Each sceNpSignalingCreateContext call creates a context with its own callback.

struct NpSignalingContext {
    OrbisNpSignalingHandler callback = nullptr;
    void* callback_arg = nullptr;
    bool active = false;
};

static std::unordered_map<s32, NpSignalingContext> s_contexts;
static s32 s_next_ctx_id = 1;
static bool s_initialized = false;
static std::mutex s_mutex;

// STUN client for NAT discovery and signaling relay.
static Libraries::Net::StunClient s_stun_client;

// Connection state machine driven by echo probes and server bilateral confirmation.
// Maps to API status: 0xa -> ACTIVE(2), 0 -> INACTIVE(0), else -> PENDING(1).
struct NpSignalingConnection {
    s32 conn_id{0};
    s32 ctx_id{0};
    u32 peer_addr{0}; // peer addr NBO
    u16 peer_port{0}; // peer port NBO
    std::string npid;

    // Connection state machine (see SIG_STATE_* constants)
    s32 state{SIG_STATE_IDLE};

    bool has_peer_info{false};       // peer signaling data received
    bool bilateral_confirmed{false}; // bilateral peer info confirmed
    bool stun_completed{false};      // STUN completed

    // Server bilateral confirmation (from HandleSignalingEstablished)
    bool server_confirmed{false};

    std::chrono::steady_clock::time_point state_start{};
    std::chrono::steady_clock::time_point peer_info_deadline{}; // +60s timeout
};
static std::map<s32, NpSignalingConnection> s_sig_connections;
static s32 s_next_sig_conn_id{1};
static std::mutex s_sig_mutex;

// Event delivery queue -- FIFO with fire_at timestamps.

struct PendingSignalingEvent {
    s32 ctx_id;
    s32 conn_id;
    u32 event_type;
    u32 error_code;
    OrbisNpSignalingHandler callback;
    void* callback_arg;
    std::chrono::steady_clock::time_point fire_at;
};

static std::deque<PendingSignalingEvent> s_event_queue;
static std::mutex s_event_mutex;
static std::condition_variable s_event_cv;
static Kernel::PthreadT s_event_thread = nullptr;
static std::atomic<bool> s_event_shutdown{false};

static const char* EventName(u32 event_type) {
    switch (event_type) {
    case 0:
        return "DEAD";
    case 1:
        return "ESTABLISHED";
    case 2:
        return "NETINFO_ERROR";
    case 3:
        return "NETINFO_RESULT";
    case 0xa:
        return "PEER_ACTIVATED";
    case 0xb:
        return "PEER_DEACTIVATED";
    case 0xc:
        return "MUTUAL_ACTIVATED";
    default:
        return "UNKNOWN";
    }
}

// Drain ready events and fire callbacks. Called from sceNpCheckCallback.
void DrainSignalingEvents() {
    auto now = std::chrono::steady_clock::now();
    std::vector<PendingSignalingEvent> ready;

    {
        std::lock_guard lock(s_event_mutex);
        auto it = s_event_queue.begin();
        while (it != s_event_queue.end()) {
            if (it->fire_at <= now) {
                ready.push_back(std::move(*it));
                it = s_event_queue.erase(it);
            } else {
                ++it;
            }
        }
    }

    for (auto& ev : ready) {
        if (ev.callback) {
            const char* ev_name = EventName(ev.event_type);
            LOG_INFO(Lib_NpSignaling,
                     "firing signaling event: ctxId={} connId={} event={}({:#x}) "
                     "cb={} cbArg={}",
                     ev.ctx_id, ev.conn_id, ev_name, ev.event_type,
                     reinterpret_cast<void*>(ev.callback), ev.callback_arg);
            ev.callback(static_cast<u32>(ev.ctx_id), static_cast<u32>(ev.conn_id), ev.event_type,
                        ev.error_code, ev.callback_arg);
            LOG_INFO(Lib_NpSignaling, "signaling event callback returned (event={})", ev_name);
        }
    }
}

// No-op: events are drained by sceNpCheckCallback on the main thread.
static void StartEventDeliveryThread() {
    // No-op: events drained by sceNpCheckCallback on main thread
}

static void StopEventDeliveryThread() {
    std::lock_guard lock(s_event_mutex);
    s_event_queue.clear();
}

// Queue a signaling event for delivery.
static void DeliverSignalingEventForCtx(s32 ctx_id, s32 conn_id, u32 event_type,
                                        u32 delay_ms = 200) {
    OrbisNpSignalingHandler callback = nullptr;
    void* callback_arg = nullptr;

    {
        std::lock_guard<std::mutex> lock(s_mutex);
        auto it = s_contexts.find(ctx_id);
        if (it != s_contexts.end() && it->second.active) {
            callback = it->second.callback;
            callback_arg = it->second.callback_arg;
        }
    }

    if (!callback) {
        LOG_WARNING(Lib_NpSignaling,
                    "DeliverSignalingEventForCtx: no active callback for ctx={}, event={:#x}",
                    ctx_id, event_type);
        return;
    }

    auto fire_at = std::chrono::steady_clock::now() + std::chrono::milliseconds(delay_ms);
    {
        std::lock_guard lock(s_event_mutex);
        s_event_queue.push_back({ctx_id, conn_id, event_type, 0, callback, callback_arg, fire_at});
    }
}

// Public wrapper for DeliverSignalingEventForCtx.
void DeliverSignalingEvent(s32 ctx_id, s32 conn_id, u32 event_type, u32 delay_ms) {
    DeliverSignalingEventForCtx(ctx_id, conn_id, event_type, delay_ms);
}

// --- API call counters ---
static std::atomic<int> s_activate_count{0};
static std::atomic<int> s_gcs_count{0};
static std::atomic<int> s_deactivate_count{0};

// --- Connection state machine implementation ---

static void TransitionToActive(s32 conn_id);
static s32 TickSignalingConnectionLocked(NpSignalingConnection& conn, s32 echo_event);

// Transition a connection to ACTIVE (0xa) and fire callbacks.
// Must be called WITHOUT s_sig_mutex held.
static void TransitionToActive(s32 conn_id) {
    s32 ctx_id = 0;
    u32 peer_addr = 0;
    u16 peer_port = 0;
    std::string npid;

    {
        std::lock_guard lock(s_sig_mutex);
        auto it = s_sig_connections.find(conn_id);
        if (it == s_sig_connections.end() || it->second.state == SIG_STATE_ACTIVE) {
            return; // already active or gone
        }
        auto& conn = it->second;
        conn.state = SIG_STATE_ACTIVE;
        conn.state_start = std::chrono::steady_clock::now();
        conn.stun_completed = true;
        ctx_id = conn.ctx_id;
        peer_addr = conn.peer_addr;
        peer_port = conn.peer_port;
        npid = conn.npid;

        LOG_WARNING(Lib_NpSignaling,
                    "SigState: conn={} -> 0xa (ACTIVE) npid='{}' addr={:#x} port={}", conn_id, npid,
                    peer_addr, ntohs(peer_port));
        fprintf(stderr, "[NpSig] SigState: conn=%d -> 0xa (ACTIVE) npid='%s'\n", conn_id,
                npid.c_str());
        fflush(stderr);
    }
    // Lock released -- fire callbacks (may re-enter)

    // Fire all three NpSignaling events on ACTIVE entry.
    // Local MUTUAL_ACTIVATED is needed by the game's connection pipeline.
    DeliverSignalingEventForCtx(ctx_id, conn_id, ORBIS_NP_SIGNALING_EVENT_PEER_ACTIVATED, 0);
    DeliverSignalingEventForCtx(ctx_id, conn_id, ORBIS_NP_SIGNALING_EVENT_ESTABLISHED, 0);
    DeliverSignalingEventForCtx(ctx_id, conn_id, ORBIS_NP_SIGNALING_EVENT_MUTUAL_ACTIVATED, 0);

    // Fire NpMatching2 peer-established events.
    NpMatching2::OnPeerEstablished(conn_id, 0);
}

// Tick a single connection's state machine (called with s_sig_mutex HELD).
// Caller must release lock and call TransitionToActive outside if needed.
// Returns conn_id to transition to ACTIVE, or 0 if no transition needed.
static s32 TickSignalingConnectionLocked(NpSignalingConnection& conn, s32 echo_event) {
    auto now = std::chrono::steady_clock::now();

    // Check kernel echo status once (used by multiple states for catch-up)
    bool kern_echo_active = false;
    {
        auto& kernel = Libraries::Net::KernelP2PSubsystem::Instance();
        s32 kern_cid = kernel.GetConnIdByNpid(conn.npid);
        if (kern_cid > 0) {
            s32 kern_status = 0;
            kernel.GetConnectionStatus(kern_cid, &kern_status, nullptr, nullptr);
            kern_echo_active = (kern_status == 2); // ACTIVE = echo bilateral done
        }
    }

    switch (conn.state) {
    case SIG_STATE_PENDING:
        // State 1->3: peer addr known?
        if (conn.peer_addr == 0) {
            // Fallback: query kernel which has addr from SetPeerInfo
            auto& kernel = Libraries::Net::KernelP2PSubsystem::Instance();
            s32 kern_cid = kernel.GetConnIdByNpid(conn.npid);
            if (kern_cid > 0) {
                u32 ka = 0;
                u16 kp = 0;
                s32 ks = 0;
                kernel.GetConnectionStatus(kern_cid, &ks, &ka, &kp);
                if (ka != 0) {
                    conn.peer_addr = ka;
                    conn.peer_port = kp;
                    LOG_INFO(Lib_NpSignaling,
                             "SigState: conn={} resolved peer_addr from kernel: {:#x}:{}",
                             conn.conn_id, ka, ntohs(kp));
                }
            }
            if (conn.peer_addr == 0)
                break;
        }
        conn.state = SIG_STATE_STUN_BIND;
        conn.state_start = now;
        LOG_INFO(Lib_NpSignaling, "SigState: conn={} 1->3 (STUN_BIND)", conn.conn_id);
        [[fallthrough]];

    case SIG_STATE_STUN_BIND:
        // State 3->4: STUN response (LAN: immediate)
        conn.state = SIG_STATE_STUN_KEEPALIVE;
        conn.state_start = now;
        LOG_INFO(Lib_NpSignaling, "SigState: conn={} 3->4 (STUN_KEEPALIVE)", conn.conn_id);
        [[fallthrough]];

    case SIG_STATE_STUN_KEEPALIVE:
        // State 4->5: echo probes running (from ActivatePeer)
        conn.state = SIG_STATE_ECHO_PROBE;
        conn.state_start = now;
        LOG_INFO(Lib_NpSignaling, "SigState: conn={} 4->5 (ECHO_PROBE)", conn.conn_id);
        [[fallthrough]];

    case SIG_STATE_ECHO_PROBE:
        // State 5->6/7: echo bilateral confirmed?
        if (echo_event != 1 && !kern_echo_active)
            break;
        if (conn.has_peer_info || conn.server_confirmed) {
            conn.state = SIG_STATE_PEER_INFO_RECV;
            conn.state_start = now;
            LOG_INFO(Lib_NpSignaling, "SigState: conn={} 5->7 (PEER_INFO_RECV)", conn.conn_id);
            // fall through to state 7
        } else {
            conn.state = SIG_STATE_PEER_INFO_WAIT;
            conn.state_start = now;
            // Configurable timeout (default 15s, override via env var)
            static const int peer_info_timeout_s = [] {
                const char* env = std::getenv("SHADPS4_PEER_INFO_TIMEOUT_S");
                return (env && *env) ? std::atoi(env) : 15;
            }();
            conn.peer_info_deadline = now + std::chrono::seconds(peer_info_timeout_s);
            LOG_INFO(Lib_NpSignaling, "SigState: conn={} 5->6 (PEER_INFO_WAIT)", conn.conn_id);
            [[fallthrough]];
        case SIG_STATE_PEER_INFO_WAIT:
            // State 6: waiting for server/peer info.
            // Also check kernel echo status -- on LAN, echo bilateral may complete
            // before server_confirmed arrives, so catch-up here prevents stalls.
            if (conn.has_peer_info || conn.server_confirmed || kern_echo_active) {
                conn.state = SIG_STATE_PEER_INFO_RECV;
                conn.state_start = now;
                LOG_INFO(Lib_NpSignaling, "SigState: conn={} 6->7 (peer info arrived{})",
                         conn.conn_id, kern_echo_active ? " via kernel catch-up" : "");
            } else if (conn.peer_info_deadline != std::chrono::steady_clock::time_point{} &&
                       now >= conn.peer_info_deadline) {
                conn.state = SIG_STATE_PEER_INFO_RECV;
                conn.state_start = now;
                LOG_WARNING(Lib_NpSignaling,
                            "SigState: conn={} 6->7 (TIMEOUT -- peer info deadline exceeded)",
                            conn.conn_id);
            } else {
                break; // still waiting
            }
        }
        [[fallthrough]];

    case SIG_STATE_PEER_INFO_RECV:
        // State 7->8: mutual/bilateral confirmed?
        if (echo_event != 0xc && !conn.bilateral_confirmed && !kern_echo_active)
            break;
        conn.bilateral_confirmed = true;
        conn.state = SIG_STATE_ESTABLISHING;
        conn.state_start = now;
        LOG_INFO(Lib_NpSignaling, "SigState: conn={} 7->8 (ESTABLISHING)", conn.conn_id);
        [[fallthrough]];

    case SIG_STATE_ESTABLISHING:
        // State 8->0xa: bilateral confirmed -> ACTIVE
        if (conn.bilateral_confirmed) {
            return conn.conn_id; // caller fires TransitionToActive outside lock
        }
        conn.state = SIG_STATE_ESTABLISHING_BILATERAL;
        conn.state_start = now;
        LOG_INFO(Lib_NpSignaling, "SigState: conn={} 8->9 (wait bilateral)", conn.conn_id);
        [[fallthrough]];

    case SIG_STATE_ESTABLISHING_BILATERAL:
        // State 9: waiting for bilateral
        if (conn.bilateral_confirmed || conn.server_confirmed) {
            return conn.conn_id; // TransitionToActive
        }
        break;

    case SIG_STATE_ACTIVE:
        // State 0xa: nothing to do
        break;

    default:
        break;
    }

    return 0; // no transition needed
}

// Public API: tick a connection by conn_id (called from KernelEventBridge)
void TickConnection(s32 conn_id, s32 echo_event) {
    s32 activate_conn = 0;
    {
        std::lock_guard lock(s_sig_mutex);
        auto it = s_sig_connections.find(conn_id);
        if (it == s_sig_connections.end())
            return;
        activate_conn = TickSignalingConnectionLocked(it->second, echo_event);
    }
    // Fire TransitionToActive OUTSIDE the lock (callbacks may re-enter)
    if (activate_conn > 0) {
        TransitionToActive(activate_conn);
    }
}

// Public API: set server_confirmed flag and tick
void SetServerConfirmed(const std::string& npid) {
    s32 activate_conn = 0;
    {
        std::lock_guard lock(s_sig_mutex);
        for (auto& [cid, conn] : s_sig_connections) {
            if (conn.npid == npid && conn.state != SIG_STATE_IDLE &&
                conn.state != SIG_STATE_ACTIVE) {
                conn.server_confirmed = true;
                conn.has_peer_info = true;
                LOG_INFO(Lib_NpSignaling,
                         "SetServerConfirmed: npid='{}' conn_id={} state={} -- "
                         "flags set, ticking",
                         npid, cid, conn.state);
                activate_conn = TickSignalingConnectionLocked(conn, -1);
                break;
            }
        }
    }
    if (activate_conn > 0) {
        TransitionToActive(activate_conn);
    }
}

// Callback bridge registered with KernelP2PSubsystem for event delivery.

static void KernelEventBridge(s32 ctx_id, s32 conn_id, s32 event, u32 delay_ms) {
    const char* event_name = "UNKNOWN";
    switch (event) {
    case 0:
        event_name = "DEAD";
        break;
    case 1:
        event_name = "ESTABLISHED";
        break;
    case 2:
        event_name = "NETINFO_ERROR";
        break;
    case 3:
        event_name = "NETINFO_RESULT";
        break;
    case 0xa:
        event_name = "PEER_ACTIVATED";
        break;
    case 0xb:
        event_name = "PEER_DEACTIVATED";
        break;
    case 0xc:
        event_name = "MUTUAL_ACTIVATED";
        break;
    }

    LOG_INFO(Lib_NpSignaling,
             "KernelEventBridge: ctx={} conn={} event={}({:#x}) delay={}ms "
             "[API totals: activate={} gcs={} deactivate={}]",
             ctx_id, conn_id, event_name, event, delay_ms, s_activate_count.load(),
             s_gcs_count.load(), s_deactivate_count.load());
    fprintf(stderr,
            "[NpSig] KernelEventBridge: ctx=%d conn=%d event=%s(0x%x) delay=%ums "
            "[activate=%d gcs=%d deactivate=%d]\n",
            ctx_id, conn_id, event_name, event, delay_ms, s_activate_count.load(),
            s_gcs_count.load(), s_deactivate_count.load());
    fflush(stderr);

    // Drive the connection state machine.
    // ESTABLISHED/MUTUAL_ACTIVATED advance toward 0xa; DEAD delivered directly.
    if (event == 0) {
        // DEAD: deliver directly -- needed for error handling
        DeliverSignalingEventForCtx(ctx_id, conn_id, static_cast<u32>(event), delay_ms);
        return;
    }

    if (event == 1 || event == 0xc) {
        // ESTABLISHED or MUTUAL_ACTIVATED from echo bilateral:
        // Feed into state machine; callbacks only fire at state 0xa.
        //
        // Find the NpSignaling conn_id that matches this kernel conn_id.
        // The kernel conn_id may differ from our s_sig_connections key.
        s32 sig_conn_id = 0;
        {
            std::lock_guard lock(s_sig_mutex);
            // Map kernel conn_id -> NpSignaling conn_id via npid.
            auto it = s_sig_connections.find(conn_id);
            if (it != s_sig_connections.end()) {
                sig_conn_id = conn_id;
            } else {
                // Look up npid from kernel, find matching NpSignaling connection
                auto& kernel = Libraries::Net::KernelP2PSubsystem::Instance();
                u16 member_id = kernel.GetMemberIdForConn(conn_id);
                std::string npid;
                LOG_INFO(Lib_NpSignaling,
                         "KernelEventBridge: npid lookup -- kernel conn_id={} member_id={} "
                         "sig_connections_size={}",
                         conn_id, member_id, s_sig_connections.size());
                if (member_id > 0) {
                    for (auto& [cid, conn] : s_sig_connections) {
                        s32 kern_cid = kernel.GetConnIdByNpid(conn.npid);
                        LOG_INFO(Lib_NpSignaling,
                                 "KernelEventBridge: checking sig conn={} npid='{}' "
                                 "state={} kern_cid_for_npid={} vs event_conn={}",
                                 cid, conn.npid, conn.state, kern_cid, conn_id);
                        if (kern_cid == conn_id) {
                            sig_conn_id = cid;
                            break;
                        }
                    }
                }
                if (sig_conn_id == 0) {
                    LOG_WARNING(Lib_NpSignaling,
                                "KernelEventBridge: no sig connection for kernel conn_id={} "
                                "(member={})",
                                conn_id, member_id);
                    return;
                }
                LOG_INFO(Lib_NpSignaling,
                         "KernelEventBridge: mapped kernel conn_id={} -> sig conn_id={}", conn_id,
                         sig_conn_id);
            }
            // On ESTABLISHED, reset the sig conn to PENDING so TickConnection
            // walks the state machine from scratch and fires a fresh
            // TransitionToActive -> DeliverSignalingEventForCtx(0x5102).
            //
            // Covers two cases:
            //  (1) First connection: state is non-ACTIVE; reset primes flags so
            //      the state machine advances 1->3->4->5->7->8->0xa in one tick.
            //  (2) Reconnect: state is ACTIVE (preserved across DeactivateConnection);
            //      game expects a fresh callback sequence. Without this reset, the
            //      state machine sees state=ACTIVE and no-ops, so the game never
            //      gets the 0x5102 event it's waiting for.
            //
            // ESTABLISHED fires once per kernel conn_id from echo bilateral, so
            // seeing it unambiguously means a fresh activation cycle. Only event==1
            // drives the reset; MUTUAL_ACTIVATED (0xc) arrives right after and should
            // not re-reset.
            if (event == 1) {
                auto sit = s_sig_connections.find(sig_conn_id);
                if (sit != s_sig_connections.end()) {
                    auto prev_state = sit->second.state;
                    sit->second.state = SIG_STATE_PENDING;
                    sit->second.state_start = std::chrono::steady_clock::now();
                    sit->second.has_peer_info = true;
                    sit->second.bilateral_confirmed = true;
                    sit->second.stun_completed = true;
                    sit->second.server_confirmed = true;
                    LOG_INFO(Lib_NpSignaling,
                             "KernelEventBridge: reset sig conn={} npid='{}' for ESTABLISHED "
                             "delivery (prev_state={})",
                             sig_conn_id, sit->second.npid, prev_state);
                }
            }
        }
        TickConnection(sig_conn_id, event);
        return;
    }

    // Other events (NETINFO_ERROR, NETINFO_RESULT, PEER_DEACTIVATED, etc.):
    // deliver directly to game
    DeliverSignalingEventForCtx(ctx_id, conn_id, static_cast<u32>(event), delay_ms);
}

// --- Diagnostic API ---

SignalingApiStats GetApiStats() {
    return {s_activate_count.load(), s_gcs_count.load(), s_deactivate_count.load()};
}

// --- Shared peer info API (delegates to KernelP2PSubsystem) ---

void SetPeerInfo(u16 member_id, u32 addr, u16 port, const std::string& online_id,
                 u32 established_delay_ms) {
    Libraries::Net::KernelP2PSubsystem::Instance().SetPeerInfo(member_id, addr, port, online_id,
                                                               established_delay_ms);
}

NpSignalingPeerInfo GetPeerInfo(u16 member_id) {
    // Query kernel subsystem for peer data
    NpSignalingPeerInfo result{};
    u32 addr = 0;
    u16 port = 0;

    auto& kernel = Libraries::Net::KernelP2PSubsystem::Instance();
    // Not directly on kernel subsystem -- return empty for legacy compatibility.
    return result;
}

void EnsureSigConnection(s32 ctx_id, const std::string& npid) {
    std::lock_guard lock(s_sig_mutex);
    // Check if a sig connection already exists for this npid
    for (auto& [id, conn] : s_sig_connections) {
        if (conn.npid == npid) {
            return; // already exists
        }
    }
    // Create a new sig connection entry in PENDING state
    s32 cid = s_next_sig_conn_id++;
    NpSignalingConnection conn;
    conn.conn_id = cid;
    conn.ctx_id = ctx_id;
    conn.state = SIG_STATE_PENDING;
    conn.npid = npid;
    conn.state_start = std::chrono::steady_clock::now();
    s_sig_connections[cid] = std::move(conn);
    LOG_INFO(Lib_NpSignaling, "EnsureSigConnection: created sig conn_id={} for npid='{}' (PENDING)",
             cid, npid);
}

NpSignalingPeerInfo GetAnyActivePeer() {
    NpSignalingPeerInfo result{};
    auto& kernel = Libraries::Net::KernelP2PSubsystem::Instance();
    if (kernel.GetActivePeerAddr(&result.addr, &result.port)) {
        result.status = ORBIS_NP_SIGNALING_CONN_STATUS_ACTIVE;
    }
    return result;
}

void ClearConnections() {
    // Clear connection map -- stale entries from previous sessions block new transitions.
    {
        std::lock_guard lock(s_sig_mutex);
        if (!s_sig_connections.empty()) {
            LOG_INFO(Lib_NpSignaling, "ClearConnections: clearing {} sig connections",
                     s_sig_connections.size());
            s_sig_connections.clear();
        }
    }
    Libraries::Net::KernelP2PSubsystem::Instance().ClearAll();
}

void SetLocalAddr(u32 addr, u16 port) {
    // Backward-compatible wrapper -- updates addr/port, preserves existing npid.
    auto& kernel = Libraries::Net::KernelP2PSubsystem::Instance();
    // Only update addr/port, preserve existing npid
    kernel.SetLocalIdentity(addr, port, "");
    LOG_INFO(Lib_NpSignaling, "SetLocalAddr: addr={:#x} port={}", addr, ntohs(port));
}

u32 GetLocalAddr() {
    return Libraries::Net::KernelP2PSubsystem::Instance().GetLocalAddr();
}

u16 GetLocalPort() {
    return Libraries::Net::KernelP2PSubsystem::Instance().GetLocalPort();
}

// --- PS4 API implementations ---

// STUN client accessor.

Libraries::Net::StunClient& GetStunClient() {
    return s_stun_client;
}

s32 PS4_SYSV_ABI sceNpSignalingInitialize() {
    LOG_INFO(Lib_NpSignaling, "called");
    s_initialized = true;

    // Re-read STUN server config now that config files are loaded.
    {
        std::string cfg = Config::GetStunServer();
        if (!cfg.empty()) {
            auto colon = cfg.find(':');
            if (colon != std::string::npos) {
                s_stun_client.SetServer(cfg.substr(0, colon),
                                        static_cast<u16>(std::stoi(cfg.substr(colon + 1))));
            } else {
                s_stun_client.SetServer(cfg, 3478);
            }
            LOG_INFO(Lib_NpSignaling, "STUN server reconfigured from config: {}", cfg);
        }
        const char* env = std::getenv("SHADPS4_STUN_SERVER");
        if (env && *env) {
            std::string s(env);
            auto colon = s.find(':');
            if (colon != std::string::npos) {
                s_stun_client.SetServer(s.substr(0, colon),
                                        static_cast<u16>(std::stoi(s.substr(colon + 1))));
            } else {
                s_stun_client.SetServer(s, 3478);
            }
            LOG_INFO(Lib_NpSignaling, "STUN server reconfigured from env: {}", s);
        }
    }

    // Initialize event delivery.
    StartEventDeliveryThread();

    // Inject STUN client and create shared P2P transport socket.
    auto& kernel = Libraries::Net::KernelP2PSubsystem::Instance();
    kernel.SetStunClient(&s_stun_client);
    Libraries::Net::EnsureP2PTransport();

    // Start the signaling thread (NAT probe, OFFER/ACCEPT, relays, keepalives).
    kernel.StartSignalingThread();

    return ORBIS_OK;
}

s32 PS4_SYSV_ABI sceNpSignalingTerminate() {
    LOG_INFO(Lib_NpSignaling, "called");
    {
        std::lock_guard<std::mutex> lock(s_mutex);
        s_initialized = false;
        s_contexts.clear();
        s_next_ctx_id = 1;
    }
    {
        std::lock_guard lock(s_sig_mutex);
        s_sig_connections.clear();
        s_next_sig_conn_id = 1;
    }
    auto& kernel = Libraries::Net::KernelP2PSubsystem::Instance();
    kernel.StopSignalingThread();
    kernel.Reset();
    StopEventDeliveryThread();
    return ORBIS_OK;
}

s32 PS4_SYSV_ABI sceNpSignalingCreateContext(const void* npId, void* handler, void* arg,
                                             s32* context_id) {
    if (!handler || !context_id) {
        LOG_ERROR(Lib_NpSignaling, "CreateContext: null param (handler={} ctxId={})", handler,
                  static_cast<void*>(context_id));
        return 0x80552715; // ORBIS_NP_SIGNALING_ERROR_INVALID_ARGUMENT
    }
    if (!s_initialized) {
        LOG_ERROR(Lib_NpSignaling, "CreateContext: not initialized");
        return 0x80552701; // ORBIS_NP_SIGNALING_ERROR_NOT_INITIALIZED
    }

    std::lock_guard<std::mutex> lock(s_mutex);

    s32 ctx_id = s_next_ctx_id++;
    NpSignalingContext ctx;
    ctx.callback = reinterpret_cast<OrbisNpSignalingHandler>(handler);
    ctx.callback_arg = arg;
    ctx.active = true;
    s_contexts[ctx_id] = ctx;

    *context_id = ctx_id;

    // Log NpId if provided
    std::string npid_str;
    if (npId) {
        npid_str = std::string(reinterpret_cast<const char*>(npId), 16);
        auto pos = npid_str.find('\0');
        if (pos != std::string::npos)
            npid_str.resize(pos);
    }
    LOG_INFO(Lib_NpSignaling,
             "context created: id={} npId='{}' callback={} arg={} (total contexts={})", ctx_id,
             npid_str, handler, arg, s_contexts.size());

    // Register callback bridge with kernel subsystem for event delivery.
    auto& kernel = Libraries::Net::KernelP2PSubsystem::Instance();
    kernel.RegisterSignalingCallback(ctx_id, KernelEventBridge);

    return ORBIS_OK;
}

s32 PS4_SYSV_ABI sceNpSignalingCreateContextA() {
    LOG_ERROR(Lib_NpSignaling, "(STUBBED) called");
    return ORBIS_OK;
}

s32 PS4_SYSV_ABI sceNpSignalingActivateConnection(s32 ctxId, void* npId, s32* connId) {
    if (!s_initialized) {
        LOG_ERROR(Lib_NpSignaling, "ActivateConnection: not initialized");
        return 0x80552701;
    }
    if (!npId || !connId) {
        LOG_ERROR(Lib_NpSignaling, "ActivateConnection: null param (npId={} connId={})", npId,
                  static_cast<void*>(connId));
        return 0x80552715;
    }
    int call_num = ++s_activate_count;
    // Extract NpId string for dedup key (first 16 bytes, null-terminated)
    std::string npid_key;
    if (npId) {
        npid_key = std::string(reinterpret_cast<const char*>(npId), 16);
        auto pos = npid_key.find('\0');
        if (pos != std::string::npos) {
            npid_key.resize(pos);
        }
    }

    // Step 1: Allocate conn_id in PENDING state (state 1).
    s32 cid = 0;
    {
        std::lock_guard lock(s_sig_mutex);
        // Check for existing connection (idempotent)
        for (auto& [id, conn] : s_sig_connections) {
            if (conn.npid == npid_key) {
                cid = id;
                // Reset non-ACTIVE stale connection to prevent state machine stalls.
                if (conn.state != SIG_STATE_ACTIVE) {
                    conn.state = SIG_STATE_PENDING;
                    conn.state_start = std::chrono::steady_clock::now();
                    conn.ctx_id = ctxId;
                    conn.has_peer_info = false;
                    conn.bilateral_confirmed = false;
                    conn.stun_completed = false;
                    conn.server_confirmed = false;
                    conn.peer_addr = 0;
                    conn.peer_port = 0;
                    LOG_INFO(Lib_NpSignaling,
                             "ActivateConnection: reset stale conn_id={} npid='{}' -> PENDING", cid,
                             npid_key);
                }
                break;
            }
        }
        if (cid == 0) {
            cid = s_next_sig_conn_id++;
            NpSignalingConnection conn;
            conn.conn_id = cid;
            conn.ctx_id = ctxId;
            conn.state = SIG_STATE_PENDING; // Start at state 1
            conn.state_start = std::chrono::steady_clock::now();
            conn.npid = npid_key;
            s_sig_connections[cid] = std::move(conn);
        }
    }

    if (connId) {
        *connId = cid;
    }

    LOG_INFO(Lib_NpSignaling, "ActivateConnection[#{}]: ctxId={} npId='{}' -> connId={}", call_num,
             ctxId, npid_key, cid);
    fprintf(stderr, "[NpSig] ActivateConnection[#%d]: ctxId=%d npId='%s' -> connId=%d\n", call_num,
            ctxId, npid_key.c_str(), cid);
    fflush(stderr);

    // Step 2: Blocking HTTP resolve -- get peer's signaling addr/port from server.
    u32 resolved_addr = 0;
    u16 resolved_port = 0;
    bool resolved = NpMatching2::ResolvePeerSignalingAddr(npid_key, resolved_addr, resolved_port);

    if (resolved) {
        // Step 3: Store resolved addr/port in our connection map.
        {
            std::lock_guard lock(s_sig_mutex);
            auto it = s_sig_connections.find(cid);
            if (it != s_sig_connections.end()) {
                it->second.peer_addr = resolved_addr;
                it->second.peer_port = resolved_port;
            }
        }

        // Step 4: Tell KernelP2PSubsystem for P2P routing (echo probes, packet delivery).
        auto& kernel = Libraries::Net::KernelP2PSubsystem::Instance();
        kernel.ActivatePeer(ctxId, npid_key);

        LOG_INFO(Lib_NpSignaling,
                 "ActivateConnection[#{}]: resolved '{}' addr={:#x} port={} -- P2P activated",
                 call_num, npid_key, resolved_addr, ntohs(resolved_port));
    } else {
        LOG_WARNING(Lib_NpSignaling,
                    "ActivateConnection[#{}]: resolve FAILED for '{}' -- P2P routing unavailable",
                    call_num, npid_key);
        // Still activate in kernel for echo probes (may resolve later via SetPeerInfo)
        auto& kernel = Libraries::Net::KernelP2PSubsystem::Instance();
        kernel.ActivatePeer(ctxId, npid_key);
    }

    // Step 5: Send UDP ActivatePacket (NAT punch-through) to peer.
    if (resolved_addr != 0) {
        auto& kernel = Libraries::Net::KernelP2PSubsystem::Instance();
        u8 pkt[32] = {};
        u32 pkt_type = 5;
        std::memcpy(pkt + 0, &pkt_type, 4); // type = 5
        std::memcpy(pkt + 4, &cid, 4);      // conn_id
        u32 ctx_tag = static_cast<u32>(ntohs(kernel.GetLocalPort()));
        std::memcpy(pkt + 8, &ctx_tag, 4); // ctx_tag = local port (host byte order)
        kernel.SendSignalingPacket(pkt, 32, resolved_addr, resolved_port);
        LOG_INFO(Lib_NpSignaling,
                 "ActivateConnection: sent ActivatePacket to peer '{}' addr={:#x} port={}",
                 npid_key, resolved_addr, ntohs(resolved_port));
    }

    // Step 6: POST activation intent to server (fire-and-forget).
    NpMatching2::PostSignalingActivation(npid_key, cid);

    // Step 7: Tick the state machine to advance through STUN states (1->3->4->5).
    // On LAN, states 1-4 complete immediately. State 5 waits for echo bilateral.
    TickConnection(cid, -1);

    return ORBIS_OK;
}

s32 PS4_SYSV_ABI sceNpSignalingActivateConnectionA() {
    LOG_ERROR(Lib_NpSignaling, "(STUBBED) called");
    return ORBIS_OK;
}

s32 PS4_SYSV_ABI sceNpSignalingGetConnectionStatus(s32 ctxId, s32 connId, s32* connStatus,
                                                   u32* peerAddr, u16* peerPort) {
    if (!s_initialized) {
        return 0x80552701;
    }
    if (!connStatus) {
        return 0x80552715;
    }
    {
        std::lock_guard<std::mutex> lock(s_mutex);
        if (s_contexts.find(ctxId) == s_contexts.end()) {
            LOG_ERROR(Lib_NpSignaling, "GetConnectionStatus: invalid ctxId={}", ctxId);
            return 0x8055270E; // ORBIS_NP_SIGNALING_ERROR_CTX_NOT_FOUND
        }
    }
    int call_num = ++s_gcs_count;

    // Map internal state to API status: 0xa->ACTIVE(2), 0->INACTIVE(0), else->PENDING(1).
    {
        std::lock_guard lock(s_sig_mutex);
        auto it = s_sig_connections.find(connId);
        if (it != s_sig_connections.end()) {
            const auto& conn = it->second;
            if (conn.state == SIG_STATE_ACTIVE) {
                *connStatus = ORBIS_NP_SIGNALING_CONN_STATUS_ACTIVE;
                if (peerAddr)
                    *peerAddr = conn.peer_addr;
                if (peerPort)
                    *peerPort = conn.peer_port;
            } else if (conn.state == SIG_STATE_IDLE) {
                *connStatus = ORBIS_NP_SIGNALING_CONN_STATUS_INACTIVE;
                if (peerAddr)
                    *peerAddr = 0;
                if (peerPort)
                    *peerPort = 0;
            } else {
                *connStatus = ORBIS_NP_SIGNALING_CONN_STATUS_PENDING;
                if (peerAddr)
                    *peerAddr = conn.peer_addr;
                if (peerPort)
                    *peerPort = conn.peer_port;
            }
        } else {
            *connStatus = ORBIS_NP_SIGNALING_CONN_STATUS_INACTIVE;
            if (peerAddr)
                *peerAddr = 0;
            if (peerPort)
                *peerPort = 0;
        }
    }

    const char* status_name = "?";
    switch (*connStatus) {
    case 0:
        status_name = "INACTIVE";
        break;
    case 1:
        status_name = "PENDING";
        break;
    case 2:
        status_name = "ACTIVE";
        break;
    }
    if (call_num <= 5 || call_num % 100 == 0) {
        LOG_INFO(Lib_NpSignaling, "GetConnectionStatus[#{}]: ctxId={} connId={} -> status={}({})",
                 call_num, ctxId, connId, status_name, *connStatus);
    }
    return ORBIS_OK;
}

s32 PS4_SYSV_ABI sceNpSignalingDeactivateConnection(s32 ctxId, s32 connId) {
    if (!s_initialized) {
        return 0x80552701;
    }
    int call_num = ++s_deactivate_count;

    // Get peer addr for flush, but do NOT reset state -- the state machine
    // continues independently and may still advance to ACTIVE.
    u32 peer_addr = 0;
    u16 peer_port = 0;
    {
        std::lock_guard lock(s_sig_mutex);
        auto it = s_sig_connections.find(connId);
        if (it != s_sig_connections.end()) {
            peer_addr = it->second.peer_addr;
            peer_port = it->second.peer_port;
            LOG_INFO(Lib_NpSignaling,
                     "DeactivateConnection[#{}]: ctxId={} connId={} npid='{}' state={} -- "
                     "kernel deactivated, NpSignaling state PRESERVED",
                     call_num, ctxId, connId, it->second.npid, it->second.state);
        } else if (connId > 0 && (call_num <= 5 || call_num % 100 == 0)) {
            LOG_INFO(Lib_NpSignaling,
                     "DeactivateConnection[#{}]: ctxId={} connId={} -- not found, no-op", call_num,
                     ctxId, connId);
        }
    }

    // Step 2: Deactivate in kernel subsystem (P2P routing cleanup).
    auto& kernel = Libraries::Net::KernelP2PSubsystem::Instance();
    kernel.DeactivatePeer(connId);

    // Step 3: Flush buffered P2P packets from the deactivated peer.
    if (peer_addr != 0) {
        Libraries::Net::P2PFlushPacketsFromPeer(peer_addr, peer_port);
    }

    // No DEAD event, no callback -- silent deactivation.
    return ORBIS_OK;
}

s32 PS4_SYSV_ABI sceNpSignalingDeleteContext(s32 ctxId) {
    if (!s_initialized) {
        return 0x80552701;
    }
    LOG_INFO(Lib_NpSignaling, "called ctxId={}", ctxId);
    {
        std::lock_guard<std::mutex> lock(s_mutex);
        s_contexts.erase(ctxId);
    }
    Libraries::Net::KernelP2PSubsystem::Instance().UnregisterSignalingCallback(ctxId);
    return ORBIS_OK;
}

s32 PS4_SYSV_ABI sceNpSignalingCancelPeerNetInfo() {
    LOG_ERROR(Lib_NpSignaling, "(STUBBED) called");
    return ORBIS_OK;
}

s32 PS4_SYSV_ABI sceNpSignalingGetConnectionFromNpId() {
    LOG_ERROR(Lib_NpSignaling, "(STUBBED) called");
    return ORBIS_OK;
}

s32 PS4_SYSV_ABI sceNpSignalingGetConnectionFromPeerAddress() {
    LOG_ERROR(Lib_NpSignaling, "(STUBBED) called");
    return ORBIS_OK;
}

s32 PS4_SYSV_ABI sceNpSignalingGetConnectionFromPeerAddressA() {
    LOG_ERROR(Lib_NpSignaling, "(STUBBED) called");
    return ORBIS_OK;
}

s32 PS4_SYSV_ABI sceNpSignalingGetConnectionInfo(s32 ctxId, s32 connId, s32 infoType, void* info) {
    if (!s_initialized) {
        return 0x80552701;
    }
    if (!info) {
        return 0x80552715;
    }
    const char* type_name = "?";
    switch (infoType) {
    case 1:
        type_name = "RTT";
        break;
    case 2:
        type_name = "BANDWIDTH";
        break;
    case 3:
        type_name = "PEER_NP_ID";
        break;
    case 4:
        type_name = "PEER_ADDR";
        break;
    case 5:
        type_name = "MAPPED_ADDR";
        break;
    case 6:
        type_name = "PACKET_LOSS";
        break;
    }
    LOG_INFO(Lib_NpSignaling, "GetConnectionInfo: ctxId={} connId={} type={}({})", ctxId, connId,
             type_name, infoType);
    fprintf(stderr, "[NpSig] GetConnectionInfo: ctxId=%d connId=%d type=%s(%d)\n", ctxId, connId,
            type_name, infoType);
    fflush(stderr);

    // Read from NpSignaling-layer connection map first.
    {
        std::lock_guard lock(s_sig_mutex);
        auto it = s_sig_connections.find(connId);
        if (it != s_sig_connections.end()) {
            const auto& conn = it->second;
            switch (infoType) {
            case ORBIS_NP_SIGNALING_CONN_INFO_RTT:
                *static_cast<u32*>(info) = 1000; // 1ms in microseconds
                return ORBIS_OK;
            case ORBIS_NP_SIGNALING_CONN_INFO_BANDWIDTH:
                *static_cast<u32*>(info) = 10 * 1024 * 1024; // 10 Mbps
                return ORBIS_OK;
            case ORBIS_NP_SIGNALING_CONN_INFO_PEER_NP_ID: {
                auto* npid_out = static_cast<OrbisNpId*>(info);
                std::memset(npid_out, 0, sizeof(OrbisNpId));
                std::strncpy(npid_out->handle.data, conn.npid.c_str(),
                             sizeof(npid_out->handle.data) - 1);
                return ORBIS_OK;
            }
            case ORBIS_NP_SIGNALING_CONN_INFO_PEER_ADDR:
            case ORBIS_NP_SIGNALING_CONN_INFO_MAPPED_ADDR: {
                auto* out = static_cast<Libraries::Net::OrbisNetSignalingAddr*>(info);
                *out = {};
                out->addr = conn.peer_addr;
                out->port = conn.peer_port;
                return ORBIS_OK;
            }
            case ORBIS_NP_SIGNALING_CONN_INFO_PACKET_LOSS:
                *static_cast<u32*>(info) = 0;
                return ORBIS_OK;
            }
        }
    }

    // Fall through to kernel subsystem for backward compat.
    auto& kernel = Libraries::Net::KernelP2PSubsystem::Instance();
    return kernel.GetConnectionInfo(connId, infoType, info);
}

s32 PS4_SYSV_ABI sceNpSignalingGetConnectionInfoA() {
    LOG_ERROR(Lib_NpSignaling, "(STUBBED) called");
    return ORBIS_OK;
}

s32 PS4_SYSV_ABI sceNpSignalingGetConnectionStatistics() {
    LOG_ERROR(Lib_NpSignaling, "(STUBBED) called");
    return ORBIS_OK;
}

s32 PS4_SYSV_ABI sceNpSignalingGetContextOption() {
    LOG_ERROR(Lib_NpSignaling, "(STUBBED) called");
    return ORBIS_OK;
}

s32 PS4_SYSV_ABI sceNpSignalingGetLocalNetInfo(s32 ctxId, OrbisNpSignalingNetInfo* info) {
    if (!s_initialized) {
        return 0x80552701;
    }
    if (!info) {
        return 0x80552715;
    }
    LOG_INFO(Lib_NpSignaling, "called ctxId={}", ctxId);

    {
        auto& kernel = Libraries::Net::KernelP2PSubsystem::Instance();
        u32 local_addr = kernel.GetLocalAddr();

        std::memset(info, 0, sizeof(*info));
        info->size = sizeof(OrbisNpSignalingNetInfo);
        info->localAddr = local_addr;

        // Use STUN probing to get mapped (reflexive) address and NAT type.
        u32 mapped_addr = s_stun_client.GetMappedAddr();
        if (mapped_addr == 0) {
            // No cached result -- run NAT probe now
            auto probe = s_stun_client.NatProbe();
            if (probe.success) {
                mapped_addr = probe.mapped_addr;
                // Map StunNatType to PS4 natStatus values:
                // 1=Open, 2=Moderate, 3=Strict
                info->natStatus = static_cast<s32>(probe.nat_type);
                LOG_INFO(Lib_NpSignaling, "GetLocalNetInfo: STUN probe success, natType={}",
                         info->natStatus);
            } else {
                // STUN probe failed -- fall back to local address
                mapped_addr = local_addr;
                info->natStatus = 2; // Assume moderate
                LOG_WARNING(Lib_NpSignaling,
                            "GetLocalNetInfo: STUN probe failed, falling back to local addr");
            }
        } else {
            info->natStatus = 2; // Use cached, assume moderate
        }

        info->mappedAddr = mapped_addr;

        char local_buf[INET_ADDRSTRLEN], mapped_buf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &local_addr, local_buf, sizeof(local_buf));
        inet_ntop(AF_INET, &mapped_addr, mapped_buf, sizeof(mapped_buf));
        LOG_INFO(Lib_NpSignaling, "GetLocalNetInfo: localAddr={} mappedAddr={} natStatus={}",
                 local_buf, mapped_buf, info->natStatus);
    }

    return ORBIS_OK;
}

s32 PS4_SYSV_ABI sceNpSignalingGetMemoryInfo() {
    LOG_ERROR(Lib_NpSignaling, "(STUBBED) called");
    return ORBIS_OK;
}

s32 PS4_SYSV_ABI sceNpSignalingGetPeerNetInfo() {
    LOG_ERROR(Lib_NpSignaling, "(STUBBED) called");
    return ORBIS_OK;
}

s32 PS4_SYSV_ABI sceNpSignalingGetPeerNetInfoA() {
    LOG_ERROR(Lib_NpSignaling, "(STUBBED) called");
    return ORBIS_OK;
}

s32 PS4_SYSV_ABI sceNpSignalingGetPeerNetInfoResult() {
    LOG_ERROR(Lib_NpSignaling, "(STUBBED) called");
    return ORBIS_OK;
}

s32 PS4_SYSV_ABI sceNpSignalingSetContextOption() {
    LOG_ERROR(Lib_NpSignaling, "(STUBBED) called");
    return ORBIS_OK;
}

s32 PS4_SYSV_ABI sceNpSignalingTerminateConnection() {
    LOG_WARNING(Lib_NpSignaling, "TerminateConnection called -- clearing all connections");
    if (!s_initialized) {
        return 0x80552701;
    }
    {
        std::lock_guard lock(s_sig_mutex);
        s_sig_connections.clear();
    }
    auto& kernel = Libraries::Net::KernelP2PSubsystem::Instance();
    kernel.ClearAll();
    return ORBIS_OK;
}

// --- Connection state machine public API ---

void SetConnectionInactive(const std::string& npid) {
    std::lock_guard lock(s_sig_mutex);
    for (auto& [cid, conn] : s_sig_connections) {
        if (conn.npid == npid && conn.state != SIG_STATE_IDLE) {
            conn.state = SIG_STATE_IDLE;
            conn.has_peer_info = false;
            conn.bilateral_confirmed = false;
            conn.stun_completed = false;
            conn.server_confirmed = false;
            LOG_INFO(Lib_NpSignaling,
                     "SetConnectionInactive: npid='{}' conn_id={} -> IDLE (peer departed)", npid,
                     cid);
        }
    }
}

// Fully erase every sig connection for this npid. Use this (rather than
// SetConnectionInactive) when the peer has genuinely left the session so that
// a subsequent rejoin gets a fresh PENDING entry via EnsureSigConnection —
// stale IDLE state was causing the game to skip sceNpSignalingActivateConnection
// on reconnect because its ConnObj still saw the peer as live.
void RemoveConnection(const std::string& npid) {
    std::lock_guard lock(s_sig_mutex);
    for (auto it = s_sig_connections.begin(); it != s_sig_connections.end();) {
        if (it->second.npid == npid) {
            LOG_INFO(Lib_NpSignaling,
                     "RemoveConnection: npid='{}' conn_id={} state={} -- erasing", npid,
                     it->first, static_cast<int>(it->second.state));
            it = s_sig_connections.erase(it);
        } else {
            ++it;
        }
    }
}

s32 GetSignalingConnId(const std::string& npid) {
    std::lock_guard lock(s_sig_mutex);
    for (const auto& [cid, conn] : s_sig_connections) {
        if (conn.npid == npid) {
            return cid;
        }
    }
    return 0;
}

std::string GetNpidForConnId(s32 conn_id) {
    std::lock_guard lock(s_sig_mutex);
    auto it = s_sig_connections.find(conn_id);
    if (it != s_sig_connections.end()) {
        return it->second.npid;
    }
    return "";
}

s32 GetSignalingStatus(s32 connId, s32* status, u32* addr, u16* port) {
    std::lock_guard lock(s_sig_mutex);
    auto it = s_sig_connections.find(connId);
    if (it != s_sig_connections.end()) {
        const auto& conn = it->second;
        if (status) {
            if (conn.state == SIG_STATE_ACTIVE) {
                *status = ORBIS_NP_SIGNALING_CONN_STATUS_ACTIVE;
            } else if (conn.state == SIG_STATE_IDLE) {
                *status = ORBIS_NP_SIGNALING_CONN_STATUS_INACTIVE;
            } else {
                *status = ORBIS_NP_SIGNALING_CONN_STATUS_PENDING;
            }
        }
        if (addr)
            *addr = conn.peer_addr;
        if (port)
            *port = conn.peer_port;
        return 0;
    }
    return -1; // not found
}

void RegisterLib(Core::Loader::SymbolsResolver* sym) {
    LIB_FUNCTION("0UvTFeomAUM", "libSceNpSignaling", 1, "libSceNpSignaling",
                 sceNpSignalingActivateConnection);
    LIB_FUNCTION("ZPLavCKqAB0", "libSceNpSignaling", 1, "libSceNpSignaling",
                 sceNpSignalingActivateConnectionA);
    LIB_FUNCTION("X1G4kkN2R-8", "libSceNpSignaling", 1, "libSceNpSignaling",
                 sceNpSignalingCancelPeerNetInfo);
    LIB_FUNCTION("5yYjEdd4t8Y", "libSceNpSignaling", 1, "libSceNpSignaling",
                 sceNpSignalingCreateContext);
    LIB_FUNCTION("dDLNFdY8dws", "libSceNpSignaling", 1, "libSceNpSignaling",
                 sceNpSignalingCreateContextA);
    LIB_FUNCTION("6UEembipgrM", "libSceNpSignaling", 1, "libSceNpSignaling",
                 sceNpSignalingDeactivateConnection);
    LIB_FUNCTION("hx+LIg-1koI", "libSceNpSignaling", 1, "libSceNpSignaling",
                 sceNpSignalingDeleteContext);
    LIB_FUNCTION("GQ0hqmzj0F4", "libSceNpSignaling", 1, "libSceNpSignaling",
                 sceNpSignalingGetConnectionFromNpId);
    LIB_FUNCTION("CkPxQjSm018", "libSceNpSignaling", 1, "libSceNpSignaling",
                 sceNpSignalingGetConnectionFromPeerAddress);
    LIB_FUNCTION("B7cT9aVby7A", "libSceNpSignaling", 1, "libSceNpSignaling",
                 sceNpSignalingGetConnectionFromPeerAddressA);
    LIB_FUNCTION("AN3h0EBSX7A", "libSceNpSignaling", 1, "libSceNpSignaling",
                 sceNpSignalingGetConnectionInfo);
    LIB_FUNCTION("rcylknsUDwg", "libSceNpSignaling", 1, "libSceNpSignaling",
                 sceNpSignalingGetConnectionInfoA);
    LIB_FUNCTION("C6ZNCDTj00Y", "libSceNpSignaling", 1, "libSceNpSignaling",
                 sceNpSignalingGetConnectionStatistics);
    LIB_FUNCTION("bD-JizUb3JM", "libSceNpSignaling", 1, "libSceNpSignaling",
                 sceNpSignalingGetConnectionStatus);
    LIB_FUNCTION("npU5V56id34", "libSceNpSignaling", 1, "libSceNpSignaling",
                 sceNpSignalingGetContextOption);
    LIB_FUNCTION("U8AQMlOFBc8", "libSceNpSignaling", 1, "libSceNpSignaling",
                 sceNpSignalingGetLocalNetInfo);
    LIB_FUNCTION("tOpqyDyMje4", "libSceNpSignaling", 1, "libSceNpSignaling",
                 sceNpSignalingGetMemoryInfo);
    LIB_FUNCTION("zFgFHId7vAE", "libSceNpSignaling", 1, "libSceNpSignaling",
                 sceNpSignalingGetPeerNetInfo);
    LIB_FUNCTION("Shr7bZq8QHY", "libSceNpSignaling", 1, "libSceNpSignaling",
                 sceNpSignalingGetPeerNetInfoA);
    LIB_FUNCTION("2HajCEGgG4s", "libSceNpSignaling", 1, "libSceNpSignaling",
                 sceNpSignalingGetPeerNetInfoResult);
    LIB_FUNCTION("3KOuC4RmZZU", "libSceNpSignaling", 1, "libSceNpSignaling",
                 sceNpSignalingInitialize);
    LIB_FUNCTION("IHRDvZodPYY", "libSceNpSignaling", 1, "libSceNpSignaling",
                 sceNpSignalingSetContextOption);
    LIB_FUNCTION("NPhw0UXaNrk", "libSceNpSignaling", 1, "libSceNpSignaling",
                 sceNpSignalingTerminate);
    LIB_FUNCTION("b4qaXPzMJxo", "libSceNpSignaling", 1, "libSceNpSignaling",
                 sceNpSignalingTerminateConnection);
}

} // namespace Libraries::Np::NpSignaling
