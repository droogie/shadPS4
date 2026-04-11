// SPDX-FileCopyrightText: Copyright 2025 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <vector>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#endif

#include <easywsclient.hpp>
#include <httplib.h>

#include "common/config.h"
#include "common/logging/log.h"
#include "core/libraries/error_codes.h"
#include "core/libraries/kernel/threads.h"
#include "core/libraries/libs.h"
#include "core/libraries/network/kernel_p2p.h"
#include "core/libraries/network/net.h"
#include "core/libraries/network/sockets.h"
#include "core/libraries/network/stun_client.h"
#include "core/libraries/np/np_matching2.h"
#include "core/libraries/np/np_signaling.h"
#include "core/tls.h"

// Dual-log helper: writes to both the shadPS4 log system AND stderr for real-time visibility.
// Formats with fmt::format once, then sends the result to LOG_INFO and fprintf(stderr).
#define NP_LOG(fmt_str, ...)                                                                       \
    do {                                                                                           \
        auto _np_msg_ = fmt::format(fmt_str, ##__VA_ARGS__);                                       \
        LOG_INFO(Lib_NpMatching2, "{}", _np_msg_);                                                 \
        fprintf(stderr, "[NpM2] %s\n", _np_msg_.c_str());                                          \
        fflush(stderr);                                                                            \
    } while (0)

// Simple JSON helpers (avoid external dependency for MVP)
namespace {

// Minimal JSON value extraction from a response body string.
// Handles: "key": number and "key": "string"
std::string JsonGetString(const std::string& json, const std::string& key) {
    std::string search = "\"" + key + "\"";
    auto pos = json.find(search);
    if (pos == std::string::npos)
        return "";
    pos = json.find(':', pos + search.size());
    if (pos == std::string::npos)
        return "";
    pos = json.find('"', pos + 1);
    if (pos == std::string::npos)
        return "";
    auto end = json.find('"', pos + 1);
    if (end == std::string::npos)
        return "";
    return json.substr(pos + 1, end - pos - 1);
}

int64_t JsonGetInt(const std::string& json, const std::string& key) {
    std::string search = "\"" + key + "\"";
    auto pos = json.find(search);
    if (pos == std::string::npos)
        return 0;
    pos = json.find(':', pos + search.size());
    if (pos == std::string::npos)
        return 0;
    // Skip whitespace
    pos++;
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t'))
        pos++;
    // Parse number
    bool negative = false;
    if (pos < json.size() && json[pos] == '-') {
        negative = true;
        pos++;
    }
    int64_t val = 0;
    while (pos < json.size() && json[pos] >= '0' && json[pos] <= '9') {
        val = val * 10 + (json[pos] - '0');
        pos++;
    }
    return negative ? -val : val;
}

// Parse a simple JSON array of objects: [{"MemberId": 1, "OnlineId": "foo", ...}, ...]
struct MemberInfo {
    int member_id;
    std::string online_id;
    std::string addr;
    int port;
    std::string local_addr; // Raw local/private address (for LAN detection)
    int local_port{0};
    std::string mapped_addr; // STUN-resolved external address (empty = LAN)
    int mapped_port{0};      // STUN-resolved external port (0 = LAN)
};

std::vector<MemberInfo> JsonGetMemberArray(const std::string& json, const std::string& key) {
    std::vector<MemberInfo> result;
    std::string search = "\"" + key + "\"";
    auto pos = json.find(search);
    if (pos == std::string::npos)
        return result;
    pos = json.find('[', pos);
    if (pos == std::string::npos)
        return result;
    // Find each object in array
    while (true) {
        auto obj_start = json.find('{', pos);
        if (obj_start == std::string::npos)
            break;
        auto obj_end = json.find('}', obj_start);
        if (obj_end == std::string::npos)
            break;
        std::string obj = json.substr(obj_start, obj_end - obj_start + 1);
        MemberInfo mi{};
        mi.member_id = static_cast<int>(JsonGetInt(obj, "MemberId"));
        mi.online_id = JsonGetString(obj, "OnlineId");
        mi.addr = JsonGetString(obj, "Addr");
        mi.port = static_cast<int>(JsonGetInt(obj, "Port"));
        mi.local_addr = JsonGetString(obj, "LocalAddr");
        mi.local_port = static_cast<int>(JsonGetInt(obj, "LocalPort"));
        mi.mapped_addr = JsonGetString(obj, "MappedAddr");
        mi.mapped_port = static_cast<int>(JsonGetInt(obj, "MappedPort"));
        result.push_back(mi);
        pos = obj_end + 1;
        // Check for array end
        auto next = json.find_first_not_of(" ,\n\r\t", pos);
        if (next == std::string::npos || json[next] == ']')
            break;
    }
    return result;
}

// Convert dotted IP string to in_addr (network byte order)
u32 IpStringToAddr(const std::string& ip) {
    u32 a, b, c, d;
    if (sscanf(ip.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d) != 4)
        return 0;
    return (a) | (b << 8) | (c << 16) | (d << 24); // network byte order (little-endian host)
}

} // anonymous namespace

namespace Libraries::Np::NpMatching2 {

// --- Global HLE state ---

struct PeerInfo {
    u32 addr = 0;
    u16 port = 0;
    u16 member_id = 0;
    s32 status = ORBIS_NP_MATCHING2_SIGNALING_CONN_STATUS_INACTIVE;
    std::string online_id; // peer's NpId name
};

struct PendingGuestInvite {
    bool valid = false;
    u64 room_id = 0;
    std::string session_id;
    std::string host_online_id;
    std::string host_addr;
    u16 host_port = 0;
    u32 notify_attempts = 0;
    std::chrono::steady_clock::time_point last_notify{};
    bool max_retry_logged = false;
};

inline bool HostPollFallbackEnabled() {
    static const bool enabled = []() -> bool {
        const char* env = std::getenv("SHADPS4_M2_HOST_POLL_FALLBACK");
        if (!env) {
            return false;
        }
        return std::strcmp(env, "1") == 0 || std::strcmp(env, "true") == 0 ||
               std::strcmp(env, "TRUE") == 0 || std::strcmp(env, "on") == 0 ||
               std::strcmp(env, "ON") == 0;
    }();
    return enabled;
}

// --- Event dispatch system ---
// Instead of spawning a new PS4 thread per callback, we queue events and
// process them from a single long-lived dispatch thread. This reduces
// thread creation (which risks rseq glibc crashes) and provides
// deterministic event ordering.
struct PendingEvent {
    // Priority order: CONTEXT < REQUEST < ROOM_EVENT < SIGNALING
    // Room events must fire before signaling events so connection state
    // is set up before signaling callbacks reference it.
    enum Type { CONTEXT_CB, REQUEST_CB, ROOM_EVENT_CB, LOBBY_EVENT_CB, SIGNALING_CB };
    Type type = CONTEXT_CB;
    std::chrono::steady_clock::time_point fire_at;

    // Context CB fields
    u16 ctx_event = 0;
    u8 ctx_event_cause = 0;
    s32 error_code = 0;

    // Request CB fields
    u32 req_id = 0;
    u16 req_event = 0;
    OrbisNpMatching2RequestCallback request_cb = nullptr;
    void* request_cb_arg = nullptr;
    void* request_data = nullptr; // if null, uses g_state.last_response

    // Signaling CB fields
    u64 room_id = 0;
    u16 member_id = 0;
    u16 sig_event = 0;
    u32 conn_id = 0;

    // Room event CB fields (Phase 3)
    u16 room_event = 0;
    void* room_event_data = nullptr;
    // Keep room event payload memory alive until callback dispatch finishes.
    std::shared_ptr<void> room_event_payload;
};

struct NpMatching2Context {
    u16 ctx_id = 0;
    bool started = false;
    u16 server_id = 1;
    u16 service_label = 0;
    std::string online_id;

    // Server-assigned session info
    std::string session_id;
    u64 room_id = 0;
    u16 my_member_id = 0;
};

struct NpMatching2State {
    bool initialized = false;
    u16 signaling_port = 3658;                // Default PS4 signaling port
    std::string signaling_addr = "127.0.0.1"; // overridable via SHADPS4_SIGNALING_ADDR

    // Callbacks
    OrbisNpMatching2RequestCallback default_request_callback = nullptr;
    void* default_request_callback_arg = nullptr;

    // Dedup guard: track the last fired request callback reqId+event to prevent
    // duplicate callbacks from crashing the game's dispatch handler.
    u32 last_fired_req_id = 0;
    u16 last_fired_req_event = 0;

    OrbisNpMatching2ContextCallback context_callback = nullptr;
    void* context_callback_arg = nullptr;

    OrbisNpMatching2RoomEventCallback room_event_callback = nullptr;
    void* room_event_callback_arg = nullptr;

    OrbisNpMatching2SignalingCallback signaling_callback = nullptr;
    void* signaling_callback_arg = nullptr;

    OrbisNpMatching2LobbyEventCallback lobby_event_callback = nullptr;
    void* lobby_event_callback_arg = nullptr;

    OrbisNpMatching2LobbyMessageCallback lobby_message_callback = nullptr;
    void* lobby_message_callback_arg = nullptr;

    OrbisNpMatching2RoomMessageCallback room_message_callback = nullptr;
    void* room_message_callback_arg = nullptr;

    NpMatching2Context ctx;

    // Peer connection info (member_id -> peer info)
    std::map<u16, PeerInfo> peers;
    // Protects peers map from concurrent access across threads.
    // Must be held for any read/write to peers from poll threads,
    // signaling thread, and game thread APIs.
    std::mutex peers_mutex;

    // Callback data memory (kept alive until next operation)
    // Uses raw pointers with manual lifecycle management
    OrbisNpMatching2RoomDataInternal* last_room_data = nullptr;
    OrbisNpMatching2RoomMemberDataInternal* last_member_data = nullptr;
    OrbisNpMatching2CreateJoinRoomResponse* last_response = nullptr;
    int last_member_count = 0;

    u32 next_request_id = 1;
    std::mutex mutex;

    // Server URL for matching2 endpoints
    std::string server_host = "http://127.0.0.1:18671";

    // Per-request callback info (captured when game calls CreateJoinRoom/JoinRoom)
    OrbisNpMatching2RequestCallback per_request_callback = nullptr;
    void* per_request_callback_arg = nullptr;

    // Background invite polling thread (PS4 thread for valid g_curthread)
    std::atomic<bool> poll_thread_running{false};
    Kernel::PthreadT poll_thread = nullptr;
    u64 np_events_cursor = 0;

    // Host-side room member polling thread
    std::atomic<bool> host_poll_running{false};
    Kernel::PthreadT host_poll_thread = nullptr;
    int known_member_count = 0;               // members the host already knows about
    std::atomic<bool> host_self_established_fired{false}; // guard: only fire self Established (0x5102) once

    // Guest-side member polling thread (Phase 2: departure detection)
    std::atomic<bool> guest_poll_running{false};
    Kernel::PthreadT guest_poll_thread = nullptr;

    // Guest invite received from NP event queue. In PSN-like flow, invite
    // delivery is notification-only; native sceNpMatching2JoinRoom performs
    // the actual server join.
    PendingGuestInvite pending_guest_invite;
    std::mutex pending_guest_invite_mutex;

    // Timestamp when the room was joined -- used to emulate signaling establishment
    // delay in sceNpMatching2SignalingGetConnectionStatus.
    std::chrono::steady_clock::time_point room_joined_time{};

    // WebSocket client for instant event push (replaces HTTP polling)
    std::unique_ptr<easywsclient::WebSocket> ws_client;
    bool ws_attempted = false; // true after first connect attempt (suppress repeat warnings)
    std::chrono::steady_clock::time_point ws_last_heartbeat{};

    // Event dispatch thread and queue (Phase 1: thread consolidation)
    std::vector<PendingEvent> pending_events;
    std::mutex event_queue_mutex;
    std::atomic<bool> dispatch_running{false};
    Kernel::PthreadT dispatch_thread = nullptr;

    // Async operation threads (PS4 threads for valid g_curthread)
    std::vector<Kernel::PthreadT> async_threads;
    std::mutex async_threads_mutex;

    void FreeCallbackData() {
        delete last_response;
        last_response = nullptr;
        delete last_room_data;
        last_room_data = nullptr;
        delete[] last_member_data;
        last_member_data = nullptr;
        last_member_count = 0;
    }

    void CleanupAsyncThreads() {
        std::lock_guard<std::mutex> lock(async_threads_mutex);
        for (auto& t : async_threads) {
            if (t != nullptr) {
                Kernel::posix_pthread_join(t, nullptr);
            }
        }
        async_threads.clear();
    }

    void StopPollThread() {
        // Signal all threads to stop FIRST
        poll_thread_running = false;
        host_poll_running = false;
        guest_poll_running = false;
        dispatch_running = false;
        np_events_cursor = 0;
        host_self_established_fired.store(false);

        // Close WebSocket to unblock poll thread's ws_client->poll() call,
        // but do NOT reset/destroy it yet -- threads may still be referencing it.
        if (ws_client) {
            ws_client->close();
        }

        {
            std::lock_guard<std::mutex> invite_lock(pending_guest_invite_mutex);
            pending_guest_invite = {};
        }

        // Join ALL threads BEFORE destroying shared state.
        // Previously ws_client.reset() ran before joins -- threads still inside
        // ws_client->poll()/dispatch() would use-after-free the destroyed object.
        if (poll_thread != nullptr) {
            Kernel::posix_pthread_join(poll_thread, nullptr);
            poll_thread = nullptr;
        }
        if (host_poll_thread != nullptr) {
            Kernel::posix_pthread_join(host_poll_thread, nullptr);
            host_poll_thread = nullptr;
        }
        if (guest_poll_thread != nullptr) {
            Kernel::posix_pthread_join(guest_poll_thread, nullptr);
            guest_poll_thread = nullptr;
        }

        // NOW safe to destroy WebSocket -- no threads are using it
        ws_client.reset();
        ws_attempted = false;

        // dispatch_thread removed -- DrainReadyEvents() runs on main thread
        {
            std::lock_guard<std::mutex> lock(event_queue_mutex);
            pending_events.clear();
        }
        CleanupAsyncThreads();
    }
};

static NpMatching2State g_state;

// Get STUN-mapped address/port for inclusion in room requests.
// Returns "0" if STUN probe hasn't completed (LAN fallback).
static std::string GetStunMappedAddrStr() {
    auto& stun = NpSignaling::GetStunClient();
    u32 addr = stun.GetMappedAddr();
    if (addr == 0)
        return "0";
    char buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr, buf, sizeof(buf));
    return std::string(buf);
}

static u16 GetStunMappedPortHost() {
    auto& stun = NpSignaling::GetStunClient();
    u16 port_nbo = stun.GetMappedPort();
    return port_nbo ? ntohs(port_nbo) : 0;
}

// Forward declarations -- defined later in file.
static void ScheduleRoomEventSignalingOptParamUpdate(u16 member_a, u16 member_b,
                                                     std::chrono::steady_clock::time_point fire_at);

static void ScheduleEvent(PendingEvent ev) {
    std::lock_guard<std::mutex> lock(g_state.event_queue_mutex);
    g_state.pending_events.push_back(std::move(ev));
}

// Forward declarations -- defined later in file (needs httplib).
static std::string HttpPost(const std::string& path, const std::string& body);
static std::string HttpGet(const std::string& path);

// Diagnostic stub -- disabled. Game memory diagnostics are not portable across
// different builds/platforms and have been removed.
static void DiagDumpGameState() {
    return;
}

// Drain ready NpMatching2 events and fire callbacks synchronously.
// Called from sceNpCheckCallback on the game's main thread.
void DrainReadyEvents() {
    DiagDumpGameState();

    auto now = std::chrono::steady_clock::now();

    std::vector<PendingEvent> ready;

    {
        std::lock_guard<std::mutex> lock(g_state.event_queue_mutex);
        auto it = g_state.pending_events.begin();
        while (it != g_state.pending_events.end()) {
            if (it->fire_at <= now) {
                ready.push_back(std::move(*it));
                it = g_state.pending_events.erase(it);
            } else {
                ++it;
            }
        }
    }

    if (ready.empty())
        return;

    // Sort by type priority: CONTEXT < REQUEST < ROOM_EVENT < SIGNALING
    // Room events must fire before signaling so game creates ConnectionObjects first.
    // Within same type, preserve insertion order (stable_sort).
    std::stable_sort(ready.begin(), ready.end(), [](const PendingEvent& a, const PendingEvent& b) {
        return static_cast<int>(a.type) < static_cast<int>(b.type);
    });

    // Deduplicate REQUEST_CB events: only keep the first one per reqId+event.
    // This prevents double-firing which crashes the game's dispatch handler.
    {
        std::set<u64> seen_req;
        auto wit = ready.begin();
        for (auto rit = ready.begin(); rit != ready.end(); ++rit) {
            if (rit->type == PendingEvent::REQUEST_CB) {
                u64 key = (static_cast<u64>(rit->req_id) << 16) | rit->req_event;
                if (!seen_req.insert(key).second) {
                    LOG_WARNING(Lib_NpMatching2,
                                "EventDispatch: removing duplicate REQUEST_CB "
                                "event={:#x} reqId={} (ready.size={})",
                                rit->req_event, rit->req_id, ready.size());
                    continue; // skip this duplicate
                }
            }
            if (wit != rit)
                *wit = std::move(*rit);
            ++wit;
        }
        ready.erase(wit, ready.end());
    }

    // Deduplicate SIGNALING_CB events: only keep the first per member_id+sig_event.
    // Prevents duplicate ESTABLISHED from confusing the game's connection state machine
    // when multiple poll threads schedule events for the same member concurrently.
    {
        std::set<u64> seen_sig;
        auto wit = ready.begin();
        for (auto rit = ready.begin(); rit != ready.end(); ++rit) {
            if (rit->type == PendingEvent::SIGNALING_CB) {
                u64 key = (static_cast<u64>(rit->member_id) << 16) | rit->sig_event;
                if (!seen_sig.insert(key).second) {
                    LOG_WARNING(Lib_NpMatching2,
                                "EventDispatch: removing duplicate SIGNALING_CB "
                                "event={:#x} member={} (ready.size={})",
                                rit->sig_event, rit->member_id, ready.size());
                    continue;
                }
            }
            if (wit != rit)
                *wit = std::move(*rit);
            ++wit;
        }
        ready.erase(wit, ready.end());
    }

    LOG_INFO(Lib_NpMatching2, "EventDispatch: processing {} ready events", ready.size());

    for (auto& ev : ready) {
        switch (ev.type) {
        case PendingEvent::CONTEXT_CB:
            if (g_state.context_callback) {
                fprintf(stderr, "[NpM2] CB_CONTEXT: ctxId=%d event=0x%x cause=%d err=%d\n",
                        g_state.ctx.ctx_id, ev.ctx_event, ev.ctx_event_cause, ev.error_code);
                fflush(stderr);
                NP_LOG("CB_CONTEXT: ctxId={} event={:#x} cause={} err={} cb={} arg={}",
                       g_state.ctx.ctx_id, ev.ctx_event, ev.ctx_event_cause, ev.error_code,
                       (void*)g_state.context_callback, g_state.context_callback_arg);
                g_state.context_callback(g_state.ctx.ctx_id, ev.ctx_event, ev.ctx_event_cause,
                                         ev.error_code, g_state.context_callback_arg);
                NP_LOG("CB_CONTEXT: returned");
            }
            break;

        case PendingEvent::REQUEST_CB:
            if (ev.request_cb) {
                if (ev.req_id == g_state.last_fired_req_id &&
                    ev.req_event == g_state.last_fired_req_event) {
                    NP_LOG("CB_REQUEST: SKIPPING duplicate event={:#x} reqId={}", ev.req_event,
                           ev.req_id);
                    break;
                }
                void* data = ev.request_data;
                fprintf(stderr, "[NpM2] CB_REQUEST: ctxId=%d reqId=%d event=0x%x err=%d data=%p cb=%p\n",
                        g_state.ctx.ctx_id, ev.req_id, ev.req_event, ev.error_code, data,
                        (void*)ev.request_cb);
                fflush(stderr);
                NP_LOG("CB_REQUEST: ctxId={} reqId={} event={:#x} err={} data={} "
                       "cb={} arg={}",
                       g_state.ctx.ctx_id, ev.req_id, ev.req_event, ev.error_code, data,
                       (void*)ev.request_cb, ev.request_cb_arg);
                g_state.last_fired_req_id = ev.req_id;
                g_state.last_fired_req_event = ev.req_event;
                ev.request_cb(g_state.ctx.ctx_id, ev.req_id, ev.req_event, ev.error_code, data,
                              ev.request_cb_arg);
                NP_LOG("CB_REQUEST: returned (event={:#x} reqId={})", ev.req_event, ev.req_id);
            }
            break;

        case PendingEvent::SIGNALING_CB:
            if (g_state.signaling_callback) {
                NP_LOG("CB_SIGNALING: ctxId={} room={} member={} event={:#x} conn={} "
                       "cb={} arg={}",
                       g_state.ctx.ctx_id, ev.room_id, ev.member_id, ev.sig_event, ev.conn_id,
                       (void*)g_state.signaling_callback, g_state.signaling_callback_arg);
                g_state.signaling_callback(g_state.ctx.ctx_id, ev.room_id, ev.member_id,
                                           ev.sig_event, ev.conn_id,
                                           g_state.signaling_callback_arg);
                NP_LOG("CB_SIGNALING: returned (event={:#x} member={})", ev.sig_event,
                       ev.member_id);
            }
            break;

        case PendingEvent::ROOM_EVENT_CB:
            if (g_state.room_event_callback && ev.room_event_data) {
                NP_LOG("CB_ROOM_EVENT: ctxId={} room={} event={:#x} data={} "
                       "cb={} arg={}",
                       g_state.ctx.ctx_id, ev.room_id, ev.room_event, ev.room_event_data,
                       (void*)g_state.room_event_callback, g_state.room_event_callback_arg);
                g_state.room_event_callback(g_state.ctx.ctx_id, ev.room_id, ev.room_event,
                                            ev.room_event_data, g_state.room_event_callback_arg);
                NP_LOG("CB_ROOM_EVENT: returned (event={:#x})", ev.room_event);
            }
            break;

        case PendingEvent::LOBBY_EVENT_CB:
            if (g_state.lobby_event_callback && ev.room_event_data) {
                NP_LOG("CB_LOBBY_EVENT: ctxId={} lobby={} event={:#x} data={} "
                       "cb={} arg={}",
                       g_state.ctx.ctx_id, ev.room_id, ev.room_event, ev.room_event_data,
                       (void*)g_state.lobby_event_callback, g_state.lobby_event_callback_arg);
                g_state.lobby_event_callback(g_state.ctx.ctx_id, ev.room_id, ev.room_event,
                                             ev.room_event_data, g_state.lobby_event_callback_arg);
                NP_LOG("CB_LOBBY_EVENT: returned (event={:#x})", ev.room_event);
            }
            break;

        default:
            break;
        }
    }
}

// --- STUN address update (called from NpSignaling async probe thread) ---

static bool IsPrivateAddr(const std::string& addr) {
    // RFC 1918 private ranges + loopback
    return addr.rfind("127.", 0) == 0 || addr.rfind("10.", 0) == 0 ||
           addr.rfind("192.168.", 0) == 0 || addr.rfind("172.16.", 0) == 0 ||
           addr.rfind("172.17.", 0) == 0 || addr.rfind("172.18.", 0) == 0 ||
           addr.rfind("172.19.", 0) == 0 || addr.rfind("172.2", 0) == 0 ||
           addr.rfind("172.30.", 0) == 0 || addr.rfind("172.31.", 0) == 0;
}

void UpdateSignalingAddrFromStun(const std::string& mapped_addr, u16 mapped_port) {
    // SHADPS4_LAN_MODE=1 keeps the LAN IP for same-subnet testing.
    // Without NAT hairpinning, STUN-mapped addresses don't route between
    // machines on the same LAN.
    const char* lan = std::getenv("SHADPS4_LAN_MODE");
    if (lan && *lan == '1') {
        LOG_INFO(Lib_NpMatching2,
                 "signaling addr STUN override skipped (SHADPS4_LAN_MODE=1), keeping {}",
                 g_state.signaling_addr);
        return;
    }
    if (!mapped_addr.empty() &&
        (mapped_addr != g_state.signaling_addr || mapped_port != g_state.signaling_port)) {
        LOG_INFO(Lib_NpMatching2, "signaling addr updated from STUN: {} -> {} (port {} -> {})",
                 g_state.signaling_addr, mapped_addr, g_state.signaling_port, mapped_port);
        g_state.signaling_addr = mapped_addr;
        if (mapped_port > 0) {
            g_state.signaling_port = mapped_port;
        }

        // Update KernelP2PSubsystem with new identity
        u32 addr = IpStringToAddr(g_state.signaling_addr);
        u16 port_nbo = htons(g_state.signaling_port);
        Libraries::Net::KernelP2PSubsystem::Instance().SetLocalIdentity(addr, port_nbo,
                                                                        g_state.ctx.online_id);

        // Notify server of updated address
        if (!g_state.server_host.empty() && !g_state.ctx.online_id.empty()) {
            std::string body = "{";
            body += "\"OnlineId\": \"" + g_state.ctx.online_id + "\",";
            body += "\"Addr\": \"" + g_state.signaling_addr + "\",";
            body += "\"Port\": " + std::to_string(g_state.signaling_port);
            body += "}";
            HttpPost("/mp/matching2/signaling_update", body);
        }
    }
}

// Bridge: NpSignaling ESTABLISHED -> NpMatching2 Established (0x5102).
// Called when the P2P connection for a peer is confirmed active.
// Fires the signaling established event after the connection pipeline completes.

void OnPeerEstablished(s32 conn_id, u16 member_id) {

    // Resolve member_id from npid if not provided
    if (member_id == 0) {
        std::string npid = NpSignaling::GetNpidForConnId(conn_id);
        if (!npid.empty()) {
            std::lock_guard<std::mutex> plock(g_state.peers_mutex);
            for (const auto& [mid, pi] : g_state.peers) {
                if (pi.online_id == npid) {
                    member_id = mid;
                    break;
                }
            }
        }
    }

    if (member_id == 0 || member_id == g_state.ctx.my_member_id) {
        return;
    }
    if (!g_state.host_self_established_fired.load()) {
        return;
    }

    // Set NpMatching2 peer status to ACTIVE
    {
        std::lock_guard<std::mutex> plock(g_state.peers_mutex);
        auto peer_it = g_state.peers.find(member_id);
        if (peer_it != g_state.peers.end()) {
            peer_it->second.status = ORBIS_NP_MATCHING2_SIGNALING_CONN_STATUS_ACTIVE;
        }
    }

    // Fire 0x5102 and 0x1105 locally. These are NpMatching2 library-internal events.
    auto now = std::chrono::steady_clock::now();

    PendingEvent sig_ev{};
    sig_ev.type = PendingEvent::SIGNALING_CB;
    sig_ev.fire_at = now;
    sig_ev.room_id = g_state.ctx.room_id;
    sig_ev.member_id = member_id;
    sig_ev.sig_event = ORBIS_NP_MATCHING2_SIGNALING_EVENT_ESTABLISHED;
    sig_ev.conn_id = static_cast<u32>(member_id);
    ScheduleEvent(std::move(sig_ev));

    // 0x1105 is not fired here; it is only needed for 3rd+ member joins.

    // Also notify server of ACTIVE for bilateral tracking (mutual_activated protocol)
    PostSignalingActive(NpSignaling::GetNpidForConnId(conn_id));

    NP_LOG("OnPeerEstablished: fired 0x5102 (local, immediate) + notified server, "
           "member={} conn_id={}",
           member_id, conn_id);
}

// --- Server-mediated signaling ---

void PostSignalingActivation(const std::string& peer_npid, s32 conn_id) {
    if (g_state.ctx.online_id.empty() || g_state.ctx.session_id.empty()) {
        return;
    }

    // Fire-and-forget in a detached thread -- can't block the game main thread
    std::string online_id = g_state.ctx.online_id;
    std::string peer_id = peer_npid;
    std::string session_id = g_state.ctx.session_id;
    u16 member_id = g_state.ctx.my_member_id;
    std::string server_host = g_state.server_host;

    std::thread([=]() {
        try {
            std::string body = "{\"OnlineId\":\"" + online_id + "\",\"PeerOnlineId\":\"" + peer_id +
                               "\",\"ConnId\":" + std::to_string(conn_id) + ",\"SessionId\":\"" +
                               session_id + "\",\"MemberId\":" + std::to_string(member_id) + "}";
            httplib::Client cli(server_host);
            cli.set_connection_timeout(3);
            cli.set_read_timeout(3);
            auto res = cli.Post("/np/signaling/activate", body, "application/json");
            if (res && res->status / 100 == 2) {
                NP_LOG("PostSignalingActivation: {} -> {} conn_id={} OK", online_id, peer_id,
                       conn_id);
            } else {
                LOG_ERROR(Lib_NpMatching2, "PostSignalingActivation: {} -> {} FAILED", online_id,
                          peer_id);
            }
        } catch (const std::exception& e) {
            LOG_ERROR(Lib_NpMatching2, "PostSignalingActivation: exception: {}", e.what());
        } catch (...) {
            LOG_ERROR(Lib_NpMatching2, "PostSignalingActivation: unknown exception");
        }
    }).detach();
}

void PostSignalingConfirm(const std::string& my_npid, const std::string& peer_npid) {
    if (g_state.server_host.empty())
        return;

    std::string server_host = g_state.server_host;
    std::thread([=]() {
        try {
            std::string body = "{\"OnlineId\":\"" + my_npid + "\",\"PeerOnlineId\":\"" + peer_npid +
                               "\",\"ConnId\":0}";
            httplib::Client cli(server_host);
            cli.set_connection_timeout(3);
            cli.set_read_timeout(3);
            auto res = cli.Post("/np/signaling/confirm", body, "application/json");
            if (res && res->status / 100 == 2) {
                NP_LOG("PostSignalingConfirm: {} confirmed peer {} OK", my_npid, peer_npid);
            } else {
                LOG_ERROR(Lib_NpMatching2, "PostSignalingConfirm: {} -> {} FAILED", my_npid,
                          peer_npid);
            }
        } catch (const std::exception& e) {
            LOG_ERROR(Lib_NpMatching2, "PostSignalingConfirm: exception: {}", e.what());
        } catch (...) {
            LOG_ERROR(Lib_NpMatching2, "PostSignalingConfirm: unknown exception");
        }
    }).detach();
}

void PostSignalingActive(const std::string& peer_npid) {
    if (g_state.server_host.empty() || g_state.ctx.online_id.empty() ||
        g_state.ctx.session_id.empty())
        return;

    std::string server_host = g_state.server_host;
    std::string online_id = g_state.ctx.online_id;
    std::string session_id = g_state.ctx.session_id;
    u16 member_id = g_state.ctx.my_member_id;

    std::thread([=]() {
        try {
            std::string body = "{\"OnlineId\":\"" + online_id + "\",\"PeerOnlineId\":\"" +
                               peer_npid + "\",\"SessionId\":\"" + session_id +
                               "\",\"MemberId\":" + std::to_string(member_id) + "}";
            httplib::Client cli(server_host);
            cli.set_connection_timeout(3);
            cli.set_read_timeout(3);
            auto res = cli.Post("/np/signaling/active", body, "application/json");
            if (res && res->status / 100 == 2) {
                NP_LOG("PostSignalingActive: {} -> {} OK", online_id, peer_npid);
            } else {
                LOG_ERROR(Lib_NpMatching2, "PostSignalingActive: {} -> {} FAILED", online_id,
                          peer_npid);
            }
        } catch (const std::exception& e) {
            LOG_ERROR(Lib_NpMatching2, "PostSignalingActive: exception: {}", e.what());
        } catch (...) {
            LOG_ERROR(Lib_NpMatching2, "PostSignalingActive: unknown exception");
        }
    }).detach();
}

void HandleSignalingEstablished(const std::string& peer_online_id, u16 peer_member_id,
                                s32 conn_id) {
    NP_LOG("HandleSignalingEstablished: peer='{}' member={} conn_id={}", peer_online_id,
           peer_member_id, conn_id);

    // Set server_confirmed flag on the NpSignaling connection.
    // The state machine advances and fires 0x5102/0x1105 at the right time.
    NpSignaling::SetServerConfirmed(peer_online_id);

    NP_LOG("HandleSignalingEstablished: set server_confirmed for peer='{}'", peer_online_id);
}

// --- HTTP helper ---

static std::string HttpPost(const std::string& path, const std::string& body) {
    httplib::Client cli(g_state.server_host);
    cli.set_connection_timeout(5);
    cli.set_read_timeout(5);
    auto res = cli.Post(path, body, "application/json");
    if (res && res->status / 100 == 2) {
        return res->body;
    }
    LOG_ERROR(Lib_NpMatching2, "HTTP POST {} failed: {}", path,
              res ? std::to_string(res->status) : "connection error");
    return "";
}

static std::string HttpGet(const std::string& path) {
    httplib::Client cli(g_state.server_host);
    cli.set_connection_timeout(5);
    cli.set_read_timeout(5);
    auto res = cli.Get(path);
    if (res && res->status / 100 == 2) {
        return res->body;
    }
    LOG_ERROR(Lib_NpMatching2, "HTTP GET {} failed: {}", path,
              res ? std::to_string(res->status) : "connection error");
    return "";
}

// --- Callback data construction ---

static void BuildCallbackData(u64 room_id, u16 server_id, const std::vector<MemberInfo>& members,
                              u16 host_member_id, u16 my_member_id) {
    std::lock_guard<std::mutex> lock(g_state.mutex);

    // Free previous data
    g_state.FreeCallbackData();

    int num_members = static_cast<int>(members.size());
    if (num_members == 0)
        num_members = 1; // At minimum, the local player

    // Allocate room data
    auto* room = new OrbisNpMatching2RoomDataInternal();
    std::memset(room, 0, sizeof(*room));
    room->serverId = server_id;
    room->worldId = 1;
    room->roomId = room_id;
    room->maxSlot = 4;
    room->membersNum = host_member_id;

    // Allocate member entries
    auto* member_arr = new OrbisNpMatching2RoomMemberDataInternal[num_members]();

    OrbisNpMatching2RoomMemberDataInternal* me_ptr = nullptr;

    for (int i = 0; i < num_members; i++) {
        std::memset(&member_arr[i], 0, sizeof(member_arr[i]));

        // Link list
        member_arr[i].next = (i + 1 < num_members) ? &member_arr[i + 1] : nullptr;

        // Set member ID
        if (i < static_cast<int>(members.size())) {
            member_arr[i].memberId = static_cast<u16>(members[i].member_id);
            // Copy OnlineId
            std::strncpy(member_arr[i].npId.handle.data, members[i].online_id.c_str(),
                         ORBIS_NP_ONLINEID_MAX_LENGTH - 1);
        } else {
            member_arr[i].memberId = my_member_id;
        }

        if (member_arr[i].memberId == my_member_id) {
            me_ptr = &member_arr[i];
        }
    }

    std::string member_ids;
    for (int i = 0; i < num_members; i++) {
        if (!member_ids.empty()) {
            member_ids += ",";
        }
        member_ids += std::to_string(member_arr[i].memberId);
    }

    // Set room member pointers
    room->members = &member_arr[0];
    room->me = me_ptr;
    room->owner = &member_arr[0]; // first member is owner (host)

    // Build response
    auto* response = new OrbisNpMatching2CreateJoinRoomResponse();
    response->roomDataInternal = room;
    response->members = &member_arr[0];
    response->membersNum = static_cast<u64>(num_members);
    response->me = me_ptr;
    response->owner = &member_arr[0]; // first member is owner (host)

    // Store for lifetime management
    g_state.last_room_data = room;
    g_state.last_member_data = member_arr;
    g_state.last_member_count = num_members;
    g_state.last_response = response;

    LOG_INFO(Lib_NpMatching2,
             "BuildCallbackData: room={} server={} host_member_id={} "
             "my_member_id={} members_in={} members_out={} me_present={} ids=[{}]",
             room_id, server_id, host_member_id, my_member_id, members.size(), num_members,
             (me_ptr != nullptr), member_ids);
}

// Forward declaration -- HostMemberPollThreadFunc is defined below but
// referenced in InvitePollThreadFunc's HOST notification handler.
static PS4_SYSV_ABI void* HostMemberPollThreadFunc(void* arg);

// Forward declaration of AsyncJoinRoomArgs and JoinRoomThreadFunc for use
// in InvitePollThreadFunc (full definitions appear later in the file).
struct AsyncJoinRoomArgs {
    u16 ctx_id;
    u32 req_id;
    u64 target_room_id;
    OrbisNpMatching2RequestCallback callback;
    void* callback_arg;
    std::string online_id;
    u16 signaling_port;
    u16 server_id;
    bool already_joined; // true if invite poll already joined this room
};
static PS4_SYSV_ABI void* JoinRoomThreadFunc(void* arg);
static PS4_SYSV_ABI void* GuestPollThreadFunc(void* arg);
static bool HandleHostPeerJoinedEvent(const MemberInfo& member, const char* source);
static bool HandleHostPeerLeftEvent(u16 departed_member_id, const std::string& online_id, u8 reason,
                                    const char* source);
static void ScheduleRoomEventMemberLeft(u16 departed_member_id, u8 reason,
                                        std::chrono::steady_clock::time_point fire_at);
static void ScheduleRoomEventKickedout(std::chrono::steady_clock::time_point fire_at);
static void ScheduleRoomEventRoomDestroyed(std::chrono::steady_clock::time_point fire_at);

// --- WebSocket URL construction helper ---
// Strips protocol prefix from g_state.server_host and extracts host:port.
// e.g. "http://192.168.1.50:18671" -> host="192.168.1.50", port=18671
static bool ParseServerHostPort(std::string& out_host, int& out_port) {
    std::string url = g_state.server_host;
    // Strip http:// or https:// protocol prefix
    auto proto = url.find("://");
    if (proto != std::string::npos)
        url = url.substr(proto + 3);
    // Split host:port
    auto colon = url.find(':');
    if (colon != std::string::npos) {
        out_host = url.substr(0, colon);
        out_port = std::stoi(url.substr(colon + 1));
    } else {
        out_host = url;
        out_port = 18671;
    }
    return !out_host.empty();
}

// --- Event handling (shared between WebSocket and HTTP poll paths) ---

static void HandlePollEvent(const std::string& resp);

// --- Invite polling thread ---
//
// Runs as a PS4 thread (via posix_pthread_create) so it has valid g_curthread
// for firing guest callbacks that use PS4 mutexes.
// Uses WebSocket for instant event delivery, with HTTP polling as fallback.
// Events: guest_invite, host_room_ready, room_member_*, room_closed

static PS4_SYSV_ABI void* InvitePollThreadFunc(void* /*arg*/) {
    LOG_INFO(Lib_NpMatching2, "invite poll PS4 thread started for online_id={}",
             g_state.ctx.online_id);

    while (g_state.poll_thread_running) {
        // --- Try WebSocket connection ---
        if (!g_state.ws_client ||
            g_state.ws_client->getReadyState() == easywsclient::WebSocket::CLOSED) {
            g_state.ws_client.reset();

            std::string ws_host;
            int ws_port = 0;
            if (ParseServerHostPort(ws_host, ws_port)) {
                std::string ws_url = "ws://" + ws_host + ":" + std::to_string(ws_port) +
                                     "/np/events/ws?online_id=" + g_state.ctx.online_id;
                g_state.ws_client.reset(easywsclient::WebSocket::from_url(ws_url));
                if (g_state.ws_client) {
                    LOG_INFO(Lib_NpMatching2, "WebSocket connected to {}", ws_url);
                    g_state.ws_last_heartbeat = std::chrono::steady_clock::now();
                    g_state.ws_attempted = true;
                } else if (!g_state.ws_attempted) {
                    LOG_WARNING(Lib_NpMatching2,
                                "WebSocket connection failed, falling back to HTTP polling");
                    g_state.ws_attempted = true;
                }
            }
        }

        // --- WebSocket path (instant events) ---
        if (g_state.ws_client &&
            g_state.ws_client->getReadyState() == easywsclient::WebSocket::OPEN) {
            g_state.ws_client->poll(2000); // 2s timeout (recv or timeout)

            // Dispatch all received messages
            g_state.ws_client->dispatch([](const std::string& msg) {
                auto msg_type = JsonGetString(msg, "type");
                if (msg_type == "ping") {
                    if (g_state.ws_client) {
                        g_state.ws_client->send("{\"type\":\"pong\"}");
                    }
                    return;
                }
                if (msg_type != "event")
                    return;

                // Process event (same logic as HTTP poll response)
                HandlePollEvent(msg);
            });

            // Periodic heartbeat via WebSocket (every 10s)
            auto now_hb = std::chrono::steady_clock::now();
            if (g_state.ctx.room_id != 0 && !g_state.ctx.session_id.empty() &&
                now_hb - g_state.ws_last_heartbeat >= std::chrono::seconds(10)) {
                g_state.ws_last_heartbeat = now_hb;
                std::string hb =
                    "{\"type\":\"heartbeat\",\"session_id\":\"" + g_state.ctx.session_id +
                    "\",\"member_id\":" + std::to_string(g_state.ctx.my_member_id) + "}";
                g_state.ws_client->send(hb);
            }

            continue; // skip HTTP polling path
        }

        // --- HTTP polling fallback (existing behavior) ---
        for (int i = 0; i < 20 && g_state.poll_thread_running; i++) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        if (!g_state.poll_thread_running)
            break;

        // HOST heartbeat via HTTP (when WebSocket is not available)
        if (g_state.ctx.room_id != 0 && g_state.ctx.my_member_id == 1 &&
            !g_state.ctx.session_id.empty()) {
            thread_local auto last_heartbeat = std::chrono::steady_clock::now();
            auto now_hb = std::chrono::steady_clock::now();
            if (now_hb - last_heartbeat >= std::chrono::seconds(10)) {
                last_heartbeat = now_hb;
                std::string hb_path =
                    "/mp/matching2/room_members?SessionId=" + g_state.ctx.session_id +
                    "&MemberId=" + std::to_string(g_state.ctx.my_member_id);
                auto hb_resp = HttpGet(hb_path);
                LOG_INFO(Lib_NpMatching2, "invite poll: HOST heartbeat sent (session={} member={})",
                         g_state.ctx.session_id, g_state.ctx.my_member_id);
            }
        }

        // Poll NP event queue for matching2 lifecycle events.
        std::string poll_body = "{";
        poll_body += "\"OnlineId\": \"" + g_state.ctx.online_id + "\",";
        poll_body += "\"Cursor\": " + std::to_string(g_state.np_events_cursor) + ",";
        poll_body += "\"Categories\": [\"matching2\"],";
        poll_body += "\"MaxEvents\": 1";
        poll_body += "}";

        auto resp = HttpPost("/np/events/poll", poll_body);
        if (resp.empty()) {
            std::string legacy_path =
                "/mp/matching2/poll_invite?online_id=" + g_state.ctx.online_id;
            resp = HttpGet(legacy_path);
            if (resp.empty()) {
                continue;
            }
        }

        HandlePollEvent(resp);
    }

    // Cleanup WebSocket on exit
    if (g_state.ws_client) {
        g_state.ws_client->close();
        g_state.ws_client.reset();
    }

    LOG_INFO(Lib_NpMatching2, "invite poll PS4 thread stopped");
    return nullptr;
}

// --- HandlePollEvent: processes a single event from either WebSocket or HTTP poll ---
// Both paths call this with a JSON string containing event data.

static void HandlePollEvent(const std::string& resp) {
    auto has_invite = 0;
    bool handled_lifecycle_event = false;
    auto event_id = static_cast<u64>(JsonGetInt(resp, "EventId"));
    auto event_name = JsonGetString(resp, "Name");
    const bool has_event = (JsonGetInt(resp, "HasEvent") != 0) || !event_name.empty();
    if (has_event) {
        if (event_name == "guest_invite") {
            has_invite = 1;
        } else if (event_name == "host_room_ready") {
            has_invite = 2;
        } else if (event_name == "room_member_joined") {
            MemberInfo m{};
            m.member_id = static_cast<int>(JsonGetInt(resp, "MemberId"));
            m.online_id = JsonGetString(resp, "OnlineId");
            m.addr = JsonGetString(resp, "Addr");
            m.port = static_cast<int>(JsonGetInt(resp, "Port"));
            m.local_addr = JsonGetString(resp, "LocalAddr");
            m.local_port = static_cast<int>(JsonGetInt(resp, "LocalPort"));
            m.mapped_addr = JsonGetString(resp, "MappedAddr");
            m.mapped_port = static_cast<int>(JsonGetInt(resp, "MappedPort"));
            auto event_room = static_cast<u64>(JsonGetInt(resp, "RoomId"));
            auto event_session = JsonGetString(resp, "SessionId");
            if ((g_state.ctx.room_id != 0 && event_room != g_state.ctx.room_id) ||
                (!g_state.ctx.session_id.empty() && !event_session.empty() &&
                 event_session != g_state.ctx.session_id)) {
                LOG_WARNING(Lib_NpMatching2,
                            "invite poll: ignoring room_member_joined for stale room/session "
                            "(event_room={} ctx_room={} event_session='{}' ctx_session='{}')",
                            event_room, g_state.ctx.room_id, event_session, g_state.ctx.session_id);
                handled_lifecycle_event = true;
            } else {
                LOG_INFO(Lib_NpMatching2,
                         "invite poll: HOST lifecycle event room_member_joined "
                         "room={} session={} member={} online_id='{}' addr='{}' port={}",
                         event_room, event_session, m.member_id, m.online_id, m.addr, m.port);
                HandleHostPeerJoinedEvent(m, "np_event");
                handled_lifecycle_event = true;
            }
        } else if (event_name == "room_member_left") {
            auto dep_mid = static_cast<u16>(JsonGetInt(resp, "MemberId"));
            auto dep_oid = JsonGetString(resp, "OnlineId");
            auto reason_str = JsonGetString(resp, "Reason");
            // Use MEMBER_DISAPPEARED for server-reported departures.
            u8 reason = ORBIS_NP_MATCHING2_EVENT_CAUSE_MEMBER_DISAPPEARED;
            auto event_room = static_cast<u64>(JsonGetInt(resp, "RoomId"));
            auto event_session = JsonGetString(resp, "SessionId");
            if ((g_state.ctx.room_id != 0 && event_room != g_state.ctx.room_id) ||
                (!g_state.ctx.session_id.empty() && !event_session.empty() &&
                 event_session != g_state.ctx.session_id)) {
                LOG_WARNING(Lib_NpMatching2,
                            "invite poll: ignoring room_member_left for stale room/session "
                            "(event_room={} ctx_room={} event_session='{}' ctx_session='{}')",
                            event_room, g_state.ctx.room_id, event_session, g_state.ctx.session_id);
                handled_lifecycle_event = true;
            } else {
                LOG_INFO(Lib_NpMatching2,
                         "invite poll: HOST lifecycle event room_member_left "
                         "room={} session={} member={} online_id='{}' reason='{}'",
                         event_room, event_session, dep_mid, dep_oid, reason_str);
                HandleHostPeerLeftEvent(dep_mid, dep_oid, reason, "np_event");
                handled_lifecycle_event = true;
            }
        } else if (event_name == "room_member_kicked") {
            // GUEST was kicked by HOST -- fire MemberLeft with KICKOUT cause
            auto event_room = static_cast<u64>(JsonGetInt(resp, "RoomId"));
            auto event_session = JsonGetString(resp, "SessionId");
            auto kick_mid = static_cast<u16>(JsonGetInt(resp, "MemberId"));
            auto kick_oid = JsonGetString(resp, "OnlineId");
            LOG_WARNING(Lib_NpMatching2,
                        "invite poll: KICKED from room={} session={} member={} online_id='{}'",
                        event_room, event_session, kick_mid, kick_oid);

            // Fire Kickedout (0x1103) room event (not MemberLeft 0x1102).
            // The kicked player receives 0x1103 which triggers session exit.
            auto now = std::chrono::steady_clock::now();
            ScheduleRoomEventKickedout(now);

            // Do NOT clear session state here. The game needs room_id and
            // peers intact when processing the 0x1103 event. The game's
            // native LeaveRoom handler does cleanup after processing.

            handled_lifecycle_event = true;
        } else if (event_name == "room_closed") {
            auto event_room = static_cast<u64>(JsonGetInt(resp, "RoomId"));
            auto event_session = JsonGetString(resp, "SessionId");
            auto reason = JsonGetString(resp, "Reason");
            LOG_WARNING(Lib_NpMatching2,
                        "invite poll: lifecycle room_closed room={} session={} reason='{}'",
                        event_room, event_session, reason);

            // Only process if this is our current room
            if (g_state.ctx.room_id != 0 &&
                (event_room == 0 || event_room == g_state.ctx.room_id)) {
                auto now = std::chrono::steady_clock::now();

                // Fire RoomDestroyed (0x1104) so the game exits cleanly.
                ScheduleRoomEventRoomDestroyed(now);

                // Fire Dead (0x5101) for all peers.
                {
                    std::lock_guard<std::mutex> plock(g_state.peers_mutex);
                    for (const auto& [mid, pi] : g_state.peers) {
                        PendingEvent sig_ev{};
                        sig_ev.type = PendingEvent::SIGNALING_CB;
                        sig_ev.fire_at = now + std::chrono::milliseconds(100);
                        sig_ev.room_id = g_state.ctx.room_id;
                        sig_ev.member_id = mid;
                        sig_ev.sig_event = ORBIS_NP_MATCHING2_SIGNALING_EVENT_DEAD;
                        sig_ev.conn_id = static_cast<u32>(mid);
                        ScheduleEvent(std::move(sig_ev));
                    }
                    g_state.peers.clear();
                }

                g_state.ctx.room_id = 0;
                g_state.ctx.my_member_id = 0;
                g_state.ctx.session_id.clear();
                NpSignaling::ClearConnections();
                g_state.known_member_count = 0;
                g_state.host_self_established_fired.store(false);
                {
                    std::lock_guard<std::mutex> inv_lock(g_state.pending_guest_invite_mutex);
                    g_state.pending_guest_invite = {};
                }
            }

            handled_lifecycle_event = true;
        } else if (event_name == "signaling_established") {
            // Server confirmed bilateral signaling activation for a peer pair.
            auto peer_online_id = JsonGetString(resp, "PeerOnlineId");
            auto peer_member_id = static_cast<u16>(JsonGetInt(resp, "MemberId"));
            auto sig_conn_id = static_cast<s32>(JsonGetInt(resp, "ConnId"));
            LOG_WARNING(Lib_NpMatching2,
                        "invite poll: signaling_established peer='{}' member={} conn_id={}",
                        peer_online_id, peer_member_id, sig_conn_id);
            HandleSignalingEstablished(peer_online_id, peer_member_id, sig_conn_id);
            handled_lifecycle_event = true;
        } else if (event_name == "signaling_event") {
            // Server pushes signaling events (ESTABLISHED/DEAD) for room members.
            // Update peers map status and schedule the callback.
            auto sig_event = static_cast<u16>(JsonGetInt(resp, "sig_event"));
            auto sig_member = static_cast<u16>(JsonGetInt(resp, "MemberId"));
            auto sig_conn = static_cast<s32>(JsonGetInt(resp, "ConnId"));
            LOG_WARNING(Lib_NpMatching2, "invite poll: signaling_event sig={:#x} member={} conn={}",
                        sig_event, sig_member, sig_conn);
            if (sig_member > 0 && sig_member != g_state.ctx.my_member_id &&
                g_state.host_self_established_fired.load()) {
                // Update peer status in the peers map.
                {
                    std::lock_guard<std::mutex> plock(g_state.peers_mutex);
                    auto peer_it = g_state.peers.find(sig_member);
                    if (peer_it != g_state.peers.end()) {
                        peer_it->second.status =
                            (sig_event == ORBIS_NP_MATCHING2_SIGNALING_EVENT_ESTABLISHED)
                                ? ORBIS_NP_MATCHING2_SIGNALING_CONN_STATUS_ACTIVE
                                : ORBIS_NP_MATCHING2_SIGNALING_CONN_STATUS_INACTIVE;
                    }
                }

                auto now_ev = std::chrono::steady_clock::now();
                PendingEvent ev{};
                ev.type = PendingEvent::SIGNALING_CB;
                ev.fire_at = now_ev;
                ev.room_id = g_state.ctx.room_id;
                ev.member_id = sig_member;
                ev.sig_event = sig_event;
                ev.conn_id = static_cast<u32>(sig_member);
                ScheduleEvent(std::move(ev));
            }
            handled_lifecycle_event = true;
        } else if (event_name == "signaling_update") {
            // Logged but not fired from this path.
            LOG_WARNING(Lib_NpMatching2, "invite poll: signaling_update (logged, not fired)");
            handled_lifecycle_event = true;
        } else if (event_name == "mutual_activated") {
            // Server pushes when BOTH sides reported ACTIVE (SignalingEstablished).
            // On real PS4, PSN sends MutualActivated (UDP cmd=0x03) to both peers.
            auto peer_oid = JsonGetString(resp, "PeerOnlineId");
            auto peer_mid = static_cast<u16>(JsonGetInt(resp, "MemberId"));
            LOG_WARNING(Lib_NpMatching2, "invite poll: mutual_activated peer='{}' member={}",
                        peer_oid, peer_mid);
            s32 sig_conn = NpSignaling::GetSignalingConnId(peer_oid);
            if (sig_conn > 0) {
                NpSignaling::DeliverSignalingEvent(
                    g_state.ctx.ctx_id, sig_conn,
                    NpSignaling::ORBIS_NP_SIGNALING_EVENT_MUTUAL_ACTIVATED, 0);
            }
            handled_lifecycle_event = true;
        } else if (event_name == "peer_deactivated") {
            // Server pushes peer_deactivated on member departure. Set the
            // NpSignaling connection INACTIVE but do NOT fire PEER_DEACTIVATED
            // (0xb) through the NpSignaling 5-arg callback. The game's
            // Do not fire PEER_DEACTIVATED through the NpSignaling callback
            // as it can trigger full session teardown. The MemberLeft room event
            // (0x1102) is sufficient for graceful departure handling.
            auto dep_oid = JsonGetString(resp, "OnlineId");
            auto dep_mid = static_cast<u16>(JsonGetInt(resp, "MemberId"));
            LOG_WARNING(Lib_NpMatching2,
                        "invite poll: peer_deactivated member={} online_id='{}' "
                        "(NpSignaling set INACTIVE, no callback fired)",
                        dep_mid, dep_oid);
            NpSignaling::SetConnectionInactive(dep_oid);
            handled_lifecycle_event = true;
        } else {
            LOG_WARNING(Lib_NpMatching2, "invite poll: unknown matching2 event '{}'", event_name);
        }
    } else {
        has_invite = static_cast<int>(JsonGetInt(resp, "HasInvite"));
    }

    if (has_invite == 1) {
        // GUEST path: cache invite details and wait for native JoinRoom
        auto room_id = static_cast<u64>(JsonGetInt(resp, "RoomId"));
        auto session_id = JsonGetString(resp, "SessionId");
        auto host_online_id = JsonGetString(resp, "HostOnlineId");
        auto host_addr_raw = JsonGetString(resp, "HostAddr");
        auto host_port_raw = static_cast<u16>(JsonGetInt(resp, "HostPort"));
        auto host_local_addr = JsonGetString(resp, "HostLocalAddr");
        auto host_local_port = static_cast<u16>(JsonGetInt(resp, "HostLocalPort"));

        // Same-NAT detection: if host's public IP matches our STUN-mapped IP,
        // both are behind the same NAT. Use local LAN address to avoid hairpin NAT.
        std::string our_public = GetStunMappedAddrStr();
        bool same_nat = !our_public.empty() && our_public != "0" &&
                        !host_local_addr.empty() && host_local_addr != "0" &&
                        host_addr_raw == our_public;
        auto host_addr = same_nat ? host_local_addr : host_addr_raw;
        auto host_port = same_nat ? host_local_port : host_port_raw;
        if (same_nat) {
            LOG_INFO(Lib_NpMatching2,
                     "Same-NAT detected: host '{}' public={} matches our public={} "
                     "-- using LAN addr '{}:{}'",
                     host_online_id, host_addr_raw, our_public, host_local_addr, host_local_port);
        }

        LOG_INFO(Lib_NpMatching2,
                 "invite poll: GUEST invite! room={} session={} host='{}' "
                 "host_addr='{}' host_port={} self_addr='{}' self_port={}",
                 room_id, session_id, host_online_id, host_addr, host_port, g_state.signaling_addr,
                 g_state.signaling_port);

        // Skip duplicate invites for the same room we already pre-joined.
        if (g_state.ctx.room_id == static_cast<u64>(room_id) && !g_state.ctx.session_id.empty()) {
            LOG_INFO(Lib_NpMatching2,
                     "invite poll: ignoring duplicate invite for room={} "
                     "(already pre-joined as member={})",
                     room_id, g_state.ctx.my_member_id);
            goto ack_event;
        }

        // Clean up stale state from a previous invite/session.
        if (g_state.ctx.room_id != 0 && g_state.ctx.room_id != static_cast<u64>(room_id)) {
            NP_LOG("invite poll: cleaning up stale pre-join state "
                   "(old room={} new room={})",
                   g_state.ctx.room_id, room_id);

            if (!g_state.ctx.session_id.empty()) {
                std::string leave_body = "{";
                leave_body += "\"SessionId\": \"" + g_state.ctx.session_id + "\",";
                leave_body += "\"MemberId\": " + std::to_string(g_state.ctx.my_member_id);
                leave_body += "}";
                HttpPost("/mp/matching2/leave_room", leave_body);
            }

            g_state.ctx.room_id = 0;
            g_state.ctx.session_id.clear();
            g_state.ctx.my_member_id = 0;
            {
                std::lock_guard<std::mutex> plock(g_state.peers_mutex);
                g_state.peers.clear();
            }
            g_state.guest_poll_running = false;
            g_state.host_self_established_fired.store(false);
            NpSignaling::ClearConnections();
            Libraries::Net::ClearP2PSessionState();
        }

        {
            std::lock_guard<std::mutex> invite_lock(g_state.pending_guest_invite_mutex);
            g_state.pending_guest_invite.valid = true;
            g_state.pending_guest_invite.room_id = room_id;
            g_state.pending_guest_invite.session_id = session_id;
            g_state.pending_guest_invite.host_online_id = host_online_id;
            g_state.pending_guest_invite.host_addr = host_addr;
            g_state.pending_guest_invite.host_port = host_port;
            g_state.pending_guest_invite.notify_attempts = 0;
            g_state.pending_guest_invite.last_notify = std::chrono::steady_clock::time_point{};
            g_state.pending_guest_invite.max_retry_logged = false;
        }

        // Store host peer info and call SetPeerInfo for P2P routing.
        {
            PeerInfo host_pi{};
            host_pi.member_id = 1;
            host_pi.addr = IpStringToAddr(host_addr);
            host_pi.port = htons(host_port);
            host_pi.status = ORBIS_NP_MATCHING2_SIGNALING_CONN_STATUS_INACTIVE;
            host_pi.online_id = host_online_id;
            {
                std::lock_guard<std::mutex> plock(g_state.peers_mutex);
                g_state.peers[host_pi.member_id] = host_pi;
            }

            NpSignaling::SetPeerInfo(host_pi.member_id, host_pi.addr, host_pi.port, host_online_id);

            LOG_INFO(Lib_NpMatching2,
                     "invite poll: stored HOST peer member={} addr={} port={} "
                     "(SetPeerInfo for routing, ESTABLISHED deferred until JoinRoom)",
                     host_pi.member_id, host_addr, host_port);
        }

        // Pre-join the room on the server (no game callbacks yet).
        {
            std::string invite_mapped_addr = GetStunMappedAddrStr();
            u16 invite_mapped_port = GetStunMappedPortHost();
            std::string join_body = "{";
            join_body += "\"OnlineId\": \"" + g_state.ctx.online_id + "\",";
            join_body += "\"RoomId\": " + std::to_string(room_id) + ",";
            join_body += "\"LocalAddr\": \"" + g_state.signaling_addr + "\",";
            join_body += "\"LocalPort\": " + std::to_string(g_state.signaling_port) + ",";
            join_body += "\"PublicAddr\": \"" + g_state.signaling_addr + "\",";
            join_body += "\"PublicPort\": " + std::to_string(g_state.signaling_port) + ",";
            join_body += "\"MappedAddr\": \"" + invite_mapped_addr + "\",";
            join_body += "\"MappedPort\": " + std::to_string(invite_mapped_port);
            join_body += "}";

            auto join_resp = HttpPost("/mp/matching2/join_room", join_body);
            if (!join_resp.empty()) {
                g_state.ctx.room_id = room_id;
                g_state.ctx.my_member_id = static_cast<u16>(JsonGetInt(join_resp, "MemberId"));
                g_state.ctx.session_id = session_id;

                LOG_INFO(Lib_NpMatching2, "invite poll: HTTP join done, room={} member={}", room_id,
                         g_state.ctx.my_member_id);

                {
                    PeerInfo self_pi;
                    self_pi.member_id = g_state.ctx.my_member_id;
                    self_pi.online_id = g_state.ctx.online_id;
                    self_pi.addr = IpStringToAddr(g_state.signaling_addr);
                    self_pi.port = htons(g_state.signaling_port);
                    self_pi.status = ORBIS_NP_MATCHING2_SIGNALING_CONN_STATUS_ACTIVE;
                    {
                        std::lock_guard<std::mutex> plock(g_state.peers_mutex);
                        g_state.peers[g_state.ctx.my_member_id] = self_pi;
                    }
                }

                Libraries::Net::KernelP2PSubsystem::Instance().OnRoomJoined(
                    room_id, g_state.ctx.my_member_id);

                LOG_INFO(Lib_NpMatching2,
                         "invite poll: pre-joined room={} member={} "
                         "(P2P tunnel active, awaiting TYPE=1 from HOST)",
                         room_id, g_state.ctx.my_member_id);

                // Multi-peer: start guest poll thread early (only if WebSocket is down —
                // when WS is active, HandlePollEvent handles all member lifecycle events).
                bool ws_active = g_state.ws_client &&
                    g_state.ws_client->getReadyState() == easywsclient::WebSocket::OPEN;
                if (g_state.ctx.my_member_id >= 3 && !g_state.guest_poll_running && !ws_active) {
                    g_state.guest_poll_running = true;
                    Kernel::PthreadT gp_thread = nullptr;
                    int gp_ret = Kernel::posix_pthread_create(&gp_thread, nullptr,
                                                              GuestPollThreadFunc, nullptr);
                    if (gp_ret == 0) {
                        std::lock_guard<std::mutex> lock(g_state.async_threads_mutex);
                        g_state.async_threads.push_back(gp_thread);
                        LOG_INFO(Lib_NpMatching2,
                                 "invite poll: multi-peer join (member={}), "
                                 "started guest poll thread for mesh peer detection",
                                 g_state.ctx.my_member_id);
                    } else {
                        g_state.guest_poll_running = false;
                        LOG_ERROR(Lib_NpMatching2,
                                  "invite poll: failed to start guest poll "
                                  "thread: {}",
                                  gp_ret);
                    }
                }
            } else {
                LOG_ERROR(Lib_NpMatching2, "invite poll: pre-join failed for room={}", room_id);
            }
        }

        LOG_INFO(Lib_NpMatching2, "invite poll (guest): cached invite room={} session={} host={}",
                 room_id, session_id, host_online_id);

    } else if (has_invite == 2) {
        // HOST path: room was auto-created by the server
        auto room_id = static_cast<u64>(JsonGetInt(resp, "RoomId"));
        auto session_id = JsonGetString(resp, "SessionId");
        auto guest_oid = JsonGetString(resp, "GuestOnlineId");

        LOG_INFO(Lib_NpMatching2, "invite poll: HOST notification! room={} session={} guest={}",
                 room_id, session_id, guest_oid);

        g_state.ctx.room_id = room_id;
        g_state.ctx.my_member_id = 1;
        g_state.ctx.session_id = session_id;

        LOG_INFO(Lib_NpMatching2,
                 "invite poll (host): room state stored (id={}). "
                 "Waiting for game to call sceNpMatching2CreateJoinRoom.",
                 room_id);
    } else if (!handled_lifecycle_event) {
        // No event to process this cycle
    }

ack_event:
    if (event_id > 0) {
        // ACK via WebSocket if connected, otherwise HTTP
        if (g_state.ws_client &&
            g_state.ws_client->getReadyState() == easywsclient::WebSocket::OPEN) {
            std::string ack = "{\"type\":\"ack\",\"cursor\":" + std::to_string(event_id) + "}";
            g_state.ws_client->send(ack);
        } else {
            std::string ack_body = "{";
            ack_body += "\"OnlineId\": \"" + g_state.ctx.online_id + "\",";
            ack_body += "\"Cursor\": " + std::to_string(event_id);
            ack_body += "}";
            auto ack_resp = HttpPost("/np/events/ack", ack_body);
            if (ack_resp.empty()) {
                LOG_WARNING(Lib_NpMatching2,
                            "invite poll: failed to ack event_id={} (will retry on next poll)",
                            event_id);
            }
        }
        g_state.np_events_cursor = event_id;
    }
}

// --- Core lifecycle ---

s32 PS4_SYSV_ABI sceNpMatching2Initialize() {
    NP_LOG("API sceNpMatching2Initialize: called");
    g_state.initialized = true;

    return ORBIS_OK;
}

s32 PS4_SYSV_ABI sceNpMatching2Terminate() {
    NP_LOG("API sceNpMatching2Terminate: called");
    g_state.StopPollThread();
    g_state.initialized = false;
    g_state.FreeCallbackData();
    {
        std::lock_guard<std::mutex> plock(g_state.peers_mutex);
        g_state.peers.clear();
    }
    NpSignaling::ClearConnections();
    return ORBIS_OK;
}

s32 PS4_SYSV_ABI sceNpMatching2SetExtraInitParam(void* param) {
    NP_LOG("API sceNpMatching2SetExtraInitParam: called param={}", param);
    if (param) {
        auto* p = reinterpret_cast<OrbisNpMatching2ExtraInitParam*>(param);
        g_state.signaling_port = p->signalingPort;
        LOG_INFO(Lib_NpMatching2, "signaling port set to {}", g_state.signaling_port);
    }
    return ORBIS_OK;
}

// --- Context management ---

s32 PS4_SYSV_ABI sceNpMatching2CreateContext(const void* reqParam, u16* ctxId) {
    NP_LOG("API sceNpMatching2CreateContext: called reqParam={} ctxId={}", reqParam, (void*)ctxId);

    g_state.ctx.ctx_id = 1;
    g_state.ctx.started = false;

    // reqParam is a struct with NpId* at offset 0x00
    if (reqParam) {
        auto* npIdPtr = *reinterpret_cast<const OrbisNpId* const*>(reqParam);
        if (npIdPtr) {
            g_state.ctx.online_id = std::string(
                npIdPtr->handle.data, strnlen(npIdPtr->handle.data, ORBIS_NP_ONLINEID_MAX_LENGTH));
        }
    }
    if (g_state.ctx.online_id.empty()) {
        g_state.ctx.online_id = "shadPS4_player";
    }

    if (ctxId) {
        *ctxId = g_state.ctx.ctx_id;
    }

    LOG_INFO(Lib_NpMatching2, "context created: id={} online_id={}", g_state.ctx.ctx_id,
             g_state.ctx.online_id);
    return ORBIS_OK;
}

s32 PS4_SYSV_ABI sceNpMatching2CreateContextInternal(const void* reqParam, u16* ctxId) {
    NP_LOG("API sceNpMatching2CreateContextInternal: called (forwarding)");
    return sceNpMatching2CreateContext(reqParam, ctxId);
}

s32 PS4_SYSV_ABI sceNpMatching2CreateContextA(const void* reqParam, u16* ctxId) {
    NP_LOG("API sceNpMatching2CreateContextA: called (forwarding)");
    return sceNpMatching2CreateContext(reqParam, ctxId);
}

// Context callback is scheduled via PendingEvent::CONTEXT_CB at T+200ms.

s32 PS4_SYSV_ABI sceNpMatching2ContextStart(u16 ctxId, void* optParam) {
    NP_LOG("API sceNpMatching2ContextStart: called ctxId={} optParam={}", ctxId, optParam);

    g_state.ctx.started = true;
    g_state.np_events_cursor = 0;
    {
        std::lock_guard<std::mutex> invite_lock(g_state.pending_guest_invite_mutex);
        g_state.pending_guest_invite = {};
    }
    g_state.ctx.server_id = 1;

    // Check for signaling address/port overrides via environment variables.
    // Support overriding signaling address/port for multi-instance testing.
    {
        // Check env var first, then config, for signaling address override.
        // SHADPS4_LAN_MODE=1 skips address overrides to keep the auto-detected LAN IP.
        const char* lan_mode = std::getenv("SHADPS4_LAN_MODE");
        bool is_lan_mode = (lan_mode && *lan_mode == '1');
        const char* addr_override = std::getenv("SHADPS4_SIGNALING_ADDR");
        std::string addr_cfg = Config::GetSignalingAddr();
        if (is_lan_mode) {
            LOG_INFO(Lib_NpMatching2,
                     "signaling addr config/env override skipped (SHADPS4_LAN_MODE=1), keeping {}",
                     g_state.signaling_addr);
        } else if (addr_override && addr_override[0]) {
            LOG_INFO(Lib_NpMatching2, "signaling addr overridden by env: {} -> {}",
                     g_state.signaling_addr, addr_override);
            g_state.signaling_addr = addr_override;
        } else if (!addr_cfg.empty()) {
            LOG_INFO(Lib_NpMatching2, "signaling addr overridden by config: {} -> {}",
                     g_state.signaling_addr, addr_cfg);
            g_state.signaling_addr = addr_cfg;
        }
        // Check env var first, then config, for signaling port override.
        const char* port_override = std::getenv("SHADPS4_SIGNALING_PORT");
        int port_cfg = Config::GetSignalingPort();
        if (port_override) {
            int port = std::atoi(port_override);
            if (port > 0 && port < 65536) {
                LOG_INFO(Lib_NpMatching2, "signaling port overridden by env: {} -> {}",
                         g_state.signaling_port, port);
                g_state.signaling_port = static_cast<u16>(port);
            }
        } else if (port_cfg > 0 && port_cfg < 65536) {
            LOG_INFO(Lib_NpMatching2, "signaling port overridden by config: {} -> {}",
                     g_state.signaling_port, port_cfg);
            g_state.signaling_port = static_cast<u16>(port_cfg);
        }
        // Check env var first, then config, for NP server override.
        const char* np_server_override = std::getenv("SHADPS4_NP_SERVER");
        std::string np_server_cfg = Config::GetNpServer();
        if (np_server_override && np_server_override[0]) {
            std::string np_server = np_server_override;
            if (np_server.rfind("http://", 0) != 0 && np_server.rfind("https://", 0) != 0) {
                np_server = "http://" + np_server;
            }
            LOG_INFO(Lib_NpMatching2, "NP server overridden by env: {} -> {}", g_state.server_host,
                     np_server);
            g_state.server_host = np_server;
        } else if (!np_server_cfg.empty()) {
            std::string np_server = np_server_cfg;
            if (np_server.rfind("http://", 0) != 0 && np_server.rfind("https://", 0) != 0) {
                np_server = "http://" + np_server;
            }
            LOG_INFO(Lib_NpMatching2, "NP server overridden by config: {} -> {}",
                     g_state.server_host, np_server);
            g_state.server_host = np_server;
        }

        // Auto-detect LAN IP if signaling address is still loopback.
        // Without this, cross-machine P2P fails because peers receive
        // 127.0.0.1 as the address to connect to.
        if (g_state.signaling_addr == "127.0.0.1") {
#ifdef _WIN32
            // Windows: use gethostname + getaddrinfo to find a non-loopback IPv4 address
            char hostname[256] = {};
            if (::gethostname(hostname, sizeof(hostname)) == 0) {
                struct addrinfo hints{}, *result = nullptr;
                hints.ai_family = AF_INET;
                hints.ai_socktype = SOCK_DGRAM;
                if (::getaddrinfo(hostname, nullptr, &hints, &result) == 0 && result) {
                    for (auto* ai = result; ai; ai = ai->ai_next) {
                        if (ai->ai_family == AF_INET) {
                            auto* sa = reinterpret_cast<sockaddr_in*>(ai->ai_addr);
                            u32 addr = ntohl(sa->sin_addr.s_addr);
                            // Skip loopback
                            if ((addr >> 24) == 127)
                                continue;
                            char buf[INET_ADDRSTRLEN];
                            inet_ntop(AF_INET, &sa->sin_addr, buf, sizeof(buf));
                            LOG_INFO(Lib_NpMatching2,
                                     "signaling addr auto-detected (Windows): {} -> {}",
                                     g_state.signaling_addr, buf);
                            g_state.signaling_addr = buf;
                            break;
                        }
                    }
                    ::freeaddrinfo(result);
                }
            }
#else
            struct ifaddrs* ifaddr = nullptr;
            if (getifaddrs(&ifaddr) == 0) {
                for (auto* ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
                    if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET)
                        continue;
                    if (ifa->ifa_flags & IFF_LOOPBACK)
                        continue;
                    if (!(ifa->ifa_flags & IFF_UP))
                        continue;
                    auto* sa = reinterpret_cast<struct sockaddr_in*>(ifa->ifa_addr);
                    char buf[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &sa->sin_addr, buf, sizeof(buf));
                    LOG_INFO(Lib_NpMatching2,
                             "signaling addr auto-detected from interface '{}': {} -> {}",
                             ifa->ifa_name, g_state.signaling_addr, buf);
                    g_state.signaling_addr = buf;
                    break;
                }
                freeifaddrs(ifaddr);
            }
#endif
        }
    }

    // Push local identity to KernelP2PSubsystem (addr + port + npid for self-connection fast path)
    u32 local_addr = IpStringToAddr(g_state.signaling_addr);
    u16 local_port_nbo = htons(g_state.signaling_port);
    Libraries::Net::KernelP2PSubsystem::Instance().SetLocalIdentity(local_addr, local_port_nbo,
                                                                    g_state.ctx.online_id);
    LOG_INFO(
        Lib_NpMatching2,
        "ContextStart: signaling_addr='{}' ({:#x}) signaling_port={} "
        "server_host='{}' SHADPS4_SIGNALING_ADDR={} "
        "SHADPS4_SIGNALING_PORT={} SHADPS4_NP_SERVER={}",
        g_state.signaling_addr, local_addr, g_state.signaling_port, g_state.server_host,
        std::getenv("SHADPS4_SIGNALING_ADDR") ? std::getenv("SHADPS4_SIGNALING_ADDR") : "(unset)",
        std::getenv("SHADPS4_SIGNALING_PORT") ? std::getenv("SHADPS4_SIGNALING_PORT") : "(unset)",
        std::getenv("SHADPS4_NP_SERVER") ? std::getenv("SHADPS4_NP_SERVER") : "(unset)");

    // Notify server of context start (include signaling address so the
    // server knows our addr:port for auto-room creation at summon/request)
    std::string mapped_addr = GetStunMappedAddrStr();
    u16 mapped_port = GetStunMappedPortHost();
    std::string body = "{";
    body += "\"OnlineId\": \"" + g_state.ctx.online_id + "\",";
    body += "\"SignalingAddr\": \"" + g_state.signaling_addr + "\",";
    body += "\"SignalingPort\": " + std::to_string(g_state.signaling_port) + ",";
    body += "\"MappedAddr\": \"" + mapped_addr + "\",";
    body += "\"MappedPort\": " + std::to_string(mapped_port);
    body += "}";
    auto resp = HttpPost("/mp/matching2/context_start", body);
    if (!resp.empty()) {
        auto sid = JsonGetInt(resp, "ServerId");
        if (sid > 0)
            g_state.ctx.server_id = static_cast<u16>(sid);
        LOG_INFO(Lib_NpMatching2, "context started, server_id={}", g_state.ctx.server_id);
    }

    // Event dispatch is now handled by DrainReadyEvents() called from
    // sceNpCheckCallback on the game's main thread. No background thread needed.
    g_state.dispatch_running = true; // Keep flag for ScheduleEvent producers

    // Schedule context callback via event queue (fires at T+200ms).
    // This triggers the game's state machine transition from state 1->2,
    // which causes it to call RegisterRoomEventCallback, RegisterSignalingCallback, etc.
    {
        PendingEvent ev{};
        ev.type = PendingEvent::CONTEXT_CB;
        ev.fire_at = std::chrono::steady_clock::now() + std::chrono::milliseconds(200);
        ev.ctx_event = 0x6F02;
        ev.ctx_event_cause = 0;
        ev.error_code = 0;
        ScheduleEvent(std::move(ev));
        LOG_INFO(Lib_NpMatching2, "context callback scheduled (event=0x6F02, T+200ms)");
    }

    // Start background invite polling as PS4 thread (needs valid g_curthread for callbacks)
    if (!g_state.poll_thread_running) {
        g_state.poll_thread_running = true;
        int ret = Kernel::posix_pthread_create(&g_state.poll_thread, nullptr, InvitePollThreadFunc,
                                               nullptr);
        if (ret != 0) {
            LOG_ERROR(Lib_NpMatching2, "Failed to create invite poll PS4 thread: {}", ret);
            g_state.poll_thread_running = false;
        } else {
            LOG_INFO(Lib_NpMatching2, "invite poll PS4 thread created successfully");
        }
    }

    return ORBIS_OK;
}

s32 PS4_SYSV_ABI sceNpMatching2ContextStop(u16 ctxId) {
    NP_LOG("API sceNpMatching2ContextStop: called ctxId={}", ctxId);
    g_state.StopPollThread();
    g_state.ctx.started = false;
    return ORBIS_OK;
}

s32 PS4_SYSV_ABI sceNpMatching2DestroyContext(u16 ctxId) {
    NP_LOG("API sceNpMatching2DestroyContext: called ctxId={}", ctxId);
    g_state.StopPollThread();
    g_state.ctx.started = false;
    g_state.ctx.ctx_id = 0;
    return ORBIS_OK;
}

s32 PS4_SYSV_ABI sceNpMatching2AbortContextStart(u16 ctxId) {
    NP_LOG("API sceNpMatching2AbortContextStart: called ctxId={}", ctxId);
    return ORBIS_OK;
}

// --- Callback registration ---

s32 PS4_SYSV_ABI sceNpMatching2SetDefaultRequestOptParam(u16 ctxId, void* optParam) {
    NP_LOG("API sceNpMatching2SetDefaultRequestOptParam: called ctxId={} optParam={}", ctxId,
           optParam);
    if (optParam) {
        auto* opt = reinterpret_cast<OrbisNpMatching2RequestOptParam*>(optParam);
        g_state.default_request_callback = opt->cbFunc;
        g_state.default_request_callback_arg = opt->cbFuncArg;
        LOG_INFO(Lib_NpMatching2, "SetDefaultRequestOptParam: cbFunc={} cbFuncArg={}",
                 (void*)opt->cbFunc, opt->cbFuncArg);
    }
    return ORBIS_OK;
}

s32 PS4_SYSV_ABI sceNpMatching2RegisterContextCallback(void* cbFunc, void* cbFuncArg) {
    NP_LOG("API sceNpMatching2RegisterContextCallback: cbFunc={} cbFuncArg={}", cbFunc, cbFuncArg);
    g_state.context_callback = reinterpret_cast<OrbisNpMatching2ContextCallback>(cbFunc);
    g_state.context_callback_arg = cbFuncArg;
    return ORBIS_OK;
}

s32 PS4_SYSV_ABI sceNpMatching2RegisterRoomEventCallback(u16 ctxId, void* cbFunc, void* cbFuncArg) {
    NP_LOG("API sceNpMatching2RegisterRoomEventCallback: ctxId={} cbFunc={} cbFuncArg={}", ctxId,
           cbFunc, cbFuncArg);
    g_state.room_event_callback = reinterpret_cast<OrbisNpMatching2RoomEventCallback>(cbFunc);
    g_state.room_event_callback_arg = cbFuncArg;
    return ORBIS_OK;
}

s32 PS4_SYSV_ABI sceNpMatching2RegisterSignalingCallback(u16 ctxId, void* cbFunc, void* cbFuncArg) {
    NP_LOG("API sceNpMatching2RegisterSignalingCallback: ctxId={} cbFunc={} cbFuncArg={}", ctxId,
           cbFunc, cbFuncArg);
    g_state.signaling_callback = reinterpret_cast<OrbisNpMatching2SignalingCallback>(cbFunc);
    g_state.signaling_callback_arg = cbFuncArg;
    return ORBIS_OK;
}

s32 PS4_SYSV_ABI sceNpMatching2RegisterLobbyEventCallback(u16 ctxId, void* cbFunc,
                                                          void* cbFuncArg) {
    NP_LOG("API sceNpMatching2RegisterLobbyEventCallback: ctxId={} cbFunc={} cbFuncArg={}", ctxId,
           cbFunc, cbFuncArg);
    g_state.lobby_event_callback = reinterpret_cast<OrbisNpMatching2LobbyEventCallback>(cbFunc);
    g_state.lobby_event_callback_arg = cbFuncArg;
    return ORBIS_OK;
}

s32 PS4_SYSV_ABI sceNpMatching2RegisterLobbyMessageCallback(u16 ctxId, void* cbFunc,
                                                            void* cbFuncArg) {
    NP_LOG("API sceNpMatching2RegisterLobbyMessageCallback: ctxId={} cbFunc={} cbFuncArg={}", ctxId,
           cbFunc, cbFuncArg);
    g_state.lobby_message_callback = reinterpret_cast<OrbisNpMatching2LobbyMessageCallback>(cbFunc);
    g_state.lobby_message_callback_arg = cbFuncArg;
    return ORBIS_OK;
}

s32 PS4_SYSV_ABI sceNpMatching2RegisterRoomMessageCallback(u16 ctxId, void* cbFunc,
                                                           void* cbFuncArg) {
    NP_LOG("API sceNpMatching2RegisterRoomMessageCallback: ctxId={} cbFunc={} cbFuncArg={}", ctxId,
           cbFunc, cbFuncArg);
    g_state.room_message_callback = reinterpret_cast<OrbisNpMatching2RoomMessageCallback>(cbFunc);
    g_state.room_message_callback_arg = cbFuncArg;
    return ORBIS_OK;
}

s32 PS4_SYSV_ABI sceNpMatching2RegisterManualUdpSignalingCallback(u16 ctxId, void* cbFunc,
                                                                  void* cbFuncArg) {
    NP_LOG("API sceNpMatching2RegisterManualUdpSignalingCallback: (STUB) ctxId={} cbFunc={} "
           "cbFuncArg={}",
           ctxId, cbFunc, cbFuncArg);
    return ORBIS_OK;
}

// --- Room event: MemberLeft (0x1102) ---
// Fires room event callback to notify the game that a member has left.

struct RoomMemberEventPayload {
    OrbisNpMatching2RoomMemberDataInternal member_data{};
    OrbisNpMatching2RoomMemberUpdateInfo update_info{};
};

// SignalingOptParamUpdate event data -- two member IDs.
// Uses 0x1105 (OWNER_CHANGED) to deliver signaling opt param updates.
struct SignalingOptParamUpdatePayload {
    u16 member_id_1; // first member (e.g., self/host)
    u16 member_id_2; // second member (e.g., new peer)
};

static void ScheduleRoomEventSignalingOptParamUpdate(
    u16 member_a, u16 member_b, std::chrono::steady_clock::time_point fire_at) {
    if (!g_state.room_event_callback || g_state.ctx.room_id == 0) {
        return;
    }

    auto payload = std::make_shared<SignalingOptParamUpdatePayload>();
    payload->member_id_1 = member_a;
    payload->member_id_2 = member_b;

    PendingEvent ev{};
    ev.type = PendingEvent::ROOM_EVENT_CB;
    ev.fire_at = fire_at;
    ev.room_id = g_state.ctx.room_id;
    ev.room_event = ORBIS_NP_MATCHING2_ROOM_EVENT_OWNER_CHANGED;
    ev.room_event_data = payload.get();
    ev.room_event_payload = payload;
    ScheduleEvent(std::move(ev));

    NP_LOG("ScheduleSignalingOptParamUpdate: member_a={} member_b={} scheduled", member_a,
           member_b);
}

static void ScheduleRoomEventMemberLeft(u16 departed_member_id, u8 reason,
                                        std::chrono::steady_clock::time_point fire_at) {
    if (!g_state.room_event_callback || g_state.ctx.room_id == 0) {
        LOG_WARNING(Lib_NpMatching2, "FireRoomEventMemberLeft: no room event callback or no room");
        return;
    }

    auto payload = std::make_shared<RoomMemberEventPayload>();
    payload->member_data.memberId = departed_member_id;
    payload->update_info.roomMemberDataInternal = &payload->member_data;
    payload->update_info.eventCause = reason;

    // Schedule room event via dispatch thread
    PendingEvent ev{};
    ev.type = PendingEvent::ROOM_EVENT_CB;
    ev.fire_at = fire_at;
    ev.room_id = g_state.ctx.room_id;
    ev.room_event = ORBIS_NP_MATCHING2_ROOM_EVENT_MEMBER_LEFT;
    ev.room_event_data = &payload->update_info;
    ev.room_event_payload = payload;
    ScheduleEvent(std::move(ev));

    LOG_INFO(Lib_NpMatching2, "ScheduleRoomEventMemberLeft: member={} reason={} scheduled",
             departed_member_id, reason);
}

// --- Room event: Kickedout (0x1103) ---
// On real PS4, when a player is kicked, the PSN server sends 0x1103 (Kickedout).
// The game's dispatch handler triggers the session exit flow.
struct KickedoutEventData {
    u64 _pad0{0};       // +0x00
    s32 status_code{0}; // +0x08: 0xff000019 = kickout
    s32 _pad1{0};       // +0x0C
    u64 _pad2{0};       // +0x10
    s32 guard_value{4}; // +0x18: must be 4
    s32 _pad3{0};       // +0x1C
};

static void ScheduleRoomEventKickedout(std::chrono::steady_clock::time_point fire_at) {
    if (!g_state.room_event_callback || g_state.ctx.room_id == 0) {
        LOG_WARNING(Lib_NpMatching2,
                    "ScheduleRoomEventKickedout: no room event callback or no room");
        return;
    }

    auto data = std::make_shared<KickedoutEventData>();
    data->status_code = static_cast<s32>(0xff000019);
    data->guard_value = 4;

    PendingEvent ev{};
    ev.type = PendingEvent::ROOM_EVENT_CB;
    ev.fire_at = fire_at;
    ev.room_id = g_state.ctx.room_id;
    ev.room_event = ORBIS_NP_MATCHING2_ROOM_EVENT_KICKEDOUT;
    ev.room_event_data = data.get();
    ev.room_event_payload = data; // prevent deallocation
    ScheduleEvent(std::move(ev));

    NP_LOG("ScheduleRoomEventKickedout: scheduled 0x1103 (status=0xff000019)");
}

// --- Room event: RoomDestroyed (0x1104) ---
// When the host leaves and the room is destroyed, the library sends 0x1104.
// The event data pointer just needs to be non-null.

static void ScheduleRoomEventRoomDestroyed(std::chrono::steady_clock::time_point fire_at) {
    if (!g_state.room_event_callback || g_state.ctx.room_id == 0) {
        LOG_WARNING(Lib_NpMatching2,
                    "ScheduleRoomEventRoomDestroyed: no room event callback or no room");
        return;
    }

    // Dispatch only checks arg3 != 0; doesn't read specific fields.
    auto data = std::make_shared<KickedoutEventData>();

    PendingEvent ev{};
    ev.type = PendingEvent::ROOM_EVENT_CB;
    ev.fire_at = fire_at;
    ev.room_id = g_state.ctx.room_id;
    ev.room_event = ORBIS_NP_MATCHING2_ROOM_EVENT_ROOM_DESTROYED;
    ev.room_event_data = data.get();
    ev.room_event_payload = data;
    ScheduleEvent(std::move(ev));

    NP_LOG("ScheduleRoomEventRoomDestroyed: scheduled 0x1104 (room destroyed, session exit)");
}

// --- Room event: MemberJoined (0x1101) ---
// Fires room event callback to notify the game that a new member has joined.
// CreateJoinRoom callback creates connection state for the initial member,
// then MemberJoined events handle each additional member as they join.

static void ScheduleRoomEventMemberJoined(const MemberInfo& member,
                                          std::chrono::steady_clock::time_point fire_at) {
    if (!g_state.room_event_callback || g_state.ctx.room_id == 0) {
        LOG_WARNING(Lib_NpMatching2,
                    "ScheduleRoomEventMemberJoined: no room event callback or no room");
        return;
    }

    auto payload = std::make_shared<RoomMemberEventPayload>();
    payload->member_data.memberId = static_cast<u16>(member.member_id);
    std::strncpy(payload->member_data.npId.handle.data, member.online_id.c_str(),
                 ORBIS_NP_ONLINEID_MAX_LENGTH - 1);
    payload->update_info.roomMemberDataInternal = &payload->member_data;
    payload->update_info.eventCause = 0; // joined normally

    // Schedule room event via dispatch thread
    PendingEvent ev{};
    ev.type = PendingEvent::ROOM_EVENT_CB;
    ev.fire_at = fire_at;
    ev.room_id = g_state.ctx.room_id;
    ev.room_event = ORBIS_NP_MATCHING2_ROOM_EVENT_MEMBER_JOINED;
    ev.room_event_data = &payload->update_info;
    ev.room_event_payload = payload;
    ScheduleEvent(std::move(ev));

    LOG_INFO(Lib_NpMatching2, "ScheduleRoomEventMemberJoined: member={} online_id={} scheduled",
             member.member_id, member.online_id);
}

static bool HandleHostPeerJoinedEvent(const MemberInfo& member, const char* source) {
    if (member.member_id <= 0 || member.member_id == static_cast<int>(g_state.ctx.my_member_id)) {
        return false;
    }

    // Choose LAN or WAN address based on network topology.
    // Same-NAT detection: if the peer's public address matches our STUN-mapped
    // address, both peers are behind the same NAT. Most routers don't support
    // hairpin NAT, so we must use the local LAN addresses instead.
    // For WAN (different public IPs), use the STUN-mapped address for NAT traversal.
    std::string our_public = GetStunMappedAddrStr();
    bool same_nat = !our_public.empty() && our_public != "0" &&
                    !member.local_addr.empty() && member.local_addr != "0" &&
                    (member.addr == our_public || member.mapped_addr == our_public);
    bool use_lan = same_nat;
    if (use_lan) {
        LOG_INFO(Lib_NpMatching2,
                 "Same-NAT detected: peer '{}' public={} matches our public={} "
                 "-- using LAN addr '{}:{}'",
                 member.online_id, member.addr, our_public,
                 member.local_addr, member.local_port);
    }
    const std::string& peer_addr =
        use_lan ? member.local_addr
                : ((!member.mapped_addr.empty() && member.mapped_addr != "0") ? member.mapped_addr
                                                                              : member.addr);
    int peer_port =
        use_lan ? member.local_port : ((member.mapped_port > 0) ? member.mapped_port : member.port);

    const u16 peer_mid = static_cast<u16>(member.member_id);
    const auto now = std::chrono::steady_clock::now();

    {
        std::lock_guard<std::mutex> plock(g_state.peers_mutex);
        auto it = g_state.peers.find(peer_mid);
        if (it != g_state.peers.end()) {
            it->second.addr = IpStringToAddr(peer_addr);
            it->second.port = htons(static_cast<u16>(peer_port));
            it->second.online_id = member.online_id;
            NpSignaling::SetPeerInfo(peer_mid, it->second.addr, it->second.port, member.online_id,
                                     0);
            LOG_INFO(Lib_NpMatching2,
                     "host peer joined event (%s): refreshed existing peer id={} online_id='{}' "
                     "addr='{}' port={}",
                     source, member.member_id, member.online_id, member.addr, member.port);
            return false;
        }

        PeerInfo pi;
        pi.member_id = peer_mid;
        pi.addr = IpStringToAddr(peer_addr);
        pi.port = htons(static_cast<u16>(peer_port));
        pi.status = ORBIS_NP_MATCHING2_SIGNALING_CONN_STATUS_ACTIVE;
        pi.online_id = member.online_id;
        g_state.peers[pi.member_id] = pi;
        // SetPeerInfo inside lock to access pi's addr/port
        NpSignaling::SetPeerInfo(peer_mid, pi.addr, pi.port, member.online_id, 0);
    }

    // For subsequent peer joins (after initial session setup), activate the P2P
    // connection immediately. For the initial join, the connection pipeline drives
    // activation naturally via the JoinRoom callback flow.
    const bool session_established = g_state.host_self_established_fired.load();

    // Start echo probes for NAT punch-through when appropriate.
    if (g_state.ctx.my_member_id == 1 || session_established) {
        auto& kernel = Libraries::Net::KernelP2PSubsystem::Instance();
        kernel.ActivatePeer(g_state.ctx.ctx_id, member.online_id);
    }

    ScheduleRoomEventMemberJoined(member, now);

    // Fire self Established (0x5102) once on first peer join.
    // Atomic CAS prevents duplicate events when multiple poll threads race here.
    bool expected_false = false;
    if (g_state.host_self_established_fired.compare_exchange_strong(expected_false, true)) {
        PendingEvent sig_ev{};
        sig_ev.type = PendingEvent::SIGNALING_CB;
        sig_ev.fire_at = now + std::chrono::milliseconds(200);
        sig_ev.room_id = g_state.ctx.room_id;
        sig_ev.member_id = g_state.ctx.my_member_id;
        sig_ev.sig_event = ORBIS_NP_MATCHING2_SIGNALING_EVENT_ESTABLISHED;
        sig_ev.conn_id = static_cast<u32>(g_state.ctx.my_member_id);
        ScheduleEvent(std::move(sig_ev));
        NP_LOG("HandleHostPeerJoinedEvent: fired FIRST self Established 0x5102 (member={})",
               g_state.ctx.my_member_id);
    } else {
        NP_LOG("HandleHostPeerJoinedEvent: SKIPPED self Established (already fired, member={})",
               g_state.ctx.my_member_id);
    }

    // Always defer peer 0x5102 to OnPeerEstablished — only fire after echo
    // bilateral confirms actual P2P connectivity. Firing eagerly creates a
    // ConnObj that polls GetConnectionStatus; if the peer is unreachable
    // (STUN failure, private IP, NAT issue), the ConnObj stays stuck forever
    // and blocks the SO's checkAllConnObjsReady, preventing ALL future
    // connections until the stuck peer disconnects.
    NpSignaling::EnsureSigConnection(g_state.ctx.ctx_id, member.online_id);
    NP_LOG("HandleHostPeerJoinedEvent: peer 0x5102 for member={} DEFERRED "
           "to OnPeerEstablished (connectivity-gated)",
           peer_mid);

    {
        std::lock_guard<std::mutex> plock(g_state.peers_mutex);
        if (g_state.known_member_count < static_cast<int>(g_state.peers.size())) {
            g_state.known_member_count = static_cast<int>(g_state.peers.size());
        }
    }

    LOG_INFO(Lib_NpMatching2,
             "host peer joined event ({}): id={} online_id='{}' addr='{}' port={} "
             "(known_member_count={})",
             source, member.member_id, member.online_id, member.addr, member.port,
             g_state.known_member_count);
    return true;
}

static bool HandleHostPeerLeftEvent(u16 departed_member_id, const std::string& online_id, u8 reason,
                                    const char* source) {
    // Skip self-departure (handled by our own LeaveRoom)
    if (departed_member_id == g_state.ctx.my_member_id) {
        return false;
    }

    // Copy peer data under lock, erase under lock.
    std::string peer_oid;
    u32 peer_addr = 0;
    u16 peer_port = 0;
    {
        std::lock_guard<std::mutex> plock(g_state.peers_mutex);
        auto it = g_state.peers.find(departed_member_id);
        if (it == g_state.peers.end()) {
            return false;
        }
        peer_oid = it->second.online_id;
        peer_addr = it->second.addr;
        peer_port = it->second.port;
        g_state.peers.erase(it);
        g_state.known_member_count = static_cast<int>(g_state.peers.size());
    }

    // Mark the departed peer's connections as inactive but do not remove them.
    // P2P transport persists across room leave/rejoin.
    NpSignaling::SetConnectionInactive(online_id);

    auto& kernel = Libraries::Net::KernelP2PSubsystem::Instance();
    s32 conn_id = kernel.GetConnIdByNpid(online_id);
    if (conn_id > 0) {
        kernel.DeactivatePeer(conn_id);
        if (peer_addr != 0) {
            Libraries::Net::P2PFlushPacketsFromPeer(peer_addr, peer_port);
        }
    }

    NP_LOG("HandleHostPeerLeftEvent: deactivated connection for departed "
           "member={} npid='{}'",
           departed_member_id, online_id);

    auto now = std::chrono::steady_clock::now();
    ScheduleRoomEventMemberLeft(departed_member_id, reason, now);

    LOG_WARNING(Lib_NpMatching2,
                "host peer left event ({}): member {} ({}) reason={} "
                "(known_member_count={})",
                source, departed_member_id, online_id, reason, g_state.known_member_count);

    return true;
}

// --- Host-side room member polling ---
// After CreateJoinRoom, the host polls the server for new members joining.
// When a guest joins, the poll fires a MemberJoined room event (0x1101).

static PS4_SYSV_ABI void* HostMemberPollThreadFunc(void* /*arg*/) {
    LOG_INFO(Lib_NpMatching2, "host member poll: started for session={}", g_state.ctx.session_id);

    while (g_state.host_poll_running && !g_state.ctx.session_id.empty()) {
        // Poll every 2 seconds
        for (int i = 0; i < 20 && g_state.host_poll_running; i++) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        if (!g_state.host_poll_running)
            break;

        // Poll server for room members (includes heartbeat via MemberId param)
        std::string path = "/mp/matching2/room_members?SessionId=" + g_state.ctx.session_id +
                           "&MemberId=" + std::to_string(g_state.ctx.my_member_id);
        auto resp = HttpGet(path);
        if (resp.empty())
            continue;

        // Check for departed members
        auto departed = JsonGetMemberArray(resp, "DepartedMembers");
        for (const auto& dep : departed) {
            u16 dep_mid = static_cast<u16>(dep.member_id);
            // Use MEMBER_DISAPPEARED for all server-detected departures.
            HandleHostPeerLeftEvent(dep_mid, dep.online_id,
                                    ORBIS_NP_MATCHING2_EVENT_CAUSE_MEMBER_DISAPPEARED, "poll");
        }

        auto member_count = static_cast<int>(JsonGetInt(resp, "MemberCount"));
        if (member_count <= g_state.known_member_count)
            continue;

        // New member(s) detected!
        LOG_INFO(Lib_NpMatching2, "host member poll: member count changed {} -> {}",
                 g_state.known_member_count, member_count);

        auto members = JsonGetMemberArray(resp, "Members");

        int new_peer_count = 0;
        for (const auto& m : members) {
            if (m.member_id == g_state.ctx.my_member_id)
                continue;
            if (HandleHostPeerJoinedEvent(m, "poll")) {
                new_peer_count += 1;
            }
        }

        if (new_peer_count == 0) {
            g_state.known_member_count = member_count;
            continue;
        }

        LOG_INFO(Lib_NpMatching2, "host member poll: {} new peers handled via lifecycle events",
                 new_peer_count);

        g_state.known_member_count = member_count;
    }

    LOG_INFO(Lib_NpMatching2, "host member poll: stopped");
    return nullptr;
}

// --- Guest-side member polling (Phase 2: departure detection) ---
// After JoinRoom, the guest polls the server to detect if the host has departed.
// Also serves as heartbeat so the host knows the guest is alive.

static PS4_SYSV_ABI void* GuestPollThreadFunc(void* /*arg*/) {
    LOG_INFO(Lib_NpMatching2, "guest member poll: started for session={}", g_state.ctx.session_id);

    while (g_state.guest_poll_running && !g_state.ctx.session_id.empty()) {
        // Poll every 2 seconds
        for (int i = 0; i < 20 && g_state.guest_poll_running; i++) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        if (!g_state.guest_poll_running)
            break;

        // If WebSocket is handling events, heartbeat is already sent by
        // InvitePollThreadFunc's WS heartbeat. Skip HTTP polling.
        if (g_state.ws_client &&
            g_state.ws_client->getReadyState() == easywsclient::WebSocket::OPEN) {
            continue;
        }

        // --- HTTP polling fallback (unchanged) ---
        // Poll server for room members (includes heartbeat via MemberId param)
        std::string path = "/mp/matching2/room_members?SessionId=" + g_state.ctx.session_id +
                           "&MemberId=" + std::to_string(g_state.ctx.my_member_id);
        auto resp = HttpGet(path);
        if (resp.empty())
            continue;

        // Check if session was closed (host departed)
        auto session_closed = JsonGetInt(resp, "SessionClosed");
        if (session_closed) {
            LOG_WARNING(Lib_NpMatching2, "guest member poll: session closed (host departed)");

            auto now = std::chrono::steady_clock::now();

            // Fire RoomDestroyed (0x1104) so the game exits cleanly.
            ScheduleRoomEventRoomDestroyed(now);

            // Signaling Dead (0x5101) for all peers.
            {
                std::lock_guard<std::mutex> plock(g_state.peers_mutex);
                for (const auto& [mid, pi] : g_state.peers) {
                    PendingEvent sig_ev{};
                    sig_ev.type = PendingEvent::SIGNALING_CB;
                    sig_ev.fire_at = now + std::chrono::milliseconds(100);
                    sig_ev.room_id = g_state.ctx.room_id;
                    sig_ev.member_id = mid;
                    sig_ev.sig_event = ORBIS_NP_MATCHING2_SIGNALING_EVENT_DEAD;
                    sig_ev.conn_id = static_cast<u32>(mid);
                    ScheduleEvent(std::move(sig_ev));
                }
            }
            break;
        }

        // Check for departed members
        auto departed = JsonGetMemberArray(resp, "DepartedMembers");
        for (const auto& dep : departed) {
            u16 dep_mid = static_cast<u16>(dep.member_id);

            // Skip HOST (member=1) -- if the HOST disconnects, the server closes
            // the session entirely (SessionClosed=true), handled above.
            // Heartbeat-based departure for the HOST causes false positives.
            if (dep_mid == 1)
                continue;

            // Skip self
            if (dep_mid == g_state.ctx.my_member_id)
                continue;

            // Extract peer data under lock, erase under lock
            u32 dep_addr = 0;
            u16 dep_port = 0;
            {
                std::lock_guard<std::mutex> plock(g_state.peers_mutex);
                if (g_state.peers.count(dep_mid) == 0)
                    continue;
                auto peer_it = g_state.peers.find(dep_mid);
                if (peer_it != g_state.peers.end()) {
                    dep_addr = peer_it->second.addr;
                    dep_port = peer_it->second.port;
                }
                g_state.peers.erase(dep_mid);
            }

            LOG_WARNING(Lib_NpMatching2, "guest member poll: member {} ({}) departed", dep_mid,
                        dep.online_id);

            // Set NpSignaling INACTIVE + deactivate kernel + flush BEFORE 0x1102
            NpSignaling::SetConnectionInactive(dep.online_id);
            {
                auto& kernel = Libraries::Net::KernelP2PSubsystem::Instance();
                s32 conn_id = kernel.GetConnIdByNpid(dep.online_id);
                if (conn_id > 0) {
                    kernel.DeactivatePeer(conn_id);
                    if (dep_addr != 0) {
                        Libraries::Net::P2PFlushPacketsFromPeer(dep_addr, dep_port);
                    }
                }
            }

            auto now = std::chrono::steady_clock::now();
            ScheduleRoomEventMemberLeft(dep_mid, ORBIS_NP_MATCHING2_EVENT_CAUSE_MEMBER_DISAPPEARED,
                                        now);
        }

        // Check for new members joining. All peers must know about each other
        // for full-mesh P2P connectivity.
        auto all_members = JsonGetMemberArray(resp, "Members");
        for (const auto& m : all_members) {
            u16 mid = static_cast<u16>(m.member_id);
            if (mid == g_state.ctx.my_member_id)
                continue; // skip self
            {
                std::lock_guard<std::mutex> plock(g_state.peers_mutex);
                if (g_state.peers.count(mid) != 0)
                    continue; // already known
            }

            NP_LOG("guest member poll: NEW member detected! id={} online_id='{}' "
                   "addr='{}' port={}",
                   m.member_id, m.online_id, m.addr, m.port);

            // Same handler as host path.
            HandleHostPeerJoinedEvent(m, "guest_poll");
        }
    }

    LOG_INFO(Lib_NpMatching2, "guest member poll: stopped");
    return nullptr;
}

// --- Async operation args ---
// Passed to PS4 threads that perform HTTP + fire callbacks asynchronously.
// Must be heap-allocated; the thread func deletes them.

struct AsyncCreateJoinRoomArgs {
    u16 ctx_id;
    u32 req_id;
    OrbisNpMatching2RequestCallback callback;
    void* callback_arg;
    std::string online_id;
    u16 signaling_port;
    u16 server_id;
    bool room_already_exists = false; // true if InvitePoll already set room state
};

static PS4_SYSV_ABI void* CreateJoinRoomThreadFunc(void* arg) {
    auto* a = static_cast<AsyncCreateJoinRoomArgs*>(arg);

    // Small delay to ensure sceNpMatching2CreateJoinRoom returns first.
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    if (!a->room_already_exists) {
        // Normal path: create room via HTTP
        LOG_INFO(Lib_NpMatching2, "CreateJoinRoom async: starting HTTP request");

        std::string mapped_addr = GetStunMappedAddrStr();
        u16 mapped_port = GetStunMappedPortHost();
        std::string body = "{";
        body += "\"OnlineId\": \"" + a->online_id + "\",";
        body += "\"LocalAddr\": \"" + g_state.signaling_addr + "\",";
        body += "\"LocalPort\": " + std::to_string(a->signaling_port) + ",";
        body += "\"PublicAddr\": \"" + g_state.signaling_addr + "\",";
        body += "\"PublicPort\": " + std::to_string(a->signaling_port) + ",";
        body += "\"MappedAddr\": \"" + mapped_addr + "\",";
        body += "\"MappedPort\": " + std::to_string(mapped_port) + ",";
        body += "\"MaxMembers\": 64";
        body += "}";

        auto resp = HttpPost("/mp/matching2/create_room", body);
        if (resp.empty()) {
            LOG_ERROR(Lib_NpMatching2, "CreateJoinRoom async: server request failed");
            if (a->callback) {
                a->callback(a->ctx_id, a->req_id, ORBIS_NP_MATCHING2_REQUEST_EVENT_CREATE_JOIN_ROOM,
                            -1, nullptr, a->callback_arg);
            }
            delete a;
            return nullptr;
        }

        auto room_id = static_cast<u64>(JsonGetInt(resp, "RoomId"));
        auto member_id = static_cast<u16>(JsonGetInt(resp, "MemberId"));
        auto session_id = JsonGetString(resp, "SessionId");

        LOG_INFO(Lib_NpMatching2, "CreateJoinRoom async: room_id={} member_id={} session={}",
                 room_id, member_id, session_id);

        // Store state
        g_state.ctx.room_id = room_id;
        g_state.ctx.my_member_id = member_id;
        g_state.ctx.session_id = session_id;

        // Notify kernel subsystem of room join (HOST role = member_id 1)
        Libraries::Net::KernelP2PSubsystem::Instance().OnRoomJoined(room_id, member_id);
    } else {
        LOG_INFO(Lib_NpMatching2,
                 "CreateJoinRoom async: room already exists (id={}), updating addr",
                 g_state.ctx.room_id);

        // Room was auto-created by summon/request with default or stale addr:port.
        // Update the session with our actual signaling address so the guest
        // gets the correct peer addr:port when it joins.
        if (!g_state.ctx.session_id.empty()) {
            std::string update_body = "{";
            update_body += "\"SessionId\": \"" + g_state.ctx.session_id + "\",";
            update_body += "\"MemberId\": " + std::to_string(g_state.ctx.my_member_id) + ",";
            update_body += "\"Addr\": \"" + g_state.signaling_addr + "\",";
            update_body += "\"Port\": " + std::to_string(a->signaling_port);
            update_body += "}";
            HttpPost("/mp/matching2/update_member", update_body);
            LOG_INFO(Lib_NpMatching2, "CreateJoinRoom async: updated member addr to {}:{}",
                     g_state.signaling_addr, a->signaling_port);
        }
    }

    // Fire the CreateJoinRoom callback with 1 member (host only).
    // Subsequent members are delivered via matching2 lifecycle events.
    {
        std::vector<MemberInfo> host_only;
        MemberInfo host_mi{};
        host_mi.member_id = g_state.ctx.my_member_id;
        host_mi.online_id = g_state.ctx.online_id;
        host_only.push_back(host_mi);

        BuildCallbackData(g_state.ctx.room_id, g_state.ctx.server_id, host_only,
                          g_state.ctx.my_member_id, g_state.ctx.my_member_id);

        auto* controller = reinterpret_cast<u8*>(g_state.per_request_callback_arg);
        if (controller && g_state.per_request_callback && g_state.last_response) {
            auto now = std::chrono::steady_clock::now();

            PendingEvent req_ev{};
            req_ev.type = PendingEvent::REQUEST_CB;
            req_ev.fire_at = now;
            req_ev.req_id = a->req_id;
            req_ev.req_event = ORBIS_NP_MATCHING2_REQUEST_EVENT_CREATE_JOIN_ROOM;
            req_ev.error_code = 0;
            req_ev.request_data = g_state.last_response; // capture now, not at dispatch time
            req_ev.request_cb = a->callback;
            req_ev.request_cb_arg = controller;
            ScheduleEvent(std::move(req_ev));

            LOG_INFO(Lib_NpMatching2,
                     "CreateJoinRoom async: scheduled callback (event=0x101, "
                     "reqId={}, members=1 [host only])",
                     a->req_id);
        }
    }

    // Add self to peers so GetConnectionStatus returns ACTIVE for self.
    // Self-signaling events are deferred until a peer actually joins.
    {
        PeerInfo self_pi;
        self_pi.member_id = g_state.ctx.my_member_id;
        self_pi.online_id = g_state.ctx.online_id;
        self_pi.addr = IpStringToAddr(g_state.signaling_addr);
        self_pi.port = htons(a->signaling_port);
        self_pi.status = ORBIS_NP_MATCHING2_SIGNALING_CONN_STATUS_ACTIVE;
        {
            std::lock_guard<std::mutex> plock(g_state.peers_mutex);
            g_state.peers[g_state.ctx.my_member_id] = self_pi;
        }

        // Self gets immediate SetPeerInfo (no delay for local connection).
        NpSignaling::SetPeerInfo(g_state.ctx.my_member_id, self_pi.addr, self_pi.port,
                                 g_state.ctx.online_id, 0);
        LOG_INFO(Lib_NpMatching2,
                 "CreateJoinRoom async: added self (member={}) to peers (no STUN delay)",
                 g_state.ctx.my_member_id);
    }

    // Host lifecycle is event-driven via /np/events matching2 events.
    // Optional poll fallback can be enabled for diagnostics/compat:
    //   SHADPS4_M2_HOST_POLL_FALLBACK=1
    g_state.known_member_count = 1;              // host only
    g_state.host_self_established_fired.store(false); // reset for new session
    if (HostPollFallbackEnabled() && !g_state.host_poll_running) {
        g_state.host_poll_running = true;
        Kernel::PthreadT poll_thread = nullptr;
        int poll_ret =
            Kernel::posix_pthread_create(&poll_thread, nullptr, HostMemberPollThreadFunc, nullptr);
        if (poll_ret != 0) {
            LOG_ERROR(Lib_NpMatching2, "CreateJoinRoom: failed to create host poll thread: {}",
                      poll_ret);
            g_state.host_poll_running = false;
        } else {
            g_state.host_poll_thread = poll_thread;
            LOG_INFO(Lib_NpMatching2, "CreateJoinRoom: host member poll thread started");
        }
    } else if (!HostPollFallbackEnabled()) {
        LOG_INFO(Lib_NpMatching2,
                 "CreateJoinRoom: host poll fallback disabled; using NP lifecycle events");
    }

    delete a;
    return nullptr;
}

// --- Room operations ---

s32 PS4_SYSV_ABI sceNpMatching2CreateJoinRoom(u16 ctxId, void* reqParam, void* optParam,
                                              s32* reqId) {
    NP_LOG("API sceNpMatching2CreateJoinRoom: called ctxId={} reqParam={} optParam={} reqId={}",
           ctxId, reqParam, optParam, (void*)reqId);

    // Extract callback from optParam
    OrbisNpMatching2RequestCallback callback = nullptr;
    void* callback_arg = nullptr;
    if (optParam) {
        auto* opt = reinterpret_cast<OrbisNpMatching2RequestOptParam*>(optParam);
        callback = opt->cbFunc;
        callback_arg = opt->cbFuncArg;
        LOG_INFO(Lib_NpMatching2, "CreateJoinRoom: optParam cbFunc={} cbFuncArg={}",
                 (void*)opt->cbFunc, opt->cbFuncArg);
    }
    if (!callback) {
        callback = g_state.default_request_callback;
        callback_arg = g_state.default_request_callback_arg;
    }

    // Save per-request callback info for later use (e.g. guest invite poll)
    g_state.per_request_callback = callback;
    g_state.per_request_callback_arg = callback_arg;

    u32 rid = g_state.next_request_id++;
    if (reqId) {
        *reqId = static_cast<s32>(rid);
    }

    LOG_INFO(Lib_NpMatching2, "CreateJoinRoom: reqId={} callback={} arg={}", rid, (void*)callback,
             callback_arg);

    // If the room was already created by the poll thread (host notification),
    // skip the HTTP call but still fire the callback with game-provided values.
    bool room_exists = (g_state.ctx.room_id != 0);
    if (room_exists) {
        LOG_INFO(Lib_NpMatching2,
                 "CreateJoinRoom: room already exists (id={}), "
                 "will fire callback with game-provided controller",
                 g_state.ctx.room_id);
    }

    // Launch async thread to perform HTTP request and fire callback.
    auto* args = new AsyncCreateJoinRoomArgs{ctxId,
                                             rid,
                                             callback,
                                             callback_arg,
                                             g_state.ctx.online_id,
                                             g_state.signaling_port,
                                             g_state.ctx.server_id,
                                             room_exists};

    Kernel::PthreadT thread = nullptr;
    int ret = Kernel::posix_pthread_create(&thread, nullptr, CreateJoinRoomThreadFunc, args);
    if (ret != 0) {
        LOG_ERROR(Lib_NpMatching2, "CreateJoinRoom: failed to create async thread: {}", ret);
        delete args;
        return ORBIS_OK;
    }

    // Track thread for cleanup
    {
        std::lock_guard<std::mutex> lock(g_state.async_threads_mutex);
        g_state.async_threads.push_back(thread);
    }

    return ORBIS_OK;
}

s32 PS4_SYSV_ABI sceNpMatching2CreateJoinRoomA(u16 ctxId, void* reqParam, void* optParam,
                                               s32* reqId) {
    NP_LOG("API sceNpMatching2CreateJoinRoomA: called (forwarding)");
    return sceNpMatching2CreateJoinRoom(ctxId, reqParam, optParam, reqId);
}

// AsyncJoinRoomArgs defined earlier (before InvitePollThreadFunc)

static PS4_SYSV_ABI void* JoinRoomThreadFunc(void* arg) {
    auto* a = static_cast<AsyncJoinRoomArgs*>(arg);

    // Small delay to ensure sceNpMatching2JoinRoom returns first.
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    LOG_INFO(Lib_NpMatching2, "JoinRoom async: starting for room={}", a->target_room_id);

    if (!a->already_joined) {
        std::string mapped_addr = GetStunMappedAddrStr();
        u16 mapped_port = GetStunMappedPortHost();
        std::string body = "{";
        body += "\"OnlineId\": \"" + a->online_id + "\",";
        body += "\"RoomId\": " + std::to_string(a->target_room_id) + ",";
        body += "\"LocalAddr\": \"" + g_state.signaling_addr + "\",";
        body += "\"LocalPort\": " + std::to_string(a->signaling_port) + ",";
        body += "\"PublicAddr\": \"" + g_state.signaling_addr + "\",";
        body += "\"PublicPort\": " + std::to_string(a->signaling_port) + ",";
        body += "\"MappedAddr\": \"" + mapped_addr + "\",";
        body += "\"MappedPort\": " + std::to_string(mapped_port);
        body += "}";

        auto resp = HttpPost("/mp/matching2/join_room", body);
        if (resp.empty()) {
            LOG_ERROR(Lib_NpMatching2, "JoinRoom async: server request failed");
            if (a->callback) {
                a->callback(a->ctx_id, a->req_id, ORBIS_NP_MATCHING2_REQUEST_EVENT_JOIN_ROOM, -1,
                            nullptr, a->callback_arg);
            }
            delete a;
            return nullptr;
        }

        auto room_id = static_cast<u64>(JsonGetInt(resp, "RoomId"));
        auto member_id = static_cast<u16>(JsonGetInt(resp, "MemberId"));
        auto session_id = JsonGetString(resp, "SessionId");
        auto peer_addr = JsonGetString(resp, "PeerAddr");
        auto peer_port = static_cast<u16>(JsonGetInt(resp, "PeerPort"));

        LOG_INFO(Lib_NpMatching2,
                 "JoinRoom async: room_id={} member_id={} session={} "
                 "peer_addr='{}' peer_port={} self_addr='{}' self_port={}",
                 room_id, member_id, session_id, peer_addr, peer_port, g_state.signaling_addr,
                 g_state.signaling_port);

        g_state.ctx.room_id = room_id;
        g_state.ctx.my_member_id = member_id;
        g_state.ctx.session_id = session_id;

        // Notify kernel subsystem of room join (GUEST role = member_id > 1)
        Libraries::Net::KernelP2PSubsystem::Instance().OnRoomJoined(room_id, member_id);
        {
            std::lock_guard<std::mutex> invite_lock(g_state.pending_guest_invite_mutex);
            if (g_state.pending_guest_invite.valid &&
                g_state.pending_guest_invite.room_id == room_id) {
                g_state.pending_guest_invite = {};
            }
        }

        // Store peer info from response.
        auto members = JsonGetMemberArray(resp, "Members");
        // Collect SetPeerInfo calls to make outside peers_mutex (avoids nested locks)
        struct PeerUpdate {
            u16 mid;
            u32 addr;
            u16 port;
            std::string npid;
        };
        std::vector<PeerUpdate> peer_updates;
        {
            std::lock_guard<std::mutex> plock(g_state.peers_mutex);
            for (const auto& m : members) {
                if (m.member_id != member_id && !m.addr.empty()) {
                    u16 mid = static_cast<u16>(m.member_id);
                    auto existing = g_state.peers.find(mid);
                    if (existing != g_state.peers.end()) {
                        existing->second.addr = IpStringToAddr(m.addr);
                        existing->second.port = htons(static_cast<u16>(m.port));
                        existing->second.online_id = m.online_id;
                    } else {
                        PeerInfo pi;
                        pi.member_id = mid;
                        pi.addr = IpStringToAddr(m.addr);
                        pi.port = htons(static_cast<u16>(m.port));
                        pi.status = ORBIS_NP_MATCHING2_SIGNALING_CONN_STATUS_ACTIVE;
                        pi.online_id = m.online_id;
                        g_state.peers[pi.member_id] = pi;
                    }
                    peer_updates.push_back({mid, IpStringToAddr(m.addr),
                                            htons(static_cast<u16>(m.port)), m.online_id});
                }
            }
            if (!peer_addr.empty() && peer_port > 0) {
                auto existing_host = g_state.peers.find(static_cast<u16>(1));
                if (existing_host != g_state.peers.end()) {
                    existing_host->second.addr = IpStringToAddr(peer_addr);
                    existing_host->second.port = htons(peer_port);
                } else {
                    PeerInfo pi;
                    pi.member_id = 1;
                    pi.addr = IpStringToAddr(peer_addr);
                    pi.port = htons(peer_port);
                    pi.status = ORBIS_NP_MATCHING2_SIGNALING_CONN_STATUS_ACTIVE;
                    for (const auto& m : members) {
                        if (m.member_id == 1 && !m.online_id.empty()) {
                            pi.online_id = m.online_id;
                            break;
                        }
                    }
                    g_state.peers[1] = pi;
                }
                auto host_it = g_state.peers.find(1);
                if (host_it != g_state.peers.end()) {
                    peer_updates.push_back(
                        {1, host_it->second.addr, host_it->second.port, host_it->second.online_id});
                }
            }
        }
        // SetPeerInfo calls outside lock
        for (const auto& pu : peer_updates) {
            NpSignaling::SetPeerInfo(pu.mid, pu.addr, pu.port, pu.npid, 0);
        }
    } else {
        LOG_INFO(Lib_NpMatching2, "JoinRoom async: already joined room {} via invite poll",
                 a->target_room_id);

        // Notify kernel subsystem NOW (not during invite pre-join).
        // Session state will be created by the JoinRoom callback.
        // This unblocks the STUN fallback gate (current_room_id_ != 0).
        Libraries::Net::KernelP2PSubsystem::Instance().OnRoomJoined(a->target_room_id,
                                                                    g_state.ctx.my_member_id);

        // The invite poll stored the HOST peer with PENDING conn.
        // Now that JoinRoom is running,
        // call SetPeerInfo to resolve the PENDING conn to ACTIVE immediately.
        u32 host_addr_v = 0;
        u16 host_port_v = 0;
        std::string host_npid_v;
        {
            std::lock_guard<std::mutex> plock(g_state.peers_mutex);
            auto host_it = g_state.peers.find(1);
            if (host_it != g_state.peers.end()) {
                host_addr_v = host_it->second.addr;
                host_port_v = host_it->second.port;
                host_npid_v = host_it->second.online_id;
            }
        }
        if (host_addr_v != 0) {
            NpSignaling::SetPeerInfo(1, host_addr_v, host_port_v, host_npid_v, 0);
            LOG_INFO(Lib_NpMatching2, "JoinRoom async: HOST peer SetPeerInfo resolved "
                                      "(deferred from invite, now immediate)");
        }
    }

    // Build callback data from current state. Fetch room members from server
    // to ensure we have a complete member list (covers both fresh-join and
    // already-joined cases).
    std::vector<MemberInfo> members;
    if (!g_state.ctx.session_id.empty()) {
        auto resp = HttpGet("/mp/matching2/room_members?SessionId=" + g_state.ctx.session_id);
        if (!resp.empty()) {
            members = JsonGetMemberArray(resp, "Members");
        }
    }

    // For the already_joined path, register all non-self, non-HOST peers
    // in g_state.peers and call SetPeerInfo for mesh connectivity.
    if (a->already_joined) {
        for (const auto& m : members) {
            u16 mid = static_cast<u16>(m.member_id);
            if (mid == g_state.ctx.my_member_id)
                continue; // skip self
            if (mid == 1)
                continue; // HOST already handled above
            if (m.addr.empty() && m.local_addr.empty())
                continue; // no usable address

            // Use LAN/WAN address selection logic (same as HandleHostPeerJoinedEvent)
            auto is_private_ip = [](const std::string& ip) -> bool {
                if (ip.empty() || ip == "0")
                    return false;
                u32 addr = ntohl(IpStringToAddr(ip));
                return ((addr >> 24) == 10) || ((addr >> 20) == 0xAC1) ||
                       ((addr >> 16) == 0xC0A8) || ((addr >> 24) == 127);
            };
            bool use_lan = !m.local_addr.empty() && is_private_ip(g_state.signaling_addr) &&
                           is_private_ip(m.local_addr);
            const std::string& peer_addr =
                use_lan
                    ? m.local_addr
                    : ((!m.mapped_addr.empty() && m.mapped_addr != "0") ? m.mapped_addr : m.addr);
            int peer_port = use_lan ? m.local_port : ((m.mapped_port > 0) ? m.mapped_port : m.port);

            bool need_insert = false;
            u32 pi_addr = IpStringToAddr(peer_addr);
            u16 pi_port = htons(static_cast<u16>(peer_port));
            {
                std::lock_guard<std::mutex> plock(g_state.peers_mutex);
                if (g_state.peers.find(mid) == g_state.peers.end()) {
                    PeerInfo pi;
                    pi.member_id = mid;
                    pi.addr = pi_addr;
                    pi.port = pi_port;
                    pi.status = ORBIS_NP_MATCHING2_SIGNALING_CONN_STATUS_ACTIVE;
                    pi.online_id = m.online_id;
                    g_state.peers[pi.member_id] = pi;
                    need_insert = true;
                }
            }
            if (need_insert) {
                NpSignaling::SetPeerInfo(mid, pi_addr, pi_port, m.online_id, 0);
                LOG_INFO(Lib_NpMatching2,
                         "JoinRoom async: mesh peer SetPeerInfo member={} "
                         "online_id='{}' addr='{}' port={} (already_joined path)",
                         mid, m.online_id, peer_addr, peer_port);
            }
        }
    }

    // Ensure self is in the list
    bool found_self = false;
    for (const auto& m : members) {
        if (m.member_id == g_state.ctx.my_member_id)
            found_self = true;
    }
    if (!found_self) {
        MemberInfo self_mi{};
        self_mi.member_id = g_state.ctx.my_member_id;
        self_mi.online_id = a->online_id;
        members.push_back(self_mi);
    }

    // Guest JoinRoom callback should include the local member entry so the
    // native step-machine receives a valid "me" pointer in the response.
    // Room events still fire after this callback to mirror room broadcast flow.
    std::vector<MemberInfo> callback_members = members;

    BuildCallbackData(g_state.ctx.room_id, a->server_id, callback_members, 1,
                      g_state.ctx.my_member_id);

    // Record room join time for signaling establishment delay emulation.
    g_state.room_joined_time = std::chrono::steady_clock::now();

    // Fire JoinRoom callback to the game's controller.
    if (a->callback && g_state.last_response) {
        auto now = std::chrono::steady_clock::now();

        // Schedule JoinRoom request callback (fires immediately from dispatch)
        PendingEvent req_ev{};
        req_ev.type = PendingEvent::REQUEST_CB;
        req_ev.fire_at = now;
        req_ev.req_id = a->req_id;
        req_ev.req_event = ORBIS_NP_MATCHING2_REQUEST_EVENT_JOIN_ROOM;
        req_ev.error_code = 0;
        req_ev.request_cb = a->callback;
        req_ev.request_cb_arg = a->callback_arg;
        req_ev.request_data = g_state.last_response;
        ScheduleEvent(std::move(req_ev));

        LOG_INFO(Lib_NpMatching2,
                 "JoinRoom async: scheduled callback (event=0x102, reqId={}, "
                 "cbArg={:p})",
                 a->req_id, a->callback_arg);

        // Guest flow: after JoinRoom request callback, emulate room-level
        // MemberJoined notifications for all known members. RoomEventDispatch
        // The native handler ignores already-known members; keeping the full set
        // lets the native callback consume the same stream shape as host/guest
        // room membership broadcasts.
        // Host-side member joins are already delivered via HostMemberPollThread.
        if (g_state.ctx.my_member_id != 1) {
            int room_evt_count = 0;
            auto room_evt_time = now + std::chrono::milliseconds(20);
            for (const auto& m : members) {
                ScheduleRoomEventMemberJoined(m, room_evt_time);
                room_evt_count++;
            }
            if (room_evt_count > 0) {
                LOG_INFO(Lib_NpMatching2,
                         "JoinRoom async: scheduled {} guest MemberJoined room events",
                         room_evt_count);
            }
        }

        // Add self to peers so GetConnectionStatus returns ACTIVE for self.
        {
            PeerInfo self_pi;
            self_pi.member_id = g_state.ctx.my_member_id;
            self_pi.online_id = g_state.ctx.online_id;
            self_pi.addr = IpStringToAddr(g_state.signaling_addr);
            self_pi.port = htons(g_state.signaling_port);
            self_pi.status = ORBIS_NP_MATCHING2_SIGNALING_CONN_STATUS_ACTIVE;
            {
                std::lock_guard<std::mutex> plock(g_state.peers_mutex);
                g_state.peers[g_state.ctx.my_member_id] = self_pi;
            }

            NpSignaling::SetPeerInfo(g_state.ctx.my_member_id, self_pi.addr, self_pi.port,
                                     g_state.ctx.online_id, 0);
            LOG_INFO(Lib_NpMatching2,
                     "JoinRoom async: added self (member={}) to peers (no STUN delay)",
                     g_state.ctx.my_member_id);
        }

        // Schedule signaling Established events for all members at T+200ms.
        {
            int conn_count = 0;
            for (const auto& m : members) {
                PendingEvent conn_ev{};
                conn_ev.type = PendingEvent::SIGNALING_CB;
                conn_ev.fire_at = now + std::chrono::milliseconds(200);
                conn_ev.room_id = g_state.ctx.room_id;
                conn_ev.member_id = static_cast<u16>(m.member_id);
                conn_ev.sig_event = ORBIS_NP_MATCHING2_SIGNALING_EVENT_ESTABLISHED;
                conn_ev.conn_id = static_cast<u32>(m.member_id);
                ScheduleEvent(std::move(conn_ev));
                conn_count++;
            }
            LOG_INFO(Lib_NpMatching2,
                     "JoinRoom async: scheduled {} signaling Dead events for all members",
                     conn_count);
        }

        // Mark self Established as fired so HandleHostPeerJoinedEvent won't re-fire.
        g_state.host_self_established_fired.store(true);

        // Dead (0x5101) events are not fired here; the native pipeline handles
        // connection advancement through the signaling state machine.

        {
            std::lock_guard<std::mutex> plock(g_state.peers_mutex);
            LOG_INFO(
                Lib_NpMatching2,
                "JoinRoom async: {} peers stored (SetPeerInfo called from lifecycle, immediate)",
                g_state.peers.size());
        }
    }

    {
        std::lock_guard<std::mutex> plock(g_state.peers_mutex);
        LOG_INFO(Lib_NpMatching2, "JoinRoom async: complete -- events scheduled for {} peers",
                 g_state.peers.size());
    }

    // Start guest-side member polling for departure detection.
    // Only needed when WebSocket is down — WS handles room_closed/member_left events.
    bool ws_active_join = g_state.ws_client &&
        g_state.ws_client->getReadyState() == easywsclient::WebSocket::OPEN;
    if (!g_state.guest_poll_running && !ws_active_join) {
        g_state.guest_poll_running = true;
        Kernel::PthreadT gp_thread = nullptr;
        int gp_ret =
            Kernel::posix_pthread_create(&gp_thread, nullptr, GuestPollThreadFunc, nullptr);
        if (gp_ret != 0) {
            LOG_ERROR(Lib_NpMatching2, "JoinRoom: failed to create guest poll thread: {}", gp_ret);
            g_state.guest_poll_running = false;
        } else {
            g_state.guest_poll_thread = gp_thread;
            LOG_INFO(Lib_NpMatching2, "JoinRoom: guest member poll thread started");
        }
    }

    delete a;
    return nullptr;
}

s32 PS4_SYSV_ABI sceNpMatching2JoinRoom(u16 ctxId, void* reqParam, void* optParam, s32* reqId) {
    NP_LOG("API sceNpMatching2JoinRoom: called ctxId={} reqParam={} optParam={} reqId={}", ctxId,
           reqParam, optParam, (void*)reqId);

    LOG_INFO(Lib_NpMatching2, "JoinRoom: native path observed (room_id={} my_member_id={})",
             g_state.ctx.room_id, g_state.ctx.my_member_id);

    OrbisNpMatching2RequestCallback callback = nullptr;
    void* callback_arg = nullptr;
    if (optParam) {
        auto* opt = reinterpret_cast<OrbisNpMatching2RequestOptParam*>(optParam);
        callback = opt->cbFunc;
        callback_arg = opt->cbFuncArg;
        LOG_INFO(Lib_NpMatching2, "JoinRoom: optParam cbFunc={} cbFuncArg={}", (void*)opt->cbFunc,
                 opt->cbFuncArg);
    }
    if (!callback) {
        callback = g_state.default_request_callback;
        callback_arg = g_state.default_request_callback_arg;
    }

    g_state.per_request_callback = callback;
    g_state.per_request_callback_arg = callback_arg;

    u64 target_room_id = 0;
    if (reqParam) {
        auto* req = reinterpret_cast<OrbisNpMatching2JoinRoomRequest*>(reqParam);
        target_room_id = req->roomId;
    }

    u32 rid = g_state.next_request_id++;
    if (reqId) {
        *reqId = static_cast<s32>(rid);
    }

    LOG_INFO(Lib_NpMatching2, "JoinRoom: reqId={} targetRoomId={} storedRoomId={}", rid,
             target_room_id, g_state.ctx.room_id);

    // If the game passes roomId=0, use the currently known room (already joined)
    // or the pending invite room captured from NP event polling.
    if (g_state.ctx.room_id != 0 && target_room_id == 0) {
        target_room_id = g_state.ctx.room_id;
        LOG_INFO(Lib_NpMatching2, "JoinRoom: using stored room_id={} (reqParam roomId was 0)",
                 target_room_id);
    }
    if (target_room_id == 0) {
        std::lock_guard<std::mutex> invite_lock(g_state.pending_guest_invite_mutex);
        if (g_state.pending_guest_invite.valid && g_state.pending_guest_invite.room_id != 0) {
            target_room_id = g_state.pending_guest_invite.room_id;
            LOG_INFO(Lib_NpMatching2,
                     "JoinRoom: using pending invite room_id={} session={} host='{}'",
                     target_room_id, g_state.pending_guest_invite.session_id,
                     g_state.pending_guest_invite.host_online_id);
        }
    }
    if (target_room_id == 0) {
        LOG_ERROR(Lib_NpMatching2,
                  "JoinRoom: no target room id available (no reqParam room and no pending invite)");
        if (callback) {
            PendingEvent req_ev{};
            req_ev.type = PendingEvent::REQUEST_CB;
            req_ev.fire_at = std::chrono::steady_clock::now();
            req_ev.req_id = rid;
            req_ev.req_event = ORBIS_NP_MATCHING2_REQUEST_EVENT_JOIN_ROOM;
            req_ev.error_code = -1;
            req_ev.request_cb = callback;
            req_ev.request_cb_arg = callback_arg;
            req_ev.request_data = nullptr;
            ScheduleEvent(std::move(req_ev));
        }
        return ORBIS_OK;
    }

    bool already_joined = (g_state.ctx.room_id != 0 && g_state.ctx.room_id == target_room_id);
    LOG_INFO(Lib_NpMatching2, "JoinRoom: already_joined={} (step machine call={})", already_joined,
             already_joined ? "yes" : "no");

    // ASYNC: Launch PS4 thread to do HTTP + fire callback
    auto* args = new AsyncJoinRoomArgs{ctxId,
                                       rid,
                                       target_room_id,
                                       callback,
                                       callback_arg,
                                       g_state.ctx.online_id,
                                       g_state.signaling_port,
                                       g_state.ctx.server_id,
                                       already_joined};

    Kernel::PthreadT thread = nullptr;
    int ret = Kernel::posix_pthread_create(&thread, nullptr, JoinRoomThreadFunc, args);
    if (ret != 0) {
        LOG_ERROR(Lib_NpMatching2, "JoinRoom: failed to create async thread: {}", ret);
        delete args;
        return ORBIS_OK;
    }

    {
        std::lock_guard<std::mutex> lock(g_state.async_threads_mutex);
        g_state.async_threads.push_back(thread);
    }

    return ORBIS_OK;
}

s32 PS4_SYSV_ABI sceNpMatching2JoinRoomA(u16 ctxId, void* reqParam, void* optParam, s32* reqId) {
    NP_LOG("API sceNpMatching2JoinRoomA: called (forwarding)");
    return sceNpMatching2JoinRoom(ctxId, reqParam, optParam, reqId);
}

s32 PS4_SYSV_ABI sceNpMatching2LeaveRoom(u16 ctxId, void* reqParam, void* optParam, s32* reqId) {
    NP_LOG("API sceNpMatching2LeaveRoom: called ctxId={} reqParam={} optParam={} reqId={}", ctxId,
           reqParam, optParam, (void*)reqId);

    u32 rid = g_state.next_request_id++;
    if (reqId)
        *reqId = static_cast<s32>(rid);

    // Extract callback from optParam (same pattern as CreateJoinRoom/JoinRoom)
    OrbisNpMatching2RequestCallback callback = nullptr;
    void* callback_arg = nullptr;
    if (optParam) {
        auto* opt = reinterpret_cast<OrbisNpMatching2RequestOptParam*>(optParam);
        callback = opt->cbFunc;
        callback_arg = opt->cbFuncArg;
        LOG_INFO(Lib_NpMatching2, "LeaveRoom: optParam cbFunc={} cbFuncArg={}", (void*)opt->cbFunc,
                 opt->cbFuncArg);
    }
    if (!callback) {
        callback = g_state.default_request_callback;
        callback_arg = g_state.default_request_callback_arg;
    }

    // --- Immediate LeaveRoom ---
    // LeaveRoom fires immediately. The game calls this as part of the normal
    // Normal session lifecycle -- LeaveRoom fires at the appropriate time.
    NP_LOG("LeaveRoom: room_id={} cb={}", g_state.ctx.room_id, (void*)callback);

    // Notify server
    if (!g_state.ctx.session_id.empty()) {
        std::string body = "{";
        body += "\"SessionId\": \"" + g_state.ctx.session_id + "\",";
        body += "\"MemberId\": " + std::to_string(g_state.ctx.my_member_id);
        body += "}";
        HttpPost("/mp/matching2/leave_room", body);
    }

    // Stop polling threads
    g_state.host_poll_running = false;
    {
        std::lock_guard<std::mutex> invite_lock(g_state.pending_guest_invite_mutex);
        g_state.pending_guest_invite = {};
    }

    // Clear session state for clean next-session start
    g_state.ctx.room_id = 0;
    g_state.ctx.my_member_id = 0;
    g_state.ctx.session_id.clear();
    g_state.guest_poll_running = false;
    {
        std::lock_guard<std::mutex> plock(g_state.peers_mutex);
        g_state.peers.clear();
    }
    NpSignaling::ClearConnections();
    Libraries::Net::ClearP2PSessionState();
    g_state.known_member_count = 0;
    g_state.host_self_established_fired.store(false);

    // Fire request callback event 0x103 immediately.
    if (callback) {
        auto now = std::chrono::steady_clock::now();
        PendingEvent req_ev{};
        req_ev.type = PendingEvent::REQUEST_CB;
        req_ev.fire_at = now + std::chrono::milliseconds(100);
        req_ev.req_id = rid;
        req_ev.req_event = ORBIS_NP_MATCHING2_REQUEST_EVENT_LEAVE_ROOM;
        req_ev.error_code = 0;
        req_ev.request_cb = callback;
        req_ev.request_cb_arg = callback_arg;
        req_ev.request_data = nullptr;
        ScheduleEvent(std::move(req_ev));
        LOG_INFO(Lib_NpMatching2,
                 "LeaveRoom: scheduled callback event 0x103 reqId={} cb={} arg={} (T+100ms)", rid,
                 (void*)callback, callback_arg);
    }

    return ORBIS_OK;
}

// Helper: schedule a fire-and-forget success callback for APIs with no response data.
// The callback is required to unblock the game's request completion handler.
static s32 FireAndForgetCallback(u16 ctxId, void* optParam, s32* reqId, u16 reqEvent,
                                 const char* apiName) {
    OrbisNpMatching2RequestCallback callback = nullptr;
    void* callback_arg = nullptr;
    if (optParam) {
        auto* opt = reinterpret_cast<OrbisNpMatching2RequestOptParam*>(optParam);
        callback = opt->cbFunc;
        callback_arg = opt->cbFuncArg;
    }
    if (!callback) {
        callback = g_state.default_request_callback;
        callback_arg = g_state.default_request_callback_arg;
    }

    u32 rid = g_state.next_request_id++;
    if (reqId)
        *reqId = static_cast<s32>(rid);

    if (callback) {
        PendingEvent ev{};
        ev.type = PendingEvent::REQUEST_CB;
        ev.fire_at = std::chrono::steady_clock::now() + std::chrono::milliseconds(50);
        ev.req_id = rid;
        ev.req_event = reqEvent;
        ev.error_code = 0;
        ev.request_cb = callback;
        ev.request_cb_arg = callback_arg;
        ScheduleEvent(std::move(ev));
        NP_LOG("{}: scheduled success callback reqId={} event={:#x}", apiName, rid, reqEvent);
    }

    return ORBIS_OK;
}

// --- SearchRoom ---
// Queries available rooms for joining (used by invasion system).

struct SearchRoomCallbackData {
    std::vector<OrbisNpMatching2RoomDataExternal> rooms;
    OrbisNpMatching2SearchRoomResponse response{};
};

struct AsyncSearchRoomArgs {
    u16 ctx_id;
    u32 req_id;
    OrbisNpMatching2RequestCallback callback;
    void* callback_arg;
};

static PS4_SYSV_ABI void* SearchRoomThreadFunc(void* arg) {
    auto* a = static_cast<AsyncSearchRoomArgs*>(arg);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    auto cb_data = std::make_shared<SearchRoomCallbackData>();

    auto resp = HttpGet("/mp/matching2/search_room?OnlineId=" + g_state.ctx.online_id);
    if (!resp.empty()) {
        // Parse rooms array from JSON response
        auto rooms_start = resp.find("\"Rooms\"");
        if (rooms_start != std::string::npos) {
            auto arr_start = resp.find('[', rooms_start);
            auto arr_end = resp.rfind(']');
            if (arr_start != std::string::npos && arr_end != std::string::npos) {
                // Parse each room object
                std::string arr = resp.substr(arr_start + 1, arr_end - arr_start - 1);
                size_t pos = 0;
                while (pos < arr.size()) {
                    auto obj_start = arr.find('{', pos);
                    if (obj_start == std::string::npos)
                        break;
                    auto obj_end = arr.find('}', obj_start);
                    if (obj_end == std::string::npos)
                        break;
                    std::string obj = arr.substr(obj_start, obj_end - obj_start + 1);

                    OrbisNpMatching2RoomDataExternal room{};
                    std::memset(&room, 0, sizeof(room));
                    room.roomId = static_cast<u64>(JsonGetInt(obj, "RoomId"));
                    room.maxSlot = static_cast<u16>(JsonGetInt(obj, "MaxSlot"));
                    room.curMemberNum = static_cast<u16>(JsonGetInt(obj, "CurMemberNum"));
                    room.serverId = static_cast<u16>(JsonGetInt(obj, "ServerId"));
                    room.worldId = static_cast<u32>(JsonGetInt(obj, "WorldId"));
                    room.publicSlotNum = room.maxSlot;
                    room.openPublicSlotNum = room.maxSlot - room.curMemberNum;

                    auto host_id = JsonGetString(obj, "HostOnlineId");
                    if (!host_id.empty()) {
                        std::strncpy(room.owner.handle.data, host_id.c_str(),
                                     ORBIS_NP_ONLINEID_MAX_LENGTH - 1);
                    }

                    cb_data->rooms.push_back(room);
                    pos = obj_end + 1;
                }
            }
        }
    }

    // Link the linked list
    for (size_t i = 0; i + 1 < cb_data->rooms.size(); i++) {
        cb_data->rooms[i].next = &cb_data->rooms[i + 1];
    }
    if (!cb_data->rooms.empty()) {
        cb_data->rooms.back().next = nullptr;
    }

    cb_data->response.range.startIndex = 0;
    cb_data->response.range.total = static_cast<u32>(cb_data->rooms.size());
    cb_data->response.range.resultCount = static_cast<u32>(cb_data->rooms.size());
    cb_data->response.roomDataExternal = cb_data->rooms.empty() ? nullptr : &cb_data->rooms[0];

    auto now = std::chrono::steady_clock::now();
    PendingEvent req_ev{};
    req_ev.type = PendingEvent::REQUEST_CB;
    req_ev.fire_at = now;
    req_ev.req_id = a->req_id;
    req_ev.req_event = ORBIS_NP_MATCHING2_REQUEST_EVENT_SEARCH_ROOM;
    req_ev.error_code = 0;
    req_ev.request_cb = a->callback;
    req_ev.request_cb_arg = a->callback_arg;
    req_ev.request_data = &cb_data->response;
    req_ev.room_event_payload = cb_data;
    ScheduleEvent(std::move(req_ev));

    NP_LOG("SearchRoom async: found {} rooms", cb_data->rooms.size());
    delete a;
    return nullptr;
}

s32 PS4_SYSV_ABI sceNpMatching2SearchRoom(u16 ctxId, void* reqParam, void* optParam, s32* reqId) {
    NP_LOG("API sceNpMatching2SearchRoom: ctxId={}", ctxId);

    OrbisNpMatching2RequestCallback callback = nullptr;
    void* callback_arg = nullptr;
    if (optParam) {
        auto* opt = reinterpret_cast<OrbisNpMatching2RequestOptParam*>(optParam);
        callback = opt->cbFunc;
        callback_arg = opt->cbFuncArg;
    }
    if (!callback) {
        callback = g_state.default_request_callback;
        callback_arg = g_state.default_request_callback_arg;
    }

    u32 rid = g_state.next_request_id++;
    if (reqId)
        *reqId = static_cast<s32>(rid);

    auto* args = new AsyncSearchRoomArgs{ctxId, rid, callback, callback_arg};
    Kernel::PthreadT thread = nullptr;
    int ret = Kernel::posix_pthread_create(&thread, nullptr, SearchRoomThreadFunc, args);
    if (ret != 0) {
        LOG_ERROR(Lib_NpMatching2, "SearchRoom: failed to create thread: {}", ret);
        delete args;
    } else {
        std::lock_guard<std::mutex> lock(g_state.async_threads_mutex);
        g_state.async_threads.push_back(thread);
    }
    return ORBIS_OK;
}

s32 PS4_SYSV_ABI sceNpMatching2KickoutRoomMember(u16 ctxId, void* reqParam, void* optParam,
                                                 s32* reqId) {
    // reqParam layout: roomId(u64) at +0x00, memberId(u16) at +0x08
    u64 kick_room_id = 0;
    u16 kick_member_id = 0;
    if (reqParam) {
        kick_room_id = *reinterpret_cast<u64*>(reinterpret_cast<u8*>(reqParam) + 0x00);
        kick_member_id = *reinterpret_cast<u16*>(reinterpret_cast<u8*>(reqParam) + 0x08);
    }
    NP_LOG("API sceNpMatching2KickoutRoomMember: ctxId={} roomId={} memberId={}", ctxId,
           kick_room_id, kick_member_id);

    // Notify server to kick the member and emit events
    if (!g_state.ctx.session_id.empty() && kick_member_id != 0) {
        std::string body = "{\"SessionId\":\"" + g_state.ctx.session_id +
                           "\",\"MemberId\":" + std::to_string(kick_member_id) +
                           ",\"KickerMemberId\":" + std::to_string(g_state.ctx.my_member_id) + "}";
        std::string path = "/mp/matching2/kick_member";
        auto resp = HttpPost(path, body);
        NP_LOG("KickoutRoomMember: server POST {} -> '{}'", path, resp);
    }

    return FireAndForgetCallback(ctxId, optParam, reqId,
                                 ORBIS_NP_MATCHING2_REQUEST_EVENT_KICKOUT_ROOM_MEMBER,
                                 "KickoutRoomMember");
}

s32 PS4_SYSV_ABI sceNpMatching2GrantRoomOwner(u16 ctxId, void* reqParam, void* optParam,
                                              s32* reqId) {
    NP_LOG("API sceNpMatching2GrantRoomOwner: ctxId={}", ctxId);
    return FireAndForgetCallback(ctxId, optParam, reqId,
                                 ORBIS_NP_MATCHING2_REQUEST_EVENT_GRANT_ROOM_OWNER,
                                 "GrantRoomOwner");
}

s32 PS4_SYSV_ABI sceNpMatching2SendRoomMessage(u16 ctxId, void* reqParam, void* optParam,
                                               s32* reqId) {
    NP_LOG("API sceNpMatching2SendRoomMessage: ctxId={}", ctxId);
    return FireAndForgetCallback(ctxId, optParam, reqId,
                                 ORBIS_NP_MATCHING2_REQUEST_EVENT_SEND_ROOM_MESSAGE,
                                 "SendRoomMessage");
}

s32 PS4_SYSV_ABI sceNpMatching2SendRoomChatMessage(u16 ctxId, void* reqParam, void* optParam,
                                                   s32* reqId) {
    NP_LOG("API sceNpMatching2SendRoomChatMessage: ctxId={}", ctxId);
    return FireAndForgetCallback(ctxId, optParam, reqId,
                                 ORBIS_NP_MATCHING2_REQUEST_EVENT_SEND_ROOM_CHAT_MESSAGE,
                                 "SendRoomChatMessage");
}

// --- Room data ---

s32 PS4_SYSV_ABI sceNpMatching2GetRoomDataInternal(u16 ctxId, void* reqParam, void* optParam,
                                                   s32* reqId) {
    NP_LOG("API sceNpMatching2GetRoomDataInternal: called ctxId={} reqParam={} optParam={}", ctxId,
           reqParam, optParam);

    OrbisNpMatching2RequestCallback callback = nullptr;
    void* callback_arg = nullptr;
    if (optParam) {
        auto* opt = reinterpret_cast<OrbisNpMatching2RequestOptParam*>(optParam);
        callback = opt->cbFunc;
        callback_arg = opt->cbFuncArg;
    }
    if (!callback) {
        callback = g_state.default_request_callback;
        callback_arg = g_state.default_request_callback_arg;
    }

    u32 rid = g_state.next_request_id++;
    if (reqId)
        *reqId = static_cast<s32>(rid);

    // If we have room data, schedule a callback with it.
    // Otherwise fire with null data (game should handle gracefully).
    if (g_state.ctx.room_id != 0 && callback) {
        // Rebuild room data from current state so it's fresh
        std::vector<MemberInfo> members;
        MemberInfo self{};
        self.member_id = g_state.ctx.my_member_id;
        self.online_id = g_state.ctx.online_id;
        members.push_back(self);
        {
            std::lock_guard<std::mutex> plock(g_state.peers_mutex);
            for (const auto& [mid, pi] : g_state.peers) {
                MemberInfo mi{};
                mi.member_id = mid;
                members.push_back(mi);
            }
        }

        BuildCallbackData(g_state.ctx.room_id, g_state.ctx.server_id, members, 1,
                          g_state.ctx.my_member_id);

        PendingEvent ev{};
        ev.type = PendingEvent::REQUEST_CB;
        ev.fire_at = std::chrono::steady_clock::now() + std::chrono::milliseconds(100);
        ev.req_id = rid;
        ev.req_event = ORBIS_NP_MATCHING2_REQUEST_EVENT_GET_ROOM_DATA_INTERNAL;
        ev.error_code = 0;
        ev.request_cb = callback;
        ev.request_cb_arg = callback_arg;
        // Uses g_state.last_response (request_data = nullptr)
        ScheduleEvent(std::move(ev));

        LOG_INFO(Lib_NpMatching2, "GetRoomDataInternal: scheduled callback (event=0x109, reqId={})",
                 rid);
    } else {
        LOG_WARNING(Lib_NpMatching2, "GetRoomDataInternal: no room or no callback, skipping");
    }

    return ORBIS_OK;
}

s32 PS4_SYSV_ABI sceNpMatching2SetRoomDataInternal(u16 ctxId, void* reqParam, void* optParam,
                                                   s32* reqId) {
    NP_LOG("API sceNpMatching2SetRoomDataInternal: ctxId={}", ctxId);
    return FireAndForgetCallback(ctxId, optParam, reqId,
                                 ORBIS_NP_MATCHING2_REQUEST_EVENT_SET_ROOM_DATA_INTERNAL,
                                 "SetRoomDataInternal");
}

s32 PS4_SYSV_ABI sceNpMatching2SetRoomDataInternalExt() {
    NP_LOG("API sceNpMatching2SetRoomDataInternalExt: (STUB)");
    return ORBIS_OK;
}

s32 PS4_SYSV_ABI sceNpMatching2SetRoomDataExternal(u16 ctxId, void* reqParam, void* optParam,
                                                   s32* reqId) {
    NP_LOG("API sceNpMatching2SetRoomDataExternal: ctxId={}", ctxId);
    return FireAndForgetCallback(ctxId, optParam, reqId,
                                 ORBIS_NP_MATCHING2_REQUEST_EVENT_SET_ROOM_DATA_EXTERNAL,
                                 "SetRoomDataExternal");
}

s32 PS4_SYSV_ABI sceNpMatching2GetRoomDataExternalList() {
    NP_LOG("API sceNpMatching2GetRoomDataExternalList: (STUB)");
    return ORBIS_OK;
}

s32 PS4_SYSV_ABI sceNpMatching2GetRoomMemberDataInternal(u16 ctxId, void* reqParam, void* optParam,
                                                         s32* reqId) {
    NP_LOG("API sceNpMatching2GetRoomMemberDataInternal: ctxId={}", ctxId);
    return FireAndForgetCallback(ctxId, optParam, reqId,
                                 ORBIS_NP_MATCHING2_REQUEST_EVENT_GET_ROOM_MEMBER_DATA_INTERNAL,
                                 "GetRoomMemberDataInternal");
}

// --- SetRoomMemberDataInternal ---
// Sets per-member binary attributes in the room (team ID, flags, bin attrs).

struct AsyncSetRoomMemberDataInternalArgs {
    u16 ctx_id;
    u32 req_id;
    u64 room_id;
    u16 member_id;
    OrbisNpMatching2RequestCallback callback;
    void* callback_arg;
};

static PS4_SYSV_ABI void* SetRoomMemberDataInternalThreadFunc(void* arg) {
    auto* a = static_cast<AsyncSetRoomMemberDataInternalArgs*>(arg);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    NP_LOG("SetRoomMemberDataInternal async: room={} member={}", a->room_id, a->member_id);

    // Fire REQUEST_CB with event 0x010b (acknowledge the set)
    auto now = std::chrono::steady_clock::now();
    PendingEvent req_ev{};
    req_ev.type = PendingEvent::REQUEST_CB;
    req_ev.fire_at = now;
    req_ev.req_id = a->req_id;
    req_ev.req_event = ORBIS_NP_MATCHING2_REQUEST_EVENT_SET_ROOM_MEMBER_DATA_INTERNAL;
    req_ev.error_code = 0;
    req_ev.request_cb = a->callback;
    req_ev.request_cb_arg = a->callback_arg;
    req_ev.request_data = nullptr; // no response data for Set
    ScheduleEvent(std::move(req_ev));

    delete a;
    return nullptr;
}

s32 PS4_SYSV_ABI sceNpMatching2SetRoomMemberDataInternal(u16 ctxId, void* reqParam, void* optParam,
                                                         s32* reqId) {
    u64 room_id = 0;
    u16 member_id = 0;
    if (reqParam) {
        // SetRoomMemberDataInternalRequest: roomId(u64), memberId(u16), teamId(u8), pad[5], ...
        auto* rp = static_cast<u8*>(reqParam);
        room_id = *reinterpret_cast<u64*>(rp);
        member_id = *reinterpret_cast<u16*>(rp + 8);
    }
    NP_LOG("API sceNpMatching2SetRoomMemberDataInternal: ctxId={} room={} member={}", ctxId,
           room_id, member_id);

    OrbisNpMatching2RequestCallback callback = nullptr;
    void* callback_arg = nullptr;
    if (optParam) {
        auto* opt = reinterpret_cast<OrbisNpMatching2RequestOptParam*>(optParam);
        callback = opt->cbFunc;
        callback_arg = opt->cbFuncArg;
    }
    if (!callback) {
        callback = g_state.default_request_callback;
        callback_arg = g_state.default_request_callback_arg;
    }

    u32 rid = g_state.next_request_id++;
    if (reqId)
        *reqId = static_cast<s32>(rid);

    auto* args = new AsyncSetRoomMemberDataInternalArgs{ctxId,     rid,      room_id,
                                                        member_id, callback, callback_arg};
    Kernel::PthreadT thread = nullptr;
    int ret =
        Kernel::posix_pthread_create(&thread, nullptr, SetRoomMemberDataInternalThreadFunc, args);
    if (ret != 0) {
        LOG_ERROR(Lib_NpMatching2, "SetRoomMemberDataInternal: failed to create thread: {}", ret);
        delete args;
    } else {
        std::lock_guard<std::mutex> lock(g_state.async_threads_mutex);
        g_state.async_threads.push_back(thread);
    }
    return ORBIS_OK;
}

s32 PS4_SYSV_ABI sceNpMatching2GetRoomMemberDataExternalList(u16 ctxId, void* reqParam,
                                                             void* optParam, s32* reqId) {
    NP_LOG("API sceNpMatching2GetRoomMemberDataExternalList: ctxId={}", ctxId);
    return FireAndForgetCallback(
        ctxId, optParam, reqId, ORBIS_NP_MATCHING2_REQUEST_EVENT_GET_ROOM_MEMBER_DATA_EXTERNAL_LIST,
        "GetRoomMemberDataExternalList");
}

s32 PS4_SYSV_ABI sceNpMatching2GetRoomMemberIdListLocal() {
    NP_LOG("API sceNpMatching2GetRoomMemberIdListLocal: (STUB)");
    return ORBIS_OK;
}

s32 PS4_SYSV_ABI sceNpMatching2GetRoomJoinedSlotMaskLocal() {
    NP_LOG("API sceNpMatching2GetRoomJoinedSlotMaskLocal: (STUB)");
    return ORBIS_OK;
}

s32 PS4_SYSV_ABI sceNpMatching2GetRoomPasswordLocal() {
    NP_LOG("API sceNpMatching2GetRoomPasswordLocal: (STUB)");
    return ORBIS_OK;
}

// --- Lobby operations ---
// Games join NpMatching2 lobbies to discover other players for ambient P2P
// connections. The library fires request callback 0x0201 (JOIN_LOBBY) followed
// by lobby event 0x3201 (MEMBER_JOINED) for each existing member.

// Holds all heap-allocated lobby data alive until callbacks consume it.
struct LobbyCallbackData {
    OrbisNpMatching2LobbyDataInternal lobby_data{};
    OrbisNpMatching2JoinLobbyResponse response{};
    std::vector<u16> member_ids;
};

// Holds per-member data for LOBBY_EVENT_MEMBER_JOINED callbacks.
struct LobbyMemberEventPayload {
    OrbisNpMatching2LobbyMemberDataInternal member_data{};
    OrbisNpMatching2LobbyMemberUpdateInfo update_info{};
};

struct AsyncJoinLobbyArgs {
    u16 ctx_id;
    u32 req_id;
    OrbisNpMatching2RequestCallback callback;
    void* callback_arg;
};

static PS4_SYSV_ABI void* JoinLobbyThreadFunc(void* arg) {
    auto* a = static_cast<AsyncJoinLobbyArgs*>(arg);

    // Small delay for API call to return first
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    // Query server for connected players (lobby membership)
    auto resp = HttpGet("/mp/matching2/lobby_members?OnlineId=" + g_state.ctx.online_id);
    if (resp.empty()) {
        LOG_WARNING(Lib_NpMatching2, "JoinLobby async: server request failed, firing no-op");
        if (a->callback) {
            a->callback(a->ctx_id, a->req_id, ORBIS_NP_MATCHING2_REQUEST_EVENT_JOIN_LOBBY, 0,
                        nullptr, a->callback_arg);
        }
        delete a;
        return nullptr;
    }

    auto lobby_id = static_cast<u64>(JsonGetInt(resp, "LobbyId"));
    auto my_member_id = static_cast<u16>(JsonGetInt(resp, "MyMemberId"));
    auto members = JsonGetMemberArray(resp, "Members");

    NP_LOG("JoinLobby async: lobby={} members={} my_mid={}", lobby_id, members.size(),
           my_member_id);

    // Build lobby callback data (shared_ptr keeps it alive through callbacks)
    auto lobby_cb = std::make_shared<LobbyCallbackData>();

    // Build member ID list
    for (const auto& m : members) {
        lobby_cb->member_ids.push_back(static_cast<u16>(m.member_id));
    }

    // Populate LobbyDataInternal
    lobby_cb->lobby_data.flagAttr = 0;
    lobby_cb->lobby_data.maxSlot = 256;
    lobby_cb->lobby_data.serverId = g_state.ctx.server_id;
    lobby_cb->lobby_data.worldId = 1;
    lobby_cb->lobby_data.lobbyId = lobby_id;
    lobby_cb->lobby_data.memberIdList.memberId = lobby_cb->member_ids.data();
    lobby_cb->lobby_data.memberIdList.memberIdNum = lobby_cb->member_ids.size();
    lobby_cb->lobby_data.memberIdList.me = my_member_id;
    std::memset(lobby_cb->lobby_data.memberIdList._pad, 0,
                sizeof(lobby_cb->lobby_data.memberIdList._pad));
    lobby_cb->lobby_data.lobbyBinAttrInternal = nullptr;
    lobby_cb->lobby_data.lobbyBinAttrInternalNum = 0;

    // Populate JoinLobbyResponse
    lobby_cb->response.lobbyDataInternal = &lobby_cb->lobby_data;

    auto now = std::chrono::steady_clock::now();

    // Schedule REQUEST_CB with event 0x0201 (JoinLobby response)
    {
        PendingEvent req_ev{};
        req_ev.type = PendingEvent::REQUEST_CB;
        req_ev.fire_at = now;
        req_ev.req_id = a->req_id;
        req_ev.req_event = ORBIS_NP_MATCHING2_REQUEST_EVENT_JOIN_LOBBY;
        req_ev.error_code = 0;
        req_ev.request_cb = a->callback;
        req_ev.request_cb_arg = a->callback_arg;
        req_ev.request_data = &lobby_cb->response;
        req_ev.room_event_payload = lobby_cb; // shared_ptr keeps data alive
        ScheduleEvent(std::move(req_ev));
    }

    // Schedule LOBBY_EVENT_MEMBER_JOINED (0x3201) for each OTHER member.
    // On real PS4, the library fires these after the join callback so the
    // game's lobby event handler can add each member to its internal list.
    int other_count = 0;
    for (const auto& m : members) {
        if (m.member_id == my_member_id)
            continue;

        auto payload = std::make_shared<LobbyMemberEventPayload>();
        std::memset(&payload->member_data, 0, sizeof(payload->member_data));
        payload->member_data.next = nullptr;
        payload->member_data.joinDate = 0;
        std::strncpy(payload->member_data.npId.handle.data, m.online_id.c_str(),
                     ORBIS_NP_ONLINEID_MAX_LENGTH - 1);
        payload->member_data.memberId = static_cast<u16>(m.member_id);

        std::memset(&payload->update_info, 0, sizeof(payload->update_info));
        payload->update_info.lobbyMemberDataInternal = &payload->member_data;
        payload->update_info.eventCause = 0; // joined normally

        PendingEvent ev{};
        ev.type = PendingEvent::LOBBY_EVENT_CB;
        ev.fire_at = now + std::chrono::milliseconds(50 + other_count * 10);
        ev.room_id = lobby_id; // reused as lobbyId
        ev.room_event = ORBIS_NP_MATCHING2_LOBBY_EVENT_MEMBER_JOINED;
        ev.room_event_data = &payload->update_info;
        ev.room_event_payload = payload;
        ScheduleEvent(std::move(ev));
        other_count++;
    }

    NP_LOG("JoinLobby async: scheduled REQUEST_CB(0x0201) + {} MEMBER_JOINED events", other_count);

    // Also call SetPeerInfo for each other member so ActivateConnection
    // can resolve their address when the signaling pipeline runs
    for (const auto& m : members) {
        if (m.member_id == my_member_id)
            continue;
        const std::string& peer_addr =
            (!m.mapped_addr.empty() && m.mapped_addr != "0") ? m.mapped_addr : m.addr;
        int peer_port = (m.mapped_port > 0) ? m.mapped_port : m.port;
        if (!peer_addr.empty() && peer_addr != "0" && peer_port > 0) {
            NpSignaling::SetPeerInfo(static_cast<u16>(m.member_id), IpStringToAddr(peer_addr),
                                     htons(static_cast<u16>(peer_port)), m.online_id);
            NP_LOG("JoinLobby: SetPeerInfo for member={} npid='{}' addr={}:{}", m.member_id,
                   m.online_id, peer_addr, peer_port);
        }
    }

    delete a;
    return nullptr;
}

s32 PS4_SYSV_ABI sceNpMatching2JoinLobby(u16 ctxId, void* reqParam, void* optParam, s32* reqId) {
    fprintf(stderr, "[NpM2] >>> sceNpMatching2JoinLobby CALLED ctxId=%d reqParam=%p\n",
            ctxId, reqParam);
    fflush(stderr);
    NP_LOG("API sceNpMatching2JoinLobby: called ctxId={} reqParam={} optParam={}", ctxId, reqParam,
           optParam);

    OrbisNpMatching2RequestCallback callback = nullptr;
    void* callback_arg = nullptr;
    if (optParam) {
        auto* opt = reinterpret_cast<OrbisNpMatching2RequestOptParam*>(optParam);
        callback = opt->cbFunc;
        callback_arg = opt->cbFuncArg;
    }
    if (!callback) {
        callback = g_state.default_request_callback;
        callback_arg = g_state.default_request_callback_arg;
    }

    u32 rid = g_state.next_request_id++;
    if (reqId) {
        *reqId = static_cast<s32>(rid);
    }

    // Launch async PS4 thread for callback
    auto* args = new AsyncJoinLobbyArgs{ctxId, rid, callback, callback_arg};
    Kernel::PthreadT thread = nullptr;
    int ret = Kernel::posix_pthread_create(&thread, nullptr, JoinLobbyThreadFunc, args);
    if (ret != 0) {
        LOG_ERROR(Lib_NpMatching2, "JoinLobby: failed to create thread: {}", ret);
        delete args;
    } else {
        std::lock_guard<std::mutex> lock(g_state.async_threads_mutex);
        g_state.async_threads.push_back(thread);
    }

    return ORBIS_OK;
}

struct AsyncLeaveLobbyArgs {
    u16 ctx_id;
    u32 req_id;
    u64 lobby_id;
    OrbisNpMatching2RequestCallback callback;
    void* callback_arg;
};

struct LeaveLobbyResponseData {
    u64 lobby_id;
};

static PS4_SYSV_ABI void* LeaveLobbyThreadFunc(void* arg) {
    auto* a = static_cast<AsyncLeaveLobbyArgs*>(arg);

    // Delay to ensure the API call returns first
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    NP_LOG("LeaveLobby async: leaving lobby={}", a->lobby_id);

    auto now = std::chrono::steady_clock::now();

    // Build response data (shared_ptr keeps it alive through callback)
    auto resp_data = std::make_shared<LeaveLobbyResponseData>();
    resp_data->lobby_id = a->lobby_id;

    // Schedule REQUEST_CB with event 0x0202 (LeaveLobby response)
    {
        PendingEvent req_ev{};
        req_ev.type = PendingEvent::REQUEST_CB;
        req_ev.fire_at = now;
        req_ev.req_id = a->req_id;
        req_ev.req_event = ORBIS_NP_MATCHING2_REQUEST_EVENT_LEAVE_LOBBY;
        req_ev.error_code = 0;
        req_ev.request_cb = a->callback;
        req_ev.request_cb_arg = a->callback_arg;
        req_ev.request_data = &resp_data->lobby_id; // LeaveLobbyResponse = just lobbyId
        req_ev.room_event_payload = resp_data;      // shared_ptr keeps data alive
        ScheduleEvent(std::move(req_ev));
    }

    // Fire LOBBY_EVENT_MEMBER_LEFT (0x3202) for self so other systems
    // (if listening) know we departed.
    {
        auto payload = std::make_shared<LobbyMemberEventPayload>();
        std::memset(&payload->member_data, 0, sizeof(payload->member_data));
        payload->member_data.next = nullptr;
        std::strncpy(payload->member_data.npId.handle.data, g_state.ctx.online_id.c_str(),
                     ORBIS_NP_ONLINEID_MAX_LENGTH - 1);
        payload->member_data.memberId = g_state.ctx.my_member_id;

        std::memset(&payload->update_info, 0, sizeof(payload->update_info));
        payload->update_info.lobbyMemberDataInternal = &payload->member_data;
        payload->update_info.eventCause = 0;

        PendingEvent ev{};
        ev.type = PendingEvent::LOBBY_EVENT_CB;
        ev.fire_at = now + std::chrono::milliseconds(50);
        ev.room_id = a->lobby_id;
        ev.room_event = ORBIS_NP_MATCHING2_LOBBY_EVENT_MEMBER_LEFT;
        ev.room_event_data = &payload->update_info;
        ev.room_event_payload = payload;
        ScheduleEvent(std::move(ev));
    }

    NP_LOG("LeaveLobby async: scheduled REQUEST_CB(0x0202) + MEMBER_LEFT for self");

    delete a;
    return nullptr;
}

s32 PS4_SYSV_ABI sceNpMatching2LeaveLobby(u16 ctxId, void* reqParam, void* optParam, s32* reqId) {
    NP_LOG("API sceNpMatching2LeaveLobby: ctxId={}", ctxId);

    u64 lobby_id = 0;
    if (reqParam) {
        // LeaveLobbyRequest: first field is lobbyId (u64)
        lobby_id = *reinterpret_cast<u64*>(reqParam);
    }

    OrbisNpMatching2RequestCallback callback = nullptr;
    void* callback_arg = nullptr;
    if (optParam) {
        auto* opt = reinterpret_cast<OrbisNpMatching2RequestOptParam*>(optParam);
        callback = opt->cbFunc;
        callback_arg = opt->cbFuncArg;
    }
    if (!callback) {
        callback = g_state.default_request_callback;
        callback_arg = g_state.default_request_callback_arg;
    }

    u32 rid = g_state.next_request_id++;
    if (reqId) {
        *reqId = static_cast<s32>(rid);
    }

    auto* args = new AsyncLeaveLobbyArgs{ctxId, rid, lobby_id, callback, callback_arg};
    Kernel::PthreadT thread = nullptr;
    int ret = Kernel::posix_pthread_create(&thread, nullptr, LeaveLobbyThreadFunc, args);
    if (ret != 0) {
        LOG_ERROR(Lib_NpMatching2, "LeaveLobby: failed to create thread: {}", ret);
        delete args;
    } else {
        std::lock_guard<std::mutex> lock(g_state.async_threads_mutex);
        g_state.async_threads.push_back(thread);
    }

    return ORBIS_OK;
}

// --- GetLobbyInfoList ---
// Returns info about available lobbies.

struct GetLobbyInfoListCallbackData {
    OrbisNpMatching2LobbyDataInternal lobby_data{};
    std::vector<u16> member_ids;
    // Response points into lobby_data
    struct {
        // Range header: startIndex, total, size
        u32 startIndex{0};
        u32 total{1};
        u32 size{1};
        u32 _pad{0};
        OrbisNpMatching2LobbyDataInternal* lobbyDataExternal{nullptr};
    } response;
};

struct AsyncGetLobbyInfoListArgs {
    u16 ctx_id;
    u32 req_id;
    OrbisNpMatching2RequestCallback callback;
    void* callback_arg;
};

static PS4_SYSV_ABI void* GetLobbyInfoListThreadFunc(void* arg) {
    auto* a = static_cast<AsyncGetLobbyInfoListArgs*>(arg);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    auto resp = HttpGet("/mp/matching2/lobby_members?OnlineId=" + g_state.ctx.online_id);

    auto cb_data = std::make_shared<GetLobbyInfoListCallbackData>();

    u64 lobby_id = 100;
    if (!resp.empty()) {
        lobby_id = static_cast<u64>(JsonGetInt(resp, "LobbyId"));
        auto members = JsonGetMemberArray(resp, "Members");
        for (const auto& m : members) {
            cb_data->member_ids.push_back(static_cast<u16>(m.member_id));
        }
    }

    cb_data->lobby_data.flagAttr = 0;
    cb_data->lobby_data.maxSlot = 256;
    cb_data->lobby_data.serverId = g_state.ctx.server_id;
    cb_data->lobby_data.worldId = 1;
    cb_data->lobby_data.lobbyId = lobby_id;
    cb_data->lobby_data.memberIdList.memberId = cb_data->member_ids.data();
    cb_data->lobby_data.memberIdList.memberIdNum = cb_data->member_ids.size();
    cb_data->lobby_data.memberIdList.me = g_state.ctx.my_member_id;
    cb_data->lobby_data.lobbyBinAttrInternal = nullptr;
    cb_data->lobby_data.lobbyBinAttrInternalNum = 0;

    cb_data->response.startIndex = 0;
    cb_data->response.total = 1;
    cb_data->response.size = 1;
    cb_data->response.lobbyDataExternal = &cb_data->lobby_data;

    auto now = std::chrono::steady_clock::now();
    PendingEvent req_ev{};
    req_ev.type = PendingEvent::REQUEST_CB;
    req_ev.fire_at = now;
    req_ev.req_id = a->req_id;
    req_ev.req_event = ORBIS_NP_MATCHING2_REQUEST_EVENT_GET_LOBBY_INFO_LIST;
    req_ev.error_code = 0;
    req_ev.request_cb = a->callback;
    req_ev.request_cb_arg = a->callback_arg;
    req_ev.request_data = &cb_data->response;
    req_ev.room_event_payload = cb_data;
    ScheduleEvent(std::move(req_ev));

    NP_LOG("GetLobbyInfoList async: returned 1 lobby (id={})", lobby_id);
    delete a;
    return nullptr;
}

s32 PS4_SYSV_ABI sceNpMatching2GetLobbyInfoList(u16 ctxId, void* reqParam, void* optParam,
                                                s32* reqId) {
    fprintf(stderr, "[NpM2] >>> sceNpMatching2GetLobbyInfoList CALLED ctxId=%d reqParam=%p\n",
            ctxId, reqParam);
    fflush(stderr);
    NP_LOG("API sceNpMatching2GetLobbyInfoList: ctxId={}", ctxId);

    OrbisNpMatching2RequestCallback callback = nullptr;
    void* callback_arg = nullptr;
    if (optParam) {
        auto* opt = reinterpret_cast<OrbisNpMatching2RequestOptParam*>(optParam);
        callback = opt->cbFunc;
        callback_arg = opt->cbFuncArg;
    }
    if (!callback) {
        callback = g_state.default_request_callback;
        callback_arg = g_state.default_request_callback_arg;
    }

    u32 rid = g_state.next_request_id++;
    if (reqId)
        *reqId = static_cast<s32>(rid);

    auto* args = new AsyncGetLobbyInfoListArgs{ctxId, rid, callback, callback_arg};
    Kernel::PthreadT thread = nullptr;
    int ret = Kernel::posix_pthread_create(&thread, nullptr, GetLobbyInfoListThreadFunc, args);
    if (ret != 0) {
        LOG_ERROR(Lib_NpMatching2, "GetLobbyInfoList: failed to create thread: {}", ret);
        delete args;
    } else {
        std::lock_guard<std::mutex> lock(g_state.async_threads_mutex);
        g_state.async_threads.push_back(thread);
    }
    return ORBIS_OK;
}

// --- GetLobbyMemberDataInternal ---
// Returns data for a single lobby member by memberId.

struct GetLobbyMemberDataInternalCallbackData {
    OrbisNpMatching2LobbyMemberDataInternal member_data{};
    OrbisNpMatching2GetLobbyMemberDataInternalResponse response{};
};

struct AsyncGetLobbyMemberDataInternalArgs {
    u16 ctx_id;
    u32 req_id;
    u64 lobby_id;
    u16 target_member_id;
    OrbisNpMatching2RequestCallback callback;
    void* callback_arg;
};

static PS4_SYSV_ABI void* GetLobbyMemberDataInternalThreadFunc(void* arg) {
    auto* a = static_cast<AsyncGetLobbyMemberDataInternalArgs*>(arg);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    auto cb_data = std::make_shared<GetLobbyMemberDataInternalCallbackData>();
    std::memset(&cb_data->member_data, 0, sizeof(cb_data->member_data));

    // Look up member in peers or query server
    std::string target_oid;
    {
        std::lock_guard<std::mutex> plock(g_state.peers_mutex);
        auto peer_it = g_state.peers.find(a->target_member_id);
        if (peer_it != g_state.peers.end() && !peer_it->second.online_id.empty()) {
            target_oid = peer_it->second.online_id;
        }
    }
    if (!target_oid.empty()) {
        std::strncpy(cb_data->member_data.npId.handle.data, target_oid.c_str(),
                     ORBIS_NP_ONLINEID_MAX_LENGTH - 1);
        cb_data->member_data.memberId = a->target_member_id;
    } else {
        // Try server
        auto resp = HttpGet("/mp/matching2/lobby_members?OnlineId=" + g_state.ctx.online_id);
        if (!resp.empty()) {
            auto members = JsonGetMemberArray(resp, "Members");
            for (const auto& m : members) {
                if (m.member_id == a->target_member_id) {
                    std::strncpy(cb_data->member_data.npId.handle.data, m.online_id.c_str(),
                                 ORBIS_NP_ONLINEID_MAX_LENGTH - 1);
                    cb_data->member_data.memberId = static_cast<u16>(m.member_id);
                    break;
                }
            }
        }
    }

    cb_data->member_data.next = nullptr;
    cb_data->response.lobbyMemberDataInternal = &cb_data->member_data;

    auto now = std::chrono::steady_clock::now();
    PendingEvent req_ev{};
    req_ev.type = PendingEvent::REQUEST_CB;
    req_ev.fire_at = now;
    req_ev.req_id = a->req_id;
    req_ev.req_event = ORBIS_NP_MATCHING2_REQUEST_EVENT_GET_LOBBY_MEMBER_DATA_INTERNAL;
    req_ev.error_code = 0;
    req_ev.request_cb = a->callback;
    req_ev.request_cb_arg = a->callback_arg;
    req_ev.request_data = &cb_data->response;
    req_ev.room_event_payload = cb_data;
    ScheduleEvent(std::move(req_ev));

    NP_LOG("GetLobbyMemberDataInternal async: member={} npid='{}'", a->target_member_id,
           cb_data->member_data.npId.handle.data);
    delete a;
    return nullptr;
}

s32 PS4_SYSV_ABI sceNpMatching2GetLobbyMemberDataInternal(u16 ctxId, void* reqParam, void* optParam,
                                                          s32* reqId) {
    u64 lobby_id = 0;
    u16 target_mid = 0;
    if (reqParam) {
        // GetLobbyMemberDataInternalRequest: lobbyId(u64), memberId(u16), pad[6], attrId*,
        // attrIdNum
        lobby_id = *reinterpret_cast<u64*>(reqParam);
        target_mid = *reinterpret_cast<u16*>(static_cast<u8*>(reqParam) + 8);
    }
    NP_LOG("API sceNpMatching2GetLobbyMemberDataInternal: ctxId={} lobby={} member={}", ctxId,
           lobby_id, target_mid);

    OrbisNpMatching2RequestCallback callback = nullptr;
    void* callback_arg = nullptr;
    if (optParam) {
        auto* opt = reinterpret_cast<OrbisNpMatching2RequestOptParam*>(optParam);
        callback = opt->cbFunc;
        callback_arg = opt->cbFuncArg;
    }
    if (!callback) {
        callback = g_state.default_request_callback;
        callback_arg = g_state.default_request_callback_arg;
    }

    u32 rid = g_state.next_request_id++;
    if (reqId)
        *reqId = static_cast<s32>(rid);

    auto* args = new AsyncGetLobbyMemberDataInternalArgs{ctxId,      rid,      lobby_id,
                                                         target_mid, callback, callback_arg};
    Kernel::PthreadT thread = nullptr;
    int ret =
        Kernel::posix_pthread_create(&thread, nullptr, GetLobbyMemberDataInternalThreadFunc, args);
    if (ret != 0) {
        LOG_ERROR(Lib_NpMatching2, "GetLobbyMemberDataInternal: failed to create thread: {}", ret);
        delete args;
    } else {
        std::lock_guard<std::mutex> lock(g_state.async_threads_mutex);
        g_state.async_threads.push_back(thread);
    }
    return ORBIS_OK;
}

// --- GetLobbyMemberDataInternalList ---
// Returns data for multiple lobby members (or all if memberId list is null).

struct GetLobbyMemberDataInternalListCallbackData {
    std::vector<OrbisNpMatching2LobbyMemberDataInternal> members;
    OrbisNpMatching2GetLobbyMemberDataInternalListResponse response{};
};

struct AsyncGetLobbyMemberDataInternalListArgs {
    u16 ctx_id;
    u32 req_id;
    u64 lobby_id;
    std::vector<u16> requested_member_ids;
    OrbisNpMatching2RequestCallback callback;
    void* callback_arg;
};

static PS4_SYSV_ABI void* GetLobbyMemberDataInternalListThreadFunc(void* arg) {
    auto* a = static_cast<AsyncGetLobbyMemberDataInternalListArgs*>(arg);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    auto cb_data = std::make_shared<GetLobbyMemberDataInternalListCallbackData>();

    // Query server for member list
    auto resp = HttpGet("/mp/matching2/lobby_members?OnlineId=" + g_state.ctx.online_id);
    if (!resp.empty()) {
        auto server_members = JsonGetMemberArray(resp, "Members");
        for (const auto& m : server_members) {
            // If specific members requested, filter; otherwise return all
            if (!a->requested_member_ids.empty()) {
                bool found = false;
                for (u16 mid : a->requested_member_ids) {
                    if (mid == static_cast<u16>(m.member_id)) {
                        found = true;
                        break;
                    }
                }
                if (!found)
                    continue;
            }

            OrbisNpMatching2LobbyMemberDataInternal md{};
            std::memset(&md, 0, sizeof(md));
            md.next = nullptr;
            std::strncpy(md.npId.handle.data, m.online_id.c_str(),
                         ORBIS_NP_ONLINEID_MAX_LENGTH - 1);
            md.memberId = static_cast<u16>(m.member_id);
            cb_data->members.push_back(md);
        }
    }

    // Link the linked list (next pointers)
    for (size_t i = 0; i + 1 < cb_data->members.size(); i++) {
        cb_data->members[i].next = &cb_data->members[i + 1];
    }

    cb_data->response.lobbyMemberDataInternal =
        cb_data->members.empty() ? nullptr : &cb_data->members[0];
    cb_data->response.lobbyMemberDataInternalNum = cb_data->members.size();

    auto now = std::chrono::steady_clock::now();
    PendingEvent req_ev{};
    req_ev.type = PendingEvent::REQUEST_CB;
    req_ev.fire_at = now;
    req_ev.req_id = a->req_id;
    req_ev.req_event = ORBIS_NP_MATCHING2_REQUEST_EVENT_GET_LOBBY_MEMBER_DATA_INTERNAL_LIST;
    req_ev.error_code = 0;
    req_ev.request_cb = a->callback;
    req_ev.request_cb_arg = a->callback_arg;
    req_ev.request_data = &cb_data->response;
    req_ev.room_event_payload = cb_data;
    ScheduleEvent(std::move(req_ev));

    NP_LOG("GetLobbyMemberDataInternalList async: returned {} members", cb_data->members.size());
    delete a;
    return nullptr;
}

s32 PS4_SYSV_ABI sceNpMatching2GetLobbyMemberDataInternalList(u16 ctxId, void* reqParam,
                                                              void* optParam, s32* reqId) {
    u64 lobby_id = 0;
    std::vector<u16> requested_ids;
    if (reqParam) {
        // GetLobbyMemberDataInternalListRequest: lobbyId(u64), memberId*(ptr), memberIdNum(u64),
        // ...
        auto* rp = static_cast<u8*>(reqParam);
        lobby_id = *reinterpret_cast<u64*>(rp);
        auto* mid_ptr = *reinterpret_cast<u16**>(rp + 8);
        u64 mid_num = *reinterpret_cast<u64*>(rp + 16);
        if (mid_ptr && mid_num > 0) {
            for (u64 i = 0; i < mid_num; i++) {
                requested_ids.push_back(mid_ptr[i]);
            }
        }
    }
    NP_LOG("API sceNpMatching2GetLobbyMemberDataInternalList: ctxId={} lobby={} requested={}",
           ctxId, lobby_id, requested_ids.size());

    OrbisNpMatching2RequestCallback callback = nullptr;
    void* callback_arg = nullptr;
    if (optParam) {
        auto* opt = reinterpret_cast<OrbisNpMatching2RequestOptParam*>(optParam);
        callback = opt->cbFunc;
        callback_arg = opt->cbFuncArg;
    }
    if (!callback) {
        callback = g_state.default_request_callback;
        callback_arg = g_state.default_request_callback_arg;
    }

    u32 rid = g_state.next_request_id++;
    if (reqId)
        *reqId = static_cast<s32>(rid);

    auto* args = new AsyncGetLobbyMemberDataInternalListArgs{
        ctxId, rid, lobby_id, std::move(requested_ids), callback, callback_arg};
    Kernel::PthreadT thread = nullptr;
    int ret = Kernel::posix_pthread_create(&thread, nullptr,
                                           GetLobbyMemberDataInternalListThreadFunc, args);
    if (ret != 0) {
        LOG_ERROR(Lib_NpMatching2, "GetLobbyMemberDataInternalList: failed to create thread: {}",
                  ret);
        delete args;
    } else {
        std::lock_guard<std::mutex> lock(g_state.async_threads_mutex);
        g_state.async_threads.push_back(thread);
    }
    return ORBIS_OK;
}

// --- SetLobbyMemberDataInternal ---
// Sets per-member attributes (bin attrs, session info). Acknowledged via callback.

struct AsyncSetLobbyMemberDataInternalArgs {
    u16 ctx_id;
    u32 req_id;
    u64 lobby_id;
    u16 member_id;
    OrbisNpMatching2RequestCallback callback;
    void* callback_arg;
};

static PS4_SYSV_ABI void* SetLobbyMemberDataInternalThreadFunc(void* arg) {
    auto* a = static_cast<AsyncSetLobbyMemberDataInternalArgs*>(arg);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    NP_LOG("SetLobbyMemberDataInternal async: lobby={} member={}", a->lobby_id, a->member_id);

    // Fire REQUEST_CB with event 0x0205 (acknowledge the set)
    auto now = std::chrono::steady_clock::now();
    PendingEvent req_ev{};
    req_ev.type = PendingEvent::REQUEST_CB;
    req_ev.fire_at = now;
    req_ev.req_id = a->req_id;
    req_ev.req_event = ORBIS_NP_MATCHING2_REQUEST_EVENT_SET_LOBBY_MEMBER_DATA_INTERNAL;
    req_ev.error_code = 0;
    req_ev.request_cb = a->callback;
    req_ev.request_cb_arg = a->callback_arg;
    req_ev.request_data = nullptr; // no response data for Set
    ScheduleEvent(std::move(req_ev));

    delete a;
    return nullptr;
}

s32 PS4_SYSV_ABI sceNpMatching2SetLobbyMemberDataInternal(u16 ctxId, void* reqParam, void* optParam,
                                                          s32* reqId) {
    u64 lobby_id = 0;
    u16 member_id = 0;
    if (reqParam) {
        // SetLobbyMemberDataInternalRequest: lobbyId(u64), memberId(u16), pad[6], ...
        lobby_id = *reinterpret_cast<u64*>(reqParam);
        member_id = *reinterpret_cast<u16*>(static_cast<u8*>(reqParam) + 8);
    }
    NP_LOG("API sceNpMatching2SetLobbyMemberDataInternal: ctxId={} lobby={} member={}", ctxId,
           lobby_id, member_id);

    OrbisNpMatching2RequestCallback callback = nullptr;
    void* callback_arg = nullptr;
    if (optParam) {
        auto* opt = reinterpret_cast<OrbisNpMatching2RequestOptParam*>(optParam);
        callback = opt->cbFunc;
        callback_arg = opt->cbFuncArg;
    }
    if (!callback) {
        callback = g_state.default_request_callback;
        callback_arg = g_state.default_request_callback_arg;
    }

    u32 rid = g_state.next_request_id++;
    if (reqId)
        *reqId = static_cast<s32>(rid);

    auto* args = new AsyncSetLobbyMemberDataInternalArgs{ctxId,     rid,      lobby_id,
                                                         member_id, callback, callback_arg};
    Kernel::PthreadT thread = nullptr;
    int ret =
        Kernel::posix_pthread_create(&thread, nullptr, SetLobbyMemberDataInternalThreadFunc, args);
    if (ret != 0) {
        LOG_ERROR(Lib_NpMatching2, "SetLobbyMemberDataInternal: failed to create thread: {}", ret);
        delete args;
    } else {
        std::lock_guard<std::mutex> lock(g_state.async_threads_mutex);
        g_state.async_threads.push_back(thread);
    }
    return ORBIS_OK;
}

// --- SendLobbyChatMessage ---
// Sends a chat message within the lobby. Callback must complete to avoid stalling.

struct AsyncSendLobbyChatMessageArgs {
    u16 ctx_id;
    u32 req_id;
    u64 lobby_id;
    OrbisNpMatching2RequestCallback callback;
    void* callback_arg;
};

struct SendLobbyChatMessageCallbackData {
    OrbisNpMatching2SendLobbyChatMessageResponse response{};
};

static PS4_SYSV_ABI void* SendLobbyChatMessageThreadFunc(void* arg) {
    auto* a = static_cast<AsyncSendLobbyChatMessageArgs*>(arg);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    auto cb_data = std::make_shared<SendLobbyChatMessageCallbackData>();
    cb_data->response.filtered = false;

    auto now = std::chrono::steady_clock::now();
    PendingEvent req_ev{};
    req_ev.type = PendingEvent::REQUEST_CB;
    req_ev.fire_at = now;
    req_ev.req_id = a->req_id;
    req_ev.req_event = ORBIS_NP_MATCHING2_REQUEST_EVENT_SEND_LOBBY_CHAT_MESSAGE;
    req_ev.error_code = 0;
    req_ev.request_cb = a->callback;
    req_ev.request_cb_arg = a->callback_arg;
    req_ev.request_data = &cb_data->response;
    req_ev.room_event_payload = cb_data;
    ScheduleEvent(std::move(req_ev));

    NP_LOG("SendLobbyChatMessage async: lobby={}", a->lobby_id);
    delete a;
    return nullptr;
}

s32 PS4_SYSV_ABI sceNpMatching2SendLobbyChatMessage(u16 ctxId, void* reqParam, void* optParam,
                                                    s32* reqId) {
    u64 lobby_id = 0;
    if (reqParam) {
        // SendLobbyChatMessageRequest: lobbyId(u64), ...
        lobby_id = *reinterpret_cast<u64*>(reqParam);
    }
    NP_LOG("API sceNpMatching2SendLobbyChatMessage: ctxId={} lobby={}", ctxId, lobby_id);

    OrbisNpMatching2RequestCallback callback = nullptr;
    void* callback_arg = nullptr;
    if (optParam) {
        auto* opt = reinterpret_cast<OrbisNpMatching2RequestOptParam*>(optParam);
        callback = opt->cbFunc;
        callback_arg = opt->cbFuncArg;
    }
    if (!callback) {
        callback = g_state.default_request_callback;
        callback_arg = g_state.default_request_callback_arg;
    }

    u32 rid = g_state.next_request_id++;
    if (reqId)
        *reqId = static_cast<s32>(rid);

    auto* args = new AsyncSendLobbyChatMessageArgs{ctxId, rid, lobby_id, callback, callback_arg};
    Kernel::PthreadT thread = nullptr;
    int ret = Kernel::posix_pthread_create(&thread, nullptr, SendLobbyChatMessageThreadFunc, args);
    if (ret != 0) {
        LOG_ERROR(Lib_NpMatching2, "SendLobbyChatMessage: failed to create thread: {}", ret);
        delete args;
    } else {
        std::lock_guard<std::mutex> lock(g_state.async_threads_mutex);
        g_state.async_threads.push_back(thread);
    }
    return ORBIS_OK;
}

// --- Server/world info ---

s32 PS4_SYSV_ABI sceNpMatching2GetServerId(u16 ctxId, u16* serverId) {
    NP_LOG("API sceNpMatching2GetServerId: called ctxId={} serverId={}", ctxId, (void*)serverId);
    if (serverId) {
        *serverId = g_state.ctx.server_id;
    }
    return ORBIS_OK;
}

s32 PS4_SYSV_ABI sceNpMatching2GetWorldIdArrayForAllServers() {
    NP_LOG("API sceNpMatching2GetWorldIdArrayForAllServers: (STUB)");
    return ORBIS_OK;
}

// Async thread for GetWorldInfoList callback
struct AsyncGetWorldInfoArgs {
    u16 ctx_id;
    u32 req_id;
    OrbisNpMatching2RequestCallback callback;
    void* callback_arg;
};

static PS4_SYSV_ABI void* GetWorldInfoListThreadFunc(void* arg) {
    auto* a = static_cast<AsyncGetWorldInfoArgs*>(arg);

    // No delay — fire callback immediately so NxrvEvent 0x29 (world data)
    // is queued BEFORE the NXRV task dispatcher fires NxrvEvent 0x10 (task done).
    // processEvent0x10 needs the world data to be available when it runs.

    LOG_INFO(Lib_NpMatching2, "GetWorldInfoList async: firing callback with 1 world");

    // Construct world info response with one world (worldId=1)
    // These are kept in g_state for lifetime management (game may reference them later)
    static OrbisNpMatching2World s_world{};
    std::memset(&s_world, 0, sizeof(s_world));
    s_world.next = nullptr;
    s_world.worldId = 1;
    s_world.lobbyCount = 1;       // +0x0C: handleEvent_type2 reads this; 0 = lobby system dead
    s_world.maxLobbyMembers = 256;
    s_world.curLobbyMembers = 1;
    s_world.curRooms = 0;
    s_world.curRoomMembers = 0;

    static OrbisNpMatching2GetWorldInfoListResponse s_resp{};
    s_resp.world = &s_world;
    s_resp.worldNum = 1;

    // Call the callback directly from this thread (PS4 pthread) — NOT through
    // ScheduleEvent/DrainReadyEvents. The game's DefaultCallback (handleEvent_type2)
    // pushes to the NXRV event queue, which must happen from a library thread
    // context, not from the game's own surveillance dispatch loop.
    if (a->callback) {
        fprintf(stderr,
                "[NpM2] GetWorldInfoList: calling callback directly ctx=%d reqId=%d "
                "cb=%p cbArg=%p world={id=%u lobbyCount=%u maxLobbyMem=%u curLobbyMem=%u "
                "curRooms=%u curRoomMem=%u} worldNum=%lu resp=%p world_ptr=%p\n",
                a->ctx_id, a->req_id, (void*)a->callback, a->callback_arg,
                s_world.worldId, s_world.lobbyCount, s_world.maxLobbyMembers,
                s_world.curLobbyMembers, s_world.curRooms, s_world.curRoomMembers,
                s_resp.worldNum, (void*)&s_resp, (void*)s_resp.world);
        fflush(stderr);
        a->callback(a->ctx_id, a->req_id,
                    ORBIS_NP_MATCHING2_REQUEST_EVENT_GET_WORLD_INFO_LIST,
                    0, &s_resp, a->callback_arg);
        fprintf(stderr, "[NpM2] GetWorldInfoList: callback returned\n");
        fflush(stderr);
    }

    delete a;
    return nullptr;
}

s32 PS4_SYSV_ABI sceNpMatching2GetWorldInfoList(u16 ctxId, void* reqParam, void* optParam,
                                                s32* reqId) {
    NP_LOG("API sceNpMatching2GetWorldInfoList: called ctxId={} reqParam={} optParam={}", ctxId,
           reqParam, optParam);

    OrbisNpMatching2RequestCallback callback = nullptr;
    void* callback_arg = nullptr;
    if (optParam) {
        auto* opt = reinterpret_cast<OrbisNpMatching2RequestOptParam*>(optParam);
        callback = opt->cbFunc;
        callback_arg = opt->cbFuncArg;
    }
    if (!callback) {
        callback = g_state.default_request_callback;
        callback_arg = g_state.default_request_callback_arg;
    }

    u32 rid = g_state.next_request_id++;
    if (reqId) {
        *reqId = static_cast<s32>(rid);
    }

    // Launch async thread — callback fires on separate thread to avoid
    // re-entrancy in the NXRV task dispatcher's event queue.
    auto* args = new AsyncGetWorldInfoArgs{ctxId, rid, callback, callback_arg};
    Kernel::PthreadT thread = nullptr;
    int ret = Kernel::posix_pthread_create(&thread, nullptr, GetWorldInfoListThreadFunc, args);
    if (ret != 0) {
        LOG_ERROR(Lib_NpMatching2, "GetWorldInfoList: failed to create thread: {}", ret);
        delete args;
    } else {
        std::lock_guard<std::mutex> lock(g_state.async_threads_mutex);
        g_state.async_threads.push_back(thread);
    }

    return ORBIS_OK;
}

// --- User info ---

s32 PS4_SYSV_ABI sceNpMatching2GetUserInfoList() {
    NP_LOG("API sceNpMatching2GetUserInfoList: (STUB)");
    return ORBIS_OK;
}

s32 PS4_SYSV_ABI sceNpMatching2GetUserInfoListA() {
    NP_LOG("API sceNpMatching2GetUserInfoListA: (STUB)");
    return ORBIS_OK;
}

s32 PS4_SYSV_ABI sceNpMatching2SetUserInfo() {
    NP_LOG("API sceNpMatching2SetUserInfo: (STUB)");
    return ORBIS_OK;
}

// --- Signaling ---

s32 PS4_SYSV_ABI sceNpMatching2SignalingGetConnectionStatus(u16 ctxId, u64 roomId, u16 memberId,
                                                            s32* connStatus, void* peerAddr,
                                                            u16* peerPort) {
    // Query NpSignaling state machine first (source of truth for connection status).
    // Falls through to kernel for self-connections (not in NpSignaling map).
    std::string npid;
    u32 peer_stored_addr = 0;
    {
        std::lock_guard<std::mutex> plock(g_state.peers_mutex);
        auto it = g_state.peers.find(memberId);
        if (it == g_state.peers.end() || it->second.online_id.empty()) {
            if (connStatus)
                *connStatus = ORBIS_NP_MATCHING2_SIGNALING_CONN_STATUS_INACTIVE;
            return ORBIS_OK;
        }
        npid = it->second.online_id;
        peer_stored_addr = it->second.addr;
    }

    s32 kern_status = ORBIS_NP_MATCHING2_SIGNALING_CONN_STATUS_INACTIVE;
    u32 kern_addr = 0;
    u16 kern_port = 0;

    if (!npid.empty()) {
        s32 sig_conn_id = NpSignaling::GetSignalingConnId(npid);
        if (sig_conn_id > 0) {
            s32 sig_status = 0;
            u32 sig_addr = 0;
            u16 sig_port = 0;
            if (NpSignaling::GetSignalingStatus(sig_conn_id, &sig_status, &sig_addr, &sig_port) ==
                0) {
                kern_status = sig_status;
                kern_addr = sig_addr;
                kern_port = sig_port;
            }
        }

        // Fall through to kernel for self-connections (not in NpSignaling map).
        if (kern_status == ORBIS_NP_MATCHING2_SIGNALING_CONN_STATUS_INACTIVE) {
            auto& kernel = Libraries::Net::KernelP2PSubsystem::Instance();
            s32 conn_id = kernel.GetConnIdByNpid(npid);
            if (conn_id > 0) {
                kernel.GetConnectionStatus(conn_id, &kern_status, &kern_addr, &kern_port);
            }
        }
    }

    if (connStatus)
        *connStatus = kern_status;
    if (peerAddr)
        *reinterpret_cast<u32*>(peerAddr) = (kern_addr != 0) ? kern_addr : peer_stored_addr;
    if (peerPort) {
        // kern_port has priority; fall back to stored peer port
        if (kern_port != 0) {
            *peerPort = kern_port;
        } else {
            std::lock_guard<std::mutex> plock(g_state.peers_mutex);
            auto pit = g_state.peers.find(memberId);
            if (pit != g_state.peers.end())
                *peerPort = pit->second.port;
        }
    }

    // Also update peers map status to stay in sync (for OnPeerEstablished/departure paths).
    if (kern_status == ORBIS_NP_MATCHING2_SIGNALING_CONN_STATUS_ACTIVE) {
        std::lock_guard<std::mutex> plock(g_state.peers_mutex);
        auto pit = g_state.peers.find(memberId);
        if (pit != g_state.peers.end())
            pit->second.status = ORBIS_NP_MATCHING2_SIGNALING_CONN_STATUS_ACTIVE;
    }

    static s32 s_last_status_per_member[16] = {};
    bool status_changed = (memberId < 16 && kern_status != s_last_status_per_member[memberId]);
    if (memberId < 16)
        s_last_status_per_member[memberId] = kern_status;

    if (status_changed) {
        const char* status_name = (kern_status == 0)   ? "INACTIVE"
                                  : (kern_status == 1) ? "PENDING"
                                  : (kern_status == 2) ? "ACTIVE"
                                                       : "?";
        NP_LOG("GetConnectionStatus: memberId={} -> {}({}){}", memberId, status_name, kern_status,
               status_changed ? " *** STATUS CHANGED ***" : "");
    }

    return ORBIS_OK;
}

s32 PS4_SYSV_ABI sceNpMatching2SignalingGetConnectionInfo(u16 ctxId, u64 roomId, u16 memberId,
                                                          s32 infoType, void* outInfo,
                                                          void* outInfoB) {
    NP_LOG("API sceNpMatching2SignalingGetConnectionInfo: ctxId={} roomId={} memberId={} "
           "infoType={} outInfo={} outInfoB={}",
           ctxId, roomId, memberId, infoType, outInfo, outInfoB);

    if (!outInfo) {
        return ORBIS_OK;
    }

    auto* info = reinterpret_cast<OrbisNpMatching2SignalingConnectionInfo*>(outInfo);

    // Copy peer data under lock -- prevents race with poll threads erasing peers.
    PeerInfo peer_copy{};
    bool peer_found = false;
    {
        std::lock_guard<std::mutex> plock(g_state.peers_mutex);
        auto peer_it = g_state.peers.find(memberId);
        if (peer_it != g_state.peers.end()) {
            peer_copy = peer_it->second;
            peer_found = true;
        }
    }

    switch (infoType) {
    case 1:             // RTT
        info->rtt = 10; // 10ms synthetic
        LOG_INFO(Lib_NpMatching2, "SignalingGetConnectionInfo: RTT={}ms (memberId={})", info->rtt,
                 memberId);
        break;

    case 2:                         // BANDWIDTH
        info->bandwidth = 10000000; // 10 Mbps synthetic
        LOG_INFO(Lib_NpMatching2, "SignalingGetConnectionInfo: bandwidth={} (memberId={})",
                 info->bandwidth, memberId);
        break;

    case 3: { // PEER_NP_ID -- does NOT require ACTIVE state
        std::memset(&info->npId, 0, sizeof(OrbisNpId));
        if (peer_found && !peer_copy.online_id.empty()) {
            std::strncpy(info->npId.handle.data, peer_copy.online_id.c_str(), 15);
            info->npId.handle.data[15] = '\0';
        }
        LOG_INFO(Lib_NpMatching2, "SignalingGetConnectionInfo: PEER_NP_ID='{}' (memberId={})",
                 info->npId.handle.data, memberId);
        break;
    }

    case 4: // PEER_ADDR
        if (peer_found && peer_copy.addr != 0) {
            info->address.addr = peer_copy.addr;
            info->address.port = peer_copy.port;
        } else {
            info->address.addr = IpStringToAddr(g_state.signaling_addr);
            info->address.port = htons(g_state.signaling_port);
        }
        LOG_INFO(Lib_NpMatching2, "SignalingGetConnectionInfo: PEER_ADDR={:#x}:{} (memberId={})",
                 info->address.addr, ntohs(info->address.port), memberId);
        break;

    case 5: // MAPPED_ADDR
        if (peer_found && peer_copy.addr != 0) {
            info->address.addr = peer_copy.addr;
            info->address.port = peer_copy.port;
        } else {
            info->address.addr = IpStringToAddr(g_state.signaling_addr);
            info->address.port = htons(g_state.signaling_port);
        }
        LOG_INFO(Lib_NpMatching2, "SignalingGetConnectionInfo: MAPPED_ADDR={:#x}:{} (memberId={})",
                 info->address.addr, ntohs(info->address.port), memberId);
        break;

    case 6: // PACKET_LOSS
        info->packetLoss = 0;
        LOG_INFO(Lib_NpMatching2, "SignalingGetConnectionInfo: PACKET_LOSS=0% (memberId={})",
                 memberId);
        break;

    default:
        LOG_WARNING(Lib_NpMatching2,
                    "SignalingGetConnectionInfo: unknown infoType={} (memberId={})", infoType,
                    memberId);
        break;
    }

    // Real library also writes to outInfoB if non-null (for dual-output types like RTT).
    // Copy only the bytes relevant to the infoType -- the union may be larger than the
    // caller's buffer for type-specific outputs (e.g., 4 bytes for RTT vs 36 for NpId).
    if (outInfoB) {
        size_t copy_size;
        switch (infoType) {
        case 1:
            copy_size = sizeof(info->rtt);
            break; // u32
        case 2:
            copy_size = sizeof(info->bandwidth);
            break; // u32
        case 3:
            copy_size = sizeof(info->npId);
            break; // OrbisNpId (36 bytes)
        case 4:    // fall through
        case 5:
            copy_size = sizeof(info->address);
            break; // {u32, u16, u16}
        case 6:
            copy_size = sizeof(info->packetLoss);
            break; // float
        default:
            copy_size = sizeof(OrbisNpMatching2SignalingConnectionInfo);
            break;
        }
        std::memcpy(outInfoB, outInfo, copy_size);
    }

    return ORBIS_OK;
}

s32 PS4_SYSV_ABI sceNpMatching2SignalingGetConnectionInfoA() {
    NP_LOG("API sceNpMatching2SignalingGetConnectionInfoA: (STUB)");
    return ORBIS_OK;
}

struct AsyncEstablishConnArgs {
    u16 ctx_id;
    u64 room_id;
    u16 member_id;
    std::string session_id;
    u16 my_member_id;
};

static PS4_SYSV_ABI void* EstablishConnThreadFunc(void* arg) {
    auto* a = static_cast<AsyncEstablishConnArgs*>(arg);

    // Delay to ensure EstablishConnection returns first
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    LOG_INFO(Lib_NpMatching2, "EstablishConn async: checking peer member={}", a->member_id);

    bool peer_exists;
    {
        std::lock_guard<std::mutex> plock(g_state.peers_mutex);
        peer_exists = g_state.peers.find(a->member_id) != g_state.peers.end();
    }
    if (!peer_exists && !a->session_id.empty()) {
        std::string path = "/mp/matching2/signaling/status?SessionId=" + a->session_id +
                           "&MemberId=" + std::to_string(a->my_member_id) +
                           "&PeerMemberId=" + std::to_string(a->member_id);
        auto resp = HttpGet(path);
        if (!resp.empty()) {
            auto status = static_cast<s32>(JsonGetInt(resp, "Status"));
            if (status == ORBIS_NP_MATCHING2_SIGNALING_CONN_STATUS_ACTIVE) {
                auto addr_str = JsonGetString(resp, "Addr");
                auto port = static_cast<u16>(JsonGetInt(resp, "Port"));
                PeerInfo pi;
                pi.member_id = a->member_id;
                pi.addr = IpStringToAddr(addr_str);
                pi.port = htons(port);
                pi.status = ORBIS_NP_MATCHING2_SIGNALING_CONN_STATUS_ACTIVE;
                {
                    std::lock_guard<std::mutex> plock(g_state.peers_mutex);
                    g_state.peers[a->member_id] = pi;
                }

                // Call SetPeerInfo from lifecycle event (immediate, no delay).
                NpSignaling::SetPeerInfo(a->member_id, pi.addr, pi.port, "", 0);

                LOG_INFO(Lib_NpMatching2, "EstablishConn async: peer found addr={}:{}", addr_str,
                         port);
            }
        }
    }

    {
        PendingEvent sig_ev{};
        sig_ev.type = PendingEvent::SIGNALING_CB;
        sig_ev.fire_at = std::chrono::steady_clock::now();
        sig_ev.room_id = a->room_id;
        sig_ev.member_id = a->member_id;
        sig_ev.sig_event = ORBIS_NP_MATCHING2_SIGNALING_EVENT_ESTABLISHED;
        sig_ev.conn_id = 0;
        ScheduleEvent(std::move(sig_ev));
    }

    delete a;
    return nullptr;
}

s32 PS4_SYSV_ABI sceNpMatching2SignalingEstablishConnection(u16 ctxId, u64 roomId, u16 memberId,
                                                            void* optParam, s32* reqId) {
    NP_LOG("API sceNpMatching2SignalingEstablishConnection: ctxId={} roomId={} memberId={}", ctxId,
           roomId, memberId);

    u32 rid = g_state.next_request_id++;
    if (reqId)
        *reqId = static_cast<s32>(rid);

    // ASYNC: Launch PS4 thread to poll peer info + fire signaling callback.
    auto* args = new AsyncEstablishConnArgs{ctxId, roomId, memberId, g_state.ctx.session_id,
                                            g_state.ctx.my_member_id};

    Kernel::PthreadT thread = nullptr;
    int ret = Kernel::posix_pthread_create(&thread, nullptr, EstablishConnThreadFunc, args);
    if (ret != 0) {
        LOG_ERROR(Lib_NpMatching2, "EstablishConnection: failed to create async thread: {}", ret);
        delete args;
    } else {
        std::lock_guard<std::mutex> lock(g_state.async_threads_mutex);
        g_state.async_threads.push_back(thread);
    }

    return ORBIS_OK;
}

s32 PS4_SYSV_ABI sceNpMatching2SignalingAbortConnection() {
    NP_LOG("API sceNpMatching2SignalingAbortConnection: (STUB)");
    return ORBIS_OK;
}

s32 PS4_SYSV_ABI sceNpMatching2SignalingGetLocalNetInfo() {
    NP_LOG("API sceNpMatching2SignalingGetLocalNetInfo: called");
    // Delegate to NpSignaling implementation
    NpSignaling::OrbisNpSignalingNetInfo info{};
    NpSignaling::sceNpSignalingGetLocalNetInfo(1, &info);
    return ORBIS_OK;
}

s32 PS4_SYSV_ABI sceNpMatching2SignalingGetPeerNetInfo() {
    NP_LOG("API sceNpMatching2SignalingGetPeerNetInfo: (STUB)");
    return ORBIS_OK;
}

s32 PS4_SYSV_ABI sceNpMatching2SignalingGetPeerNetInfoResult() {
    NP_LOG("API sceNpMatching2SignalingGetPeerNetInfoResult: (STUB)");
    return ORBIS_OK;
}

s32 PS4_SYSV_ABI sceNpMatching2SignalingCancelPeerNetInfo() {
    NP_LOG("API sceNpMatching2SignalingCancelPeerNetInfo: (STUB)");
    return ORBIS_OK;
}

s32 PS4_SYSV_ABI sceNpMatching2SignalingSetPort() {
    NP_LOG("API sceNpMatching2SignalingSetPort: (STUB)");
    return ORBIS_OK;
}

s32 PS4_SYSV_ABI sceNpMatching2SignalingGetPort() {
    NP_LOG("API sceNpMatching2SignalingGetPort: (STUB)");
    return ORBIS_OK;
}

s32 PS4_SYSV_ABI sceNpMatching2SignalingGetPingInfo(u16 ctxId, void* reqParam, void* optParam,
                                                    s32* reqId) {
    NP_LOG("API sceNpMatching2SignalingGetPingInfo: ctxId={}", ctxId);
    // On real PS4, fires request callback with event 0x0e01 on completion.
    return FireAndForgetCallback(ctxId, optParam, reqId,
                                 ORBIS_NP_MATCHING2_REQUEST_EVENT_SIGNALING_GET_PING_INFO,
                                 "SignalingGetPingInfo");
}

s32 PS4_SYSV_ABI sceNpMatching2SignalingEnableManualUdpMode() {
    NP_LOG("API sceNpMatching2SignalingEnableManualUdpMode: (STUB)");
    return ORBIS_OK;
}

s32 PS4_SYSV_ABI sceNpMatching2SetSignalingOptParam(u16 ctxId, void* reqParam, void* optParam,
                                                    s32* reqId) {
    NP_LOG("API sceNpMatching2SetSignalingOptParam: ctxId={} reqParam={} optParam={} reqId={}",
           ctxId, reqParam, optParam, fmt::ptr(reqId));
    // On real PS4, this sends signaling opt params to the PSN server and fires
    // a request callback with event 0x010d on completion. The game may have a
    // completion guard that stalls without this callback.
    return FireAndForgetCallback(ctxId, optParam, reqId,
                                 ORBIS_NP_MATCHING2_REQUEST_EVENT_SET_SIGNALING_OPT_PARAM,
                                 "SetSignalingOptParam");
}

s32 PS4_SYSV_ABI sceNpMatching2GetSignalingOptParamLocal(u16 ctxId, u64 roomId, void* outBuf) {
    NP_LOG("API sceNpMatching2GetSignalingOptParamLocal: ctxId={} roomId={} outBuf={}", ctxId,
           roomId, outBuf);
    // Reads locally cached signaling opt param data (currently a no-op).
    return ORBIS_OK;
}

// --- Memory/misc ---

s32 PS4_SYSV_ABI sceNpMatching2GetMemoryInfo() {
    NP_LOG("API sceNpMatching2GetMemoryInfo: (STUB)");
    return ORBIS_OK;
}

s32 PS4_SYSV_ABI sceNpMatching2GetSslMemoryInfo() {
    NP_LOG("API sceNpMatching2GetSslMemoryInfo: (STUB)");
    return ORBIS_OK;
}

// --- Signaling address resolution ---
// Emulates PSN signaling server's role in brokering peer address exchange.
// When ActivateConnection creates a PENDING connection, NpSignaling calls this
// to resolve the peer's signaling address from our custom server.

bool ResolvePeerSignalingAddr(const std::string& npid, u32& addr, u16& port) {
    if (npid.empty() || g_state.server_host.empty())
        return false;

    std::string body = "{\"OnlineId\": \"" + npid + "\"}";
    auto resp = HttpPost("/np/signaling/resolve", body);
    if (resp.empty())
        return false;

    auto res_kind = JsonGetInt(resp, "ResKind");
    if (res_kind != 0)
        return false;

    auto addr_str = JsonGetString(resp, "Addr");
    auto port_val = static_cast<u16>(JsonGetInt(resp, "Port"));
    if (addr_str.empty() || port_val == 0)
        return false;

    struct in_addr in;
    if (inet_pton(AF_INET, addr_str.c_str(), &in) != 1)
        return false;

    addr = in.s_addr;
    port = htons(port_val);
    LOG_INFO(Lib_NpMatching2, "ResolvePeerSignalingAddr: '{}' -> {}:{}", npid, addr_str, port_val);
    return true;
}

// --- RegisterLib ---

void RegisterLib(Core::Loader::SymbolsResolver* sym) {
    // Core lifecycle
    LIB_FUNCTION("10t3e5+JPnU", "libSceNpMatching2", 1, "libSceNpMatching2",
                 sceNpMatching2Initialize);
    LIB_FUNCTION("Mqp3lJ+sjy4", "libSceNpMatching2", 1, "libSceNpMatching2",
                 sceNpMatching2Terminate);
    LIB_FUNCTION("nHZpTF30wto", "libSceNpMatching2", 1, "libSceNpMatching2",
                 sceNpMatching2SetExtraInitParam);

    // Context management
    LIB_FUNCTION("YfmpW719rMo", "libSceNpMatching2", 1, "libSceNpMatching2",
                 sceNpMatching2CreateContext);
    LIB_FUNCTION("6xlf9+pa0GY", "libSceNpMatching2", 1, "libSceNpMatching2",
                 sceNpMatching2CreateContextInternal);
    LIB_FUNCTION("ajvzc8e2upo", "libSceNpMatching2", 1, "libSceNpMatching2",
                 sceNpMatching2CreateContextA);
    LIB_FUNCTION("7vjNQ6Z1op0", "libSceNpMatching2", 1, "libSceNpMatching2",
                 sceNpMatching2ContextStart);
    LIB_FUNCTION("-f6M4caNe8k", "libSceNpMatching2", 1, "libSceNpMatching2",
                 sceNpMatching2ContextStop);
    LIB_FUNCTION("Nz-ZE7ur32I", "libSceNpMatching2", 1, "libSceNpMatching2",
                 sceNpMatching2DestroyContext);
    LIB_FUNCTION("pFzhpCMlJXQ", "libSceNpMatching2", 1, "libSceNpMatching2",
                 sceNpMatching2AbortContextStart);

    // Callback registration
    LIB_FUNCTION("+8e7wXLmjds", "libSceNpMatching2", 1, "libSceNpMatching2",
                 sceNpMatching2SetDefaultRequestOptParam);
    LIB_FUNCTION("fQQfP87I7hs", "libSceNpMatching2", 1, "libSceNpMatching2",
                 sceNpMatching2RegisterContextCallback);
    LIB_FUNCTION("p+2EnxmaAMM", "libSceNpMatching2", 1, "libSceNpMatching2",
                 sceNpMatching2RegisterRoomEventCallback);
    LIB_FUNCTION("0UMeWRGnZKA", "libSceNpMatching2", 1, "libSceNpMatching2",
                 sceNpMatching2RegisterSignalingCallback);
    LIB_FUNCTION("4Nj7u5B5yCA", "libSceNpMatching2", 1, "libSceNpMatching2",
                 sceNpMatching2RegisterLobbyEventCallback);
    LIB_FUNCTION("DnPUsBAe8oI", "libSceNpMatching2", 1, "libSceNpMatching2",
                 sceNpMatching2RegisterLobbyMessageCallback);
    LIB_FUNCTION("uBESzz4CQws", "libSceNpMatching2", 1, "libSceNpMatching2",
                 sceNpMatching2RegisterRoomMessageCallback);
    LIB_FUNCTION("KT082n6I75E", "libSceNpMatching2", 1, "libSceNpMatching2",
                 sceNpMatching2RegisterManualUdpSignalingCallback);

    // Room operations
    LIB_FUNCTION("zCWZmXXN600", "libSceNpMatching2", 1, "libSceNpMatching2",
                 sceNpMatching2CreateJoinRoom);
    LIB_FUNCTION("V6KSpKv9XJE", "libSceNpMatching2", 1, "libSceNpMatching2",
                 sceNpMatching2CreateJoinRoomA);
    LIB_FUNCTION("CSIMDsVjs-g", "libSceNpMatching2", 1, "libSceNpMatching2",
                 sceNpMatching2JoinRoom);
    LIB_FUNCTION("gQ6cUriNpgs", "libSceNpMatching2", 1, "libSceNpMatching2",
                 sceNpMatching2JoinRoomA);
    LIB_FUNCTION("BD6kfx442Do", "libSceNpMatching2", 1, "libSceNpMatching2",
                 sceNpMatching2LeaveRoom);
    LIB_FUNCTION("VqZX7POg2Mk", "libSceNpMatching2", 1, "libSceNpMatching2",
                 sceNpMatching2SearchRoom);
    LIB_FUNCTION("AUVfU6byg3c", "libSceNpMatching2", 1, "libSceNpMatching2",
                 sceNpMatching2KickoutRoomMember);
    LIB_FUNCTION("NCP3bLGPt+o", "libSceNpMatching2", 1, "libSceNpMatching2",
                 sceNpMatching2GrantRoomOwner);
    LIB_FUNCTION("Iw2h0Jrrb5U", "libSceNpMatching2", 1, "libSceNpMatching2",
                 sceNpMatching2SendRoomMessage);
    LIB_FUNCTION("opDpl74pi2E", "libSceNpMatching2", 1, "libSceNpMatching2",
                 sceNpMatching2SendRoomChatMessage);

    // Room data
    LIB_FUNCTION("Jraxifmoet4", "libSceNpMatching2", 1, "libSceNpMatching2",
                 sceNpMatching2GetRoomDataInternal);
    LIB_FUNCTION("S9D8JSYIrjE", "libSceNpMatching2", 1, "libSceNpMatching2",
                 sceNpMatching2SetRoomDataInternal);
    LIB_FUNCTION("jMxxNNLh6ms", "libSceNpMatching2", 1, "libSceNpMatching2",
                 sceNpMatching2SetRoomDataInternalExt);
    LIB_FUNCTION("q7GK98-nYSE", "libSceNpMatching2", 1, "libSceNpMatching2",
                 sceNpMatching2SetRoomDataExternal);
    LIB_FUNCTION("26vWrPAWJfM", "libSceNpMatching2", 1, "libSceNpMatching2",
                 sceNpMatching2GetRoomDataExternalList);
    LIB_FUNCTION("5lhvOqheFBA", "libSceNpMatching2", 1, "libSceNpMatching2",
                 sceNpMatching2GetRoomMemberDataInternal);
    LIB_FUNCTION("HoqTrkS9c5Q", "libSceNpMatching2", 1, "libSceNpMatching2",
                 sceNpMatching2SetRoomMemberDataInternal);
    LIB_FUNCTION("dMQ+xGvTdqM", "libSceNpMatching2", 1, "libSceNpMatching2",
                 sceNpMatching2GetRoomMemberDataExternalList);
    LIB_FUNCTION("KC+GnHzrK2o", "libSceNpMatching2", 1, "libSceNpMatching2",
                 sceNpMatching2GetRoomMemberIdListLocal);
    LIB_FUNCTION("nddl5xnQQEY", "libSceNpMatching2", 1, "libSceNpMatching2",
                 sceNpMatching2GetRoomJoinedSlotMaskLocal);
    LIB_FUNCTION("vbtWT3lZBOM", "libSceNpMatching2", 1, "libSceNpMatching2",
                 sceNpMatching2GetRoomPasswordLocal);

    // Lobby operations
    LIB_FUNCTION("n5JmImxTiZU", "libSceNpMatching2", 1, "libSceNpMatching2",
                 sceNpMatching2JoinLobby);
    LIB_FUNCTION("BBbJ92uUdCg", "libSceNpMatching2", 1, "libSceNpMatching2",
                 sceNpMatching2LeaveLobby);
    LIB_FUNCTION("wyvlEgZ-55w", "libSceNpMatching2", 1, "libSceNpMatching2",
                 sceNpMatching2GetLobbyInfoList);
    LIB_FUNCTION("1JtbJ0kxm3E", "libSceNpMatching2", 1, "libSceNpMatching2",
                 sceNpMatching2GetLobbyMemberDataInternal);
    LIB_FUNCTION("1Z4Xxumgm+Y", "libSceNpMatching2", 1, "libSceNpMatching2",
                 sceNpMatching2GetLobbyMemberDataInternalList);
    LIB_FUNCTION("ir2CzSs9K-g", "libSceNpMatching2", 1, "libSceNpMatching2",
                 sceNpMatching2SetLobbyMemberDataInternal);
    LIB_FUNCTION("K+KtxhPsMZ4", "libSceNpMatching2", 1, "libSceNpMatching2",
                 sceNpMatching2SendLobbyChatMessage);

    // Server/world info
    LIB_FUNCTION("LhCPctIICxQ", "libSceNpMatching2", 1, "libSceNpMatching2",
                 sceNpMatching2GetServerId);
    LIB_FUNCTION("lagjVl+bHFI", "libSceNpMatching2", 1, "libSceNpMatching2",
                 sceNpMatching2GetWorldIdArrayForAllServers);
    LIB_FUNCTION("rJNPJqDCpiI", "libSceNpMatching2", 1, "libSceNpMatching2",
                 sceNpMatching2GetWorldInfoList);

    // User info
    LIB_FUNCTION("qeF-q5KDtAc", "libSceNpMatching2", 1, "libSceNpMatching2",
                 sceNpMatching2GetUserInfoList);
    LIB_FUNCTION("GyI2f9yDUXM", "libSceNpMatching2", 1, "libSceNpMatching2",
                 sceNpMatching2GetUserInfoListA);
    LIB_FUNCTION("meEjIdbjAA0", "libSceNpMatching2", 1, "libSceNpMatching2",
                 sceNpMatching2SetUserInfo);

    // Signaling
    LIB_FUNCTION("tHD5FPFXtu4", "libSceNpMatching2", 1, "libSceNpMatching2",
                 sceNpMatching2SignalingGetConnectionStatus);
    LIB_FUNCTION("twVupeaYYrk", "libSceNpMatching2", 1, "libSceNpMatching2",
                 sceNpMatching2SignalingGetConnectionInfo);
    LIB_FUNCTION("nNeC3F8-g+4", "libSceNpMatching2", 1, "libSceNpMatching2",
                 sceNpMatching2SignalingGetConnectionInfoA);
    LIB_FUNCTION("UcYuZkNhHI8", "libSceNpMatching2", 1, "libSceNpMatching2",
                 sceNpMatching2SignalingEstablishConnection);
    LIB_FUNCTION("eDxEHb9f7B8", "libSceNpMatching2", 1, "libSceNpMatching2",
                 sceNpMatching2SignalingAbortConnection);
    LIB_FUNCTION("380EWm2DrVg", "libSceNpMatching2", 1, "libSceNpMatching2",
                 sceNpMatching2SignalingGetLocalNetInfo);
    LIB_FUNCTION("8CqniKDzjvg", "libSceNpMatching2", 1, "libSceNpMatching2",
                 sceNpMatching2SignalingGetPeerNetInfo);
    LIB_FUNCTION("CTy4PBhpWDw", "libSceNpMatching2", 1, "libSceNpMatching2",
                 sceNpMatching2SignalingGetPeerNetInfoResult);
    LIB_FUNCTION("GNSN5849fjU", "libSceNpMatching2", 1, "libSceNpMatching2",
                 sceNpMatching2SignalingCancelPeerNetInfo);
    LIB_FUNCTION("wupHEf8WOhM", "libSceNpMatching2", 1, "libSceNpMatching2",
                 sceNpMatching2SignalingSetPort);
    LIB_FUNCTION("WkvclTMjNdI", "libSceNpMatching2", 1, "libSceNpMatching2",
                 sceNpMatching2SignalingGetPort);
    LIB_FUNCTION("wUmwXZHaX1w", "libSceNpMatching2", 1, "libSceNpMatching2",
                 sceNpMatching2SignalingGetPingInfo);
    LIB_FUNCTION("LKRatXLV85k", "libSceNpMatching2", 1, "libSceNpMatching2",
                 sceNpMatching2SignalingEnableManualUdpMode);
    LIB_FUNCTION("ES3UMUWWj9U", "libSceNpMatching2", 1, "libSceNpMatching2",
                 sceNpMatching2SetSignalingOptParam);
    LIB_FUNCTION("cgQhq3E0eGo", "libSceNpMatching2", 1, "libSceNpMatching2",
                 sceNpMatching2GetSignalingOptParamLocal);

    // Memory/misc
    LIB_FUNCTION("gpSAvdheZ0Q", "libSceNpMatching2", 1, "libSceNpMatching2",
                 sceNpMatching2GetMemoryInfo);
    LIB_FUNCTION("8btynvj0KNA", "libSceNpMatching2", 1, "libSceNpMatching2",
                 sceNpMatching2GetSslMemoryInfo);
}

} // namespace Libraries::Np::NpMatching2
