// SPDX-FileCopyrightText: Copyright 2025-2026 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

// KernelP2PSubsystem -- centralized P2P peer management.
// Replaces scattered connection tracking across NpSignaling/NpMatching2 HLE.

#include <cstring>
#include <thread>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

#include "common/logging/log.h"
#include "core/libraries/network/kernel_p2p.h"
#include "core/libraries/network/sockets.h"
#include "core/libraries/network/stun_client.h"
#include "core/libraries/np/np_matching2.h"

// NpSignaling event constants (duplicated here to avoid circular dependency)
static constexpr s32 SIG_EVENT_DEAD = 0;
static constexpr s32 SIG_EVENT_ESTABLISHED = 1;
static constexpr s32 SIG_EVENT_MUTUAL_ACTIVATED = 0xc;

// NpSignaling connection status constants
static constexpr s32 CONN_STATUS_INACTIVE = 0;
static constexpr s32 CONN_STATUS_PENDING = 1;
static constexpr s32 CONN_STATUS_ACTIVE = 2;

// OrbisNpSignalingConnInfoType and OrbisNetSignalingAddr defined in kernel_p2p.h

namespace Libraries::Net {

KernelP2PSubsystem& KernelP2PSubsystem::Instance() {
    static KernelP2PSubsystem instance;
    return instance;
}

// === Ioctl Interface ===

int KernelP2PSubsystem::HandleIoctl(int fd, u32 code, void* buf) {
    if (!buf) {
        LOG_WARNING(Lib_Net, "KernelP2P: ioctl with null buffer, code={:#x}", code);
        return 0;
    }

    auto* data = static_cast<u8*>(buf);

    if (code == 0x802450c8) {
        // Gate registration / Activate / Deactivate
        u32 type = 0;
        std::memcpy(&type, data, sizeof(u32));

        if (type == 0) {
            // Initialize -- check gate flag at byte 0x23
            if (data[0x23] == 0x02) {
                EnableGate();
                LOG_INFO(Lib_Net,
                         "KernelP2P: ioctl Initialize -- gate enabled (fd={}, byte[0x23]={:#x})",
                         fd, data[0x23]);
            } else {
                LOG_INFO(
                    Lib_Net,
                    "KernelP2P: ioctl Initialize -- gate NOT enabled (fd={}, byte[0x23]={:#x})", fd,
                    data[0x23]);
            }
        } else if (type == 5) {
            // Activate connection
            s32 conn_id = 0;
            std::memcpy(&conn_id, data + 0x04, sizeof(s32));
            LOG_INFO(Lib_Net, "KernelP2P: ioctl Activate conn_id={}", conn_id);
            // The real kernel activates the tunnel here. In HLE, the activation
            // is driven by ActivatePeer() from the NpSignaling API layer.
        } else if (type == 6) {
            // Deactivate connection
            s32 conn_id = 0;
            std::memcpy(&conn_id, data + 0x04, sizeof(s32));
            LOG_INFO(Lib_Net, "KernelP2P: ioctl Deactivate conn_id={}", conn_id);
            DeactivatePeer(conn_id);
        } else {
            LOG_WARNING(Lib_Net, "KernelP2P: ioctl 0x802450c8 unknown type={}", type);
        }
        return 0;
    }

    if (code == 0x802450cb) {
        // Tunnel establish -- peer connection confirmed
        u16 peer_port = 0;
        u32 peer_addr = 0;
        std::memcpy(&peer_port, data + 0x02, sizeof(u16));
        std::memcpy(&peer_addr, data + 0x04, sizeof(u32));
        LOG_INFO(Lib_Net,
                 "KernelP2P: ioctl TunnelEstablish peer_addr={:#x} ({}.{}.{}.{}) peer_port={}",
                 peer_addr, (ntohl(peer_addr) >> 24) & 0xff, (ntohl(peer_addr) >> 16) & 0xff,
                 (ntohl(peer_addr) >> 8) & 0xff, ntohl(peer_addr) & 0xff, ntohs(peer_port));
        // In HLE, the event is fired when ActivatePeer transitions to ACTIVE.
        return 0;
    }

    if (code == 0x802450cc) {
        // Tunnel teardown -- peer departed
        LOG_INFO(Lib_Net, "KernelP2P: ioctl TunnelTeardown");
        return 0;
    }

    LOG_WARNING(Lib_Net, "KernelP2P: unhandled ioctl code={:#x}", code);
    return 0;
}

// === Peer/Connection Management ===

s32 KernelP2PSubsystem::ActivatePeer(s32 ctx_id, const std::string& npid) {
    // Collect deferred events to fire after releasing lock (FireEstablished
    // acquires mutex_ internally, so we must NOT call it while holding it).
    struct DeferredEvent {
        s32 ctx_id;
        s32 conn_id;
        bool fire_mutual; // true for self-connections; false for peers (deferred to
                          // OnPeerPacketReceived)
    };
    std::vector<DeferredEvent> deferred;
    s32 result_cid = 0;

    {
        std::lock_guard lock(mutex_);

        // Idempotent: if connection already exists for this NpId, return existing conn_id.
        // If the existing conn was deactivated (INACTIVE), remove it and create fresh.
        auto existing = npid_to_conn_.find(npid);
        if (existing != npid_to_conn_.end()) {
            s32 cid = existing->second;
            auto conn_it = connections_.find(cid);
            if (conn_it != connections_.end() && conn_it->second.state == ConnState::INACTIVE) {
                // Stale deactivated entry -- clean up and fall through to new creation.
                LOG_INFO(Lib_Net,
                         "KernelP2P: ActivatePeer replacing INACTIVE conn_id={} for npid='{}'", cid,
                         npid);
                connections_.erase(conn_it);
                npid_to_conn_.erase(existing);
                existing = npid_to_conn_.end(); // force new creation below
            }
        }
        if (existing != npid_to_conn_.end()) {
            s32 cid = existing->second;
            auto conn_it = connections_.find(cid);
            if (conn_it != connections_.end()) {
                auto& conn = conn_it->second;

                // Re-fire ESTABLISHED for idempotent calls (SocketState entries created after
                // the initial event need fresh events). Rate-limit to 150ms window.
                if (conn.events_fired) {
                    auto now = std::chrono::steady_clock::now();
                    auto since_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                        now - conn.last_event_time)
                                        .count();
                    if (since_ms >= 150) {
                        conn.last_event_time = now;
                        LOG_INFO(Lib_Net,
                                 "KernelP2P: ActivatePeer EXISTING npid='{}' conn_id={} "
                                 "re-firing ESTABLISHED (since={}ms, mutual_fired={})",
                                 npid, cid, since_ms, conn.mutual_fired);
                        // Re-fire MUTUAL only if it was already fired (bilateral confirmed)
                        deferred.push_back({ctx_id, cid, conn.mutual_fired});
                    } else {
                        LOG_INFO(Lib_Net,
                                 "KernelP2P: ActivatePeer EXISTING npid='{}' conn_id={} "
                                 "rate-limited (since={}ms)",
                                 npid, cid, since_ms);
                    }
                } else if (conn.addr != 0 && !conn.events_fired) {
                    // Connection has peer data but ESTABLISHED hasn't fired yet.
                    conn.state = ConnState::ACTIVE;
                    conn.game_activated = true;

                    if (!conn.echo_started) {
                        conn.echo_started = true;
                        conn.last_echo_sent = {};
                    }

                    if (conn.echo_bilateral && !conn.data_phase_active) {
                        // Bilateral done, no data phase -- fire immediately
                        conn.events_fired = true;
                        conn.gcs_active_at =
                            std::chrono::steady_clock::now() + std::chrono::milliseconds(150);
                        conn.mutual_fired = true;
                        conn.last_event_time = std::chrono::steady_clock::now();
                        deferred.push_back({ctx_id, cid, true});
                        LOG_INFO(Lib_Net,
                                 "KernelP2P: ActivatePeer EXISTING npid='{}' conn_id={} "
                                 "echo bilateral already done -- firing ESTABLISHED now",
                                 npid, cid);
                    } else {
                        LOG_INFO(Lib_Net,
                                 "KernelP2P: ActivatePeer EXISTING npid='{}' conn_id={} "
                                 "addr={:#x} stun={} bilateral={} data_phase={} "
                                 "(game activated, echo probes running)",
                                 npid, cid, conn.addr, static_cast<int>(conn.stun_state),
                                 conn.echo_bilateral, conn.data_phase_active);
                    }
                } else {
                    LOG_INFO(Lib_Net,
                             "KernelP2P: ActivatePeer EXISTING npid='{}' conn_id={} "
                             "(events not yet fired, pending peer data)",
                             npid, cid);
                }
                result_cid = cid;
                goto fire_deferred;
            }
        }

        {
            // New activation -- assign conn_id sequentially.
            // connId->memberId translation for events is in KernelEventBridge.
            s32 cid = next_conn_id_++;
            PeerConnection conn;
            conn.conn_id = cid;
            conn.ctx_id = ctx_id;
            conn.npid = npid;

            // Check if this is a self-connection (local identity)
            bool is_self = (!local_npid_.empty() && npid == local_npid_);

            // Look for matching peer by NpId
            PeerInfo* matched = nullptr;
            for (auto& [mid, pi] : peers_) {
                if (pi.npid == npid && pi.addr != 0) {
                    matched = &pi;
                    break;
                }
            }

            if (is_self) {
                // Self-connection fast path: immediately ACTIVE with local addr.
                // Both sides are local -- bilateral by definition, fire MUTUAL immediately.
                conn.addr = local_addr_;
                conn.port = local_port_;
                conn.state = ConnState::ACTIVE;
                conn.events_fired = true;
                conn.gcs_active_at =
                    std::chrono::steady_clock::now() + std::chrono::milliseconds(150);
                conn.mutual_fired = true;
                conn.last_event_time = std::chrono::steady_clock::now();

                LOG_INFO(Lib_Net,
                         "KernelP2P: ActivatePeer SELF npid='{}' conn_id={} addr={:#x} port={} "
                         "(immediate ACTIVE + MUTUAL)",
                         npid, cid, local_addr_, ntohs(local_port_));

                connections_[cid] = conn;
                npid_to_conn_[npid] = cid;
                deferred.push_back({ctx_id, cid, true});
                result_cid = cid;
                goto fire_deferred;
            }

            if (matched) {
                // Peer already known -- set ACTIVE for GCS reads, but ESTABLISHED
                // deferred to echo probe bilateral confirmation (~1.5s).
                conn.addr = matched->addr;
                conn.port = matched->port;
                conn.state = ConnState::ACTIVE;
                conn.game_activated = true; // game explicitly activated
                conn.events_fired = false;  // deferred to echo bilateral confirmation
                conn.mutual_fired = false;
                conn.echo_started = true; // start echo probes
                conn.last_echo_sent = {}; // probe on next cycle
                conn.last_event_time = std::chrono::steady_clock::now();

                LOG_INFO(Lib_Net,
                         "KernelP2P: ActivatePeer NEW npid='{}' conn_id={} "
                         "peer_addr={:#x} ({}.{}.{}.{}) port={} (peer known, ACTIVE -- "
                         "ESTABLISHED deferred to echo bilateral confirmation)",
                         npid, cid, matched->addr, (ntohl(matched->addr) >> 24) & 0xff,
                         (ntohl(matched->addr) >> 16) & 0xff, (ntohl(matched->addr) >> 8) & 0xff,
                         ntohl(matched->addr) & 0xff, ntohs(matched->port));

                connections_[cid] = conn;
                npid_to_conn_[npid] = cid;
                // NO deferred event -- ESTABLISHED fires from ProcessEchoProbe
                result_cid = cid;
                goto fire_deferred;
            }

            // Peer NOT yet known -- defer events until SetPeerInfo resolves
            conn.addr = 0;
            conn.port = 0;
            conn.state = ConnState::PENDING;
            conn.game_activated = true; // game explicitly activated
            conn.events_fired = false;

            LOG_INFO(Lib_Net,
                     "KernelP2P: ActivatePeer NEW npid='{}' conn_id={} (peer not known, PENDING)",
                     npid, cid);

            connections_[cid] = conn;
            npid_to_conn_[npid] = cid;
            result_cid = cid;
        }
    } // lock released

fire_deferred:
    // Fire ESTABLISHED outside the lock. MUTUAL_ACTIVATED is bilateral:
    // - Self connections: fire immediately (both sides are local)
    // - LAN peers: fire immediately (kernel confirms bilateral via probe, instant on LAN)
    // - STUN/WAN: fired after STUN OFFER/ACCEPT exchange completes (bilateral by design)
    for (const auto& ev : deferred) {
        FireEstablished(ev.ctx_id, ev.conn_id, 200);
        if (ev.fire_mutual) {
            FireMutualActivated(ev.ctx_id, ev.conn_id, 250);
        }
    }
    return result_cid;
}

int KernelP2PSubsystem::DeactivatePeer(s32 conn_id) {
    std::lock_guard lock(mutex_);

    auto it = connections_.find(conn_id);
    if (it != connections_.end()) {
        // Mark as INACTIVE but do NOT destroy the entry.
        // The game calls DeactivateConnection multiple times for the same connId
        // (once per signaling event received). Destroying on first call causes
        // subsequent calls to fail and leaves the game's native structures with
        // a stale connId reference. The entry is cleaned up when:
        //   - ClearAll() is called (LeaveRoom / session end)
        //   - A new ActivatePeer for the same NpId reuses the slot
        if (it->second.state != ConnState::INACTIVE) {
            LOG_INFO(Lib_Net,
                     "KernelP2P: DeactivatePeer conn_id={} npid='{}' state={} -> INACTIVE "
                     "(full echo state reset)",
                     conn_id, it->second.npid, static_cast<int>(it->second.state));
            it->second.state = ConnState::INACTIVE;
            it->second.events_fired = false;
            it->second.mutual_fired = false;
            it->second.data_phase_active = false;
            // Full reset of echo/signaling state so re-activation starts fresh.
            it->second.echo_started = false;
            it->second.echo_bilateral = false;
            it->second.game_activated = false;
            it->second.echo_probes_sent = 0;
            it->second.echo_responses_received = 0;
            it->second.echo_start_at = {};
            it->second.last_echo_sent = {};
            it->second.last_event_time = {};
            it->second.gcs_active_at = {};
            it->second.stun_state = StunState::NONE;
            it->second.mapped_addr = 0;
            it->second.mapped_port = 0;
        } else {
            LOG_INFO(Lib_Net,
                     "KernelP2P: DeactivatePeer conn_id={} npid='{}' already INACTIVE (idempotent)",
                     conn_id, it->second.npid);
        }
    } else {
        if (conn_id > 0) {
            LOG_WARNING(Lib_Net, "KernelP2P: DeactivatePeer conn_id={} NOT FOUND", conn_id);
        }
    }
    return 0;
}

void KernelP2PSubsystem::RemoveConnectionByNpid(const std::string& npid) {
    std::lock_guard lock(mutex_);
    auto map_it = npid_to_conn_.find(npid);
    if (map_it != npid_to_conn_.end()) {
        s32 cid = map_it->second;
        LOG_INFO(Lib_Net, "KernelP2P: RemoveConnectionByNpid npid='{}' conn_id={} -- erasing entry",
                 npid, cid);
        connections_.erase(cid);
        npid_to_conn_.erase(map_it);
    } else {
        LOG_INFO(Lib_Net,
                 "KernelP2P: RemoveConnectionByNpid npid='{}' -- no mapping found (already clean)",
                 npid);
    }
}

int KernelP2PSubsystem::GetConnectionStatus(s32 conn_id, s32* status_out, u32* addr_out,
                                            u16* port_out, bool delayed) {
    std::lock_guard lock(mutex_);

    auto it = connections_.find(conn_id);
    if (it != connections_.end()) {
        const auto& conn = it->second;

        if (conn.state == ConnState::PENDING) {
            if (status_out)
                *status_out = CONN_STATUS_PENDING;
            if (addr_out)
                *addr_out = 0;
            if (port_out)
                *port_out = 0;
            LOG_INFO(Lib_Net, "KernelP2P: GetConnectionStatus conn_id={} PENDING npid='{}'",
                     conn_id, conn.npid);
        } else {
            // Report raw echo-bilateral state for P2P routing.
            s32 status;
            if (conn.state == ConnState::ACTIVE && !conn.events_fired) {
                status = CONN_STATUS_PENDING;
            } else if (conn.state == ConnState::ACTIVE) {
                status = CONN_STATUS_ACTIVE;
            } else {
                status = CONN_STATUS_INACTIVE;
            }
            if (status_out)
                *status_out = status;

            // Return STUN-mapped address when available (NAT traversal),
            // otherwise fall back to server-reported address (LAN mode).
            u32 out_addr = conn.addr;
            u16 out_port = conn.port;
            if (conn.stun_state == StunState::COMPLETE && conn.mapped_addr != 0) {
                out_addr = conn.mapped_addr;
                out_port = conn.mapped_port;
            }

            if (addr_out)
                *addr_out = out_addr;
            if (port_out)
                *port_out = out_port;
            LOG_INFO(Lib_Net,
                     "KernelP2P: GetConnectionStatus conn_id={} status={} "
                     "addr={:#x} ({}.{}.{}.{}) port={} npid='{}' stun={}",
                     conn_id, status, out_addr, (ntohl(out_addr) >> 24) & 0xff,
                     (ntohl(out_addr) >> 16) & 0xff, (ntohl(out_addr) >> 8) & 0xff,
                     ntohl(out_addr) & 0xff, out_port ? ntohs(out_port) : 0, conn.npid,
                     static_cast<int>(conn.stun_state));
        }
        return 0;
    }

    if (status_out)
        *status_out = CONN_STATUS_INACTIVE;
    if (addr_out)
        *addr_out = 0;
    if (port_out)
        *port_out = 0;
    if (conn_id > 0) {
        LOG_WARNING(Lib_Net, "KernelP2P: GetConnectionStatus conn_id={} NOT FOUND", conn_id);
    }
    return 0x8055270E; // ORBIS_NP_SIGNALING_ERROR_CONN_NOT_FOUND
}

int KernelP2PSubsystem::GetConnectionInfo(s32 conn_id, s32 info_type, void* info) {
    if (!info)
        return 0;

    std::lock_guard lock(mutex_);

    PeerConnection ci{};
    bool found = false;
    auto it = connections_.find(conn_id);
    if (it != connections_.end()) {
        ci = it->second;
        found = true;
    }

    switch (info_type) {
    case CONN_INFO_RTT: {
        // Return measured RTT from echo probes (microseconds).
        auto* out = static_cast<u32*>(info);
        *out = found ? static_cast<u32>(std::max(ci.rtt_us / 1000, 1)) : 10;
        break;
    }

    case CONN_INFO_BANDWIDTH: {
        // Return measured bandwidth from echo probe timing (bytes/sec).
        auto* out = static_cast<s32*>(info);
        *out = found && ci.bandwidth_bps > 0 ? ci.bandwidth_bps : 10000000;
        break;
    }

    case CONN_INFO_PEER_NP_ID: {
        auto* npid_out = static_cast<Libraries::Np::OrbisNpId*>(info);
        std::memset(npid_out, 0, sizeof(Libraries::Np::OrbisNpId));
        if (found && !ci.npid.empty()) {
            std::strncpy(npid_out->handle.data, ci.npid.c_str(), sizeof(npid_out->handle.data) - 1);
        }
        break;
    }

    case CONN_INFO_PEER_ADDR: {
        auto* out = static_cast<OrbisNetSignalingAddr*>(info);
        *out = {};
        if (found && ci.state == ConnState::ACTIVE) {
            out->addr = ci.addr;
            out->port = ci.port;
        }
        LOG_INFO(Lib_Net, "KernelP2P: GetConnectionInfo PEER_ADDR conn_id={} addr={:#x} port={}",
                 conn_id, out->addr, ntohs(out->port));
        break;
    }

    case CONN_INFO_MAPPED_ADDR: {
        // Return STUN-mapped address when available (NAT traversal),
        // otherwise fall back to server-reported address.
        auto* out = static_cast<OrbisNetSignalingAddr*>(info);
        *out = {};
        if (found && ci.state == ConnState::ACTIVE) {
            if (ci.stun_state == StunState::COMPLETE && ci.mapped_addr != 0) {
                out->addr = ci.mapped_addr;
                out->port = ci.mapped_port;
            } else {
                out->addr = ci.addr;
                out->port = ci.port;
            }
        }
        LOG_INFO(Lib_Net,
                 "KernelP2P: GetConnectionInfo MAPPED_ADDR conn_id={} addr={:#x} port={} stun={}",
                 conn_id, out->addr, ntohs(out->port), static_cast<int>(ci.stun_state));
        break;
    }

    case CONN_INFO_PACKET_LOSS: {
        auto* out = static_cast<u32*>(info);
        *out = 0;
        break;
    }

    default:
        LOG_WARNING(Lib_Net, "KernelP2P: GetConnectionInfo unknown type={}", info_type);
        break;
    }
    return 0;
}

int KernelP2PSubsystem::GetActivePeerCount() const {
    std::lock_guard lock(mutex_);
    int count = 0;
    for (const auto& [mid, pi] : peers_) {
        if (pi.addr != 0 && !(pi.addr == local_addr_ && pi.port == local_port_)) {
            count++;
        }
    }
    return count;
}

bool KernelP2PSubsystem::GetActivePeerAddr(u32* addr_out, u16* port_out) {
    std::lock_guard lock(mutex_);

    for (const auto& [mid, pi] : peers_) {
        if (pi.addr != 0 && !(pi.addr == local_addr_ && pi.port == local_port_)) {
            if (addr_out)
                *addr_out = pi.addr;
            if (port_out)
                *port_out = pi.port;
            return true;
        }
    }
    return false;
}

bool KernelP2PSubsystem::ResolvePeerPort(u32 addr, u16* port_out) {
    std::lock_guard lock(mutex_);

    for (const auto& [mid, pi] : peers_) {
        if (pi.addr == addr && pi.addr != 0) {
            if (port_out)
                *port_out = pi.port;
            return true;
        }
    }
    // Fallback: check connections (may have addr from STUN resolution)
    for (const auto& [cid, conn] : connections_) {
        if (conn.addr == addr && conn.state == ConnState::ACTIVE) {
            if (port_out)
                *port_out = conn.port;
            return true;
        }
    }
    return false;
}

u16 KernelP2PSubsystem::GetMemberIdForConn(s32 conn_id) const {
    std::lock_guard lock(mutex_);
    auto it = connections_.find(conn_id);
    if (it == connections_.end())
        return 0;
    // Find the peer whose npid matches this connection
    for (const auto& [mid, pi] : peers_) {
        if (pi.npid == it->second.npid)
            return mid;
    }
    return 0;
}

s32 KernelP2PSubsystem::GetConnIdByNpid(const std::string& npid) const {
    std::lock_guard lock(mutex_);
    auto it = npid_to_conn_.find(npid);
    return (it != npid_to_conn_.end()) ? it->second : 0;
}

std::string KernelP2PSubsystem::GetNpidForConn(s32 conn_id) const {
    std::lock_guard lock(mutex_);
    auto it = connections_.find(conn_id);
    return (it != connections_.end()) ? it->second.npid : std::string{};
}

// === Peer Data Updates ===

void KernelP2PSubsystem::SetPeerInfo(u16 member_id, u32 addr, u16 port, const std::string& npid,
                                     u32 established_delay_ms) {
    // Collect deferred events to fire after releasing lock
    struct DeferredEvent {
        s32 ctx_id;
        s32 conn_id;
        bool needs_stun;    // true if STUN exchange should gate ESTABLISHED
        bool is_mesh_offer; // true if this peer should send OFFER (mesh: higher member_id)
    };
    std::vector<DeferredEvent> deferred;
    bool is_self = false;

    {
        std::lock_guard lock(mutex_);

        PeerInfo pi;
        pi.member_id = member_id;
        pi.addr = addr;
        pi.port = port;
        pi.npid = npid;
        peers_[member_id] = pi;

        is_self = (!local_npid_.empty() && npid == local_npid_);

        LOG_INFO(Lib_Net,
                 "KernelP2P: SetPeerInfo member={} addr={:#x} ({}.{}.{}.{}) port={} npid='{}' "
                 "is_self={} stun_client={}",
                 member_id, addr, (ntohl(addr) >> 24) & 0xff, (ntohl(addr) >> 16) & 0xff,
                 (ntohl(addr) >> 8) & 0xff, ntohl(addr) & 0xff, port ? ntohs(port) : 0, npid,
                 is_self, stun_client_.load() != nullptr);

        // Resolve or create connections for this peer.
        // If ActivatePeer was already called, resolve the PENDING connection.
        // If not, pre-create a PENDING connection so the STUN worker can
        // match incoming OFFERs before ActivatePeer runs.
        if (!npid.empty() && addr != 0) {
            auto conn_it = npid_to_conn_.find(npid);
            bool was_pre_created = false;
            if (conn_it == npid_to_conn_.end() && !is_self) {
                // No connection yet -- pre-create one for STUN matching.
                // Use the first registered context's ID.
                s32 ctx_id = 0;
                if (!sig_callbacks_.empty()) {
                    ctx_id = sig_callbacks_.begin()->first;
                }
                if (ctx_id > 0) {
                    s32 new_conn_id = next_conn_id_++;
                    PeerConnection pc{};
                    pc.conn_id = new_conn_id;
                    pc.ctx_id = ctx_id;
                    pc.npid = npid;
                    pc.addr = addr;
                    pc.port = port;
                    pc.state = ConnState::PENDING;
                    connections_[new_conn_id] = pc;
                    npid_to_conn_[npid] = new_conn_id;
                    was_pre_created = true;
                    LOG_INFO(Lib_Net,
                             "KernelP2P: SetPeerInfo pre-created conn for '{}' -> "
                             "conn_id={} (for STUN OFFER matching)",
                             npid, new_conn_id);
                    conn_it = npid_to_conn_.find(npid);
                }
            }
            if (conn_it != npid_to_conn_.end()) {
                auto& conn = connections_[conn_it->second];
                // Skip INACTIVE connections -- ActivatePeer will erase and recreate
                // them fresh. Updating an INACTIVE connection here would change its
                // state (e.g. to ACTIVE for LAN), preventing ActivatePeer from
                // detecting it as stale and creating a clean replacement.
                if (conn.state == ConnState::INACTIVE) {
                    LOG_INFO(Lib_Net,
                             "KernelP2P: SetPeerInfo skipping INACTIVE conn for '{}' "
                             "conn_id={} -- ActivatePeer will recreate",
                             npid, conn.conn_id);
                } else if (!conn.events_fired) {
                    conn.addr = addr;
                    conn.port = port;

                    // Determine if STUN exchange should gate ESTABLISHED events.
                    // Always attempt STUN for non-self peers when a STUN client is
                    // available. Private (RFC 1918) addresses do NOT imply same-LAN
                    // reachability — cross-network peers may report their LAN IP if
                    // their client hasn't completed NAT probing. Echo probes run in
                    // parallel with STUN, so LAN peers still get the fast path
                    // (direct echo bilateral confirms before STUN finishes).
                    auto* sc_spi = stun_client_.load();
                    bool stun_usable = (sc_spi != nullptr && sc_spi->GetMappedAddr() != 0);
                    bool needs_stun = (stun_usable && !is_self);

                    if (needs_stun && (my_member_id_ == 1 || member_id == 1)) {
                        // HOST<->GUEST STUN exchange: gate ESTABLISHED until
                        // ProcessStunOffer completes. HOST sends OFFER, GUEST waits.
                        // Echo probes start immediately in parallel with STUN --
                        // if direct connectivity works (port forwarding), echo
                        // bilateral confirms without waiting for STUN relay.
                        conn.state = ConnState::ACTIVE;
                        conn.stun_state = StunState::PENDING;
                        conn.events_fired = false;
                        conn.echo_started = true;
                        conn.last_echo_sent = {};
                        LOG_INFO(
                            Lib_Net,
                            "KernelP2P: SetPeerInfo STUN-gated conn for '{}' -> "
                            "conn_id={} addr={:#x} port={} (STUN PENDING, echo probes parallel)",
                            npid, conn.conn_id, addr, ntohs(port));
                        // HOST always sends OFFER to GUESTs
                        deferred.push_back({conn.ctx_id, conn.conn_id, true, my_member_id_ == 1});
                    } else if (needs_stun) {
                        // Non-HOST <-> Non-HOST (mesh): both peers are GUESTs.
                        // Port-restricted NAT requires a STUN exchange between
                        // mesh peers too -- the HOST<->GUEST NAT mapping only allows
                        // packets from HOST's IP.
                        //
                        // Deterministic role: higher member_id sends OFFER,
                        // lower waits for incoming OFFER via relay loop.
                        bool i_send_offer = (my_member_id_ > member_id);
                        conn.state = ConnState::ACTIVE;
                        conn.stun_state = StunState::PENDING;
                        conn.events_fired = false;
                        conn.echo_started = true;
                        conn.last_echo_sent = {};
                        LOG_INFO(Lib_Net,
                                 "KernelP2P: SetPeerInfo mesh-peer '{}' -> conn_id={} "
                                 "addr={:#x} port={} (STUN PENDING, mesh role={}, "
                                 "my_member={} peer_member={})",
                                 npid, conn.conn_id, addr, ntohs(port),
                                 i_send_offer ? "OFFER" : "WAIT", my_member_id_, member_id);
                        deferred.push_back({conn.ctx_id, conn.conn_id, true, i_send_offer});
                    } else {
                        // Start echo probes immediately to create NAT mappings.
                        conn.state = ConnState::ACTIVE;
                        conn.stun_state = StunState::NONE;
                        conn.events_fired = false;
                        conn.echo_started = true;
                        conn.last_echo_sent = {};
                        LOG_INFO(Lib_Net,
                                 "KernelP2P: SetPeerInfo {} '{}' -> "
                                 "conn_id={} addr={:#x} port={} (ACTIVE, echo probes started)",
                                 was_pre_created ? "pre-created" : "resolved", npid, conn.conn_id,
                                 addr, ntohs(port));
                    }
                }
            }
        }
    } // lock released

    // Handle deferred actions outside lock.
    // SetPeerInfo NEVER fires ESTABLISHED directly -- that's ActivatePeer's job.
    // Only STUN offers are queued here (WAN path).
    for (const auto& ev : deferred) {
        if (ev.needs_stun) {
            if (ev.is_mesh_offer) {
                // I send OFFER: HOST->GUEST or higher-member->lower-member (mesh)
                QueueStunOffer(ev.ctx_id, ev.conn_id, addr, port, npid);
            } else {
                // I wait: signaling thread's relay loop catches incoming OFFER
                LOG_INFO(Lib_Net,
                         "KernelP2P: SetPeerInfo WAIT role -- expecting OFFER "
                         "for conn_id={} npid='{}' (no outbound OFFER)",
                         ev.conn_id, npid);
            }
        }
    }
}

void KernelP2PSubsystem::RemovePeer(u16 member_id) {
    struct DeferredDead {
        s32 ctx_id;
        s32 conn_id;
    };
    std::vector<DeferredDead> dead_events;

    {
        std::lock_guard lock(mutex_);

        auto it = peers_.find(member_id);
        if (it == peers_.end()) {
            LOG_WARNING(Lib_Net, "KernelP2P: RemovePeer member={} NOT FOUND", member_id);
            return;
        }

        const std::string& npid = it->second.npid;
        LOG_INFO(Lib_Net, "KernelP2P: RemovePeer member={} npid='{}'", member_id, npid);

        // Find connection for this peer and schedule DEAD event
        if (!npid.empty()) {
            auto conn_it = npid_to_conn_.find(npid);
            if (conn_it != npid_to_conn_.end()) {
                auto& conn = connections_[conn_it->second];
                if (conn.state == ConnState::ACTIVE) {
                    dead_events.push_back({conn.ctx_id, conn.conn_id});
                }
                conn.state = ConnState::INACTIVE;
            }
        }

        peers_.erase(it);
    }

    for (const auto& ev : dead_events) {
        LOG_INFO(Lib_Net, "KernelP2P: RemovePeer firing DEAD for conn_id={}", ev.conn_id);
        FireDead(ev.ctx_id, ev.conn_id, 50);
    }
}

void KernelP2PSubsystem::ClearAll() {
    std::lock_guard lock(mutex_);
    LOG_INFO(Lib_Net, "KernelP2P: ClearAll -- clearing {} connections, {} npid mappings, {} peers",
             connections_.size(), npid_to_conn_.size(), peers_.size());
    connections_.clear();
    npid_to_conn_.clear();
    peers_.clear();
    // Do NOT reset next_conn_id_ -- conn_ids must be globally unique across
    // the NpSignaling context lifetime. Reusing conn_id=1 causes the game's
    // SocketState pipeline to skip it as "already used".
    current_room_id_ = 0;
    my_member_id_ = 0;
    peer_classifications_.clear();

    // Clear P2P transport session state so stale peer data from the
    // previous session doesn't interfere with the next one.
    ClearP2PSessionState();
}

// === Local Identity ===

void KernelP2PSubsystem::SetLocalIdentity(u32 addr, u16 port, const std::string& npid) {
    std::lock_guard lock(mutex_);
    local_addr_ = addr;
    local_port_ = port;
    local_npid_ = npid;
    LOG_INFO(Lib_Net, "KernelP2P: SetLocalIdentity addr={:#x} ({}.{}.{}.{}) port={} npid='{}'",
             addr, (ntohl(addr) >> 24) & 0xff, (ntohl(addr) >> 16) & 0xff,
             (ntohl(addr) >> 8) & 0xff, ntohl(addr) & 0xff, ntohs(port), npid);
}

u32 KernelP2PSubsystem::GetLocalAddr() const {
    std::lock_guard lock(mutex_);
    return local_addr_;
}

u16 KernelP2PSubsystem::GetLocalPort() const {
    std::lock_guard lock(mutex_);
    return local_port_;
}

// === Signaling Callback Registration ===

void KernelP2PSubsystem::RegisterSignalingCallback(
    s32 ctx_id, std::function<void(s32 ctx_id, s32 conn_id, s32 event, u32 delay_ms)> callback) {
    std::lock_guard lock(mutex_);
    sig_callbacks_[ctx_id] = CallbackInfo{std::move(callback)};
    LOG_INFO(Lib_Net, "KernelP2P: RegisterSignalingCallback ctx_id={}", ctx_id);
}

void KernelP2PSubsystem::UnregisterSignalingCallback(s32 ctx_id) {
    std::lock_guard lock(mutex_);
    sig_callbacks_.erase(ctx_id);
    LOG_INFO(Lib_Net, "KernelP2P: UnregisterSignalingCallback ctx_id={}", ctx_id);
}

void KernelP2PSubsystem::ClearSignalingCallbacks() {
    std::lock_guard lock(mutex_);
    sig_callbacks_.clear();
}

// === Ioctl Gate ===

void KernelP2PSubsystem::EnableGate() {
    std::lock_guard lock(mutex_);
    gate_enabled_ = true;
    LOG_INFO(Lib_Net, "KernelP2P: signaling gate ENABLED");
}

bool KernelP2PSubsystem::IsGateEnabled() const {
    std::lock_guard lock(mutex_);
    return gate_enabled_;
}

// === Session Lifecycle ===

void KernelP2PSubsystem::OnRoomJoined(u64 room_id, u16 my_member_id) {
    std::lock_guard lock(mutex_);
    current_room_id_ = room_id;
    my_member_id_ = my_member_id;
    LOG_INFO(Lib_Net, "KernelP2P: OnRoomJoined room={} member={}", room_id, my_member_id);
}

void KernelP2PSubsystem::OnRoomLeft() {
    // ClearAll handles the full cleanup
    ClearAll();
    LOG_INFO(Lib_Net, "KernelP2P: OnRoomLeft -- state cleared");
}

u64 KernelP2PSubsystem::GetCurrentRoomId() const {
    std::lock_guard lock(mutex_);
    return current_room_id_;
}

// === Reset ===

void KernelP2PSubsystem::Reset() {
    StopSignalingThread();
    std::lock_guard lock(mutex_);
    connections_.clear();
    npid_to_conn_.clear();
    peers_.clear();
    sig_callbacks_.clear();
    next_conn_id_ = 1;
    current_room_id_ = 0;
    my_member_id_ = 0;
    gate_enabled_ = false;
    nat_probe_succeeded_.store(false);
    local_npid_.clear();
    stun_client_.store(nullptr);
    peer_classifications_.clear();
    bound_vports_.clear();
    LOG_INFO(Lib_Net, "KernelP2P: full Reset");
}

void KernelP2PSubsystem::SendSignalingPacket(const u8* data, size_t len, u32 peer_addr_nbo,
                                             u16 peer_port_nbo) {
    auto* sc = stun_client_.load();
    if (!sc) {
        LOG_WARNING(Lib_Net, "KernelP2P: SendSignalingPacket -- no STUN client, cannot send");
        return;
    }
    int fd = sc->GetSocketFd();
    if (fd < 0)
        return;

    sockaddr_in dest{};
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = peer_addr_nbo;
    dest.sin_port = peer_port_nbo;

    auto sent = ::sendto(fd, reinterpret_cast<const char*>(data), len, 0,
                         reinterpret_cast<sockaddr*>(&dest), sizeof(dest));
    LOG_INFO(Lib_Net, "KernelP2P: SendSignalingPacket {} bytes to {:#x}:{} result={}", len,
             ntohl(peer_addr_nbo), ntohs(peer_port_nbo), sent);
}

void KernelP2PSubsystem::HandleActivatePacket(u32 from_addr, u16 from_port, u32 peer_conn_id,
                                              u32 ctx_tag) {
    // Find the peer's online_id by matching addr/port in our peers_ map
    std::string peer_npid;
    std::string my_npid;
    {
        std::lock_guard lock(mutex_);
        my_npid = local_npid_;
        for (const auto& [mid, pi] : peers_) {
            if (pi.addr == from_addr) {
                peer_npid = pi.npid;
                break;
            }
        }
    }

    if (peer_npid.empty()) {
        LOG_WARNING(Lib_Net, "KernelP2P: HandleActivatePacket -- no peer found for addr={:#x}:{}",
                    ntohl(from_addr), ntohs(from_port));
        return;
    }

    LOG_INFO(Lib_Net, "KernelP2P: HandleActivatePacket from '{}' -- posting confirm to server",
             peer_npid);

    // Fire-and-forget: POST /np/signaling/confirm to server
    Libraries::Np::NpMatching2::PostSignalingConfirm(my_npid, peer_npid);
}

// === Event Delivery (private) ===

void KernelP2PSubsystem::FireEstablished(s32 ctx_id, s32 conn_id, u32 delay_ms) {
    // Must be called WITHOUT mutex_ held (callbacks may re-enter)
    CallbackInfo cb_info;
    bool found = false;
    {
        std::lock_guard lock(mutex_);
        auto it = sig_callbacks_.find(ctx_id);
        if (it != sig_callbacks_.end()) {
            cb_info = it->second;
            found = true;
        }
    }

    if (found && cb_info.callback) {
        cb_info.callback(ctx_id, conn_id, SIG_EVENT_ESTABLISHED, delay_ms);
    } else {
        LOG_WARNING(Lib_Net, "KernelP2P: FireEstablished -- no callback for ctx_id={}", ctx_id);
    }
}

void KernelP2PSubsystem::FireDead(s32 ctx_id, s32 conn_id, u32 delay_ms) {
    // Must be called WITHOUT mutex_ held
    CallbackInfo cb_info;
    bool found = false;
    {
        std::lock_guard lock(mutex_);
        auto it = sig_callbacks_.find(ctx_id);
        if (it != sig_callbacks_.end()) {
            cb_info = it->second;
            found = true;
        }
    }

    if (found && cb_info.callback) {
        cb_info.callback(ctx_id, conn_id, SIG_EVENT_DEAD, delay_ms);
    } else {
        LOG_WARNING(Lib_Net, "KernelP2P: FireDead -- no callback for ctx_id={}", ctx_id);
    }
}

void KernelP2PSubsystem::FireMutualActivated(s32 ctx_id, s32 conn_id, u32 delay_ms) {
    // MUTUAL_ACTIVATED fires when both peers have completed their P2P tunnel setup.
    // SocketState state 9 (sendHandshakeType2) requires this event.
    CallbackInfo cb_info;
    bool found = false;
    {
        std::lock_guard lock(mutex_);
        auto it = sig_callbacks_.find(ctx_id);
        if (it != sig_callbacks_.end()) {
            cb_info = it->second;
            found = true;
        }
    }

    if (found && cb_info.callback) {
        cb_info.callback(ctx_id, conn_id, SIG_EVENT_MUTUAL_ACTIVATED, delay_ms);
    } else {
        LOG_WARNING(Lib_Net, "KernelP2P: FireMutualActivated -- no callback for ctx_id={}", ctx_id);
    }
}

// === STUN Signaling Integration ===

void KernelP2PSubsystem::SetStunClient(StunClient* client) {
    stun_client_.store(client);
    LOG_INFO(Lib_Net, "KernelP2P: STUN client set ({})", client ? "valid" : "null");
}

StunClient* KernelP2PSubsystem::GetStunClient() const {
    return stun_client_.load();
}

bool KernelP2PSubsystem::IsStunComplete(s32 conn_id) const {
    std::lock_guard lock(mutex_);
    auto it = connections_.find(conn_id);
    if (it == connections_.end())
        return false;
    return it->second.stun_state == StunState::COMPLETE || it->second.stun_state == StunState::NONE;
}

void KernelP2PSubsystem::StartSignalingThread() {
    if (signaling_thread_.joinable()) {
        return; // Already running
    }
    signaling_shutdown_.store(false);
    signaling_thread_ = std::thread([this]() { SignalingThreadFunc(); });
    LOG_INFO(Lib_Net, "KernelP2P: signaling thread started");
}

void KernelP2PSubsystem::StopSignalingThread() {
    signaling_shutdown_.store(true);
    if (signaling_thread_.joinable()) {
        signaling_thread_.join();
    }
    LOG_INFO(Lib_Net, "KernelP2P: signaling thread stopped");
}

void KernelP2PSubsystem::QueueStunOffer(s32 ctx_id, s32 conn_id, u32 peer_addr, u16 peer_port,
                                        const std::string& peer_npid) {
    std::lock_guard lock(offer_queue_mutex_);
    offer_queue_.push_back({ctx_id, conn_id, peer_addr, peer_port, peer_npid});
    LOG_INFO(Lib_Net, "KernelP2P: queued STUN OFFER for conn_id={} npid='{}' (queue size={})",
             conn_id, peer_npid, offer_queue_.size());
}

void KernelP2PSubsystem::SignalingThreadFunc() {
    // Single signaling thread for NAT probe, STUN OFFER/ACCEPT, and keepalives.
    LOG_INFO(Lib_Net, "KernelP2P: signaling thread started");

    // Phase A: NAT probe (async -- runs in background so the signaling loop
    // starts immediately for echo probes and STUN offers). Previously this
    // blocked the signaling thread for up to ~36s when STUN was unreachable
    // (3 rounds x 10 retries x exponential backoff).
    auto* sc_probe = stun_client_.load();
    std::atomic<bool> nat_probe_done{false};
    std::thread nat_probe_thread;
    if (sc_probe && !signaling_shutdown_.load()) {
        nat_probe_thread = std::thread([this, sc_probe, &nat_probe_done]() {
            LOG_INFO(Lib_Net, "KernelP2P: NAT probe starting (async)");
            auto probe = sc_probe->NatProbe();
            if (probe.success) {
                char buf[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &probe.mapped_addr, buf, sizeof(buf));
                LOG_INFO(Lib_Net, "KernelP2P: NAT probe complete: mapped={}:{} type={}", buf,
                         ntohs(probe.mapped_port), static_cast<int>(probe.nat_type));
                Libraries::Np::NpMatching2::UpdateSignalingAddrFromStun(std::string(buf),
                                                                        ntohs(probe.mapped_port));
                nat_probe_succeeded_.store(true);
            } else {
                LOG_WARNING(Lib_Net, "KernelP2P: NAT probe failed -- STUN server unreachable, "
                                     "will retry periodically");
            }
            nat_probe_done.store(true);
        });
    } else {
        nat_probe_done.store(true);
    }

    // Phase B: processing loop (starts immediately, doesn't wait for NAT probe)
    auto last_keepalive = std::chrono::steady_clock::now();
    constexpr auto KEEPALIVE_INTERVAL = std::chrono::seconds(15);

    int sig_loop_tick = 0;
    while (!signaling_shutdown_.load()) {
        sig_loop_tick++;
        auto loop_start = std::chrono::steady_clock::now();

        // Send echo probes for bilateral P2P confirmation.
        SendEchoProbes();

        // Load stun_client_ once per iteration to avoid TOCTOU races
        // (pointer could become null between check and dereference).
        auto* sc = stun_client_.load();
        if (!sc) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }

        // 1. Process pending STUN OFFERs from the queue (synchronous)
        int offers_processed = 0;
        {
            std::deque<PendingOffer> offers;
            {
                std::lock_guard lock(offer_queue_mutex_);
                offers.swap(offer_queue_);
            }
            for (const auto& offer : offers) {
                if (signaling_shutdown_.load())
                    break;
                LOG_INFO(Lib_Net, "KernelP2P: sigloop tick={} processing STUN OFFER for conn_id={}",
                         sig_loop_tick, offer.conn_id);
                ProcessStunOffer(offer.ctx_id, offer.conn_id, offer.peer_addr, offer.peer_port,
                                 offer.peer_npid);
                offers_processed++;
            }
        }

        // 2. Send periodic keepalive
        auto now = std::chrono::steady_clock::now();
        if (now - last_keepalive >= KEEPALIVE_INTERVAL) {
            last_keepalive = now;
            sc->SendKeepalive();
        }

        // 2b. Retry NAT probe if it hasn't succeeded yet.
        // The initial probe can fail if the STUN server is temporarily unreachable
        // (e.g., DNS resolution timing, transient network issue). Without this,
        // the client is stuck on its LAN IP forever and remote peers can't reach it.
        static constexpr auto NAT_RETRY_INTERVAL = std::chrono::seconds(10);
        static auto last_nat_retry = std::chrono::steady_clock::time_point{};
        if (!nat_probe_succeeded_.load() && nat_probe_done.load() &&
            (now - last_nat_retry >= NAT_RETRY_INTERVAL)) {
            last_nat_retry = now;
            LOG_INFO(Lib_Net, "KernelP2P: retrying NAT probe (previous attempt failed)");
            auto probe = sc->NatProbe();
            if (probe.success) {
                char buf[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &probe.mapped_addr, buf, sizeof(buf));
                LOG_INFO(Lib_Net, "KernelP2P: NAT probe retry succeeded: mapped={}:{}", buf,
                         ntohs(probe.mapped_port));
                Libraries::Np::NpMatching2::UpdateSignalingAddrFromStun(std::string(buf),
                                                                        ntohs(probe.mapped_port));
                nat_probe_succeeded_.store(true);
            } else {
                LOG_WARNING(Lib_Net,
                            "KernelP2P: NAT probe retry failed -- will try again in {}s",
                            NAT_RETRY_INTERVAL.count());
            }
        }

        // 3. Process incoming STUN relays (OFFER from peer)
        auto relay = sc->WaitForRelay(500);
        auto loop_elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                                std::chrono::steady_clock::now() - loop_start)
                                .count();
        if (sig_loop_tick <= 5 || sig_loop_tick % 50 == 0) {
            LOG_INFO(Lib_Net, "KernelP2P: sigloop tick={} elapsed={}ms offers={} relay={}",
                     sig_loop_tick, loop_elapsed, offers_processed, relay.success);
        }
        if (!relay.success) {
            continue;
        }

        char mapped_buf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &relay.mapped_addr, mapped_buf, sizeof(mapped_buf));
        std::string relay_username = sc->GetLastRelayUsername();

        LOG_INFO(Lib_Net, "KernelP2P: STUN relay received -- peer mapped={}:{} username='{}'",
                 mapped_buf, ntohs(relay.mapped_port), relay_username);

        // Skip self-relays (USERNAME match only -- address check breaks same-NAT LAN)
        {
            std::lock_guard lock(mutex_);
            if (!relay_username.empty() && relay_username == local_npid_) {
                LOG_DEBUG(Lib_Net,
                          "KernelP2P: STUN relay is from ourselves (username='{}'), ignoring",
                          relay_username);
                continue;
            }
        }

        // Find matching connection
        struct DeferredAccept {
            s32 ctx_id;
            s32 conn_id;
            u32 peer_addr;
            u16 peer_port;
        };
        std::vector<DeferredAccept> to_accept;

        {
            std::lock_guard lock(mutex_);
            PeerConnection* matched_conn = nullptr;

            // Strategy 1: Match by USERNAME -> NpId
            if (!relay_username.empty()) {
                auto conn_it = npid_to_conn_.find(relay_username);
                if (conn_it != npid_to_conn_.end()) {
                    auto& conn = connections_[conn_it->second];
                    if (conn.stun_state == StunState::PENDING || !conn.events_fired) {
                        matched_conn = &conn;
                        LOG_INFO(Lib_Net,
                                 "KernelP2P: STUN relay matched by USERNAME='{}' -> conn_id={}",
                                 relay_username, conn.conn_id);
                    }
                }
            }

            // Strategy 2: Match by address
            if (!matched_conn) {
                for (auto& [cid, conn] : connections_) {
                    if (conn.addr == relay.mapped_addr && conn.port == relay.mapped_port &&
                        (conn.stun_state == StunState::PENDING || !conn.events_fired)) {
                        matched_conn = &conn;
                        LOG_INFO(Lib_Net,
                                 "KernelP2P: STUN relay matched by address {}:{} -> conn_id={}",
                                 mapped_buf, ntohs(relay.mapped_port), cid);
                        break;
                    }
                }
            }

            // Strategy 3: Any PENDING with no address
            if (!matched_conn) {
                for (auto& [cid, conn] : connections_) {
                    if (conn.state == ConnState::PENDING && conn.addr == 0) {
                        matched_conn = &conn;
                        LOG_INFO(Lib_Net,
                                 "KernelP2P: STUN relay matched PENDING conn_id={} (no addr yet)",
                                 cid);
                        break;
                    }
                }
            }

            if (matched_conn) {
                matched_conn->mapped_addr = relay.mapped_addr;
                matched_conn->mapped_port = relay.mapped_port;
                // Always update primary address to STUN-resolved values.
                // SetPeerInfo may have set addr to the server-reported address
                // (correct IP but wrong NAT port). The relay provides the
                // actual NAT-mapped address from the peer's NatProbe.
                matched_conn->addr = relay.mapped_addr;
                matched_conn->port = relay.mapped_port;
                matched_conn->state = ConnState::ACTIVE;
                matched_conn->stun_state = StunState::COMPLETE;

                // Start echo probes immediately at STUN COMPLETE, even before
                // game_activated. Both sides must probe simultaneously to create
                // bidirectional NAT mappings.
                if (!matched_conn->echo_started) {
                    matched_conn->echo_started = true;
                    matched_conn->last_echo_sent = {};
                    LOG_INFO(Lib_Net,
                             "KernelP2P: STUN COMPLETE -> echo probes started for conn_id={} "
                             "(pre-activation, for NAT punch-through)",
                             matched_conn->conn_id);
                }

                // Only fire ESTABLISHED if the game has already called
                // ActivateConnection. If not yet activated (e.g., STUN completed
                // during invite poll), ActivatePeer will fire events when called.
                if (matched_conn->game_activated) {
                    matched_conn->events_fired = true;
                    matched_conn->gcs_active_at =
                        std::chrono::steady_clock::now() + std::chrono::milliseconds(150);
                    matched_conn->mutual_fired = true;
                    matched_conn->last_event_time = std::chrono::steady_clock::now();
                }

                LOG_INFO(Lib_Net,
                         "KernelP2P: STUN relay resolved conn_id={} npid='{}' -> "
                         "STUN COMPLETE mapped={}:{} game_activated={}",
                         matched_conn->conn_id, matched_conn->npid, mapped_buf,
                         ntohs(relay.mapped_port), matched_conn->game_activated ? "yes" : "no");

                // Always send ACCEPT (NAT punch), but only fire events if game is ready
                to_accept.push_back({matched_conn->ctx_id, matched_conn->conn_id, relay.mapped_addr,
                                     relay.mapped_port});
            } else {
                LOG_WARNING(Lib_Net,
                            "KernelP2P: STUN relay -- no matching connection, "
                            "sending speculative ACCEPT (username='{}' mapped={}:{})",
                            relay_username, mapped_buf, ntohs(relay.mapped_port));
                if (relay.mapped_addr != 0) {
                    std::vector<u8> udata;
                    if (!local_npid_.empty()) {
                        udata.assign(local_npid_.begin(), local_npid_.end());
                        udata.resize(16, 0);
                    }
                    sc->SendAccept(relay.mapped_addr, relay.mapped_port, udata, {0x03});

                    struct sockaddr_in peer_sa{};
                    peer_sa.sin_family = AF_INET;
                    peer_sa.sin_addr.s_addr = relay.mapped_addr;
                    peer_sa.sin_port = relay.mapped_port;
                    u8 punch[] = {0xFF, 0xC3, 0x00, 0x00};
                    int fd = sc->GetSocketFd();
                    for (int i = 0; i < 2; i++) {
                        ::sendto(fd, reinterpret_cast<const char*>(punch), sizeof(punch), 0,
                                 reinterpret_cast<struct sockaddr*>(&peer_sa), sizeof(peer_sa));
                        std::this_thread::sleep_for(std::chrono::milliseconds(50));
                    }
                }
            }
        }

        // Send ACCEPT + NAT punch + fire events for matched connections
        for (const auto& ev : to_accept) {
            std::vector<u8> username_data;
            {
                std::lock_guard lock(mutex_);
                if (!local_npid_.empty()) {
                    username_data.assign(local_npid_.begin(), local_npid_.end());
                    username_data.resize(16, 0);
                }
            }

            sc->SendAccept(ev.peer_addr, ev.peer_port, username_data);

            char peer_buf[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &ev.peer_addr, peer_buf, sizeof(peer_buf));

            struct sockaddr_in peer_sa{};
            peer_sa.sin_family = AF_INET;
            peer_sa.sin_addr.s_addr = ev.peer_addr;
            peer_sa.sin_port = ev.peer_port;
            u8 punch[] = {0xFF, 0xC3, 0x00, 0x00};
            int fd = sc->GetSocketFd();
            for (int i = 0; i < 2; i++) {
                ::sendto(fd, reinterpret_cast<const char*>(punch), sizeof(punch), 0,
                         reinterpret_cast<struct sockaddr*>(&peer_sa), sizeof(peer_sa));
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
            }
            LOG_INFO(Lib_Net, "KernelP2P: STUN ACCEPT + NAT punch sent to {}:{} for conn_id={}",
                     peer_buf, ntohs(ev.peer_port), ev.conn_id);

            // Update STUN state and primary address for matched connection
            {
                std::lock_guard lock(mutex_);
                auto it = connections_.find(ev.conn_id);
                if (it != connections_.end()) {
                    it->second.stun_state = StunState::COMPLETE;
                    it->second.mapped_addr = ev.peer_addr;
                    it->second.mapped_port = ev.peer_port;
                    it->second.addr = ev.peer_addr;
                    it->second.port = ev.peer_port;
                }
            }

            // Only fire ESTABLISHED + MUTUAL if the game has activated this connection.
            // If not activated yet, ActivatePeer will fire events when the game calls
            // ActivateConnection. This prevents premature ESTABLISHED firing during the
            // invite poll phase (before JoinRoom/ActivateConnection), which causes the
            // SCO to receive ESTABLISHED for an unknown connId -> teardown -> broken session.
            bool should_fire = false;
            {
                std::lock_guard lock(mutex_);
                auto it = connections_.find(ev.conn_id);
                if (it != connections_.end() && it->second.game_activated) {
                    should_fire = true;
                }
            }
            if (should_fire) {
                FireEstablished(ev.ctx_id, ev.conn_id, 200);
                FireMutualActivated(ev.ctx_id, ev.conn_id, 250);
            } else {
                LOG_INFO(Lib_Net,
                         "KernelP2P: STUN ACCEPT sent for conn_id={} but game not activated yet "
                         "-- deferring ESTABLISHED to ActivatePeer",
                         ev.conn_id);
            }
        }
    }

    // Wait for async NAT probe to finish before exiting
    if (nat_probe_thread.joinable()) {
        nat_probe_thread.join();
    }

    LOG_INFO(Lib_Net, "KernelP2P: signaling thread exiting");
}

// === Echo Probe System ===
// Bilateral connectivity confirmation via type 0x06/0x07 probes on vport 0xFFFD.
// Both sides must respond before ESTABLISHED fires. Keepalive probes every 10s.

static constexpr int ECHO_PROBE_SIZE = 90; // payload after wire header
static constexpr u8 ECHO_TYPE_PROBE = 0x06;
static constexpr u8 ECHO_TYPE_RESPONSE = 0x07;
// Echo probe timing:
//   Phase 1: 3 bilateral responses (~1.5s) -- confirms reachability.
//   Phase 2 (LAN only): DATA exchange delay before ESTABLISHED, giving the game
//     time to create SocketState entries for 3+ player sessions.
//   STUN connections skip Phase 2.
static constexpr auto ECHO_PROBE_INTERVAL = std::chrono::milliseconds(500);
static constexpr auto ECHO_KEEPALIVE_INTERVAL = std::chrono::seconds(10);
static constexpr int ECHO_PROBES_FOR_ESTABLISHED = 3;

// DATA exchange phase duration (GUEST/INVADER LAN only, late-joiners).
// 2s delay lets the game create SocketState entries before ESTABLISHED fires.
// HOST side always fires ESTABLISHED immediately (needs to send TYPE=1).
// Configurable via SHADPS4_DATA_EXCHANGE_MS environment variable.
// Set to 0 to disable (instant ESTABLISHED after bilateral, old behavior).
static const auto DATA_EXCHANGE_DURATION = std::chrono::milliseconds([] {
    const char* env = std::getenv("SHADPS4_DATA_EXCHANGE_MS");
    return (env && *env) ? std::atoi(env) : 2000;
}());

void KernelP2PSubsystem::SendEchoProbes() {
    // Collect connections that need probes
    struct ProbeTarget {
        s32 conn_id;
        s32 ctx_id;
        u32 addr;
        u16 port;
        std::string npid;
        bool established;
    };
    std::vector<ProbeTarget> targets;

    // Collect DATA phase completions (timer-based, doesn't require a response).
    // This ensures ESTABLISHED fires even if no echo responses arrive during
    // the DATA phase (e.g., peer is temporarily unreachable but was bilateral).
    struct DeferredFire {
        s32 ctx_id;
        s32 conn_id;
    };
    std::vector<DeferredFire> data_phase_done;
    std::vector<DeferredFire> unreachable_dead;

    // Diagnostic snapshot — captured under lock, logged outside to reduce hold time.
    struct ConnDiag {
        s32 cid; std::string npid; u32 addr; u16 port;
        int state; int stun; bool echo_started; bool game_activated;
        bool events_fired; bool echo_bilateral; int probes_sent; int resp; long long ms_since_echo;
    };
    std::vector<ConnDiag> diag_snapshot;
    int diag_tick = 0;
    size_t diag_conn_count = 0;
    int diag_fd = -1;
    bool should_log = false;

    {
        std::lock_guard lock(mutex_);
        static int echo_tick = 0;
        echo_tick++;
        diag_tick = echo_tick;
        should_log = (echo_tick <= 20 || echo_tick % 50 == 0);
        if (should_log) {
            diag_conn_count = connections_.size();
            auto* s = stun_client_.load();
            diag_fd = s ? s->GetSocketFd() : -1;
            for (const auto& [cid, conn] : connections_) {
                auto ms_since_echo =
                    conn.last_echo_sent != std::chrono::steady_clock::time_point{}
                        ? std::chrono::duration_cast<std::chrono::milliseconds>(
                              std::chrono::steady_clock::now() - conn.last_echo_sent)
                              .count()
                        : -1LL;
                diag_snapshot.push_back({cid, conn.npid, conn.addr, conn.port,
                    static_cast<int>(conn.state), static_cast<int>(conn.stun_state),
                    conn.echo_started, conn.game_activated, conn.events_fired,
                    conn.echo_bilateral, conn.echo_probes_sent,
                    conn.echo_responses_received, ms_since_echo});
            }
        }
        for (auto& [cid, conn] : connections_) {
            if (conn.addr == 0 || conn.state == ConnState::INACTIVE)
                continue;
            // Skip self connections
            if (!local_npid_.empty() && conn.npid == local_npid_)
                continue;
            // Don't skip STUN PENDING -- echo probes run in parallel with
            // STUN to create NAT mappings simultaneously.

            auto now = std::chrono::steady_clock::now();

            // Check DATA exchange phase timer completion.
            // This runs every probe cycle (~100ms) so the timer fires promptly
            // even if no echo responses trigger ProcessEchoProbe.
            if (conn.data_phase_active && conn.echo_bilateral && conn.game_activated) {
                auto elapsed = now - conn.data_phase_start;
                if (elapsed >= DATA_EXCHANGE_DURATION) {
                    conn.data_phase_active = false;
                    conn.events_fired = true;
                    conn.gcs_active_at =
                        std::chrono::steady_clock::now() + std::chrono::milliseconds(150);
                    conn.mutual_fired = true;
                    conn.last_event_time = now;
                    data_phase_done.push_back({conn.ctx_id, cid});
                    LOG_INFO(
                        Lib_Net,
                        "KernelP2P: DATA exchange timer complete for conn_id={} "
                        "npid='{}' ({}ms elapsed) -- firing ESTABLISHED + MUTUAL",
                        cid, conn.npid,
                        std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count());
                }
            }

            // Echo fallback: if echo probes haven't gotten bilateral confirmation
            // after a delay, decide based on whether any echo responses arrived:
            // - resp > 0: peer is reachable but bilateral threshold not met -> fire ESTABLISHED
            // - resp == 0: peer is genuinely unreachable -> fire DEAD so the game
            //   can move on to the next candidate (prevents stuck matchmaking)
            //
            // With port-based relay (--relay), all peers connect through relay
            // server virtual ports -- echo probes succeed naturally via the relay.
            // This fallback only matters for STUN-only mode where direct P2P fails.
            // Echo fallback with retry: mesh peers (GUEST<->GUEST) may not be
            // online simultaneously. The first peer starts echo probes before
            // the second has finished JoinRoom. Instead of permanently dying
            // after one timeout, retry echo probes up to MAX_ECHO_RETRIES times.
            // This gives late-joining mesh peers time to come online (~35s total
            // with 3 retries at 3.5s each + the initial attempt).
            static constexpr auto STUN_FALLBACK_DELAY = std::chrono::milliseconds(3500);
            static constexpr int MAX_ECHO_RETRIES = 3;
            if (conn.echo_started && !conn.events_fired && !conn.echo_bilateral &&
                !conn.data_phase_active && conn.game_activated) {
                if (conn.echo_start_at == std::chrono::steady_clock::time_point{}) {
                    conn.echo_start_at = now;
                } else if ((now - conn.echo_start_at) >= STUN_FALLBACK_DELAY) {
                    if (conn.echo_responses_received > 0) {
                        // Got some responses -- peer reachable, fire ESTABLISHED
                        conn.events_fired = true;
                        conn.gcs_active_at = now + std::chrono::milliseconds(150);
                        conn.mutual_fired = true;
                        conn.last_event_time = now;
                        data_phase_done.push_back({conn.ctx_id, cid});
                        LOG_INFO(Lib_Net,
                                 "KernelP2P: STUN fallback -- partial echo for conn_id={} "
                                 "npid='{}' after {}ms -- firing ESTABLISHED "
                                 "(probes_sent={} resp={})",
                                 cid, conn.npid,
                                 std::chrono::duration_cast<std::chrono::milliseconds>(
                                     now - conn.echo_start_at)
                                     .count(),
                                 conn.echo_probes_sent, conn.echo_responses_received);
                    } else if (conn.echo_retries < MAX_ECHO_RETRIES) {
                        // Zero responses but retries remaining -- reset echo state
                        // and try again. Mesh peers may not be online yet (concurrent
                        // JoinRoom in flight). Retrying avoids permanently killing a
                        // connection that would work a few seconds later.
                        conn.echo_retries++;
                        conn.echo_probes_sent = 0;
                        conn.echo_responses_received = 0;
                        conn.echo_start_at = now;
                        conn.last_echo_sent = {};
                        LOG_WARNING(Lib_Net,
                                    "KernelP2P: peer UNREACHABLE -- conn_id={} npid='{}' "
                                    "after {}ms, 0 responses (retry {}/{}) -- "
                                    "resetting echo probes",
                                    cid, conn.npid,
                                    STUN_FALLBACK_DELAY.count(),
                                    conn.echo_retries, MAX_ECHO_RETRIES);
                    } else {
                        // Exhausted retries -- peer genuinely unreachable, fire DEAD
                        conn.state = ConnState::INACTIVE;
                        conn.echo_started = false;
                        conn.events_fired = false;
                        unreachable_dead.push_back({conn.ctx_id, cid});
                        LOG_WARNING(Lib_Net,
                                    "KernelP2P: peer UNREACHABLE -- conn_id={} npid='{}' "
                                    "after {}ms, 0 echo responses (probes_sent={}) -- "
                                    "firing DEAD to release matchmaking",
                                    cid, conn.npid,
                                    std::chrono::duration_cast<std::chrono::milliseconds>(
                                        now - conn.echo_start_at)
                                        .count(),
                                    conn.echo_probes_sent);
                    }
                }
            }

            // Only probe if ActivatePeer has set echo_started.
            if (!conn.echo_started)
                continue;

            // Determine probe interval
            auto interval = conn.events_fired ? ECHO_KEEPALIVE_INTERVAL : ECHO_PROBE_INTERVAL;
            if (now - conn.last_echo_sent < interval)
                continue;

            // Prefer STUN-resolved mapped address if available.
            u32 target_addr = conn.mapped_addr ? conn.mapped_addr : conn.addr;
            u16 target_port = conn.mapped_port ? conn.mapped_port : conn.port;
            targets.push_back(
                {cid, conn.ctx_id, target_addr, target_port, conn.npid, conn.events_fired});
        }
    }

    // Deferred diagnostic logging outside lock (avoids holding mutex_ during I/O).
    if (should_log) {
        LOG_INFO(Lib_Net, "KernelP2P: SendEchoProbes tick={} connections={} fd={}", diag_tick,
                 diag_conn_count, diag_fd);
        for (const auto& d : diag_snapshot) {
            LOG_INFO(Lib_Net,
                     "  conn_id={} npid='{}' addr={:#x}:{} state={} stun={} "
                     "echo_started={} game_activated={} events_fired={} "
                     "echo_bilateral={} probes_sent={} resp={} ms_since_echo={}",
                     d.cid, d.npid, d.addr, ntohs(d.port), d.state,
                     d.stun, d.echo_started, d.game_activated,
                     d.events_fired, d.echo_bilateral, d.probes_sent,
                     d.resp, d.ms_since_echo);
        }
    }

    // Fire DATA phase completion events outside lock (before probes).
    for (const auto& ev : data_phase_done) {
        FireEstablished(ev.ctx_id, ev.conn_id, 0);
        FireMutualActivated(ev.ctx_id, ev.conn_id, 50);
    }

    // Fire DEAD for unreachable peers so the game can move on.
    for (const auto& ev : unreachable_dead) {
        FireDead(ev.ctx_id, ev.conn_id, 50);
    }

    // Send probes outside lock
    auto* sc_echo = stun_client_.load();
    int fd = sc_echo ? sc_echo->GetSocketFd() : -1;
    if (fd < 0)
        return;

    auto now_ts = std::chrono::steady_clock::now().time_since_epoch().count();

    for (auto& t : targets) {
        // Build echo probe: [FF 83 FF FD] wire header + 90-byte payload
        u8 pkt[4 + ECHO_PROBE_SIZE] = {};
        pkt[0] = 0xFF;
        pkt[1] = 0x83;
        pkt[2] = 0xFF; // src vport high byte
        pkt[3] = 0xFD; // dst vport = 0xFFFD

        u8* payload = pkt + 4;
        payload[0] = 0xFF;
        payload[1] = 0xFD; // sub-protocol ID
        payload[2] = ECHO_TYPE_PROBE;
        payload[3] = 0x00;

        // Sequence counter at [4..7]
        static u32 echo_seq = 0;
        u32 seq = ++echo_seq;
        std::memcpy(payload + 4, &seq, 4);

        // Local identity at [8..23] -- use local npid padded to 16 bytes
        {
            std::lock_guard lock(mutex_);
            if (!local_npid_.empty()) {
                std::memcpy(payload + 8, local_npid_.c_str(),
                            std::min(local_npid_.size(), size_t(16)));
            }
        }
        // Remote identity at [36..51]
        std::memcpy(payload + 36, t.npid.c_str(), std::min(t.npid.size(), size_t(16)));

        // Timestamps at [64..79]
        std::memcpy(payload + 64, &now_ts, 8);

        // Echo probes ALWAYS go direct to the peer's address.
        // Relay routing is for game data only -- probes via relay get dropped.
        sockaddr_in dest{};
        dest.sin_family = AF_INET;
        dest.sin_addr.s_addr = t.addr;
        dest.sin_port = t.port;
        int sent = ::sendto(fd, reinterpret_cast<const char*>(pkt), sizeof(pkt), 0,
                            reinterpret_cast<sockaddr*>(&dest), sizeof(dest));
        LOG_INFO(Lib_Net,
                 "KernelP2P: echo probe SENT {} bytes to {:#x}:{} fd={} conn_id={} (result={})",
                 sizeof(pkt), ntohl(t.addr), ntohs(t.port), fd, t.conn_id, sent);

        // Update state
        {
            std::lock_guard lock(mutex_);
            auto it = connections_.find(t.conn_id);
            if (it != connections_.end()) {
                it->second.last_echo_sent = std::chrono::steady_clock::now();
                it->second.echo_probes_sent++;
            }
        }
    }
}

void KernelP2PSubsystem::ProcessEchoProbe(u32 from_addr, u16 from_port, const u8* data,
                                          size_t len) {
    LOG_INFO(Lib_Net,
             "KernelP2P: ProcessEchoProbe ENTRY from={:#x}:{} len={} "
             "data[0:4]={:02x}{:02x}{:02x}{:02x}",
             ntohl(from_addr), ntohs(from_port), len, len > 0 ? data[0] : 0, len > 1 ? data[1] : 0,
             len > 2 ? data[2] : 0, len > 3 ? data[3] : 0);

    if (len < ECHO_PROBE_SIZE) {
        LOG_WARNING(Lib_Net, "KernelP2P: ProcessEchoProbe -- len {} < ECHO_PROBE_SIZE {}, dropping",
                    len, ECHO_PROBE_SIZE);
        return;
    }

    // Check sub-protocol ID
    if (data[0] != 0xFF || data[1] != 0xFD) {
        LOG_WARNING(Lib_Net,
                    "KernelP2P: ProcessEchoProbe -- bad sub-protocol {:02x}{:02x}, dropping",
                    data[0], data[1]);
        return;
    }

    u8 type = data[2];
    auto* sc_ep = stun_client_.load();
    int fd = sc_ep ? sc_ep->GetSocketFd() : -1;

    if (type == ECHO_TYPE_PROBE && fd >= 0) {
        // Received probe request -> send response
        u8 resp[4 + ECHO_PROBE_SIZE] = {};
        resp[0] = 0xFF;
        resp[1] = 0x83;
        resp[2] = 0xFF;
        resp[3] = 0xFD;

        u8* payload = resp + 4;
        std::memcpy(payload, data, ECHO_PROBE_SIZE);
        payload[2] = ECHO_TYPE_RESPONSE; // change type to response

        // Add responder timestamp at [80..87]
        auto now_ts = std::chrono::steady_clock::now().time_since_epoch().count();
        std::memcpy(payload + 80, &now_ts, 8);

        sockaddr_in dest{};
        dest.sin_family = AF_INET;
        dest.sin_addr.s_addr = from_addr;
        dest.sin_port = from_port;

        // Echo responses ALWAYS go direct (to the address the probe came from).
        // Relay routing is for game data only -- responses via relay get dropped.
        ::sendto(fd, reinterpret_cast<const char*>(resp), sizeof(resp), 0,
                 reinterpret_cast<sockaddr*>(&dest), sizeof(dest));
    }

    LOG_INFO(Lib_Net, "KernelP2P: ProcessEchoProbe CALLED type={} from={:#x}:{} len={}", type,
             from_addr, ntohs(from_port), len);

    // Both PROBE (type=6) and RESPONSE (type=7) count as bilateral evidence.
    // Receiving a probe FROM the peer proves they can reach us AND we can reach them
    // (since they got our address somehow). With symmetric NAT, the peer's public IP
    // may differ from what we registered, so match by NpId from the payload.
    if (type == ECHO_TYPE_PROBE || type == ECHO_TYPE_RESPONSE) {
        // Compute RTT and check bilateral confirmation.
        // bandwidth = 9,375,000,000 / median_RTT_us (approximated from 94-byte probes).
        struct DeferredFire {
            s32 ctx_id;
            s32 conn_id;
        };
        std::vector<DeferredFire> to_fire;

        // Extract sender's timestamp from the response to compute RTT
        s64 sent_ts = 0;
        if (len >= 72) {
            std::memcpy(&sent_ts, data + 64, 8);
        }
        auto now_tp = std::chrono::steady_clock::now();
        auto now_ts = now_tp.time_since_epoch().count();
        s32 rtt_us = (sent_ts > 0) ? static_cast<s32>((now_ts - sent_ts) / 1000) : 1000;
        if (rtt_us <= 0)
            rtt_us = 1;

        {
            // Extract sender NpId from probe payload [8..23] for fallback matching.
            // NAT hairpin/relay can change the source IP, so addr match alone fails.
            std::string probe_npid;
            if (len >= 24) {
                probe_npid = std::string(reinterpret_cast<const char*>(data + 8), 16);
                auto pos = probe_npid.find('\0');
                if (pos != std::string::npos)
                    probe_npid.resize(pos);
            }

            std::lock_guard lock(mutex_);
            for (auto& [cid, conn] : connections_) {
                bool match_addr = (conn.addr == from_addr && conn.port == from_port);
                bool match_npid = (!probe_npid.empty() && conn.npid == probe_npid);
                LOG_INFO(Lib_Net,
                         "KernelP2P: echo match check cid={} conn.addr={:#x} "
                         "conn.port={} from={:#x}:{} echo_started={} "
                         "match_addr={} match_npid={} probe_npid='{}'",
                         cid, conn.addr, ntohs(conn.port), from_addr, ntohs(from_port),
                         conn.echo_started, match_addr, match_npid, probe_npid);
                if ((match_addr || match_npid) && conn.echo_started) {
                    conn.echo_responses_received++;
                    conn.last_echo_recv = now_tp;

                    // Update RTT and bandwidth from echo probe timing.
                    conn.rtt_us = rtt_us;
                    if (rtt_us > 0) {
                        conn.bandwidth_bps = static_cast<s32>(
                            std::min(static_cast<s64>(9375000000LL / rtt_us),
                                     static_cast<s64>(100000000))); // cap at 100MB/s
                    }

                    if (conn.echo_responses_received >= ECHO_PROBES_FOR_ESTABLISHED) {
                        if (!conn.echo_bilateral) {
                            // First time reaching bilateral threshold
                            conn.echo_bilateral = true;
                            conn.state = ConnState::ACTIVE;

                            // Delay ESTABLISHED for GUEST late-joiners so the game
                            // has time to create SocketState entries. HOST always fires
                            // immediately (needs to send TYPE=1 sessionReady promptly).
                            // STUN: always delay on GUEST side.
                            // LAN: delay only when there are already established peers.
                            bool should_delay = false;
                            if (DATA_EXCHANGE_DURATION.count() > 0 && my_member_id_ != 1) {
                                if (conn.stun_state != StunState::NONE) {
                                    // STUN connections: always delay for GUEST
                                    should_delay = true;
                                } else {
                                    // LAN: delay only for late-joiners (existing peers)
                                    for (const auto& [other_cid, other] : connections_) {
                                        if (other_cid != cid && other.events_fired &&
                                            other.state == ConnState::ACTIVE) {
                                            should_delay = true;
                                            break;
                                        }
                                    }
                                }
                            }

                            if (should_delay) {
                                // GUEST/INVADER late-joiner: delay ESTABLISHED
                                conn.data_phase_active = true;
                                conn.data_phase_start = now_tp;
                                LOG_INFO(Lib_Net,
                                         "KernelP2P: echo bilateral confirmed for conn_id={} "
                                         "npid='{}' after {} probes/{} responses rtt={}us "
                                         "bw={}B/s -- entering DATA exchange phase ({}ms, "
                                         "GUEST/INVADER late-joiner, my_member={})",
                                         cid, conn.npid, conn.echo_probes_sent,
                                         conn.echo_responses_received, rtt_us, conn.bandwidth_bps,
                                         DATA_EXCHANGE_DURATION.count(), my_member_id_);
                            } else {
                                // HOST, first connection, or DATA phase disabled -- fire
                                // immediately
                                conn.events_fired = true;
                                conn.gcs_active_at = std::chrono::steady_clock::now() +
                                                     std::chrono::milliseconds(150);
                                conn.mutual_fired = true;
                                conn.last_event_time = now_tp;
                                to_fire.push_back({conn.ctx_id, cid});
                                LOG_INFO(Lib_Net,
                                         "KernelP2P: echo bilateral confirmed for conn_id={} "
                                         "npid='{}' after {} probes/{} responses rtt={}us "
                                         "bw={}B/s -- ESTABLISHED immediate (my_member={}, "
                                         "stun={} data_ms={})",
                                         cid, conn.npid, conn.echo_probes_sent,
                                         conn.echo_responses_received, rtt_us, conn.bandwidth_bps,
                                         my_member_id_, static_cast<int>(conn.stun_state),
                                         DATA_EXCHANGE_DURATION.count());
                            }
                        } else if (conn.data_phase_active) {
                            // During DATA exchange phase -- check completion timer.
                            auto elapsed = now_tp - conn.data_phase_start;
                            if (elapsed >= DATA_EXCHANGE_DURATION) {
                                conn.data_phase_active = false;
                                conn.events_fired = true;
                                conn.gcs_active_at = std::chrono::steady_clock::now() +
                                                     std::chrono::milliseconds(150);
                                conn.mutual_fired = true;
                                conn.last_event_time = now_tp;
                                to_fire.push_back({conn.ctx_id, cid});
                                LOG_INFO(
                                    Lib_Net,
                                    "KernelP2P: DATA exchange complete for conn_id={} "
                                    "npid='{}' ({}ms elapsed, {} total probes) -- "
                                    "firing ESTABLISHED + MUTUAL",
                                    cid, conn.npid,
                                    std::chrono::duration_cast<std::chrono::milliseconds>(elapsed)
                                        .count(),
                                    conn.echo_probes_sent);
                            }
                        }
                    }
                }
            }
        }

        for (const auto& ev : to_fire) {
            FireEstablished(ev.ctx_id, ev.conn_id, 0);
            FireMutualActivated(ev.ctx_id, ev.conn_id, 50);
        }
    }
}

bool KernelP2PSubsystem::TranslateRelaySourceByNpid(const std::string& sender_npid,
                                                    u32* peer_addr_out, u16* peer_port_out) {
    // Receive-side only: translates FD-tagged relay packets back to the real
    // peer address. The STUN server tags forwarded packets with the sender's
    // NpId in a [0xFE][len][npid] header. The client never sends these tags --
    // relay routing is server-transparent.
    if (sender_npid.empty())
        return false;

    std::lock_guard lock(mutex_);

    // Strategy 1: Look up active connection by NpId
    auto conn_it = npid_to_conn_.find(sender_npid);
    if (conn_it != npid_to_conn_.end()) {
        auto ci = connections_.find(conn_it->second);
        if (ci != connections_.end() && ci->second.state == ConnState::ACTIVE) {
            auto& conn = ci->second;
            u32 actual = conn.mapped_addr ? conn.mapped_addr : conn.addr;
            u16 actual_port = conn.mapped_port ? conn.mapped_port : conn.port;
            if (actual != 0) {
                if (peer_addr_out)
                    *peer_addr_out = actual;
                if (peer_port_out)
                    *peer_port_out = actual_port;
                return true;
            }
        }
    }

    // Strategy 2: Fall back to peers_ map (connection may be in transition)
    for (const auto& [mid, pi] : peers_) {
        if (pi.npid == sender_npid && pi.addr != 0) {
            if (peer_addr_out)
                *peer_addr_out = pi.addr;
            if (peer_port_out)
                *peer_port_out = pi.port;
            return true;
        }
    }

    return false;
}

void KernelP2PSubsystem::ProcessStunOffer(s32 ctx_id, s32 conn_id, u32 peer_addr, u16 peer_port,
                                          const std::string& peer_npid) {
    // Called synchronously from the signaling thread.
    auto* sc_offer = stun_client_.load();
    if (!sc_offer) {
        {
            std::lock_guard lock(mutex_);
            auto it = connections_.find(conn_id);
            if (it != connections_.end()) {
                it->second.stun_state = StunState::NONE;
                // No STUN client -- let echo probes handle ESTABLISHED
                if (it->second.game_activated && !it->second.echo_started) {
                    it->second.echo_started = true;
                    it->second.last_echo_sent = {};
                }
            }
        }
        LOG_WARNING(Lib_Net,
                    "KernelP2P: ProcessStunOffer -- no StunClient, echo probes will confirm");
        return;
    }

    std::vector<u8> username_data;
    {
        std::lock_guard lock(mutex_);
        if (!local_npid_.empty()) {
            username_data.assign(local_npid_.begin(), local_npid_.end());
            username_data.resize(16, 0);
        }
    }
    std::vector<u8> signaling_data = {0x03};

    char peer_buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &peer_addr, peer_buf, sizeof(peer_buf));
    LOG_INFO(Lib_Net, "KernelP2P: processing STUN OFFER to {}:{} for conn_id={} npid='{}'",
             peer_buf, ntohs(peer_port), conn_id, peer_npid);

    auto result = sc_offer->SendOffer(peer_addr, peer_port, username_data, signaling_data);

    if (result.success) {
        char mapped_buf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &result.mapped_addr, mapped_buf, sizeof(mapped_buf));
        LOG_INFO(Lib_Net,
                 "KernelP2P: STUN OFFER success -- our mapped={}:{}, "
                 "waiting for ACCEPT (2s timeout)",
                 mapped_buf, ntohs(result.mapped_port));

        // Short timeout -- the signaling thread's main loop will catch the
        // ACCEPT as an incoming relay if we miss it here.
        auto accept = sc_offer->WaitForRelay(500);

        // Update connection state under lock, then send NAT punch outside lock
        // (sendto + sleep_for while holding mutex_ starves other threads for ~100ms).
        u32 punch_addr = 0;
        u16 punch_port = 0;
        {
            std::lock_guard lock(mutex_);
            auto it = connections_.find(conn_id);
            if (it != connections_.end()) {
                if (accept.success && accept.mapped_addr != 0) {
                    it->second.mapped_addr = accept.mapped_addr;
                    it->second.mapped_port = accept.mapped_port;
                    // Update primary address so ALL code paths (echo probes,
                    // game data, GetActivePeerAddr) use the STUN-resolved addr.
                    it->second.addr = accept.mapped_addr;
                    it->second.port = accept.mapped_port;
                    it->second.stun_state = StunState::COMPLETE;
                    if (it->second.game_activated && !it->second.echo_started) {
                        it->second.echo_started = true;
                        it->second.last_echo_sent = {};
                    }
                    punch_addr = accept.mapped_addr;
                    punch_port = accept.mapped_port;

                    char accept_buf[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &accept.mapped_addr, accept_buf, sizeof(accept_buf));
                    LOG_INFO(Lib_Net,
                             "KernelP2P: STUN COMPLETE for conn_id={} -- "
                             "peer verified mapped={}:{} (echo probes will confirm)",
                             conn_id, accept_buf, ntohs(accept.mapped_port));
                } else {
                    it->second.stun_state = StunState::FAILED;
                    if (it->second.game_activated && !it->second.echo_started) {
                        it->second.echo_started = true;
                        it->second.last_echo_sent = {};
                    }
                    LOG_WARNING(Lib_Net,
                                "KernelP2P: STUN FAILED for conn_id={} -- "
                                "using server-reported addr, echo probes will confirm",
                                conn_id);
                }
            }
        }

        // Send NAT punch packets outside lock
        if (punch_addr != 0) {
            struct sockaddr_in peer_sa{};
            peer_sa.sin_family = AF_INET;
            peer_sa.sin_addr.s_addr = punch_addr;
            peer_sa.sin_port = punch_port;
            u8 punch[] = {0xFF, 0xC3, 0x00, 0x00};
            int fd = sc_offer->GetSocketFd();
            for (int i = 0; i < 2; i++) {
                ::sendto(fd, reinterpret_cast<const char*>(punch), sizeof(punch), 0,
                         reinterpret_cast<struct sockaddr*>(&peer_sa), sizeof(peer_sa));
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
            }
        }
    } else {
        LOG_WARNING(Lib_Net,
                    "KernelP2P: STUN OFFER failed for conn_id={} -- "
                    "falling back to direct connection, echo probes will confirm",
                    conn_id);
        {
            std::lock_guard lock(mutex_);
            auto it = connections_.find(conn_id);
            if (it != connections_.end()) {
                it->second.stun_state = StunState::FAILED;
                // Don't set events_fired -- let echo probes/STUN fallback handle it
                if (it->second.game_activated && !it->second.echo_started) {
                    it->second.echo_started = true;
                    it->second.last_echo_sent = {};
                }
            }
        }
    }

    // ESTABLISHED is NOT fired from here. Echo probes run at 500ms after STUN
    // completes and fire ESTABLISHED when bilateral confirms or fallback expires.
    LOG_INFO(Lib_Net,
             "KernelP2P: ProcessStunOffer conn_id={} -- STUN done, "
             "echo probes will drive ESTABLISHED",
             conn_id);
}

// === Bilateral P2P Confirmation ===

void KernelP2PSubsystem::OnPeerPacketReceived(u32 peer_addr) {
    // Called from P2P socket Drain() when a packet arrives from a peer.
    // On LAN (no STUN), receiving a packet proves bilateral connectivity,
    // triggering MUTUAL_ACTIVATED.
    struct DeferredMutual {
        s32 ctx_id;
        s32 conn_id;
    };
    std::vector<DeferredMutual> to_fire;

    {
        std::lock_guard lock(mutex_);
        for (auto& [cid, conn] : connections_) {
            if (conn.state == ConnState::ACTIVE && conn.addr == peer_addr && conn.events_fired &&
                !conn.mutual_fired) {
                conn.mutual_fired = true;
                to_fire.push_back({conn.ctx_id, conn.conn_id});
            }
        }
    }

    for (const auto& ev : to_fire) {
        // Delay MUTUAL by 3s so SocketState state 9 (sendHandshakeType2) blocks
        // long enough for ConnObj's slow path to read SigDataManager data.
        LOG_INFO(Lib_Net,
                 "KernelP2P: OnPeerPacketReceived -- bilateral P2P confirmed, "
                 "firing MUTUAL_ACTIVATED for conn_id={} (3000ms, emulates STUN timing)",
                 ev.conn_id);
        FireMutualActivated(ev.ctx_id, ev.conn_id, 3000);
    }
}

// === Kernel P2P Vport Translation ===
//
// The kernel strips the 4-byte wire header and delivers the full remaining
// payload to the socket. Each vport is independently demultiplexed.
//
// For cross-platform (console HOST -> emulator GUEST):
//   Console sends on vport 30, emulator game only binds vport 40.
//   We translate: inbound vport 30 -> deliver to vport 40 with full payload intact.
//   Outbound: game sends on vport 40 -> rewrite wire header to vport 30 for console peers.

bool KernelP2PSubsystem::ShouldForwardUnboundPacket(u16 vport_nbo, const sockaddr_in& from) {
    // If game has bound this vport, normal path -- no forwarding needed
    {
        std::lock_guard lock(mutex_);
        if (bound_vports_.count(vport_nbo)) {
            static int skip_count = 0;
            if (++skip_count <= 3) {
                LOG_INFO(Lib_Net,
                         "KernelP2P: ShouldForwardUnboundPacket vport {} -- "
                         "ALREADY BOUND in kernel (bound_vports size={})",
                         ntohs(vport_nbo), bound_vports_.size());
            }
            return false;
        }
    }

    u32 peer_ip = from.sin_addr.s_addr;

    char ip_buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &from.sin_addr, ip_buf, sizeof(ip_buf));

    // Grace period for peer classification.
    // Emulator peers send on both vport 30 and vport 40. We wait briefly
    // so they get classified via vport 40 traffic. Console peers (vport 30
    // only) are classified after the grace period expires.
    static constexpr auto kPeerClassifyGraceMs = std::chrono::milliseconds(100);

    std::lock_guard lock(mutex_);
    auto& pc = peer_classifications_[peer_ip];
    auto now = std::chrono::steady_clock::now();

    if (pc.first_seen_at == std::chrono::steady_clock::time_point{}) {
        pc.first_seen_at = now;
        LOG_INFO(Lib_Net,
                 "KernelP2P: first vport {} packet from {}:{} -- "
                 "starting {}ms grace period for peer classification",
                 ntohs(vport_nbo), ip_buf, ntohs(from.sin_port), kPeerClassifyGraceMs.count());
        return false;
    }

    if (!pc.classified) {
        auto elapsed = now - pc.first_seen_at;
        if (elapsed < kPeerClassifyGraceMs) {
            return false;
        }
        pc.classified = true;
        LOG_INFO(Lib_Net,
                 "KernelP2P: peer {} classified as console (vport 30 only, "
                 "no bound vport traffic after {}ms grace) -- "
                 "enabling vport translation (30->40 in, 40->30 out)",
                 ip_buf, std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count());
    }

    return true; // Forward this packet to a bound vport
}

void KernelP2PSubsystem::ClearPS4PeerClassification(u32 peer_addr) {
    std::lock_guard lock(mutex_);
    peer_classifications_.erase(peer_addr);
}

bool KernelP2PSubsystem::IsPS4Peer(u32 peer_addr) const {
    std::lock_guard lock(mutex_);
    auto it = peer_classifications_.find(peer_addr);
    return it != peer_classifications_.end() && it->second.classified;
}

void KernelP2PSubsystem::OnVportBound(u16 vport_nbo) {
    std::lock_guard lock(mutex_);
    bound_vports_.insert(vport_nbo);
    LOG_INFO(Lib_Net, "KernelP2P: vport {} claimed by game socket (kernel handler yields)",
             ntohs(vport_nbo));
}

} // namespace Libraries::Net
