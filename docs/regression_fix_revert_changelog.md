# regression-fix-revert Branch Changelog

Base: `d4bb9b8539853e0c00d6df0668cd1caefeb2a2b4` ("tweaked signaling for multipeer")

This branch applies bug fixes from the refactor commits (`0dfe6481..1fb98e38`) while
reverting behavioral changes that caused multi-player regressions. The categorization
below was determined through analysis of 6 test sessions (bad_online through bad_online6)
with 2-4 players over WAN.

---

## Bug Fixes (kept)

| # | File | Change | Rationale |
|---|---|---|---|
| 1 | p2p_sockets.cpp | VP30 echo: added `buf[3] == 0xFE` alongside `0xFD` | VP30 echo probes were silently dropped, VP30 stayed in HELLO retransmission |
| 2 | np_signaling.cpp | `sceNpSignalingDeactivateConnection` resolves kernel conn_id via npid lookup | Was passing NpSignaling conn_id to kernel `DeactivatePeer`, deactivating wrong peer |
| 3 | np_signaling.cpp | KernelEventBridge DEAD handler translates kernel conn_id → NpSignaling conn_id | Game received DEAD with wrong conn_id, deactivated wrong peer (e.g., ancat's DEAD hit Scorched-Knight) |
| 4 | np_signaling.cpp | KernelEventBridge DEAD handler calls `SetConnectionInactive(npid)` | Without this, sig connection stays stuck at intermediate state (e.g., ECHO_PROBE) after 30s timeout |
| 5 | np_signaling.cpp | KernelEventBridge ESTABLISHED handler skips re-fire when sig conn already ACTIVE | MUTUAL_ACTIVATED following ESTABLISHED caused cascading duplicate callbacks (reset ACTIVE→PENDING→ACTIVE) |
| 6 | np_signaling.cpp | `ResolvePendingPeer` call added after `ActivatePeer` in `sceNpSignalingActivateConnection` | Breaks chicken-and-egg where game calls ActivateConnection before JoinRoom provides mesh peer addresses |
| 7 | np_signaling.cpp | 30s watchdog in `TickSignalingConnectionLocked` for stuck intermediate states | Prevents permanent stalls from missed events — forces ACTIVE (if kernel confirms) or resets to IDLE |
| 8 | np_signaling.cpp | Peer info timeout hardcoded to 30s (was env var, default 15s) | Matches PS4 firmware value (0x1c9c380 us) |
| 9 | kernel_p2p.cpp | `IsEchoBilateral(npid)` accessor added | Pure read accessor, no behavior change on its own |
| 10 | kernel_p2p.cpp | `SetConnState` helper tracking `prev_state` + `state_changed_at` | Enables PENDING timeout (#12), firmware pattern (sub_4089f0) |
| 11 | kernel_p2p.cpp | `ResolvePendingPeer` function added | Supports #6 — resolves PENDING conn addr from NpSignaling resolver |
| 12 | kernel_p2p.cpp | PENDING addr=0 zombie timeout (30s → DEAD) | Cleans up connections where peer never joined room (addr never resolved) |
| 13 | kernel_p2p.cpp | STUN relay match: removed `\|\| !events_fired` fallback | Old fallback caused infinite OFFER/ACCEPT loop when `game_activated` deferred ESTABLISHED |
| 14 | kernel_p2p.cpp | Speculative ACCEPT removed (no-match relay case) | Was causing ping-pong flood between already-connected peers |
| 15 | kernel_p2p.cpp | `HandleActivatePacket` matches addr+port first, addr-only fallback | Fixes LAN multi-peer disambiguation (multiple peers share same IP) |
| 16 | kernel_p2p.cpp | `WaitForRelay(500, peer_npid)` filtered by expected username | Prevents cross-peer ACCEPT confusion in multi-player sessions |
| 17 | kernel_p2p.cpp | Duplicate `to_accept` push removed in relay loop | Was sending 2x ACCEPT + 4 NAT punch packets per relay |
| 18 | kernel_p2p.cpp | STUN ACCEPT handler: `!events_fired` idempotent guard | Prevents double-fire of ESTABLISHED from same ACCEPT |
| 19 | kernel_p2p.cpp | STUN ACCEPT handler: sets `echo_bilateral=true` on STUN ACCEPT | STUN completion confirms connectivity; don't require separate echo bilateral for WAN |
| 20 | kernel_p2p.cpp | ActivatePeer reconnection: mesh peer STUN OFFER (`i_send_offer` role) | Old code only queued STUN OFFER for HOST↔GUEST, mesh peers got no STUN on reconnection |
| 21 | kernel_p2p.cpp | LAN detection: skip STUN when both sides on private subnet | Direct echo probes confirm LAN connectivity without relay involvement |
| 22 | kernel_p2p.cpp | `offer_queue_mutex_` consolidated into `mutex_` | Eliminates potential lock ordering issue between two mutexes |
| 23 | np_matching2.cpp | `next_signaling_conn_id` monotonic counter for 0x5102 events | Prevents game from treating re-join DEAD events as duplicates of previous session |
| 24 | np_matching2.cpp | DrainReadyEvents sort: ROOM_EVENT fires before SIGNALING | Game creates ConnectionObjects on ROOM_EVENT; signaling callbacks reference them |
| 25 | np_matching2.cpp | `sceNpMatching2Initialize` full state reset on re-init | Without this, stale state from previous session corrupts next session |
| 26 | np_matching2.cpp | Same-NAT detection via STUN-mapped addr comparison | More accurate than RFC1918 heuristic — handles CGNAT and tunneled setups |
| 27 | np_matching2.cpp | Mesh peer registration from join response (`HandleHostPeerJoinedEvent` for each member) | Critical for 3+ player — GUEST needs peer addresses before native ActivateConnection |
| 28 | np_matching2.cpp | Stale member_id cleanup in `HandleHostPeerJoinedEvent` on rejoin | Prevents stale peers map entries when same player rejoins with new member_id |
| 29 | np_matching2.cpp | `HandleHostPeerLeftEvent`: `kernel.RemovePeer(member_id)` instead of `kernel.DeactivatePeer(conn_id)` | `DeactivatePeer` left stale addr in `peers_` map; reconnecting peer would use old NAT address |
| 30 | np_matching2.cpp | Guest poll departure: same `RemovePeer` fix | Same stale address issue on guest path |
| 31 | np_matching2.cpp | `ResolvePeerSignalingAddr` local cache fast-path (check `g_state.peers` before HTTP) | Eliminates blocking HTTP call on game thread during signaling setup |
| 32 | np_matching2.cpp | Guest poll thread gated on WebSocket active | Prevents redundant HTTP polling when WebSocket handles lifecycle events |
| 33 | np_matching2.cpp | LeaveRoom/KickoutRoomMember HTTP as fire-and-forget detached thread | Prevents blocking game thread on HTTP call |
| 34 | np_matching2.cpp | `GetWorldInfoListThreadFunc`: direct callback + correct struct layout | Fixes lobby data (RE-accurate OrbisNpMatching2World) and ensures callback fires on correct thread |
| 35 | np_matching2.cpp | JoinLobby delay 200ms → 50ms | Minor timing improvement |
| 36 | np_matching2_types.h | OrbisNpMatching2World struct: RE-accurate field layout from handleEvent_type2 (0x10be5e0) | Correct offsets for lobbyCount, maxLobbyMembers, curRooms, etc. |
| 37 | stun_client.cpp/h | `WaitForRelay` username filter parameter + `StunBindingResult.username` field | Supports #16 — enables per-peer relay filtering |
| 38 | signals.cpp | Windows minidump on unhandled exceptions | Cherry-picked feature (feature/windows-minidump) |
| 39 | module.cpp | ModuleLoadBase `0x800000000` → `0x400000` | Separate fix |

## Regression Changes (reverted to old behavior)

| # | File | Change | Old behavior | New (broken) behavior | Why it regressed |
|---|---|---|---|---|---|
| A | np_signaling.cpp | ActivateConnection: conditional vs unconditional reset | `if (state != ACTIVE)` guard — ACTIVE connections are no-op | Always reset to PENDING regardless of state | **Root cause of 3rd player failure.** Game calls ActivateConnection 2x per peer during multi-player ConnObj setup. Second call destroyed the working ACTIVE connection; subsequent resolve failed because LeaveRoom had already cleared peer data. |
| B | np_signaling.cpp | `QueryKernelEchoState` — what counts as "active" | `kern_status == 2` (ConnState::ACTIVE = addr/port known) | `kernel.IsEchoBilateral(npid)` (requires 3+ echo responses) | NpSignaling state machine stalled at ECHO_PROBE waiting for bilateral that takes 30+ seconds on WAN. Combined with C, created deadlock where game waited for GCS=ACTIVE while HLE waited for echo bilateral. |
| C | kernel_p2p.cpp | `GetConnectionStatus` — GCS gate | Returns ACTIVE immediately when `ConnState::ACTIVE` | Returns PENDING until `events_fired=true` | Game's SocketState pipeline polls GCS in a loop. Returning PENDING blocked the pipeline from calling ActivateConnection, which blocked `game_activated`, which blocked echo bilateral from firing ESTABLISHED. |
| D | kernel_p2p.cpp | Echo probe interval | 500ms | 200ms | Firmware-accurate but not reverted — kept at 200ms. Noted here as a difference from old code. |
| E | kernel_p2p.cpp | Keepalive interval | 10s | 60s (was changed, then reverted to 10s) | Consumer NATs have 30-40s UDP idle timeouts; 60s gap killed NAT mappings silently. **Reverted to 10s.** |
| F | kernel_p2p.cpp | MUTUAL_ACTIVATED delay | 3000ms | 50ms (was changed, then reverted to 3000ms) | SocketState state 9 sends handshake type 2 and needs MUTUAL_ACTIVATED to advance. 50ms was too fast for the handshake to complete. **Reverted to 3000ms.** |

## Changes Still Different From Old Code (not reverted, monitoring)

| # | File | Change | Old | New | Risk |
|---|---|---|---|---|---|
| G | kernel_p2p.cpp | DATA exchange phase | 0-2000ms configurable delay for GUEST late-joiners | Removed entirely | Medium — old delays gave game time to create SocketState entries. The STUN ACCEPT immediate-ESTABLISHED (#19) partially compensates. |
| H | kernel_p2p.cpp | Echo timeout strategy | 3.5s × 3 retries (~14s total) | Hard 30s, no retries | Low — 30s is firmware-accurate. Old retries gave fresh-start chances but also caused faster false-DEAD. |
| I | kernel_p2p.cpp | `gcs_active_at` 150ms delay | GCS delayed ACTIVE by 150ms after events fired | Removed (GCS returns ACTIVE immediately) | Low — with GCS gate reverted (#C), ACTIVE fires immediately like old code. The 150ms micro-delay is gone but shouldn't matter. |
| J | kernel_p2p.cpp | Echo probe interval | 500ms | 200ms | Low — more probes means faster bilateral on good connections. Firmware-accurate. |
| K | kernel_p2p.cpp | PeerConnection struct | Had `gcs_active_at`, `data_phase_active`, `data_phase_start`, `echo_retries` | Removed; added `prev_state`, `state_changed_at` | N/A — structural change supporting new features, no direct behavioral impact. |
