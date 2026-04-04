// SPDX-FileCopyrightText: Copyright 2025 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include "common/types.h"
#include "core/libraries/np/np_matching2_types.h"

namespace Core::Loader {
class SymbolsResolver;
}

namespace Libraries::Np::NpMatching2 {

// --- Core lifecycle ---
s32 PS4_SYSV_ABI sceNpMatching2Initialize();
s32 PS4_SYSV_ABI sceNpMatching2Terminate();
s32 PS4_SYSV_ABI sceNpMatching2SetExtraInitParam(void* param);

// --- Context management ---
s32 PS4_SYSV_ABI sceNpMatching2CreateContext(const void* reqParam, u16* ctxId);
s32 PS4_SYSV_ABI sceNpMatching2CreateContextInternal(const void* reqParam, u16* ctxId);
s32 PS4_SYSV_ABI sceNpMatching2CreateContextA(const void* reqParam, u16* ctxId);
s32 PS4_SYSV_ABI sceNpMatching2ContextStart(u16 ctxId, void* optParam);
s32 PS4_SYSV_ABI sceNpMatching2ContextStop(u16 ctxId);
s32 PS4_SYSV_ABI sceNpMatching2DestroyContext(u16 ctxId);
s32 PS4_SYSV_ABI sceNpMatching2AbortContextStart(u16 ctxId);

// --- Callback registration ---
s32 PS4_SYSV_ABI sceNpMatching2SetDefaultRequestOptParam(u16 ctxId, void* optParam);
s32 PS4_SYSV_ABI sceNpMatching2RegisterContextCallback(void* cbFunc, void* cbFuncArg);
s32 PS4_SYSV_ABI sceNpMatching2RegisterRoomEventCallback(u16 ctxId, void* cbFunc, void* cbFuncArg);
s32 PS4_SYSV_ABI sceNpMatching2RegisterSignalingCallback(u16 ctxId, void* cbFunc, void* cbFuncArg);
s32 PS4_SYSV_ABI sceNpMatching2RegisterLobbyEventCallback(u16 ctxId, void* cbFunc, void* cbFuncArg);
s32 PS4_SYSV_ABI sceNpMatching2RegisterLobbyMessageCallback(u16 ctxId, void* cbFunc,
                                                            void* cbFuncArg);
s32 PS4_SYSV_ABI sceNpMatching2RegisterRoomMessageCallback(u16 ctxId, void* cbFunc,
                                                           void* cbFuncArg);
s32 PS4_SYSV_ABI sceNpMatching2RegisterManualUdpSignalingCallback(u16 ctxId, void* cbFunc,
                                                                  void* cbFuncArg);

// --- Room operations ---
s32 PS4_SYSV_ABI sceNpMatching2CreateJoinRoom(u16 ctxId, void* reqParam, void* optParam,
                                              s32* reqId);
s32 PS4_SYSV_ABI sceNpMatching2CreateJoinRoomA(u16 ctxId, void* reqParam, void* optParam,
                                               s32* reqId);
s32 PS4_SYSV_ABI sceNpMatching2JoinRoom(u16 ctxId, void* reqParam, void* optParam, s32* reqId);
s32 PS4_SYSV_ABI sceNpMatching2JoinRoomA(u16 ctxId, void* reqParam, void* optParam, s32* reqId);
s32 PS4_SYSV_ABI sceNpMatching2LeaveRoom(u16 ctxId, void* reqParam, void* optParam, s32* reqId);
s32 PS4_SYSV_ABI sceNpMatching2SearchRoom(u16 ctxId, void* reqParam, void* optParam, s32* reqId);
s32 PS4_SYSV_ABI sceNpMatching2KickoutRoomMember(u16 ctxId, void* reqParam, void* optParam,
                                                 s32* reqId);
s32 PS4_SYSV_ABI sceNpMatching2GrantRoomOwner(u16 ctxId, void* reqParam, void* optParam,
                                              s32* reqId);
s32 PS4_SYSV_ABI sceNpMatching2SendRoomMessage(u16 ctxId, void* reqParam, void* optParam,
                                               s32* reqId);
s32 PS4_SYSV_ABI sceNpMatching2SendRoomChatMessage(u16 ctxId, void* reqParam, void* optParam,
                                                   s32* reqId);

// --- Room data ---
s32 PS4_SYSV_ABI sceNpMatching2GetRoomDataInternal(u16 ctxId, void* reqParam, void* optParam,
                                                   s32* reqId);
s32 PS4_SYSV_ABI sceNpMatching2SetRoomDataInternal(u16 ctxId, void* reqParam, void* optParam,
                                                   s32* reqId);
s32 PS4_SYSV_ABI sceNpMatching2SetRoomDataInternalExt();
s32 PS4_SYSV_ABI sceNpMatching2SetRoomDataExternal(u16 ctxId, void* reqParam, void* optParam,
                                                   s32* reqId);
s32 PS4_SYSV_ABI sceNpMatching2GetRoomDataExternalList();
s32 PS4_SYSV_ABI sceNpMatching2GetRoomMemberDataInternal(u16 ctxId, void* reqParam, void* optParam,
                                                         s32* reqId);
s32 PS4_SYSV_ABI sceNpMatching2SetRoomMemberDataInternal(u16 ctxId, void* reqParam, void* optParam,
                                                         s32* reqId);
s32 PS4_SYSV_ABI sceNpMatching2GetRoomMemberDataExternalList(u16 ctxId, void* reqParam,
                                                             void* optParam, s32* reqId);
s32 PS4_SYSV_ABI sceNpMatching2GetRoomMemberIdListLocal();
s32 PS4_SYSV_ABI sceNpMatching2GetRoomJoinedSlotMaskLocal();
s32 PS4_SYSV_ABI sceNpMatching2GetRoomPasswordLocal();

// --- Lobby operations ---
s32 PS4_SYSV_ABI sceNpMatching2JoinLobby(u16 ctxId, void* reqParam, void* optParam, s32* reqId);
s32 PS4_SYSV_ABI sceNpMatching2LeaveLobby(u16 ctxId, void* reqParam, void* optParam, s32* reqId);
s32 PS4_SYSV_ABI sceNpMatching2GetLobbyInfoList(u16 ctxId, void* reqParam, void* optParam,
                                                s32* reqId);
s32 PS4_SYSV_ABI sceNpMatching2GetLobbyMemberDataInternal(u16 ctxId, void* reqParam, void* optParam,
                                                          s32* reqId);
s32 PS4_SYSV_ABI sceNpMatching2GetLobbyMemberDataInternalList(u16 ctxId, void* reqParam,
                                                              void* optParam, s32* reqId);
s32 PS4_SYSV_ABI sceNpMatching2SetLobbyMemberDataInternal(u16 ctxId, void* reqParam, void* optParam,
                                                          s32* reqId);
s32 PS4_SYSV_ABI sceNpMatching2SendLobbyChatMessage(u16 ctxId, void* reqParam, void* optParam,
                                                    s32* reqId);

// --- Server/world info ---
s32 PS4_SYSV_ABI sceNpMatching2GetServerId(u16 ctxId, u16* serverId);
s32 PS4_SYSV_ABI sceNpMatching2GetWorldIdArrayForAllServers();
s32 PS4_SYSV_ABI sceNpMatching2GetWorldInfoList(u16 ctxId, void* reqParam, void* optParam,
                                                s32* reqId);

// --- User info ---
s32 PS4_SYSV_ABI sceNpMatching2GetUserInfoList();
s32 PS4_SYSV_ABI sceNpMatching2GetUserInfoListA();
s32 PS4_SYSV_ABI sceNpMatching2SetUserInfo();

// --- Signaling ---
s32 PS4_SYSV_ABI sceNpMatching2SignalingGetConnectionStatus(u16 ctxId, u64 roomId, u16 memberId,
                                                            s32* connStatus, void* peerAddr,
                                                            u16* peerPort);
s32 PS4_SYSV_ABI sceNpMatching2SignalingGetConnectionInfo(u16 ctxId, u64 roomId, u16 memberId,
                                                          s32 infoType, void* outInfo,
                                                          void* outInfoB);
s32 PS4_SYSV_ABI sceNpMatching2SignalingGetConnectionInfoA();
s32 PS4_SYSV_ABI sceNpMatching2SignalingEstablishConnection(u16 ctxId, u64 roomId, u16 memberId,
                                                            void* optParam, s32* reqId);
s32 PS4_SYSV_ABI sceNpMatching2SignalingAbortConnection();
s32 PS4_SYSV_ABI sceNpMatching2SignalingGetLocalNetInfo();
s32 PS4_SYSV_ABI sceNpMatching2SignalingGetPeerNetInfo();
s32 PS4_SYSV_ABI sceNpMatching2SignalingGetPeerNetInfoResult();
s32 PS4_SYSV_ABI sceNpMatching2SignalingCancelPeerNetInfo();
s32 PS4_SYSV_ABI sceNpMatching2SignalingSetPort();
s32 PS4_SYSV_ABI sceNpMatching2SignalingGetPort();
s32 PS4_SYSV_ABI sceNpMatching2SignalingGetPingInfo(u16 ctxId, void* reqParam, void* optParam,
                                                    s32* reqId);
s32 PS4_SYSV_ABI sceNpMatching2SignalingEnableManualUdpMode();
s32 PS4_SYSV_ABI sceNpMatching2SetSignalingOptParam(u16 ctxId, void* reqParam, void* optParam,
                                                    s32* reqId);
s32 PS4_SYSV_ABI sceNpMatching2GetSignalingOptParamLocal(u16 ctxId, u64 roomId, void* outBuf);

// --- Memory/misc ---
s32 PS4_SYSV_ABI sceNpMatching2GetMemoryInfo();
s32 PS4_SYSV_ABI sceNpMatching2GetSslMemoryInfo();

// --- Signaling address resolution ---
// Resolves a peer's signaling address via the custom server.
// Emulates PSN signaling server's role in brokering peer address exchange.
// Called from NpSignaling when ActivateConnection creates a PENDING connection.
bool ResolvePeerSignalingAddr(const std::string& npid, u32& addr, u16& port);

// Called from NpSignaling when async STUN probe completes.
// Updates signaling_addr if still loopback (Windows has no getifaddrs).
void UpdateSignalingAddrFromStun(const std::string& mapped_addr, u16 mapped_port);

// Drain ready NpMatching2 events and fire callbacks on the calling thread.
// Called from sceNpCheckCallback to ensure callbacks run on the game's main thread.
void DrainReadyEvents();

// No-op stub kept for API compatibility.
void OnPeerEstablished(s32 conn_id, u16 member_id);

// Server-mediated signaling: POST activation intent to server.
// Called from sceNpSignalingActivateConnection. Fire-and-forget HTTP POST.
void PostSignalingActivation(const std::string& peer_npid, s32 conn_id);

// Server-mediated signaling: POST confirm when we receive a peer's ActivatePacket.
// Called from KernelP2PSubsystem::HandleActivatePacket. Fire-and-forget HTTP POST.
void PostSignalingConfirm(const std::string& my_npid, const std::string& peer_npid);
void PostSignalingActive(const std::string& peer_npid);

// Server-mediated signaling: handle signaling_established event from server.
// Called from InvitePollThread when WebSocket delivers the event.
void HandleSignalingEstablished(const std::string& peer_online_id, u16 peer_member_id, s32 conn_id);

void RegisterLib(Core::Loader::SymbolsResolver* sym);

} // namespace Libraries::Np::NpMatching2
