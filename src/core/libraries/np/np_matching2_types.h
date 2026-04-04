// SPDX-FileCopyrightText: Copyright 2025 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include "common/types.h"
#include "core/libraries/np/np_types.h"

namespace Libraries::Np::NpMatching2 {

using OrbisNpMatching2ContextId = u16;
using OrbisNpMatching2RequestId = u32;
using OrbisNpMatching2Event = u16;
using OrbisNpMatching2ServerId = u16;
using OrbisNpMatching2WorldId = u32;
using OrbisNpMatching2LobbyId = u64;
using OrbisNpMatching2RoomId = u64;
using OrbisNpMatching2RoomPasswordSlotMask = u64;
using OrbisNpMatching2FlagAttr = u32;
using OrbisNpMatching2RoomMemberId = u16;
using OrbisNpMatching2SignalingRequestId = u32;

constexpr u16 ORBIS_NP_MATCHING2_REQUEST_EVENT_CREATE_JOIN_ROOM = 0x0101;
constexpr u16 ORBIS_NP_MATCHING2_REQUEST_EVENT_JOIN_ROOM = 0x0102;
constexpr u16 ORBIS_NP_MATCHING2_REQUEST_EVENT_LEAVE_ROOM = 0x0103;
constexpr u16 ORBIS_NP_MATCHING2_REQUEST_EVENT_GRANT_ROOM_OWNER = 0x0104;
constexpr u16 ORBIS_NP_MATCHING2_REQUEST_EVENT_KICKOUT_ROOM_MEMBER = 0x0105;
constexpr u16 ORBIS_NP_MATCHING2_REQUEST_EVENT_SEARCH_ROOM = 0x0106;
constexpr u16 ORBIS_NP_MATCHING2_REQUEST_EVENT_SET_ROOM_DATA_INTERNAL = 0x0109;
constexpr u16 ORBIS_NP_MATCHING2_REQUEST_EVENT_GET_ROOM_DATA_INTERNAL = 0x010a;
constexpr u16 ORBIS_NP_MATCHING2_REQUEST_EVENT_SET_ROOM_MEMBER_DATA_INTERNAL = 0x010b;
constexpr u16 ORBIS_NP_MATCHING2_REQUEST_EVENT_GET_ROOM_MEMBER_DATA_INTERNAL = 0x010c;
constexpr u16 ORBIS_NP_MATCHING2_REQUEST_EVENT_SET_SIGNALING_OPT_PARAM = 0x010d;
constexpr u16 ORBIS_NP_MATCHING2_REQUEST_EVENT_SET_ROOM_DATA_EXTERNAL = 0x0004;
constexpr u16 ORBIS_NP_MATCHING2_REQUEST_EVENT_GET_ROOM_MEMBER_DATA_EXTERNAL_LIST = 0x0003;
constexpr u16 ORBIS_NP_MATCHING2_REQUEST_EVENT_SEND_ROOM_CHAT_MESSAGE = 0x0107;
constexpr u16 ORBIS_NP_MATCHING2_REQUEST_EVENT_SEND_ROOM_MESSAGE = 0x0108;
constexpr u16 ORBIS_NP_MATCHING2_REQUEST_EVENT_SIGNALING_GET_PING_INFO = 0x0e01;

constexpr u16 ORBIS_NP_MATCHING2_ROOM_EVENT_MEMBER_JOINED = 0x1101;
constexpr u16 ORBIS_NP_MATCHING2_ROOM_EVENT_MEMBER_LEFT = 0x1102;
constexpr u16 ORBIS_NP_MATCHING2_ROOM_EVENT_KICKEDOUT = 0x1103;
constexpr u16 ORBIS_NP_MATCHING2_ROOM_EVENT_ROOM_DESTROYED = 0x1104;
constexpr u16 ORBIS_NP_MATCHING2_ROOM_EVENT_OWNER_CHANGED = 0x1105;

// Signaling event types:
//   0x5101 = Dead -- peer connection lost
//   0x5102 = Established -- peer connection established
constexpr u16 ORBIS_NP_MATCHING2_SIGNALING_EVENT_DEAD = 0x5101;
constexpr u16 ORBIS_NP_MATCHING2_SIGNALING_EVENT_ESTABLISHED = 0x5102;

constexpr u16 ORBIS_NP_MATCHING2_CONTEXT_EVENT_START_OVER = 0x6f01;
constexpr u16 ORBIS_NP_MATCHING2_CONTEXT_EVENT_STARTED = 0x6f02;
constexpr u16 ORBIS_NP_MATCHING2_CONTEXT_EVENT_STOPPED = 0x6f03;

constexpr u8 ORBIS_NP_MATCHING2_EVENT_CAUSE_LEAVE_ACTION = 1;
constexpr u8 ORBIS_NP_MATCHING2_EVENT_CAUSE_KICKOUT_ACTION = 2;
constexpr u8 ORBIS_NP_MATCHING2_EVENT_CAUSE_MEMBER_DISAPPEARED = 5;
constexpr u8 ORBIS_NP_MATCHING2_EVENT_CAUSE_CONNECTION_ERROR = 7;
constexpr u8 ORBIS_NP_MATCHING2_EVENT_CAUSE_NP_SIGNED_OUT = 8;
constexpr u8 ORBIS_NP_MATCHING2_EVENT_CAUSE_CONTEXT_ERROR = 10;
constexpr u8 ORBIS_NP_MATCHING2_EVENT_CAUSE_CONTEXT_ACTION = 11;

constexpr s32 ORBIS_NP_MATCHING2_SIGNALING_CONN_STATUS_INACTIVE = 0;
constexpr s32 ORBIS_NP_MATCHING2_SIGNALING_CONN_STATUS_PENDING = 1;
constexpr s32 ORBIS_NP_MATCHING2_SIGNALING_CONN_STATUS_ACTIVE = 2;

struct OrbisNpMatching2SessionPassword {
    u8 data[8];
};

using OrbisNpMatching2RequestCallback = PS4_SYSV_ABI void (*)(u16 ctxId, u32 reqId, u16 event,
                                                              s32 errorCode, void* data, void* arg);

using OrbisNpMatching2ContextCallback = PS4_SYSV_ABI void (*)(u16 ctxId, u16 event, u8 eventCause,
                                                              s32 errorCode, void* arg);

using OrbisNpMatching2RoomEventCallback = PS4_SYSV_ABI void (*)(u16 ctxId, u64 roomId,
                                                                u16 roomEvent, void* data,
                                                                void* arg);

using OrbisNpMatching2SignalingCallback = PS4_SYSV_ABI void (*)(u16 ctxId, u64 roomId, u16 memberId,
                                                                u16 event, s32 errorCode,
                                                                void* arg);

using OrbisNpMatching2LobbyEventCallback = PS4_SYSV_ABI void (*)(u16 ctxId, u64 lobbyId, u16 event,
                                                                 void* data, void* arg);
using OrbisNpMatching2LobbyMessageCallback = PS4_SYSV_ABI void (*)(u16 ctxId, u64 lobbyId,
                                                                   u16 srcMemberId, u16 event,
                                                                   void* data, void* arg);
using OrbisNpMatching2RoomMessageCallback = PS4_SYSV_ABI void (*)(u16 ctxId, u64 roomId,
                                                                  u16 srcMemberId, u16 event,
                                                                  void* data, void* arg);

struct OrbisNpMatching2RequestOptParam {
    OrbisNpMatching2RequestCallback cbFunc;
    void* cbFuncArg;
    u32 timeout;
    u16 appReqId;
    u8 _pad[2];
};

struct OrbisNpMatching2RoomMemberDataInternal {
    struct OrbisNpMatching2RoomMemberDataInternal* next; // +0x00
    u64 joinDate;                                        // +0x08
    OrbisNpId npId;                                      // +0x10
    u8 _pad_34[4];                                       // +0x34
    u16 memberId;                                        // +0x38
    u8 teamId;                                           // +0x3A
    u8 natType;                                          // +0x3B
    u32 flagAttr;                                        // +0x3C
    void* roomGroup;                                     // +0x40
    void* roomMemberBinAttrInternal;                     // +0x48
    u64 roomMemberBinAttrInternalNum;                    // +0x50
};
static_assert(sizeof(OrbisNpMatching2RoomMemberDataInternal) == 0x58);

struct OrbisNpMatching2RoomDataInternal {
    u16 serverId;                                    // +0x00
    u8 _pad_02[6];                                   // +0x02
    u32 worldId;                                     // +0x08
    u32 _pad_0C;                                     // +0x0C
    u64 lobbyId;                                     // +0x10
    u64 roomId;                                      // +0x18
    u64 passwordSlotMask;                            // +0x20
    u32 maxSlot;                                     // +0x28
    u32 _pad_2C;                                     // +0x2C
    OrbisNpMatching2RoomMemberDataInternal* members; // +0x30
    u32 membersNum;                                  // +0x38
    u32 _pad_3C;                                     // +0x3C
    OrbisNpMatching2RoomMemberDataInternal* me;      // +0x40
    OrbisNpMatching2RoomMemberDataInternal* owner;   // +0x48
    void* roomGroup;                                 // +0x50
    u32 roomGroupNum;                                // +0x58
    u32 _pad_5C;                                     // +0x5C
    u64 flagAttr;                                    // +0x60
    void* roomBinAttrInternal;                       // +0x68
    u32 roomBinAttrInternalNum;                      // +0x70
    u32 _pad_74;                                     // +0x74
};
static_assert(sizeof(OrbisNpMatching2RoomDataInternal) == 0x78);

struct OrbisNpMatching2PresenceOptionData {
    u8 data[16]; // +0x00: ORBIS_NP_MATCHING2_PRESENCE_OPTION_DATA_SIZE = 16
    u64 len;     // +0x10: size_t
};
static_assert(sizeof(OrbisNpMatching2PresenceOptionData) == 0x18);

struct OrbisNpMatching2RoomMemberUpdateInfo {
    OrbisNpMatching2RoomMemberDataInternal* roomMemberDataInternal; // +0x00
    u8 eventCause;                                                  // +0x08
    u8 _pad[7];                                                     // +0x09
    OrbisNpMatching2PresenceOptionData optData;                     // +0x10
};
static_assert(sizeof(OrbisNpMatching2RoomMemberUpdateInfo) == 0x28);

// {roomDataInternal*, memberList{members*, membersNum, me*, owner*}}
struct OrbisNpMatching2CreateJoinRoomResponse {
    OrbisNpMatching2RoomDataInternal* roomDataInternal; // +0x00
    OrbisNpMatching2RoomMemberDataInternal* members;    // +0x08
    u64 membersNum;                                     // +0x10
    OrbisNpMatching2RoomMemberDataInternal* me;         // +0x18
    OrbisNpMatching2RoomMemberDataInternal* owner;      // +0x20
};
static_assert(sizeof(OrbisNpMatching2CreateJoinRoomResponse) == 0x28);

using OrbisNpMatching2JoinRoomResponse = OrbisNpMatching2CreateJoinRoomResponse;

struct OrbisNpMatching2CreateJoinRoomRequest {
    u8 _data[0x200]; // opaque, we extract fields as needed
};

struct OrbisNpMatching2JoinRoomRequest {
    u64 roomId;                                    // +0x00
    OrbisNpMatching2SessionPassword* roomPassword; // +0x08
    u8 _rest[0x88];
};

struct OrbisNpMatching2LeaveRoomRequest {
    u64 roomId;                                 // +0x00
    OrbisNpMatching2PresenceOptionData optData; // +0x08
};
static_assert(sizeof(OrbisNpMatching2LeaveRoomRequest) == 0x20);

struct OrbisNpMatching2World {
    u64 _pad_00;       // +0x00
    u32 worldId;       // +0x08
    u32 _pad_0C;       // +0x0C
    u64 _pad_10;       // +0x10
    u32 curNumOfLobby; // +0x18
    u32 maxNumOfLobby; // +0x1C
    u64 _pad_20;       // +0x20
};
static_assert(sizeof(OrbisNpMatching2World) == 0x28);

struct OrbisNpMatching2GetWorldInfoListResponse {
    OrbisNpMatching2World* world; // +0x00
    u64 worldNum;                 // +0x08
};

// Room data as seen by external searchers (SearchRoom response).
struct OrbisNpMatching2RoomDataExternal {
    struct OrbisNpMatching2RoomDataExternal* next; // +0x00
    u16 maxSlot;                                   // +0x08
    u16 curMemberNum;                              // +0x0A
    OrbisNpMatching2FlagAttr flagAttr;             // +0x0C
    u16 serverId;                                  // +0x10
    u8 _pad_12[2];                                 // +0x12
    u32 worldId;                                   // +0x14
    u64 lobbyId;                                   // +0x18
    u64 roomId;                                    // +0x20
    u64 passwordSlotMask;                          // +0x28
    u64 joinedSlotMask;                            // +0x30
    u16 publicSlotNum;                             // +0x38
    u16 privateSlotNum;                            // +0x3A
    u16 openPublicSlotNum;                         // +0x3C
    u16 openPrivateSlotNum;                        // +0x3E
    OrbisNpId owner;                               // +0x40
    u8 _rest[0x40];                                // +0x64 (attrs, etc.)
};

struct OrbisNpMatching2Range {
    u32 startIndex;  // +0x00
    u32 total;       // +0x04
    u32 resultCount; // +0x08
    u8 _pad[4];      // +0x0C
};
static_assert(sizeof(OrbisNpMatching2Range) == 0x10);

struct OrbisNpMatching2SearchRoomResponse {
    OrbisNpMatching2Range range;                        // +0x00
    OrbisNpMatching2RoomDataExternal* roomDataExternal; // +0x10
};

// Same layout as OrbisNpSignalingNetInfo
struct OrbisNpMatching2SignalingNetInfo {
    u64 size;       // +0x00: must be 0x18 (sizeof this struct)
    u32 localAddr;  // +0x08
    u32 mappedAddr; // +0x0C
    s32 natStatus;  // +0x10: NAT type (0=unknown, 1=type1, 2=type2, 3=type3)
    u32 _pad;       // +0x14
};

union OrbisNpMatching2SignalingConnectionInfo {
    u32 rtt;
    u32 bandwidth;
    OrbisNpId npId;
    struct {
        u32 addr;
        u16 port;
        u8 _pad[2];
    } address;
    u32 packetLoss;
};

struct OrbisNpMatching2ExtraInitParam {
    u16 signalingPort;
    u8 _pad[6];
};

// --- Lobby types ---

using OrbisNpMatching2LobbyMemberId = u16;
using OrbisNpMatching2AttributeId = u16;

constexpr u16 ORBIS_NP_MATCHING2_REQUEST_EVENT_GET_LOBBY_INFO_LIST = 0x0006;
constexpr u16 ORBIS_NP_MATCHING2_REQUEST_EVENT_JOIN_LOBBY = 0x0201;
constexpr u16 ORBIS_NP_MATCHING2_REQUEST_EVENT_LEAVE_LOBBY = 0x0202;
constexpr u16 ORBIS_NP_MATCHING2_REQUEST_EVENT_SEND_LOBBY_CHAT_MESSAGE = 0x0203;
constexpr u16 ORBIS_NP_MATCHING2_REQUEST_EVENT_SET_LOBBY_MEMBER_DATA_INTERNAL = 0x0205;
constexpr u16 ORBIS_NP_MATCHING2_REQUEST_EVENT_GET_LOBBY_MEMBER_DATA_INTERNAL = 0x0206;
constexpr u16 ORBIS_NP_MATCHING2_REQUEST_EVENT_GET_LOBBY_MEMBER_DATA_INTERNAL_LIST = 0x0207;

constexpr u16 ORBIS_NP_MATCHING2_LOBBY_EVENT_MEMBER_JOINED = 0x3201;
constexpr u16 ORBIS_NP_MATCHING2_LOBBY_EVENT_MEMBER_LEFT = 0x3202;
constexpr u16 ORBIS_NP_MATCHING2_LOBBY_EVENT_LOBBY_DESTROYED = 0x3203;

struct OrbisNpMatching2LobbyMemberIdList {
    OrbisNpMatching2LobbyMemberId* memberId; // +0x00
    u64 memberIdNum;                         // +0x08
    OrbisNpMatching2LobbyMemberId me;        // +0x10
    u8 _pad[6];                              // +0x12
};
static_assert(sizeof(OrbisNpMatching2LobbyMemberIdList) == 0x18);

struct OrbisNpMatching2LobbyDataInternal {
    OrbisNpMatching2FlagAttr flagAttr;              // +0x00
    u8 _pad_04[4];                                  // +0x04
    u16 maxSlot;                                    // +0x08
    OrbisNpMatching2ServerId serverId;              // +0x0A
    OrbisNpMatching2WorldId worldId;                // +0x0C
    OrbisNpMatching2LobbyId lobbyId;                // +0x10
    OrbisNpMatching2LobbyMemberIdList memberIdList; // +0x18
    void* lobbyBinAttrInternal;                     // +0x30
    u64 lobbyBinAttrInternalNum;                    // +0x38
};
static_assert(sizeof(OrbisNpMatching2LobbyDataInternal) == 0x40);

struct OrbisNpMatching2JoinLobbyResponse {
    OrbisNpMatching2LobbyDataInternal* lobbyDataInternal; // +0x00
};

struct OrbisNpMatching2LobbyMemberDataInternal {
    struct OrbisNpMatching2LobbyMemberDataInternal* next; // +0x00
    u64 joinDate;                                         // +0x08
    OrbisNpId npId;                                       // +0x10
    OrbisNpMatching2LobbyMemberId memberId;               // +0x34
    u8 _pad_36[2];                                        // +0x36
    u8 reserved[8];                                       // +0x38
    void* joinedSessionInfo;                              // +0x40
    u64 joinedSessionInfoNum;                             // +0x48
    void* lobbyMemberBinAttrInternal;                     // +0x50
    u64 lobbyMemberBinAttrInternalNum;                    // +0x58
};
static_assert(sizeof(OrbisNpMatching2LobbyMemberDataInternal) == 0x60);

struct OrbisNpMatching2LobbyMemberUpdateInfo {
    const OrbisNpMatching2LobbyMemberDataInternal* lobbyMemberDataInternal; // +0x00
    u8 eventCause;                                                          // +0x08
    u8 _pad[7];                                                             // +0x09
    OrbisNpMatching2PresenceOptionData optData;                             // +0x10
};
static_assert(sizeof(OrbisNpMatching2LobbyMemberUpdateInfo) == 0x28);

struct OrbisNpMatching2JoinLobbyRequest {
    OrbisNpMatching2LobbyId lobbyId;            // +0x00
    const void* joinedSessionInfo;              // +0x08
    u64 joinedSessionInfoNum;                   // +0x10
    const void* lobbyMemberBinAttrInternal;     // +0x18
    u64 lobbyMemberBinAttrInternalNum;          // +0x20
    OrbisNpMatching2PresenceOptionData optData; // +0x28
};

struct OrbisNpMatching2GetLobbyMemberDataInternalResponse {
    OrbisNpMatching2LobbyMemberDataInternal* lobbyMemberDataInternal; // +0x00
};

struct OrbisNpMatching2GetLobbyMemberDataInternalListResponse {
    OrbisNpMatching2LobbyMemberDataInternal* lobbyMemberDataInternal; // +0x00
    u64 lobbyMemberDataInternalNum;                                   // +0x08
};

struct OrbisNpMatching2SendLobbyChatMessageResponse {
    bool filtered; // +0x00
    u8 _pad[7];    // +0x01
};

} // namespace Libraries::Np::NpMatching2
