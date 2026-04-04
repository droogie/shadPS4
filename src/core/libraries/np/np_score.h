// SPDX-FileCopyrightText: Copyright 2025 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include <cstddef>

#include "common/types.h"
#include "core/libraries/np/np_types.h"
#include "core/libraries/rtc/rtc.h"

namespace Core::Loader {
class SymbolsResolver;
}

namespace Libraries::Np::NpScore {

constexpr size_t ORBIS_NP_SCORE_COMMENT_MAXLEN = 63;
constexpr size_t ORBIS_NP_SCORE_GAMEINFO_MAXSIZE = 189;

using OrbisNpScoreBoardId = u32;
using OrbisNpScoreValue = s64;
using OrbisNpScoreRankNumber = u32;
using OrbisNpScorePcId = s32;

struct OrbisNpScoreGameInfo {
    size_t infoSize;
    u8 data[ORBIS_NP_SCORE_GAMEINFO_MAXSIZE];
    u8 pad2[3];
};

struct OrbisNpScoreComment {
    char utf8Comment[ORBIS_NP_SCORE_COMMENT_MAXLEN + 1];
};

struct OrbisNpScoreRankData {
    OrbisNpId npId;
    u8 reserved[49];
    u8 pad0[3];
    OrbisNpScorePcId pcId;
    OrbisNpScoreRankNumber serialRank;
    OrbisNpScoreRankNumber rank;
    OrbisNpScoreRankNumber highestRank;
    s32 hasGameData;
    u8 pad1[4];
    OrbisNpScoreValue scoreValue;
    Rtc::OrbisRtcTick recordDate;
};

struct OrbisNpScorePlayerRankData {
    s32 hasData;
    u8 pad0[4];
    OrbisNpScoreRankData rankData;
};

struct OrbisNpScoreBoardInfo {
    u32 rankLimit;
    u32 updateMode;
    u32 sortMode;
    OrbisNpScoreRankNumber uploadNumLimit;
    size_t uploadSizeLimit;
};

struct OrbisNpScoreNpIdPcId {
    OrbisNpId npId;
    OrbisNpScorePcId pcId;
    u8 pad[4];
};

// --- Sync API ---
int PS4_SYSV_ABI sceNpScoreAbortRequest(s32 reqId);
int PS4_SYSV_ABI sceNpScoreCensorComment();
int PS4_SYSV_ABI sceNpScoreCensorCommentAsync();
int PS4_SYSV_ABI sceNpScoreChangeModeForOtherSaveDataOwners();
int PS4_SYSV_ABI sceNpScoreCreateNpTitleCtx(s32 serviceLabel, const OrbisNpId* selfNpId);
int PS4_SYSV_ABI sceNpScoreCreateNpTitleCtxA();
int PS4_SYSV_ABI sceNpScoreCreateRequest(s32 titleCtxId);
int PS4_SYSV_ABI sceNpScoreCreateTitleCtx();
int PS4_SYSV_ABI sceNpScoreDeleteNpTitleCtx(s32 titleCtxId);
int PS4_SYSV_ABI sceNpScoreDeleteRequest(s32 reqId);

int PS4_SYSV_ABI sceNpScoreGetBoardInfo(s32 reqId, OrbisNpScoreBoardId boardId,
                                        OrbisNpScoreBoardInfo* boardInfo, void* option);
int PS4_SYSV_ABI sceNpScoreGetBoardInfoAsync(s32 reqId, OrbisNpScoreBoardId boardId,
                                             OrbisNpScoreBoardInfo* boardInfo, void* option);

int PS4_SYSV_ABI sceNpScoreGetFriendsRanking();
int PS4_SYSV_ABI sceNpScoreGetFriendsRankingA();
int PS4_SYSV_ABI sceNpScoreGetFriendsRankingAAsync();
int PS4_SYSV_ABI sceNpScoreGetFriendsRankingAsync();
int PS4_SYSV_ABI sceNpScoreGetFriendsRankingForCrossSave();
int PS4_SYSV_ABI sceNpScoreGetFriendsRankingForCrossSaveAsync();

int PS4_SYSV_ABI sceNpScoreGetGameData(s32 reqId, OrbisNpScoreBoardId boardId,
                                       const OrbisNpId* npId, size_t* totalSize, size_t recvSize,
                                       void* data, void* option);
int PS4_SYSV_ABI sceNpScoreGetGameDataAsync(s32 reqId, OrbisNpScoreBoardId boardId,
                                            const OrbisNpId* npId, size_t* totalSize,
                                            size_t recvSize, void* data, void* option);

int PS4_SYSV_ABI sceNpScoreGetGameDataByAccountId();
int PS4_SYSV_ABI sceNpScoreGetGameDataByAccountIdAsync();

int PS4_SYSV_ABI sceNpScoreGetRankingByAccountId();
int PS4_SYSV_ABI sceNpScoreGetRankingByAccountIdAsync();
int PS4_SYSV_ABI sceNpScoreGetRankingByAccountIdForCrossSave();
int PS4_SYSV_ABI sceNpScoreGetRankingByAccountIdForCrossSaveAsync();
int PS4_SYSV_ABI sceNpScoreGetRankingByAccountIdPcId();
int PS4_SYSV_ABI sceNpScoreGetRankingByAccountIdPcIdAsync();
int PS4_SYSV_ABI sceNpScoreGetRankingByAccountIdPcIdForCrossSave();
int PS4_SYSV_ABI sceNpScoreGetRankingByAccountIdPcIdForCrossSaveAsync();

int PS4_SYSV_ABI sceNpScoreGetRankingByNpId(
    s32 reqId, OrbisNpScoreBoardId boardId, const OrbisNpId* npIdArray, size_t npIdArraySize,
    OrbisNpScorePlayerRankData* rankArray, size_t rankArraySize, OrbisNpScoreComment* commentArray,
    size_t commentArraySize, OrbisNpScoreGameInfo* infoArray, size_t infoArraySize, size_t arrayNum,
    Rtc::OrbisRtcTick* lastSortDate, OrbisNpScoreRankNumber* totalRecord, void* option);
int PS4_SYSV_ABI sceNpScoreGetRankingByNpIdAsync(
    s32 reqId, OrbisNpScoreBoardId boardId, const OrbisNpId* npIdArray, size_t npIdArraySize,
    OrbisNpScorePlayerRankData* rankArray, size_t rankArraySize, OrbisNpScoreComment* commentArray,
    size_t commentArraySize, OrbisNpScoreGameInfo* infoArray, size_t infoArraySize, size_t arrayNum,
    Rtc::OrbisRtcTick* lastSortDate, OrbisNpScoreRankNumber* totalRecord, void* option);

int PS4_SYSV_ABI sceNpScoreGetRankingByNpIdPcId(
    s32 reqId, OrbisNpScoreBoardId boardId, const OrbisNpScoreNpIdPcId* idArray, size_t idArraySize,
    OrbisNpScorePlayerRankData* rankArray, size_t rankArraySize, OrbisNpScoreComment* commentArray,
    size_t commentArraySize, OrbisNpScoreGameInfo* infoArray, size_t infoArraySize, size_t arrayNum,
    Rtc::OrbisRtcTick* lastSortDate, OrbisNpScoreRankNumber* totalRecord, void* option);
int PS4_SYSV_ABI sceNpScoreGetRankingByNpIdPcIdAsync(
    s32 reqId, OrbisNpScoreBoardId boardId, const OrbisNpScoreNpIdPcId* idArray, size_t idArraySize,
    OrbisNpScorePlayerRankData* rankArray, size_t rankArraySize, OrbisNpScoreComment* commentArray,
    size_t commentArraySize, OrbisNpScoreGameInfo* infoArray, size_t infoArraySize, size_t arrayNum,
    Rtc::OrbisRtcTick* lastSortDate, OrbisNpScoreRankNumber* totalRecord, void* option);

int PS4_SYSV_ABI sceNpScoreGetRankingByRange(
    s32 reqId, OrbisNpScoreBoardId boardId, OrbisNpScoreRankNumber startSerialRank,
    OrbisNpScoreRankData* rankArray, size_t rankArraySize, OrbisNpScoreComment* commentArray,
    size_t commentArraySize, OrbisNpScoreGameInfo* infoArray, size_t infoArraySize, size_t arrayNum,
    Rtc::OrbisRtcTick* lastSortDate, OrbisNpScoreRankNumber* totalRecord, void* option);
int PS4_SYSV_ABI sceNpScoreGetRankingByRangeA();
int PS4_SYSV_ABI sceNpScoreGetRankingByRangeAAsync();
int PS4_SYSV_ABI sceNpScoreGetRankingByRangeAsync(
    s32 reqId, OrbisNpScoreBoardId boardId, OrbisNpScoreRankNumber startSerialRank,
    OrbisNpScoreRankData* rankArray, size_t rankArraySize, OrbisNpScoreComment* commentArray,
    size_t commentArraySize, OrbisNpScoreGameInfo* infoArray, size_t infoArraySize, size_t arrayNum,
    Rtc::OrbisRtcTick* lastSortDate, OrbisNpScoreRankNumber* totalRecord, void* option);
int PS4_SYSV_ABI sceNpScoreGetRankingByRangeForCrossSave();
int PS4_SYSV_ABI sceNpScoreGetRankingByRangeForCrossSaveAsync();

int PS4_SYSV_ABI sceNpScorePollAsync(s32 reqId, s32* result);

int PS4_SYSV_ABI sceNpScoreRecordGameData(s32 reqId, OrbisNpScoreBoardId boardId,
                                          OrbisNpScoreValue score, size_t totalSize,
                                          size_t sendSize, const void* data, void* option);
int PS4_SYSV_ABI sceNpScoreRecordGameDataAsync(s32 reqId, OrbisNpScoreBoardId boardId,
                                               OrbisNpScoreValue score, size_t totalSize,
                                               size_t sendSize, const void* data, void* option);

int PS4_SYSV_ABI sceNpScoreRecordScore(s32 reqId, OrbisNpScoreBoardId boardId,
                                       OrbisNpScoreValue score,
                                       const OrbisNpScoreComment* scoreComment,
                                       const OrbisNpScoreGameInfo* gameInfo,
                                       OrbisNpScoreRankNumber* tmpRank,
                                       const Rtc::OrbisRtcTick* compareDate, void* option);
int PS4_SYSV_ABI sceNpScoreRecordScoreAsync(s32 reqId, OrbisNpScoreBoardId boardId,
                                            OrbisNpScoreValue score,
                                            const OrbisNpScoreComment* scoreComment,
                                            const OrbisNpScoreGameInfo* gameInfo,
                                            OrbisNpScoreRankNumber* tmpRank,
                                            const Rtc::OrbisRtcTick* compareDate, void* option);

int PS4_SYSV_ABI sceNpScoreSanitizeComment(s32 request_handle, char* input_string,
                                           char* output_buffer, void* options);
int PS4_SYSV_ABI sceNpScoreSanitizeCommentAsync();
int PS4_SYSV_ABI sceNpScoreSetPlayerCharacterId(s32 id, OrbisNpScorePcId pcId);
int PS4_SYSV_ABI sceNpScoreSetThreadParam();
int PS4_SYSV_ABI sceNpScoreSetTimeout(s32 id, s32 resolveRetry, s32 resolveTimeout, s32 connTimeout,
                                      s32 sendTimeout, s32 recvTimeout);
int PS4_SYSV_ABI sceNpScoreWaitAsync(s32 id, s32* result);

void RegisterLib(Core::Loader::SymbolsResolver* sym);
} // namespace Libraries::Np::NpScore
