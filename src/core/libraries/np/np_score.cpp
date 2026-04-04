// SPDX-FileCopyrightText: Copyright 2025 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <future>
#include <map>
#include <mutex>
#include <string>
#include <vector>

#include <httplib.h>

#include "common/logging/log.h"
#include "core/libraries/error_codes.h"
#include "core/libraries/libs.h"
#include "core/libraries/np/np_score.h"
#include "core/libraries/rtc/rtc.h"
#include "np_error.h"

namespace Libraries::Np::NpScore {

namespace {

struct TitleContext {
    s32 service_label = 0;
    OrbisNpId self_npid{};
    std::string online_id;
    OrbisNpScorePcId default_pcid = 0;
};

struct RequestContext {
    s32 title_ctx_id = 0;
    OrbisNpScorePcId pcid = 0;
    s32 last_result = ORBIS_OK;
    bool async_pending = false;     // true while an async op is in flight
    std::shared_future<s32> future; // background result (shared so PollAsync can check)
    size_t game_data_offset = 0;    // read cursor for chunked GetGameData
};

struct ScoreRecord {
    std::string online_id;
    OrbisNpScorePcId pcid = 0;
    OrbisNpScoreValue score = 0;
    std::string comment;
    std::vector<u8> game_info; // small metadata in ranking response (<=189 bytes)
    std::vector<u8> game_data; // large blob fetched separately via GetGameData
    Rtc::OrbisRtcTick record_date{};
};

std::mutex s_mutex;
s32 s_next_title_ctx_id = 1;
s32 s_next_request_id = 1;
std::map<s32, TitleContext> s_title_contexts;
std::map<s32, RequestContext> s_requests;
std::map<OrbisNpScoreBoardId, std::vector<ScoreRecord>> s_boards;

// Server host for persistent leaderboard storage.
// Same as NpMatching2's server_host; reads SHADPS4_NP_SERVER env var.
std::string GetScoreServerHost() {
    static std::string host = []() -> std::string {
        const char* env = std::getenv("SHADPS4_NP_SERVER");
        if (env && *env) {
            return std::string("http://") + env;
        }
        return "http://127.0.0.1:18671";
    }();
    return host;
}

std::string ScoreHttpPost(const std::string& path, const std::string& body) {
    httplib::Client cli(GetScoreServerHost());
    cli.set_connection_timeout(5);
    cli.set_read_timeout(5);
    auto res = cli.Post(path, body, "application/json");
    if (res && res->status / 100 == 2) {
        return res->body;
    }
    LOG_WARNING(Lib_NpScore, "HTTP POST {} failed: {}", path,
                res ? std::to_string(res->status) : "connection error");
    return "";
}

std::string ScoreHttpGet(const std::string& path) {
    httplib::Client cli(GetScoreServerHost());
    cli.set_connection_timeout(5);
    cli.set_read_timeout(5);
    auto res = cli.Get(path);
    if (res && res->status / 100 == 2) {
        return res->body;
    }
    LOG_WARNING(Lib_NpScore, "HTTP GET {} failed: {}", path,
                res ? std::to_string(res->status) : "connection error");
    return "";
}

// Minimal base64 encode/decode for game data blobs
static const char b64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string Base64Encode(const u8* data, size_t len) {
    std::string out;
    out.reserve(((len + 2) / 3) * 4);
    for (size_t i = 0; i < len; i += 3) {
        u32 n = static_cast<u32>(data[i]) << 16;
        if (i + 1 < len)
            n |= static_cast<u32>(data[i + 1]) << 8;
        if (i + 2 < len)
            n |= static_cast<u32>(data[i + 2]);
        out += b64_table[(n >> 18) & 0x3F];
        out += b64_table[(n >> 12) & 0x3F];
        out += (i + 1 < len) ? b64_table[(n >> 6) & 0x3F] : '=';
        out += (i + 2 < len) ? b64_table[n & 0x3F] : '=';
    }
    return out;
}

std::vector<u8> Base64Decode(const std::string& in) {
    static u8 dtable[256] = {};
    static bool init = false;
    if (!init) {
        std::memset(dtable, 0x80, sizeof(dtable));
        for (int i = 0; i < 64; i++)
            dtable[static_cast<u8>(b64_table[i])] = i;
        dtable[static_cast<u8>('=')] = 0;
        init = true;
    }
    std::vector<u8> out;
    out.reserve(in.size() * 3 / 4);
    u32 buf = 0;
    int bits = 0;
    for (char c : in) {
        if (dtable[static_cast<u8>(c)] == 0x80)
            continue;
        if (c == '=')
            break;
        buf = (buf << 6) | dtable[static_cast<u8>(c)];
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<u8>((buf >> bits) & 0xFF));
        }
    }
    return out;
}

// Simple JSON value extractors (matches np_matching2.cpp pattern)
static int64_t ScoreJsonGetInt(const std::string& json, const std::string& key) {
    auto kpos = json.find("\"" + key + "\"");
    if (kpos == std::string::npos)
        return 0;
    auto colon = json.find(':', kpos);
    if (colon == std::string::npos)
        return 0;
    auto vstart = json.find_first_not_of(" \t\n\r", colon + 1);
    if (vstart == std::string::npos)
        return 0;
    return std::strtoll(json.c_str() + vstart, nullptr, 10);
}

static std::string ScoreJsonGetString(const std::string& json, const std::string& key) {
    auto kpos = json.find("\"" + key + "\"");
    if (kpos == std::string::npos)
        return "";
    auto colon = json.find(':', kpos);
    if (colon == std::string::npos)
        return "";
    auto qstart = json.find('"', colon + 1);
    if (qstart == std::string::npos)
        return "";
    auto qend = json.find('"', qstart + 1);
    if (qend == std::string::npos)
        return "";
    return json.substr(qstart + 1, qend - qstart - 1);
}

Rtc::OrbisRtcTick GetNowTick() {
    Rtc::OrbisRtcTick tick{};
    Rtc::sceRtcGetCurrentTick(&tick);
    return tick;
}

std::string NpIdToString(const OrbisNpId* id) {
    if (!id) {
        return "";
    }
    return std::string(id->handle.data, strnlen(id->handle.data, ORBIS_NP_ONLINEID_MAX_LENGTH));
}

void FillNpId(OrbisNpId& out, const std::string& online_id) {
    std::memset(&out, 0, sizeof(out));
    std::strncpy(out.handle.data, online_id.c_str(), ORBIS_NP_ONLINEID_MAX_LENGTH - 1);
}

std::vector<ScoreRecord*> SortedBoardLocked(OrbisNpScoreBoardId board_id) {
    auto& board = s_boards[board_id];
    std::vector<ScoreRecord*> sorted;
    sorted.reserve(board.size());
    for (auto& r : board) {
        sorted.push_back(&r);
    }
    std::sort(sorted.begin(), sorted.end(), [](const ScoreRecord* a, const ScoreRecord* b) {
        if (a->score != b->score) {
            return a->score > b->score;
        }
        if (a->record_date.tick != b->record_date.tick) {
            return a->record_date.tick < b->record_date.tick;
        }
        if (a->online_id != b->online_id) {
            return a->online_id < b->online_id;
        }
        return a->pcid < b->pcid;
    });
    return sorted;
}

std::vector<OrbisNpScoreRankNumber> ComputeRanks(const std::vector<ScoreRecord*>& sorted) {
    std::vector<OrbisNpScoreRankNumber> ranks(sorted.size(), 0);
    OrbisNpScoreRankNumber current_rank = 0;
    OrbisNpScoreValue last_score = 0;
    bool has_last = false;
    for (size_t i = 0; i < sorted.size(); i++) {
        if (!has_last || sorted[i]->score != last_score) {
            current_rank = static_cast<OrbisNpScoreRankNumber>(i + 1);
            last_score = sorted[i]->score;
            has_last = true;
        }
        ranks[i] = current_rank;
    }
    return ranks;
}

void FillRankData(OrbisNpScoreRankData* out, const ScoreRecord& rec,
                  OrbisNpScoreRankNumber serial_rank, OrbisNpScoreRankNumber rank) {
    std::memset(out, 0, sizeof(*out));
    FillNpId(out->npId, rec.online_id);
    out->pcId = rec.pcid;
    out->serialRank = serial_rank;
    out->rank = rank;
    out->highestRank = rank;
    out->hasGameData = rec.game_data.empty() ? 0 : 1;
    out->scoreValue = rec.score;
    out->recordDate = rec.record_date;
}

template <typename T>
size_t CapacityFromByteSize(size_t byte_size) {
    return byte_size / sizeof(T);
}

// Launch an async NpScore operation.  Marks the request as pending under
// the lock, then spawns a background thread that calls the sync function.
// The sync function will acquire s_mutex independently on the new thread.
// Caller must NOT hold s_mutex.
template <typename Fn>
void LaunchAsync(s32 reqId, Fn&& fn) {
    {
        std::lock_guard<std::mutex> lock(s_mutex);
        auto it = s_requests.find(reqId);
        if (it == s_requests.end())
            return;
        it->second.async_pending = true;
        it->second.future = std::async(std::launch::async, std::forward<Fn>(fn)).share();
    }
}

} // namespace

int PS4_SYSV_ABI sceNpScoreAbortRequest(s32 reqId) {
    LOG_INFO(Lib_NpScore, "AbortRequest: reqId={}", reqId);
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_requests.find(reqId);
    if (it == s_requests.end()) {
        return ORBIS_OK;
    }
    it->second.last_result = ORBIS_OK;
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNpScoreCensorComment() {
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNpScoreCensorCommentAsync() {
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNpScoreChangeModeForOtherSaveDataOwners() {
    LOG_WARNING(Lib_NpScore, "ChangeModeForOtherSaveDataOwners is unimplemented");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNpScoreCreateNpTitleCtx(s32 serviceLabel, const OrbisNpId* selfNpId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    s32 title_ctx_id = s_next_title_ctx_id++;
    TitleContext& ctx = s_title_contexts[title_ctx_id];
    ctx.service_label = serviceLabel;
    if (selfNpId) {
        ctx.self_npid = *selfNpId;
        ctx.online_id = NpIdToString(selfNpId);
    } else {
        std::memset(&ctx.self_npid, 0, sizeof(ctx.self_npid));
        ctx.online_id = "";
    }
    LOG_INFO(Lib_NpScore, "CreateNpTitleCtx: ctx={} serviceLabel={} online_id='{}'", title_ctx_id,
             serviceLabel, ctx.online_id);
    return title_ctx_id;
}

int PS4_SYSV_ABI sceNpScoreCreateNpTitleCtxA() {
    LOG_WARNING(Lib_NpScore, "CreateNpTitleCtxA is unimplemented");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNpScoreCreateRequest(s32 titleCtxId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_title_contexts.contains(titleCtxId)) {
        LOG_ERROR(Lib_NpScore, "CreateRequest: invalid titleCtxId={}", titleCtxId);
        return ORBIS_NP_SCORE_INVALID_ARGUMENT;
    }
    const s32 req_id = s_next_request_id++;
    RequestContext req{};
    req.title_ctx_id = titleCtxId;
    req.pcid = s_title_contexts[titleCtxId].default_pcid;
    s_requests[req_id] = req;
    LOG_INFO(Lib_NpScore, "CreateRequest: titleCtxId={} -> reqId={}", titleCtxId, req_id);
    return req_id;
}

int PS4_SYSV_ABI sceNpScoreCreateTitleCtx() {
    LOG_WARNING(Lib_NpScore, "CreateTitleCtx (legacy) is unimplemented");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNpScoreDeleteNpTitleCtx(s32 titleCtxId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    s_title_contexts.erase(titleCtxId);
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNpScoreDeleteRequest(s32 reqId) {
    LOG_INFO(Lib_NpScore, "DeleteRequest: reqId={}", reqId);
    std::lock_guard<std::mutex> lock(s_mutex);
    s_requests.erase(reqId);
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNpScoreGetBoardInfo(s32 reqId, OrbisNpScoreBoardId boardId,
                                        OrbisNpScoreBoardInfo* boardInfo, void* option) {
    (void)reqId;
    (void)boardId;
    (void)option;
    if (!boardInfo) {
        return ORBIS_NP_SCORE_INVALID_ARGUMENT;
    }
    std::memset(boardInfo, 0, sizeof(*boardInfo));
    boardInfo->rankLimit = 100000;
    boardInfo->updateMode = 0; // normal
    boardInfo->sortMode = 0;   // descending
    boardInfo->uploadNumLimit = 1;
    boardInfo->uploadSizeLimit = ORBIS_NP_SCORE_GAMEINFO_MAXSIZE;
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNpScoreGetBoardInfoAsync(s32 reqId, OrbisNpScoreBoardId boardId,
                                             OrbisNpScoreBoardInfo* boardInfo, void* option) {
    LaunchAsync(reqId,
                [=]() -> s32 { return sceNpScoreGetBoardInfo(reqId, boardId, boardInfo, option); });
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNpScoreGetFriendsRanking() {
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNpScoreGetFriendsRankingA() {
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNpScoreGetFriendsRankingAAsync() {
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNpScoreGetFriendsRankingAsync() {
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNpScoreGetFriendsRankingForCrossSave() {
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNpScoreGetFriendsRankingForCrossSaveAsync() {
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNpScoreGetGameData(s32 reqId, OrbisNpScoreBoardId boardId,
                                       const OrbisNpId* npId, size_t* totalSize, size_t recvSize,
                                       void* data, void* option) {
    (void)option;
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_requests.contains(reqId)) {
        return ORBIS_NP_SCORE_INVALID_ARGUMENT;
    }

    std::string online_id = NpIdToString(npId);
    OrbisNpScorePcId pcid = s_requests[reqId].pcid;

    // Always clear totalSize first -- the game's fetch loop checks this
    // and will spin forever if it retains a stale value.
    if (totalSize)
        *totalSize = 0;

    LOG_INFO(Lib_NpScore, "GetGameData: board={} npid='{}' pcid={} recvSize={}", boardId, online_id,
             pcid, recvSize);

    // Find data -- check local cache first, then server
    const u8* src_data = nullptr;
    size_t src_size = 0;

    auto& board = s_boards[boardId];
    for (auto& rec : board) {
        if (rec.online_id == online_id && rec.pcid == pcid && !rec.game_data.empty()) {
            src_data = rec.game_data.data();
            src_size = rec.game_data.size();
            break;
        }
    }

    // If not in local cache, try server
    std::vector<u8> server_buf;
    if (!src_data) {
        std::string path = "/np/score/game_data?BoardId=" + std::to_string(boardId) +
                           "&OnlineId=" + online_id + "&PcId=" + std::to_string(pcid);
        auto resp = ScoreHttpGet(path);
        if (!resp.empty()) {
            auto srv_total = static_cast<size_t>(ScoreJsonGetInt(resp, "TotalSize"));
            auto b64 = ScoreJsonGetString(resp, "Data");
            if (srv_total > 0 && !b64.empty()) {
                server_buf = Base64Decode(b64);
                src_data = server_buf.data();
                src_size = srv_total;
            }
        }
    }

    if (!src_data || src_size == 0) {
        // No data -- totalSize already 0, return 0 bytes.
        // Game loop terminates: copied(0) >= totalSize(0).
        return 0;
    }

    if (totalSize)
        *totalSize = src_size;

    // Chunked read: the game calls GetGameData in a loop, each time
    // expecting the NEXT chunk. Track offset per request.
    auto& req = s_requests[reqId];
    size_t offset = req.game_data_offset;
    if (offset >= src_size) {
        return 0;
    }

    size_t remaining = src_size - offset;
    size_t copy_len = std::min(remaining, recvSize);
    if (data && copy_len > 0) {
        std::memcpy(data, src_data + offset, copy_len);
    }
    req.game_data_offset = offset + copy_len;

    LOG_INFO(Lib_NpScore, "GetGameData: returning {} bytes (offset={} total={})", copy_len, offset,
             src_size);
    return static_cast<int>(copy_len);
}

int PS4_SYSV_ABI sceNpScoreGetGameDataAsync(s32 reqId, OrbisNpScoreBoardId boardId,
                                            const OrbisNpId* npId, size_t* totalSize,
                                            size_t recvSize, void* data, void* option) {
    LaunchAsync(reqId, [=]() -> s32 {
        return sceNpScoreGetGameData(reqId, boardId, npId, totalSize, recvSize, data, option);
    });
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNpScoreGetGameDataByAccountId() {
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNpScoreGetGameDataByAccountIdAsync() {
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNpScoreGetRankingByAccountId() {
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNpScoreGetRankingByAccountIdAsync() {
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNpScoreGetRankingByAccountIdForCrossSave() {
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNpScoreGetRankingByAccountIdForCrossSaveAsync() {
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNpScoreGetRankingByAccountIdPcId() {
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNpScoreGetRankingByAccountIdPcIdAsync() {
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNpScoreGetRankingByAccountIdPcIdForCrossSave() {
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNpScoreGetRankingByAccountIdPcIdForCrossSaveAsync() {
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNpScoreGetRankingByNpId(
    s32 reqId, OrbisNpScoreBoardId boardId, const OrbisNpId* npIdArray, size_t npIdArraySize,
    OrbisNpScorePlayerRankData* rankArray, size_t rankArraySize, OrbisNpScoreComment* commentArray,
    size_t commentArraySize, OrbisNpScoreGameInfo* infoArray, size_t infoArraySize, size_t arrayNum,
    Rtc::OrbisRtcTick* lastSortDate, OrbisNpScoreRankNumber* totalRecord, void* option) {
    (void)option;
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_requests.contains(reqId)) {
        return ORBIS_NP_SCORE_INVALID_ARGUMENT;
    }

    auto sorted = SortedBoardLocked(boardId);
    auto ranks = ComputeRanks(sorted);
    if (totalRecord) {
        *totalRecord = static_cast<OrbisNpScoreRankNumber>(sorted.size());
    }
    if (lastSortDate) {
        *lastSortDate = GetNowTick();
    }

    const size_t id_cap = CapacityFromByteSize<OrbisNpId>(npIdArraySize);
    const size_t rank_cap = CapacityFromByteSize<OrbisNpScorePlayerRankData>(rankArraySize);
    const size_t out_count = std::min(arrayNum, std::min(id_cap, rank_cap));
    const size_t comment_cap = CapacityFromByteSize<OrbisNpScoreComment>(commentArraySize);
    const size_t info_cap = CapacityFromByteSize<OrbisNpScoreGameInfo>(infoArraySize);

    for (size_t i = 0; i < out_count; i++) {
        auto* out = &rankArray[i];
        std::memset(out, 0, sizeof(*out));
        const std::string npid = NpIdToString(&npIdArray[i]);
        long found = -1;
        for (size_t j = 0; j < sorted.size(); j++) {
            if (sorted[j]->online_id == npid) {
                found = static_cast<long>(j);
                break;
            }
        }
        if (found < 0) {
            out->hasData = 0;
            continue;
        }
        out->hasData = 1;
        FillRankData(&out->rankData, *sorted[found], static_cast<u32>(found + 1), ranks[found]);

        if (i < comment_cap && commentArray) {
            std::memset(&commentArray[i], 0, sizeof(commentArray[i]));
            std::strncpy(commentArray[i].utf8Comment, sorted[found]->comment.c_str(),
                         ORBIS_NP_SCORE_COMMENT_MAXLEN);
        }
        if (i < info_cap && infoArray) {
            std::memset(&infoArray[i], 0, sizeof(infoArray[i]));
            const size_t copy_len = std::min(sorted[found]->game_info.size(),
                                             static_cast<size_t>(ORBIS_NP_SCORE_GAMEINFO_MAXSIZE));
            infoArray[i].infoSize = copy_len;
            if (copy_len > 0) {
                std::memcpy(infoArray[i].data, sorted[found]->game_info.data(), copy_len);
            }
        }
    }

    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNpScoreGetRankingByNpIdAsync(
    s32 reqId, OrbisNpScoreBoardId boardId, const OrbisNpId* npIdArray, size_t npIdArraySize,
    OrbisNpScorePlayerRankData* rankArray, size_t rankArraySize, OrbisNpScoreComment* commentArray,
    size_t commentArraySize, OrbisNpScoreGameInfo* infoArray, size_t infoArraySize, size_t arrayNum,
    Rtc::OrbisRtcTick* lastSortDate, OrbisNpScoreRankNumber* totalRecord, void* option) {
    LaunchAsync(reqId, [=]() -> s32 {
        return sceNpScoreGetRankingByNpId(reqId, boardId, npIdArray, npIdArraySize, rankArray,
                                          rankArraySize, commentArray, commentArraySize, infoArray,
                                          infoArraySize, arrayNum, lastSortDate, totalRecord,
                                          option);
    });
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNpScoreGetRankingByNpIdPcId(
    s32 reqId, OrbisNpScoreBoardId boardId, const OrbisNpScoreNpIdPcId* idArray, size_t idArraySize,
    OrbisNpScorePlayerRankData* rankArray, size_t rankArraySize, OrbisNpScoreComment* commentArray,
    size_t commentArraySize, OrbisNpScoreGameInfo* infoArray, size_t infoArraySize, size_t arrayNum,
    Rtc::OrbisRtcTick* lastSortDate, OrbisNpScoreRankNumber* totalRecord, void* option) {
    (void)option;
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_requests.contains(reqId)) {
        return ORBIS_NP_SCORE_INVALID_ARGUMENT;
    }

    if (totalRecord)
        *totalRecord = 0;
    if (lastSortDate)
        *lastSortDate = GetNowTick();

    const size_t id_cap = CapacityFromByteSize<OrbisNpScoreNpIdPcId>(idArraySize);
    const size_t rank_cap = CapacityFromByteSize<OrbisNpScorePlayerRankData>(rankArraySize);
    const size_t out_count = std::min(arrayNum, std::min(id_cap, rank_cap));
    const size_t comment_cap = CapacityFromByteSize<OrbisNpScoreComment>(commentArraySize);
    const size_t info_cap = CapacityFromByteSize<OrbisNpScoreGameInfo>(infoArraySize);

    // Query server for each NpId+PcId
    size_t filled = 0;
    for (size_t i = 0; i < out_count; i++) {
        auto* out = &rankArray[i];
        std::memset(out, 0, sizeof(*out));
        const std::string npid = NpIdToString(&idArray[i].npId);
        const OrbisNpScorePcId pcid = idArray[i].pcId;

        LOG_INFO(Lib_NpScore, "GetRankingByNpIdPcId: board={} npid='{}' pcid={}", boardId, npid,
                 pcid);

        out->hasData = 0; // default
    }

    // Build server query with all NpId+PcId pairs at once
    std::string body = "{\"BoardId\": " + std::to_string(boardId) + ", \"Ids\": [";
    for (size_t i = 0; i < out_count; i++) {
        if (i > 0)
            body += ",";
        body += "{\"OnlineId\": \"" + NpIdToString(&idArray[i].npId) +
                "\", \"PcId\": " + std::to_string(idArray[i].pcId) + "}";
    }
    body += "]}";
    auto resp = ScoreHttpPost("/np/score/ranking_npid", body);

    if (!resp.empty()) {
        auto srv_total = ScoreJsonGetInt(resp, "Total");
        if (totalRecord && srv_total > 0) {
            *totalRecord = static_cast<OrbisNpScoreRankNumber>(srv_total);
        }
        // Parse each entry from the response
        size_t spos = 0;
        size_t entry_idx = 0;
        while ((spos = resp.find("\"OnlineId\"", spos)) != std::string::npos &&
               entry_idx < out_count) {
            size_t ws = (spos > 80) ? spos - 80 : 0;
            size_t we = std::min(resp.size(), spos + 600);
            auto entry = resp.substr(ws, we - ws);

            auto has_data = static_cast<s32>(ScoreJsonGetInt(entry, "HasData"));
            auto* out = &rankArray[entry_idx];
            if (has_data) {
                out->hasData = 1;
                auto& rd = out->rankData;
                std::memset(&rd, 0, sizeof(rd));
                auto oid = ScoreJsonGetString(entry, "OnlineId");
                FillNpId(rd.npId, oid);
                rd.pcId = static_cast<OrbisNpScorePcId>(ScoreJsonGetInt(entry, "PcId"));
                rd.serialRank = static_cast<u32>(ScoreJsonGetInt(entry, "SerialRank"));
                rd.rank = static_cast<u32>(ScoreJsonGetInt(entry, "Rank"));
                rd.highestRank = rd.rank;
                rd.hasGameData = static_cast<s32>(ScoreJsonGetInt(entry, "HasGameData"));
                rd.scoreValue = ScoreJsonGetInt(entry, "Score");
                rd.recordDate = GetNowTick();
                auto comment_str = ScoreJsonGetString(entry, "Comment");
                if (entry_idx < comment_cap && commentArray) {
                    std::memset(&commentArray[entry_idx], 0, sizeof(commentArray[entry_idx]));
                    std::strncpy(commentArray[entry_idx].utf8Comment, comment_str.c_str(),
                                 ORBIS_NP_SCORE_COMMENT_MAXLEN);
                }
                auto gi_b64 = ScoreJsonGetString(entry, "GameInfo");
                if (entry_idx < info_cap && infoArray) {
                    std::memset(&infoArray[entry_idx], 0, sizeof(infoArray[entry_idx]));
                    if (!gi_b64.empty()) {
                        auto gi_data = Base64Decode(gi_b64);
                        const size_t copy_len = std::min(
                            gi_data.size(), static_cast<size_t>(ORBIS_NP_SCORE_GAMEINFO_MAXSIZE));
                        infoArray[entry_idx].infoSize = copy_len;
                        if (copy_len > 0) {
                            std::memcpy(infoArray[entry_idx].data, gi_data.data(), copy_len);
                        }
                    }
                }
                LOG_INFO(Lib_NpScore, "GetRankingByNpIdPcId: found npid='{}' rank={} score={}", oid,
                         rd.rank, rd.scoreValue);
                filled++;
            }
            entry_idx++;
            spos += 10;
        }
    }

    if (filled == 0) {
        return ORBIS_NP_SCORE_ERROR_NOT_FOUND;
    }
    return static_cast<int>(filled);
}

int PS4_SYSV_ABI sceNpScoreGetRankingByNpIdPcIdAsync(
    s32 reqId, OrbisNpScoreBoardId boardId, const OrbisNpScoreNpIdPcId* idArray, size_t idArraySize,
    OrbisNpScorePlayerRankData* rankArray, size_t rankArraySize, OrbisNpScoreComment* commentArray,
    size_t commentArraySize, OrbisNpScoreGameInfo* infoArray, size_t infoArraySize, size_t arrayNum,
    Rtc::OrbisRtcTick* lastSortDate, OrbisNpScoreRankNumber* totalRecord, void* option) {
    LaunchAsync(reqId, [=]() -> s32 {
        return sceNpScoreGetRankingByNpIdPcId(reqId, boardId, idArray, idArraySize, rankArray,
                                              rankArraySize, commentArray, commentArraySize,
                                              infoArray, infoArraySize, arrayNum, lastSortDate,
                                              totalRecord, option);
    });
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNpScoreGetRankingByRange(
    s32 reqId, OrbisNpScoreBoardId boardId, OrbisNpScoreRankNumber startSerialRank,
    OrbisNpScoreRankData* rankArray, size_t rankArraySize, OrbisNpScoreComment* commentArray,
    size_t commentArraySize, OrbisNpScoreGameInfo* infoArray, size_t infoArraySize, size_t arrayNum,
    Rtc::OrbisRtcTick* lastSortDate, OrbisNpScoreRankNumber* totalRecord, void* option) {
    (void)option;
    LOG_INFO(Lib_NpScore, "GetRankingByRange: reqId={} boardId={} start={} arrayNum={}", reqId,
             boardId, startSerialRank, arrayNum);
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_requests.contains(reqId)) {
        LOG_ERROR(Lib_NpScore, "GetRankingByRange: reqId={} NOT FOUND!", reqId);
        return ORBIS_NP_SCORE_INVALID_ARGUMENT;
    }

    // Fetch the requested slice directly from the server. The server handles
    // sorting, Start/Count offset, and returns pre-ranked entries. We write
    // them directly into the output arrays -- no local re-sorting needed.
    {
        std::string path = "/np/score/ranking?BoardId=" + std::to_string(boardId) +
                           "&Start=" + std::to_string(startSerialRank) +
                           "&Count=" + std::to_string(arrayNum);
        auto resp = ScoreHttpGet(path);
        if (!resp.empty()) {
            auto total_val = ScoreJsonGetInt(resp, "Total");
            if (totalRecord && total_val > 0) {
                *totalRecord = static_cast<OrbisNpScoreRankNumber>(total_val);
            }
            if (lastSortDate) {
                *lastSortDate = GetNowTick();
            }

            const size_t rank_cap = CapacityFromByteSize<OrbisNpScoreRankData>(rankArraySize);
            const size_t out_count = std::min(arrayNum, rank_cap);
            const size_t comment_cap = CapacityFromByteSize<OrbisNpScoreComment>(commentArraySize);
            const size_t info_cap = CapacityFromByteSize<OrbisNpScoreGameInfo>(infoArraySize);

            // Zero all output slots first
            for (size_t i = 0; i < out_count; i++) {
                std::memset(&rankArray[i], 0, sizeof(rankArray[i]));
            }

            // Parse server entries directly into output arrays
            size_t filled = 0;
            size_t pos = 0;
            while ((pos = resp.find("\"OnlineId\"", pos)) != std::string::npos &&
                   filled < out_count) {
                // Window must reach back far enough to include "Rank" and "SerialRank"
                // which precede "OnlineId" in each JSON entry (~50 chars before)
                size_t win_start = (pos > 80) ? pos - 80 : 0;
                size_t win_end = std::min(resp.size(), pos + 600);
                auto entry = resp.substr(win_start, win_end - win_start);

                auto oid = ScoreJsonGetString(entry, "OnlineId");
                if (oid.empty()) {
                    pos += 10;
                    continue;
                }

                auto score_val = ScoreJsonGetInt(entry, "Score");
                auto rank_val = static_cast<u32>(ScoreJsonGetInt(entry, "Rank"));
                auto serial = static_cast<u32>(ScoreJsonGetInt(entry, "SerialRank"));
                auto has_gd = static_cast<s32>(ScoreJsonGetInt(entry, "HasGameData"));
                auto comment_str = ScoreJsonGetString(entry, "Comment");
                auto gi_b64 = ScoreJsonGetString(entry, "GameInfo");

                auto& rd = rankArray[filled];
                std::memset(&rd, 0, sizeof(rd));
                FillNpId(rd.npId, oid);
                rd.pcId = static_cast<OrbisNpScorePcId>(ScoreJsonGetInt(entry, "PcId"));
                rd.serialRank = serial;
                rd.rank = rank_val;
                rd.highestRank = rank_val;
                rd.hasGameData = has_gd;
                rd.scoreValue = score_val;
                rd.recordDate = GetNowTick();

                if (filled < comment_cap && commentArray) {
                    std::memset(&commentArray[filled], 0, sizeof(commentArray[filled]));
                    std::strncpy(commentArray[filled].utf8Comment, comment_str.c_str(),
                                 ORBIS_NP_SCORE_COMMENT_MAXLEN);
                }
                if (filled < info_cap && infoArray) {
                    std::memset(&infoArray[filled], 0, sizeof(infoArray[filled]));
                    if (!gi_b64.empty()) {
                        auto gi_data = Base64Decode(gi_b64);
                        const size_t copy_len = std::min(
                            gi_data.size(), static_cast<size_t>(ORBIS_NP_SCORE_GAMEINFO_MAXSIZE));
                        infoArray[filled].infoSize = copy_len;
                        if (copy_len > 0) {
                            std::memcpy(infoArray[filled].data, gi_data.data(), copy_len);
                        }
                    }
                }
                filled++;
                pos += 10;
            }

            LOG_INFO(
                Lib_NpScore,
                "GetRankingByRange: filled={} from server (board={} start={} count={} total={})",
                filled, boardId, startSerialRank, arrayNum,
                totalRecord ? static_cast<int>(*totalRecord) : -1);
            if (filled > 0) {
                LOG_INFO(Lib_NpScore, "  entry[0]: npid='{}' rank={} serial={} score={} hasGD={}",
                         rankArray[0].npId.handle.data, rankArray[0].rank, rankArray[0].serialRank,
                         rankArray[0].scoreValue, rankArray[0].hasGameData);
            }

            if (filled == 0) {
                return ORBIS_NP_SCORE_ERROR_NOT_FOUND;
            }
            return static_cast<int>(filled);
        }
    }

    // Server unreachable -- return empty
    if (totalRecord)
        *totalRecord = 0;
    if (lastSortDate)
        *lastSortDate = GetNowTick();
    return ORBIS_NP_SCORE_ERROR_NOT_FOUND;
}

int PS4_SYSV_ABI sceNpScoreGetRankingByRangeA() {
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNpScoreGetRankingByRangeAAsync() {
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNpScoreGetRankingByRangeAsync(
    s32 reqId, OrbisNpScoreBoardId boardId, OrbisNpScoreRankNumber startSerialRank,
    OrbisNpScoreRankData* rankArray, size_t rankArraySize, OrbisNpScoreComment* commentArray,
    size_t commentArraySize, OrbisNpScoreGameInfo* infoArray, size_t infoArraySize, size_t arrayNum,
    Rtc::OrbisRtcTick* lastSortDate, OrbisNpScoreRankNumber* totalRecord, void* option) {
    LaunchAsync(reqId, [=]() -> s32 {
        return sceNpScoreGetRankingByRange(reqId, boardId, startSerialRank, rankArray,
                                           rankArraySize, commentArray, commentArraySize, infoArray,
                                           infoArraySize, arrayNum, lastSortDate, totalRecord,
                                           option);
    });
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNpScoreGetRankingByRangeForCrossSave() {
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNpScoreGetRankingByRangeForCrossSaveAsync() {
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNpScorePollAsync(s32 reqId, s32* result) {
    // Lock-free check: shared_future::wait_for is thread-safe.
    // Must NOT hold s_mutex here -- the async worker thread holds it
    // during HTTP calls, and PollAsync would deadlock/stall.
    std::shared_future<s32> fut;
    bool pending = false;
    {
        std::lock_guard<std::mutex> lock(s_mutex);
        auto it = s_requests.find(reqId);
        if (it == s_requests.end()) {
            if (result)
                *result = ORBIS_OK;
            return 0;
        }
        if (!it->second.async_pending) {
            if (result)
                *result = it->second.last_result;
            return 0;
        }
        pending = true;
        fut = it->second.future; // copy shared_future (cheap)
    }
    // Check future WITHOUT holding the mutex
    if (pending && fut.valid() &&
        fut.wait_for(std::chrono::milliseconds(0)) == std::future_status::ready) {
        s32 res = fut.get();
        std::lock_guard<std::mutex> lock(s_mutex);
        auto it = s_requests.find(reqId);
        if (it != s_requests.end()) {
            it->second.last_result = res;
            it->second.async_pending = false;
        }
        if (result)
            *result = res;
        return 0;
    }
    return 1; // still running
}

int PS4_SYSV_ABI sceNpScoreRecordGameData(s32 reqId, OrbisNpScoreBoardId boardId,
                                          OrbisNpScoreValue score, size_t totalSize,
                                          size_t sendSize, const void* data, void* option) {
    (void)option;
    LOG_INFO(Lib_NpScore,
             "RecordGameData ENTER: reqId={} board={} score={} totalSize={} sendSize={} data={}",
             reqId, boardId, score, totalSize, sendSize, data);
    std::lock_guard<std::mutex> lock(s_mutex);
    auto req_it = s_requests.find(reqId);
    if (req_it == s_requests.end()) {
        return ORBIS_NP_SCORE_INVALID_ARGUMENT;
    }
    auto ctx_it = s_title_contexts.find(req_it->second.title_ctx_id);
    if (ctx_it == s_title_contexts.end()) {
        return ORBIS_NP_SCORE_INVALID_ARGUMENT;
    }

    const std::string online_id = ctx_it->second.online_id;
    const OrbisNpScorePcId pcid = req_it->second.pcid;

    LOG_INFO(Lib_NpScore,
             "RecordGameData: board={} npid='{}' pcid={} score={} "
             "totalSize={} sendSize={}",
             boardId, online_id, pcid, score, totalSize, sendSize);

    // Store locally
    auto& board = s_boards[boardId];
    ScoreRecord* rec = nullptr;
    for (auto& r : board) {
        if (r.online_id == online_id && r.pcid == pcid) {
            rec = &r;
            break;
        }
    }
    if (!rec) {
        board.push_back(ScoreRecord{});
        rec = &board.back();
        rec->online_id = online_id;
        rec->pcid = pcid;
        rec->score = score;
        rec->record_date = GetNowTick();
    }

    if (data && sendSize > 0) {
        // Game sends game_data in chunks. Pre-allocate on first chunk,
        // then append each chunk to build the full blob.
        if (rec->game_data.empty() && totalSize > 0) {
            rec->game_data.reserve(totalSize);
        }
        rec->game_data.insert(rec->game_data.end(), static_cast<const u8*>(data),
                              static_cast<const u8*>(data) + sendSize);
    }

    // Send to server
    std::string b64_data;
    if (data && sendSize > 0) {
        b64_data = Base64Encode(static_cast<const u8*>(data), sendSize);
    }
    std::string body = "{";
    body += "\"BoardId\": " + std::to_string(boardId) + ",";
    body += "\"OnlineId\": \"" + online_id + "\",";
    body += "\"PcId\": " + std::to_string(pcid) + ",";
    body += "\"TotalSize\": " + std::to_string(totalSize) + ",";
    body += "\"Data\": \"" + b64_data + "\"";
    body += "}";
    ScoreHttpPost("/np/score/record_data", body);

    req_it->second.last_result = ORBIS_OK;
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNpScoreRecordGameDataAsync(s32 reqId, OrbisNpScoreBoardId boardId,
                                               OrbisNpScoreValue score, size_t totalSize,
                                               size_t sendSize, const void* data, void* option) {
    LOG_INFO(Lib_NpScore, "RecordGameDataAsync ENTER: reqId={} board={} totalSize={} sendSize={}",
             reqId, boardId, totalSize, sendSize);
    // Copy data from game memory NOW -- pointer will be dangling in async thread.
    auto data_copy = std::make_shared<std::vector<u8>>();
    if (data && sendSize > 0) {
        data_copy->assign(static_cast<const u8*>(data), static_cast<const u8*>(data) + sendSize);
    }
    LaunchAsync(reqId, [=]() -> s32 {
        return sceNpScoreRecordGameData(reqId, boardId, score, totalSize, data_copy->size(),
                                        data_copy->data(), option);
    });
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNpScoreRecordScore(s32 reqId, OrbisNpScoreBoardId boardId,
                                       OrbisNpScoreValue score,
                                       const OrbisNpScoreComment* scoreComment,
                                       const OrbisNpScoreGameInfo* gameInfo,
                                       OrbisNpScoreRankNumber* tmpRank,
                                       const Rtc::OrbisRtcTick* compareDate, void* option) {
    (void)compareDate;
    (void)option;
    std::lock_guard<std::mutex> lock(s_mutex);
    auto req_it = s_requests.find(reqId);
    if (req_it == s_requests.end()) {
        return ORBIS_NP_SCORE_INVALID_ARGUMENT;
    }
    auto ctx_it = s_title_contexts.find(req_it->second.title_ctx_id);
    if (ctx_it == s_title_contexts.end()) {
        return ORBIS_NP_SCORE_INVALID_ARGUMENT;
    }

    const std::string online_id = ctx_it->second.online_id;
    if (online_id.empty()) {
        return ORBIS_NP_SCORE_INVALID_ARGUMENT;
    }
    const OrbisNpScorePcId pcid = req_it->second.pcid;

    LOG_INFO(Lib_NpScore, "RecordScore: gameInfo={} infoSize={} comment='{}'", (void*)gameInfo,
             gameInfo ? gameInfo->infoSize : 0,
             scoreComment ? scoreComment->utf8Comment : "(null)");
    if (gameInfo && gameInfo->infoSize > 0) {
        std::string hex;
        const size_t dump_len =
            std::min(gameInfo->infoSize, static_cast<size_t>(ORBIS_NP_SCORE_GAMEINFO_MAXSIZE));
        for (size_t i = 0; i < dump_len; i++) {
            char buf[4];
            snprintf(buf, sizeof(buf), "%02x ", gameInfo->data[i]);
            hex += buf;
        }
        LOG_INFO(Lib_NpScore, "RecordScore: game_info[{}] = {}", gameInfo->infoSize, hex);
    }

    auto& board = s_boards[boardId];
    ScoreRecord* rec = nullptr;
    for (auto& r : board) {
        if (r.online_id == online_id && r.pcid == pcid) {
            rec = &r;
            break;
        }
    }
    if (!rec) {
        board.push_back(ScoreRecord{});
        rec = &board.back();
        rec->online_id = online_id;
        rec->pcid = pcid;
    }
    rec->score = score;
    rec->comment =
        scoreComment
            ? std::string(scoreComment->utf8Comment,
                          strnlen(scoreComment->utf8Comment, ORBIS_NP_SCORE_COMMENT_MAXLEN))
            : "";
    rec->game_info.clear();
    if (gameInfo && gameInfo->infoSize > 0) {
        const size_t copy_len =
            std::min(gameInfo->infoSize, static_cast<size_t>(ORBIS_NP_SCORE_GAMEINFO_MAXSIZE));
        rec->game_info.assign(gameInfo->data, gameInfo->data + copy_len);
    }
    rec->record_date = GetNowTick();

    auto sorted = SortedBoardLocked(boardId);
    auto ranks = ComputeRanks(sorted);
    if (tmpRank) {
        *tmpRank = 0;
        for (size_t i = 0; i < sorted.size(); i++) {
            if (sorted[i] == rec) {
                *tmpRank = ranks[i];
                break;
            }
        }
    }
    // Persist to server and get the real rank from the server response
    {
        std::string gi_b64;
        if (!rec->game_info.empty()) {
            gi_b64 = Base64Encode(rec->game_info.data(), rec->game_info.size());
        }
        std::string body = "{";
        body += "\"BoardId\": " + std::to_string(boardId) + ",";
        body += "\"OnlineId\": \"" + online_id + "\",";
        body += "\"PcId\": " + std::to_string(pcid) + ",";
        body += "\"Score\": " + std::to_string(score) + ",";
        body += "\"Comment\": \"" + rec->comment + "\",";
        body += "\"GameInfo\": \"" + gi_b64 + "\"";
        body += "}";
        auto resp = ScoreHttpPost("/np/score/record", body);
        if (!resp.empty() && tmpRank) {
            auto server_rank = static_cast<OrbisNpScoreRankNumber>(ScoreJsonGetInt(resp, "Rank"));
            if (server_rank > 0) {
                *tmpRank = server_rank;
            }
        }
    }

    LOG_INFO(Lib_NpScore, "RecordScore: board={} npid='{}' pcid={} score={} rank={}", boardId,
             online_id, pcid, score, tmpRank ? *tmpRank : 0);

    req_it->second.last_result = ORBIS_OK;
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNpScoreRecordScoreAsync(s32 reqId, OrbisNpScoreBoardId boardId,
                                            OrbisNpScoreValue score,
                                            const OrbisNpScoreComment* scoreComment,
                                            const OrbisNpScoreGameInfo* gameInfo,
                                            OrbisNpScoreRankNumber* tmpRank,
                                            const Rtc::OrbisRtcTick* compareDate, void* option) {
    // Copy data from game memory NOW -- pointers will be dangling by the time
    // the async thread reads them.
    auto comment_copy = std::make_shared<OrbisNpScoreComment>();
    if (scoreComment) {
        *comment_copy = *scoreComment;
    } else {
        std::memset(comment_copy.get(), 0, sizeof(OrbisNpScoreComment));
    }
    auto gi_copy = std::make_shared<OrbisNpScoreGameInfo>();
    if (gameInfo) {
        *gi_copy = *gameInfo;
    } else {
        std::memset(gi_copy.get(), 0, sizeof(OrbisNpScoreGameInfo));
    }
    LaunchAsync(reqId, [=]() -> s32 {
        return sceNpScoreRecordScore(reqId, boardId, score, comment_copy.get(), gi_copy.get(),
                                     tmpRank, compareDate, option);
    });
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNpScoreSanitizeComment(s32 request_handle, char* input_string,
                                           char* output_buffer, void* options) {
    (void)request_handle;
    (void)options;
    if (output_buffer == nullptr || input_string == nullptr) {
        return ORBIS_NP_SCORE_INVALID_ARGUMENT;
    }
    std::strncpy(output_buffer, input_string, 255);
    output_buffer[255] = '\0';
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNpScoreSanitizeCommentAsync() {
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNpScoreSetPlayerCharacterId(s32 id, OrbisNpScorePcId pcId) {
    LOG_INFO(Lib_NpScore, "SetPlayerCharacterId: id={} pcId={}", id, pcId);
    std::lock_guard<std::mutex> lock(s_mutex);
    if (auto req_it = s_requests.find(id); req_it != s_requests.end()) {
        req_it->second.pcid = pcId;
        return ORBIS_OK;
    }
    if (auto ctx_it = s_title_contexts.find(id); ctx_it != s_title_contexts.end()) {
        ctx_it->second.default_pcid = pcId;
        return ORBIS_OK;
    }
    return ORBIS_NP_SCORE_INVALID_ARGUMENT;
}

int PS4_SYSV_ABI sceNpScoreSetThreadParam() {
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNpScoreSetTimeout(s32 id, s32 resolveRetry, s32 resolveTimeout, s32 connTimeout,
                                      s32 sendTimeout, s32 recvTimeout) {
    LOG_INFO(Lib_NpScore,
             "SetTimeout: id={} resolve_retry={} resolve_to={} conn_to={} send_to={} recv_to={}",
             id, resolveRetry, resolveTimeout, connTimeout, sendTimeout, recvTimeout);
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceNpScoreWaitAsync(s32 id, s32* result) {
    // Real library blocks on a semaphore until the async operation completes.
    // We block on the shared_future.
    std::shared_future<s32> fut;
    {
        std::lock_guard<std::mutex> lock(s_mutex);
        auto it = s_requests.find(id);
        if (it == s_requests.end()) {
            if (result)
                *result = ORBIS_OK;
            return 0;
        }
        if (!it->second.async_pending) {
            if (result)
                *result = it->second.last_result;
            return 0;
        }
        fut = it->second.future;
    }
    // Block until complete -- do NOT hold s_mutex while waiting
    if (fut.valid()) {
        s32 res = fut.get(); // blocks until ready
        std::lock_guard<std::mutex> lock(s_mutex);
        auto it = s_requests.find(id);
        if (it != s_requests.end()) {
            it->second.last_result = res;
            it->second.async_pending = false;
        }
        if (result)
            *result = res;
    } else {
        if (result)
            *result = ORBIS_OK;
    }
    return 0;
}

void RegisterLib(Core::Loader::SymbolsResolver* sym) {
    LIB_FUNCTION("1i7kmKbX6hk", "libSceNpScore", 1, "libSceNpScore", sceNpScoreAbortRequest);
    LIB_FUNCTION("2b3TI0mDYiI", "libSceNpScore", 1, "libSceNpScore", sceNpScoreCensorComment);
    LIB_FUNCTION("4eOvDyN-aZc", "libSceNpScore", 1, "libSceNpScore", sceNpScoreCensorCommentAsync);
    LIB_FUNCTION("dTXC+YcePtM", "libSceNpScore", 1, "libSceNpScore",
                 sceNpScoreChangeModeForOtherSaveDataOwners);
    LIB_FUNCTION("KnNA1TEgtBI", "libSceNpScore", 1, "libSceNpScore", sceNpScoreCreateNpTitleCtx);
    LIB_FUNCTION("GWnWQNXZH5M", "libSceNpScore", 1, "libSceNpScore", sceNpScoreCreateNpTitleCtxA);
    LIB_FUNCTION("gW8qyjYrUbk", "libSceNpScore", 1, "libSceNpScore", sceNpScoreCreateRequest);
    LIB_FUNCTION("qW9M0bQ-Zx0", "libSceNpScore", 1, "libSceNpScore", sceNpScoreCreateTitleCtx);
    LIB_FUNCTION("G0pE+RNCwfk", "libSceNpScore", 1, "libSceNpScore", sceNpScoreDeleteNpTitleCtx);
    LIB_FUNCTION("dK8-SgYf6r4", "libSceNpScore", 1, "libSceNpScore", sceNpScoreDeleteRequest);
    LIB_FUNCTION("LoVMVrijVOk", "libSceNpScore", 1, "libSceNpScore", sceNpScoreGetBoardInfo);
    LIB_FUNCTION("Q0Avi9kebsY", "libSceNpScore", 1, "libSceNpScore", sceNpScoreGetBoardInfoAsync);
    LIB_FUNCTION("8kuIzUw6utQ", "libSceNpScore", 1, "libSceNpScore", sceNpScoreGetFriendsRanking);
    LIB_FUNCTION("gMbOn+-6eXA", "libSceNpScore", 1, "libSceNpScore", sceNpScoreGetFriendsRankingA);
    LIB_FUNCTION("6-G9OxL5DKg", "libSceNpScore", 1, "libSceNpScore",
                 sceNpScoreGetFriendsRankingAAsync);
    LIB_FUNCTION("7SuMUlN7Q6I", "libSceNpScore", 1, "libSceNpScore",
                 sceNpScoreGetFriendsRankingAsync);
    LIB_FUNCTION("AgcxgceaH8k", "libSceNpScore", 1, "libSceNpScore",
                 sceNpScoreGetFriendsRankingForCrossSave);
    LIB_FUNCTION("m6F7sE1HQZU", "libSceNpScore", 1, "libSceNpScore",
                 sceNpScoreGetFriendsRankingForCrossSaveAsync);
    LIB_FUNCTION("zKoVok6FFEI", "libSceNpScore", 1, "libSceNpScore", sceNpScoreGetGameData);
    LIB_FUNCTION("JjOFRVPdQWc", "libSceNpScore", 1, "libSceNpScore", sceNpScoreGetGameDataAsync);
    LIB_FUNCTION("Lmtc9GljeUA", "libSceNpScore", 1, "libSceNpScore",
                 sceNpScoreGetGameDataByAccountId);
    LIB_FUNCTION("PP9jx8s0574", "libSceNpScore", 1, "libSceNpScore",
                 sceNpScoreGetGameDataByAccountIdAsync);
    LIB_FUNCTION("K9tlODTQx3c", "libSceNpScore", 1, "libSceNpScore",
                 sceNpScoreGetRankingByAccountId);
    LIB_FUNCTION("dRszNNyGWkw", "libSceNpScore", 1, "libSceNpScore",
                 sceNpScoreGetRankingByAccountIdAsync);
    LIB_FUNCTION("3Ybj4E1qNtY", "libSceNpScore", 1, "libSceNpScore",
                 sceNpScoreGetRankingByAccountIdForCrossSave);
    LIB_FUNCTION("Kc+3QK84AKM", "libSceNpScore", 1, "libSceNpScore",
                 sceNpScoreGetRankingByAccountIdForCrossSaveAsync);
    LIB_FUNCTION("wJPWycVGzrs", "libSceNpScore", 1, "libSceNpScore",
                 sceNpScoreGetRankingByAccountIdPcId);
    LIB_FUNCTION("bFVjDgxFapc", "libSceNpScore", 1, "libSceNpScore",
                 sceNpScoreGetRankingByAccountIdPcIdAsync);
    LIB_FUNCTION("oXjVieH6ZGQ", "libSceNpScore", 1, "libSceNpScore",
                 sceNpScoreGetRankingByAccountIdPcIdForCrossSave);
    LIB_FUNCTION("nXaF1Bxb-Nw", "libSceNpScore", 1, "libSceNpScore",
                 sceNpScoreGetRankingByAccountIdPcIdForCrossSaveAsync);
    LIB_FUNCTION("9mZEgoiEq6Y", "libSceNpScore", 1, "libSceNpScore", sceNpScoreGetRankingByNpId);
    LIB_FUNCTION("Rd27dqUFZV8", "libSceNpScore", 1, "libSceNpScore",
                 sceNpScoreGetRankingByNpIdAsync);
    LIB_FUNCTION("ETS-uM-vH9Q", "libSceNpScore", 1, "libSceNpScore",
                 sceNpScoreGetRankingByNpIdPcId);
    LIB_FUNCTION("FsouSN0ykN8", "libSceNpScore", 1, "libSceNpScore",
                 sceNpScoreGetRankingByNpIdPcIdAsync);
    LIB_FUNCTION("KBHxDjyk-jA", "libSceNpScore", 1, "libSceNpScore", sceNpScoreGetRankingByRange);
    LIB_FUNCTION("MA9vSt7JImY", "libSceNpScore", 1, "libSceNpScore", sceNpScoreGetRankingByRangeA);
    LIB_FUNCTION("y5ja7WI05rs", "libSceNpScore", 1, "libSceNpScore",
                 sceNpScoreGetRankingByRangeAAsync);
    LIB_FUNCTION("rShmqXHwoQE", "libSceNpScore", 1, "libSceNpScore",
                 sceNpScoreGetRankingByRangeAsync);
    LIB_FUNCTION("nRoYV2yeUuw", "libSceNpScore", 1, "libSceNpScore",
                 sceNpScoreGetRankingByRangeForCrossSave);
    LIB_FUNCTION("AZ4eAlGDy-Q", "libSceNpScore", 1, "libSceNpScore",
                 sceNpScoreGetRankingByRangeForCrossSaveAsync);
    LIB_FUNCTION("m1DfNRstkSQ", "libSceNpScore", 1, "libSceNpScore", sceNpScorePollAsync);
    LIB_FUNCTION("bcoVwcBjQ9E", "libSceNpScore", 1, "libSceNpScore", sceNpScoreRecordGameData);
    LIB_FUNCTION("1gL5PwYzrrw", "libSceNpScore", 1, "libSceNpScore", sceNpScoreRecordGameDataAsync);
    LIB_FUNCTION("zT0XBtgtOSI", "libSceNpScore", 1, "libSceNpScore", sceNpScoreRecordScore);
    LIB_FUNCTION("ANJssPz3mY0", "libSceNpScore", 1, "libSceNpScore", sceNpScoreRecordScoreAsync);
    LIB_FUNCTION("r4oAo9in0TA", "libSceNpScore", 1, "libSceNpScore", sceNpScoreSanitizeComment);
    LIB_FUNCTION("3UVqGJeDf30", "libSceNpScore", 1, "libSceNpScore",
                 sceNpScoreSanitizeCommentAsync);
    LIB_FUNCTION("bygbKdHmjn4", "libSceNpScore", 1, "libSceNpScore",
                 sceNpScoreSetPlayerCharacterId);
    LIB_FUNCTION("yxK68584JAU", "libSceNpScore", 1, "libSceNpScore", sceNpScoreSetThreadParam);
    LIB_FUNCTION("S3xZj35v8Z8", "libSceNpScore", 1, "libSceNpScore", sceNpScoreSetTimeout);
    LIB_FUNCTION("fqk8SC63p1U", "libSceNpScore", 1, "libSceNpScore", sceNpScoreWaitAsync);
    LIB_FUNCTION("KnNA1TEgtBI", "libSceNpScoreCompat", 1, "libSceNpScore",
                 sceNpScoreCreateNpTitleCtx);
    LIB_FUNCTION("8kuIzUw6utQ", "libSceNpScoreCompat", 1, "libSceNpScore",
                 sceNpScoreGetFriendsRanking);
    LIB_FUNCTION("7SuMUlN7Q6I", "libSceNpScoreCompat", 1, "libSceNpScore",
                 sceNpScoreGetFriendsRankingAsync);
    LIB_FUNCTION("zKoVok6FFEI", "libSceNpScoreCompat", 1, "libSceNpScore", sceNpScoreGetGameData);
    LIB_FUNCTION("JjOFRVPdQWc", "libSceNpScoreCompat", 1, "libSceNpScore",
                 sceNpScoreGetGameDataAsync);
    LIB_FUNCTION("9mZEgoiEq6Y", "libSceNpScoreCompat", 1, "libSceNpScore",
                 sceNpScoreGetRankingByNpId);
    LIB_FUNCTION("Rd27dqUFZV8", "libSceNpScoreCompat", 1, "libSceNpScore",
                 sceNpScoreGetRankingByNpIdAsync);
    LIB_FUNCTION("ETS-uM-vH9Q", "libSceNpScoreCompat", 1, "libSceNpScore",
                 sceNpScoreGetRankingByNpIdPcId);
    LIB_FUNCTION("FsouSN0ykN8", "libSceNpScoreCompat", 1, "libSceNpScore",
                 sceNpScoreGetRankingByNpIdPcIdAsync);
    LIB_FUNCTION("KBHxDjyk-jA", "libSceNpScoreCompat", 1, "libSceNpScore",
                 sceNpScoreGetRankingByRange);
    LIB_FUNCTION("rShmqXHwoQE", "libSceNpScoreCompat", 1, "libSceNpScore",
                 sceNpScoreGetRankingByRangeAsync);
};

} // namespace Libraries::Np::NpScore
