// SPDX-FileCopyrightText: Copyright 2025 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#include <atomic>
#include <cstring>
#include <map>
#include <mutex>
#include <unordered_map>
#include <unordered_set>
#include <variant>

#include "common/config.h"
#include "common/logging/log.h"
#include "core/libraries/error_codes.h"
#include "core/libraries/libs.h"
#include "core/libraries/np/np_error.h"
#include "core/libraries/np/np_manager.h"
#include "core/libraries/np/np_matching2.h"
#include "core/libraries/np/np_signaling.h"
#include "core/libraries/system/userservice.h"
#include "core/tls.h"

namespace Libraries::Np::NpManager {

static bool g_signed_in = false;
static s32 g_active_requests = 0;
static std::mutex g_request_mutex;

static std::map<std::string, std::function<void()>> g_np_callbacks;
static std::mutex g_np_callbacks_mutex;

// Internal types for storing request-related information
enum class NpRequestState {
    None = 0,
    Ready = 1,
    Aborted = 2,
    Complete = 3,
};

struct NpRequest {
    NpRequestState state;
    bool async;
    s32 result;
};

static std::vector<NpRequest> g_requests;

s32 CreateNpRequest(bool async) {
    if (g_active_requests == ORBIS_NP_MANAGER_REQUEST_LIMIT) {
        return ORBIS_NP_ERROR_REQUEST_MAX;
    }

    std::scoped_lock lk{g_request_mutex};

    s32 req_index = 0;
    while (req_index < g_requests.size()) {
        // Find first nonexistant request
        if (g_requests[req_index].state == NpRequestState::None) {
            // There is no request at this index, set the index to ready then break.
            g_requests[req_index].state = NpRequestState::Ready;
            g_requests[req_index].async = async;
            break;
        }
        req_index++;
    }

    if (req_index == g_requests.size()) {
        // There are no requests to replace.
        NpRequest new_request{NpRequestState::Ready, async, 0};
        g_requests.emplace_back(new_request);
    }

    // Offset by one, first returned ID is 0x20000001
    g_active_requests++;
    return req_index + ORBIS_NP_MANAGER_REQUEST_ID_OFFSET + 1;
}

s32 PS4_SYSV_ABI sceNpCreateRequest() {
    LOG_DEBUG(Lib_NpManager, "called");
    return CreateNpRequest(false);
}

s32 PS4_SYSV_ABI sceNpCreateAsyncRequest(const OrbisNpCreateAsyncRequestParameter* param) {
    LOG_DEBUG(Lib_NpManager, "called");
    if (param == nullptr) {
        return ORBIS_NP_ERROR_INVALID_ARGUMENT;
    }

    if (param->size != sizeof(OrbisNpCreateAsyncRequestParameter)) {
        return ORBIS_NP_ERROR_INVALID_SIZE;
    }

    return CreateNpRequest(true);
}

s32 PS4_SYSV_ABI sceNpCheckNpAvailability(s32 req_id, OrbisNpOnlineId* online_id) {
    if (online_id == nullptr) {
        return ORBIS_NP_ERROR_INVALID_ARGUMENT;
    }

    std::scoped_lock lk{g_request_mutex};

    s32 req_index = req_id - ORBIS_NP_MANAGER_REQUEST_ID_OFFSET - 1;
    if (g_active_requests == 0 || g_requests.size() <= req_index ||
        g_requests[req_index].state == NpRequestState::None) {
        return ORBIS_NP_ERROR_REQUEST_NOT_FOUND;
    }

    auto& request = g_requests[req_index];
    if (request.state == NpRequestState::Complete) {
        request.result = ORBIS_NP_ERROR_INVALID_ARGUMENT;
        return ORBIS_NP_ERROR_INVALID_ARGUMENT;
    } else if (request.state == NpRequestState::Aborted) {
        request.result = ORBIS_NP_ERROR_ABORTED;
        return ORBIS_NP_ERROR_ABORTED;
    }

    request.state = NpRequestState::Complete;
    if (!g_signed_in) {
        request.result = ORBIS_NP_ERROR_SIGNED_OUT;
        // If the request is processed in some form, and it's an async request, then it returns OK.
        if (request.async) {
            return ORBIS_OK;
        }
        return ORBIS_NP_ERROR_SIGNED_OUT;
    }

    LOG_ERROR(Lib_NpManager, "(STUBBED) called, req_id = {:#x}, is_async = {}", req_id,
              request.async);

    request.result = ORBIS_OK;
    return ORBIS_OK;
}

s32 PS4_SYSV_ABI sceNpCheckNpAvailabilityA(s32 req_id,
                                           Libraries::UserService::OrbisUserServiceUserId user_id) {
    std::scoped_lock lk{g_request_mutex};

    s32 req_index = req_id - ORBIS_NP_MANAGER_REQUEST_ID_OFFSET - 1;
    if (g_active_requests == 0 || g_requests.size() <= req_index ||
        g_requests[req_index].state == NpRequestState::None) {
        return ORBIS_NP_ERROR_REQUEST_NOT_FOUND;
    }

    auto& request = g_requests[req_index];
    if (request.state == NpRequestState::Complete) {
        request.result = ORBIS_NP_ERROR_INVALID_ARGUMENT;
        return ORBIS_NP_ERROR_INVALID_ARGUMENT;
    } else if (request.state == NpRequestState::Aborted) {
        request.result = ORBIS_NP_ERROR_ABORTED;
        return ORBIS_NP_ERROR_ABORTED;
    }

    request.state = NpRequestState::Complete;
    if (!g_signed_in) {
        request.result = ORBIS_NP_ERROR_SIGNED_OUT;
        // If the request is processed in some form, and it's an async request, then it returns OK.
        if (request.async) {
            return ORBIS_OK;
        }
        return ORBIS_NP_ERROR_SIGNED_OUT;
    }

    LOG_ERROR(Lib_NpManager, "(STUBBED) called, req_id = {:#x}, is_async = {}", req_id,
              request.async);

    request.result = ORBIS_OK;
    return ORBIS_OK;
}

s32 PS4_SYSV_ABI sceNpCheckNpReachability(s32 req_id,
                                          Libraries::UserService::OrbisUserServiceUserId user_id) {
    std::scoped_lock lk{g_request_mutex};

    s32 req_index = req_id - ORBIS_NP_MANAGER_REQUEST_ID_OFFSET - 1;
    if (g_active_requests == 0 || g_requests.size() <= req_index ||
        g_requests[req_index].state == NpRequestState::None) {
        return ORBIS_NP_ERROR_REQUEST_NOT_FOUND;
    }

    auto& request = g_requests[req_index];
    if (request.state == NpRequestState::Complete) {
        request.result = ORBIS_NP_ERROR_INVALID_ARGUMENT;
        return ORBIS_NP_ERROR_INVALID_ARGUMENT;
    } else if (request.state == NpRequestState::Aborted) {
        request.result = ORBIS_NP_ERROR_ABORTED;
        return ORBIS_NP_ERROR_ABORTED;
    }

    request.state = NpRequestState::Complete;
    if (!g_signed_in) {
        request.result = ORBIS_NP_ERROR_SIGNED_OUT;
        // If the request is processed in some form, and it's an async request, then it returns OK.
        if (request.async) {
            return ORBIS_OK;
        }
        return ORBIS_NP_ERROR_SIGNED_OUT;
    }

    LOG_ERROR(Lib_NpManager, "(STUBBED) called, req_id = {:#x}, is_async = {}", req_id,
              request.async);

    request.result = ORBIS_OK;
    return ORBIS_OK;
}

s32 PS4_SYSV_ABI sceNpCheckPlus(s32 req_id, const OrbisNpCheckPlusParameter* param,
                                OrbisNpCheckPlusResult* result) {

    if (req_id == 0 || param == nullptr || result == nullptr) {
        return ORBIS_NP_ERROR_INVALID_ARGUMENT;
    }

    if (param->size != sizeof(OrbisNpCheckPlusParameter)) {
        return ORBIS_NP_ERROR_INVALID_SIZE;
    }

    if (param->features < 1 || param->features > 3) {
        // TODO: If compiled SDK version is greater or equal to fw 3.50,
        // error if param->features != 1 instead.
        return ORBIS_NP_ERROR_INVALID_ARGUMENT;
    }

    std::scoped_lock lk{g_request_mutex};

    s32 req_index = req_id - ORBIS_NP_MANAGER_REQUEST_ID_OFFSET - 1;
    if (g_active_requests == 0 || g_requests.size() <= req_index ||
        g_requests[req_index].state == NpRequestState::None) {
        return ORBIS_NP_ERROR_REQUEST_NOT_FOUND;
    }

    auto& request = g_requests[req_index];
    if (request.state == NpRequestState::Complete) {
        request.result = ORBIS_NP_ERROR_INVALID_ARGUMENT;
        return ORBIS_NP_ERROR_INVALID_ARGUMENT;
    } else if (request.state == NpRequestState::Aborted) {
        request.result = ORBIS_NP_ERROR_ABORTED;
        return ORBIS_NP_ERROR_ABORTED;
    }

    request.state = NpRequestState::Complete;
    if (!g_signed_in) {
        request.result = ORBIS_NP_ERROR_SIGNED_OUT;
        // If the request is processed in some form, and it's an async request, then it returns OK.
        if (request.async) {
            return ORBIS_OK;
        }
        return ORBIS_NP_ERROR_SIGNED_OUT;
    }

    LOG_ERROR(Lib_NpManager,
              "(STUBBED) called, req_id = {:#x}, is_async = {}, param.features = {:#x}", req_id,
              request.async, param->features);

    // For now, set authorized to true to signal PS+ access.
    result->authorized = true;

    request.result = ORBIS_OK;
    return ORBIS_OK;
}

s32 PS4_SYSV_ABI sceNpGetAccountLanguage(s32 req_id, OrbisNpOnlineId* online_id,
                                         OrbisNpLanguageCode* language) {
    if (online_id == nullptr || language == nullptr) {
        return ORBIS_NP_ERROR_INVALID_ARGUMENT;
    }

    std::scoped_lock lk{g_request_mutex};

    s32 req_index = req_id - ORBIS_NP_MANAGER_REQUEST_ID_OFFSET - 1;
    if (g_active_requests == 0 || g_requests.size() <= req_index ||
        g_requests[req_index].state == NpRequestState::None) {
        return ORBIS_NP_ERROR_REQUEST_NOT_FOUND;
    }

    auto& request = g_requests[req_index];
    if (request.state == NpRequestState::Complete) {
        request.result = ORBIS_NP_ERROR_INVALID_ARGUMENT;
        return ORBIS_NP_ERROR_INVALID_ARGUMENT;
    } else if (request.state == NpRequestState::Aborted) {
        request.result = ORBIS_NP_ERROR_ABORTED;
        return ORBIS_NP_ERROR_ABORTED;
    }

    request.state = NpRequestState::Complete;
    if (!g_signed_in) {
        request.result = ORBIS_NP_ERROR_SIGNED_OUT;
        // If the request is processed in some form, and it's an async request, then it returns OK.
        if (request.async) {
            return ORBIS_OK;
        }
        return ORBIS_NP_ERROR_SIGNED_OUT;
    }

    LOG_ERROR(Lib_NpManager, "(STUBBED) called, req_id = {:#x}, is_async = {}", req_id,
              request.async);

    std::memset(language, 0, sizeof(OrbisNpLanguageCode));

    request.result = ORBIS_OK;
    return ORBIS_OK;
}

s32 PS4_SYSV_ABI sceNpGetAccountLanguageA(s32 req_id,
                                          Libraries::UserService::OrbisUserServiceUserId user_id,
                                          OrbisNpLanguageCode* language) {
    if (language == nullptr) {
        return ORBIS_NP_ERROR_INVALID_ARGUMENT;
    }

    std::scoped_lock lk{g_request_mutex};

    s32 req_index = req_id - ORBIS_NP_MANAGER_REQUEST_ID_OFFSET - 1;
    if (g_active_requests == 0 || g_requests.size() <= req_index ||
        g_requests[req_index].state == NpRequestState::None) {
        return ORBIS_NP_ERROR_REQUEST_NOT_FOUND;
    }

    auto& request = g_requests[req_index];
    if (request.state == NpRequestState::Complete) {
        request.result = ORBIS_NP_ERROR_INVALID_ARGUMENT;
        return ORBIS_NP_ERROR_INVALID_ARGUMENT;
    } else if (request.state == NpRequestState::Aborted) {
        request.result = ORBIS_NP_ERROR_ABORTED;
        return ORBIS_NP_ERROR_ABORTED;
    }

    request.state = NpRequestState::Complete;
    if (!g_signed_in) {
        request.result = ORBIS_NP_ERROR_SIGNED_OUT;
        // If the request is processed in some form, and it's an async request, then it returns OK.
        if (request.async) {
            return ORBIS_OK;
        }
        return ORBIS_NP_ERROR_SIGNED_OUT;
    }

    LOG_ERROR(Lib_NpManager, "(STUBBED) called, req_id = {:#x}, user_id = {}, is_async = {}",
              req_id, user_id, request.async);

    std::memset(language, 0, sizeof(OrbisNpLanguageCode));

    request.result = ORBIS_OK;
    return ORBIS_OK;
}

s32 PS4_SYSV_ABI sceNpGetParentalControlInfo(s32 req_id, OrbisNpOnlineId* online_id, s8* age,
                                             OrbisNpParentalControlInfo* info) {
    if (online_id == nullptr || age == nullptr || info == nullptr) {
        return ORBIS_NP_ERROR_INVALID_ARGUMENT;
    }

    std::scoped_lock lk{g_request_mutex};

    s32 req_index = req_id - ORBIS_NP_MANAGER_REQUEST_ID_OFFSET - 1;
    if (g_active_requests == 0 || g_requests.size() <= req_index ||
        g_requests[req_index].state == NpRequestState::None) {
        return ORBIS_NP_ERROR_REQUEST_NOT_FOUND;
    }

    auto& request = g_requests[req_index];
    if (request.state == NpRequestState::Complete) {
        request.result = ORBIS_NP_ERROR_INVALID_ARGUMENT;
        return ORBIS_NP_ERROR_INVALID_ARGUMENT;
    } else if (request.state == NpRequestState::Aborted) {
        request.result = ORBIS_NP_ERROR_ABORTED;
        return ORBIS_NP_ERROR_ABORTED;
    }

    request.state = NpRequestState::Complete;
    if (!g_signed_in) {
        request.result = ORBIS_NP_ERROR_SIGNED_OUT;
        // If the request is processed in some form, and it's an async request, then it returns OK.
        if (request.async) {
            return ORBIS_OK;
        }
        return ORBIS_NP_ERROR_SIGNED_OUT;
    }

    LOG_ERROR(Lib_NpManager, "(STUBBED) called, req_id = {:#x}, is_async = {}", req_id,
              request.async);

    // TODO: Add to config?
    *age = 13;
    std::memset(info, 0, sizeof(OrbisNpParentalControlInfo));

    request.result = ORBIS_OK;
    return ORBIS_OK;
}

s32 PS4_SYSV_ABI
sceNpGetParentalControlInfoA(s32 req_id, Libraries::UserService::OrbisUserServiceUserId user_id,
                             s8* age, OrbisNpParentalControlInfo* info) {
    if (age == nullptr || info == nullptr) {
        return ORBIS_NP_ERROR_INVALID_ARGUMENT;
    }

    std::scoped_lock lk{g_request_mutex};

    s32 req_index = req_id - ORBIS_NP_MANAGER_REQUEST_ID_OFFSET - 1;
    if (g_active_requests == 0 || g_requests.size() <= req_index ||
        g_requests[req_index].state == NpRequestState::None) {
        return ORBIS_NP_ERROR_REQUEST_NOT_FOUND;
    }

    auto& request = g_requests[req_index];
    if (request.state == NpRequestState::Complete) {
        request.result = ORBIS_NP_ERROR_INVALID_ARGUMENT;
        return ORBIS_NP_ERROR_INVALID_ARGUMENT;
    } else if (request.state == NpRequestState::Aborted) {
        request.result = ORBIS_NP_ERROR_ABORTED;
        return ORBIS_NP_ERROR_ABORTED;
    }

    request.state = NpRequestState::Complete;
    if (!g_signed_in) {
        request.result = ORBIS_NP_ERROR_SIGNED_OUT;
        // If the request is processed in some form, and it's an async request, then it returns OK.
        if (request.async) {
            return ORBIS_OK;
        }
        return ORBIS_NP_ERROR_SIGNED_OUT;
    }

    LOG_ERROR(Lib_NpManager, "(STUBBED) called, req_id = {:#x}, user_id = {}, is_async = {}",
              req_id, user_id, request.async);

    // TODO: Add to config?
    *age = 13;
    std::memset(info, 0, sizeof(OrbisNpParentalControlInfo));

    request.result = ORBIS_OK;
    return ORBIS_OK;
}

s32 PS4_SYSV_ABI sceNpAbortRequest(s32 req_id) {
    LOG_DEBUG(Lib_NpManager, "called req_id = {:#x}", req_id);

    std::scoped_lock lk{g_request_mutex};

    s32 req_index = req_id - ORBIS_NP_MANAGER_REQUEST_ID_OFFSET - 1;
    if (g_active_requests == 0 || g_requests.size() <= req_index ||
        g_requests[req_index].state == NpRequestState::None) {
        return ORBIS_NP_ERROR_REQUEST_NOT_FOUND;
    }

    if (g_requests[req_index].state == NpRequestState::Complete) {
        // If the request is already complete, abort is ignored.
        return ORBIS_OK;
    }

    g_requests[req_index].state = NpRequestState::Aborted;
    return ORBIS_OK;
}

s32 PS4_SYSV_ABI sceNpWaitAsync(s32 req_id, s32* result) {
    if (result == nullptr) {
        return ORBIS_NP_ERROR_INVALID_ARGUMENT;
    }

    std::scoped_lock lk{g_request_mutex};

    s32 req_index = req_id - ORBIS_NP_MANAGER_REQUEST_ID_OFFSET - 1;
    if (g_active_requests == 0 || g_requests.size() <= req_index ||
        g_requests[req_index].state == NpRequestState::None) {
        return ORBIS_NP_ERROR_REQUEST_NOT_FOUND;
    }

    if (!g_requests[req_index].async || g_requests[req_index].state == NpRequestState::Ready) {
        return ORBIS_NP_ERROR_INVALID_ID;
    }

    // Since we're not actually performing any sort of network request here,
    // we can just set result based on the request and return.
    *result = g_requests[req_index].result;
    LOG_WARNING(Lib_NpManager, "called req_id = {:#x}, returning result = {:#x}", req_id,
                static_cast<u32>(*result));
    return ORBIS_OK;
}

s32 PS4_SYSV_ABI sceNpPollAsync(s32 req_id, s32* result) {
    if (result == nullptr) {
        return ORBIS_NP_ERROR_INVALID_ARGUMENT;
    }

    std::scoped_lock lk{g_request_mutex};

    s32 req_index = req_id - ORBIS_NP_MANAGER_REQUEST_ID_OFFSET - 1;
    if (g_active_requests == 0 || g_requests.size() <= req_index ||
        g_requests[req_index].state == NpRequestState::None) {
        return ORBIS_NP_ERROR_REQUEST_NOT_FOUND;
    }

    if (!g_requests[req_index].async || g_requests[req_index].state == NpRequestState::Ready) {
        return ORBIS_NP_ERROR_INVALID_ID;
    }

    // Since we're not actually performing any sort of network request here,
    // we can just set result based on the request and return.
    *result = g_requests[req_index].result;
    LOG_WARNING(Lib_NpManager, "called req_id = {:#x}, returning result = {:#x}", req_id,
                static_cast<u32>(*result));
    return ORBIS_OK;
}

s32 PS4_SYSV_ABI sceNpDeleteRequest(s32 req_id) {
    LOG_DEBUG(Lib_NpManager, "called req_id = {:#x}", req_id);

    std::scoped_lock lk{g_request_mutex};

    s32 req_index = req_id - ORBIS_NP_MANAGER_REQUEST_ID_OFFSET - 1;
    if (g_active_requests == 0 || g_requests.size() <= req_index ||
        g_requests[req_index].state == NpRequestState::None) {
        return ORBIS_NP_ERROR_REQUEST_NOT_FOUND;
    }

    g_active_requests--;
    g_requests[req_index].state = NpRequestState::None;
    return ORBIS_OK;
}

s32 PS4_SYSV_ABI sceNpGetAccountCountry(OrbisNpOnlineId* online_id,
                                        OrbisNpCountryCode* country_code) {
    if (online_id == nullptr || country_code == nullptr) {
        return ORBIS_NP_ERROR_INVALID_ARGUMENT;
    }
    if (!g_signed_in) {
        return ORBIS_NP_ERROR_SIGNED_OUT;
    }
    std::memset(country_code, 0, sizeof(OrbisNpCountryCode));
    // TODO: get NP country code from config
    std::memcpy(country_code->country_code, "us", 2);
    return ORBIS_OK;
}

s32 PS4_SYSV_ABI sceNpGetAccountCountryA(Libraries::UserService::OrbisUserServiceUserId user_id,
                                         OrbisNpCountryCode* country_code) {
    if (country_code == nullptr) {
        return ORBIS_NP_ERROR_INVALID_ARGUMENT;
    }
    if (!g_signed_in) {
        return ORBIS_NP_ERROR_SIGNED_OUT;
    }
    std::memset(country_code, 0, sizeof(OrbisNpCountryCode));
    // TODO: get NP country code from config
    std::memcpy(country_code->country_code, "us", 2);
    return ORBIS_OK;
}

s32 PS4_SYSV_ABI sceNpGetAccountDateOfBirth(OrbisNpOnlineId* online_id,
                                            OrbisNpDate* date_of_birth) {
    if (online_id == nullptr || date_of_birth == nullptr) {
        return ORBIS_NP_ERROR_INVALID_ARGUMENT;
    }
    if (!g_signed_in) {
        return ORBIS_NP_ERROR_SIGNED_OUT;
    }

    // TODO: maybe add to config?
    date_of_birth->day = 1;
    date_of_birth->month = 1;
    date_of_birth->year = 2000;
    return ORBIS_OK;
}

s32 PS4_SYSV_ABI sceNpGetAccountDateOfBirthA(Libraries::UserService::OrbisUserServiceUserId user_id,
                                             OrbisNpDate* date_of_birth) {
    if (date_of_birth == nullptr) {
        return ORBIS_NP_ERROR_INVALID_ARGUMENT;
    }
    if (!g_signed_in) {
        return ORBIS_NP_ERROR_SIGNED_OUT;
    }

    // TODO: maybe add to config?
    date_of_birth->day = 1;
    date_of_birth->month = 1;
    date_of_birth->year = 2000;
    return ORBIS_OK;
}

s32 PS4_SYSV_ABI sceNpGetGamePresenceStatus(OrbisNpOnlineId* online_id,
                                            OrbisNpGamePresenseStatus* game_status) {
    if (online_id == nullptr || game_status == nullptr) {
        return ORBIS_NP_ERROR_INVALID_ARGUMENT;
    }

    *game_status =
        g_signed_in ? OrbisNpGamePresenseStatus::Online : OrbisNpGamePresenseStatus::Offline;
    return ORBIS_OK;
}

s32 PS4_SYSV_ABI sceNpGetGamePresenceStatusA(Libraries::UserService::OrbisUserServiceUserId user_id,
                                             OrbisNpGamePresenseStatus* game_status) {
    if (game_status == nullptr) {
        return ORBIS_NP_ERROR_INVALID_ARGUMENT;
    }

    *game_status =
        g_signed_in ? OrbisNpGamePresenseStatus::Online : OrbisNpGamePresenseStatus::Offline;
    return ORBIS_OK;
}

s32 PS4_SYSV_ABI sceNpGetAccountId(OrbisNpOnlineId* online_id, u64* account_id) {
    LOG_DEBUG(Lib_NpManager, "called");
    if (online_id == nullptr || account_id == nullptr) {
        return ORBIS_NP_ERROR_INVALID_ARGUMENT;
    }
    if (!g_signed_in) {
        *account_id = 0;
        return ORBIS_NP_ERROR_SIGNED_OUT;
    }
    *account_id = 0xFEEDFACE;
    return ORBIS_OK;
}

s32 PS4_SYSV_ABI sceNpGetAccountIdA(Libraries::UserService::OrbisUserServiceUserId user_id,
                                    u64* account_id) {
    LOG_DEBUG(Lib_NpManager, "user_id {}", user_id);
    if (account_id == nullptr) {
        return ORBIS_NP_ERROR_INVALID_ARGUMENT;
    }
    if (!g_signed_in) {
        *account_id = 0;
        return ORBIS_NP_ERROR_SIGNED_OUT;
    }
    *account_id = 0xFEEDFACE;
    return ORBIS_OK;
}

s32 PS4_SYSV_ABI sceNpGetNpId(Libraries::UserService::OrbisUserServiceUserId user_id,
                              OrbisNpId* np_id) {
    LOG_DEBUG(Lib_NpManager, "user_id {}", user_id);
    if (np_id == nullptr) {
        return ORBIS_NP_ERROR_INVALID_ARGUMENT;
    }
    if (!g_signed_in) {
        return ORBIS_NP_ERROR_SIGNED_OUT;
    }
    memset(np_id, 0, sizeof(OrbisNpId));
    strncpy(np_id->handle.data, Config::getUserName().c_str(), sizeof(np_id->handle.data));
    return ORBIS_OK;
}

s32 PS4_SYSV_ABI sceNpGetOnlineId(Libraries::UserService::OrbisUserServiceUserId user_id,
                                  OrbisNpOnlineId* online_id) {
    LOG_DEBUG(Lib_NpManager, "user_id {}", user_id);
    if (online_id == nullptr) {
        return ORBIS_NP_ERROR_INVALID_ARGUMENT;
    }
    if (!g_signed_in) {
        return ORBIS_NP_ERROR_SIGNED_OUT;
    }
    memset(online_id, 0, sizeof(OrbisNpOnlineId));
    strncpy(online_id->data, Config::getUserName().c_str(), sizeof(online_id->data));
    return ORBIS_OK;
}

s32 PS4_SYSV_ABI sceNpGetNpReachabilityState(Libraries::UserService::OrbisUserServiceUserId user_id,
                                             OrbisNpReachabilityState* state) {
    if (state == nullptr) {
        return ORBIS_NP_ERROR_INVALID_ARGUMENT;
    }

    *state =
        g_signed_in ? OrbisNpReachabilityState::Reachable : OrbisNpReachabilityState::Unavailable;
    return ORBIS_OK;
}

s32 PS4_SYSV_ABI sceNpGetState(Libraries::UserService::OrbisUserServiceUserId user_id,
                               OrbisNpState* state) {
    if (state == nullptr) {
        return ORBIS_NP_ERROR_INVALID_ARGUMENT;
    }
    *state = g_signed_in ? OrbisNpState::SignedIn : OrbisNpState::SignedOut;
    LOG_DEBUG(Lib_NpManager, "Signed {}", g_signed_in ? "in" : "out");
    return ORBIS_OK;
}

s32 PS4_SYSV_ABI
sceNpGetUserIdByAccountId(u64 account_id, Libraries::UserService::OrbisUserServiceUserId* user_id) {
    if (user_id == nullptr) {
        return ORBIS_NP_ERROR_INVALID_ARGUMENT;
    }
    if (!g_signed_in) {
        return ORBIS_NP_ERROR_SIGNED_OUT;
    }
    *user_id = 1;
    LOG_DEBUG(Lib_NpManager, "userid({}) = {}", account_id, *user_id);
    return ORBIS_OK;
}

s32 PS4_SYSV_ABI sceNpHasSignedUp(Libraries::UserService::OrbisUserServiceUserId user_id,
                                  bool* has_signed_up) {
    LOG_DEBUG(Lib_NpManager, "called");
    if (has_signed_up == nullptr) {
        return ORBIS_NP_ERROR_INVALID_ARGUMENT;
    }
    *has_signed_up = g_signed_in ? true : false;
    return ORBIS_OK;
}

struct NpStateCallbackForNpToolkit {
    OrbisNpStateCallbackForNpToolkit func;
    void* userdata;
};

NpStateCallbackForNpToolkit NpStateCbForNp;

// sceNpRegisterStateCallback stores a 4-arg callback.
struct NpStateCallbackInfo {
    OrbisNpStateCallback func = nullptr;
    void* userdata = nullptr;
};

static NpStateCallbackInfo g_np_state_callback;
static bool g_np_callback_dispatched = false;

// PS Plus event callback (registered via sceNpRegisterPlusEventCallback).
// On real PS4, sceNpNotifyPlusFeature triggers the system to check Plus status
// and fire this callback. Games gate multiplayer features behind this callback.
using OrbisNpPlusEventCallback = PS4_SYSV_ABI void (*)(
    Libraries::UserService::OrbisUserServiceUserId userId, s32 event, void* userdata);

struct NpPlusCallbackInfo {
    OrbisNpPlusEventCallback func = nullptr;
    void* userdata = nullptr;
};

static NpPlusCallbackInfo g_plus_callback;
static bool g_plus_callback_dispatched = false;

// --- PS Plus Feature Support ---
// sceNpNotifyPlusFeature declares required Plus features. The system checks
// Plus status and fires the callback from sceNpRegisterPlusEventCallback.
// Games may gate multiplayer behind this callback.

struct OrbisNpNotifyPlusFeatureParameter {
    u64 size;
    Libraries::UserService::OrbisUserServiceUserId user_id;
    u8 padding[4];
    u64 features;
    u8 reserved[32];
};

s32 PS4_SYSV_ABI sceNpRegisterPlusEventCallback(OrbisNpPlusEventCallback callback, void* userdata) {
    LOG_INFO(Lib_NpManager, "called callback={:p} userdata={:p}", reinterpret_cast<void*>(callback),
             userdata);
    g_plus_callback.func = callback;
    g_plus_callback.userdata = userdata;
    g_plus_callback_dispatched = false;
    return ORBIS_OK;
}

s32 PS4_SYSV_ABI sceNpUnregisterPlusEventCallback() {
    LOG_INFO(Lib_NpManager, "called");
    g_plus_callback.func = nullptr;
    g_plus_callback.userdata = nullptr;
    return ORBIS_OK;
}

s32 PS4_SYSV_ABI sceNpNotifyPlusFeature(const OrbisNpNotifyPlusFeatureParameter* param) {
    LOG_INFO(Lib_NpManager, "called features={:#x}", param ? param->features : 0);
    // Mark that Plus notification was requested; callback fires from sceNpCheckCallback.
    g_plus_callback_dispatched = false;
    return ORBIS_OK;
}

struct NpStateCallback {
    std::variant<OrbisNpStateCallback, OrbisNpStateCallbackA> func;
    void* userdata;
};

NpStateCallback NpStateCb;

s32 PS4_SYSV_ABI sceNpCheckCallback() {
    // Dispatch the registered NP state callback once when signed in.
    // On real hardware, firmware dispatches this on NP state changes.
    // We fire it on the first call after sign-in so games detect the transition.
    if (!g_np_callback_dispatched && g_signed_in && g_np_state_callback.func) {
        g_np_callback_dispatched = true;

        // Get initial user ID for the callback.
        Libraries::UserService::OrbisUserServiceUserId userId = 1;
        Libraries::UserService::sceUserServiceGetInitialUser(&userId);

        LOG_INFO(Lib_NpManager,
                 "sceNpCheckCallback: dispatching NP state callback "
                 "(userId={}, state=SignedIn, userdata={:p})",
                 userId, g_np_state_callback.userdata);
        g_np_state_callback.func(userId, OrbisNpState::SignedIn, nullptr,
                                 g_np_state_callback.userdata);
        LOG_INFO(Lib_NpManager, "sceNpCheckCallback: NP state callback returned");
    }

    // Dispatch Plus event callback after state callback has been delivered.
    // Event type 1 (ORBIS_NP_PLUS_EVENT_RECHECK_NEEDED) tells the game to
    // re-check Plus status via sceNpCheckPlus.
    if (!g_plus_callback_dispatched && g_np_callback_dispatched && g_signed_in &&
        g_plus_callback.func) {
        g_plus_callback_dispatched = true;

        Libraries::UserService::OrbisUserServiceUserId userId = 1;
        Libraries::UserService::sceUserServiceGetInitialUser(&userId);

        constexpr s32 ORBIS_NP_PLUS_EVENT_RECHECK_NEEDED = 1;
        LOG_INFO(Lib_NpManager,
                 "sceNpCheckCallback: dispatching Plus event callback "
                 "(userId={}, event=RECHECK_NEEDED, userdata={:p})",
                 userId, g_plus_callback.userdata);
        g_plus_callback.func(userId, ORBIS_NP_PLUS_EVENT_RECHECK_NEEDED, g_plus_callback.userdata);
        LOG_INFO(Lib_NpManager, "sceNpCheckCallback: Plus event callback returned");
    }

    // Drain NpMatching2 first, then NpSignaling (matching must complete before signaling).
    NpMatching2::DrainReadyEvents();
    NpSignaling::DrainSignalingEvents();

    // Process any registered NP callbacks.
    {
        std::scoped_lock lk{g_np_callbacks_mutex};
        for (auto i : g_np_callbacks) {
            (i.second)();
        }
    }

    return ORBIS_OK;
}

s32 PS4_SYSV_ABI sceNpCheckCallbackForLib() {
    LOG_DEBUG(Lib_NpManager, "(STUBBED) called");
    return ORBIS_OK;
}

s32 PS4_SYSV_ABI sceNpRegisterStateCallback(OrbisNpStateCallback callback, void* userdata) {
    LOG_INFO(Lib_NpManager, "called callback={:p} userdata={:p}", reinterpret_cast<void*>(callback),
             userdata);
    NpStateCb.func = callback;
    NpStateCb.userdata = userdata;
    g_np_state_callback.func = callback;
    g_np_state_callback.userdata = userdata;
    g_np_callback_dispatched = false; // reset so callback fires on next sceNpCheckCallback
    return ORBIS_OK;
}

s32 PS4_SYSV_ABI sceNpRegisterStateCallbackA(OrbisNpStateCallbackA callback, void* userdata) {
    static s32 id = 0;
    LOG_ERROR(Lib_NpManager, "(STUBBED) called, userdata = {}", userdata);
    NpStateCb.func = callback;
    NpStateCb.userdata = userdata;

    return id;
}

struct NpReachabilityStateCallback {
    OrbisNpReachabilityStateCallback func;
    void* userdata;
};

NpReachabilityStateCallback NpReachabilityCb;

s32 PS4_SYSV_ABI sceNpRegisterNpReachabilityStateCallback(OrbisNpReachabilityStateCallback callback,
                                                          void* userdata) {
    static s32 id = 0;
    LOG_ERROR(Lib_NpManager, "(STUBBED) called");
    NpReachabilityCb.func = callback;
    NpReachabilityCb.userdata = userdata;
    return id;
}

s32 PS4_SYSV_ABI sceNpRegisterStateCallbackForToolkit(OrbisNpStateCallbackForNpToolkit callback,
                                                      void* userdata) {
    static s32 id = 0;
    LOG_ERROR(Lib_NpManager, "(STUBBED) called");
    NpStateCbForNp.func = callback;
    NpStateCbForNp.userdata = userdata;
    return id;
}

void RegisterNpCallback(std::string key, std::function<void()> cb) {
    std::scoped_lock lk{g_np_callbacks_mutex};

    LOG_DEBUG(Lib_NpManager, "registering callback processing for {}", key);

    g_np_callbacks.emplace(key, cb);
}

void DeregisterNpCallback(std::string key) {
    std::scoped_lock lk{g_np_callbacks_mutex};

    LOG_DEBUG(Lib_NpManager, "deregistering callback processing for {}", key);

    g_np_callbacks.erase(key);
}

// --- sceNpLookup* HLE ---
// Used during connection setup to resolve peer NpIds.
// Flow: CreateAsyncRequest + NpId (start lookup)
//       PollAsync (check completion)
//       DeleteRequest (cleanup)

static std::atomic<s32> s_next_lookup_handle{1};
static std::unordered_set<s32> s_completed_lookups;
static std::mutex s_lookup_mutex;

s32 PS4_SYSV_ABI sceNpLookupCreateTitleCtx(s32 titleId, void* npId, void* param) {
    // Returns a valid title context ID for use with sceNpLookupCreateAsyncRequest.
    LOG_INFO(Lib_NpManager, "called titleId={} npId={} param={}", titleId, npId, param);
    return 1;
}

s32 PS4_SYSV_ABI sceNpLookupCreateAsyncRequest(s32 titleCtxId, void* param) {
    // Creates an async lookup request. Returns a positive request handle.
    s32 handle = s_next_lookup_handle++;
    LOG_INFO(Lib_NpManager, "titleCtxId={} param={} -> handle={}", titleCtxId, param, handle);
    return handle;
}

s32 PS4_SYSV_ABI sceNpLookupNpId(s32 requestHandle, const char* onlineIdStr, void* npIdOut,
                                 s32 option) {
    // Resolves an online ID string to an NpId struct (36 bytes).
    // NpId layout: online_id[16], padding[4], opt[8], reserved[8].
    LOG_INFO(Lib_NpManager, "handle={} onlineId='{}' option={}", requestHandle,
             onlineIdStr ? onlineIdStr : "null", option);

    if (npIdOut) {
        std::memset(npIdOut, 0, 36);
        if (onlineIdStr) {
            std::strncpy(static_cast<char*>(npIdOut), onlineIdStr, 15);
        }
    }

    // Mark request as immediately complete (synchronous resolution for local peers)
    {
        std::lock_guard lock(s_lookup_mutex);
        s_completed_lookups.insert(requestHandle);
    }

    return ORBIS_OK;
}

s32 PS4_SYSV_ABI sceNpLookupPollAsync(s32 requestHandle, s32* result) {
    // Returns 0 if completed, 1 if still pending. *result >= 0 on success.
    LOG_INFO(Lib_NpManager, "handle={}", requestHandle);

    if (result) {
        *result = 0; // success
    }

    return 0; // completed
}

s32 PS4_SYSV_ABI sceNpLookupDeleteRequest(s32 requestHandle) {
    // Cleanup after successful poll.
    LOG_INFO(Lib_NpManager, "handle={}", requestHandle);
    {
        std::lock_guard lock(s_lookup_mutex);
        s_completed_lookups.erase(requestHandle);
    }
    return ORBIS_OK;
}

s32 PS4_SYSV_ABI sceNpLookupDeleteTitleCtx(s32 titleCtxId) {
    LOG_INFO(Lib_NpManager, "called titleCtxId={}", titleCtxId);
    return ORBIS_OK;
}

s32 PS4_SYSV_ABI sceNpLookupAbortRequest(s32 requestHandle) {
    LOG_INFO(Lib_NpManager, "called handle={}", requestHandle);
    return ORBIS_OK;
}

s32 PS4_SYSV_ABI sceNpLookupWaitAsync(s32 requestHandle, s32* result) {
    LOG_INFO(Lib_NpManager, "handle={}", requestHandle);
    if (result) {
        *result = 0;
    }
    return ORBIS_OK;
}

s32 PS4_SYSV_ABI sceNpLookupCreateRequest(s32 titleCtxId, void* param) {
    s32 handle = s_next_lookup_handle++;
    LOG_INFO(Lib_NpManager, "titleCtxId={} -> handle={}", titleCtxId, handle);
    return handle;
}

s32 PS4_SYSV_ABI sceNpLookupSetTimeout(s32 requestHandle, s32 timeout) {
    LOG_INFO(Lib_NpManager, "handle={} timeout={}", requestHandle, timeout);
    return ORBIS_OK;
}

void RegisterLib(Core::Loader::SymbolsResolver* sym) {
    g_signed_in = Config::getPSNSignedIn();

    LIB_FUNCTION("GpLQDNKICac", "libSceNpManager", 1, "libSceNpManager", sceNpCreateRequest);
    LIB_FUNCTION("eiqMCt9UshI", "libSceNpManager", 1, "libSceNpManager", sceNpCreateAsyncRequest);
    LIB_FUNCTION("2rsFmlGWleQ", "libSceNpManager", 1, "libSceNpManager", sceNpCheckNpAvailability);
    LIB_FUNCTION("8Z2Jc5GvGDI", "libSceNpManager", 1, "libSceNpManager", sceNpCheckNpAvailabilityA);
    LIB_FUNCTION("KfGZg2y73oM", "libSceNpManager", 1, "libSceNpManager", sceNpCheckNpReachability);
    LIB_FUNCTION("r6MyYJkryz8", "libSceNpManager", 1, "libSceNpManager", sceNpCheckPlus);
    LIB_FUNCTION("Gaxrp3EWY-M", "libSceNpManager", 1, "libSceNpManager", sceNpNotifyPlusFeature);
    LIB_FUNCTION("GImICnh+boA", "libSceNpManager", 1, "libSceNpManager",
                 sceNpRegisterPlusEventCallback);
    LIB_FUNCTION("xViqJdDgKl0", "libSceNpManager", 1, "libSceNpManager",
                 sceNpUnregisterPlusEventCallback);
    LIB_FUNCTION("KZ1Mj9yEGYc", "libSceNpManager", 1, "libSceNpManager", sceNpGetAccountLanguage);
    LIB_FUNCTION("TPMbgIxvog0", "libSceNpManager", 1, "libSceNpManager", sceNpGetAccountLanguageA);
    LIB_FUNCTION("ilwLM4zOmu4", "libSceNpManager", 1, "libSceNpManager",
                 sceNpGetParentalControlInfo);
    LIB_FUNCTION("m9L3O6yst-U", "libSceNpManager", 1, "libSceNpManager",
                 sceNpGetParentalControlInfoA);
    LIB_FUNCTION("OzKvTvg3ZYU", "libSceNpManager", 1, "libSceNpManager", sceNpAbortRequest);
    LIB_FUNCTION("jyi5p9XWUSs", "libSceNpManager", 1, "libSceNpManager", sceNpWaitAsync);
    LIB_FUNCTION("uqcPJLWL08M", "libSceNpManager", 1, "libSceNpManager", sceNpPollAsync);
    LIB_FUNCTION("S7QTn72PrDw", "libSceNpManager", 1, "libSceNpManager", sceNpDeleteRequest);

    LIB_FUNCTION("Ghz9iWDUtC4", "libSceNpManager", 1, "libSceNpManager", sceNpGetAccountCountry);
    LIB_FUNCTION("JT+t00a3TxA", "libSceNpManager", 1, "libSceNpManager", sceNpGetAccountCountryA);
    LIB_FUNCTION("8VBTeRf1ZwI", "libSceNpManager", 1, "libSceNpManager",
                 sceNpGetAccountDateOfBirth);
    LIB_FUNCTION("q3M7XzBKC3s", "libSceNpManager", 1, "libSceNpManager",
                 sceNpGetAccountDateOfBirthA);
    LIB_FUNCTION("IPb1hd1wAGc", "libSceNpManager", 1, "libSceNpManager",
                 sceNpGetGamePresenceStatus);
    LIB_FUNCTION("oPO9U42YpgI", "libSceNpManager", 1, "libSceNpManager",
                 sceNpGetGamePresenceStatusA);
    LIB_FUNCTION("e-ZuhGEoeC4", "libSceNpManager", 1, "libSceNpManager",
                 sceNpGetNpReachabilityState);

    LIB_FUNCTION("a8R9-75u4iM", "libSceNpManager", 1, "libSceNpManager", sceNpGetAccountId);
    LIB_FUNCTION("rbknaUjpqWo", "libSceNpManager", 1, "libSceNpManager", sceNpGetAccountIdA);
    LIB_FUNCTION("p-o74CnoNzY", "libSceNpManager", 1, "libSceNpManager", sceNpGetNpId);
    LIB_FUNCTION("XDncXQIJUSk", "libSceNpManager", 1, "libSceNpManager", sceNpGetOnlineId);
    LIB_FUNCTION("eQH7nWPcAgc", "libSceNpManager", 1, "libSceNpManager", sceNpGetState);
    LIB_FUNCTION("VgYczPGB5ss", "libSceNpManager", 1, "libSceNpManager", sceNpGetUserIdByAccountId);
    LIB_FUNCTION("Oad3rvY-NJQ", "libSceNpManager", 1, "libSceNpManager", sceNpHasSignedUp);
    LIB_FUNCTION("3Zl8BePTh9Y", "libSceNpManager", 1, "libSceNpManager", sceNpCheckCallback);
    LIB_FUNCTION("JELHf4xPufo", "libSceNpManager", 1, "libSceNpManager", sceNpCheckCallbackForLib);
    LIB_FUNCTION("VfRSmPmj8Q8", "libSceNpManager", 1, "libSceNpManager",
                 sceNpRegisterStateCallback);
    LIB_FUNCTION("hw5KNqAAels", "libSceNpManager", 1, "libSceNpManager",
                 sceNpRegisterNpReachabilityStateCallback);
    LIB_FUNCTION("JELHf4xPufo", "libSceNpManagerForToolkit", 1, "libSceNpManager",
                 sceNpCheckCallbackForLib);
    LIB_FUNCTION("0c7HbXRKUt4", "libSceNpManagerForToolkit", 1, "libSceNpManager",
                 sceNpRegisterStateCallbackForToolkit);

    // --- sceNpLookup* registrations (imported from libSceNpUtility) ---
    LIB_FUNCTION("8533Q+LU7EQ", "libSceNpUtility", 1, "libSceNpUtility", sceNpLookupCreateTitleCtx);
    LIB_FUNCTION("JA4+sS39GMs", "libSceNpUtility", 1, "libSceNpUtility",
                 sceNpLookupCreateAsyncRequest);
    LIB_FUNCTION("T6tnM1Uti4g", "libSceNpUtility", 1, "libSceNpUtility", sceNpLookupNpId);
    LIB_FUNCTION("V4EVrruHuy8", "libSceNpUtility", 1, "libSceNpUtility", sceNpLookupPollAsync);
    LIB_FUNCTION("wLaxchvEEnk", "libSceNpUtility", 1, "libSceNpUtility", sceNpLookupDeleteRequest);
    LIB_FUNCTION("mtqDK9zkoIE", "libSceNpUtility", 1, "libSceNpUtility", sceNpLookupDeleteTitleCtx);
    LIB_FUNCTION("eYz4v5Uek9U", "libSceNpUtility", 1, "libSceNpUtility", sceNpLookupAbortRequest);
    LIB_FUNCTION("YX9dAus6baE", "libSceNpUtility", 1, "libSceNpUtility", sceNpLookupWaitAsync);
    LIB_FUNCTION("iQr9UxPHUFs", "libSceNpUtility", 1, "libSceNpUtility", sceNpLookupCreateRequest);
    LIB_FUNCTION("0MV72WO7V34", "libSceNpUtility", 1, "libSceNpUtility", sceNpLookupSetTimeout);

    LIB_FUNCTION("2rsFmlGWleQ", "libSceNpManagerCompat", 1, "libSceNpManager",
                 sceNpCheckNpAvailability);
    LIB_FUNCTION("a8R9-75u4iM", "libSceNpManagerCompat", 1, "libSceNpManager", sceNpGetAccountId);
    LIB_FUNCTION("KZ1Mj9yEGYc", "libSceNpManagerCompat", 1, "libSceNpManager",
                 sceNpGetAccountLanguage);
    LIB_FUNCTION("Ghz9iWDUtC4", "libSceNpManagerCompat", 1, "libSceNpManager",
                 sceNpGetAccountCountry);
    LIB_FUNCTION("8VBTeRf1ZwI", "libSceNpManagerCompat", 1, "libSceNpManager",
                 sceNpGetAccountDateOfBirth);
    LIB_FUNCTION("IPb1hd1wAGc", "libSceNpManagerCompat", 1, "libSceNpManager",
                 sceNpGetGamePresenceStatus);
    LIB_FUNCTION("ilwLM4zOmu4", "libSceNpManagerCompat", 1, "libSceNpManager",
                 sceNpGetParentalControlInfo);
};

} // namespace Libraries::Np::NpManager
