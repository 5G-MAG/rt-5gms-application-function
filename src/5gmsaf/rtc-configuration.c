/*
 * License: 5G-MAG Public License (v1.0)
 * Author: Nils Duval <nils.duval@motionspell.com>
 * Copyright: (C) 2026 Motion Spell
 *
 * For full license terms please see the LICENSE file distributed with this
 * program. If this file is missing then the license can be retrieved from
 * https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
 */

#include "ogs-core.h"

#include "openapi/model/msaf_api_rtc_configuration.h"
#include "provisioning-session.h"
#include "hash.h"

#include "rtc-configuration.h"

bool msaf_rtc_configuration_register(msaf_provisioning_session_t *session /* [no-transfer, not-null] */,
                                                  msaf_api_rtc_configuration_t *config /* [transfer, not-null] */)
{
    char *body;

    ogs_assert(session);
    ogs_assert(config);

    if (session->rtcConfiguration) return false;

    session->rtcConfiguration = config;

    body = msaf_rtc_configuration_body(session);
    session->httpMetadata.rtcConfiguration.hash = calculate_hash(body);
    ogs_free(body);

    time(&session->httpMetadata.rtcConfiguration.received);

    msaf_sai_cache_clear(session->sai_cache);

    return true;
}

bool msaf_rtc_configuration_update(msaf_provisioning_session_t *session /* [no-transfer, not-null] */,
                                                msaf_api_rtc_configuration_t *config /* [transfer, not-null] */)
{
    char *body;

    ogs_assert(session);
    ogs_assert(config);

    if (!session->rtcConfiguration) return false;

    msaf_api_rtc_configuration_free(session->rtcConfiguration);

    if (session->httpMetadata.rtcConfiguration.hash) {
        ogs_free(session->httpMetadata.rtcConfiguration.hash);
    }

    session->rtcConfiguration = config;

    body = msaf_rtc_configuration_body(session);
    session->httpMetadata.rtcConfiguration.hash = calculate_hash(body);
    ogs_free(body);

    time(&session->httpMetadata.rtcConfiguration.received);

    msaf_sai_cache_clear(session->sai_cache);

    return true;
}

bool msaf_rtc_configuration_deregister(msaf_provisioning_session_t *session /* [no-transfer, not-null] */)
{
    ogs_assert(session);

    if (!session->rtcConfiguration) return false;

    msaf_api_rtc_configuration_free(session->rtcConfiguration);
    session->rtcConfiguration = NULL;

    if (session->httpMetadata.rtcConfiguration.hash) {
        ogs_free(session->httpMetadata.rtcConfiguration.hash);
        session->httpMetadata.rtcConfiguration.hash = NULL;
    }

    session->httpMetadata.rtcConfiguration.received = 0;

    msaf_sai_cache_clear(session->sai_cache);

    return true;
}

msaf_api_rtc_configuration_t *msaf_rtc_configuration_parseJSON(cJSON *json /* [no-transfer, not-null] */, const char **err_out /* [out, not-null] */, char **err_param /* [out, transfer, not-null] */)
{
    msaf_api_rtc_configuration_t *rtc_config;

    *err_out = NULL;
    *err_param = NULL;

    rtc_config = msaf_api_rtc_configuration_parseRequestFromJSON(json, err_out, err_param);
    if (!rtc_config) {
        /* err_out and err_param set by parser */
        return NULL;
    }

    return rtc_config;
}

cJSON *msaf_rtc_configuration_json(msaf_provisioning_session_t *session /* [no-transfer, not-null] */)
{
    cJSON *json;

    ogs_assert(session);

    if (!session->rtcConfiguration) return NULL;

    json = msaf_api_rtc_configuration_convertResponseToJSON(session->rtcConfiguration);

    if (!json) {
        ogs_error("Failed to convert RTCConfiguration to JSON");
    }

    return json;
}

char *msaf_rtc_configuration_body(msaf_provisioning_session_t *session /* [no-transfer, not-null] */)
{
    cJSON *json;
    char *body;

    ogs_assert(session);

    if (!session->rtcConfiguration) return NULL;

    json = msaf_rtc_configuration_json(session);
    if (!json) return NULL;

    body = cJSON_Print(json);

    cJSON_Delete(json);

    return body;
}

time_t msaf_rtc_configuration_last_modified(msaf_provisioning_session_t *session /* [no-transfer, not-null] */)
{
    ogs_assert(session);

    return session->httpMetadata.rtcConfiguration.received;
}

char *msaf_rtc_configuration_etag(msaf_provisioning_session_t *session /* [no-transfer, not-null] */)
{
    ogs_assert(session);

    return session->httpMetadata.rtcConfiguration.hash;
}

bool msaf_rtc_configuration_changed(msaf_provisioning_session_t *session /* [no-transfer, not-null] */,
                                                   time_t modified_since, const char *none_match /* [null] */)
{
    ogs_assert(session);

    /* Check modification time (input of 0 time indicates don't check modification time) */
    if (modified_since != 0 && session->httpMetadata.rtcConfiguration.received != modified_since) {
        return true;
    }

    /* Check ETag (NULL input means don't check ETag) */
    if (none_match && (!session->httpMetadata.rtcConfiguration.hash ||
                       strcmp(session->httpMetadata.rtcConfiguration.hash, none_match))) {
        return true;
    }

    return false;
}

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
