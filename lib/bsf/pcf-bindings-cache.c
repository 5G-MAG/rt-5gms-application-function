/*
 * License: 5G-MAG Public License (v1.0)
 * Copyright: (C) 2022 British Broadcasting Corporation
 *
 * For full license terms please see the LICENSE file distributed with this
 * program. If this file is missing then the license can be retrieved from
 * https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
 */

#include "ogs-core.h"
#include "ogs-sbi.h"

#include "log.h"
#include "utils.h"

#include "pcf-bindings-cache.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Library Internals */
void _pcf_bindings_cache_init(ogs_hash_t **cache)
{
    *cache = ogs_hash_make();
}

void _pcf_bindings_cache_clear(ogs_hash_t **cache)
{
    ogs_hash_index_t *idx;

    if (!cache || !*cache) return;

    for (idx = ogs_hash_first(*cache); idx ; idx = ogs_hash_next(idx)) {
        const void *key;
        int key_len;
        pcf_bindings_cache_t *value;

        ogs_hash_this(idx, &key, &key_len, (void**)&value);
        ogs_hash_set(*cache, key, key_len, NULL);
        OpenAPI_pcf_binding_free(value->pcf_binding);
        ogs_free(value);
    }

    ogs_hash_destroy(*cache);
    *cache = NULL;
}

void _pcf_bindings_cache_log_debug(ogs_hash_t *cache, int indent)
{
    ogs_hash_index_t *idx;

    ogs_debug("%*sBindings Cache:", indent, "");
    for (idx = ogs_hash_first(cache); idx ; idx = ogs_hash_next(idx)) {
        const ogs_sockaddr_t *key;
        int key_len;
        pcf_bindings_cache_t *value;
        char *ue_addr;
        char *json_txt;
        cJSON *json;
        char *expires;

        ogs_hash_this(idx, (const void**)&key, &key_len, (void**)&value);
        ogs_assert(key_len == sizeof(ogs_sockaddr_t));
        ue_addr = _sockaddr_string(key);
        json = OpenAPI_pcf_binding_convertToJSON(value->pcf_binding);
        json_txt = cJSON_Print(json);
        cJSON_Delete(json);
        expires = _time_string(value->expires);

        ogs_debug("%*s%s [%s] = %s", indent+2, "", ue_addr, expires, json_txt);

        ogs_free(ue_addr);
        ogs_free(json_txt);
        ogs_free(expires);
    }
}

OpenAPI_pcf_binding_t *_pcf_bindings_cache_find(ogs_hash_t *cache, const ogs_sockaddr_t *ue_address)
{
    pcf_bindings_cache_t *value;
    ogs_time_t now;

    now = ogs_time_now();
    value = ogs_hash_get(cache, ue_address, sizeof(*ue_address));

    /* not found */
    if (!value) return NULL;

    /* found, but expired */
    if (value->expires < now) {
        OpenAPI_pcf_binding_free(value->pcf_binding);
        ogs_hash_set(cache, ue_address, sizeof(*ue_address), NULL);
        ogs_free(value);
        return NULL;
    }

    /* found and not expired */
    return value->pcf_binding;
}

bool _pcf_bindings_cache_add(ogs_hash_t *cache, const ogs_sockaddr_t *ue_address, const OpenAPI_pcf_binding_t *bindings, ogs_time_t expires)
{
    pcf_bindings_cache_t *value;

    /* check for existing entry and modify, or create */
    value = ogs_hash_get(cache, ue_address, sizeof(*ue_address));
    if (value) {
        value->pcf_binding = OpenAPI_pcf_binding_copy(value->pcf_binding, (OpenAPI_pcf_binding_t*)bindings);
        value->expires = expires;
    } else {
        value = ogs_calloc(1, sizeof(*value));
        ogs_assert(value);
        value->pcf_binding = OpenAPI_pcf_binding_copy(NULL, (OpenAPI_pcf_binding_t*)bindings);
        value->expires = expires;
        ogs_hash_set(cache, ue_address, sizeof(*ue_address), value);
    }

    return true;
}

#ifdef __cplusplus
}
#endif

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
