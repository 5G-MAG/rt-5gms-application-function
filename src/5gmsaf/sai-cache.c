/*
License: 5G-MAG Public License (v1.0)
Author: David Waring
Copyright: (C) 2023 British Broadcasting Corporation

For full license terms please see the LICENSE file distributed with this
program. If this file is missing then the license can be retrieved from
https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
*/

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "ogs-core.h"

#include "openapi/model/msaf_api_service_access_information_resource.h"
#include "hash.h"

#include "sai-cache.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct msaf_sai_cache_key_s {
    size_t key_len;
    bool use_tls;
    char authority[0]; /* actual length is dynamic */
} msaf_sai_cache_key_t;

static void _debug_key(const msaf_sai_cache_key_t *key, const char *prefix);
static msaf_sai_cache_key_t *_msaf_sai_cache_make_key(bool tls, const char *authority);
static msaf_sai_cache_entry_t *_msaf_sai_cache_find(msaf_sai_cache_t *cache, const msaf_sai_cache_key_t *key);

msaf_sai_cache_t *msaf_sai_cache_new(void)
{
    ogs_hash_t *ret;

    ret = ogs_hash_make();

    ogs_debug("msaf_sai_cache_new() = %p", ret);

    return (msaf_sai_cache_t*)ret;
}

void msaf_sai_cache_free(msaf_sai_cache_t *cache)
{
    if (!cache) return;
    ogs_debug("msaf_sai_cache_free(%p)", cache);
    msaf_sai_cache_clear(cache);
    ogs_hash_destroy(cache);
}

bool msaf_sai_cache_add(msaf_sai_cache_t *cache, bool tls, const char *authority, const msaf_api_service_access_information_resource_t *sai)
{
    msaf_sai_cache_entry_t *entry;
    msaf_sai_cache_key_t *key;

    ogs_assert(cache);

    ogs_debug("msaf_sai_cache_add(%p, %s, \"%s\", %p)", cache, tls?"true":"false", authority, sai);

    key = _msaf_sai_cache_make_key(tls, authority);
    entry = _msaf_sai_cache_find(cache, key);
    if (entry) {
        /* replacing existing entry, free old one */
        msaf_sai_cache_entry_free(entry);
    }

    ogs_hash_set(cache, key, key->key_len, msaf_sai_cache_entry_new(sai));
    return true;
}

bool msaf_sai_cache_del(msaf_sai_cache_t *cache, bool tls, const char *authority)
{
    msaf_sai_cache_entry_t *entry;
    msaf_sai_cache_key_t *key;

    if (!cache) return false;

    ogs_debug("msaf_sai_cache_del(%p, %s, \"%s\")", cache, tls?"true":"false", authority);

    key = _msaf_sai_cache_make_key(tls, authority);

    entry = _msaf_sai_cache_find(cache, key);

    if (entry) {
        msaf_sai_cache_entry_free(entry);
        ogs_hash_set(cache, key, key->key_len, NULL);
        ogs_free(key);
        return true;
    }

    ogs_free(key);
    return false;
}

const msaf_sai_cache_entry_t *msaf_sai_cache_find(msaf_sai_cache_t *cache, bool tls, const char *authority)
{
    msaf_sai_cache_key_t *key;
    const msaf_sai_cache_entry_t *entry;

    //ogs_debug("msaf_sai_cache_find(cache=%p, tls=%s, authority=\"%s\")", cache, tls?"true":"false", authority);
    key = _msaf_sai_cache_make_key(tls, authority);
    entry = (const msaf_sai_cache_entry_t*)_msaf_sai_cache_find(cache, key);
    ogs_free(key);
    return entry;
}

bool msaf_sai_cache_clear(msaf_sai_cache_t *cache)
{
    ogs_hash_index_t *it;

    if (!cache) return false;

    ogs_debug("msaf_sai_cache_clear(%p) [%i entries]", cache, ogs_hash_count(cache));
    for (it = ogs_hash_first(cache); it; it = ogs_hash_next(it)) {
        const msaf_sai_cache_key_t *key;
        int key_len;
        msaf_sai_cache_entry_t *entry;

        ogs_hash_this(it, (const void **)&key, &key_len, (void**)(&entry));
        _debug_key(key, "=");
        ogs_debug("clear %p[%i]: %p", key, key_len, entry);
        ogs_hash_set(cache, key, key_len, NULL);
        ogs_free((msaf_sai_cache_key_t*)key);
        msaf_sai_cache_entry_free(entry);
    }
    ogs_debug("Entries after clear = %i", ogs_hash_count(cache));

    return true;
}

bool msaf_sai_cache_clear_authority(msaf_sai_cache_t *cache, bool tls, const char *authority)
{
    return msaf_sai_cache_del(cache, tls, authority);
}

msaf_sai_cache_entry_t *msaf_sai_cache_entry_new(const msaf_api_service_access_information_resource_t *sai)
{
    msaf_sai_cache_entry_t *entry;
    cJSON *sai_json;

    entry = ogs_calloc(1, sizeof(*entry));
    ogs_assert(entry);

    sai_json = msaf_api_service_access_information_resource_convertResponseToJSON((msaf_api_service_access_information_resource_t*)sai);
    ogs_assert(sai_json);

    entry->sai_body = cJSON_Print(sai_json);
    cJSON_Delete(sai_json);

    entry->hash = calculate_hash(entry->sai_body);

    entry->generated = ogs_time_now();

    return entry;
}

void msaf_sai_cache_entry_free(msaf_sai_cache_entry_t *entry)
{
    if (!entry) return;

    if (entry->sai_body) cJSON_free(entry->sai_body);
    if (entry->hash) ogs_free(entry->hash);

    ogs_free(entry);
}

/**** Static functions ****/

static msaf_sai_cache_key_t *_msaf_sai_cache_make_key(bool tls, const char *authority)
{
    msaf_sai_cache_key_t *key;
    size_t key_len;

    key_len = sizeof(*key)+strlen(authority)+1;
    key = ogs_calloc(1, key_len);
    ogs_assert(key);

    key->key_len = key_len;
    key->use_tls = tls;
    strcpy(key->authority, authority);

    return key;
}

static void _debug_key(const msaf_sai_cache_key_t *key, const char *prefix)
{
    ogs_debug("%s len=%zi, tls=%s, authority=\"%s\"", prefix, key->key_len, key->use_tls?"true":"false", key->authority);
}

static msaf_sai_cache_entry_t *_msaf_sai_cache_find(msaf_sai_cache_t *cache, const msaf_sai_cache_key_t *key)
{
    {
        ogs_hash_index_t *it;
        _debug_key(key,"*");
        for (it = ogs_hash_first(cache); it; it = ogs_hash_next(it)) {
            const msaf_sai_cache_key_t *hkey;
            int key_len;
            msaf_sai_cache_entry_t *entry;

            ogs_hash_this(it, (const void**)&hkey, &key_len, (void **)&entry);
            _debug_key(hkey,">");
        }
    }
    return (msaf_sai_cache_entry_t*)ogs_hash_get(cache, key, key->key_len);
}

#ifdef __cplusplus
}
#endif

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
