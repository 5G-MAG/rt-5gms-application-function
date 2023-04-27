/*
 * License: 5G-MAG Public License (v1.0)
 * Author: David Waring
 * Copyright: (C) 2023 British Broadcasting Corporation
 *
 * For full license terms please see the LICENSE file distributed with this
 * program. If this file is missing then the license can be retrieved from
 * https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
 */

#include "ogs-core.h"

#include "utilities.h"

#include "headers.h"

#ifdef __cplusplus
extern "C" {
#endif

/* nf_headers_t methods */
nf_headers_t *nf_headers_new()
{
    nf_headers_t *hdrs;

    hdrs = ogs_calloc(1, sizeof(nf_headers_t));
    hdrs->hdrs = ogs_hash_make();

    return hdrs;
}

static int headers_hash_do_free(void *rec, const void *key, int klen, const void *value)
{
    ogs_free((void*)value);
    ogs_hash_set((ogs_hash_t*)rec, key, klen, NULL);
    ogs_free((void*)key);
    return 1;
}

void nf_headers_free(nf_headers_t *headers)
{
    if (headers->hdrs) {
        ogs_hash_do(headers_hash_do_free, headers->hdrs, headers->hdrs);
        ogs_hash_destroy(headers->hdrs);
    }
    ogs_free(headers);
}

const char *nf_headers_get(nf_headers_t *headers, const char *fieldname)
{
    nf_headers_iter_t *iter;

    iter = nf_headers_iter_find(headers, fieldname);
    if (iter) {
        const char *ret;
        ret = nf_headers_iter_value(iter);
        nf_headers_iter_free(iter);
        return ret;
    }
    return NULL;
}

int nf_headers_set(nf_headers_t *headers, const char *fieldname, const char *value)
{
    nf_headers_iter_t *iter;
    iter = nf_headers_iter_find(headers, fieldname);
    if (iter) {
        ogs_hash_set(headers->hdrs, nf_headers_iter_fieldname(iter), OGS_HASH_KEY_STRING, NULL);
        nf_headers_iter_free(iter);
    }
    ogs_hash_set(headers->hdrs, msaf_strdup(fieldname), OGS_HASH_KEY_STRING, msaf_strdup(value));
    return 1;
}

int nf_headers_add(nf_headers_t *headers, const char *fieldname, const char *value) {
    nf_headers_iter_t *iter;
    iter = nf_headers_iter_find(headers, fieldname);
    if (iter) {
        char *new_value = ogs_msprintf("%s, %s", nf_headers_iter_value(iter), value);
        ogs_hash_set(headers->hdrs, nf_headers_iter_fieldname(iter), OGS_HASH_KEY_STRING, new_value);
    } else {
        ogs_hash_set(headers->hdrs, msaf_strdup(fieldname), OGS_HASH_KEY_STRING, msaf_strdup(value));
    }
    return 1;
}

int nf_headers_delete(nf_headers_t *headers, const char *fieldname)
{
    nf_headers_iter_t *iter;
    iter = nf_headers_iter_find(headers, fieldname);
    if (iter) {
        ogs_hash_set(headers->hdrs, nf_headers_iter_fieldname(iter), OGS_HASH_KEY_STRING, NULL);
        return 1;
    }
    return 0;
}

int nf_headers_clear(nf_headers_t *headers)
{
    ogs_hash_clear(headers->hdrs);
    return 1;
}

int nf_headers_count(nf_headers_t *headers)
{
    return ogs_hash_count(headers->hdrs);
}

typedef struct hdrs_hash_do_data_s {
    nf_headers_do_callback_fn_t *fn;
    nf_headers_t *headers;
    void *user_data;
} hdrs_hash_do_data_t;

static int _hash_do_callback(void *rec, const void *key, int key_len, const void *value)
{
    hdrs_hash_do_data_t *data = (hdrs_hash_do_data_t*)rec;

    return data->fn((const char *)key, (const char *)value, data->user_data);
}

int nf_headers_do(nf_headers_t *headers, nf_headers_do_callback_fn_t *fn, void *user_data)
{
    hdrs_hash_do_data_t data = {fn, headers, user_data};
    
    return ogs_hash_do(_hash_do_callback, &data, headers->hdrs);
}

/* Iterator for nf_headers_t */
nf_headers_iter_t *nf_headers_iter_new(nf_headers_t *headers)
{
    nf_headers_iter_t *iter;

    iter = ogs_calloc(1, sizeof(nf_headers_iter_t));
    iter->ptr = ogs_hash_first(headers->hdrs);
    if (!iter->ptr) {
        ogs_free(iter);
        return NULL;
    }
    return iter;
}

nf_headers_iter_t *nf_headers_iter_find(nf_headers_t *headers, const char *fieldname)
{
    nf_headers_iter_t *iter;

    for (iter = nf_headers_iter_new(headers); iter; iter = nf_headers_iter_next(iter)) {
        if (!strcasecmp(nf_headers_iter_fieldname(iter), fieldname)) {
            return iter;
        }
    }
    return NULL;
}

nf_headers_iter_t *nf_headers_iter_next(nf_headers_iter_t *iter)
{
    iter->ptr = ogs_hash_next(iter->ptr);
    if (!iter->ptr) {
        ogs_free(iter);
        return NULL;
    }
    return iter;
}

const char *nf_headers_iter_fieldname(nf_headers_iter_t *iter)
{
    if (!iter) return NULL;
    return (const char *)ogs_hash_this_key(iter->ptr);
}

const char *nf_headers_iter_value(nf_headers_iter_t *iter)
{
    if (!iter) return NULL;
    return (const char *)ogs_hash_this_val(iter->ptr);
}

void nf_headers_iter_free(nf_headers_iter_t *iter)
{
    ogs_free(iter);
}

#ifdef __cplusplus
}
#endif

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
