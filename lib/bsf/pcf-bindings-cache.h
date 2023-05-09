/*
 * License: 5G-MAG Public License (v1.0)
 * Copyright: (C) 2022 British Broadcasting Corporation
 *
 * For full license terms please see the LICENSE file distributed with this
 * program. If this file is missing then the license can be retrieved from
 * https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
 */

#ifndef BSF_CLIENT_PCF_BINDINGS_CACHE_H
#define BSF_CLIENT_PCF_BINDINGS_CACHE_H

#include "ogs-core.h"
#include "ogs-sbi.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct pcf_bindings_cache_s {
    OpenAPI_pcf_binding_t *pcf_binding;
    ogs_time_t expires;
} pcf_bindings_cache_t;

/* Library Internals */
void _pcf_bindings_cache_init(ogs_hash_t **cache);
void _pcf_bindings_cache_clear(ogs_hash_t **cache);
void _pcf_bindings_cache_log_debug(ogs_hash_t *cache, int indent);
OpenAPI_pcf_binding_t *_pcf_bindings_cache_find(ogs_hash_t *cache, const ogs_sockaddr_t *ue_address);
bool _pcf_bindings_cache_add(ogs_hash_t *cache, const ogs_sockaddr_t *ue_address, const OpenAPI_pcf_binding_t *bindings, ogs_time_t expires);

#ifdef __cplusplus
}
#endif

/* vim:ts=8:sts=4:sw=4:expandtab:
 */

#endif /* BSF_CLIENT_PCF_BINDINGS_CACHE_H */
