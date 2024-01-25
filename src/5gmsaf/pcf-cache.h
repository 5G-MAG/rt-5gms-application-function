/*
License: 5G-MAG Public License (v1.0)
Author: David Waring
Copyright: (C) 2023 British Broadcasting Corporation

For full license terms please see the LICENSE file distributed with this
program. If this file is missing then the license can be retrieved from
https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
*/

#ifndef MSAF_PCF_CACHE_H
#define MSAF_PCF_CACHE_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "ogs-core.h"
#include "ogs-sbi.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct msaf_pcf_cache_entry_s {
    ogs_sockaddr_t *pcf_bindings;
    ogs_time_t expires;
} msaf_pcf_cache_entry_t;

typedef ogs_hash_t msaf_pcf_cache_t;

msaf_pcf_cache_t *msaf_pcf_cache_new(void);
void msaf_pcf_cache_free(msaf_pcf_cache_t*);
bool msaf_pcf_cache_add(msaf_pcf_cache_t*, const ogs_sockaddr_t *ue_address, const OpenAPI_pcf_binding_t *api_pcf_binding, ogs_time_t expires);
const ogs_sockaddr_t *msaf_pcf_cache_find(msaf_pcf_cache_t*, const ogs_sockaddr_t *ue_address);

#ifdef __cplusplus
}
#endif

#endif /* MSAF_CONTEXT_H */
