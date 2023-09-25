/*
License: 5G-MAG Public License (v1.0)
Author: David Waring
Copyright: (C) 2023 British Broadcasting Corporation

For full license terms please see the LICENSE file distributed with this
program. If this file is missing then the license can be retrieved from
https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
*/

#ifndef MSAF_SAI_CACHE_H
#define MSAF_SAI_CACHE_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "ogs-core.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct msaf_api_service_access_information_resource_s msaf_api_service_access_information_resource_t;

typedef struct msaf_sai_cache_entry_s {
    char *sai_body;
    char *hash;
    ogs_time_t generated;
} msaf_sai_cache_entry_t;

typedef ogs_hash_t msaf_sai_cache_t;

msaf_sai_cache_t *msaf_sai_cache_new(void);
void msaf_sai_cache_free(msaf_sai_cache_t*);
bool msaf_sai_cache_add(msaf_sai_cache_t*, bool tls, const char *authority, const msaf_api_service_access_information_resource_t *);
bool msaf_sai_cache_del(msaf_sai_cache_t*, bool tls, const char *authority);
const msaf_sai_cache_entry_t *msaf_sai_cache_find(msaf_sai_cache_t*, bool tls, const char *authority);
bool msaf_sai_cache_clear(msaf_sai_cache_t*);
bool msaf_sai_cache_clear_authority(msaf_sai_cache_t*, bool tls, const char *authority);

msaf_sai_cache_entry_t *msaf_sai_cache_entry_new(const msaf_api_service_access_information_resource_t *);
void msaf_sai_cache_entry_free(msaf_sai_cache_entry_t*);

#ifdef __cplusplus
}
#endif

/* vim:ts=8:sts=4:sw=4:expandtab:
 */

#endif /* MSAF_SAI_CACHE_H */
