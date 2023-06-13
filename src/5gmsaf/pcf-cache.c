/*
License: 5G-MAG Public License (v1.0)
Author: David Waring
Copyright: (C) 2023 British Broadcasting Corporation

For full license terms please see the LICENSE file distributed with this
program. If this file is missing then the license can be retrieved from
https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
*/

#include "ogs-core.h"
#include "ogs-sbi.h"

#include "pcf-cache.h"

#ifdef __cplusplus
extern "C" {
#endif

msaf_pcf_cache_t *msaf_pcf_cache_new(void)
{
    return ogs_hash_make();
}

void msaf_pcf_cache_free(msaf_pcf_cache_t *cache)
{
    ogs_hash_index_t *it;

    for (it = ogs_hash_first(cache); it; it = ogs_hash_next(it)) {
        msaf_pcf_cache_entry_t *entry = NULL;
        ogs_sockaddr_t *ue_addr = NULL;
        int ue_addr_len = 0;

        ogs_hash_this(it, (const void**)(&ue_addr), &ue_addr_len, (void**)(&entry));
        ogs_assert(ue_addr_len == sizeof(ogs_sockaddr_t));

        ogs_hash_set(cache, ue_addr, ue_addr_len, NULL);
        ogs_freeaddrinfo(entry->pcf_bindings);
        ogs_free(entry);
    }
    ogs_hash_destroy(cache);
}

bool msaf_pcf_cache_add(msaf_pcf_cache_t *cache, const ogs_sockaddr_t *ue_address, const OpenAPI_pcf_binding_t *api_pcf_binding, ogs_time_t expires)
{
    msaf_pcf_cache_entry_t *entry;
    OpenAPI_lnode_t *node;

    entry = ogs_calloc(1, sizeof(*entry));
    ogs_assert(entry);

    OpenAPI_list_for_each(api_pcf_binding->pcf_ip_end_points, node) {
        OpenAPI_ip_end_point_t *ip = (OpenAPI_ip_end_point_t*)node->data;
        if (ip->ipv4_address) {
            ogs_addaddrinfo(&entry->pcf_bindings, AF_INET, ip->ipv4_address, ip->is_port?ip->port:0, 0);
        }
        if (ip->ipv6_address) {
            ogs_addaddrinfo(&entry->pcf_bindings, AF_INET6, ip->ipv6_address, ip->is_port?ip->port:0, 0);
        }
    }
    entry->expires = expires;

    ogs_hash_set(cache, ue_address, sizeof(*ue_address), entry);

    return true;
}

const ogs_sockaddr_t *msaf_pcf_cache_find(msaf_pcf_cache_t *cache, const ogs_sockaddr_t *ue_address)
{
    msaf_pcf_cache_entry_t *entry;
    
    entry = ogs_hash_get(cache, ue_address, sizeof(*ue_address));

    if (!entry) return NULL;

    if (entry->expires < ogs_time_now()) {
        /* entry expired, remove it */
        ogs_hash_set(cache, ue_address, sizeof(*ue_address), NULL);
        ogs_freeaddrinfo(entry->pcf_bindings);
        ogs_free(entry);
        return NULL;
    }

    return entry->pcf_bindings;
}

#ifdef __cplusplus
}
#endif

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
