/*
 * License: 5G-MAG Public License (v1.0)
 * Copyright: (C) 2022 British Broadcasting Corporation
 *
 * For full license terms please see the LICENSE file distributed with this
 * program. If this file is missing then the license can be retrieved from
 * https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
 */

#ifndef BSF_CLIENT_CONTEXT_H
#define BSF_CLIENT_CONTEXT_H

#include "ogs-core.h"
#include "ogs-sbi.h"

#include "bsf-configuration.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct bsf_client_sess_s bsf_client_sess_t;

typedef struct bsf_client_context_s {
    bsf_configuration_t config;
    ogs_hash_t *pcf_bindings_cache;  // ue-address => pcf_bindings_cache_t
    ogs_list_t active_sessions_list; // Nodes of this list are bsf_client_sess_t
} bsf_client_context_t;

/* Library Internal Public */
bool _bsf_parse_config(const char *local);
void _bsf_client_context_final(void);

bsf_client_context_t *_bsf_client_self(void);

void _bsf_client_context_log_debug(void);

OpenAPI_pcf_binding_t *_bsf_client_pcf_bindings_from_cache(ogs_sockaddr_t *ue_address);
bool _bsf_client_context_add_pcf_binding(const ogs_sockaddr_t *ue_address, const OpenAPI_pcf_binding_t *binding, ogs_time_t expires);

bool _bsf_client_context_active_sessions_add(bsf_client_sess_t *sess);
bool _bsf_client_context_active_sessions_remove(bsf_client_sess_t *sess);
bool _bsf_client_context_active_sessions_exists(bsf_client_sess_t *sess);

#ifdef __cplusplus
}
#endif

/* vim:ts=8:sts=4:sw=4:expandtab:
 */

#endif /* BSF_CLIENT_CONTEXT_H */
