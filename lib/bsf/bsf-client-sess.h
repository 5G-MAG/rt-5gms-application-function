/*
License: 5G-MAG Public License (v1.0)
Copyright: (C) 2023 British Broadcasting Corporation

For full license terms please see the LICENSE file distributed with this
program. If this file is missing then the license can be retrieved from
https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
*/

#ifndef BSF_CLIENT_SESS_H
#define BSF_CLIENT_SESS_H

#include "ogs-sbi.h"

#include "bsf-client.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ogs_sockaddr_s ogs_sockaddr_t;

typedef struct bsf_client_sess_s {
    ogs_sbi_object_t sbi;

    ogs_sockaddr_t *ue_address; /* used as the key to store results in the cache */

    char *ipv4addr;
    char *ipv6prefix;

    struct {
        bsf_retrieve_callback_f callback;
        void *user_data;
    } retrieve;
} bsf_client_sess_t;

bsf_client_sess_t *_bsf_client_sess_new(void);
void _bsf_client_sess_free(bsf_client_sess_t *sess);

void _bsf_client_sess_log_debug(bsf_client_sess_t *sess, int indent);

bool _bsf_client_sess_ue_address_set(bsf_client_sess_t *sess, const ogs_sockaddr_t *ue_address);
bool _bsf_client_sess_ipv4addr_set_from_sockaddr(bsf_client_sess_t *sess, const ogs_sockaddr_t *addr);
bool _bsf_client_sess_ipv6prefix_set_from_sockaddr(bsf_client_sess_t *sess, const ogs_sockaddr_t *addr);

bool _bsf_client_sess_retrieve_callback_set(bsf_client_sess_t *sess, bsf_retrieve_callback_f cb, void *user_data);
bool _bsf_client_sess_retrieve_callback_call(bsf_client_sess_t *sess, const OpenAPI_pcf_binding_t *binding);
bool _bsf_client_sess_discover_and_send(bsf_client_sess_t *sess);

#ifdef __cplusplus
}
#endif

/* vim:ts=8:sts=4:sw=4:expandtab:
 */

#endif /* BSF_CLIENT_SESS_H */
