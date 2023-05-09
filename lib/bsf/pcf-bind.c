/*
License: 5G-MAG Public License (v1.0)
Copyright: (C) 2022 British Broadcasting Corporation

For full license terms please see the LICENSE file distributed with this
program. If this file is missing then the license can be retrieved from
https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
*/

#include "bsf-client.h"
#include "bsf-client-sess.h"
#include "context.h"
#include "local.h"
#include "log.h"

#include "pcf-bind.h"

#ifdef __cplusplus
extern "C" {
#endif

bool _bsf_retrieve_pcf_binding_for_pdu_session(ogs_sockaddr_t *ue_address, bsf_retrieve_callback_f callback, void *user_data)
{
    OpenAPI_pcf_binding_t *binding;
    bsf_client_sess_t *sess;

    ogs_assert(ue_address);

    ogs_debug("_bsf_retrieve_pcf_binding_for_pdu_session(ue_address=%p, callback=%p, user_data=%p)", ue_address, callback, user_data);
    /* Check the cache */
    binding = _bsf_client_pcf_bindings_from_cache(ue_address);
    if (binding) {
        OpenAPI_pcf_binding_t *bind_copy;

        bind_copy = OpenAPI_pcf_binding_copy(NULL, binding);
        if (!callback(bind_copy, user_data)) {
            ogs_error("BSF client callback failed");
            OpenAPI_pcf_binding_free(bind_copy);
        }
        return true;
    }

    /* Send the request */
    sess = _bsf_client_sess_new();
    ogs_assert(sess);

    _bsf_client_sess_ue_address_set(sess, ue_address);
    if (ue_address->ogs_sa_family == AF_INET) {
        _bsf_client_sess_ipv4addr_set_from_sockaddr(sess, ue_address);
    } else if (ue_address->ogs_sa_family == AF_INET6) {
        _bsf_client_sess_ipv6prefix_set_from_sockaddr(sess, ue_address);
    } else {
        ogs_assert_if_reached();
    }
    _bsf_client_sess_retrieve_callback_set(sess, callback, user_data);

    _bsf_client_context_log_debug();

    _bsf_client_local_discover_and_send(sess);

    return true;
}

#ifdef __cplusplus
}
#endif

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
