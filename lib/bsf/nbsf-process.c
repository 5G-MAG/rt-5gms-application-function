/*
License: 5G-MAG Public License (v1.0)
Copyright: (C) 2023 British Broadcasting Corporation

For full license terms please see the LICENSE file distributed with this
program. If this file is missing then the license can be retrieved from
https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
*/

#include "ogs-proto.h"
#include "ogs-sbi.h"

#include "bsf-client-sess.h"
#include "context.h"
#include "local.h"
#include "log.h"
#include "utils.h"

#include "nbsf-process.h"

#ifdef __cplusplus
extern "C" {
#endif

bool _bsf_process_event(ogs_event_t *e)
{
    /* check if we're ready */
    if (_bsf_client_self() == NULL) return false;

    ogs_debug("_bsf_process_event: %s", ogs_event_get_name(e));

    switch (e->id) {
        case OGS_EVENT_SBI_CLIENT:
        {
            int rv;
            ogs_sbi_response_t *response = e->sbi.response;
            ogs_sbi_message_t message;

            ogs_assert(response);
            rv = ogs_sbi_parse_response(&message, response);
            if (rv != OGS_OK) {
                ogs_error("Failed to parse response");
                ogs_sbi_message_free(&message);
                break;
            }

            ogs_debug("OGS_EVENT_SBI_CLIENT: service=%s, component[0]=%s", message.h.service.name, message.h.resource.component[0]);

            SWITCH(message.h.service.name)
                CASE(OGS_SBI_SERVICE_NAME_NNRF_DISC)
                {
                    ogs_sbi_xact_t *xact = (ogs_sbi_xact_t*)e->sbi.data;

                    SWITCH(message.h.resource.component[0])
                        CASE(OGS_SBI_RESOURCE_NAME_NF_INSTANCES)
                            ogs_debug("Got NF-Instances");
                            _bsf_client_context_log_debug();
                            bsf_client_sess_t *sess = ogs_container_of(xact->sbi_object, bsf_client_sess_t, sbi);
                            ogs_debug("bsf_client_sess_t = %p", sess);
                            if (_bsf_client_context_active_sessions_exists(sess)) {
                                ogs_sbi_nf_instance_t *nf_instance = e->sbi.data;

                                ogs_debug("one of ours!");
                                ogs_assert(nf_instance);
                                ogs_assert(OGS_FSM_STATE(&nf_instance->sm));

                                e->sbi.message = &message;
                                ogs_fsm_dispatch(&nf_instance->sm, e);
                                
                                ogs_sbi_response_free(response);
                                ogs_sbi_message_free(&message);
                                return true;
                            }
                        DEFAULT
                    END
                }
                break;
                CASE(OGS_SBI_SERVICE_NAME_NBSF_MANAGEMENT)
                {
                    ogs_sbi_xact_t *xact = (ogs_sbi_xact_t*)e->sbi.data;

                    SWITCH(message.h.resource.component[0])
                        CASE(OGS_SBI_RESOURCE_NAME_PCF_BINDINGS)
                            ogs_debug("Got pcfBindings!");
                            _bsf_client_context_log_debug();
                            bsf_client_sess_t *sess = ogs_container_of(xact->sbi_object, bsf_client_sess_t, sbi);
                            ogs_debug("bsf_client_sess_t = %p", sess);
                            if (_bsf_client_context_active_sessions_exists(sess)) {
                                ogs_time_t expires;

                                ogs_debug("one of ours!");
                                expires = _response_to_expiry_time(response);
                                _bsf_client_context_add_pcf_binding(sess->ue_address, message.PcfBinding, expires);
                                
                                if (!_bsf_client_sess_retrieve_callback_call(sess, message.PcfBinding)) {
                                    ogs_error("_bsf_client_sess_retrieve_callback_call() failed");
                                }

                                ogs_sbi_xact_remove(xact);
                                ogs_sbi_response_free(response);
                                _bsf_client_sess_free(sess);
                                ogs_sbi_message_free(&message);
                                ogs_debug("taking event for OGS_EVENT_SBI_CLIENT");
                                return true;
                            }
                            break;
                        DEFAULT
                    END
                }
                break;
                DEFAULT
            END

            ogs_sbi_message_free(&message);
            /* ogs_sbi_parse_response leaves allocated strings in the response->h that we need to free */
            {
                char *method = response->h.method; /* save this */
                response->h.method = NULL;
                ogs_sbi_header_free(&response->h);
                response->h.method = method;
            }
            ogs_debug("end OGS_EVENT_SBI_CLIENT");

            break;
        }    
        case BSF_CLIENT_LOCAL_EVENT:
            return _bsf_client_local_process_event(e);
        default:
    }

    return false;    
}

#ifdef __cplusplus
}
#endif

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
