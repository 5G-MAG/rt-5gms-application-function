/*
 * License: 5G-MAG Public License (v1.0)
 * Copyright: (C) 2022 British Broadcasting Corporation
 *
 * For full license terms please see the LICENSE file distributed with this
 * program. If this file is missing then the license can be retrieved from
 * https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
 */

#include "ogs-sbi.h"
#include "sbi-path.h"
#include "context.h"
#include "certmgr.h"
#include "server.h"
#include "response-cache-control.h"
#include "msaf-version.h"
#include "msaf-mgmt-sm.h"
#include "openapi/api/TS26512_M1_ProvisioningSessionsAPI-info.h"

const nf_server_interface_metadata_t
m1_mgmt_provisioningsession_api_metadata = {
    M1_PROVISIONINGSESSIONS_API_NAME,
    M1_PROVISIONINGSESSIONS_API_VERSION
};

void msaf_mgmt_state_initial(ogs_fsm_t *s, msaf_event_t *e)
{
    msaf_sm_debug(e);

    ogs_assert(s);

    OGS_FSM_TRAN(s, &msaf_mgmt_state_functional);
}

void msaf_mgmt_state_final(ogs_fsm_t *s, msaf_event_t *e)
{
    msaf_sm_debug(e);

    ogs_assert(s);
}

void msaf_mgmt_state_functional(ogs_fsm_t *s, msaf_event_t *e)
{
    int rv;

    ogs_sbi_stream_t *stream = NULL;
    ogs_sbi_request_t *request = NULL;

    ogs_sbi_nf_instance_t *nf_instance = NULL;
    ogs_sbi_subscription_data_t *subscription_data = NULL;
    ogs_sbi_response_t *response = NULL;
    ogs_sbi_message_t message;
    ogs_sbi_xact_t *sbi_xact = NULL;

    msaf_sm_debug(e);

    msaf_context_server_name_set();
    char *nf_name = ogs_msprintf("5GMSdAF-%s", msaf_self()->server_name);
    const nf_server_app_metadata_t app_metadata = { MSAF_NAME, MSAF_VERSION, nf_name};
    const nf_server_interface_metadata_t *m1_provisioningsession_api = &m1_mgmt_provisioningsession_api_metadata;    
    const nf_server_app_metadata_t *app_meta = &app_metadata;

    ogs_assert(s);

    switch (e->h.id) {
        case OGS_FSM_ENTRY_SIG:
            ogs_info("[%s] MSAF Management Interface Running", ogs_sbi_self()->nf_instance->id);
            break;

        case OGS_FSM_EXIT_SIG:
            break;

        case OGS_EVENT_SBI_SERVER:
            request = e->h.sbi.request;
            ogs_assert(request);
            stream = e->h.sbi.data;
            ogs_assert(stream);

            rv = ogs_sbi_parse_header(&message, &request->h);
            if (rv != OGS_OK) {
                ogs_error("ogs_sbi_parse_header() failed");
                ogs_assert(true == nf_server_send_error(stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST, 1, NULL, "cannot parse HTTP message", NULL, NULL, NULL, app_meta));

                break;
            }

            SWITCH(message.h.service.name)
            CASE(OGS_SBI_SERVICE_NAME_NNRF_NFM)
                if (strcmp(message.h.api.version, OGS_SBI_API_V1) != 0) {
                    ogs_error("Not supported version [%s]", message.h.api.version);
                    ogs_assert(true == ogs_sbi_server_send_error(
                                stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                                &message, "Not supported version", NULL));
                    ogs_sbi_message_free(&message);
                    break;
                }
                SWITCH(message.h.resource.component[0])
                CASE(OGS_SBI_RESOURCE_NAME_NF_STATUS_NOTIFY)
                    SWITCH(message.h.method)
                    CASE(OGS_SBI_HTTP_METHOD_POST)
                        ogs_nnrf_nfm_handle_nf_status_notify(stream, &message);
                        break;

                    DEFAULT
                        ogs_error("Invalid HTTP method [%s]", message.h.method);
                        ogs_assert(true ==
                                ogs_sbi_server_send_error(stream,
                                        OGS_SBI_HTTP_STATUS_FORBIDDEN, &message,
                                        "Invalid HTTP method", message.h.method));
                    END
                    break;

                DEFAULT
                    ogs_error("Invalid resource name [%s]",
                            message.h.resource.component[0]);
                    ogs_assert(true ==
                            ogs_sbi_server_send_error(stream,
                                    OGS_SBI_HTTP_STATUS_BAD_REQUEST, &message,
                                    "Invalid resource name",
                                    message.h.resource.component[0]));
                END
                ogs_sbi_message_free(&message);
                break;

            CASE("5gmag-rt-management")
                if (strcmp(message.h.api.version, "v1") != 0) {
                    char *error;
                    ogs_error("Not supported version [%s]", message.h.api.version);

                    error = ogs_msprintf("Version [%s] not supported", message.h.api.version);

                    ogs_assert(true == nf_server_send_error(stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST, 1, NULL, "Not supported version", error, NULL, NULL, app_meta));    
                                
                    ogs_sbi_message_free(&message);
                    ogs_free(error);
                    break;
                }
                
                SWITCH(message.h.resource.component[0])

                    CASE("provisioning-sessions")
                        SWITCH(message.h.method)
                            CASE(OGS_SBI_HTTP_METHOD_GET)
                                char *provisioning_sessions;
                                ogs_sbi_response_t *response;
                                provisioning_sessions = enumerate_provisioning_sessions();
                                if (provisioning_sessions) {
                                    response = nf_server_new_response(NULL, "application/json",  NULL, NULL, msaf_self()->config.server_response_cache_control->m1_provisioning_session_response_max_age, NULL, NULL, app_meta);
        
                                    nf_server_populate_response(response, strlen(provisioning_sessions), ogs_strdup(provisioning_sessions), 200);
                                    ogs_assert(response);
                                    ogs_assert(true == ogs_sbi_server_send_response(stream, response));
                                    if (strcmp(provisioning_sessions,"[]"))  ogs_free(provisioning_sessions);
                                    break;
                                } else {
                                    ogs_error("Internal Server Error.");                                          
                                    ogs_assert(true == nf_server_send_error(stream, OGS_SBI_HTTP_STATUS_INTERNAL_SERVER_ERROR, 0, &message, "Internal Server Error.", message.h.method, NULL, NULL, app_meta)); 
                                    
                                }
                            DEFAULT
                                ogs_error("Invalid HTTP method [%s]", message.h.method);
                                ogs_assert(true == nf_server_send_error(stream, OGS_SBI_HTTP_STATUS_FORBIDDEN, 1, &message, "Invalid HTTP method.", message.h.method, NULL, NULL, app_meta));
                            END
                            break;	     
                        DEFAULT
                            char *err;
                            ogs_error("Invalid resource name [%s]",
                            message.h.resource.component[0]);
                            asprintf(&err,"Invalid resource name [%s]", message.h.resource.component[0]);
                            ogs_assert(true == nf_server_send_error(stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST, 0, &message, "Invalid resource name", err, NULL, NULL, app_meta));
    
    
                END	
                ogs_sbi_message_free(&message);		    
                break;
    

           
            DEFAULT
                ogs_error("Invalid API name [%s]", message.h.service.name);
                ogs_assert(true == nf_server_send_error(stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST, 1, &message, "Invalid API name.",  message.h.service.name, NULL, NULL, app_meta));

            END
            break;

        case OGS_EVENT_SBI_CLIENT:
            ogs_assert(e);

            response = e->h.sbi.response;
            ogs_assert(response);
            rv = ogs_sbi_parse_header(&message, &response->h);
            if (rv != OGS_OK) {
                ogs_error("ogs_sbi_parse_header() failed");
                ogs_sbi_message_free(&message);
                ogs_sbi_response_free(response);
                break;
            }
            {
                ogs_hash_index_t *hi;
                for (hi = ogs_hash_first(response->http.headers);
                        hi; hi = ogs_hash_next(hi)) {
                    if (!ogs_strcasecmp(ogs_hash_this_key(hi), OGS_SBI_CONTENT_TYPE)) {
                        message.http.content_type = ogs_hash_this_val(hi);
                    } else if (!ogs_strcasecmp(ogs_hash_this_key(hi), OGS_SBI_LOCATION)) {
                        message.http.location = ogs_hash_this_val(hi);
                    }
                }
            }

            message.res_status = response->status;

            SWITCH(message.h.service.name)
            
            CASE(OGS_SBI_SERVICE_NAME_NNRF_NFM)

                SWITCH(message.h.resource.component[0])
                CASE(OGS_SBI_RESOURCE_NAME_NF_INSTANCES)
                    nf_instance = e->h.sbi.data;
                    ogs_assert(nf_instance);
                    ogs_assert(OGS_FSM_STATE(&nf_instance->sm));

                    e->h.sbi.message = &message;
                    ogs_fsm_dispatch(&nf_instance->sm, e);
                    break;

                CASE(OGS_SBI_RESOURCE_NAME_SUBSCRIPTIONS)
                    subscription_data = e->h.sbi.data;
                    ogs_assert(subscription_data);

                    SWITCH(message.h.method)
                    CASE(OGS_SBI_HTTP_METHOD_POST)
                        if (message.res_status == OGS_SBI_HTTP_STATUS_CREATED ||
                                message.res_status == OGS_SBI_HTTP_STATUS_OK) {
                            ogs_nnrf_nfm_handle_nf_status_subscribe(
                                    subscription_data, &message);
                        } else {
                            ogs_error("HTTP response error : %d",
                                    message.res_status);
                        }
                        break;

                    CASE(OGS_SBI_HTTP_METHOD_DELETE)
                        if (message.res_status == OGS_SBI_HTTP_STATUS_NO_CONTENT) {
                            ogs_sbi_subscription_data_remove(subscription_data);
                        } else {
                            ogs_error("HTTP response error : %d",
                                    message.res_status);
                        }
                        break;

                    DEFAULT
                        ogs_error("Invalid HTTP method [%s]", message.h.method);
                        ogs_assert_if_reached();
                    END
                    break;

                DEFAULT
                    ogs_error("Invalid resource name [%s]",
                            message.h.resource.component[0]);
                    ogs_assert_if_reached();
                END
                break;

            DEFAULT
                ogs_error("Invalid service name [%s]", message.h.service.name);
                ogs_assert_if_reached();
            END

            ogs_sbi_message_free(&message);
            ogs_sbi_response_free(response);
            break;

        case OGS_EVENT_SBI_TIMER:
            ogs_assert(e);

            switch(e->h.timer_id) {
                case OGS_TIMER_NF_INSTANCE_REGISTRATION_INTERVAL:
                case OGS_TIMER_NF_INSTANCE_HEARTBEAT_INTERVAL:
                case OGS_TIMER_NF_INSTANCE_NO_HEARTBEAT:
                case OGS_TIMER_NF_INSTANCE_VALIDITY:
                    nf_instance = e->h.sbi.data;
                    ogs_assert(nf_instance);
                    ogs_assert(OGS_FSM_STATE(&nf_instance->sm));

                    ogs_fsm_dispatch(&nf_instance->sm, e);
                    if (OGS_FSM_CHECK(&nf_instance->sm, ogs_sbi_nf_state_exception))
                        ogs_error("State machine exception [%d]", e->h.timer_id);
                    break;

                case OGS_TIMER_SUBSCRIPTION_VALIDITY:
                    subscription_data = e->h.sbi.data;
                    ogs_assert(subscription_data);

                    ogs_assert(true ==
                            ogs_nnrf_nfm_send_nf_status_subscribe(subscription_data));

                    ogs_debug("Subscription validity expired [%s]",
                            subscription_data->id);
                    ogs_sbi_subscription_data_remove(subscription_data);
                    break;

                case OGS_TIMER_SBI_CLIENT_WAIT:
                    sbi_xact = e->h.sbi.data;
                    ogs_assert(sbi_xact);

                    stream = sbi_xact->assoc_stream;

                    ogs_sbi_xact_remove(sbi_xact);

                    ogs_error("Cannot receive SBI message");
                    if (stream) {
                        ogs_assert(true ==
                                ogs_sbi_server_send_error(stream,
                                    OGS_SBI_HTTP_STATUS_GATEWAY_TIMEOUT, NULL,
                                    "Cannot receive SBI message", NULL));
                    }
                    break;

                default:
                    ogs_error("Unknown timer[%s:%d]",
                            ogs_timer_get_name(e->h.timer_id), e->h.timer_id);
            }
            break;

        default:
            ogs_error("No handler for event %s", msaf_event_get_name(e));
            break;
    }
    ogs_free(nf_name);
}

/* vim:ts=8:sts=4:sw=4:expandtab:
*/
