/*
 * License: 5G-MAG Public License (v1.0)
 * Author: Dev Audsin
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
#include "msaf-sm.h"
#include "openapi/api/TS26512_M5_ServiceAccessInformationAPI-info.h"

const nf_server_interface_metadata_t
m5_serviceaccessinformation_api_metadata = {
    M5_SERVICEACCESSINFORMATION_API_NAME,
    M5_SERVICEACCESSINFORMATION_API_VERSION
};

void msaf_m5_state_initial(ogs_fsm_t *s, msaf_event_t *e)
{
    msaf_sm_debug(e);

    ogs_assert(s);

    OGS_FSM_TRAN(s, &msaf_m5_state_functional);
}

void msaf_m5_state_final(ogs_fsm_t *s, msaf_event_t *e)
{
    msaf_sm_debug(e);

    ogs_assert(s);
}

void msaf_m5_state_functional(ogs_fsm_t *s, msaf_event_t *e)
{
    ogs_sbi_stream_t *stream = NULL;
    ogs_sbi_request_t *request = NULL;
    ogs_sbi_message_t message;

    msaf_sm_debug(e);

    char *nf_name = ogs_msprintf("5GMSdAF-%s", msaf_self()->server_name);
    const nf_server_app_metadata_t app_metadata = { MSAF_NAME, MSAF_VERSION, nf_name};
    const nf_server_interface_metadata_t *m5_serviceaccessinformation_api = &m5_serviceaccessinformation_api_metadata;
    const nf_server_app_metadata_t *app_meta = &app_metadata;

    ogs_assert(s);

    switch (e->h.id) {
        case OGS_FSM_ENTRY_SIG:
            ogs_info("[%s] MSAF M5 Running", ogs_sbi_self()->nf_instance->id);

            break;

        case OGS_FSM_EXIT_SIG:
            break;

        case OGS_EVENT_SBI_SERVER:
            request = e->h.sbi.request;
            ogs_assert(request);
            stream = e->h.sbi.data;
            ogs_assert(stream);
            message = *(e->message);

            SWITCH(message.h.service.name)         
            CASE("3gpp-m5")
                if (strcmp(message.h.api.version, "v2") != 0) {
                    char *error;
                    error = ogs_msprintf("Version [%s] not supported", message.h.api.version);
                    ogs_error("%s", error);
                    ogs_assert(true == nf_server_send_error(stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST, 1, NULL, "Not supported version", error, NULL, NULL, app_meta));

                    ogs_sbi_message_free(&message);
                    break;
                }
                SWITCH(message.h.resource.component[0])
                CASE("service-access-information")
                    SWITCH(message.h.method)
                    CASE(OGS_SBI_HTTP_METHOD_GET)
                        cJSON *service_access_information;
                        msaf_provisioning_session_t *msaf_provisioning_session = NULL;
                        msaf_provisioning_session = msaf_provisioning_session_find_by_provisioningSessionId(message.h.resource.component[1]);

                        if(msaf_provisioning_session == NULL) {
                            char *err = NULL;
                            asprintf(&err,"Provisioning Session [%s] not found.", message.h.resource.component[1]);
                            ogs_error("%s", err);
                            ogs_assert(true == nf_server_send_error(stream, 404, 1, &message, "Provisioning Session not found.", err, NULL, m5_serviceaccessinformation_api, app_meta));
                        } else if (msaf_provisioning_session->serviceAccessInformation) {
                            service_access_information = msaf_context_retrieve_service_access_information(message.h.resource.component[1]);
                            if (service_access_information != NULL) {
                                ogs_sbi_response_t *response;
                                char *text;
                                text = cJSON_Print(service_access_information);
                                response = nf_server_new_response(NULL, "application/json",  msaf_provisioning_session->serviceAccessInformationCreated, msaf_provisioning_session->serviceAccessInformationHash, msaf_self()->config.server_response_cache_control->m5_service_access_information_response_max_age, NULL, m5_serviceaccessinformation_api, app_meta);
                                nf_server_populate_response(response, strlen(text), text, 201);
                                ogs_assert(response);
                                ogs_assert(true == ogs_sbi_server_send_response(stream, response));
                                cJSON_Delete(service_access_information);
                            } else {
                                char *err = NULL;
                                asprintf(&err,"Service Access Information for the Provisioning Session [%s] not found.", message.h.resource.component[1]);
                                ogs_error("%s", err);

                                ogs_assert(true == nf_server_send_error(stream, 404, 1, &message, "Service Access Information not found.", err, NULL, m5_serviceaccessinformation_api, app_meta));
                            }
                        } else {
                            char *err = NULL;
                            asprintf(&err,"Provisioning Session [%s] has no Service Access Information associated with it.", message.h.resource.component[1]);
                            ogs_error("%s", err);

                            ogs_assert(true == nf_server_send_error(stream, 404, 1, &message, "Service Access Information not found.", err, NULL, m5_serviceaccessinformation_api, app_meta));
                        }
                        break;
                    DEFAULT
                        ogs_error("Invalid HTTP method [%s]", message.h.method);

                        ogs_assert(true == nf_server_send_error(stream, OGS_SBI_HTTP_STATUS_FORBIDDEN, 1, &message, "Invalid HTTP method.", ogs_strdup(message.h.method), NULL, NULL, app_meta));

                    END
                    break;
                DEFAULT
                    ogs_error("Invalid resource name [%s]",
                            message.h.resource.component[0]);
                    ogs_assert(true == nf_server_send_error(stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST, 1, &message, "Invalid resource name.", ogs_strdup(message.h.resource.component[0]), NULL, NULL, app_meta));

                END
                ogs_sbi_message_free(&message);
                break;
            DEFAULT
                ogs_error("Invalid API name [%s]", message.h.service.name);
                ogs_assert(true == nf_server_send_error(stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST, 1, &message, "Invalid API name.", ogs_strdup(message.h.service.name), NULL, NULL, app_meta));

            END
            break;
#if 0
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
#endif
        default:
            ogs_error("No handler for event %s", msaf_event_get_name(e));
            break;
    }
    ogs_free(nf_name);
}

/* vim:ts=8:sts=4:sw=4:expandtab:
*/
