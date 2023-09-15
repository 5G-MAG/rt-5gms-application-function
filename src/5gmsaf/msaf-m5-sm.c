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
    ogs_sbi_message_t *message = NULL;

    msaf_sm_debug(e);

    char *nf_name = ogs_msprintf("5GMSAF-%s", msaf_self()->server_name);
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
            message = e->message;

            SWITCH(message->h.service.name)         
            CASE("3gpp-m5")
                if (strcmp(message->h.api.version, "v2") != 0) {
                    char *error;
                    error = ogs_msprintf("Version [%s] not supported", message->h.api.version);
                    ogs_error("%s", error);
                    ogs_assert(true == nf_server_send_error(stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST, 1, NULL, "Not supported version", error, NULL, NULL, app_meta));

                    break;
                }
                SWITCH(message->h.resource.component[0])
                CASE("service-access-information")
                    SWITCH(message->h.method)
                    CASE(OGS_SBI_HTTP_METHOD_GET)
                        cJSON *service_access_information;
                        msaf_provisioning_session_t *msaf_provisioning_session = NULL;
                        msaf_provisioning_session = msaf_provisioning_session_find_by_provisioningSessionId(message->h.resource.component[1]);

                        if(msaf_provisioning_session == NULL) {
                            char *err = NULL;
                            err = ogs_msprintf("Provisioning Session [%s] not found.", message->h.resource.component[1]);
                            ogs_error("%s", err);
                            ogs_assert(true == nf_server_send_error(stream, 404, 1, message, "Provisioning Session not found.", err, NULL, m5_serviceaccessinformation_api, app_meta));
                            ogs_free(err);
                        } else if (msaf_provisioning_session->serviceAccessInformation) {
                            service_access_information = msaf_context_retrieve_service_access_information(message->h.resource.component[1]);
                            if (service_access_information != NULL) {
                                ogs_sbi_response_t *response;
                                char *text;
                                text = cJSON_Print(service_access_information);
                                response = nf_server_new_response(NULL, "application/json",  msaf_provisioning_session->httpMetadata.serviceAccessInformation.received, msaf_provisioning_session->httpMetadata.serviceAccessInformation.hash, msaf_self()->config.server_response_cache_control->m5_service_access_information_response_max_age, NULL, m5_serviceaccessinformation_api, app_meta);
                                nf_server_populate_response(response, strlen(text), text, 200);
                                ogs_assert(response);
                                ogs_assert(true == ogs_sbi_server_send_response(stream, response));
                                cJSON_Delete(service_access_information);
                            } else {
                                char *err = NULL;
                                err = ogs_msprintf("Service Access Information for the Provisioning Session [%s] not found.", message->h.resource.component[1]);
                                ogs_error("%s", err);

                                ogs_assert(true == nf_server_send_error(stream, 404, 1, message, "Service Access Information not found.", err, NULL, m5_serviceaccessinformation_api, app_meta));
                                ogs_free(err);
                            }
                        } else {
                            char *err = NULL;
                            err = ogs_msprintf("Provisioning Session [%s] has no Service Access Information associated with it.", message->h.resource.component[1]);
                            ogs_error("%s", err);

                            ogs_assert(true == nf_server_send_error(stream, 404, 1, message, "Service Access Information not found.", err, NULL, m5_serviceaccessinformation_api, app_meta));
                            ogs_free(err);
                        }
                        break;
                    DEFAULT
                        ogs_error("Invalid HTTP method [%s]", message->h.method);

                        ogs_assert(true == nf_server_send_error(stream, OGS_SBI_HTTP_STATUS_FORBIDDEN, 1, message, "Invalid HTTP method.", message->h.method, NULL, NULL, app_meta));
                    END
                    break;
                DEFAULT
                    ogs_error("Invalid resource name [%s]",
                            message->h.resource.component[0]);
                    ogs_assert(true == nf_server_send_error(stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST, 1, message, "Invalid resource name.", message->h.resource.component[0], NULL, NULL, app_meta));

                END
                break;
            DEFAULT
                ogs_error("Invalid API name [%s]", message->h.service.name);
                ogs_assert(true == nf_server_send_error(stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST, 1, message, "Invalid API name.", message->h.service.name, NULL, NULL, app_meta));

            END
            break;
        default:
            ogs_error("No handler for event %s", msaf_event_get_name(e));
            break;
    }
    if (message) {
        ogs_sbi_message_free(message);
        ogs_free(message);
    }
    ogs_free(nf_name);
}

/* vim:ts=8:sts=4:sw=4:expandtab:
*/
