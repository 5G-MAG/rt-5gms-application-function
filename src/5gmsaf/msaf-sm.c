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
#include "openapi/api/TS26512_M1_ContentHostingProvisioningAPI-info.h"
#include "openapi/api/M3_ContentHostingProvisioningAPI-info.h"

static const nf_server_interface_metadata_t
        m1_contenthostingprovisioning_api_metadata = {
        M1_CONTENTHOSTINGPROVISIONING_API_NAME,
        M1_CONTENTHOSTINGPROVISIONING_API_VERSION
};

static const nf_server_interface_metadata_t
        m3_contenthostingprovisioning_api_metatdata = {
        M3_CONTENTHOSTINGPROVISIONING_API_NAME,
        M3_CONTENTHOSTINGPROVISIONING_API_VERSION
};

void msaf_state_initial(ogs_fsm_t *s, msaf_event_t *e)
{
    msaf_sm_debug(e);

    ogs_assert(s);

    OGS_FSM_TRAN(s, &msaf_state_functional);
}

void msaf_state_final(ogs_fsm_t *s, msaf_event_t *e)
{
    msaf_sm_debug(e);
    msaf_fsm_fini();

    ogs_assert(s);
}

void msaf_state_functional(ogs_fsm_t *s, msaf_event_t *e)
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
    static const nf_server_interface_metadata_t *m3_contenthostingprovisioning_api = &m3_contenthostingprovisioning_api_metatdata;
    static const nf_server_interface_metadata_t *m1_contenthostingprovisioning_api = &m1_contenthostingprovisioning_api_metadata;
    const nf_server_app_metadata_t *app_meta = &app_metadata;

    ogs_assert(s);

    switch (e->h.id) {
        case OGS_FSM_ENTRY_SIG:
            msaf_fsm_init();
            ogs_info("[%s] MSAF Running", ogs_sbi_self()->nf_instance->id);
            break;

        case OGS_FSM_EXIT_SIG:
            break;

        // Event for request coming in on server
        // Handler of all incoming requests
        case OGS_EVENT_SBI_SERVER:
            request = e->h.sbi.request;
            ogs_assert(request);
            stream = e->h.sbi.data;
            ogs_assert(stream);

            if (!strcmp(request->h.method, OGS_SBI_HTTP_METHOD_OPTIONS) && !strcmp(request->h.uri, "*")){
                char *methods = NULL;
                ogs_sbi_response_t *response;
                methods = ogs_msprintf("%s, %s, %s, %s, %s",OGS_SBI_HTTP_METHOD_POST, OGS_SBI_HTTP_METHOD_GET, OGS_SBI_HTTP_METHOD_PUT, OGS_SBI_HTTP_METHOD_DELETE, OGS_SBI_HTTP_METHOD_OPTIONS);
                response = nf_server_new_response(NULL, NULL,  0, NULL, 0, methods, NULL, app_meta);
                nf_server_populate_response(response, 0, NULL, 204);
                ogs_assert(response);
                ogs_assert(true == ogs_sbi_server_send_response(stream, response));
                ogs_free(methods);
                break;
            }

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

            CASE("3gpp-m1")
            if(check_event_addresses(e, msaf_self()->config.m1_server_sockaddr, msaf_self()->config.m1_server_sockaddr_v6)){
                e->message =  &message;
                // Dispatching to another state machine
                ogs_fsm_dispatch(&msaf_self()->msaf_fsm.msaf_m1_sm, e);


            } else {
                char *error;
                error = ogs_msprintf("Resource [%s] not found.", request->h.uri);
                ogs_assert(true == nf_server_send_error(stream, OGS_SBI_HTTP_STATUS_NOT_FOUND, 1, NULL, "Not Found.", error, NULL, NULL, app_meta));
                ogs_free(error);
            }
            ogs_sbi_message_free(&message);
            break;

            CASE("5gmag-rt-management")
            if(!msaf_self()->config.maf_mgmt_server_sockaddr && !msaf_self()->config.maf_mgmt_server_sockaddr_v6) {
                if(check_event_addresses(e, msaf_self()->config.m1_server_sockaddr, msaf_self()->config.m1_server_sockaddr_v6)){
                    e->message = &message;
                    ogs_fsm_dispatch(&msaf_self()->msaf_fsm.msaf_m1_sm, e);
                }
            } else
            if(check_event_addresses(e, msaf_self()->config.maf_mgmt_server_sockaddr, msaf_self()->config.maf_mgmt_server_sockaddr_v6)){
                e->message =  &message;
                ogs_fsm_dispatch(&msaf_self()->msaf_fsm.msaf_maf_mgmt_sm, e);

            } else {
                char *error;
                error = ogs_msprintf("Resource [%s] not found.", request->h.uri);
                ogs_assert(true == nf_server_send_error(stream, OGS_SBI_HTTP_STATUS_NOT_FOUND, 1, NULL, "Not Found.", error, NULL, NULL, app_meta));
                ogs_free(error);
            }
            ogs_sbi_message_free(&message);
            break;

            CASE("3gpp-m5")
            if(check_event_addresses(e, msaf_self()->config.m5_server_sockaddr, msaf_self()->config.m5_server_sockaddr_v6)){
                e->message =  &message;
                ogs_fsm_dispatch(&msaf_self()->msaf_fsm.msaf_m5_sm, e);

            } else {
                char *error;
                error = ogs_msprintf("Resource [%s] not found.", request->h.uri);
                ogs_assert(true == nf_server_send_error(stream, OGS_SBI_HTTP_STATUS_NOT_FOUND, 1, NULL, "Not Found.", error, NULL, NULL, app_meta));
                ogs_free(error);
            }
            ogs_sbi_message_free(&message);
            break;
            DEFAULT
            ogs_error("Invalid API name [%s]", message.h.service.name);
            ogs_assert(true == nf_server_send_error(stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST, 0, &message, "Invalid API name.",  message.h.service.name, NULL, NULL, app_meta));

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
            message.res_status = response->status;

            SWITCH(message.h.service.name)

            CASE("3gpp-m3")
            SWITCH(message.h.resource.component[0])
            CASE("content-hosting-configurations")

            msaf_application_server_state_node_t *as_state;
            as_state = e->application_server_state;
            ogs_assert(as_state);

            if (message.h.resource.component[1] && message.h.resource.component[2]) {

                if (!strcmp(message.h.resource.component[2],"purge")) {

                    SWITCH(message.h.method)
                    CASE(OGS_SBI_HTTP_METHOD_POST)
                    purge_resource_id_node_t *purge_node = e->purge_node;

                    if (response->status == 204 || response->status == 200) {

                        purge_resource_id_node_t *content_hosting_cache, *next = NULL;

                        if (response->status == 200) {
                            //parse the int in response body
                            //Add the integer to purge_node->m1_purge_info->purged_entries_total;
                            {
                                ogs_hash_index_t *hi;
                                for (hi = ogs_hash_first(request->http.headers);
                                     hi; hi = ogs_hash_next(hi)) {
                                    if (!ogs_strcasecmp(ogs_hash_this_key(hi), OGS_SBI_CONTENT_TYPE)) {
                                        if (ogs_strcasecmp(ogs_hash_this_val(hi), "application/json")) {
                                            char *err = NULL;
                                            char *type = NULL;
                                            type = (char *)ogs_hash_this_val(hi);
                                            ogs_error("Unsupported Media Type: received type: %s, should have been application/x-www-form-urlencoded", type);
                                            asprintf(&err, "Unsupported Media Type: received type: %s, should have been application/x-www-form-urlencoded", type);

                                            ogs_assert(true == nf_server_send_error(stream, 415, 2, &message, "Provisioning session does not exist.", err, NULL, m3_contenthostingprovisioning_api, app_meta));
                                            ogs_sbi_message_free(&message);
                                            return;
                                        }
                                    }
                                }
                            }

                            int purged_items_from_as =  0;
                            cJSON *entry;
                            cJSON *number_of_cache_entries = cJSON_Parse(response->http.content);
                            cJSON_ArrayForEach(entry, number_of_cache_entries) {
                                ogs_debug("Purged entries return %d\n", entry->valueint);
                                purged_items_from_as = entry->valueint;

                            }
                            purge_node->m1_purge_info->purged_entries_total += purged_items_from_as;

                        }


                        ogs_list_for_each_safe(&as_state->purge_content_hosting_cache, next, content_hosting_cache){
                            if (purge_node->purge_regex) {
                                if(!strcmp(content_hosting_cache->provisioning_session_id, purge_node->provisioning_session_id) && !strcmp(content_hosting_cache->purge_regex, purge_node->purge_regex))
                                    break;
                            } else if(!strcmp(content_hosting_cache->provisioning_session_id, purge_node->provisioning_session_id)) {
                                break;
                            }
                        }
                        if(content_hosting_cache){
                            ogs_list_remove(&as_state->purge_content_hosting_cache, content_hosting_cache);
                            ogs_debug("M1 List Purge refs: %d, Event Purge node refs: %d ", content_hosting_cache->m1_purge_info->refs, purge_node->m1_purge_info->refs);

                            purge_node->m1_purge_info->refs--;
                            ogs_debug(" After decrement, M1 List Purge refs: %d, Event Purge node refs: %d ", content_hosting_cache->m1_purge_info->refs, purge_node->m1_purge_info->refs);
                            if(!purge_node->m1_purge_info->refs){
                                //  send M1 response with total from purge_node->m1_purge_info->purged_entries_total
                                //  ogs_free(purge_node->m1_purge_info);
                                ogs_sbi_response_t *response;
                                cJSON *purged_entries_total_json = cJSON_CreateNumber(purge_node->m1_purge_info->purged_entries_total);
                                char *purged_entries_total = cJSON_Print(purged_entries_total_json);
                                response = ogs_sbi_response_new();
                                response->http.content_length = strlen(purged_entries_total);
                                response->http.content = purged_entries_total;
                                response->status = 200;
                                ogs_sbi_header_set(response->http.headers, "Content-Type", "application/json");
                                ogs_assert(response);
                                ogs_assert(true == ogs_sbi_server_send_response(purge_node->m1_purge_info->m1_stream, response));

                                if(content_hosting_cache->m1_purge_info) ogs_free(content_hosting_cache->m1_purge_info);
                                if (content_hosting_cache->provisioning_session_id) ogs_free(content_hosting_cache->provisioning_session_id);
                                if(content_hosting_cache->purge_regex) ogs_free(content_hosting_cache->purge_regex);
                                ogs_free(content_hosting_cache);
                            }
                            msaf_application_server_state_log(&as_state->purge_content_hosting_cache, "Purge Content Hosting Cache list");

                        }
                    }


                    if((response->status == 404) || (response->status == 413) || (response->status == 414) || (response->status == 415) || (response->status == 422) || (response->status == 500) || (response->status == 503)) {
                        char *error;
                        purge_resource_id_node_t *content_hosting_cache, *next = NULL;
                        cJSON *purge_cache_err = NULL;
                        if(response->http.content){
                            purge_cache_err = cJSON_Parse(response->http.content);
                            char *txt = cJSON_Print(purge_cache_err);
                            ogs_debug("txt:%s", txt);
                        }

                        if(response->status == 404) {

                            ogs_error("Error message from the Application Server [%s] with response code [%d]: Cache not found\n", as_state->application_server->canonicalHostname, response->status);
                        } else if(response->status == 413) {
                            ogs_error("Error message from the Application Server [%s] with response code [%d]: Pay load too large\n", as_state->application_server->canonicalHostname, response->status);
                        } else if(response->status == 414) {
                            ogs_error("Error message from the Application Server [%s] with response code [%d]: URI too long\n", as_state->application_server->canonicalHostname, response->status);
                        } else if(response->status == 415) {
                            ogs_error("Error message from the Application Server [%s] with response code [%d]: Unsupported media type\n", as_state->application_server->canonicalHostname, response->status);
                        } else if(response->status == 422) {
                            ogs_error("Error message from the Application Server [%s] with response code [%d]: Unprocessable Entity\n", as_state->application_server->canonicalHostname, response->status);
                        } else if(response->status == 500) {
                            ogs_error("Error message from the Application Server [%s] with response code [%d]: Internal server error\n", as_state->application_server->canonicalHostname, response->status);
                        } else if(response->status == 503) {
                            ogs_error("Error message from the Application Server [%s] with response code [%d]: Service Unavailable\n", as_state->application_server->canonicalHostname, response->status);
                        } else {

                            ogs_error("Application Server [%s] sent unrecognised response code [%d]", as_state->application_server->canonicalHostname, response->status);
                        }

                        if (purge_node->purge_regex) {
                            error = ogs_msprintf("Application Server possibly encountered problem with regex %s", purge_node->purge_regex);
                        } else {
                            error = ogs_msprintf("Application Server unable to process the contained instructions");
                        }


                        ogs_assert(true == nf_server_send_error( purge_node->m1_purge_info->m1_stream,
                                                                 response->status, 3, &purge_node->m1_purge_info->m1_message, "Problem occured during cache purge", error, purge_cache_err, m1_contenthostingprovisioning_api, app_meta));

                        ogs_list_for_each_safe(&as_state->purge_content_hosting_cache, next, content_hosting_cache){
                            if (purge_node->purge_regex) {
                                if(!strcmp(content_hosting_cache->provisioning_session_id, purge_node->provisioning_session_id) && !strcmp(content_hosting_cache->purge_regex, purge_node->purge_regex)) {

                                    ogs_list_remove(&as_state->purge_content_hosting_cache, content_hosting_cache);
                                    ogs_debug("M1 List Purge refs: %d, Event Purge node refs: %d ", content_hosting_cache->m1_purge_info->refs, purge_node->m1_purge_info->refs);
                                    if(content_hosting_cache->m1_purge_info) ogs_free(content_hosting_cache->m1_purge_info);
                                    if (content_hosting_cache->provisioning_session_id) ogs_free(content_hosting_cache->provisioning_session_id);
                                    if(content_hosting_cache->purge_regex) ogs_free(content_hosting_cache->purge_regex);
                                    ogs_free(content_hosting_cache);

                                }
                            } else if(!strcmp(content_hosting_cache->provisioning_session_id, purge_node->provisioning_session_id)) {

                                ogs_list_remove(&as_state->purge_content_hosting_cache, content_hosting_cache);
                                ogs_debug("M1 List Purge refs: %d, Event Purge node refs: %d ", content_hosting_cache->m1_purge_info->refs, purge_node->m1_purge_info->refs);
                                if(content_hosting_cache->m1_purge_info) ogs_free(content_hosting_cache->m1_purge_info);
                                if (content_hosting_cache->provisioning_session_id) ogs_free(content_hosting_cache->provisioning_session_id);
                                if(content_hosting_cache->purge_regex) ogs_free(content_hosting_cache->purge_regex);
                                ogs_free(content_hosting_cache);

                            }
                        }
                        ogs_free(error);
                        cJSON_Delete(purge_cache_err);

                    }

                    next_action_for_application_server(as_state);
                    break;
                    END
                    break;

                }
            } else if (message.h.resource.component[1]) {

                SWITCH(message.h.method)
                CASE(OGS_SBI_HTTP_METHOD_POST)

                if (response->status == 201) {

                    ogs_debug("[%s] Method [%s] with Response [%d] recieved for Content Hosting Configuration [%s]", message.h.resource.component[0], message.h.method, response->status, message.h.resource.component[1]);

                    resource_id_node_t *content_hosting_configuration;
                    ogs_list_for_each(&as_state->upload_content_hosting_configurations,content_hosting_configuration) {
                        if(!strcmp(content_hosting_configuration->state, message.h.resource.component[1]))
                            break;
                    }
                    if(content_hosting_configuration) {

                        ogs_debug("Removing %s from upload_content_hosting_configurations", content_hosting_configuration->state);
                        ogs_list_remove(&as_state->upload_content_hosting_configurations, content_hosting_configuration);
                        ogs_debug("Adding %s to current_content_hosting_configurations",content_hosting_configuration->state);
                        ogs_list_add(as_state->current_content_hosting_configurations, content_hosting_configuration);
                    }

                }
                if(response->status == 405){
                    ogs_error("Content Hosting Configuration resource already exist at the specified path\n");
                }
                if(response->status == 413){
                    ogs_error("Payload too large\n");
                }
                if(response->status == 414){
                    ogs_error("URI too long\n");
                }
                if(response->status == 415){
                    ogs_error("Unsupported media type\n");
                }
                if(response->status == 500){
                    ogs_error("Internal server error\n");
                }
                if(response->status == 503){
                    ogs_error("Service unavailable\n");
                }
                next_action_for_application_server(as_state);
                break;
                CASE(OGS_SBI_HTTP_METHOD_PUT)
                if(response->status == 200 || response->status == 204) {

                    ogs_debug("[%s] Method [%s] with Response [%d] recieved for Content Hosting Configuration [%s]", message.h.resource.component[0], message.h.method, response->status, message.h.resource.component[1]);
                    resource_id_node_t *content_hosting_configuration;
                    ogs_list_for_each(&as_state->upload_content_hosting_configurations,content_hosting_configuration){
                        if(!strcmp(content_hosting_configuration->state, message.h.resource.component[1]))
                            break;
                    }
                    if(content_hosting_configuration) {

                        ogs_debug("Removing %s from upload_content_hosting_configurations", content_hosting_configuration->state);
                        ogs_free(content_hosting_configuration->state);
                        ogs_list_remove(&as_state->upload_content_hosting_configurations, content_hosting_configuration);
                        ogs_free(content_hosting_configuration);
                    }

                }
                if(response->status == 404){
                    ogs_error("Not Found\n");
                }
                if(response->status == 413){
                    ogs_error("Payload too large\n");
                }
                if(response->status == 414){
                    ogs_error("URI too long\n");
                }
                if(response->status == 415){
                    ogs_error("Unsupported Media Type\n");
                }
                if(response->status == 500){
                    ogs_error("Internal Server Error\n");
                }
                if(response->status == 503){
                    ogs_error("Service Unavailable\n");
                }
                next_action_for_application_server(as_state);
                break;
                CASE(OGS_SBI_HTTP_METHOD_DELETE)
                if(response->status == 204) {

                    ogs_debug("[%s] Method [%s] with Response [%d] recieved for Content Hosting Configuration [%s]", message.h.resource.component[0], message.h.method, response->status,message.h.resource.component[1]);

                    resource_id_node_t *content_hosting_configuration, *next = NULL;
                    resource_id_node_t *delete_content_hosting_configuration, *node = NULL;

                    if(as_state->current_content_hosting_configurations) {

                        ogs_list_for_each_safe(as_state->current_content_hosting_configurations, next, content_hosting_configuration){

                            if(!strcmp(content_hosting_configuration->state, message.h.resource.component[1]))
                                break;
                        }
                    }

                    if(content_hosting_configuration) {

                        msaf_application_server_state_log(as_state->current_content_hosting_configurations, "Current Content Hosting Configurations");

                        ogs_debug("Removing %s from current_content_hosting_configurations", content_hosting_configuration->state);
                        ogs_free(content_hosting_configuration->state);
                        ogs_list_remove(as_state->current_content_hosting_configurations, content_hosting_configuration);
                        ogs_free(content_hosting_configuration);
                        msaf_application_server_state_log(as_state->current_content_hosting_configurations, "Current Content Hosting Configurations");
                    }

                    ogs_list_for_each_safe(&as_state->delete_content_hosting_configurations, node, delete_content_hosting_configuration) {

                        if (!strcmp(delete_content_hosting_configuration->state, message.h.resource.component[1])) {

                            msaf_application_server_state_log(&as_state->delete_content_hosting_configurations, "Delete Content Hosting Configurations");

                            ogs_debug("Destroying Content Hosting Configuration: %s", delete_content_hosting_configuration->state);
                            ogs_free(delete_content_hosting_configuration->state);
                            ogs_list_remove(&as_state->delete_content_hosting_configurations, delete_content_hosting_configuration);
                            ogs_free(delete_content_hosting_configuration);

                            msaf_application_server_state_log(&as_state->delete_content_hosting_configurations, "Delete Content Hosting Configurations");
                        }
                    }

                }
                if(response->status == 404){
                    ogs_error("Not Found\n");
                }
                if(response->status == 413){
                    ogs_error("Payload too large\n");
                }
                if(response->status == 414){
                    ogs_error("URI too long\n");
                }
                if(response->status == 415){
                    ogs_error("Unsupported Media Type\n");
                }
                if(response->status == 500){
                    ogs_error("Internal Server Error\n");
                }
                if(response->status == 503){
                    ogs_error("Service Unavailable\n");
                }
                next_action_for_application_server(as_state);
                break;
                DEFAULT
                ogs_error("Unknown M3 Content Hosting Configuration operation [%s]", message.h.resource.component[1]);
                ogs_assert(true == nf_server_send_error(stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST, 0, &message, "Unknown M3 Content Hosting Configuration operation", message.h.resource.component[1], NULL, NULL, app_meta));
                break;
                END
                break;
            } else {
                cJSON *entry;
                cJSON *chc_array = cJSON_Parse(response->http.content);
                resource_id_node_t *current_chc;
                SWITCH(message.h.method)
                CASE(OGS_SBI_HTTP_METHOD_GET)

                if(response->status == 200) {

                    ogs_debug("[%s] Method [%s] with Response [%d] for Content Hosting Configuration operation [%s]",
                              message.h.resource.component[0], message.h.method, response->status, message.h.resource.component[1]);

                    if (as_state->current_content_hosting_configurations == NULL) {
                        as_state->current_content_hosting_configurations = ogs_calloc(1,sizeof(*as_state->current_content_hosting_configurations));
                        ogs_assert(as_state->current_content_hosting_configurations);
                        ogs_list_init(as_state->current_content_hosting_configurations);

                    } else {
                        resource_id_node_t *next, *node;
                        ogs_list_for_each_safe(as_state->current_content_hosting_configurations, next, node) {
                            ogs_free(node->state);
                            ogs_list_remove(as_state->current_content_hosting_configurations, node);
                            ogs_free(node);
                        }
                    }
                    cJSON_ArrayForEach(entry, chc_array) {
                        char *id = strrchr(entry->valuestring, '/');
                        if (id == NULL) {
                            id = entry->valuestring;
                        } else {
                            id++;
                        }
                        current_chc = ogs_calloc(1, sizeof(*current_chc));
                        current_chc->state = ogs_strdup(id);
                        ogs_debug("Adding [%s] to the current Content Hosting Configuration list",current_chc->state);
                        ogs_list_add(as_state->current_content_hosting_configurations, current_chc);
                    }

                    cJSON_Delete(chc_array);
                }
                if (response->status == 500){
                    ogs_error("Received Internal Server error\n");
                }
                if (response->status == 503) {
                    ogs_error("Service Unavailable\n");
                }
                next_action_for_application_server(as_state);
                break;
                DEFAULT
                char *err;
                ogs_error("Unknown M3 Content Hosting Configuration operation [%s] with method [%s]", message.h.resource.component[1], message.h.method);
                asprintf(&err, "Unknown M3 Content Hosting Configuration operation [%s] with method [%s]", message.h.resource.component[1], message.h.method);
                ogs_assert(true == nf_server_send_error(stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST, 0, &message, "Unknown M3 Content Hosting Configuration operation", err, NULL, NULL, app_meta));

                break;
                END
                break;
            }
            next_action_for_application_server(as_state);

            break;

            CASE("certificates")

            msaf_application_server_state_node_t *as_state;
            as_state = e->application_server_state;
            ogs_assert(as_state);
            if (message.h.resource.component[1]) {
                SWITCH(message.h.method)
                CASE(OGS_SBI_HTTP_METHOD_POST)
                if(response->status == 201) {

                    ogs_debug("[%s] Method [%s] with Response [%d] recieved for certificate [%s]", message.h.resource.component[0], message.h.method, response->status, message.h.resource.component[1]);

                    resource_id_node_t *certificate;

                    //Iterate upload_certs and find match strcmp resource component 0
                    ogs_list_for_each(&as_state->upload_certificates,certificate){
                        if(!strcmp(certificate->state, message.h.resource.component[1]))
                            break;
                    }
                    if(certificate) {

                        ogs_debug("Removing certificate [%s] from upload_certificates", certificate->state);

                        ogs_list_remove(&as_state->upload_certificates, certificate);

                        ogs_debug("Adding certificate [%s] to  current_certificates", certificate->state);

                        ogs_list_add(as_state->current_certificates, certificate);
                        // ogs_free(upload_cert_id);
                    }
                }
                if(response->status == 405){
                    ogs_error("Server Certificate resource already exist at the specified path\n");
                }
                if(response->status == 413){
                    ogs_error("Payload too large\n");
                }
                if(response->status == 414){
                    ogs_error("URI too long\n");
                }
                if(response->status == 415){
                    ogs_error("Unsupported media type\n");
                }
                if(response->status == 500){
                    ogs_error("Internal server error\n");
                }
                if(response->status == 503){
                    ogs_error("Service unavailable\n");
                }
                next_action_for_application_server(as_state);
                break;
                CASE(OGS_SBI_HTTP_METHOD_PUT)
                if(response->status == 200 || response->status == 204) {

                    ogs_debug("[%s] Method [%s] with Response [%d] recieved for certificate [%s]", message.h.resource.component[0], message.h.method, response->status,message.h.resource.component[1]);

                    resource_id_node_t *certificate;

                    msaf_application_server_state_log(&as_state->upload_certificates, "Upload Certificates");

                    //Iterate upload_certs and find match strcmp resource component 0
                    ogs_list_for_each(&as_state->upload_certificates,certificate){

                        if(!strcmp(certificate->state, message.h.resource.component[1]))
                            break;
                    }

                    if(!certificate){
                        ogs_debug("Certificate %s not found in upload certificates", message.h.resource.component[1]);
                    } else {
                        ogs_debug("Removing certificate [%s] from upload_certificates", certificate->state);
                        ogs_free(certificate->state);

                        ogs_list_remove(&as_state->upload_certificates, certificate);
                        ogs_free(certificate);
                    }
                }
                if(response->status == 404){
                    ogs_error("Not Found\n");
                }
                if(response->status == 413){
                    ogs_error("Payload too large\n");
                }
                if(response->status == 414){
                    ogs_error("URI too long\n");
                }
                if(response->status == 415){
                    ogs_error("Unsupported Media Type\n");
                }
                if(response->status == 500){
                    ogs_error("Internal Server Error\n");
                }
                if(response->status == 503){
                    ogs_error("Service Unavailable\n");
                }
                next_action_for_application_server(as_state);
                break;
                CASE(OGS_SBI_HTTP_METHOD_DELETE)
                if(response->status == 204) {

                    ogs_debug("[%s] Method [%s] with Response [%d] recieved for Certificate [%s]", message.h.resource.component[0], message.h.method, response->status,message.h.resource.component[1]);

                    resource_id_node_t *certificate, *next = NULL;
                    resource_id_node_t *delete_certificate, *node = NULL;

                    if(as_state->current_certificates) {
                        ogs_list_for_each_safe(as_state->current_certificates, next, certificate){

                            if(!strcmp(certificate->state, message.h.resource.component[1]))
                                break;
                        }
                    }

                    if(certificate) {

                        msaf_application_server_state_log(as_state->current_certificates, "Current Certificates");

                        ogs_debug("Removing certificate [%s] from current_certificates", certificate->state);
                        ogs_free(certificate->state);

                        ogs_list_remove(as_state->current_certificates, certificate);
                        ogs_free(certificate);
                        msaf_application_server_state_log(as_state->current_certificates, "Current Certificates");
                    }


                    ogs_list_for_each_safe(&as_state->delete_certificates, node, delete_certificate){

                        if(!strcmp(delete_certificate->state, message.h.resource.component[1])) {
                            msaf_application_server_state_log(&as_state->delete_certificates, "Delete Certificates");

                            ogs_debug("Destroying Certificate: %s", delete_certificate->state);
                            ogs_free(delete_certificate->state);
                            ogs_list_remove(&as_state->delete_certificates, delete_certificate);
                            ogs_free(delete_certificate);
                            msaf_application_server_state_log(&as_state->delete_certificates, "Delete Certificates");

                        }
                    }
                }
                if(response->status == 404){
                    ogs_error("Not Found\n");
                }
                if(response->status == 413){
                    ogs_error("Payload too large\n");
                }
                if(response->status == 414){
                    ogs_error("URI too long\n");
                }
                if(response->status == 415){
                    ogs_error("Unsupported Media Type\n");
                }
                if(response->status == 500){
                    ogs_error("Internal Server Error\n");
                }
                if(response->status == 503){
                    ogs_error("Service Unavailable\n");
                }
                next_action_for_application_server(as_state);
                break;
                DEFAULT
                ogs_error("Unknown M3 certificate operation [%s]", message.h.resource.component[1]);
                ogs_assert(true == nf_server_send_error(stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST, 0, &message, "Unknown M3 certificate operation.", message.h.resource.component[1], NULL, NULL, app_meta));
                break;
                END
                break;
            } else {
                cJSON *entry;
                cJSON *cert_array = cJSON_Parse(response->http.content);
                resource_id_node_t *current_cert;
                SWITCH(message.h.method)
                CASE(OGS_SBI_HTTP_METHOD_GET)

                if(response->status == 200) {

                    ogs_debug("[%s] Method [%s] with Response [%d] received",
                              message.h.resource.component[0], message.h.method, response->status);

                    if (as_state->current_certificates == NULL) {
                        as_state->current_certificates = ogs_calloc(1,sizeof(*as_state->current_certificates));
                        ogs_assert(as_state->current_certificates);
                        ogs_list_init(as_state->current_certificates);

                    } else {
                        resource_id_node_t *next, *node;
                        ogs_list_for_each_safe(as_state->current_certificates, next, node) {

                            ogs_debug("Removing certificate [%s] from current_certificates", node->state);

                            ogs_free(node->state);
                            ogs_list_remove(as_state->current_certificates, node);
                            ogs_free(node);
                        }
                    }
                    cJSON_ArrayForEach(entry, cert_array) {
                        char *id = strrchr(entry->valuestring, '/');
                        if (id == NULL) {
                            id = entry->valuestring;
                        } else {
                            id++;
                        }
                        current_cert = ogs_calloc(1, sizeof(*current_cert));
                        current_cert->state = ogs_strdup(id);
                        ogs_debug("Adding certificate [%s] to Current certificates", current_cert->state);
                        ogs_list_add(as_state->current_certificates, current_cert);
                    }

                    cJSON_Delete(cert_array);
                }
                if (response->status == 500){
                    ogs_error("Received Internal Server error");
                }
                if (response->status == 503) {
                    ogs_error("Service Unavailable");
                }
                next_action_for_application_server(as_state);
                break;
                DEFAULT
                char *err;
                ogs_error("Unknown M3 certificate operation [%s] with method [%s]", message.h.resource.component[1], message.h.method);
                asprintf(&err, "Unsupported M3 Certificate operation [%s] with method [%s]", message.h.resource.component[1], message.h.method);
                ogs_assert(true == nf_server_send_error(stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST, 0, &message, "Unknown M3 Certificate operation", err, NULL, NULL, app_meta));

                break;
                END
                break;
            }
            next_action_for_application_server(as_state);

            break;

            DEFAULT
            ogs_error("Unknown M3 operation [%s]", message.h.resource.component[0]);
            ogs_assert(true == nf_server_send_error(stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST, 0, &message, "Unsupported M3 operation", message.h.resource.component[0], NULL, NULL, app_meta));
            break;
            END
            break;

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
