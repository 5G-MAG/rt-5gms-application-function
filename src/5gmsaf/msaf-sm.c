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

void msaf_state_initial(ogs_fsm_t *s, msaf_event_t *e)
{
    msaf_sm_debug(e);

    ogs_assert(s);

    OGS_FSM_TRAN(s, &msaf_state_functional);
}

void msaf_state_final(ogs_fsm_t *s, msaf_event_t *e)
{
    msaf_sm_debug(e);

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

    ogs_assert(s);

    switch (e->h.id) {
        case OGS_FSM_ENTRY_SIG:
            ogs_info("[%s] MSAF Running", ogs_sbi_self()->nf_instance->id);    
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
                ogs_sbi_message_free(&message);
                ogs_sbi_response_free(request);
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
                    break;

                CASE("3gpp-m1")
                    if (strcmp(message.h.api.version, "v2") != 0) {
                        ogs_error("Not supported version [%s]", message.h.api.version);
                        ogs_assert(true ==
                                ogs_sbi_server_send_error(
                                        stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                                        &message, "Not supported version", NULL));
                        ogs_sbi_message_free(&message);
                        break;
                    }
                    SWITCH(message.h.resource.component[0])
                        CASE("provisioning-sessions") 
                            SWITCH(message.h.method)
                                CASE(OGS_SBI_HTTP_METHOD_POST)

                                    cJSON *entry;
                                    cJSON *prov_sess = cJSON_Parse(request->http.content);
                                    cJSON *provisioning_session;
				                    char *provisioning_session_type, *asp_id, *external_app_id;
		                            msaf_provisioning_session_t *msaf_provisioning_session;

                                    cJSON_ArrayForEach(entry, prov_sess) {
                                        if(!strcmp(entry->string, "provisioningSessionType")){
                                            provisioning_session_type = entry->valuestring;
                                        }
                                        if(!strcmp(entry->string, "aspId")){
                                            asp_id = entry->valuestring;
                                        }
                                        if(!strcmp(entry->string, "externalApplicationId")){
                                            external_app_id = entry->valuestring;
                                        }
                                  
                                    }
                                    msaf_provisioning_session = msaf_provisioning_session_create(provisioning_session_type, asp_id, external_app_id);
	                                provisioning_session = msaf_provisioning_session_get_json(msaf_provisioning_session->provisioningSessionId);
                                    if (provisioning_session != NULL) {
                                        ogs_sbi_response_t *response;
                                        char *text;
					                    char *location;
                                        response = ogs_sbi_response_new();
                                        text = cJSON_Print(provisioning_session);
                                        response->http.content_length = strlen(text);
                                        response->http.content = text;
                                        response->status = 201;
                                        ogs_sbi_header_set(response->http.headers, "Content-Type", "application/json");

					                    if (request->h.uri[strlen(request->h.uri)-1] != '/') {
                                            location = ogs_msprintf("%s/%s", request->h.uri,msaf_provisioning_session->provisioningSessionId);
                                        } else {
					                        location = ogs_msprintf("%s%s", request->h.uri,msaf_provisioning_session->provisioningSessionId);
                                           }
					                    ogs_sbi_header_set(response->http.headers, "Location", location);
                                        ogs_assert(response);
                                        ogs_assert(true == ogs_sbi_server_send_response(stream, response));
                                        ogs_free(location);
                                        cJSON_Delete(provisioning_session);
                                        cJSON_Delete(prov_sess);
                                    } else {
                                        char *err = NULL;
                                        asprintf(&err,"Creation of the Provisioning session failed.");
                                        ogs_error("Creation of the Provisioning session failed.");
                                        ogs_assert(true == ogs_sbi_server_send_error(stream,
                                                    404, &message,
                                                    "Creation of the Provisioning session failed.",
                                                    err));
                                    }
                                    break;

                                CASE(OGS_SBI_HTTP_METHOD_GET)
				                    if (message.h.resource.component[1]) {
                                        ogs_sbi_response_t *response;
                                        msaf_provisioning_session_t *msaf_provisioning_session = NULL;
                                        cJSON *provisioning_session = NULL;

                                        msaf_provisioning_session = msaf_provisioning_session_find_by_provisioningSessionId(message.h.resource.component[1]);

                                        provisioning_session = msaf_provisioning_session_get_json(message.h.resource.component[1]);

                                        if (provisioning_session && msaf_provisioning_session && !msaf_provisioning_session->marked_for_deletion) {
                                            ogs_sbi_response_t *response;
                                            char *text;
                                            char *location;
                                            response = ogs_sbi_response_new();
                                            text = cJSON_Print(provisioning_session);
                                            response->http.content_length = strlen(text);
                                            response->http.content = text;
                                            response->status = 200;
                                            ogs_sbi_header_set(response->http.headers, "Content-Type", "application/json");

                                            ogs_assert(response);
                                            ogs_assert(true == ogs_sbi_server_send_response(stream, response));
                                            cJSON_Delete(provisioning_session);
                                            
                                        } else {
                                            char *err = NULL;
                                            asprintf(&err,"Provisioning session is not available.");
                                            ogs_error("Provisioning session is not available.");
                                            ogs_assert(true == ogs_sbi_server_send_error(stream,
                                                        404, &message,
                                                        "Provisioning session is not available.",
                                                        err));
                                        }
                                    }
                                    break;

                                CASE(OGS_SBI_HTTP_METHOD_DELETE)
				                    if (message.h.resource.component[1]) {
                                        ogs_sbi_response_t *response;
                                        msaf_provisioning_session_t *provisioning_session = NULL;
                                        provisioning_session = msaf_provisioning_session_find_by_provisioningSessionId(message.h.resource.component[1]);
                                        if(!provisioning_session || provisioning_session->marked_for_deletion){
                                            char *err = NULL;
                                            ogs_error("Provisioning session either not found or already marked for deletion.");
                                            ogs_assert(true == ogs_sbi_server_send_error(stream,
                                                    404, &message,
                                                    "Unable to find the Provisioning session or it is marked for deletion already.",
                                                    err));
                                        } else {
                                            
                                            provisioning_session->marked_for_deletion = 1;
                                    
                                            response = ogs_sbi_response_new();
                                            ogs_assert(response);
                                            response->status = 202;
                                            ogs_assert(true == ogs_sbi_server_send_response(stream, response));

                                            msaf_delete_content_hosting_configuration(message.h.resource.component[1]);
                                            msaf_delete_certificate(message.h.resource.component[1]);
                                            msaf_context_provisioning_session_free(provisioning_session);
                                        }
				                    }
                                    break;

				                DEFAULT
                                    ogs_error("Invalid HTTP method [%s]", message.h.method);
                                    ogs_assert(true == ogs_sbi_server_send_error(stream,
                                                 OGS_SBI_HTTP_STATUS_FORBIDDEN,
                                                 &message, "Invalid HTTP method",
                                                 message.h.method));
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
            
                CASE("3gpp-m5")
                    if (strcmp(message.h.api.version, "v2") != 0) {
                        ogs_error("Not supported version [%s]", message.h.api.version);
                        ogs_assert(true ==
                                ogs_sbi_server_send_error(
                                        stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                                        &message, "Not supported version", NULL));
                        ogs_sbi_message_free(&message);
                        break;
                    }
                    SWITCH(message.h.resource.component[0])
                        CASE("service-access-information") 
                            SWITCH(message.h.method)
                                CASE(OGS_SBI_HTTP_METHOD_GET)
                                    cJSON *service_access_information;

                                    service_access_information = msaf_context_retrieve_service_access_information(message.h.resource.component[1]);
                                    if (service_access_information != NULL) {
                                        ogs_sbi_response_t *response;
                                        char *text;
                                        response = ogs_sbi_response_new();
                                        text = cJSON_Print(service_access_information);
                                        response->http.content_length = strlen(text);
                                        response->http.content = text;
                                        response->status = 200;
                                        ogs_sbi_header_set(response->http.headers, "Content-Type", "application/json");
                                        ogs_assert(response);
                                        ogs_assert(true == ogs_sbi_server_send_response(stream, response));
                                        cJSON_Delete(service_access_information);
                                    } else {
                                        char *err = NULL;
                                        asprintf(&err,"Service Access Information %s not found.", message.h.resource.component[1]);
                                        ogs_error("Client requested invalid Service Access Information [%s]", message.h.resource.component[1]);
                                        ogs_assert(true == ogs_sbi_server_send_error(stream,
                                                    404, &message,
                                                    "Service Access Information not found",
                                                    err));
                                    }
                                    break;
                                DEFAULT
                                    ogs_error("Invalid HTTP method [%s]", message.h.method);
                                    ogs_assert(true == ogs_sbi_server_send_error(stream,
                                                 OGS_SBI_HTTP_STATUS_FORBIDDEN,
                                                 &message, "Invalid HTTP method",
                                                 message.h.method));
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
                    break;
                DEFAULT
                    ogs_error("Invalid API name [%s]", message.h.service.name);
                    ogs_assert(true ==
                            ogs_sbi_server_send_error(stream,
                                OGS_SBI_HTTP_STATUS_BAD_REQUEST, &message,
                                "Invalid API name", message.h.service.name));
            END

            ogs_sbi_message_free(&message);
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
                CASE("3gpp-m3")
                    SWITCH(message.h.resource.component[0])
                        CASE("content-hosting-configurations")

                            msaf_application_server_state_node_t *as_state;
                            as_state = e->application_server_state;
                            ogs_assert(as_state);
                            if (message.h.resource.component[1]) {
                                char *upload_chc;
                                char *provisioning_session;
                                char *chc_id;
                                char *chc;
                                char *upload_chc_id;
                                SWITCH(message.h.method)
                                    CASE(OGS_SBI_HTTP_METHOD_POST)

                                        if (response->status == 201) {

                                            ogs_info("[%s] Method [%s] with Response [%d] recieved for Content Hosting Configuration [%s]", message.h.resource.component[0], message.h.method, response->status, message.h.resource.component[1]);

                                            resource_id_node_t *content_hosting_configuration;	
                                            ogs_list_for_each(&as_state->upload_content_hosting_configurations,content_hosting_configuration) {
                                                        if(!strcmp(content_hosting_configuration->state, message.h.resource.component[1]))
                                                                break;
                                            }		
                                            if(content_hosting_configuration) {

                                                ogs_info("Removing %s from upload_content_hosting_configurations", content_hosting_configuration->state);  
                                                ogs_list_remove(&as_state->upload_content_hosting_configurations, content_hosting_configuration);
                                                ogs_info("Adding %s to current_content_hosting_configurations",content_hosting_configuration->state); 
                                                ogs_list_add(as_state->current_content_hosting_configurations, content_hosting_configuration);
                                            }
                                             
                                        }                                        
                                        if(response->status == 405){
                                            ogs_error("Content Hosting Configuration resource already exists at the specified path\n");
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

                                            ogs_info("[%s] Method [%s] with Response [%d] recieved for Content Hosting Configuration", message.h.resource.component[0], message.h.method, response->status, message.h.resource.component[1]);
                                            resource_id_node_t *content_hosting_configuration;	
                                            ogs_list_for_each(&as_state->upload_content_hosting_configurations,content_hosting_configuration){
                                            if(!strcmp(content_hosting_configuration->state, message.h.resource.component[1]))
                                                break;
                                            }   		
                                            if(content_hosting_configuration) {

                                                ogs_info("Removing %s from upload_content_hosting_configurations", content_hosting_configuration->state); 
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

					                        ogs_info("[%s] Method [%s] with Response [%d] recieved for Content Hosting Configuration [%s]", message.h.resource.component[0], message.h.method, response->status,message.h.resource.component[1]);

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
						    					
                                                ogs_info("Removing %s from current_content_hosting_configurations", content_hosting_configuration->state);
						                        ogs_free(content_hosting_configuration->state);
                                                ogs_list_remove(as_state->current_content_hosting_configurations, content_hosting_configuration);
                                                 ogs_free(content_hosting_configuration);
                                                msaf_application_server_state_log(as_state->current_content_hosting_configurations, "Current Content Hosting Configurations");
					                        }
					    
					                        if(&as_state->delete_content_hosting_configurations) {

           				                        ogs_list_for_each_safe(&as_state->delete_content_hosting_configurations, node, delete_content_hosting_configuration){

                                                    if(!strcmp(delete_content_hosting_configuration->state, message.h.resource.component[1])) {
                                                        
                                                        msaf_application_server_state_log(&as_state->delete_content_hosting_configurations, "Delete Content Hosting Configurations");    
    						                            
                                                        ogs_info("Destroying Content Hosting Configuration: %s", delete_content_hosting_configuration->state);
                                                        ogs_free(delete_content_hosting_configuration->state);
                                                        ogs_list_remove(&as_state->delete_content_hosting_configurations, delete_content_hosting_configuration);
                                                        ogs_free(delete_content_hosting_configuration);
                                                        
                                                        msaf_application_server_state_log(&as_state->delete_content_hosting_configurations, "Delete Content Hosting Configurations");
                                                    }                                    
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

                                            ogs_info("[%s] Method [%s] with Response [%d] for Content Hosting Configuration",
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
                                                ogs_info("Adding [%s] to the current Content Hosting Configuration list",current_chc->state);
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
                                        ogs_error("Unknown M3 Content Hosting Configuratiobn GET operation [%s]", message.h.resource.component[1]);
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
                                char *upload_cert;
				                char *current_cert;
                                char *provisioning_session;
                                char *cert_id;
                                char *cert;
                                char *location;
                                char *upload_cert_id;
				char *current_cert_id;

                                SWITCH(message.h.method)
                                    CASE(OGS_SBI_HTTP_METHOD_POST)
                                        if(response->status == 201) {

                                            ogs_info("[%s] Method [%s] with Response [%d] recieved for certificate [%s]", message.h.resource.component[0], message.h.method, response->status, message.h.resource.component[1]);

                                            resource_id_node_t *certificate;

                                            //Iterate upload_certs and find match strcmp resource component 0 
                                            ogs_list_for_each(&as_state->upload_certificates,certificate){
                                                if(!strcmp(certificate->state, message.h.resource.component[1]))
                                                    break;
                                            }		
                                            if(certificate) {

                                                ogs_info("Removing certificate [%s] from upload_certificates", certificate->state);

                                                ogs_list_remove(&as_state->upload_certificates, certificate);

                                                ogs_info("Adding certificate [%s] to  current_certificates", certificate->state);

                                                ogs_list_add(as_state->current_certificates, certificate);
                                                // ogs_free(upload_cert_id);
                                            }
                                        }
                                        if(response->status == 405){
                                            ogs_error("Server Certificate resource already exists at the specified path\n");
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

                                            ogs_info("[%s] Method [%s] with Response [%d] recieved for certificate [%s]", message.h.resource.component[0], message.h.method, response->status,message.h.resource.component[1]);

                                            resource_id_node_t *certificate;	

                                            msaf_application_server_state_log(&as_state->upload_certificates, "Upload Certificates");

                                            //Iterate upload_certs and find match strcmp resource component 0 
                                            ogs_list_for_each(&as_state->upload_certificates,certificate){
            
                                                if(!strcmp(certificate->state, message.h.resource.component[1]))
                                                    break;
                                            }
                                            
                                            if(!certificate){
						                        ogs_info("Certificate %s not found in upload certificates", message.h.resource.component[1]);
			    		                    }
                                            		
                                            if(certificate) {
                                                ogs_info("Removing certificate [%s] from upload_certificates", certificate->state);
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
                                          
                                            ogs_info("[%s] Method [%s] with Response [%d] recieved for Certificate [%s]", message.h.resource.component[0], message.h.method, response->status,message.h.resource.component[1]);

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

                                                ogs_info("Removing certificate [%s] from current_certificates", certificate->state);
                                                ogs_free(certificate->state);    
						    
						                        ogs_list_remove(as_state->current_certificates, certificate);
                                                 ogs_free(certificate);  
                                                msaf_application_server_state_log(as_state->current_certificates, "Current Certificates");
					                        }
					    
					                        if(&as_state->delete_certificates) {

           				                        ogs_list_for_each_safe(&as_state->delete_certificates, node, delete_certificate){

                                                    if(!strcmp(delete_certificate->state, message.h.resource.component[1])) {
                                                        msaf_application_server_state_log(&as_state->delete_certificates, "Delete Certificates");
                                                        
                                                        ogs_info("Destroying Certificate: %s", delete_certificate->state);
                                                        ogs_free(delete_certificate->state);
                                                        ogs_list_remove(&as_state->delete_certificates, delete_certificate);
                                                        ogs_free(delete_certificate);
                                                        msaf_application_server_state_log(&as_state->delete_certificates, "Delete Certificates");
                                                    
                                                    }                                    
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

                                            ogs_info("[%s] Method [%s] with Response [%d] received",
                                                message.h.resource.component[0], message.h.method, response->status);
                                            
                                            if (as_state->current_certificates == NULL) {
                                                as_state->current_certificates = ogs_calloc(1,sizeof(*as_state->current_certificates));
                                                ogs_assert(as_state->current_certificates);
                                                ogs_list_init(as_state->current_certificates);

                                            } else {
                                                resource_id_node_t *next, *node;
                                                ogs_list_for_each_safe(as_state->current_certificates, next, node) {

                                                    ogs_info("Removing certificate [%s] from current_certificates", node->state);
                                                   
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
                                                ogs_info("Adding certificate [%s] to Current certificates", current_cert->state);
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
                                        ogs_error("Unknown M3 certificate GET operation [%s]", message.h.resource.component[1]);
                                        break;
                                END
                                break;           
                            }
                            next_action_for_application_server(as_state);

                            break;

                        DEFAULT
                            ogs_error("Unknown M3 operation [%s]", message.h.resource.component[0]);
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

                    ogs_info("Subscription validity expired [%s]",
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
}
