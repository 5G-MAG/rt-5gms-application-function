/*
 * License: 5G-MAG Public License (v1.0)
 * Author: Dev Audsin
 * Copyright: (C) 2023 British Broadcasting Corporation
 *
 * For full license terms please see the LICENSE file distributed with this
 * program. If this file is missing then the license can be retrieved from
 * https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
 */

#include "ogs-sbi.h"
#include "sbi-path.h"
#include "context.h"
#include "certmgr.h"
#include "data-collection.h"
#include "server.h"
#include "sai-cache.h"
#include "response-cache-control.h"
#include "msaf-version.h"
#include "msaf-sm.h"
#include "data-collection.h"
#include "network-assistance-session.h"
#include "dynamic-policy.h"
#include "utilities.h"
#include "hash.h"
#include "timer.h"
#include "openapi/api/TS26512_M5_ServiceAccessInformationAPI-info.h"
#include "openapi/api/TS26512_M5_ConsumptionReportingAPI-info.h"
#include "openapi/api/TS26512_M5_NetworkAssistanceAPI-info.h"
#include "openapi/model/msaf_api_consumption_report.h"
#include "openapi/api/TS26512_M5_DynamicPoliciesAPI-info.h"
#include "openapi/model/msaf_api_operation_success_response.h"

#include "msaf-m5-sm.h"

static const nf_server_interface_metadata_t
m5_serviceaccessinformation_api_metadata = {
    M5_SERVICEACCESSINFORMATION_API_NAME,
    M5_SERVICEACCESSINFORMATION_API_VERSION
};

static const nf_server_interface_metadata_t
m5_consumptionreporting_api_metadata = {
    M5_CONSUMPTIONREPORTING_API_NAME,
    M5_CONSUMPTIONREPORTING_API_VERSION
};

static const nf_server_interface_metadata_t
m5_networkassistance_api_metadata = {
    M5_NETWORKASSISTANCE_API_NAME,
    M5_NETWORKASSISTANCE_API_VERSION
};

static const nf_server_interface_metadata_t
m5_dynamicpolicy_api_metadata = {
    M5_DYNAMICPOLICIES_API_NAME,
    M5_DYNAMICPOLICIES_API_VERSION
};


static bool 
is_dynamic_policy_create_request_valid(ogs_sbi_request_t *request, ogs_sbi_stream_t *stream, ogs_sbi_message_t *message,
                                       const nf_server_interface_metadata_t *m5_dynamicpolicy_api,
                                       const nf_server_app_metadata_t *app_meta);

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
    msaf_event_t *nw_assist_event = NULL;
    msaf_event_t *dynamic_policy_event = NULL;

    msaf_sm_debug(e);

    static const nf_server_interface_metadata_t *m5_serviceaccessinformation_api = &m5_serviceaccessinformation_api_metadata;
    static const nf_server_interface_metadata_t *m5_consumptionreporting_api = &m5_consumptionreporting_api_metadata;
    static const nf_server_interface_metadata_t *m5_networkassistance_api = &m5_networkassistance_api_metadata;
    static const nf_server_interface_metadata_t *m5_dynamicpolicy_api = &m5_dynamicpolicy_api_metadata;
    const nf_server_app_metadata_t *app_meta = msaf_app_metadata();

    ogs_assert(s);

    switch (e->h.id) {
        case OGS_FSM_ENTRY_SIG:
            ogs_info("[%s] MSAF M5 Running", ogs_sbi_self()->nf_instance->id);

            break;

        case OGS_FSM_EXIT_SIG:
            break;
	
	case MSAF_EVENT_DELIVERY_BOOST_TIMER:
            ogs_assert(e);
            switch(e->h.timer_id) {
                case MSAF_TIMER_DELIVERY_BOOST:
	            {		
		        msaf_network_assistance_session_t *na_sess = NULL;
	                na_sess = e->network_assistance_session; 
		        ogs_assert(na_sess);
			ogs_info("MSAF_EVENT_DELIVERY_BOOST_TIMER: MSAF_TIMER_DELIVERY_BOOST");

 		        msaf_nw_assistance_session_update_pcf_on_timeout(na_sess);
		    }
		    break;
                default:
                    ogs_error("Invalid timer for event %s", msaf_event_get_name(e));
                    break;
		    
            }
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
		CASE("dynamic-policies")
                    SWITCH(message->h.method)
		    CASE(OGS_SBI_HTTP_METHOD_DELETE)
                        if(message->h.resource.component[1] && !message->h.resource.component[2])
                        {
                            msaf_dynamic_policy_t *msaf_dynamic_policy = NULL;

			    msaf_dynamic_policy = msaf_dynamic_policy_find_by_dynamicPolicyId(message->h.resource.component[1]);
                            if(!msaf_dynamic_policy) {
				char *err = NULL;
                                err = ogs_msprintf("The AF has no dynamic policy with id [%s].", message->h.resource.component[1]);
                                ogs_error("%s", err);
                                ogs_assert(true == nf_server_send_error(stream, 404, 1, message, "Deleting dynamic policy failed.",
                                           err, NULL, m5_dynamicpolicy_api, app_meta));
                                ogs_free(err);
				break;
                            }

                            dynamic_policy_event = (msaf_event_t*)populate_msaf_event_with_metadata(e, m5_dynamicpolicy_api, app_meta);

                            msaf_dynamic_policy_delete_by_id((const char *)message->h.resource.component[1], dynamic_policy_event);

                        }

                        break;

		    CASE(OGS_SBI_HTTP_METHOD_GET)
			if (message->h.resource.component[1] && !message->h.resource.component[2])    
		        {
			    ogs_sbi_response_t *response;
		    	    cJSON *dynamic_policy = NULL;
			    int response_code = 200;
			    msaf_dynamic_policy_t *msaf_dynamic_policy;
                            char *body;
                            char *hash;


                            dynamic_policy = msaf_dynamic_policy_get_json(message->h.resource.component[1]);
			    
			    if(!dynamic_policy) {
			        const char *err = "Dynamic policy not found";
                                ogs_error("%s", err);
                                ogs_assert(true == nf_server_send_error(stream, 404, 1, message, "Retrieving dynamic policy failed.",
                                           err, NULL, m5_dynamicpolicy_api, app_meta));
				ogs_sbi_message_free(message);
                                ogs_free(message);
                                return;
			    }

			    body = cJSON_Print(dynamic_policy);
                            hash= calculate_hash(body);
			    msaf_dynamic_policy = msaf_dynamic_policy_find_by_dynamicPolicyId((const char *)message->h.resource.component[1]);

                            response = nf_server_new_response(request->h.uri, "application/json",
                                                            msaf_dynamic_policy->dynamic_policy_created, hash,
                                                            msaf_self()->config.server_response_cache_control->m5_service_access_information_response_max_age,
                                                            NULL, m5_dynamicpolicy_api, app_meta);
                            ogs_assert(response);
                            nf_server_populate_response(response, strlen(body), ogs_strdup(body), response_code);
                            ogs_assert(true == ogs_sbi_server_send_response(stream, response));
                            ogs_free(hash);

                            cJSON_Delete(dynamic_policy);
                            cJSON_free(body);


			     
			}
		        break;
		    CASE(OGS_SBI_HTTP_METHOD_POST)
		        {
                            cJSON *dynamic_policy;

                            if (!is_dynamic_policy_create_request_valid (request, stream, message, m5_dynamicpolicy_api, app_meta)) return;

                            ogs_debug("Request body: %s", request->http.content);

                            dynamic_policy = cJSON_Parse(request->http.content);

                            dynamic_policy_event = (msaf_event_t*)populate_msaf_event_with_metadata(e, m5_dynamicpolicy_api, app_meta);

                            if(!msaf_dynamic_policy_create(dynamic_policy, dynamic_policy_event)) {

                                const char *err = "Problem in obtaining the information required to create the Dynamic Policy";
                                ogs_error("%s", err);
                                ogs_assert(true == nf_server_send_error(stream, 400, 0, message, "Creation of the Dynamic Policy failed.", err, NULL, m5_dynamicpolicy_api, app_meta));
                                cJSON_Delete(dynamic_policy);
                                break;
                            }

                            cJSON_Delete(dynamic_policy);
                        }
	                break;
		    CASE(OGS_SBI_HTTP_METHOD_PUT)
			if (message->h.resource.component[1] && !message->h.resource.component[2])    
		        {
                            msaf_api_dynamic_policy_t *dynamic_policy;
                            msaf_dynamic_policy_t *msaf_dynamic_policy = NULL;
			    cJSON *dynamic_policy_received;
			    const char *reason;

                            if(!check_http_content_type(request->http,"application/json")){
                                ogs_assert(true == nf_server_send_error(stream, 415, 1, message, "Unsupported Media Type.", "Expected content type: application/json", NULL, m5_dynamicpolicy_api, app_meta));
                                ogs_sbi_message_free(message);
                                ogs_free(message);
                                return;
                            }

                            if(!request->http.content) {
                                ogs_assert(true == nf_server_send_error(stream, 400, 1, message, "Bad request.", "Request has no content", NULL, m5_dynamicpolicy_api, app_meta));
                                ogs_sbi_message_free(message);
                                ogs_free(message);
                                return; 

                            }

			    dynamic_policy_received = cJSON_Parse(request->http.content);

                            dynamic_policy = msaf_api_dynamic_policy_parseRequestFromJSON(dynamic_policy_received, &reason);

                            if (!dynamic_policy) {
				char *err;
				err = ogs_msprintf("Badly formed Dynamic Policy [%s]", reason);
                                ogs_error("%s", err);
                                ogs_assert(true == nf_server_send_error(stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST, 1, message, "Malformed request body", err, NULL, m5_dynamicpolicy_api, app_meta));
                                ogs_free(err);
                                break;
                            }
			    /*
			    if(strcmp(message->h.resource.component[1], dynamic_policy->dynamic_policy_id)){
                                const char *err = "Updating dynamic policy: The path component and the JSON body have mismatching Dynamic policy id";
                                ogs_error("%s", err);
                                ogs_assert(true == nf_server_send_error(stream, 400, 1, message, "Updating dynamic policy failed.",
                                           err, NULL, m5_dynamicpolicy_api, app_meta));
                                break;
		            }
			    */

			    msaf_dynamic_policy = msaf_dynamic_policy_find_by_dynamicPolicyId(message->h.resource.component[1]);
			    if(!msaf_dynamic_policy) {
			        const char *err = "Updating dynamic policy: Dynamic policy not found";
                                ogs_error("%s", err);
                                ogs_assert(true == nf_server_send_error(stream, 404, 1, message, "Updating dynamic policy failed.",
                                           err, NULL, m5_dynamicpolicy_api, app_meta));
                                break;
	    
			    }
			    
			    if(dynamic_policy->dynamic_policy_id) ogs_free(dynamic_policy->dynamic_policy_id);
			    dynamic_policy->dynamic_policy_id = msaf_strdup(message->h.resource.component[1]);
			    
                            if(!msaf_dynamic_policy_update_pcf(msaf_dynamic_policy, dynamic_policy)) {
			        const char *err = "Updating dynamic policy: Dynamic policy not found";
                                ogs_error("%s", err);
                                ogs_assert(true == nf_server_send_error(stream, 404, 1, message, "Updating dynamic policy failed.",
                                           err, NULL, m5_dynamicpolicy_api, app_meta));
                                break;
			    } else {
                                ogs_sbi_response_t *response;
                                int response_code = 200;
                                char *body;
				char *hash;
				cJSON *dyn_policy;

				dyn_policy = msaf_api_dynamic_policy_convertResponseToJSON((const msaf_api_dynamic_policy_t *)msaf_dynamic_policy->DynamicPolicy);

                                body = cJSON_Print(dyn_policy);
                                hash= calculate_hash(body);

                                response = nf_server_new_response(request->h.uri, "application/json",
                                                            msaf_dynamic_policy->dynamic_policy_created, hash,
                                                            0,
                                                            NULL, m5_dynamicpolicy_api, app_meta);
                                ogs_assert(response);
                                nf_server_populate_response(response, strlen(body), ogs_strdup(body), response_code);
                                ogs_assert(true == ogs_sbi_server_send_response(stream, response));
                                ogs_free(hash);

                                cJSON_Delete(dyn_policy);
                                cJSON_free(body);
    
			    }


			    cJSON_Delete(dynamic_policy_received);


				
			}
	                break; 	    

                    CASE(OGS_SBI_HTTP_METHOD_OPTIONS)
	                if (message->h.resource.component[1] && !message->h.resource.component[2]) {
                            msaf_dynamic_policy_t *msaf_dynamic_policy;             
			    ogs_sbi_response_t *response;
			    char *methods = NULL;
			    msaf_dynamic_policy = msaf_dynamic_policy_find_by_dynamicPolicyId(message->h.resource.component[1]);
                            if(!msaf_dynamic_policy) {
                                const char *err = "OPTIONS: Dynamic policy not found";
                                ogs_error("%s", err);
                                ogs_assert(true == nf_server_send_error(stream, 404, 1, message, "Dynamic policy failed.",
                                           err, NULL, m5_dynamicpolicy_api, app_meta));
                                break;

                            }
			    methods = ogs_msprintf("%s, %s, %s, %s",OGS_SBI_HTTP_METHOD_GET, OGS_SBI_HTTP_METHOD_PUT, OGS_SBI_HTTP_METHOD_DELETE, OGS_SBI_HTTP_METHOD_OPTIONS);
			    response = nf_server_new_response(request->h.uri, NULL,  0, NULL, 0, methods, m5_dynamicpolicy_api, app_meta);
                            nf_server_populate_response(response, 0, NULL, 204);
                            ogs_assert(response);
                            ogs_assert(true == ogs_sbi_server_send_response(stream, response));
			    if(methods) ogs_free(methods);
			} else {
		            		
			    ogs_sbi_response_t *response;
			    char *methods = NULL;

			    methods = ogs_msprintf("%s, %s",OGS_SBI_HTTP_METHOD_POST, OGS_SBI_HTTP_METHOD_OPTIONS);
                            response = nf_server_new_response(request->h.uri, NULL,  0, NULL, 0, methods, m5_dynamicpolicy_api, app_meta);
                            nf_server_populate_response(response, 0, NULL, 204);
                            ogs_assert(response);
                            ogs_assert(true == ogs_sbi_server_send_response(stream, response));
			    if(methods) ogs_free(methods);
                        }
		        break;
	
		    DEFAULT
                        ogs_error("Invalid HTTP method [%s]", message->h.method);
                        ogs_assert(true == nf_server_send_error(stream, OGS_SBI_HTTP_STATUS_FORBIDDEN, 1, message, "Invalid HTTP method.", message->h.method, NULL, NULL, app_meta));
                    END
                    break;
 
	        CASE("network-assistance")
                    SWITCH(message->h.method)
		    CASE(OGS_SBI_HTTP_METHOD_DELETE)
                        if(message->h.resource.component[1])
                        {
			    msaf_network_assistance_session_t *na_sess = NULL;
		            na_sess = msaf_network_assistance_session_retrieve((const char *)message->h.resource.component[1]);	    
			    if(na_sess){
			        ogs_sbi_response_t *response;
                                response = nf_server_new_response(NULL, NULL, 0, NULL, 0, NULL,  m5_networkassistance_api, app_meta);
                                nf_server_populate_response(response, 0, NULL, 204);
                                ogs_assert(response);
                                ogs_assert(true == ogs_sbi_server_send_response(stream, response));

                                msaf_network_assistance_session_delete_by_session_id((const char *)message->h.resource.component[1]);
			    } else {
				char *err = NULL;
                                err = ogs_msprintf("The AF has no network assistance session with id [%s].", message->h.resource.component[1]);
                                ogs_error("%s", err);
				ogs_assert(true == nf_server_send_error(stream, 404, 0, message, "Unable to retrieve the Network Assistance Session", err, NULL, m5_networkassistance_api, app_meta));
                                ogs_free(err);
			    }

			} else {
			    ogs_assert(true == nf_server_send_error(stream, 400, 0, message, "Unable to retrieve the Network Assistance Session", "Session Id not present in the request", NULL, m5_networkassistance_api, app_meta));
	
			}	
		        break;


		    CASE(OGS_SBI_HTTP_METHOD_GET)
		        if(message->h.resource.component[1])
			{

		            cJSON *network_assistance_sess;
			    network_assistance_sess = msaf_network_assistance_session_get_json((const char *)message->h.resource.component[1]);
			    if(network_assistance_sess) {
				msaf_network_assistance_session_t *na_sess = NULL;
			        ogs_sbi_response_t *response;
			        int response_code = 200;	
		                char *body;
				char *hash;

				body = cJSON_Print(network_assistance_sess);
			       	hash= calculate_hash(body);

				na_sess = msaf_network_assistance_session_retrieve((const char *)message->h.resource.component[1]);

				response = nf_server_new_response(request->h.uri, "application/json",
                                                            na_sess->na_sess_created, hash,
							    msaf_self()->config.server_response_cache_control->m5_service_access_information_response_max_age,
                                                            NULL, m5_networkassistance_api, app_meta);
				ogs_assert(response);
                                nf_server_populate_response(response, strlen(body), ogs_strdup(body), response_code);
                                ogs_assert(true == ogs_sbi_server_send_response(stream, response));
				ogs_free(hash);
				
				cJSON_Delete(network_assistance_sess);
				cJSON_free(body);



			    } else {

                                char *err = NULL;
                                err = ogs_msprintf("The AF has no network assistance session with id [%s].", message->h.resource.component[1]);
                                ogs_error("%s", err);

                                ogs_assert(true == nf_server_send_error(stream, 404, 0, message, "Unable to retrieve the Network Assistance Session", err, NULL, m5_networkassistance_api, app_meta));
				ogs_free(err);
			    }


			} else {
		            
                            ogs_assert(true == nf_server_send_error(stream, 400, 0, message, "Unable to retrieve the Network Assistance Session", "Session Id not present in the request", NULL, m5_networkassistance_api, app_meta));
			}
		        break;

		    CASE(OGS_SBI_HTTP_METHOD_PUT)
                        if(message->h.resource.component[1] && !message->h.resource.component[2])
                        {
                            msaf_network_assistance_session_t *na_sess;
			    cJSON *network_assistance_sess;
			    msaf_api_network_assistance_session_t *nas;

                            if(!check_http_content_type(request->http,"application/json")){
                                ogs_assert(true == nf_server_send_error(stream, 415, 3, message, "Unsupported Media Type.", "Expected content type: application/json", NULL, m5_networkassistance_api, app_meta));
                                ogs_sbi_message_free(message);
                                ogs_free(message);
                            }
                            ogs_debug("Request body: %s", request->http.content);

                            network_assistance_sess = cJSON_Parse(request->http.content);

                            if (!network_assistance_sess) {
                                const char *err = "networkAssistanceSession: Could not parse request body as JSON";
                                ogs_error("%s", err);
                                ogs_assert(true == nf_server_send_error(stream, 400, 0, message, "Creation of the Network Assistance Session failed.", err, NULL, m5_networkassistance_api, app_meta));
                                break;
                            }
			    
			    nas =  msaf_api_network_assistance_session_parseRequestFromJSON(network_assistance_sess, NULL);
			    if(nas->na_session_id) {
		                ogs_free(nas->na_session_id);
			        nas->na_session_id = message->h.resource.component[1];
			    }

                            na_sess = msaf_network_assistance_session_retrieve((const char *)message->h.resource.component[1]);
                            if(!na_sess){
                                char *err = NULL;
                                err = ogs_msprintf("The AF has no network assistance session with id [%s].", message->h.resource.component[1]);
                                ogs_error("%s", err);

                                ogs_assert(true == nf_server_send_error(stream, 404, 0, message, "Unable to retrieve the Network Assistance Session", err, NULL, m5_networkassistance_api, app_meta));
                                ogs_free(err);
                                break;
                            }

                            if(!msaf_nw_assistance_session_update(na_sess, nas)) {
			                    const char *err = "Updating dynamic policy: Unable to communicate withe the PCF";
                                ogs_error("%s", err);
                                ogs_assert(true == nf_server_send_error(stream, 404, 1, message, "Updating dynamic policy failed.",
                                           err, NULL, m5_networkassistance_api, app_meta));
                                break;
			                } else {
                                ogs_sbi_response_t *response;
                                int response_code = 200;
                                char *body;
				char *hash;
				cJSON *nw_assist_session;

				nw_assist_session = msaf_api_network_assistance_session_convertResponseToJSON((const msaf_api_network_assistance_session_t *)na_sess->NetworkAssistanceSession);

                                body = cJSON_Print(nw_assist_session);
                                hash = calculate_hash(body);

                                response = nf_server_new_response(request->h.uri, "application/json",
                                                            na_sess->na_sess_created, hash,
                                                            0,
                                                            NULL, m5_networkassistance_api, app_meta);
                                ogs_assert(response);
                                nf_server_populate_response(response, strlen(body), ogs_strdup(body), response_code);
                                ogs_assert(true == ogs_sbi_server_send_response(stream, response));
                                ogs_free(hash);

                                cJSON_Delete(nw_assist_session);
                                cJSON_free(body);
                            }	            

        	            cJSON_Delete(network_assistance_sess);
				
            		}
	                break; 	    	

                    CASE(OGS_SBI_HTTP_METHOD_POST)
			if(message->h.resource.component[1] && !strcmp(message->h.resource.component[2], "boost-request"))
                        {
			    msaf_network_assistance_session_t *na_sess;
			    na_sess = msaf_network_assistance_session_retrieve((const char *)message->h.resource.component[1]);
			    if(!na_sess){
			        char *err = NULL;
                                err = ogs_msprintf("The AF has no network assistance session with id [%s].", message->h.resource.component[1]);
                                ogs_error("%s", err);

                                ogs_assert(true == nf_server_send_error(stream, 404, 0, message, "Unable to retrieve the Network Assistance Session", err, NULL, m5_networkassistance_api, app_meta));
                                ogs_free(err);

			    }
			    if(!is_ue_allowed_to_request_delivery_boost(na_sess)) {
			        char *reason = NULL;
				msaf_api_operation_success_response_t *operation_success_response;
				cJSON *op_success_response;
				char *success_response;
				ogs_sbi_response_t *response;
                                int response_code = 200;


                                reason = ogs_msprintf("The AF has an active delivery boost for the network assistance session [%s].", message->h.resource.component[1]);
                                ogs_debug("%s", reason);
				
				operation_success_response = msaf_api_operation_success_response_create(reason, 0);
				op_success_response = msaf_api_operation_success_response_convertResponseToJSON(operation_success_response);
				success_response = cJSON_Print(op_success_response);

				response = nf_server_new_response(NULL, "application/json", 0, NULL, 0, NULL, m5_networkassistance_api, app_meta);
                                ogs_assert(response);
                                nf_server_populate_response(response, strlen(success_response), ogs_strdup(success_response), response_code);
                                ogs_assert(true == ogs_sbi_server_send_response(stream, response));

				cJSON_Delete(op_success_response);
				cJSON_free(success_response);
				//ogs_free(reason);
				msaf_api_operation_success_response_free(operation_success_response);
				break;

			    }

                            nw_assist_event = (msaf_event_t*)populate_msaf_event_with_metadata(e, m5_networkassistance_api, app_meta); 
			    msaf_nw_assistance_session_delivery_boost_update(na_sess, nw_assist_event);

			} else {
				
		            cJSON *network_assistance_sess;
		            cJSON *service_data_flow_descriptions = NULL;
			    cJSON *policy_template_id = NULL;
			    cJSON *requested_qos = NULL;
			    cJSON *provisioning_session_id = NULL;

	        	    if(!check_http_content_type(request->http,"application/json")){
			        ogs_assert(true == nf_server_send_error(stream, 415, 3, message, "Unsupported Media Type.", "Expected content type: application/json", NULL, m5_networkassistance_api, app_meta));
                                ogs_sbi_message_free(message);
                                ogs_free(message);
			    }
                            ogs_debug("Request body: %s", request->http.content);

                            network_assistance_sess = cJSON_Parse(request->http.content);

			    if (!network_assistance_sess) {
                                const char *err = "networkAssistanceSession: Could not parse request body as JSON";
                                ogs_error("%s", err);
                                ogs_assert(true == nf_server_send_error(stream, 400, 0, message, "Creation of the Network Assistance Session failed.", err, NULL, m5_networkassistance_api, app_meta));
                                break;
                            }  

			    service_data_flow_descriptions = cJSON_GetObjectItemCaseSensitive(network_assistance_sess, "serviceDataFlowDescriptions");
                            if (!service_data_flow_descriptions) {
                                const char *err = "createNetworkAssistanceSession: \"serviceDataFlowDescriptions\" not present";
                                ogs_error("%s", err);
                                ogs_assert(true == nf_server_send_error(stream, 400, 0, message, "Creation of the Network Assistance Session failed.", err, NULL, m5_networkassistance_api, app_meta));
			        cJSON_Delete(network_assistance_sess);
                                break;
                            }
                            if (!cJSON_IsArray(service_data_flow_descriptions)) {
                                const char *err = "createNetworkAssistanceSession: \"serviceDataFlowDescriptions\" is not an array";
                                ogs_error("%s", err);
                                ogs_assert(true == nf_server_send_error(stream, 400, 0, message, "Creation of the Network Assistance Session failed.", err, NULL, m5_networkassistance_api, app_meta));
                                cJSON_Delete(network_assistance_sess);
				break;
                            }

			    provisioning_session_id = cJSON_GetObjectItemCaseSensitive(network_assistance_sess, "provisioningSessionId");
			    if(!provisioning_session_id) {
			        const char *err = "createNetworkAssistanceSession: \"provisioningSessionId\" is not present";
                                ogs_error("%s", err);
                                ogs_assert(true == nf_server_send_error(stream, 400, 0, message, "Creation of the Network Assistance Session failed.", err, NULL, m5_networkassistance_api, app_meta));
                                cJSON_Delete(network_assistance_sess);
                                break;
	    
			    }
			    if (!cJSON_IsString(provisioning_session_id)) {
			        const char *err = "createNetworkAssistanceSession: \"provisioningSessionId\" is not a string";
                                ogs_error("%s", err);
                                ogs_assert(true == nf_server_send_error(stream, 400, 0, message, "Creation of the Network Assistance Session failed.", err, NULL, m5_networkassistance_api, app_meta));
                                cJSON_Delete(network_assistance_sess);
                                break;
	    
			    }

                            policy_template_id = cJSON_GetObjectItemCaseSensitive(network_assistance_sess, "policyTemplateId");
                            if (!policy_template_id) {
                                ogs_debug("createNetworkAssistanceSession: \"policyTemplateId\" is not present");
                           
                            }
                            if (!policy_template_id && cJSON_IsString(policy_template_id)) {
                                ogs_debug("createNetworkAssistanceSession: \"policyTemplateId\" is not a string");
                            }

                            requested_qos = cJSON_GetObjectItemCaseSensitive(network_assistance_sess, "requestedQoS");
                            if (!requested_qos) {
                                ogs_debug("createNetworkAssistanceSession: \"requestedQoS\" is not present");
                            }
                       
			    nw_assist_event = (msaf_event_t*)populate_msaf_event_with_metadata(e, m5_networkassistance_api, app_meta);

			    if(!msaf_nw_assistance_session_create(network_assistance_sess, nw_assist_event)) {

                                const char *err = "Problem in obtaining the information required to create the Network Assitance Session";
                                ogs_error("%s", err);
                                ogs_assert(true == nf_server_send_error(stream, 400, 0, message, "Creation of the Network Assistance Session failed.", err, NULL, m5_networkassistance_api, app_meta));
                                cJSON_Delete(network_assistance_sess);
                                break;

			    }


			    cJSON_Delete(network_assistance_sess);
			}
		        break; 
		    DEFAULT
                        ogs_error("Invalid HTTP method [%s]", message->h.method);
                        ogs_assert(true == nf_server_send_error(stream, OGS_SBI_HTTP_STATUS_FORBIDDEN, 1, message, "Invalid HTTP method.", message->h.method, NULL, NULL, app_meta));
                    END
                    break;
	
                CASE("service-access-information")
                    SWITCH(message->h.method)
                    CASE(OGS_SBI_HTTP_METHOD_GET)
                        const msaf_sai_cache_entry_t *sai_entry;

                        sai_entry = msaf_context_retrieve_service_access_information(message->h.resource.component[1],
                                            strncmp(request->h.uri,"https:",6)==0,
                                            ogs_hash_get(request->http.headers, "Host", OGS_HASH_KEY_STRING));

                        if (!sai_entry) {
                            char *err = NULL;
                            err = ogs_msprintf("Provisioning Session [%s] not found.", message->h.resource.component[1]);
                            ogs_error("%s", err);
                            ogs_assert(true == nf_server_send_error(stream, 404, 1, message, "Provisioning Session not found.", err, NULL, m5_serviceaccessinformation_api, app_meta));
                            ogs_free(err);
                        } else {
                            const char *if_none_match;
                            const char *if_modified_since;
                            int response_code = 200;
                            const char *response_body = sai_entry->sai_body;

                            if_none_match = ogs_hash_get(request->http.headers, "If-None-Match", OGS_HASH_KEY_STRING);
                            if (if_none_match) {
                                if (strcmp(sai_entry->hash, if_none_match)==0) {
                                    /* ETag hasn't changed */
                                    response_code = 304;
                                    response_body = NULL;
                                }
                            }

                            if_modified_since = ogs_hash_get(request->http.headers, "If-Modified-Since", OGS_HASH_KEY_STRING);
                            if (if_modified_since) {
                                struct tm tm = {0};
                                ogs_time_t modified_since;
                                ogs_strptime(if_modified_since, "%a, %d %b %Y %H:%M:%S GMT", &tm);
                                ogs_debug("IMS: sec=%i, min=%i, hour=%i, mday=%i, mon=%i, year=%i, gmtoff=%li", tm.tm_sec, tm.tm_min, tm.tm_hour, tm.tm_mday, tm.tm_mon, tm.tm_year, tm.tm_gmtoff);
                                ogs_time_from_gmt(&modified_since, &tm, 0);
                                ogs_debug("If-Modified-Since: %li < %li?", modified_since, sai_entry->generated);
                                if (modified_since >= sai_entry->generated) {
                                    /* Not modified since the time given */
                                    response_code = 304;
                                    response_body = NULL;
                                }
                            }

                            ogs_sbi_response_t *response;
                            response = nf_server_new_response(NULL, "application/json", ogs_time_sec(sai_entry->generated)+1, sai_entry->hash, msaf_self()->config.server_response_cache_control->m5_service_access_information_response_max_age, NULL, m5_serviceaccessinformation_api, app_meta);
                            ogs_assert(response);
                            nf_server_populate_response(response, response_body?strlen(response_body):0, ogs_strdup(response_body), response_code);
                            ogs_assert(true == ogs_sbi_server_send_response(stream, response));
                        }
                        break;
                    CASE(OGS_SBI_HTTP_METHOD_OPTIONS)
                        if (message->h.resource.component[1] && !message->h.resource.component[2]) {
                            ogs_sbi_response_t *response;
                            response = nf_server_new_response(request->h.uri, NULL,  0, NULL, 0, OGS_SBI_HTTP_METHOD_GET ", " OGS_SBI_HTTP_METHOD_OPTIONS, m5_serviceaccessinformation_api, app_meta);
                            ogs_assert(response);
                            nf_server_populate_response(response, 0, NULL, 204);
                            ogs_assert(true == ogs_sbi_server_send_response(stream, response));
                        } else {
                            ogs_assert(true == nf_server_send_error(stream, OGS_SBI_HTTP_STATUS_NOT_FOUND, 2, message, "Not Found", message->h.method, NULL, m5_serviceaccessinformation_api, app_meta));
                        }
                        break;
                    DEFAULT
                        ogs_error("Invalid HTTP method [%s]", message->h.method);

                        ogs_assert(true == nf_server_send_error(stream, OGS_SBI_HTTP_STATUS_FORBIDDEN, 1, message, "Invalid HTTP method.", message->h.method, NULL, NULL, app_meta));
                    END
                    break;
                CASE("consumption-reporting")
                    SWITCH(message->h.method)
                    CASE(OGS_SBI_HTTP_METHOD_POST)
                        if (message->h.resource.component[1] && !message->h.resource.component[2]) {
                            msaf_provisioning_session_t *provisioning_session;

                            provisioning_session = msaf_provisioning_session_find_by_provisioningSessionId(message->h.resource.component[1]);
                            if (provisioning_session) {
                                if (!provisioning_session->consumptionReportingConfiguration) {
                                    char *err;

                                    err = ogs_msprintf("No ConsumptionReportingConfiguration for Provisioning Session [%s], cannot accept reports", message->h.resource.component[1]);
                                    ogs_error("%s", err);
                                    ogs_assert(true==nf_server_send_error(stream, OGS_SBI_HTTP_STATUS_NOT_FOUND, 1, message, "Not found", err, NULL, m5_consumptionreporting_api, app_meta));
                                    ogs_free(err);
                                } else {
                                    const char *content_type = "application/octet-stream";
                                    ogs_hash_index_t *hi;

                                    /* Find Content-Type header value */
                                    for (hi = ogs_hash_first(request->http.headers); hi; hi = ogs_hash_next(hi)) {
                                        if (!ogs_strcasecmp(ogs_hash_this_key(hi), OGS_SBI_CONTENT_TYPE)) {
                                            content_type = ogs_hash_this_val(hi);
                                            break;
                                        }
                                    }
                                    SWITCH(content_type)
                                    CASE("application/json")
                                        cJSON *json;

                                        json = cJSON_Parse(request->http.content);
                                        if (json) {
                                            msaf_api_consumption_report_t *consumption_report;
                                            const char *reason;

                                            consumption_report = msaf_api_consumption_report_parseRequestFromJSON(json, &reason);
                                            if (consumption_report) {
                                                struct timespec ts;
                                                char buf[32];
                                                char *filetime = NULL;
                                                clock_gettime(CLOCK_REALTIME, &ts);
                                                strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", gmtime(&ts.tv_sec));
                                                filetime = ogs_msprintf("%s.%.6iZ", buf, (int)(ts.tv_nsec/1000));
                                                if (msaf_data_collection_store(message->h.resource.component[1], "consumption_reports",
                                                                    consumption_report->reporting_client_id, NULL, filetime,
                                                                    "json", request->http.content)) {
                                                    ogs_sbi_response_t *response;
                                                    response = nf_server_new_response(request->h.uri, NULL,  0, NULL, 0, NULL, m5_consumptionreporting_api, app_meta);
                                                    ogs_assert(response);
                                                    nf_server_populate_response(response, 0, NULL, 204);
                                                    ogs_assert(true == ogs_sbi_server_send_response(stream, response));
                                                } else {
                                                    char *err;

                                                    err = ogs_msprintf("Failed to store Consumption Report for provisioning session [%s]", message->h.resource.component[1]);
                                                    ogs_error("%s", err);
                                                    ogs_assert(true == nf_server_send_error(stream, OGS_SBI_HTTP_STATUS_INTERNAL_SERVER_ERROR, 1, message, "Data storage error", err, NULL, m5_consumptionreporting_api, app_meta));
                                                    ogs_free(err);
                                                }
                                                ogs_free(filetime);
                                                msaf_api_consumption_report_free(consumption_report);
                                            } else {
                                                char *err;

                                                err = ogs_msprintf("Badly formed ConsumptionReport posted for provisioning session [%s]: %s", message->h.resource.component[1], reason);
                                                ogs_error("%s", err);
                                                ogs_assert(true == nf_server_send_error(stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST, 1, message, "Malformed request body", err, NULL, m5_consumptionreporting_api, app_meta));
                                                ogs_free(err);
                                            }
                                            cJSON_Delete(json);
                                        } else {
                                            char *err;

                                            err = ogs_msprintf("Badly formed request body when posting a consumption report for provisioning session [%s]", message->h.resource.component[1]);
                                            ogs_error("%s", err);
                                            ogs_assert(true == nf_server_send_error(stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST, 1, message, "Malformed request body", err, NULL, m5_consumptionreporting_api, app_meta));
                                            ogs_free(err);
                                        }
                                        break;
                                    DEFAULT
                                        char *err;
                                        err = ogs_msprintf("Unrecognised content type for Consumption Report for Provisioning Session [%s]", message->h.resource.component[1]);
                                        ogs_error("%s", err);
                                        ogs_assert(true == nf_server_send_error(stream, OGS_SBI_HTTP_STATUS_UNSUPPORTED_MEDIA_TYPE, 1, message, "Malformed request body", err, NULL, m5_consumptionreporting_api, app_meta));
                                        ogs_free(err);
                                    END
                                }
                            } else {
                                char *err;

                                err = ogs_msprintf("Provisioning session [%s] not found for Consumption Report",
                                                   message->h.resource.component[1]);
                                ogs_error("%s", err);
                                ogs_assert(true == nf_server_send_error(stream, OGS_SBI_HTTP_STATUS_NOT_FOUND, 1, message,
                                                                        "Not Found", err, NULL, m5_consumptionreporting_api,
                                                                        app_meta));
                                ogs_free(err);
                            }
                        } else {
                            ogs_assert(true == nf_server_send_error(stream, OGS_SBI_HTTP_STATUS_NOT_FOUND, 0, message, "Not Found",
                                                                    NULL, NULL, m5_consumptionreporting_api, app_meta));
                        }
                        break;
                    CASE(OGS_SBI_HTTP_METHOD_OPTIONS)
                        if (message->h.resource.component[1] && !message->h.resource.component[2]) {
                            ogs_sbi_response_t *response;
                            response = nf_server_new_response(request->h.uri, NULL,  0, NULL, 0,
                                                              OGS_SBI_HTTP_METHOD_POST ", " OGS_SBI_HTTP_METHOD_OPTIONS,
                                                              m5_consumptionreporting_api, app_meta);
                            ogs_assert(response);
                            nf_server_populate_response(response, 0, NULL, 204);
                            ogs_assert(true == ogs_sbi_server_send_response(stream, response));
                        } else {
                            ogs_assert(true == nf_server_send_error(stream, OGS_SBI_HTTP_STATUS_NOT_FOUND, 2, message, "Not Found",
                                                                    message->h.method, NULL, m5_consumptionreporting_api, app_meta)
                                      );
                        }
                        break;
                    DEFAULT
                        char *err;
                        err = ogs_msprintf("Method [%s] not implemented for M5 Consumption Reporting API", message->h.method);
                        ogs_error("%s", err);
                        ogs_assert(true == nf_server_send_error(stream, OGS_SBI_HTTP_STATUS_MEHTOD_NOT_ALLOWED, 1, message,
                                                                "Method Not Allowed", err, NULL, m5_consumptionreporting_api,
                                                                app_meta));
                        ogs_free(err);
                    END
                    break;
                DEFAULT
                    ogs_error("Invalid resource name [%s]",
                            message->h.resource.component[0]);
                    ogs_assert(true == nf_server_send_error(stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST, 1, message,
                                                            "Invalid resource name.", message->h.resource.component[0], NULL, NULL,
                                                            app_meta));

                END
                break;
            DEFAULT
                ogs_error("Invalid API name [%s]", message->h.service.name);
                ogs_assert(true == nf_server_send_error(stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST, 1, message, "Invalid API name.",
                                                        message->h.service.name, NULL, NULL, app_meta));

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
}

static bool is_dynamic_policy_create_request_valid(ogs_sbi_request_t *request, ogs_sbi_stream_t *stream,
                                                   ogs_sbi_message_t *message,
                                                   const nf_server_interface_metadata_t *m5_dynamicpolicy_api,
                                                   const nf_server_app_metadata_t *app_meta)
{

    cJSON *dynamic_policy;
    cJSON *service_data_flow_descriptions = NULL;
    cJSON *policy_template_id = NULL;
    cJSON *provisioning_session_id = NULL;

    if(!check_http_content_type(request->http,"application/json")){
        ogs_assert(true == nf_server_send_error(stream, 415, 3, message, "Unsupported Media Type.",
                                                "Expected content type: application/json", NULL, m5_dynamicpolicy_api, app_meta));
        ogs_sbi_message_free(message);
        ogs_free(message);
    }

    dynamic_policy = cJSON_Parse(request->http.content);

    if (!dynamic_policy) {
        const char *err = "dynamicPolicy: Could not parse request body as JSON";
        ogs_error("%s", err);
        ogs_assert(true == nf_server_send_error(stream, 400, 0, message, "Creation of the Dynamic Policy failed.", err, NULL, m5_dynamicpolicy_api, app_meta));
        cJSON_Delete(dynamic_policy);
        return 0;
    }

    service_data_flow_descriptions = cJSON_GetObjectItemCaseSensitive(dynamic_policy, "serviceDataFlowDescriptions");
    if (!service_data_flow_descriptions) {
        const char *err = "createDynamicPolicy: \"serviceDataFlowDescriptions\" not present";
        ogs_error("%s", err);
        ogs_assert(true == nf_server_send_error(stream, 400, 0, message, "Creation of the Dynamic Policy failed.", err, NULL, m5_dynamicpolicy_api, app_meta));
        cJSON_Delete(dynamic_policy);
        return 0;
    }
    if (!cJSON_IsArray(service_data_flow_descriptions)) {
        const char *err = "createDynamicPolicy: \"serviceDataFlowDescriptions\" is not an array";
        ogs_error("%s", err);
        ogs_assert(true == nf_server_send_error(stream, 400, 0, message, "Creation of the Dynamic Policy failed.", err, NULL, m5_dynamicpolicy_api, app_meta));
        cJSON_Delete(dynamic_policy);
        return 0;
    }

    provisioning_session_id = cJSON_GetObjectItemCaseSensitive(dynamic_policy, "provisioningSessionId");
    if(!provisioning_session_id) {
        const char *err = "createDynamicPolicy: \"provisioningSessionId\" is not present";
        ogs_error("%s", err);
        ogs_assert(true == nf_server_send_error(stream, 400, 0, message, "Creation of the Dynamic Policy failed.", err, NULL, m5_dynamicpolicy_api, app_meta));
        cJSON_Delete(dynamic_policy);
        return 0;

    }
    if (!cJSON_IsString(provisioning_session_id)) {
        const char *err = "createDynamicPolicy: \"provisioningSessionId\" is not a string";
        ogs_error("%s", err);
        ogs_assert(true == nf_server_send_error(stream, 400, 0, message, "Creation of the Dynamic Policy failed.", err, NULL, m5_dynamicpolicy_api, app_meta));
        cJSON_Delete(dynamic_policy);
        return 0;

    }

    policy_template_id = cJSON_GetObjectItemCaseSensitive(dynamic_policy, "policyTemplateId");
    if (!policy_template_id) {
        const char *err = "createDynamicPolicy: \"policyTemplateId\" is not present";
        ogs_error("%s", err);
        ogs_assert(true == nf_server_send_error(stream, 400, 0, message, "Creation of the Dynamic Policy failed.", err, NULL, m5_dynamicpolicy_api, app_meta));
        cJSON_Delete(dynamic_policy);
        return 0;

    }
    if (!policy_template_id && cJSON_IsString(policy_template_id)) {
        const char *err = "createDynamicPolicy: \"policyTemplateId\" is not a string";
        ogs_error("%s", err);
        ogs_assert(true == nf_server_send_error(stream, 400, 0, message, "Creation of the Dynamic Policy failed.", err, NULL, m5_dynamicpolicy_api, app_meta));
        cJSON_Delete(dynamic_policy);
        return 0;
    }

    if(dynamic_policy) {
        cJSON_Delete(dynamic_policy);
        dynamic_policy = NULL;
    }

    return 1;
}

/* vim:ts=8:sts=4:sw=4:expandtab:
*/
