/*
License: 5G-MAG Public License (v1.0)
Author: Dev Audsin
Copyright: (C) 2022 British Broadcasting Corporation

For full license terms please see the LICENSE file distributed with this
program. If this file is missing then the license can be retrieved from
https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
*/

#include "utilities.h"
#include "network-assistance-session.h"
#include "pcf-session.h"

typedef struct retrieve_pcf_binding_cb_data_s {
    ue_network_identifier_t *ue_connection;
    msaf_network_assistance_session_t *na_sess;
} retrieve_pcf_binding_cb_data_t;

static void msaf_network_assistance_session_remove(msaf_network_assistance_session_t *na_sess);
static void ue_connection_details_free(ue_network_identifier_t *ue_connection);

static bool app_session_change_callback(pcf_app_session_t *app_session, void *user_data);
static bool app_session_notification_callback(pcf_app_session_t *app_session, const OpenAPI_events_notification_t *notifications, void *user_data);
static void display_notifications(const OpenAPI_events_notification_t *notifications);
static void add_create_event_metadata_to_na_sess_context(msaf_network_assistance_session_t *na_sess, msaf_event_t *e);
static bool create_msaf_na_sess_and_send_response(msaf_network_assistance_session_t *na_sess);
static ue_network_identifier_t *copy_ue_network_connection_identifier(const ue_network_identifier_t *ue_net_connection);
static void free_ue_network_connection_identifier(ue_network_identifier_t *ue_net_connection);
static bool bsf_retrieve_pcf_binding_callback(OpenAPI_pcf_binding_t *pcf_binding, void *data);
static void create_pcf_app_session(ogs_sockaddr_t *pcf_address, ue_network_identifier_t *ue_connection, msaf_network_assistance_session_t *na_sess);
static void retrieve_pcf_binding_and_create_app_session(ue_network_identifier_t *ue_connection, msaf_network_assistance_session_t *na_sess);
static void msaf_network_assistance_session_add_to_delete_list(pcf_app_session_t *pcf_app_session);
static void msaf_network_assistance_session_remove_from_delete_list(void);
static void msaf_pcf_app_session_free(void);
static void retrieve_pcf_binding_cb_data_free(retrieve_pcf_binding_cb_data_t *cb_data);

/***** Public functions *****/

int msaf_nw_assistance_session_create(cJSON *network_assistance_sess, msaf_event_t *e)
{

    msaf_network_assistance_session_t *na_sess;
    OpenAPI_network_assistance_session_t *nas;
    OpenAPI_service_data_flow_description_t *service_data_flow_information;
    OpenAPI_lnode_t *node = NULL;

    ogs_sockaddr_t *pcf_address;

    nas =  OpenAPI_network_assistance_session_parseFromJSON(network_assistance_sess);

    na_sess = ogs_calloc(1, sizeof(msaf_network_assistance_session_t));
    ogs_assert(na_sess);
    na_sess->NetworkAssistanceSession = OpenAPI_network_assistance_session_parseFromJSON(network_assistance_sess);
    
    add_create_event_metadata_to_na_sess_context(na_sess, e);

    if (nas->service_data_flow_description) {
        OpenAPI_list_for_each(nas->service_data_flow_description, node) {
	    ue_network_identifier_t *ue_connection;	
            service_data_flow_information = (OpenAPI_service_data_flow_description_t *)node->data;
            ue_connection = populate_ue_connection_details(service_data_flow_information);

            pcf_address = msaf_pcf_cache_find(msaf_self()->pcf_cache, ue_connection->address);

	    if(pcf_address)
	    {  
	        create_pcf_app_session(pcf_address, ue_connection, na_sess);

	    } else {
		retrieve_pcf_binding_and_create_app_session(ue_connection, na_sess);    
	    }
	    ue_connection_details_free(ue_connection);

        }
    }
    OpenAPI_network_assistance_session_free(nas); 
    return 1;

}

msaf_network_assistance_session_t *msaf_network_assistance_session_retrieve(const char *na_session_id)
{
    msaf_network_assistance_session_t *na_sess = NULL;
    ogs_list_for_each(&msaf_self()->network_assistance_sessions, na_sess)
    {
        if(!strcmp(na_sess->naSessionId, na_session_id))
            break;
    }
    if(na_sess)
        return na_sess;

    return NULL;

}

cJSON *msaf_network_assistance_session_get_json(const char *na_session_id)
{
    msaf_network_assistance_session_t *na_sess = NULL;
    ogs_list_for_each(&msaf_self()->network_assistance_sessions, na_sess)
    { 
        if(!strcmp(na_sess->naSessionId, na_session_id))
	    break;		
    }
    if(na_sess)
        return OpenAPI_network_assistance_session_convertToJSON(na_sess->NetworkAssistanceSession);

    return NULL;
	
}

ue_network_identifier_t *populate_ue_connection_details(OpenAPI_service_data_flow_description_t *service_data_flow_information)
{
    int rv;
    ue_network_identifier_t *ue_connection;

    ue_connection = ogs_calloc(1, sizeof(ue_network_identifier_t));
    ogs_assert(ue_connection);

    ue_connection->ip_domain = msaf_strdup(service_data_flow_information->domain_name);

    rv = ogs_getaddrinfo(&ue_connection->address, AF_UNSPEC, service_data_flow_information->flow_description->dst_ip, service_data_flow_information->flow_description->dst_port, 0);
    if (rv != OGS_OK) {
        ogs_error("getaddrinfo failed");
        return NULL;
    }

    if (ue_connection->address == NULL)
        ogs_error("Could not get the address for the UE connection");
    
    return ue_connection;
	  
}

void msaf_network_assistance_session_remove_all_pcf_app_session(void)
{
    msaf_pcf_app_session_t *msaf_pcf_app_session = NULL, *next = NULL;
    ogs_list_for_each_safe(&msaf_self()->delete_pcf_app_sessions, next, msaf_pcf_app_session){
        ogs_list_remove(&msaf_self()->delete_pcf_app_sessions, msaf_pcf_app_session);
        ogs_free(msaf_pcf_app_session);
    }

}


OpenAPI_list_t *populate_media_component(char *policy_template_id, OpenAPI_m5_qo_s_specification_t *requested_qos) {

    OpenAPI_list_t *MediaComponentList = NULL;
    OpenAPI_map_t *MediaComponentMap = NULL;
    OpenAPI_media_component_t *MediaComponent = NULL;
    int i = 0;

    msaf_network_assistance_policy_template_t *policy_template;
    policy_template = get_policy_template_by_id(policy_template_id);
    ogs_assert(policy_template);

    MediaComponentList = OpenAPI_list_create();
    ogs_assert(MediaComponentList);

    MediaComponent = ogs_calloc(1, sizeof(*MediaComponent));
    ogs_assert(MediaComponent);

    MediaComponent->med_type = OpenAPI_media_type_VIDEO;

    MediaComponent->med_comp_n = i++;

    MediaComponent->mar_bw_dl = msaf_strdup(requested_qos->mar_bw_dl_bit_rate);
    MediaComponent->mar_bw_ul = msaf_strdup(requested_qos->mar_bw_ul_bit_rate);
    MediaComponent->mir_bw_dl = msaf_strdup(requested_qos->mir_bw_dl_bit_rate);
    MediaComponent->mir_bw_ul = msaf_strdup(requested_qos->mir_bw_ul_bit_rate);
    MediaComponent->min_des_bw_dl = requested_qos->min_des_bw_dl_bit_rate;
    MediaComponent->min_des_bw_ul = requested_qos->min_des_bw_ul_bit_rate;

    MediaComponentMap = OpenAPI_map_create(
            ogs_msprintf("%d", MediaComponent->med_comp_n), MediaComponent);
    ogs_assert(MediaComponentMap);
    ogs_assert(MediaComponentMap->key);

    OpenAPI_list_add(MediaComponentList, MediaComponentMap);

    ogs_assert(MediaComponentList->count);

    return MediaComponentList;
}

void msaf_network_assistance_session_remove_all()
{
    msaf_network_assistance_session_t *msaf_network_assistance_session = NULL, *next = NULL;

    ogs_list_for_each_safe(&msaf_self()->network_assistance_sessions, next, msaf_network_assistance_session){
	ogs_list_remove(&msaf_self()->network_assistance_sessions, msaf_network_assistance_session);
        msaf_network_assistance_session_remove(msaf_network_assistance_session);
    }
}

void msaf_network_assistance_session_delete_by_session_id(const char *na_sess_id)
{
    msaf_network_assistance_session_t *msaf_network_assistance_session = NULL, *next = NULL;

    ogs_list_for_each_safe(&msaf_self()->network_assistance_sessions, next, msaf_network_assistance_session){
        if(!strcmp(msaf_network_assistance_session->naSessionId, na_sess_id)) {
            ogs_list_remove(&msaf_self()->network_assistance_sessions, msaf_network_assistance_session);
            msaf_network_assistance_session_add_to_delete_list(msaf_network_assistance_session->pcf_app_session);
            msaf_network_assistance_session_remove(msaf_network_assistance_session);
        }
    }
    msaf_pcf_app_session_free();
}


static void msaf_network_assistance_session_add_to_delete_list(pcf_app_session_t *pcf_app_session)
{
    ogs_assert(pcf_app_session);
    msaf_pcf_app_session_t *msaf_pcf_app_session;
    msaf_pcf_app_session =  ogs_calloc(1, sizeof(msaf_pcf_app_session_t));
    msaf_pcf_app_session->pcf_app_session = pcf_app_session;
    ogs_list_add(&msaf_self()->delete_pcf_app_sessions, msaf_pcf_app_session);
}

static void msaf_network_assistance_session_remove_from_delete_list(void)
{
    msaf_pcf_app_session_t *msaf_pcf_app_session = NULL, *next = NULL;
    ogs_list_for_each_safe(&msaf_self()->delete_pcf_app_sessions, next, msaf_pcf_app_session){
        if(!msaf_pcf_app_session->pcf_app_session){
            ogs_list_remove(&msaf_self()->delete_pcf_app_sessions, msaf_pcf_app_session);
            ogs_free(msaf_pcf_app_session);
        }
    }

}

static void msaf_pcf_app_session_free(void)
{
        msaf_pcf_app_session_t *msaf_pcf_app_session;
        ogs_list_for_each(&msaf_self()->delete_pcf_app_sessions, msaf_pcf_app_session){
            if(msaf_pcf_app_session->pcf_app_session)
	    {
                pcf_app_session_free(msaf_pcf_app_session->pcf_app_session);
		msaf_pcf_app_session->pcf_app_session = NULL;
	    }
        }
}



static void create_pcf_app_session(ogs_sockaddr_t *pcf_address, ue_network_identifier_t *ue_connection, msaf_network_assistance_session_t *na_sess)
{
    pcf_session_t *pcf_session;
    int events = 0;
    cJSON *network_policy_template = NULL;
    OpenAPI_list_t *media_component = NULL;
    ue_network_identifier_t *ue_net = NULL;


    events = PCF_APP_SESSION_EVENT_TYPE_QOS_NOTIF | PCF_APP_SESSION_EVENT_TYPE_QOS_MONITORING | PCF_APP_SESSION_EVENT_TYPE_SUCCESSFUL_QOS_UPDATE | PCF_APP_SESSION_EVENT_TYPE_FAILED_QOS_UPDATE;

    pcf_session = msaf_pcf_session_new(pcf_address);

    // To do: Remove msaf_na_policy_template_create() call when dynamic policies is implemented
    msaf_na_policy_template_create(network_policy_template);

    media_component = populate_media_component(na_sess->NetworkAssistanceSession->policy_template_id, na_sess->NetworkAssistanceSession->requested_qo_s);

    ue_net  = copy_ue_network_connection_identifier(ue_connection);

    pcf_session_create_app_session(pcf_session, ue_net, events, media_component, app_session_notification_callback, NULL, app_session_change_callback, na_sess);

    ue_connection_details_free(ue_net);
}

static void retrieve_pcf_binding_and_create_app_session(ue_network_identifier_t *ue_connection, msaf_network_assistance_session_t *na_sess)
{
    	
    retrieve_pcf_binding_cb_data_t *cb_data;

    ogs_sockaddr_t *ue_address;

    cb_data = ogs_calloc(1, sizeof(retrieve_pcf_binding_cb_data_t));
    cb_data->ue_connection = copy_ue_network_connection_identifier((const ue_network_identifier_t *)ue_connection);
    cb_data->na_sess = na_sess;

    ogs_copyaddrinfo(&ue_address, ue_connection->address);

    bsf_retrieve_pcf_binding_for_pdu_session(ue_address, bsf_retrieve_pcf_binding_callback, cb_data);
	
}

static ue_network_identifier_t *copy_ue_network_connection_identifier(const ue_network_identifier_t *ue_net_connection)
{
    ue_network_identifier_t *ue_net_connection_copy;

    ue_net_connection_copy = ogs_calloc(1, sizeof(ue_network_identifier_t));
    if (ue_net_connection_copy) {
        if (ue_net_connection->address) ogs_copyaddrinfo(&ue_net_connection_copy->address, ue_net_connection->address);
        if (ue_net_connection->supi) ue_net_connection_copy->supi = ogs_strdup(ue_net_connection->supi);
        if (ue_net_connection->gpsi) ue_net_connection_copy->gpsi = ogs_strdup(ue_net_connection->gpsi);
        if (ue_net_connection->dnn) ue_net_connection_copy->dnn = ogs_strdup(ue_net_connection->dnn);
        if (ue_net_connection->ip_domain) ue_net_connection_copy->ip_domain = ogs_strdup(ue_net_connection->ip_domain);
    }
    return  ue_net_connection_copy;
}

static void free_ue_network_connection_identifier(ue_network_identifier_t *ue_net_connection)
{
    if (!ue_net_connection) return;
    if (ue_net_connection->address) ogs_freeaddrinfo(ue_net_connection->address);
    if (ue_net_connection->supi) ogs_free(ue_net_connection->supi);
    if (ue_net_connection->gpsi) ogs_free(ue_net_connection->gpsi);
    if (ue_net_connection->dnn) ogs_free(ue_net_connection->dnn);
    if (ue_net_connection->ip_domain) ogs_free(ue_net_connection->ip_domain);
    ogs_free(ue_net_connection);
}

static void msaf_network_assistance_session_remove(msaf_network_assistance_session_t *msaf_network_assistance_session){
    ogs_assert(msaf_network_assistance_session);

    if(msaf_network_assistance_session->naSessionId) {
        ogs_free(msaf_network_assistance_session->naSessionId);
        msaf_network_assistance_session->naSessionId = NULL;
    }

    if(msaf_network_assistance_session->NetworkAssistanceSession) OpenAPI_network_assistance_session_free(msaf_network_assistance_session->NetworkAssistanceSession);
    if(msaf_network_assistance_session->create_event) msaf_event_free(msaf_network_assistance_session->create_event);
    ogs_free(msaf_network_assistance_session);

}

static void ue_connection_details_free(ue_network_identifier_t *ue_connection) {
    if(ue_connection->address) ogs_freeaddrinfo(ue_connection->address);
    if(ue_connection->ip_domain) ogs_free(ue_connection->ip_domain);
    ogs_free(ue_connection);

}

static bool app_session_change_callback(pcf_app_session_t *app_session, void *data){

    msaf_network_assistance_session_t *na_sess;
    ogs_debug("msaf_na_sess_cb(app_session=%p, data=%p)", app_session, data);

    na_sess = (msaf_network_assistance_session_t *)data;

    if(!app_session){
	    
	if(na_sess->create_event)
	{
	    /*
	    ogs_assert(true == nf_server_send_error(na_sess->create_event->h.sbi.data, 401, 0, na_sess->create_event->message, "Creation of the Network Assistance Session failed.", "PCF App Session creation failed" , NULL, na_sess->create_event->local.nf_server_interface_metadata, na_sess->create_event->local.app_meta));
            */
	    msaf_network_assistance_session_remove(na_sess);
	
	} else {
	    msaf_network_assistance_session_remove_from_delete_list();
	}
	return false;
    }

    if(app_session){
	na_sess->pcf_app_session = app_session;    
	create_msaf_na_sess_and_send_response(na_sess);    
	return true;
    }
    return false;
}

static bool create_msaf_na_sess_and_send_response(msaf_network_assistance_session_t *na_sess){
    ogs_uuid_t uuid;
    char id[OGS_UUID_FORMATTED_LENGTH + 1];
    ogs_sbi_response_t *response;
    cJSON *nas_json;
    char *response_body;
    int response_code = 200;
    ogs_uuid_get(&uuid);
    ogs_uuid_format(id, &uuid);
    
    if(na_sess->NetworkAssistanceSession->na_session_id) {
	    ogs_free(na_sess->NetworkAssistanceSession->na_session_id);
	    na_sess->NetworkAssistanceSession->na_session_id = NULL;
    }
    

    na_sess->NetworkAssistanceSession->na_session_id = msaf_strdup(id);
    na_sess->naSessionId = msaf_strdup(id);
    
    na_sess->na_sess_created = time(NULL);
    
    response = nf_server_new_response(NULL, "application/json", 0, NULL, msaf_self()->config.server_response_cache_control->m5_service_access_information_response_max_age, NULL,na_sess->create_event->local.nf_server_interface_metadata, na_sess->create_event->local.app_meta);
    ogs_assert(response);

    nas_json = OpenAPI_network_assistance_session_convertToJSON(na_sess->NetworkAssistanceSession);
    response_body= cJSON_Print(nas_json);
    nf_server_populate_response(response, response_body?strlen(response_body):0, msaf_strdup(response_body), response_code);
    ogs_assert(true == ogs_sbi_server_send_response(na_sess->create_event->h.sbi.data, response));

    if(na_sess->create_event) 
    {
        msaf_event_free(na_sess->create_event);
	na_sess->create_event =  NULL;
    }

    ogs_list_add(&msaf_self()->network_assistance_sessions, na_sess);

    cJSON_Delete(nas_json);
    cJSON_free(response_body);
    ogs_sbi_header_free(&response->h);

    
    return true;

}

static bool app_session_notification_callback(pcf_app_session_t *app_session, const OpenAPI_events_notification_t *notifications, void *user_data)
{
    if (notifications) display_notifications(notifications);
    return true;
}

static bool bsf_retrieve_pcf_binding_callback(OpenAPI_pcf_binding_t *pcf_binding, void *data){
    int rv;
    int valid_time = 50;
    ogs_time_t expires;
    ogs_assert(data);
    ogs_sockaddr_t *pcf_address;
    ogs_sockaddr_t *ue_address = NULL;
    retrieve_pcf_binding_cb_data_t *retrieve_pcf_binding_cb_data; 
    
    retrieve_pcf_binding_cb_data = (retrieve_pcf_binding_cb_data_t *)data;
    ogs_assert(retrieve_pcf_binding_cb_data);

    ue_address = retrieve_pcf_binding_cb_data->ue_connection->address;

    ogs_assert(ue_address);

    if(pcf_binding){
        expires = ogs_time_now() + ogs_time_from_sec(valid_time);
        rv =  msaf_pcf_cache_add(msaf_self()->pcf_cache, ue_address, (const OpenAPI_pcf_binding_t *)pcf_binding, expires);
	OpenAPI_pcf_binding_free(pcf_binding);


        if (rv != true){
            ogs_error("Adding PCF Binding to the cache failed");
	    retrieve_pcf_binding_cb_data_free(retrieve_pcf_binding_cb_data);
            return false;
        }
	pcf_address = msaf_pcf_cache_find(msaf_self()->pcf_cache, retrieve_pcf_binding_cb_data->ue_connection->address);
	if(pcf_address){
	    create_pcf_app_session(pcf_address, retrieve_pcf_binding_cb_data->ue_connection, retrieve_pcf_binding_cb_data->na_sess);
            
	} else{
	   // send 404 to the ue client
	   char *err = NULL;
           err = ogs_msprintf("Unable to create the PCF app session.");
           ogs_error("%s", err);
           ogs_assert(true == nf_server_send_error(retrieve_pcf_binding_cb_data->na_sess->create_event->h.sbi.data, 404, 0, 
				   retrieve_pcf_binding_cb_data->na_sess->create_event->message, 
				   "PCF app session creation failed.", err, NULL, 
				   retrieve_pcf_binding_cb_data->na_sess->create_event->local.nf_server_interface_metadata, 
				   retrieve_pcf_binding_cb_data->na_sess->create_event->local.app_meta));
           ogs_free(err);

	   ogs_error("unable to create the PCF app session");
	   retrieve_pcf_binding_cb_data_free(retrieve_pcf_binding_cb_data);
	   return false;
	}
    } else {
	char *err = NULL;
        err = ogs_msprintf("Unable to retrieve PCF Binding.");
        ogs_error("%s", err);
        ogs_assert(true == nf_server_send_error(retrieve_pcf_binding_cb_data->na_sess->create_event->h.sbi.data, 404, 0,
                                   retrieve_pcf_binding_cb_data->na_sess->create_event->message,
                                   "PCF Binding not found.", err, NULL,
                                   retrieve_pcf_binding_cb_data->na_sess->create_event->local.nf_server_interface_metadata,
                                   retrieve_pcf_binding_cb_data->na_sess->create_event->local.app_meta));
        ogs_free(err);
        ogs_error("Unable to retrieve PCF Binding.");
	retrieve_pcf_binding_cb_data_free(retrieve_pcf_binding_cb_data);
        return false;
    }

    retrieve_pcf_binding_cb_data_free(retrieve_pcf_binding_cb_data);

    return true;

}

static void retrieve_pcf_binding_cb_data_free(retrieve_pcf_binding_cb_data_t *cb_data)
{
    free_ue_network_connection_identifier(cb_data->ue_connection);
    ogs_free(cb_data);	    

}

static void add_create_event_metadata_to_na_sess_context(msaf_network_assistance_session_t *na_sess, msaf_event_t *e)
{
  if(na_sess->create_event) msaf_event_free(na_sess->create_event);
  na_sess->create_event =  e; 
}

static void display_notifications(const OpenAPI_events_notification_t *notifications)
{
    OpenAPI_lnode_t *node;

    ogs_info("Notifications from [%s]", notifications->ev_subs_uri);
    OpenAPI_list_for_each(notifications->ev_notifs, node) {
        OpenAPI_af_event_notification_t *af_event = (OpenAPI_af_event_notification_t*)node->data;
        ogs_info("  Event: %s [%i]", OpenAPI_af_event_ToString(af_event->event), af_event->event);
        switch (af_event->event) {
        case OpenAPI_npcf_af_event_ACCESS_TYPE_CHANGE:
            ogs_info("    Access type = %s", OpenAPI_access_type_ToString(notifications->access_type));
            if (notifications->rat_type != OpenAPI_rat_type_NULL) {
                ogs_info("    Rat type = %s", OpenAPI_rat_type_ToString(notifications->rat_type));
            }
            if (notifications->add_access_info) {
                ogs_info("    Additional Access Info:");
                ogs_info("      Access type = %s", OpenAPI_access_type_ToString(notifications->add_access_info->access_type));
                if (notifications->add_access_info->rat_type != OpenAPI_rat_type_NULL) {
                    ogs_info("      Rat type = %s", OpenAPI_rat_type_ToString(notifications->add_access_info->rat_type));
                }
            }
            if (notifications->rel_access_info) {
                ogs_info("    Released Access Info:");
                ogs_info("      Access type = %s", OpenAPI_access_type_ToString(notifications->rel_access_info->access_type));
                if (notifications->rel_access_info->rat_type != OpenAPI_rat_type_NULL) {
                    ogs_info("      Rat type = %s", OpenAPI_rat_type_ToString(notifications->rel_access_info->rat_type));
                }
            }
            if (notifications->an_gw_addr) {
                ogs_info("    Access Network Gateway Address:");
                if (notifications->an_gw_addr->an_gw_ipv4_addr) {
                    ogs_info("      IPv4 = %s", notifications->an_gw_addr->an_gw_ipv4_addr);
                }
                if (notifications->an_gw_addr->an_gw_ipv6_addr) {
                    ogs_info("      IPv6 = %s", notifications->an_gw_addr->an_gw_ipv6_addr);
                }
            }
            break;
        case OpenAPI_npcf_af_event_ANI_REPORT:
            ogs_info("    Access Network Information Report:");
            break;
        case OpenAPI_npcf_af_event_APP_DETECTION:
            ogs_info("    Detected Application Reports:");
            break;
        case OpenAPI_npcf_af_event_CHARGING_CORRELATION:
            ogs_info("    Access Network Charging Correlation:");
            break;
        case OpenAPI_npcf_af_event_EPS_FALLBACK:
            ogs_info("    QoS flow failed - Fallback to EPS:");
            break;
        case OpenAPI_npcf_af_event_FAILED_QOS_UPDATE:
            ogs_info("    QoS update Failed:");
            break;
        case OpenAPI_npcf_af_event_FAILED_RESOURCES_ALLOCATION:
            ogs_info("    Resource Allocation Failed:");
            break;
        case OpenAPI_npcf_af_event_OUT_OF_CREDIT:
            ogs_info("    Out of Credit:");
            break;
        case OpenAPI_npcf_af_event_PDU_SESSION_STATUS:
            ogs_info("    PDU Session Status:");
            break;
        case OpenAPI_npcf_af_event_PLMN_CHG:
            ogs_info("    PLMN Change:");
            break;
        case OpenAPI_npcf_af_event_QOS_MONITORING:
            ogs_info("    QoS Monitoring:");
            break;
        case OpenAPI_npcf_af_event_QOS_NOTIF:
            ogs_info("    QoS Notification:");
            break;
        case OpenAPI_npcf_af_event_RAN_NAS_CAUSE:
            ogs_info("    RAN-NAS Release Cause:");
            break;
        case OpenAPI_npcf_af_event_REALLOCATION_OF_CREDIT:
            ogs_info("    Reallocation of Credit:");
            break;
        case OpenAPI_npcf_af_event_SAT_CATEGORY_CHG:
            ogs_info("    Satellite Backhaul Change:");
            break;
        case OpenAPI_npcf_af_event_SUCCESSFUL_QOS_UPDATE:
            ogs_info("    QoS Update Successful:");
            break;
        case OpenAPI_npcf_af_event_SUCCESSFUL_RESOURCES_ALLOCATION:
            ogs_info("    Resource Allocation Successful:");
            break;
        case OpenAPI_npcf_af_event_TSN_BRIDGE_INFO:
            ogs_info("    5GS Bridge Information:");
            break;
        case OpenAPI_npcf_af_event_UP_PATH_CHG_FAILURE:
            ogs_info("    AF Required Routing Failed:");
            break;
        case OpenAPI_npcf_af_event_USAGE_REPORT:
            ogs_info("    Usage Report:");
            break;
        default:
            ogs_error("Unknown notification type");
            break;
        }

        if (af_event->flows) {
            OpenAPI_lnode_t *flow_node;
            ogs_info("  Affected flows:");
            OpenAPI_list_for_each(af_event->flows, flow_node) {
                OpenAPI_flows_t *flows = (OpenAPI_flows_t*)flow_node->data;
                ogs_info("    Media component %i", flows->med_comp_n);
            }
        }
    }
}



/* vim:ts=8:sts=4:sw=4:expandtab:
 */
