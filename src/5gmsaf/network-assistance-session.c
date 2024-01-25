/*
License: 5G-MAG Public License (v1.0)
Author: Dev Audsin
Copyright: (C) 2023 British Broadcasting Corporation

For full license terms please see the LICENSE file distributed with this
program. If this file is missing then the license can be retrieved from
https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
*/

#include "utilities.h"
#include "network-assistance-session.h"
#include "pcf-session.h"
#include "timer.h"
#include "openapi/model/msaf_api_operation_success_response.h"


typedef struct retrieve_pcf_binding_cb_data_s {
    ue_network_identifier_t *ue_connection;
    OpenAPI_list_t *media_component;
    msaf_network_assistance_session_t *na_sess;
} retrieve_pcf_binding_cb_data_t;

static msaf_network_assistance_session_t *msaf_network_assistance_session_init(void);
static void msaf_network_assistance_session_remove(msaf_network_assistance_session_t *na_sess);
static void ue_connection_details_free(ue_network_identifier_t *ue_connection);

static bool app_session_change_callback(pcf_app_session_t *app_session, void *user_data);
static bool app_session_notification_callback(pcf_app_session_t *app_session, const OpenAPI_events_notification_t *notifications, void *user_data);
static void display_notifications(const OpenAPI_events_notification_t *notifications);
static void add_create_event_metadata_to_na_sess_context(msaf_network_assistance_session_t *na_sess, msaf_event_t *e);
static void add_delivery_boost_event_metadata_to_na_sess_context(msaf_network_assistance_session_t *na_sess, msaf_event_t *e);
static bool create_msaf_na_sess_and_send_response(msaf_network_assistance_session_t *na_sess);
static ue_network_identifier_t *copy_ue_network_connection_identifier(const ue_network_identifier_t *ue_net_connection);
static void free_ue_network_connection_identifier(ue_network_identifier_t *ue_net_connection);
static bool bsf_retrieve_pcf_binding_callback(OpenAPI_pcf_binding_t *pcf_binding, void *data);
static void create_pcf_app_session(const ogs_sockaddr_t *pcf_address, ue_network_identifier_t *ue_connection, OpenAPI_list_t *media_component, msaf_network_assistance_session_t *na_sess);
static void retrieve_pcf_binding_and_create_app_session(ue_network_identifier_t *ue_connection, OpenAPI_list_t *media_component, msaf_network_assistance_session_t *na_sess);
static void msaf_network_assistance_session_add_to_delete_list(pcf_app_session_t *pcf_app_session);
static void msaf_network_assistance_session_remove_from_delete_list(void);
static void msaf_pcf_app_session_free(void);
static void retrieve_pcf_binding_cb_data_free(retrieve_pcf_binding_cb_data_t *cb_data);
static OpenAPI_list_t *update_media_component(char *mir_bw_dl_bit_rate);
static char *flow_description_port(int port);
static char *flow_description_protocol_to_string(int protocol);
static OpenAPI_list_t *populate_media_component(char *policy_template_id, msaf_api_ip_packet_filter_set_t *flow_description, msaf_api_m5_qo_s_specification_t *requested_qos, msaf_api_media_type_e media_type);
static void activate_delivery_boost_and_send_response(msaf_network_assistance_session_t *na_sess);
static void delivery_boost_send_response(msaf_network_assistance_session_t *na_sess);
static void update_msaf_network_assistance_session_context(msaf_network_assistance_session_t *na_sess, msaf_api_network_assistance_session_t *network_assistance_session);

/***** Public functions *****/

int msaf_nw_assistance_session_create(cJSON *network_assistance_sess, msaf_event_t *e)
{
    msaf_network_assistance_session_t *na_sess;
    msaf_api_network_assistance_session_t *nas;
    msaf_api_service_data_flow_description_t *service_data_flow_description;
    OpenAPI_lnode_t *node = NULL;
    OpenAPI_list_t *media_component = NULL;

    nas =  msaf_api_network_assistance_session_parseRequestFromJSON(network_assistance_sess, NULL);
    if(!nas) return 0;

    na_sess = msaf_network_assistance_session_init();
    ogs_assert(na_sess);
    na_sess->NetworkAssistanceSession = nas;
    ogs_assert(na_sess->NetworkAssistanceSession);

    add_create_event_metadata_to_na_sess_context(na_sess, e);

    if (nas->service_data_flow_descriptions) {
        OpenAPI_list_for_each(nas->service_data_flow_descriptions, node) {
            const ogs_sockaddr_t *pcf_address;
            ue_network_identifier_t *ue_connection;

            service_data_flow_description = (msaf_api_service_data_flow_description_t *)node->data;

	    if(service_data_flow_description->domain_name) {
	        ogs_debug("Service Data Flow Descriptions specified using a domain name are not yet supported by this implementation");
                msaf_network_assistance_session_remove(na_sess);
                return 0;		
	    }	
		    

	    if(service_data_flow_description->flow_description && service_data_flow_description->domain_name) {
	        ogs_error("Validation of service data flow description failed: Only one of flowDescription or domainName may be present");
                msaf_network_assistance_session_remove(na_sess);
                return 0;
	    }

            if(!service_data_flow_description->flow_description && !service_data_flow_description->domain_name) {
                ogs_error("Validation of service data flow description failed: flowDescription or domainName must be present");
                msaf_network_assistance_session_remove(na_sess);
                return 0;
            }

	    if(service_data_flow_description->flow_description){

                if (!service_data_flow_description->flow_description->direction) {
                    ogs_error("Validation of service data flow description failed: no flowDescription.direction present");
                    msaf_network_assistance_session_remove(na_sess);
                    return 0;
                }

                SWITCH(service_data_flow_description->flow_description->direction)
                CASE("UPLINK")
                    if (!service_data_flow_description->flow_description->src_ip) {
                        ogs_error("Validation of service data flow description failed: flowDescription.srcIp must be set for UPLINK");
                        msaf_network_assistance_session_remove(na_sess);
                        return 0;
                    }
                    break;
                CASE("DOWNLINK")
                    if (!service_data_flow_description->flow_description->dst_ip) {
                        ogs_error("Validation of service data flow description failed: flowDescription.dstIp must be set for DOWNLINK");
                        msaf_network_assistance_session_remove(na_sess);
                        return 0;
                    }
                    break;
                CASE("BIDIRECTIONAL")
                    if (!service_data_flow_description->flow_description->dst_ip) {
                        ogs_error("Validation of service data flow description failed: flowDescription.dstIp must be set for BIDIRECTIONAL");
                        msaf_network_assistance_session_remove(na_sess);
                        return 0;
                    }
                    break;
                DEFAULT
                    ogs_error("Validation of service data flow description failed: flowDescription.direction of \"%s\" not implemented", service_data_flow_description->flow_description->direction);
                    msaf_network_assistance_session_remove(na_sess);
                    return 0;
                END

                ue_connection = populate_ue_connection_details(service_data_flow_description);
                if (!ue_connection) {
                    ogs_error("Validation of service data flow description failed: Failed to find UE connection details");
                    msaf_network_assistance_session_remove(na_sess);
                    return 0;
                }

                media_component = populate_media_component(na_sess->NetworkAssistanceSession->policy_template_id, service_data_flow_description->flow_description, na_sess->NetworkAssistanceSession->requested_qo_s, na_sess->NetworkAssistanceSession->media_type?na_sess->NetworkAssistanceSession->media_type:OpenAPI_media_type_VIDEO);

                pcf_address = msaf_pcf_cache_find(msaf_self()->pcf_cache, ue_connection->address);

                if (pcf_address) {
                    create_pcf_app_session(pcf_address, ue_connection, media_component, na_sess);
                } else {
                    retrieve_pcf_binding_and_create_app_session(ue_connection, media_component, na_sess);
                }
                ue_connection_details_free(ue_connection);
            }
	}
    }
    return 1;

}

int msaf_nw_assistance_session_update(msaf_network_assistance_session_t *msaf_network_assistance_session, msaf_api_network_assistance_session_t *network_assistance_session) {

    msaf_api_service_data_flow_description_t *service_data_flow_description;
    OpenAPI_lnode_t *node = NULL;
    OpenAPI_list_t *media_component = NULL;

    ogs_assert(msaf_network_assistance_session);
    ogs_assert(network_assistance_session);

    if (!msaf_network_assistance_session->pcf_app_session) {
	    ogs_error("The Network Assistance Session has no associated App Session");
        return 0;
    }

    if (network_assistance_session->service_data_flow_descriptions) {
        OpenAPI_list_for_each(network_assistance_session->service_data_flow_descriptions, node) {

            service_data_flow_description = (msaf_api_service_data_flow_description_t *)node->data;

            if(service_data_flow_description->domain_name) {
                ogs_debug("Service Data Flow Descriptions specified using a domain name are not yet supported by this implementation");
                return 0;
            }


            if(service_data_flow_description->flow_description && service_data_flow_description->domain_name) {
                ogs_error("Validation of service data flow description failed: Exactly one of flowDescription or domainName must be present");
                return 0;
            }

            if(service_data_flow_description->flow_description){

                if (!service_data_flow_description->flow_description->direction) {
                    ogs_error("The Network Assistance Session has direction in flow description");
                    return 0;
                }

                media_component = populate_media_component(network_assistance_session->policy_template_id, service_data_flow_description->flow_description, network_assistance_session->requested_qo_s, network_assistance_session->media_type?network_assistance_session->media_type: OpenAPI_media_type_VIDEO);

                if(!pcf_session_update_app_session(msaf_network_assistance_session->pcf_app_session, media_component)) {
                    ogs_error("Unable to send update request to the PCF");
                    return 0;
                }
	    }
	}
    }
    update_msaf_network_assistance_session_context(msaf_network_assistance_session, network_assistance_session);
    return 1;
}

void msaf_nw_assistance_session_delivery_boost_update(msaf_network_assistance_session_t *na_sess, msaf_event_t *e){

    OpenAPI_list_t *media_comps;
    char *mir_bw_dl_bit_rate = NULL;

    ogs_assert(na_sess);

    mir_bw_dl_bit_rate =  ogs_sbi_bitrate_to_string(msaf_self()->config.network_assistance_delivery_boost->delivery_boost_min_dl_bit_rate, OGS_SBI_BITRATE_BPS);

    ogs_assert(mir_bw_dl_bit_rate);

    media_comps = update_media_component(mir_bw_dl_bit_rate);

    if (na_sess->pcf_app_session) {

        add_delivery_boost_event_metadata_to_na_sess_context(na_sess, e);

        if(!pcf_session_update_app_session(na_sess->pcf_app_session, media_comps)) {
            ogs_error("Unable to send update request to the PCF");
            ogs_assert(true == nf_server_send_error(e->h.sbi.data, 401, 0, e->message, "Creation of delivery boost failed.", "Unable to send update request to the PCF" , NULL, e->nf_server_interface_metadata, e->app_meta));
        }

    } else {
            ogs_error("The Network Assistance Session has no associated App Session");
            ogs_assert(true == nf_server_send_error(e->h.sbi.data, 401, 0, e->message, "Creation of delivery boost failed.", "The Network Assistance Session has no associated App Session" , NULL, e->nf_server_interface_metadata, e->app_meta));

    }
    ogs_info("END of msaf_nw_assistance_session_update_pcf");

}

void msaf_nw_assistance_session_update_pcf_on_timeout(msaf_network_assistance_session_t *na_sess){

    OpenAPI_list_t *media_comps;
    char *mir_bw_dl_bit_rate;
    bool rv = false;

    ogs_assert(na_sess);

    mir_bw_dl_bit_rate = msaf_strdup(na_sess->NetworkAssistanceSession->requested_qo_s->mir_bw_dl_bit_rate);
    ogs_assert(mir_bw_dl_bit_rate);

    media_comps = update_media_component(mir_bw_dl_bit_rate);

    if (na_sess->pcf_app_session) {

        rv = pcf_session_update_app_session(na_sess->pcf_app_session, media_comps);

        if(!rv){
            ogs_error("Unable to send update request to the PCF");
        } else {
            na_sess->active_delivery_boost = false;
        }

    } else {
            ogs_error("The Network Assistance Session has no associated App Session");

    }

    ogs_timer_stop(na_sess->delivery_boost_timer);

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
        return msaf_api_network_assistance_session_convertResponseToJSON(na_sess->NetworkAssistanceSession);

    return NULL;
}

ue_network_identifier_t *populate_ue_connection_details(msaf_api_service_data_flow_description_t *service_data_flow_information)
{
    int rv;
    ue_network_identifier_t *ue_connection;

    ue_connection = ogs_calloc(1, sizeof(ue_network_identifier_t));
    ogs_assert(ue_connection);

    if (service_data_flow_information->domain_name) {
        ue_connection->ip_domain = msaf_strdup(service_data_flow_information->domain_name);
    }

    if (!strcmp(service_data_flow_information->flow_description->direction, "UPLINK")) {

        rv = ogs_getaddrinfo(&ue_connection->address, AF_UNSPEC, service_data_flow_information->flow_description->src_ip, service_data_flow_information->flow_description->src_port, 0);
    }

    if (!strcmp(service_data_flow_information->flow_description->direction, "DOWNLINK")) {
        ogs_info("%s: dst_ip", service_data_flow_information->flow_description->dst_ip);

        rv = ogs_getaddrinfo(&ue_connection->address, AF_UNSPEC, service_data_flow_information->flow_description->dst_ip, service_data_flow_information->flow_description->dst_port, 0);
    }

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

static OpenAPI_list_t *update_media_component(char *mir_bw_dl_bit_rate) {

    OpenAPI_list_t *media_comps;
    OpenAPI_media_component_rm_t *media_comp;
    OpenAPI_map_t *media_comp_map;

    media_comps = OpenAPI_list_create();
    ogs_assert(media_comps);

    media_comp = OpenAPI_media_component_rm_create(NULL , NULL, NULL, NULL, NULL, false , 0, false, 0, NULL, false, 0.0,
            false, 0.0, NULL, OpenAPI_flow_status_NULL, NULL, NULL, false, 0, false, 0, NULL, NULL, 0, NULL,
            OpenAPI_media_type_VIDEO, NULL, NULL, mir_bw_dl_bit_rate, NULL, OpenAPI_preemption_capability_NULL,
            OpenAPI_preemption_vulnerability_NULL, OpenAPI_priority_sharing_indicator_NULL, OpenAPI_reserv_priority_NULL,
            NULL, NULL, false, 0, false, 0, NULL, NULL, NULL, false, 0);

    media_comp_map = OpenAPI_map_create(ogs_msprintf("%d", media_comp->med_comp_n), media_comp);
    ogs_assert(media_comp_map);
    ogs_assert(media_comp_map->key);

    OpenAPI_list_add(media_comps, media_comp_map);

    ogs_assert(media_comps->count);

    return media_comps;
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

/*Private functions */

static msaf_network_assistance_session_t *msaf_network_assistance_session_init(void){

    msaf_network_assistance_session_t *na_sess;
    na_sess = ogs_calloc(1, sizeof(msaf_network_assistance_session_t));
    ogs_assert(na_sess);
    na_sess->delivery_boost_timer = NULL;
    return na_sess;


}


static OpenAPI_list_t *populate_media_component(char *policy_template_id, msaf_api_ip_packet_filter_set_t *flow_description, msaf_api_m5_qo_s_specification_t *requested_qos, msaf_api_media_type_e media_type) {

    OpenAPI_list_t *MediaComponentList = NULL;
    OpenAPI_map_t *MediaComponentMap = NULL;
    OpenAPI_media_component_t *MediaComponent = NULL;
    OpenAPI_list_t *media_sub_comp_list = NULL;

    MediaComponentList = OpenAPI_list_create();
    ogs_assert(MediaComponentList);

    if (flow_description->src_ip || flow_description->src_port !=0 || flow_description->protocol != IPPROTO_IP ||
                flow_description->dst_ip || flow_description->dst_port != 0) {
        OpenAPI_media_sub_component_t *media_sub_comp;
        OpenAPI_list_t *flow_descs;
        OpenAPI_map_t *media_sub_comp_map;
        char *flow_desc;
        char *ue_addr;
        char *ue_port;
        char *remote_addr;
        char *remote_port;

        if(!strcmp(flow_description->direction, "UPLINK")){
            remote_addr = flow_description->dst_ip?flow_description->dst_ip:"any";
            remote_port = flow_description_port(flow_description->dst_port);

            ue_addr = flow_description->src_ip?flow_description->src_ip:"any";
            ue_port = flow_description_port(flow_description->dst_port);

        }

        if(!strcmp(flow_description->direction, "DOWNLINK")){

            remote_addr = flow_description->src_ip?flow_description->src_ip:"any";
            remote_port = flow_description_port(flow_description->src_port);

            ue_addr = flow_description->dst_ip?flow_description->dst_ip:"any";
            ue_port = flow_description_port(flow_description->dst_port);
         }

        flow_descs = OpenAPI_list_create();
        ogs_assert(flow_descs);

        flow_desc = ogs_msprintf("permit in %s from %s%s to %s%s", flow_description_protocol_to_string(flow_description->protocol),
                ue_addr, ue_port, remote_addr, remote_port);
        ogs_assert(flow_desc);

        OpenAPI_list_add(flow_descs, flow_desc);

        flow_desc = ogs_msprintf("permit out %s from %s%s to %s%s", flow_description_protocol_to_string(flow_description->protocol),
                remote_addr, remote_port, ue_addr, ue_port);
        ogs_assert(flow_desc);

        OpenAPI_list_add(flow_descs, flow_desc);

        ogs_free(ue_port);
        ogs_free(remote_port);

        media_sub_comp = OpenAPI_media_sub_component_create(OpenAPI_af_sig_protocol_NULL,
                NULL, 0, flow_descs, OpenAPI_flow_status_ENABLED,
                requested_qos->mar_bw_dl_bit_rate,
                requested_qos->mar_bw_ul_bit_rate,
                NULL , OpenAPI_flow_usage_NULL);
        ogs_assert(media_sub_comp);

        media_sub_comp_map = OpenAPI_map_create(ogs_msprintf("%d", media_sub_comp->f_num), media_sub_comp);
        ogs_assert(media_sub_comp_map);

        media_sub_comp_list = OpenAPI_list_create();
        OpenAPI_list_add(media_sub_comp_list, media_sub_comp_map);

    }

    MediaComponent = OpenAPI_media_component_create(NULL, NULL, NULL, false, 0, NULL, NULL,
            false, 0, NULL, false, 0.0, false, 0.0, NULL, OpenAPI_flow_status_NULL,
            msaf_strdup(requested_qos->mar_bw_dl_bit_rate), msaf_strdup(requested_qos->mar_bw_ul_bit_rate),
            false, 0, false, 0, NULL, NULL, 0, media_sub_comp_list, media_type,
            requested_qos->min_des_bw_dl_bit_rate, requested_qos->min_des_bw_ul_bit_rate,
            msaf_strdup(requested_qos->mir_bw_dl_bit_rate), msaf_strdup(requested_qos->mir_bw_ul_bit_rate),
            OpenAPI_preemption_capability_NULL, OpenAPI_preemption_vulnerability_NULL,
            OpenAPI_priority_sharing_indicator_NULL, OpenAPI_reserv_priority_NULL,
            NULL, NULL, false, 0, false, 0, NULL, NULL, NULL, false, 0);

    MediaComponentMap = OpenAPI_map_create(
            ogs_msprintf("%d", MediaComponent->med_comp_n), MediaComponent);
    ogs_assert(MediaComponentMap);
    ogs_assert(MediaComponentMap->key);

    OpenAPI_list_add(MediaComponentList, MediaComponentMap);

    ogs_assert(MediaComponentList->count);

    return MediaComponentList;
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



static void create_pcf_app_session(const ogs_sockaddr_t *pcf_address, ue_network_identifier_t *ue_connection, OpenAPI_list_t *media_component, msaf_network_assistance_session_t *na_sess)
{
    pcf_session_t *pcf_session;
    int events = 0;
    ue_network_identifier_t *ue_net = NULL;


    events = PCF_APP_SESSION_EVENT_TYPE_QOS_NOTIF | PCF_APP_SESSION_EVENT_TYPE_QOS_MONITORING | PCF_APP_SESSION_EVENT_TYPE_SUCCESSFUL_QOS_UPDATE | PCF_APP_SESSION_EVENT_TYPE_FAILED_QOS_UPDATE;

    pcf_session = msaf_pcf_session_new(pcf_address);

    ue_net  = copy_ue_network_connection_identifier(ue_connection);

    pcf_session_create_app_session(pcf_session, ue_net, events, media_component, app_session_notification_callback, NULL, app_session_change_callback, na_sess);

    ue_connection_details_free(ue_net);
}

static void retrieve_pcf_binding_and_create_app_session(ue_network_identifier_t *ue_connection, OpenAPI_list_t *media_component, msaf_network_assistance_session_t *na_sess)
{
    retrieve_pcf_binding_cb_data_t *cb_data;

    cb_data = ogs_calloc(1, sizeof(retrieve_pcf_binding_cb_data_t));
    cb_data->ue_connection = copy_ue_network_connection_identifier((const ue_network_identifier_t *)ue_connection);
    cb_data->na_sess = na_sess;
    cb_data->media_component = media_component;

    bsf_retrieve_pcf_binding_for_pdu_session(ue_connection->address, bsf_retrieve_pcf_binding_callback, cb_data);
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

    if(msaf_network_assistance_session->NetworkAssistanceSession) msaf_api_network_assistance_session_free(msaf_network_assistance_session->NetworkAssistanceSession);
    if(msaf_network_assistance_session->metadata){
        if(msaf_network_assistance_session->metadata->create_event) msaf_event_free(msaf_network_assistance_session->metadata->create_event);
        if(msaf_network_assistance_session->metadata->delivery_boost) msaf_event_free(msaf_network_assistance_session->metadata->delivery_boost);
        ogs_free(msaf_network_assistance_session->metadata);
    }
    if(msaf_network_assistance_session->delivery_boost_timer)
        ogs_timer_delete(msaf_network_assistance_session->delivery_boost_timer);

    ogs_free(msaf_network_assistance_session);

}

static void ue_connection_details_free(ue_network_identifier_t *ue_connection) {
    if(ue_connection->address) ogs_freeaddrinfo(ue_connection->address);
    if(ue_connection->ip_domain) ogs_free(ue_connection->ip_domain);
    ogs_free(ue_connection);

}

static bool app_session_change_callback(pcf_app_session_t *app_session, void *data){

    msaf_network_assistance_session_t *na_sess;
    ogs_debug("change callback(app_session=%p, data=%p)", app_session, data);

    na_sess = (msaf_network_assistance_session_t *)data;

    if(!app_session){

        if(na_sess->metadata->create_event)
        {
            /*
            ogs_assert(true == nf_server_send_error(na_sess->create_event->h.sbi.data, 401, 0, na_sess->create_event->message, "Creation of the Network Assistance Session failed.", "PCF App Session creation failed" , NULL, na_sess->create_event->local.nf_server_interface_metadata, na_sess->create_event->local.app_meta));
            */
            msaf_network_assistance_session_remove(na_sess);
            return false;

        }

        if(na_sess->metadata->delivery_boost){
            delivery_boost_send_response(na_sess);
            return false;
        }

        msaf_network_assistance_session_remove_from_delete_list();

        return false;
    }

    if(app_session && na_sess->metadata->create_event){
        na_sess->pcf_app_session = app_session;
        create_msaf_na_sess_and_send_response(na_sess);
        return true;
    }

    if(app_session && na_sess->metadata->delivery_boost) {
        ogs_info("Callback from PCF Update");
        activate_delivery_boost_and_send_response(na_sess);
        return true;
    }
    return false;
}

static void activate_delivery_boost_and_send_response(msaf_network_assistance_session_t *na_sess) {

    char *reason = NULL;
    msaf_api_operation_success_response_t *operation_success_response;
    cJSON *op_success_response;
    char *success_response;
    ogs_sbi_response_t *response;
    int response_code = 200;
    int cache_control_max_age;

    ogs_assert(na_sess);
    na_sess->active_delivery_boost = true;

    operation_success_response = msaf_api_operation_success_response_create(reason, 1);
    op_success_response = msaf_api_operation_success_response_convertResponseToJSON(operation_success_response);
    success_response = cJSON_Print(op_success_response);

    cache_control_max_age = (msaf_self()->config.network_assistance_delivery_boost->delivery_boost_period);

    response = nf_server_new_response(NULL, "application/json", 0, NULL, cache_control_max_age, NULL, na_sess->metadata->delivery_boost->nf_server_interface_metadata, na_sess->metadata->delivery_boost->app_meta);
    ogs_assert(response);
    nf_server_populate_response(response, strlen(success_response), ogs_strdup(success_response), response_code);
    ogs_assert(true == ogs_sbi_server_send_response(na_sess->metadata->delivery_boost->h.sbi.data, response));

    if(!na_sess->delivery_boost_timer) na_sess->delivery_boost_timer = ogs_timer_add(ogs_app()->timer_mgr, msaf_timer_delivery_boost, na_sess);

    if (na_sess->delivery_boost_timer) {
            ogs_timer_start(na_sess->delivery_boost_timer, ogs_time_from_sec(msaf_self()->config.network_assistance_delivery_boost->delivery_boost_period));
    }
    if(na_sess->metadata->delivery_boost)
    {
        msaf_event_free(na_sess->metadata->delivery_boost);
        na_sess->metadata->delivery_boost =  NULL;

    }

    cJSON_Delete(op_success_response);
    msaf_api_operation_success_response_free(operation_success_response);
    cJSON_free(success_response);

}

static void delivery_boost_send_response(msaf_network_assistance_session_t *na_sess) {

    char *reason = NULL;
    msaf_api_operation_success_response_t *operation_success_response;
    cJSON *op_success_response;
    char *success_response;
    ogs_sbi_response_t *response;
    int response_code = 200;

    ogs_assert(na_sess);

    reason = "PCF rejected delivery boost requested";


    operation_success_response = msaf_api_operation_success_response_create(reason, 0);
    op_success_response = msaf_api_operation_success_response_convertResponseToJSON(operation_success_response);
    success_response = cJSON_Print(op_success_response);

    response = nf_server_new_response(NULL, "application/json", 0, NULL, 0, NULL, na_sess->metadata->delivery_boost->nf_server_interface_metadata, na_sess->metadata->delivery_boost->app_meta);
    ogs_assert(response);
    nf_server_populate_response(response, strlen(success_response), ogs_strdup(success_response), response_code);
    ogs_assert(true == ogs_sbi_server_send_response(na_sess->metadata->delivery_boost->h.sbi.data, response));

    cJSON_Delete(op_success_response);
    msaf_api_operation_success_response_free(operation_success_response);
    cJSON_free(success_response);

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

    if (na_sess->NetworkAssistanceSession->na_session_id) {
        ogs_free(na_sess->NetworkAssistanceSession->na_session_id);
        na_sess->NetworkAssistanceSession->na_session_id = NULL;
    }

    na_sess->NetworkAssistanceSession->na_session_id = msaf_strdup(id);
    na_sess->naSessionId = msaf_strdup(id);

    na_sess->na_sess_created = time(NULL);

    response = nf_server_new_response(NULL, "application/json", 0, NULL, msaf_self()->config.server_response_cache_control->m5_service_access_information_response_max_age, NULL,na_sess->metadata->create_event->nf_server_interface_metadata, na_sess->metadata->create_event->app_meta);

    ogs_assert(response);

    nas_json = msaf_api_network_assistance_session_convertResponseToJSON(na_sess->NetworkAssistanceSession);
    response_body= cJSON_Print(nas_json);
    nf_server_populate_response(response, response_body?strlen(response_body):0, msaf_strdup(response_body), response_code);
    ogs_assert(true == ogs_sbi_server_send_response(na_sess->metadata->create_event->h.sbi.data, response));

    if(na_sess->metadata->create_event)
    {
        msaf_event_free(na_sess->metadata->create_event);
        na_sess->metadata->create_event =  NULL;
        //ogs_free(na_sess->metadata);
        //na_sess->metadata =  NULL;

    }

    na_sess->active_delivery_boost = false;

    ogs_list_add(&msaf_self()->network_assistance_sessions, na_sess);

    cJSON_Delete(nas_json);
    cJSON_free(response_body);
    ogs_sbi_header_free(&response->h);

    return true;

}

static void update_msaf_network_assistance_session_context(msaf_network_assistance_session_t *na_sess, msaf_api_network_assistance_session_t *network_assistance_session)
{

    if (na_sess->NetworkAssistanceSession) {
        msaf_api_network_assistance_session_free(na_sess->NetworkAssistanceSession);
        na_sess->NetworkAssistanceSession->na_session_id = NULL;
    }
    na_sess->NetworkAssistanceSession = network_assistance_session;
    na_sess->NetworkAssistanceSession->na_session_id = msaf_strdup(na_sess->naSessionId);
    na_sess->na_sess_created = time(NULL);
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
    ogs_sockaddr_t *ue_address;
    retrieve_pcf_binding_cb_data_t *retrieve_pcf_binding_cb_data = (retrieve_pcf_binding_cb_data_t *)data;

    ogs_assert(retrieve_pcf_binding_cb_data);

    ue_address = retrieve_pcf_binding_cb_data->ue_connection->address;

    ogs_assert(ue_address);

    if(pcf_binding){
        const ogs_sockaddr_t *pcf_address;
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
            create_pcf_app_session(pcf_address, retrieve_pcf_binding_cb_data->ue_connection, retrieve_pcf_binding_cb_data->media_component, retrieve_pcf_binding_cb_data->na_sess);
            retrieve_pcf_binding_cb_data_free(retrieve_pcf_binding_cb_data);
            return true;
        } else{
           // send 404 to the ue client
           char *err = NULL;
           err = ogs_msprintf("Unable to create the PCF app session.");
           ogs_error("%s", err);
           ogs_assert(true == nf_server_send_error(retrieve_pcf_binding_cb_data->na_sess->metadata->create_event->h.sbi.data, 404, 0,
                                   retrieve_pcf_binding_cb_data->na_sess->metadata->create_event->message,
                                   "PCF app session creation failed.", err, NULL,
                                   retrieve_pcf_binding_cb_data->na_sess->metadata->create_event->nf_server_interface_metadata,
                                   retrieve_pcf_binding_cb_data->na_sess->metadata->create_event->app_meta));
           ogs_free(err);

           ogs_error("unable to create the PCF app session");
           retrieve_pcf_binding_cb_data_free(retrieve_pcf_binding_cb_data);
           return false;
        }
    } else {
        char *err = NULL;
        err = ogs_msprintf("Unable to retrieve PCF Binding.");
        ogs_error("%s", err);
        ogs_assert(true == nf_server_send_error(retrieve_pcf_binding_cb_data->na_sess->metadata->create_event->h.sbi.data, 404, 0,
                                   retrieve_pcf_binding_cb_data->na_sess->metadata->create_event->message,
                                   "PCF Binding not found.", err, NULL,
                                   retrieve_pcf_binding_cb_data->na_sess->metadata->create_event->nf_server_interface_metadata,
                                   retrieve_pcf_binding_cb_data->na_sess->metadata->create_event->app_meta));
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
  //if(na_sess->metadata->create_event) msaf_event_free(na_sess->metadata->create_event);
  na_sess->metadata = ogs_calloc(1, sizeof(msaf_network_assistance_session_internal_metadata_t));
  na_sess->metadata->create_event =  e;
}

static void add_delivery_boost_event_metadata_to_na_sess_context(msaf_network_assistance_session_t *na_sess, msaf_event_t *e){
    na_sess->metadata->delivery_boost = e;
}

static char *flow_description_protocol_to_string(int protocol)
{
    switch (protocol) {
    case IPPROTO_IP:
        return "ip";
    case IPPROTO_TCP:
        return "tcp";
    case IPPROTO_UDP:
        return "udp";
    case IPPROTO_ICMP:
        return "icmp";
    case IPPROTO_SCTP:
        return "sctp";
    default:
        break;
    }
    return "ip";
}


static char *flow_description_port(int port)
{
    if (port == 0) return ogs_strdup("");
    return ogs_msprintf(" %d", port);
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
