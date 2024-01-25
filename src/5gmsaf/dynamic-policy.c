/*
License: 5G-MAG Public License (v1.0)
Author: Dev Audsin
Copyright: (C) 2023 British Broadcasting Corporation

For full license terms please see the LICENSE file distributed with this
program. If this file is missing then the license can be retrieved from
https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
*/

#include "utilities.h"
#include "dynamic-policy.h"
#include "pcf-session.h"
#include "hash.h"

typedef struct retrieve_pcf_binding_cb_data_s {
    ue_network_identifier_t *ue_connection;
    OpenAPI_list_t *media_component;
    msaf_dynamic_policy_t *dyn_policy;
} retrieve_pcf_binding_cb_data_t;

typedef struct free_ogs_hash_dynamic_policy_s {
    const char *dynamic_policy_id;
    ogs_hash_t *hash;
} free_ogs_hash_dynamic_policy_t;


typedef struct app_session_change_cb_data_s {
    msaf_policy_template_node_t *msaf_policy_template;
    msaf_dynamic_policy_t *dyn_policy;
} app_session_change_cb_data_t;

static msaf_dynamic_policy_t *msaf_dynamic_policy_init(void);
static void msaf_dynamic_policy_remove(msaf_dynamic_policy_t *msaf_dynamic_policy);
static void ue_connection_details_free(ue_network_identifier_t *ue_connection);
static char *set_max_bit_rate_compliant_with_policy_template(char *policy_template_m1_qos_bit_rate, char *m5_qos_bit_rate); 
static int calculate_max_bit_rate_for_enforcement(char *policy_template_m1_qos_bit_rate, char *m5_qos_bit_rate);
static bool app_session_change_callback(pcf_app_session_t *app_session, void *user_data);
static bool app_session_notification_callback(pcf_app_session_t *app_session, const OpenAPI_events_notification_t *notifications, void *user_data);
static void display_notifications(const OpenAPI_events_notification_t *notifications);
static void add_create_event_metadata_to_dynamic_policy_context(msaf_dynamic_policy_t *dynamic_policy, msaf_event_t *e);
static bool create_msaf_dynamic_policy_and_send_response(msaf_dynamic_policy_t *dynamic_policy);
static ue_network_identifier_t *copy_ue_network_connection_identifier(const ue_network_identifier_t *ue_net_connection);
static void free_ue_network_connection_identifier(ue_network_identifier_t *ue_net_connection);
static bool bsf_retrieve_pcf_binding_callback(OpenAPI_pcf_binding_t *pcf_binding, void *data);
static void create_dynamic_policy_app_session(const ogs_sockaddr_t *pcf_address, ue_network_identifier_t *ue_connection, OpenAPI_list_t *media_component, msaf_dynamic_policy_t *dynamic_policy);
static void retrieve_pcf_binding_and_create_dynamic_policy_app_session(ue_network_identifier_t *ue_connection, OpenAPI_list_t *media_component, msaf_dynamic_policy_t *dynamic_policy);
static void retrieve_pcf_binding_cb_data_free(retrieve_pcf_binding_cb_data_t *cb_data);
static OpenAPI_list_t *update_media_component(msaf_api_m1_qo_s_specification_t *m1_qos, msaf_api_m5_qo_s_specification_t *requested_qos, msaf_api_media_type_e media_type);
static char *flow_description_port(int port);
static char *flow_description_protocol_to_string(int protocol);
static ue_network_identifier_t *populate_ue_connection_information(msaf_api_service_data_flow_description_t *service_data_flow_information);
static OpenAPI_list_t *populate_media_component(msaf_api_m1_qo_s_specification_t *m1_qos, msaf_api_ip_packet_filter_set_t *flow_description, msaf_api_m5_qo_s_specification_t *requested_qos, msaf_api_media_type_e media_type);
static void update_dynamic_policy_context(msaf_dynamic_policy_t *msaf_dynamic_policy, msaf_api_dynamic_policy_t *dynamic_policy);
static void dynamic_policy_set_enforcement_bit_rate(msaf_policy_template_node_t *msaf_policy_template, msaf_api_dynamic_policy_t *dynamic_policy);
static void add_delete_event_metadata_to_dynamic_policy_context(msaf_dynamic_policy_t *dynamic_policy, msaf_event_t *e);
static void msaf_dynamic_policy_delete(msaf_dynamic_policy_t *dynamic_policy);
static void msaf_dynamic_policy_hash_remove(const char *dynamic_policy_id);
static int free_ogs_hash_dynamic_policy(void *rec, const void *key, int klen, const void *value);


/***** Public functions *****/

ogs_hash_t *msaf_dynamic_policy_new(void)
{
    ogs_hash_t *ret;

    ret = ogs_hash_make();

    ogs_debug("msaf_dynamic_policy_new() = %p", ret);

    return ret;
}


int msaf_dynamic_policy_create(cJSON *dynamicPolicy, msaf_event_t *e)
{
    msaf_dynamic_policy_t *dyn_policy;
    msaf_api_dynamic_policy_t *dynamic_policy;
    msaf_api_service_data_flow_description_t *service_data_flow_description;
    msaf_policy_template_node_t *msaf_policy_template;
    OpenAPI_lnode_t *node = NULL;
    OpenAPI_list_t *media_component = NULL;
    const char *reason;


    dynamic_policy =  msaf_api_dynamic_policy_parseRequestFromJSON(dynamicPolicy, &reason);
    if(!dynamic_policy) {
	ogs_error("Dynamic Policy Badly formed JSON: [%s]", reason);     
        return 0;
    }

    dyn_policy = msaf_dynamic_policy_init();
    if(!dyn_policy) return 0;

    dyn_policy->DynamicPolicy = dynamic_policy;
    ogs_assert(dyn_policy->DynamicPolicy);

    add_create_event_metadata_to_dynamic_policy_context(dyn_policy, e);

    if (dynamic_policy->service_data_flow_descriptions) {
        if (dynamic_policy->service_data_flow_descriptions->first == NULL) {
            ogs_error("Service Data Flow Descriptions must have at least one entry");
            msaf_dynamic_policy_remove(dyn_policy);
            return 0;
        }
        OpenAPI_list_for_each(dynamic_policy->service_data_flow_descriptions, node) {
            const ogs_sockaddr_t *pcf_address;
            ue_network_identifier_t *ue_connection;

            service_data_flow_description = (msaf_api_service_data_flow_description_t *)node->data;

            /* Not Implemented Yet */
	    if(service_data_flow_description->domain_name) {
	        ogs_error("Service Data Flow Descriptions specified using a domain name are not yet supported by this implementation");
                msaf_dynamic_policy_remove(dyn_policy);
                return 0;		
	    }	

            /* Validate SDF */
	    if (service_data_flow_description->flow_description && service_data_flow_description->domain_name) {
	        ogs_error("Validation of service data flow description failed: Only one of flowDescription or domainName may be present");
                msaf_dynamic_policy_remove(dyn_policy);
                return 0;
	    }

            if (!service_data_flow_description->flow_description && !service_data_flow_description->domain_name) {
                ogs_error("Validation of service data flow description failed: flowDescription or domainName must be present");
                msaf_dynamic_policy_remove(dyn_policy);
                return 0;
            }

	    if (service_data_flow_description->flow_description) {

                if (!service_data_flow_description->flow_description->direction) {
                    ogs_error("Mandatory direction property missing");
                    msaf_dynamic_policy_remove(dyn_policy);
                    return 0;
                } else {
                    /* direction passed to Npcf_PolicyAuthorization so needs to match rules for FlowDirection enumerated type */
                    SWITCH(service_data_flow_description->flow_description->direction)
                    CASE("DOWNLINK")
                        if (!service_data_flow_description->flow_description->dst_ip) {
                            ogs_error("Validation of service data flow description failed: Need dstIp for DOWNLINK flow direction");
                            msaf_dynamic_policy_remove(dyn_policy);
                            return 0;
                        }
                        break;
                    CASE("UPLINK")
                        if (!service_data_flow_description->flow_description->src_ip) {
                            ogs_error("Validation of service data flow description failed: Need srcIp for UPLINK flow direction");
                            msaf_dynamic_policy_remove(dyn_policy);
                            return 0;
                        }
                        break;
                    CASE("BIDIRECTIONAL")
                        if (!service_data_flow_description->flow_description->dst_ip) {
                            ogs_error("Validation of service data flow description failed: Need dstIp for BIDIRECTIONAL flow direction");
                            msaf_dynamic_policy_remove(dyn_policy);
                            return 0;
                        }
                        break;
                    /*CASE("UNSPECIFIED")
                        if (!service_data_flow_description->flow_description->dst_ip) {
                            ogs_error("Validation of service data flow description failed: Need dstIp for UNSPECIFIED flow direction");
                            msaf_dynamic_policy_remove(dyn_policy);
                            return 0;
                        }
                        break; */
                    DEFAULT
                        ogs_error("Validation of service data flow description failed: flowDescription.direction \"%s\" not implemented", service_data_flow_description->flow_description->direction);
                        msaf_dynamic_policy_remove(dyn_policy);
                        return 0;
                    END
                }

                ue_connection = populate_ue_connection_information(service_data_flow_description);
                if (!ue_connection) {
                    ogs_error("Cannot find UE address, unable to request policy authorization");
                    msaf_dynamic_policy_remove(dyn_policy);
                    return 0;
                }

		msaf_policy_template = msaf_provisioning_session_get_policy_template_by_id(dynamic_policy->provisioning_session_id, dynamic_policy->policy_template_id);
		if (!msaf_policy_template) {
                    ogs_error("Cannot find policy template %s in provisioning session %s", dynamic_policy->policy_template_id, dynamic_policy->provisioning_session_id);
                    msaf_dynamic_policy_remove(dyn_policy);
                    return 0;
                }

                media_component = populate_media_component(msaf_policy_template->policy_template->qo_s_specification, service_data_flow_description->flow_description, dynamic_policy->qos_specification?dynamic_policy->qos_specification: NULL, dynamic_policy->media_type?dynamic_policy->media_type: OpenAPI_media_type_VIDEO);
                if (!media_component) {
                    ogs_error("Unable to convert policy to MediaComponent");
                    msaf_dynamic_policy_remove(dyn_policy);
                    return 0;
                } 
                dynamic_policy_set_enforcement_bit_rate(msaf_policy_template, dynamic_policy);
		 /*
	         dynamic_policy->is_enforcement_bit_rate = true;
		 if (!dynamic_policy->qos_specification) {
		        dynamic_policy->enforcement_bit_rate = ogs_sbi_bitrate_from_string(msaf_policy_template->policy_template->qo_s_specification->max_auth_btr_dl?msaf_policy_template->policy_template->qo_s_specification->max_auth_btr_dl: msaf_policy_template->policy_template->qo_s_specification->max_btr_dl);
                 } else {
		        dynamic_policy->enforcement_bit_rate = calculate_max_bit_rate_for_enforcement(msaf_policy_template->policy_template->qo_s_specification->max_auth_btr_dl?msaf_policy_template->policy_template->qo_s_specification->max_auth_btr_dl: msaf_policy_template->policy_template->qo_s_specification->max_btr_dl, dynamic_policy->qos_specification->mar_bw_dl_bit_rate); 
                }
	        */	
                pcf_address = msaf_pcf_cache_find(msaf_self()->pcf_cache, ue_connection->address);

                if (pcf_address) {
                    create_dynamic_policy_app_session(pcf_address, ue_connection, media_component, dyn_policy);
                } else {
                    retrieve_pcf_binding_and_create_dynamic_policy_app_session(ue_connection, media_component, dyn_policy);
                }
                ue_connection_details_free(ue_connection);
            }
	}
    } else {
        ogs_error("Must have a serviceDataFlowDescriptions");
        msaf_dynamic_policy_remove(dyn_policy);
        return 0;
    }
    return 1;

}

int msaf_dynamic_policy_update_pcf(msaf_dynamic_policy_t *msaf_dynamic_policy, msaf_api_dynamic_policy_t *dynamic_policy) {
    OpenAPI_list_t *media_comps;
    msaf_policy_template_node_t *msaf_policy_template;

    ogs_assert(msaf_dynamic_policy);
    ogs_assert(dynamic_policy);

    msaf_policy_template = msaf_provisioning_session_get_policy_template_by_id(dynamic_policy->provisioning_session_id, dynamic_policy->policy_template_id);
    if(!msaf_policy_template) return 0;

    dynamic_policy_set_enforcement_bit_rate(msaf_policy_template, dynamic_policy);

    /*

    if(!dynamic_policy->qos_specification) {
        dynamic_policy->enforcement_bit_rate = ogs_sbi_bitrate_from_string(msaf_policy_template->policy_template->qo_s_specification->max_btr_dl);
    } else {
        dynamic_policy->enforcement_bit_rate = calculate_max_bit_rate_for_enforcement(msaf_policy_template->policy_template->qo_s_specification->max_btr_dl, dynamic_policy->qos_specification->mar_bw_dl_bit_rate);
    } 
    */   
    media_comps = update_media_component(msaf_policy_template->policy_template->qo_s_specification, dynamic_policy->qos_specification, dynamic_policy->media_type?dynamic_policy->media_type: OpenAPI_media_type_VIDEO);

    if (msaf_dynamic_policy->pcf_app_session) {

        if(!pcf_session_update_app_session(msaf_dynamic_policy->pcf_app_session, media_comps)) {
            ogs_error("Unable to send dynamic policy update request to the PCF");
	    return 0;
        }

    } else {
            ogs_error("The dynamic policy has no associated App Session");
	    return 0;
    }
    update_dynamic_policy_context(msaf_dynamic_policy, dynamic_policy);

    return 1;

}

cJSON *msaf_dynamic_policy_get_json(const char *dynamic_policy_id)
{
    msaf_dynamic_policy_t *dynamic_policy = NULL;

    dynamic_policy = msaf_dynamic_policy_find_by_dynamicPolicyId(dynamic_policy_id);
    
    if(dynamic_policy)
        return msaf_api_dynamic_policy_convertResponseToJSON(dynamic_policy->DynamicPolicy);

    return NULL;
}

msaf_dynamic_policy_t *
msaf_dynamic_policy_find_by_dynamicPolicyId(const char *dynamicPolicyId)
{
    if (!msaf_self()->dynamic_policies) return NULL;
    return (msaf_dynamic_policy_t*) ogs_hash_get(msaf_self()->dynamic_policies, dynamicPolicyId, OGS_HASH_KEY_STRING);
}

void msaf_dynamic_policy_delete_by_id(const char *dynamic_policy_id, msaf_event_t *delete_event)
{
    
    msaf_dynamic_policy_t *msaf_dynamic_policy;

    if (!msaf_self()->dynamic_policies) return;


    msaf_dynamic_policy = msaf_dynamic_policy_find_by_dynamicPolicyId(dynamic_policy_id);
    if(msaf_dynamic_policy) {
        add_delete_event_metadata_to_dynamic_policy_context(msaf_dynamic_policy, delete_event);
        pcf_app_session_free(msaf_dynamic_policy->pcf_app_session);
    }
}    

void msaf_context_dynamic_policy_free(msaf_dynamic_policy_t *dynamic_policy) {
    msaf_dynamic_policy_remove(dynamic_policy);	
}


/*Private functions */

static msaf_dynamic_policy_t *msaf_dynamic_policy_init(void){

    msaf_dynamic_policy_t *dyn_policy;
    dyn_policy = ogs_calloc(1, sizeof(msaf_dynamic_policy_t));
    if(!dyn_policy) return NULL;
    return dyn_policy;


}

static void update_dynamic_policy_context(msaf_dynamic_policy_t *msaf_dynamic_policy, msaf_api_dynamic_policy_t *dynamic_policy) {
  
    cJSON *dynamic_policy_json;	
    char *dynamic_policy_to_hash;
    
    dynamic_policy_json = msaf_api_dynamic_policy_convertResponseToJSON(dynamic_policy);
    if(dynamic_policy_json) {
        dynamic_policy_to_hash = cJSON_Print(dynamic_policy_json);
        if(msaf_dynamic_policy->hash) ogs_free(msaf_dynamic_policy->hash);
        msaf_dynamic_policy->hash = calculate_hash(dynamic_policy_to_hash);
        msaf_dynamic_policy->dynamic_policy_created = time(NULL);
        if(msaf_dynamic_policy->DynamicPolicy)
            msaf_api_dynamic_policy_free(msaf_dynamic_policy->DynamicPolicy);
        msaf_dynamic_policy->DynamicPolicy = dynamic_policy;

        cJSON_Delete(dynamic_policy_json);
        cJSON_free(dynamic_policy_to_hash);

    } else {
        ogs_error("Error converting the Dynamic Policy to JSON"); 	     
    }
}

static OpenAPI_list_t *populate_media_component(msaf_api_m1_qo_s_specification_t *m1_qos, msaf_api_ip_packet_filter_set_t *flow_description, msaf_api_m5_qo_s_specification_t *requested_qos, msaf_api_media_type_e media_type) {

    OpenAPI_list_t *MediaComponentList = NULL;
    OpenAPI_map_t *MediaComponentMap = NULL;
    OpenAPI_media_component_t *MediaComponent = NULL;
    OpenAPI_list_t *media_sub_comp_list = NULL;
    char *mar_bw_dl_bit_rate = NULL;
    char *mar_bw_ul_bit_rate = NULL;

    MediaComponentList = OpenAPI_list_create();
    ogs_assert(MediaComponentList);

    if(!requested_qos) {
	if(m1_qos->max_auth_btr_dl) {   
            mar_bw_dl_bit_rate = m1_qos->max_auth_btr_dl;
	} else if(m1_qos->max_btr_dl) {   
            mar_bw_dl_bit_rate = m1_qos->max_btr_dl;
	}

	if(m1_qos->max_auth_btr_ul) {   
            mar_bw_ul_bit_rate = m1_qos->max_auth_btr_ul;
	} else if(m1_qos->max_btr_ul) {   
            mar_bw_ul_bit_rate = m1_qos->max_btr_ul;
	}

    } else {
	
	if(m1_qos->max_auth_btr_dl) {    
            mar_bw_dl_bit_rate = set_max_bit_rate_compliant_with_policy_template(m1_qos->max_auth_btr_dl, requested_qos->mar_bw_dl_bit_rate);
	} else if(m1_qos->max_btr_dl) {
            mar_bw_dl_bit_rate = set_max_bit_rate_compliant_with_policy_template(m1_qos->max_btr_dl, requested_qos->mar_bw_dl_bit_rate);
	}
	
	if(m1_qos->max_auth_btr_ul) {    
            mar_bw_ul_bit_rate = set_max_bit_rate_compliant_with_policy_template(m1_qos->max_auth_btr_ul, requested_qos->mar_bw_ul_bit_rate);
	} else if(m1_qos->max_btr_ul) {
            mar_bw_ul_bit_rate = set_max_bit_rate_compliant_with_policy_template(m1_qos->max_btr_ul, requested_qos->mar_bw_ul_bit_rate);
	}
    }

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

        if (!strcmp(flow_description->direction, "UPLINK")) {
            remote_addr = flow_description->dst_ip?flow_description->dst_ip:"any";
            remote_port = flow_description_port(flow_description->dst_port);

            ue_addr = flow_description->src_ip?flow_description->src_ip:"any";
            ue_port = flow_description_port(flow_description->dst_port);

        } else if (!strcmp(flow_description->direction, "DOWNLINK") || !strcmp(flow_description->direction, "BIDIRECTIONAL")) {

            remote_addr = flow_description->src_ip?flow_description->src_ip:"any";
            remote_port = flow_description_port(flow_description->src_port);

            ue_addr = flow_description->dst_ip?flow_description->dst_ip:"any";
            ue_port = flow_description_port(flow_description->dst_port);
        } else {
            ogs_error("Unknown flow direction %s", flow_description->direction);
            OpenAPI_list_free(MediaComponentList);
            return NULL;
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
                mar_bw_dl_bit_rate,
                mar_bw_ul_bit_rate,
                NULL , OpenAPI_flow_usage_NULL);
        ogs_assert(media_sub_comp);

        media_sub_comp_map = OpenAPI_map_create(ogs_msprintf("%d", media_sub_comp->f_num), media_sub_comp);
        ogs_assert(media_sub_comp_map);

        media_sub_comp_list = OpenAPI_list_create();
        OpenAPI_list_add(media_sub_comp_list, media_sub_comp_map);

    }

    MediaComponent = OpenAPI_media_component_create(NULL, NULL, NULL, false, 0, NULL, NULL,
            false, 0, NULL, false, 0.0, false, 0.0, NULL, OpenAPI_flow_status_NULL,
            msaf_strdup(mar_bw_dl_bit_rate), msaf_strdup(mar_bw_ul_bit_rate),
            false, 0, false, 0, NULL, NULL, 0, media_sub_comp_list, media_type,
            requested_qos?requested_qos->min_des_bw_dl_bit_rate: NULL, requested_qos?requested_qos->min_des_bw_ul_bit_rate: NULL,
            requested_qos?msaf_strdup(requested_qos->mir_bw_dl_bit_rate): NULL, requested_qos?msaf_strdup(requested_qos->mir_bw_ul_bit_rate): NULL,
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

static OpenAPI_list_t *update_media_component(msaf_api_m1_qo_s_specification_t *m1_qos, msaf_api_m5_qo_s_specification_t *requested_qos, msaf_api_media_type_e media_type) {

    OpenAPI_list_t *media_comps;
    OpenAPI_media_component_rm_t *media_comp;
    OpenAPI_map_t *media_comp_map;
    char *mar_bw_dl_bit_rate;
    char *mar_bw_ul_bit_rate;

    media_comps = OpenAPI_list_create();
    ogs_assert(media_comps);

    if(!requested_qos) {
        if(m1_qos->max_auth_btr_dl) {
            mar_bw_dl_bit_rate = m1_qos->max_auth_btr_dl;
        } else if(m1_qos->max_btr_dl) {
            mar_bw_dl_bit_rate = m1_qos->max_btr_dl;
        }

        if(m1_qos->max_auth_btr_ul) {
            mar_bw_ul_bit_rate = m1_qos->max_auth_btr_ul;
        } else if(m1_qos->max_btr_ul) {
            mar_bw_ul_bit_rate = m1_qos->max_btr_ul;
        }

    } else {

        if(m1_qos->max_auth_btr_dl) {
            mar_bw_dl_bit_rate = set_max_bit_rate_compliant_with_policy_template(m1_qos->max_auth_btr_dl, requested_qos->mar_bw_dl_bit_rate);
        } else if(m1_qos->max_btr_dl) {
            mar_bw_dl_bit_rate = set_max_bit_rate_compliant_with_policy_template(m1_qos->max_btr_dl, requested_qos->mar_bw_dl_bit_rate);
        }

        if(m1_qos->max_auth_btr_ul) {
            mar_bw_ul_bit_rate = set_max_bit_rate_compliant_with_policy_template(m1_qos->max_auth_btr_ul, requested_qos->mar_bw_ul_bit_rate);
        } else if(m1_qos->max_btr_ul) {
            mar_bw_ul_bit_rate = set_max_bit_rate_compliant_with_policy_template(m1_qos->max_btr_ul, requested_qos->mar_bw_ul_bit_rate);
        }
    }

    media_comp = OpenAPI_media_component_rm_create(NULL, NULL, NULL, NULL, NULL, false, 0,
            false, 0, NULL, false, 0.0, false, 0.0, NULL, OpenAPI_flow_status_NULL,
            msaf_strdup(mar_bw_dl_bit_rate), msaf_strdup(mar_bw_ul_bit_rate),
            false, 0, false, 0, NULL, NULL, 0, NULL, media_type,
            requested_qos?msaf_strdup(requested_qos->min_des_bw_dl_bit_rate): NULL, requested_qos?msaf_strdup(requested_qos->min_des_bw_ul_bit_rate): NULL,
            requested_qos?msaf_strdup(requested_qos->mir_bw_dl_bit_rate): NULL, requested_qos?msaf_strdup(requested_qos->mir_bw_ul_bit_rate): NULL,
            OpenAPI_preemption_capability_NULL, OpenAPI_preemption_vulnerability_NULL,
            OpenAPI_priority_sharing_indicator_NULL, OpenAPI_reserv_priority_NULL,
            NULL, NULL, false, 0, false, 0, NULL, NULL, NULL, false, 0);

    media_comp_map = OpenAPI_map_create(ogs_msprintf("%d", media_comp->med_comp_n), media_comp);
    ogs_assert(media_comp_map);
    ogs_assert(media_comp_map->key);

    OpenAPI_list_add(media_comps, media_comp_map);

    ogs_assert(media_comps->count);

    return media_comps;
}


static ue_network_identifier_t *populate_ue_connection_information(msaf_api_service_data_flow_description_t *service_data_flow_information)
{
    int rv;
    ue_network_identifier_t *ue_connection;

    ue_connection = ogs_calloc(1, sizeof(*ue_connection));
    ogs_assert(ue_connection);

    if (service_data_flow_information->domain_name) {
        ue_connection->ip_domain = msaf_strdup(service_data_flow_information->domain_name);
    } else {
        if (!strcmp(service_data_flow_information->flow_description->direction, "UPLINK")) {

            rv = ogs_getaddrinfo(&ue_connection->address, AF_UNSPEC, service_data_flow_information->flow_description->src_ip, service_data_flow_information->flow_description->src_port, 0);
        } else if (!strcmp(service_data_flow_information->flow_description->direction, "DOWNLINK") || !strcmp(service_data_flow_information->flow_description->direction, "BIDIRECTIONAL")) {
            ogs_info("%s: dst_ip", service_data_flow_information->flow_description->dst_ip);
            rv = ogs_getaddrinfo(&ue_connection->address, AF_UNSPEC, service_data_flow_information->flow_description->dst_ip, service_data_flow_information->flow_description->dst_port, 0);
        } else {
            ogs_error("Flow direction \"%s\" not implemented", service_data_flow_information->flow_description->direction);
            ue_connection_details_free(ue_connection);
            return NULL;
        }

        if (rv != OGS_OK) {
            ogs_error("getaddrinfo failed");
            ue_connection_details_free(ue_connection);
            return NULL;
        }
    }

    if (ue_connection->address == NULL) {
        ogs_error("Could not get the address for the UE connection");
        ue_connection_details_free(ue_connection);
        return NULL;
    }

    return ue_connection;
}

static char *set_max_bit_rate_compliant_with_policy_template(char *policy_template_m1_qos_bit_rate, char *m5_qos_bit_rate) {
    uint64_t qos_bit_rate_m5;
    uint64_t qos_bit_rate_m1;

    qos_bit_rate_m5 = ogs_sbi_bitrate_from_string(m5_qos_bit_rate);
    qos_bit_rate_m1 = ogs_sbi_bitrate_from_string(policy_template_m1_qos_bit_rate);
    if(qos_bit_rate_m5 > qos_bit_rate_m1)
        return policy_template_m1_qos_bit_rate;
    return m5_qos_bit_rate;    
}

static int calculate_max_bit_rate_for_enforcement(char *policy_template_m1_qos_bit_rate, char *m5_qos_bit_rate) {
    int qos_bit_rate_m5;
    int qos_bit_rate_m1;

    qos_bit_rate_m5 = ogs_sbi_bitrate_from_string(m5_qos_bit_rate);
    qos_bit_rate_m1 = ogs_sbi_bitrate_from_string(policy_template_m1_qos_bit_rate);
    if(qos_bit_rate_m5 > qos_bit_rate_m1)
        return qos_bit_rate_m1;
    return qos_bit_rate_m5;
}

static void dynamic_policy_set_enforcement_bit_rate(msaf_policy_template_node_t *msaf_policy_template, msaf_api_dynamic_policy_t *dynamic_policy)
{

    dynamic_policy->is_enforcement_bit_rate = true;
    if(!dynamic_policy->qos_specification) {
        dynamic_policy->enforcement_bit_rate = ogs_sbi_bitrate_from_string(msaf_policy_template->policy_template->qo_s_specification->max_auth_btr_dl?msaf_policy_template->policy_template->qo_s_specification->max_auth_btr_dl: msaf_policy_template->policy_template->qo_s_specification->max_btr_dl);
    } else {
        dynamic_policy->enforcement_bit_rate = calculate_max_bit_rate_for_enforcement(msaf_policy_template->policy_template->qo_s_specification->max_auth_btr_dl?msaf_policy_template->policy_template->qo_s_specification->max_auth_btr_dl: msaf_policy_template->policy_template->qo_s_specification->max_btr_dl, dynamic_policy->qos_specification->mar_bw_dl_bit_rate);
   }

}

static void create_dynamic_policy_app_session(const ogs_sockaddr_t *pcf_address, ue_network_identifier_t *ue_connection, OpenAPI_list_t *media_component, msaf_dynamic_policy_t *dynamic_policy)
{
    pcf_session_t *pcf_session =  NULL;
    int events = 0;
    ue_network_identifier_t *ue_net = NULL;

    pcf_session = msaf_pcf_session_new(pcf_address);
    
    if(!pcf_session) {
        ogs_assert(true == nf_server_send_error(dynamic_policy->metadata->create_event->h.sbi.data, 401, 0, dynamic_policy->metadata->create_event->message, "Failed to create dynamic policy.", "Unable to establish connection with the PCF." , NULL, dynamic_policy->metadata->create_event->nf_server_interface_metadata, dynamic_policy->metadata->create_event->app_meta));	    
    }

    ue_net  = copy_ue_network_connection_identifier(ue_connection);

    events = PCF_APP_SESSION_EVENT_TYPE_QOS_NOTIF | PCF_APP_SESSION_EVENT_TYPE_QOS_MONITORING | PCF_APP_SESSION_EVENT_TYPE_SUCCESSFUL_QOS_UPDATE | PCF_APP_SESSION_EVENT_TYPE_FAILED_QOS_UPDATE;

    pcf_session_create_app_session(pcf_session, ue_net, events, media_component, app_session_notification_callback, NULL, app_session_change_callback, dynamic_policy);

    ue_connection_details_free(ue_net);
}

static void retrieve_pcf_binding_and_create_dynamic_policy_app_session(ue_network_identifier_t *ue_connection, OpenAPI_list_t *media_component, msaf_dynamic_policy_t *dynamic_policy)
{
    retrieve_pcf_binding_cb_data_t *cb_data;

    cb_data = ogs_calloc(1, sizeof(retrieve_pcf_binding_cb_data_t));
    cb_data->ue_connection = copy_ue_network_connection_identifier((const ue_network_identifier_t *)ue_connection);
    cb_data->dyn_policy = dynamic_policy;
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

static void msaf_dynamic_policy_remove(msaf_dynamic_policy_t *msaf_dynamic_policy){
   
    if(!msaf_dynamic_policy) return;

    if(msaf_dynamic_policy->dynamicPolicyId) {
        ogs_free(msaf_dynamic_policy->dynamicPolicyId);
        msaf_dynamic_policy->dynamicPolicyId = NULL;
    }

    if(msaf_dynamic_policy->DynamicPolicy) msaf_api_dynamic_policy_free(msaf_dynamic_policy->DynamicPolicy);
    if(msaf_dynamic_policy->hash) ogs_free(msaf_dynamic_policy->hash);
    if(msaf_dynamic_policy->metadata){
        if(msaf_dynamic_policy->metadata->create_event) msaf_event_free(msaf_dynamic_policy->metadata->create_event);
	if(msaf_dynamic_policy->metadata->delete_event) msaf_event_free(msaf_dynamic_policy->metadata->delete_event);
        ogs_free(msaf_dynamic_policy->metadata);
    }

    ogs_free(msaf_dynamic_policy);

}

static void ue_connection_details_free(ue_network_identifier_t *ue_connection) {
    if(ue_connection->address) ogs_freeaddrinfo(ue_connection->address);
    if(ue_connection->ip_domain) ogs_free(ue_connection->ip_domain);
    ogs_free(ue_connection);

}

static bool app_session_change_callback(pcf_app_session_t *app_session, void *data){

    msaf_dynamic_policy_t *dynamic_policy;
    ogs_debug("change callback(app_session=%p, data=%p)", app_session, data);

    dynamic_policy = (msaf_dynamic_policy_t *)data;

    if(!app_session){

        if(dynamic_policy->metadata->create_event)
        {
	    ogs_assert(true == nf_server_send_error(dynamic_policy->metadata->create_event->h.sbi.data, 401, 0, dynamic_policy->metadata->create_event->message, "Failed to create dynamic policy.", "Unable to establish connection with the PCF." , NULL, dynamic_policy->metadata->create_event->nf_server_interface_metadata, dynamic_policy->metadata->create_event->app_meta));
            msaf_dynamic_policy_remove(dynamic_policy);
            return true;
        }

        msaf_dynamic_policy_delete(dynamic_policy);
        return true;
    }

    if(app_session && dynamic_policy->metadata->create_event){
        dynamic_policy->pcf_app_session = app_session;
        create_msaf_dynamic_policy_and_send_response(dynamic_policy);
        return true;
    }
    return false;
}

static void msaf_dynamic_policy_delete(msaf_dynamic_policy_t *dynamic_policy) {

    ogs_sbi_response_t *response;

    ogs_assert(dynamic_policy->metadata);

    if (dynamic_policy->metadata->delete_event) {
        response = nf_server_new_response(NULL, NULL, 0, NULL, 0, NULL, dynamic_policy->metadata->delete_event->nf_server_interface_metadata, dynamic_policy->metadata->delete_event->app_meta);
        nf_server_populate_response(response, 0, NULL, 204);
        ogs_assert(response);
        ogs_assert(true == ogs_sbi_server_send_response(dynamic_policy->metadata->delete_event->h.sbi.data, response));
    }

    msaf_dynamic_policy_hash_remove((const char *)dynamic_policy->dynamicPolicyId);
    msaf_dynamic_policy_remove(dynamic_policy);
}

static void
msaf_dynamic_policy_hash_remove(const char *dynamic_policy_id)
{
    free_ogs_hash_dynamic_policy_t fohdp = {
        dynamic_policy_id,
        msaf_self()->dynamic_policies
    };
    ogs_hash_do(free_ogs_hash_dynamic_policy, &fohdp, msaf_self()->dynamic_policies);
}


static int
free_ogs_hash_dynamic_policy(void *rec, const void *key, int klen, const void *value)
{
    free_ogs_hash_dynamic_policy_t *fohdp = (free_ogs_hash_dynamic_policy_t *)rec;
    if (!strcmp(fohdp->dynamic_policy_id, (char *)key)) {

        ogs_hash_set(fohdp->hash, key, klen, NULL);
        ogs_free((void*)key);

    }
    return 1;
}

static bool create_msaf_dynamic_policy_and_send_response(msaf_dynamic_policy_t *dyn_policy){
    ogs_uuid_t uuid;
    char id[OGS_UUID_FORMATTED_LENGTH + 1];
    ogs_sbi_response_t *response;
    cJSON *dynamic_policy = NULL;
    char *response_body;
    int response_code = 201;
    ogs_uuid_get(&uuid);
    ogs_uuid_format(id, &uuid);
    char *location;
    char *dynamic_policy_to_hash;


    if (dyn_policy->DynamicPolicy->dynamic_policy_id) {
        ogs_free(dyn_policy->DynamicPolicy->dynamic_policy_id);
        dyn_policy->DynamicPolicy->dynamic_policy_id = NULL;
    }

    dyn_policy->DynamicPolicy->dynamic_policy_id = msaf_strdup(id);
    dyn_policy->dynamicPolicyId = msaf_strdup(id);

    dyn_policy->dynamic_policy_created = time(NULL);

    dynamic_policy = msaf_api_dynamic_policy_convertResponseToJSON(dyn_policy->DynamicPolicy);
    if(dynamic_policy) {
        dynamic_policy_to_hash = cJSON_Print(dynamic_policy);
        dyn_policy->hash = calculate_hash(dynamic_policy_to_hash);
    } else {
        ogs_error("Error converting Dynamic Policy to JSON");
	ogs_free(dyn_policy->DynamicPolicy->dynamic_policy_id);
	ogs_free(dyn_policy->dynamicPolicyId);
	return 0;	
    }

    ogs_hash_set(msaf_self()->dynamic_policies, msaf_strdup(id), OGS_HASH_KEY_STRING, dyn_policy);

    location = ogs_msprintf("%s/%s", dyn_policy->metadata->create_event->message->h.uri, id);

    response = nf_server_new_response(location, "application/json", dyn_policy->dynamic_policy_created, dyn_policy->hash, msaf_self()->config.server_response_cache_control->m5_service_access_information_response_max_age, NULL,dyn_policy->metadata->create_event->nf_server_interface_metadata, dyn_policy->metadata->create_event->app_meta);

    ogs_assert(response);

  //  dynamic_policy = msaf_api_dynamic_policy_convertResponseToJSON(dyn_policy->DynamicPolicy);
    response_body= cJSON_Print(dynamic_policy);
    nf_server_populate_response(response, response_body?strlen(response_body):0, msaf_strdup(response_body), response_code);
    ogs_assert(true == ogs_sbi_server_send_response(dyn_policy->metadata->create_event->h.sbi.data, response));

    if(dyn_policy->metadata->create_event)
    {
        msaf_event_free(dyn_policy->metadata->create_event);
        dyn_policy->metadata->create_event =  NULL;

    }

    cJSON_Delete(dynamic_policy);
    cJSON_free(dynamic_policy_to_hash);
    cJSON_free(response_body);
    ogs_sbi_header_free(&response->h);
    ogs_free(location);

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
            create_dynamic_policy_app_session(pcf_address, retrieve_pcf_binding_cb_data->ue_connection, retrieve_pcf_binding_cb_data->media_component, retrieve_pcf_binding_cb_data->dyn_policy);
            retrieve_pcf_binding_cb_data_free(retrieve_pcf_binding_cb_data);
            return true;
        } else{
           // send 404 to the ue client
           char *err = NULL;
           err = ogs_msprintf("Unable to create the PCF app session.");
           ogs_error("%s", err);
           ogs_assert(true == nf_server_send_error(retrieve_pcf_binding_cb_data->dyn_policy->metadata->create_event->h.sbi.data, 404, 0,
                                   retrieve_pcf_binding_cb_data->dyn_policy->metadata->create_event->message,
                                   "PCF app session creation failed.", err, NULL,
                                   retrieve_pcf_binding_cb_data->dyn_policy->metadata->create_event->nf_server_interface_metadata,
                                   retrieve_pcf_binding_cb_data->dyn_policy->metadata->create_event->app_meta));
           ogs_free(err);

           ogs_error("unable to create the PCF app session");
           retrieve_pcf_binding_cb_data_free(retrieve_pcf_binding_cb_data);
           return false;
        }
    } else {
        char *err = NULL;
        err = ogs_msprintf("Unable to retrieve PCF Binding.");
        ogs_error("%s", err);
        ogs_assert(true == nf_server_send_error(retrieve_pcf_binding_cb_data->dyn_policy->metadata->create_event->h.sbi.data, 404, 0,
                                   retrieve_pcf_binding_cb_data->dyn_policy->metadata->create_event->message,
                                   "PCF Binding not found.", err, NULL,
                                   retrieve_pcf_binding_cb_data->dyn_policy->metadata->create_event->nf_server_interface_metadata,
                                   retrieve_pcf_binding_cb_data->dyn_policy->metadata->create_event->app_meta));
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

static void add_create_event_metadata_to_dynamic_policy_context(msaf_dynamic_policy_t *dynamic_policy, msaf_event_t *e)
{
    dynamic_policy->metadata = ogs_calloc(1, sizeof(msaf_dynamic_policy_local_metadata_t));
    dynamic_policy->metadata->create_event =  e;
}

static void add_delete_event_metadata_to_dynamic_policy_context(msaf_dynamic_policy_t *dynamic_policy, msaf_event_t *e)
{
    ogs_assert(dynamic_policy->metadata);
    dynamic_policy->metadata->delete_event =  e;
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
