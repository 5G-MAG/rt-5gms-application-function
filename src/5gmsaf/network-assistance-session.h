/*
License: 5G-MAG Public License (v1.0)
Author: Dev Audsin
Copyright: (C) 2023 British Broadcasting Corporation

For full license terms please see the LICENSE file distributed with this
program. If this file is missing then the license can be retrieved from
https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
*/

#ifndef MSAF_NETWORK_ASSISTANCE_SESSION_H
#define MSAF_NETWORK_ASSISTANCE_SESSION_H


#include "openapi/model/msaf_api_network_assistance_session.h"
#include "openapi/model/msaf_api_m5_qo_s_specification.h"
#include "openapi/model/msaf_api_service_data_flow_description.h"
#include "openapi/api/TS26512_M5_NetworkAssistanceAPI-info.h"
#include "server.h"
#include "bsf-service-consumer.h"
#include "pcf-service-consumer.h"
#include "policy-template.h"
#include "event.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ue_network_identifier_s ue_network_identifier_t;
typedef struct msaf_event_s msaf_event_t;

typedef struct msaf_network_assistance_session_internal_metadata_s {
    msaf_event_t *create_event;
    msaf_event_t *delivery_boost;    
} msaf_network_assistance_session_internal_metadata_t;

typedef struct msaf_network_assistance_session_s {
    ogs_lnode_t node;	
    char *naSessionId;
    msaf_network_assistance_session_internal_metadata_t *metadata;
    msaf_api_network_assistance_session_t *NetworkAssistanceSession;
    pcf_app_session_t *pcf_app_session;
    time_t na_sess_created;
    bool active_delivery_boost;
    ogs_timer_t *delivery_boost_timer;
} msaf_network_assistance_session_t;

typedef struct msaf_pcf_app_session_s {
    ogs_lnode_t node;
    pcf_app_session_t *pcf_app_session;
} msaf_pcf_app_session_t;

extern int msaf_nw_assistance_session_create(cJSON *dynamic_policy, msaf_event_t *e);
extern int msaf_nw_assistance_session_update(msaf_network_assistance_session_t *msaf_network_assistance_session, msaf_api_network_assistance_session_t *network_assistance_session);

extern msaf_network_assistance_session_t *msaf_network_assistance_session_retrieve(const char *na_session_id);

extern cJSON *msaf_network_assistance_session_get_json(const char *na_session_id);

extern void msaf_network_assistance_session_delete_by_session_id(const char *na_sess_id);

void msaf_network_assistance_session_remove_all_pcf_app_session(void);

extern ue_network_identifier_t *populate_ue_connection_details(msaf_api_service_data_flow_description_t *service_data_flow_information);

extern void msaf_network_assistance_session_remove_all(void);

extern void msaf_nw_assistance_session_delivery_boost_update(msaf_network_assistance_session_t *na_sess, msaf_event_t *e);

extern void na_session_set_active_delivery_boost(msaf_network_assistance_session_t *na_sess);

extern void msaf_nw_assistance_session_update_pcf_on_timeout(msaf_network_assistance_session_t *na_sess);


#ifdef __cplusplus
}
#endif

#endif /* MSAF_NETWORK_ASSISTANCE_SESSION_H */
