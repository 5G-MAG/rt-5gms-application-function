/*
License: 5G-MAG Public License (v1.0)
Author: Dev Audsin
Copyright: (C) 2022 British Broadcasting Corporation

For full license terms please see the LICENSE file distributed with this
program. If this file is missing then the license can be retrieved from
https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
*/

#ifndef MSAF_NETWORK_ASSISTANCE_SESSION_H
#define MSAF_NETWORK_ASSISTANCE_SESSION_H


#include "openapi/model/network_assistance_session.h"
#include "openapi/model/m5_qo_s_specification.h"
#include "openapi/model/service_data_flow_description.h"
#include "openapi/model/m5_qo_s_specification.h"
#include "openapi/api/TS26512_M5_NetworkAssistanceAPI-info.h"
#include "server.h"
#include "bsf-service-consumer.h"
#include "pcf-service-consumer.h"
#include "policy-template.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ue_network_identifier_s ue_network_identifier_t;

typedef struct msaf_network_assistance_session_s {
    ogs_lnode_t node;	
    char *naSessionId;
    OpenAPI_network_assistance_session_t *NetworkAssistanceSession;
    pcf_app_session_t *pcf_app_session;
    msaf_event_t *create_event;
    time_t na_sess_created;
} msaf_network_assistance_session_t;

typedef struct msaf_pcf_app_session_s {
    ogs_lnode_t node;
    pcf_app_session_t *pcf_app_session;
} msaf_pcf_app_session_t;


extern int msaf_nw_assistance_session_create(cJSON *network_assistance_sess, msaf_event_t *e);

extern int msaf_nw_assistance_session_delete(msaf_network_assistance_session_t *msaf_network_assistance_session, msaf_event_t *e);
extern msaf_network_assistance_session_t *msaf_network_assistance_session_retrieve(const char *na_session_id);
extern cJSON *msaf_network_assistance_session_get_json(const char *na_session_id);
extern void msaf_network_assistance_session_delete_by_session_id(const char *na_sess_id);
void msaf_network_assistance_session_remove_all_pcf_app_session(void);

extern void msaf_network_assistance_session_delete(const char *na_session_id);

extern char *enumerate_network_assistance_sessions(void);

extern ue_network_identifier_t *populate_ue_connection_details(OpenAPI_service_data_flow_description_t *service_data_flow_information);

extern void msaf_network_assistance_session_remove_all(void);

extern OpenAPI_list_t *populate_media_component(char *policy_template_id, OpenAPI_m5_qo_s_specification_t *requested_qos);

extern bool msaf_na_sess_cb(pcf_app_session_t *app_session, void *user_data);


#ifdef __cplusplus
}
#endif

#endif /* MSAF_NETWORK_ASSISTANCE_SESSION_H */
