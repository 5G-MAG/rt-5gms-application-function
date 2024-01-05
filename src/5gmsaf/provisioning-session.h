/*
License: 5G-MAG Public License (v1.0)
Author: Dev Audsin
Copyright: (C) 2022-2023 British Broadcasting Corporation

For full license terms please see the LICENSE file distributed with this
program. If this file is missing then the license can be retrieved from
https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
*/

#ifndef MSAF_PROVISIONING_SESSION_H
#define MSAF_PROVISIONING_SESSION_H

#include <regex.h>

#include "sai-cache.h"

#include "openapi/model/msaf_api_provisioning_session_type.h"
#include "openapi/model/msaf_api_policy_template.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct msaf_api_consumption_reporting_configuration_s msaf_api_consumption_reporting_configuration_t;
typedef struct msaf_api_content_hosting_configuration_s msaf_api_content_hosting_configuration_t;

typedef struct msaf_http_metadata_s {
    time_t received;
    char *hash;
} msaf_http_metadata_t;

typedef struct msaf_policy_template_node_s {
    msaf_api_policy_template_t *policy_template;
    char *hash;
    time_t last_modified;
} msaf_policy_template_node_t;

typedef struct msaf_provisioning_session_s {
    char *provisioningSessionId;
    msaf_api_provisioning_session_type_e provisioningSessionType;
    char *aspId;
    char *appId;
    msaf_api_consumption_reporting_configuration_t *consumptionReportingConfiguration;
    msaf_api_content_hosting_configuration_t *contentHostingConfiguration;
    msaf_sai_cache_t *sai_cache;
    struct {
        msaf_http_metadata_t provisioningSession;
        msaf_http_metadata_t consumptionReportingConfiguration;
        msaf_http_metadata_t contentHostingConfiguration;
    } httpMetadata;
    ogs_hash_t *certificate_map;          //Type: char* => n/a (just used as a set - external tool manages data)
    ogs_hash_t *policy_templates; /* key: policy template id, value: msaf_policy_template_node_t */
    ogs_list_t application_server_states; //Type: msaf_application_server_state_ref_node_t*
    int marked_for_deletion;
} msaf_provisioning_session_t;

typedef struct msaf_application_server_state_node_s msaf_application_server_state_node_t;

typedef void (*msaf_policy_template_state_change_callback)(msaf_provisioning_session_t *provisioning_session, msaf_policy_template_node_t *policy_template_node, msaf_api_policy_template_state_e new_state, void *user_data);

typedef struct msaf_application_server_state_ref_node_s {
    ogs_lnode_t node;
    msaf_application_server_state_node_t *as_state;
} msaf_application_server_state_ref_node_t;

typedef struct msaf_policy_template_change_state_event_data_s {
    msaf_provisioning_session_t *provisioning_session;
    msaf_policy_template_node_t *policy_template_node;
    msaf_api_policy_template_state_e new_state;
    msaf_policy_template_state_change_callback callback;
    void *callback_user_data;
} msaf_policy_template_change_state_event_data_t;

extern msaf_provisioning_session_t *msaf_provisioning_session_create(const char *provisioning_session_type, const char *asp_id, const char *external_app_id);
extern void msaf_provisioning_session_free(msaf_provisioning_session_t *provisioning_session);
extern msaf_provisioning_session_t *msaf_provisioning_session_find_by_provisioningSessionId(const char *provisioningSessionId);
extern cJSON *msaf_provisioning_session_get_json(const char *provisioning_session_id);

extern msaf_api_content_hosting_configuration_t *msaf_content_hosting_configuration_create(msaf_provisioning_session_t *provisioning_session);

extern int msaf_content_hosting_configuration_certificate_check(msaf_provisioning_session_t *provisioning_session);
extern int msaf_distribution_certificate_check(void);

extern const char *msaf_get_certificate_filename(const char *provisioning_session_id, const char *certificate_id);
extern ogs_list_t *msaf_retrieve_certificates_from_map(msaf_provisioning_session_t *provisioning_session);

extern msaf_api_content_hosting_configuration_t *msaf_content_hosting_configuration_with_af_unique_cert_id(msaf_provisioning_session_t *provisioning_session);

extern void msaf_delete_content_hosting_configuration(const char *provisioning_session_id);

extern void msaf_delete_certificates(const char *provisioning_session_id);

extern void msaf_provisioning_session_hash_remove(const char *provisioning_session_id);

extern void msaf_provisioning_session_certificate_hash_remove(const char *provisioning_session_id, const char *certificate_id);

extern int uri_relative_check(const char *entry_point_path);

extern int msaf_distribution_create(cJSON *content_hosting_config, msaf_provisioning_session_t *provisioning_session, const char **reason_ret);

extern cJSON *msaf_get_content_hosting_configuration_by_provisioning_session_id(const char *provisioning_session_id);

extern char *enumerate_provisioning_sessions(void);

extern bool msaf_provisioning_session_add_policy_template(msaf_provisioning_session_t *provisioning_session, msaf_api_policy_template_t *policy_template, time_t creation_time);

extern bool msaf_provisioning_session_delete_policy_template(msaf_provisioning_session_t *provisioning_session, msaf_policy_template_node_t *policy_template);

extern bool msaf_provisioning_session_delete_policy_template_by_id(msaf_provisioning_session_t *provisioning_session, const char *policy_template_id);

extern msaf_policy_template_node_t *msaf_provisioning_session_find_policy_template_by_id(msaf_provisioning_session_t *provisioning_session, const char *policy_template_id);

extern msaf_policy_template_node_t *msaf_provisioning_session_get_policy_template_by_id(const char *provisioning_session_id, const char *policy_template_id);

extern bool msaf_provisioning_session_send_policy_template_state_change_event(msaf_provisioning_session_t *provisioning_session,  msaf_policy_template_node_t *policy_template, msaf_api_policy_template_state_e new_state, msaf_policy_template_state_change_callback callback, void *user_data);

extern bool msaf_provisioning_session_update_policy_template(msaf_provisioning_session_t *provisioning_session, msaf_policy_template_node_t *msaf_policy_template, msaf_api_policy_template_t *policy_template);

extern void msaf_provisioning_session_policy_template_free(ogs_hash_t *policy_templates);

extern OpenAPI_list_t *msaf_provisioning_session_get_id_of_policy_templates_in_ready_state(msaf_provisioning_session_t *provisioning_session);
extern OpenAPI_list_t *msaf_provisioning_session_get_external_reference_of_policy_templates_in_ready_state(msaf_provisioning_session_t *provisioning_session);

//extern void msaf_provisioning_session_policy_template_free(ogs_hash_t *policy_templates);


#ifdef __cplusplus
}
#endif

#endif /* MSAF_PROVISIONING_SESSION_H */
