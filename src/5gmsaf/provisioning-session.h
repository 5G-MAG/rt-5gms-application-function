/*
License: 5G-MAG Public License (v1.0)
Author: Dev Audsin
Copyright: (C) 2022 British Broadcasting Corporation

For full license terms please see the LICENSE file distributed with this
program. If this file is missing then the license can be retrieved from
https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
*/

#ifndef MSAF_PROVISIONING_SESSION_H
#define MSAF_PROVISIONING_SESSION_H

#include <regex.h>
#include "openapi/model/content_hosting_configuration.h"
#include "openapi/model/service_access_information_resource.h"
#include "openapi/model/provisioning_session.h"
#include "openapi/model/provisioning_session_type.h"
#include "openapi/model/rel_media_entry_point.h"
#include "openapi/model/abs_media_entry_point.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct msaf_provisioning_session_s {
    char *provisioningSessionId;
    OpenAPI_provisioning_session_type_e provisioningSessionType;
    char *aspId;
    char *externalApplicationId;
    OpenAPI_content_hosting_configuration_t *contentHostingConfiguration;
    OpenAPI_service_access_information_resource_t *serviceAccessInformation;
    time_t provisioningSessionReceived;
    char *provisioningSessionHash;
    time_t contentHostingConfigurationReceived;
    char *contentHostingConfigurationHash;
    time_t serviceAccessInformationCreated;
    char *serviceAccessInformationHash;
    ogs_hash_t *certificate_map;
    ogs_list_t application_server_states; //Type: msaf_application_server_state_ref_node_t *
    int marked_for_deletion;
} msaf_provisioning_session_t;

typedef struct msaf_application_server_state_node_s msaf_application_server_state_node_t;
typedef struct msaf_application_server_state_ref_node_s {
    ogs_lnode_t node;
    msaf_application_server_state_node_t *as_state;
} msaf_application_server_state_ref_node_t;

extern msaf_provisioning_session_t *msaf_provisioning_session_create(const char *provisioning_session_type, const char *asp_id, const char *external_app_id);
extern msaf_provisioning_session_t *msaf_provisioning_session_find_by_provisioningSessionId(const char *provisioningSessionId);
extern cJSON *msaf_provisioning_session_get_json(const char *provisioning_session_id);

extern OpenAPI_content_hosting_configuration_t *msaf_content_hosting_configuration_create(msaf_provisioning_session_t *provisioning_session);

extern int msaf_content_hosting_configuration_certificate_check(msaf_provisioning_session_t *provisioning_session);
extern int msaf_distribution_certificate_check(void);

extern ogs_hash_t *msaf_certificate_map();
extern const char *msaf_get_certificate_filename(const char *provisioning_session_id, const char *certificate_id);
extern ogs_list_t *msaf_retrieve_certificates_from_map(msaf_provisioning_session_t *provisioning_session);

extern OpenAPI_content_hosting_configuration_t *msaf_content_hosting_configuration_with_af_unique_cert_id(msaf_provisioning_session_t *provisioning_session);

extern void msaf_delete_content_hosting_configuration(const char *provisioning_session_id);

extern void msaf_delete_certificates(const char *provisioning_session_id);

extern void msaf_provisioning_session_hash_remove(const char *provisioning_session_id);

extern void msaf_provisioning_session_certificate_hash_remove(const char *provisioning_session_id, const char *certificate_id);

extern int uri_relative_check(const char *entry_point_path);

extern int
msaf_distribution_create(cJSON *content_hosting_config, msaf_provisioning_session_t *provisioning_session);

extern cJSON *msaf_get_content_hosting_configuration_by_provisioning_session_id(const char *provisioning_session_id);

extern char *enumerate_provisioning_sessions(void);

#ifdef __cplusplus
}
#endif

#endif /* MSAF_PROVISIONING_SESSION_H */
