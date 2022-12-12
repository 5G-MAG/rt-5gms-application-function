/*
License: 5G-MAG Public License (v1.0)
Author: Dev Audsin
Copyright: (C) 2022 British Broadcasting Corporation

For full license terms please see the LICENSE file distributed with this
program. If this file is missing then the license can be retrieved from
https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
*/

#ifndef MSAF_APPLICATION_SERVER_H
#define MSAF_APPLICATION_SERVER_H

#include "provisioning-session.h"
#include "ogs-sbi.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct msaf_application_server_node_s {
    ogs_lnode_t   node;
    char *canonicalHostname;
    char *urlPathPrefixFormat;
    int   m3Port;
} msaf_application_server_node_t;

typedef struct msaf_application_server_state_node_s {
    ogs_lnode_t       node;
    ogs_sbi_client_t  *client;
    msaf_application_server_node_t *application_server;
    ogs_list_t        assigned_provisioning_sessions;
    ogs_list_t       *current_certificates;
    ogs_list_t        upload_certificates;
    ogs_list_t        delete_certificates;
    ogs_list_t       *current_content_hosting_configurations;
    ogs_list_t        upload_content_hosting_configurations;
    ogs_list_t        delete_content_hosting_configurations;
} msaf_application_server_state_node_t;

typedef struct assigned_provisioning_sessions_node_s {
    ogs_lnode_t       node;
    msaf_provisioning_session_t *assigned_provisioning_session;
} assigned_provisioning_sessions_node_t;

typedef struct application_server_state_node_s {
    ogs_lnode_t       node;
    char *state;
} resource_id_node_t;

extern void msaf_application_server_state_set( msaf_provisioning_session_t *provisioning_session, OpenAPI_content_hosting_configuration_t *contentHostingConfiguration);
extern void msaf_application_server_state_log(ogs_list_t *list, const char* list_name);
extern void application_server_state_init();
extern msaf_application_server_node_t *msaf_application_server_add(char *canonical_hostname, char *url_path_prefix_format, int m3_port);
extern void msaf_application_server_remove_all(void);
extern void msaf_application_server_print_all(void);
extern void next_action_for_application_server(msaf_application_server_state_node_t *as_state);


#ifdef __cplusplus
}
#endif

#endif /* MSAF_APPLICATION_SERVER_H */
