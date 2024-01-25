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
    char *m3Host;
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
    ogs_list_t        purge_content_hosting_cache;
} msaf_application_server_state_node_t;

typedef struct assigned_provisioning_sessions_node_s {
    ogs_lnode_t       node;
    msaf_provisioning_session_t *assigned_provisioning_session;
} assigned_provisioning_sessions_node_t;

typedef struct application_server_state_node_s {
    ogs_lnode_t       node;
    char *state;
} resource_id_node_t;

typedef struct m1_purge_information_s {
    int refs;
    int purged_entries_total;

    ogs_sbi_stream_t *m1_stream;
    ogs_sbi_message_t m1_message;
} m1_purge_information_t;

typedef struct purge_resource_id_node_s {
    ogs_lnode_t node;
    char *provisioning_session_id;
    char *purge_regex;
    m1_purge_information_t *m1_purge_info;
} purge_resource_id_node_t;

/**
 * Add a content hosting configuration to an application server
 *
 * @param as_state The application server state to add this CHC to.
 * @param provisioning_session The provisioning session of the CHC.
 */
extern int msaf_application_server_state_set(msaf_application_server_state_node_t *as_state, msaf_provisioning_session_t *provisioning_session);
extern void msaf_application_server_state_log(ogs_list_t *list, const char* list_name);
extern msaf_application_server_node_t *msaf_application_server_add(char *canonical_hostname, char *url_path_prefix_format, int m3_port, char *m3_host);
extern void msaf_application_server_remove_all(void);
extern void msaf_application_server_print_all(void);
extern void next_action_for_application_server(msaf_application_server_state_node_t *as_state);
extern int msaf_application_server_state_set_on_post( msaf_provisioning_session_t *provisioning_session);
extern void msaf_application_server_state_update( msaf_provisioning_session_t *provisioning_session);


#ifdef __cplusplus
}
#endif

#endif /* MSAF_APPLICATION_SERVER_H */
