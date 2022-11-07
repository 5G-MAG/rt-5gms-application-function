/*
License: 5G-MAG Public License (v1.0)
Author: Dev Audsin
Copyright: (C) 2022 British Broadcasting Corporation

For full license terms please see the LICENSE file distributed with this
program. If this file is missing then the license can be retrieved from
https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
*/

#ifndef MSAF_CONTEXT_H
#define MSAF_CONTEXT_H

#include <sys/inotify.h>
#include <unistd.h>

#include "ogs-sbi.h"
#include "ogs-app.h"

#include "event.h"
#include "msaf-sm.h"

#include <stdio.h>
#include <stdlib.h>
#include "openapi/model/content_hosting_configuration.h"
#include "openapi/model/service_access_information_resource.h"

#define EVENT_SIZE  (sizeof (struct inotify_event))
#define BUF_LEN        (16 * (EVENT_SIZE + 16))

#ifdef __cplusplus
extern "C" {
#endif

extern int __msaf_log_domain;

#undef OGS_LOG_DOMAIN
#define OGS_LOG_DOMAIN __msaf_log_domain

typedef struct msaf_configuration_s {
    int open5gsIntegration_flag;
    ogs_list_t applicationServers_list;
    char *contentHostingConfiguration;
    char *provisioningSessionId;
    char *mediaPlayerEntrySuffix;
    char *certificate;
    int  number_of_application_servers;
} msaf_configuration_t;

typedef struct msaf_application_server_node_s {
    ogs_lnode_t   node;
    char *canonicalHostname;
    char *urlPathPrefixFormat;
    int   m3Port;
} msaf_application_server_node_t;

typedef struct inotify_context_s {
        char *watch_dir;
        ogs_poll_t *poll;
        ogs_socket_t fd;
        int wd;
} inotify_context_t;

typedef struct msaf_context_s {
    msaf_configuration_t config;
    ogs_hash_t  *provisioningSessions_map;
    ogs_list_t   application_server_states;
    ogs_hash_t *content_hosting_configuration_file_map;
    inotify_context_t *inotify_context; // Can be removed when M1 interface is in place
} msaf_context_t; 

typedef struct msaf_provisioning_session_s {
    char *provisioningSessionId;
    OpenAPI_content_hosting_configuration_t *contentHostingConfiguration;
    OpenAPI_service_access_information_resource_t *serviceAccessInformation;
    ogs_hash_t  *certificate_map;
} msaf_provisioning_session_t;

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

extern void msaf_context_init(void);
extern void msaf_context_final(void);
extern msaf_context_t *msaf_self(void);
extern int msaf_context_parse_config(void);

extern void next_action_for_application_server(msaf_application_server_state_node_t *as_state);
extern msaf_provisioning_session_t *msaf_context_provisioning_session_set(void);
extern int msaf_context_distribution_certificate_check(void);
extern int  msaf_context_content_hosting_configuration_certificate_check(msaf_provisioning_session_t *provisioning_session);
extern cJSON *msaf_context_retrieve_service_access_information(char *provisioning_session_id);
extern msaf_application_server_node_t *msaf_context_application_server_add(char *canonical_hostname, char *url_path_prefix_format, int m3_port);
extern void msaf_context_application_server_remove(msaf_application_server_node_t *msaf_as);
extern void msaf_context_application_server_remove_all(void);
extern void msaf_context_application_server_print_all(void);
extern void msaf_context_application_server_state_list(const char *list_name, ogs_list_t *list);
extern msaf_provisioning_session_t *msaf_context_find_provisioning_session(const char *provisioning_session_id);
extern const char *msaf_context_get_certificate_filename(const char *provisioning_session_id, const char *certificate_id);
extern const char *msaf_context_get_content_hosting_configuration_resource_identifier(const char *content_hosting_configuration_file_name);
extern void msaf_context_inotify_poll_add(void);

#ifdef __cplusplus
}
#endif

#endif /* MSAF_CONTEXT_H */
