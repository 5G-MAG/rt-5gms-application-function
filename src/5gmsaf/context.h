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
#include "provisioning-session.h"
#include "application-server.h"
#include "service-access-information.h"

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
    char *mediaPlayerEntrySuffix;
    char *certificate;
    int  number_of_application_servers;
} msaf_configuration_t;

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

extern void msaf_context_init(void);
extern void msaf_context_final(void);
extern msaf_context_t *msaf_self(void);
extern int msaf_context_parse_config(void);

extern void msaf_context_provisioning_session_free(msaf_provisioning_session_t *provisioning_session);


// Functions to handle inotify Delete notifications.

extern void msaf_context_inotify_poll_add(void);
extern const char *msaf_context_get_content_hosting_configuration_resource_identifier(const char *content_hosting_configuration_file_name);
extern ogs_hash_t *msaf_context_content_hosting_configuration_file_map(char *provisioning_session_id);



#ifdef __cplusplus
}
#endif

#endif /* MSAF_CONTEXT_H */
