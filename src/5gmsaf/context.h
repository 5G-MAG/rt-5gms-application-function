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
    char *certificate;
    int  number_of_application_servers;
} msaf_configuration_t;

typedef struct msaf_context_s {
    msaf_configuration_t config;
    ogs_hash_t  *provisioningSessions_map;
    ogs_list_t   application_server_states;
    ogs_hash_t *content_hosting_configuration_file_map;
} msaf_context_t; 

extern void msaf_context_init(void);
extern void msaf_context_final(void);
extern msaf_context_t *msaf_self(void);
extern int msaf_context_parse_config(void);

extern void msaf_context_provisioning_session_free(msaf_provisioning_session_t *provisioning_session);

#ifdef __cplusplus
}
#endif

#endif /* MSAF_CONTEXT_H */
