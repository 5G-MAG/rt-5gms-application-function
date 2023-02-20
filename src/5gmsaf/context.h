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
#include <sys/socket.h>
#include <netdb.h>

#include "ogs-sbi.h"
#include "ogs-app.h"

#include "event.h"
#include "msaf-sm.h"

#include <stdio.h>
#include <stdlib.h>
#include "openapi/api/TS26512_M1_ProvisioningSessionsAPI-info.h"
#include "openapi/api/TS26512_M1_ServerCertificatesProvisioningAPI-info.h"
#include "openapi/api/TS26512_M1_ContentHostingProvisioningAPI-info.h"
#include "openapi/api/M3_ServerCertificatesProvisioningAPI-info.h"
#include "openapi/api/M3_ContentHostingProvisioningAPI-info.h"
#include "openapi/api/TS26512_M5_ServiceAccessInformationAPI-info.h"
#include "openapi/api/TS26512_M1_ContentProtocolsDiscoveryAPI-info.h"
#include "openapi/model/content_hosting_configuration.h"
#include "openapi/model/service_access_information_resource.h"
#include "provisioning-session.h"
#include "application-server-context.h"
#include "service-access-information.h"
#include "response-cache-control.h"

#ifdef __cplusplus
extern "C" {
#endif

extern int __msaf_log_domain;

#undef OGS_LOG_DOMAIN
#define OGS_LOG_DOMAIN __msaf_log_domain

typedef struct msaf_configuration_s {
    int open5gsIntegration_flag;
    ogs_list_t applicationServers_list;
    ogs_list_t server_addr_list; // Nodes for this list are of type msaf_sbi_addr_t *
    char *contentHostingConfiguration;
    char *certificate;
    char *certificateManager;
    msaf_server_response_cache_control_t *server_response_cache_control;
    int  number_of_application_servers;
} msaf_configuration_t;

typedef struct msaf_context_s {
    msaf_configuration_t config;
    ogs_hash_t  *provisioningSessions_map;
    ogs_list_t   application_server_states;
    ogs_hash_t *content_hosting_configuration_file_map;
    char server_name[NI_MAXHOST];
} msaf_context_t;

typedef struct msaf_server_addr_s {
    ogs_lnode_t node;
    const char *server_addr;
} msaf_context_server_addr_t;

extern void msaf_context_init(void);
extern void msaf_context_final(void);
extern msaf_context_t *msaf_self(void);
extern int msaf_context_parse_config(void);

extern void msaf_context_provisioning_session_free(msaf_provisioning_session_t *provisioning_session);
extern int msaf_context_server_name_set(void);

#ifdef __cplusplus
}
#endif

#endif /* MSAF_CONTEXT_H */
