/*
 * License: 5G-MAG Public License (v1.0)
 * Copyright: (C) 2022 British Broadcasting Corporation
 *
 * For full license terms please see the LICENSE file distributed with this
 * program. If this file is missing then the license can be retrieved from
 * https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
 */

#ifndef BSF_CLIENT_CONFIGURATION_H
#define BSF_CLIENT_CONFIGURATION_H

#include "ogs-core.h"
#include "ogs-sbi.h"
#include "ogs-proto.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct connection_addr_s {
    ogs_lnode_t node;	
    char *addr;
    int port;
} connection_addr_t;

typedef connection_addr_t bsf_server_t;
typedef connection_addr_t bsf_client_notification_listener_t;

typedef struct bsf_configuration_s {
    ogs_list_t bsf_client_notification_listener_list; // Nodes of this list are of type bsf_client_notification_listen_t*
    ogs_list_t bsf_servers_list; // Nodes of this list are of type bsf_server_t*
    int discover_flag;
    ogs_sbi_nf_instance_t *discovered_bsf_nf_instance;
} bsf_configuration_t;

/* Library Internals */
void _bsf_configuration_init(bsf_configuration_t *config);
void _bsf_configuration_clear(bsf_configuration_t *config);

void _bsf_configuration_log_debug(bsf_configuration_t *config, int indent);

void _bsf_configuration_set_discover_flag(bsf_configuration_t *config, int flag);
int _bsf_configuration_get_discover_flag(bsf_configuration_t *config);

bool _bsf_configuration_notification_listeners_exist(bsf_configuration_t *config);
int _bsf_configuration_notification_listeners_add(bsf_configuration_t *config, const char *hostname,
                                                  int port);

int _bsf_configuration_server_add(bsf_configuration_t *config, const char *hostname, int port);
bool _bsf_configuration_servers_exist(bsf_configuration_t *config);

ogs_sockaddr_t *_bsf_configuration_get_bsf_address(bsf_configuration_t *config);

#ifdef __cplusplus
}
#endif

/* vim:ts=8:sts=4:sw=4:expandtab:
 */

#endif /* BSF_CLIENT_CONFIGURATION_H */
