/*
 * License: 5G-MAG Public License (v1.0)
 * Copyright: (C) 2022 British Broadcasting Corporation
 *
 * For full license terms please see the LICENSE file distributed with this
 * program. If this file is missing then the license can be retrieved from
 * https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
 */

#include "ogs-core.h"
#include "ogs-sbi.h"
#include "ogs-proto.h"

#include "log.h"

#include "bsf-configuration.h"

#ifdef __cplusplus
extern "C" {
#endif

static connection_addr_t *__connection_addr_new(const char *host, int port);
static void __connection_addr_free(connection_addr_t *addr);

/* Library Internals */
void _bsf_configuration_init(bsf_configuration_t *config)
{
    ogs_list_init(&config->bsf_client_notification_listener_list);
    ogs_list_init(&config->bsf_servers_list);
    config->discover_flag = 0;
    config->discovered_bsf_nf_instance = NULL;
}

void _bsf_configuration_clear(bsf_configuration_t *config)
{
    connection_addr_t *next, *node;

    ogs_list_for_each_safe(&config->bsf_client_notification_listener_list, next, node) {
        ogs_list_remove(&config->bsf_client_notification_listener_list, node);
        __connection_addr_free(node);
    }

    ogs_list_for_each_safe(&config->bsf_servers_list, next, node) {
        ogs_list_remove(&config->bsf_client_notification_listener_list, node);
        __connection_addr_free(node);
    }

    config->discovered_bsf_nf_instance = NULL;
}

void _bsf_configuration_log_debug(bsf_configuration_t *config, int indent)
{
    connection_addr_t *node;

    if (!config) return;

    ogs_debug("%*sNotification listener addresses:", indent, "");
    ogs_list_for_each(&config->bsf_client_notification_listener_list, node) {
        ogs_debug("%*s  %s:%i", indent, "", node->addr, node->port);
    }

    ogs_debug("%*sBSF Service addresses:", indent, "");
    ogs_list_for_each(&config->bsf_servers_list, node) {
        ogs_debug("%*s  %s:%i", indent, "", node->addr, node->port);
    }

    ogs_debug("%*sDiscovery flag = %i", indent, "", config->discover_flag);

    ogs_debug("%*sDiscovered NF instance = %p", indent, "", config->discovered_bsf_nf_instance);
}

void _bsf_configuration_set_discover_flag(bsf_configuration_t *config, int flag)
{
    if (!config) return;
    config->discover_flag = flag;
}

int _bsf_configuration_get_discover_flag(bsf_configuration_t *config)
{
    if (!config) return 0;
    return config->discover_flag;
}

bool _bsf_configuration_notification_listeners_exist(bsf_configuration_t *config)
{
    if (!config) return false;
    return (ogs_list_first(&config->bsf_client_notification_listener_list) != NULL);
}

int _bsf_configuration_notification_listeners_add(bsf_configuration_t *config, const char *hostname, int port)
{
    connection_addr_t *node;

    if (!config) return OGS_ERROR;

    node = __connection_addr_new(hostname, port);
    ogs_list_add(&config->bsf_client_notification_listener_list, node);

    return OGS_OK;
}

int _bsf_configuration_server_add(bsf_configuration_t *config, const char *hostname, int port)
{
    connection_addr_t *node;

    if (!config) return OGS_ERROR;

    node = __connection_addr_new(hostname, port);
    ogs_list_add(&config->bsf_servers_list, node);

    return OGS_OK;
}

bool _bsf_configuration_servers_exist(bsf_configuration_t *config)
{
    if (!config) return false;

    return ogs_list_first(&config->bsf_servers_list) != NULL;
}

ogs_sockaddr_t *_bsf_configuration_get_bsf_address(bsf_configuration_t *config)
{
    connection_addr_t *node;
    ogs_sockaddr_t *addr = NULL;

    if (!config) return NULL;

    node = ogs_list_first(&config->bsf_servers_list);
    if (node) {
        ogs_assert(ogs_addaddrinfo(&addr, AF_UNSPEC, node->addr, node->port, 0) == OGS_OK);
    } else {
        if (config->discovered_bsf_nf_instance) {
            if (config->discovered_bsf_nf_instance->num_of_ipv6 > 0 && ogs_app()->parameter.no_ipv6 == 0) {
                ogs_copyaddrinfo(&addr, config->discovered_bsf_nf_instance->ipv6[0]);
            } else if (config->discovered_bsf_nf_instance->num_of_ipv4 > 0 && ogs_app()->parameter.no_ipv4 == 0) {
                ogs_copyaddrinfo(&addr, config->discovered_bsf_nf_instance->ipv4[0]);
            }
        }
    }
    return addr;
}

/*** Private functions ***/

static connection_addr_t *__connection_addr_new(const char *host, int port)
{
    connection_addr_t *node;

    node = ogs_calloc(1, sizeof(*node));
    ogs_assert(node);

    node->addr = ogs_strdup(host);
    node->port = port;

    return node;
}

static void __connection_addr_free(connection_addr_t *addr)
{
    if (!addr) return;

    if (addr->addr) ogs_free(addr->addr);

    ogs_free(addr);
}

#ifdef __cplusplus
}
#endif

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
