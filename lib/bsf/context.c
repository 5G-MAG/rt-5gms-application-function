/*
 * License: 5G-MAG Public License (v1.0)
 * Copyright: (C) 2022 British Broadcasting Corporation
 *
 * For full license terms please see the LICENSE file distributed with this
 * program. If this file is missing then the license can be retrieved from
 * https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
 */

#include "ogs-app.h"
#include "ogs-core.h"
#include "ogs-sbi.h"

#include "bsf-configuration.h"
#include "bsf-client-sess.h"
#include "log.h"
#include "pcf-bindings-cache.h"

#include "context.h"

#ifdef __cplusplus
extern "C" {
#endif

static bsf_client_context_t *__self = NULL;

typedef struct bsf_client_sess_node_s {
    ogs_lnode_t node;
    bsf_client_sess_t *sess;
} bsf_client_sess_node_t;

typedef int (*parse_server_add_f)(const char *hostname, int port);
typedef int (*parse_server_start_f)(ogs_list_t *ipv4_listen, ogs_list_t *ipv6_listen, ogs_sockaddr_t *addr, ogs_sockopt_t *option);

static void __bsf_client_context_init(void);
static void __parse_server_config(ogs_yaml_iter_t *iter, parse_server_add_f adder, parse_server_start_f starter);
static int  __server_add(const char *hostname, int port);
static int  __notification_listener_add(const char *hostname, int port);
static int  __notification_listener_start(ogs_list_t *ipv4_listen, ogs_list_t *ipv6_listen, ogs_sockaddr_t *addr, ogs_sockopt_t *option);
static int  __bsf_client_context_validation(void);
static bsf_client_sess_node_t *__bsf_client_context_active_sessions_find(bsf_client_sess_t *sess);
static void __active_sessions_log_debug(int indent);

/* Library Internal Public */
bool _bsf_parse_config(const char *local)
{
    yaml_document_t *document = NULL;
    ogs_yaml_iter_t root_iter;

    if (!__self) __bsf_client_context_init();
    ogs_assert(__self);

    document = ogs_app()->document;
    ogs_assert(document);

    ogs_yaml_iter_init(&root_iter, document);
    while (ogs_yaml_iter_next(&root_iter)) {
        const char *root_key = ogs_yaml_iter_key(&root_iter);
        ogs_assert(root_key);

        if (!strcmp(root_key, local)) {
            ogs_yaml_iter_t bsf_iter;
            ogs_yaml_iter_recurse(&root_iter, &bsf_iter);
            while (ogs_yaml_iter_next(&bsf_iter)) {
                const char *bsf_key = ogs_yaml_iter_key(&bsf_iter);
                ogs_assert(bsf_key);

                if (!strcmp(bsf_key, "sbi")) {
                    __parse_server_config(&bsf_iter, __server_add, NULL);
                } else if (!strcmp(bsf_key, "notificationListener")) {
                    __parse_server_config(&bsf_iter, __notification_listener_add, __notification_listener_start);
                } else if (!strcmp(bsf_key, "service_name")) {
                    /* ignore */
                } else if (!strcmp(bsf_key, "discovery")) {
                    _bsf_configuration_set_discover_flag(&__self->config, 1);
                } else {
                    ogs_warn("unknown key `%s`", bsf_key);
                }
            }
        }
    }

    return __bsf_client_context_validation();
}

void _bsf_client_context_final(void)
{
    bsf_client_sess_node_t *node, *next;

    if (!__self) return;

    ogs_debug("Finalising BSF client context");

    _bsf_configuration_clear(&__self->config);

    _pcf_bindings_cache_clear(&__self->pcf_bindings_cache);

    ogs_list_for_each_safe(&__self->active_sessions_list, next, node) {
        _bsf_client_sess_free(node->sess); /* calls _bsf_client_context_active_sessions_remove() to remove list entry */
    }

    ogs_free(__self);

    __self = NULL;
}

bsf_client_context_t *_bsf_client_self(void)
{
    return __self;
}

void _bsf_client_context_log_debug(void)
{
    ogs_debug("BSF Client Context:");

    if (!__self) {
        ogs_debug("  Context uninitialised");
        return;
    }

    ogs_debug("  Configuration:");
    _bsf_configuration_log_debug(&__self->config, 4);
    ogs_debug("  PCF Bindings Cache:");
    _pcf_bindings_cache_log_debug(__self->pcf_bindings_cache, 4);
    ogs_debug("  BSF Client Sessions:");
    __active_sessions_log_debug(4);
}

ogs_sockaddr_t *_bsf_client_context_get_bsf_address(void)
{
    if (!__self) return NULL;
    return _bsf_configuration_get_bsf_address(&__self->config);
}

OpenAPI_pcf_binding_t *_bsf_client_pcf_bindings_from_cache(ogs_sockaddr_t *ue_address)
{
    if (!__self) return NULL;

    return _pcf_bindings_cache_find(__self->pcf_bindings_cache, ue_address);
}

bool _bsf_client_context_add_pcf_binding(const ogs_sockaddr_t *ue_address, const OpenAPI_pcf_binding_t *binding, ogs_time_t expires)
{
    if (!__self) return false;

    return _pcf_bindings_cache_add(__self->pcf_bindings_cache, ue_address, binding, expires);
}

bool _bsf_client_context_active_sessions_add(bsf_client_sess_t *sess)
{
    bsf_client_sess_node_t *node;
    if (!__self) return false;
    node = ogs_calloc(1, sizeof(*node));
    node->sess = sess;
    ogs_list_add(&__self->active_sessions_list, node);
    return true;
}

bool _bsf_client_context_active_sessions_remove(bsf_client_sess_t *sess)
{
    bsf_client_sess_node_t *node;

    if (!__self) return false;
    node = __bsf_client_context_active_sessions_find(sess);
    if (!node) return false;
    ogs_list_remove(&__self->active_sessions_list, node);
    ogs_free(node);
    return true;
}

bool _bsf_client_context_active_sessions_exists(bsf_client_sess_t *sess)
{
    return __bsf_client_context_active_sessions_find(sess) != NULL;
}

/*** Private functions ***/

static void __bsf_client_context_init(void)
{
    ogs_assert(!__self);

    /* Initialise log domain */
    _log_init();

    ogs_debug("Initialising BSF client context");

    /* make initial context */
    __self = ogs_calloc(1,sizeof(bsf_client_context_t));
    ogs_assert(__self);

    /* Initialise context fields */
    _bsf_configuration_init(&__self->config);
    _pcf_bindings_cache_init(&__self->pcf_bindings_cache);
    ogs_list_init(&__self->active_sessions_list);

    ogs_debug("BSF client context initialised");
}

static void __parse_server_config(ogs_yaml_iter_t *iter, parse_server_add_f adder, parse_server_start_f starter)
{
    ogs_yaml_iter_t sbi_array;

    ogs_yaml_iter_recurse(iter, &sbi_array);
    do {
        ogs_yaml_iter_t sbi_iter;
        int i, family = AF_UNSPEC;
        int num = 0;
        const char *hostname[OGS_MAX_NUM_OF_HOSTNAME];
        int num_of_advertise = 0;
        const char *advertise[OGS_MAX_NUM_OF_HOSTNAME];
        uint16_t port = OGS_SBI_HTTP_PORT;
        ogs_sockaddr_t *addr = NULL;
        const char *dev = NULL;
        ogs_sockopt_t option;
        bool is_option = false;

        if (ogs_yaml_iter_type(&sbi_array) == YAML_MAPPING_NODE) {
            memcpy(&sbi_iter, &sbi_array, sizeof(ogs_yaml_iter_t));
        } else if (ogs_yaml_iter_type(&sbi_array) == YAML_SEQUENCE_NODE) {
            if (!ogs_yaml_iter_next(&sbi_array)) break;
            ogs_yaml_iter_recurse(&sbi_array, &sbi_iter);
        } else if (ogs_yaml_iter_type(&sbi_array) == YAML_SCALAR_NODE) {
            break;
        } else {
            ogs_assert_if_reached();
        }

        while (ogs_yaml_iter_next(&sbi_iter)) {
            const char *sbi_key = ogs_yaml_iter_key(&sbi_iter);
            ogs_assert(sbi_key);

            if (!strcmp(sbi_key, "family")) {
                const char *v = ogs_yaml_iter_value(&sbi_iter);
                if (v) family = atoi(v);
                if (family != AF_UNSPEC && family != AF_INET && family != AF_INET6) {
                    ogs_warn("Ignore family(%d) : AF_UNSPEC(%d), AF_INET(%d), AF_INET6(%d) ", family, AF_UNSPEC, AF_INET, AF_INET6);
                    family = AF_UNSPEC;
                }
            } else if (!strcmp(sbi_key, "addr") || !strcmp(sbi_key, "name")) {
                ogs_yaml_iter_t hostname_iter;

                ogs_yaml_iter_recurse(&sbi_iter, &hostname_iter);
                ogs_assert(ogs_yaml_iter_type(&hostname_iter) != YAML_MAPPING_NODE);

                do {
                    if (ogs_yaml_iter_type(&hostname_iter) == YAML_SEQUENCE_NODE && !ogs_yaml_iter_next(&hostname_iter)) break;
                    ogs_assert(num < OGS_MAX_NUM_OF_HOSTNAME);
                    hostname[num++] = ogs_yaml_iter_value(&hostname_iter);
                } while (ogs_yaml_iter_type(&hostname_iter) == YAML_SEQUENCE_NODE);
            } else if (!strcmp(sbi_key, "advertise")) {
                ogs_yaml_iter_t advertise_iter;

                ogs_yaml_iter_recurse(&sbi_iter, &advertise_iter);
                ogs_assert(ogs_yaml_iter_type(&advertise_iter) != YAML_MAPPING_NODE);

                do {
                    if (ogs_yaml_iter_type(&advertise_iter) == YAML_SEQUENCE_NODE && !ogs_yaml_iter_next(&advertise_iter)) break;
                    ogs_assert(num_of_advertise < OGS_MAX_NUM_OF_HOSTNAME);
                    advertise[num_of_advertise++] = ogs_yaml_iter_value(&advertise_iter);
                } while (ogs_yaml_iter_type(&advertise_iter) == YAML_SEQUENCE_NODE);
            } else if (!strcmp(sbi_key, "port")) {
                const char *v = ogs_yaml_iter_value(&sbi_iter);
                if (v) port = atoi(v);
            } else if (!strcmp(sbi_key, "dev")) {
                dev = ogs_yaml_iter_value(&sbi_iter);
            } else if (!strcmp(sbi_key, "option")) {
                int rv;
                rv = ogs_app_config_parse_sockopt(&sbi_iter, &option);
                if (rv != OGS_OK) return;
                is_option = true;
            } else {
                ogs_warn("unknown key `%s`", sbi_key);
            }
        }

        for (i = 0; i < num; i++) {
            int rv;

            rv = ogs_addaddrinfo(&addr, family, hostname[i], port, 0);
            ogs_assert(rv == OGS_OK);

            if (adder) adder(hostname[i], port);
        }

        if (starter) {
            ogs_list_t list, list6;

            ogs_list_init(&list);
            ogs_list_init(&list6);

            if (addr) {
                if (ogs_app()->parameter.no_ipv4 == 0)
                    ogs_socknode_add(&list, AF_INET, addr, NULL);
                if (ogs_app()->parameter.no_ipv6 == 0)
                    ogs_socknode_add(&list6, AF_INET6, addr, NULL);
            }

            if (dev) {
                int rv;

                rv = ogs_socknode_probe(ogs_app()->parameter.no_ipv4 ? NULL : &list,
                                        ogs_app()->parameter.no_ipv6 ? NULL : &list6,
                                        dev, port, NULL);
                ogs_assert(rv == OGS_OK);
            }

            if (addr) {
                ogs_freeaddrinfo(addr);
                addr = NULL;
            }

            for (i = 0; i < num_of_advertise; i++) {
                int rv;

                rv = ogs_addaddrinfo(&addr, family, advertise[i], port, 0);
                ogs_assert(rv == OGS_OK);
            }

            starter(&list, &list6, addr, is_option ? &option : NULL);

            ogs_socknode_remove_all(&list);
            ogs_socknode_remove_all(&list6);
        }

        if (addr) ogs_freeaddrinfo(addr);
    } while (ogs_yaml_iter_type(&sbi_array) == YAML_SEQUENCE_NODE);
}

static int __server_add(const char *hostname, int port)
{
    if (!__self) return OGS_ERROR;
    return _bsf_configuration_server_add(&__self->config, hostname, port);
}

static int __notification_listener_add(const char *hostname, int port)
{
    if (!__self) return OGS_ERROR;
    return _bsf_configuration_notification_listeners_add(&__self->config, hostname, port);
}

static int  __notification_listener_start(ogs_list_t *ipv4_listen, ogs_list_t *ipv6_listen, ogs_sockaddr_t *addr, ogs_sockopt_t *option)
{
    ogs_socknode_t *node;

    node = ogs_list_first(ipv4_listen);
    if (node) {
        ogs_sbi_server_t *server = ogs_sbi_server_add(node->addr, option);
        ogs_assert(server);

        if (addr && ogs_app()->parameter.no_ipv4 == 0)
            ogs_sbi_server_set_advertise(server, AF_INET, addr);
    }

    node = ogs_list_first(ipv6_listen);
    if (node) {
        ogs_sbi_server_t *server = ogs_sbi_server_add(node->addr, option);
        ogs_assert(server);

        if (addr && ogs_app()->parameter.no_ipv6 == 0)
            ogs_sbi_server_set_advertise(server, AF_INET6, addr);
    }

    return OGS_OK;
}

static int  __bsf_client_context_validation(void)
{
    if (!_bsf_configuration_notification_listeners_exist(&__self->config)) {
        ogs_error("No notification listener address");
        return OGS_ERROR;
    }

    if (!_bsf_configuration_servers_exist(&__self->config) && _bsf_configuration_get_discover_flag(&__self->config)) {
        int rv;
        ogs_sbi_xact_t *xact;
        xact = ogs_sbi_xact_add((ogs_sbi_object_t*)_bsf_client_sess_new() ,OGS_SBI_SERVICE_TYPE_NBSF_MANAGEMENT , NULL, NULL, NULL, NULL);
        if (!xact) {
            ogs_error("ogs_sbi_xact_add() failed");
            return OGS_ERROR;
        }
        rv = ogs_sbi_discover_only(xact);
        if (rv != OGS_OK) {
            ogs_error("ogs_sbi_discover_only() failed");
            return OGS_ERROR;
        }
    }

    return OGS_OK;
}

static bsf_client_sess_node_t *__bsf_client_context_active_sessions_find(bsf_client_sess_t *sess)
{
    bsf_client_sess_node_t *node;
    if (!__self) return NULL;
    ogs_list_for_each(&__self->active_sessions_list, node) {
        if (node->sess == sess) return node;
    }
    return NULL;
}

static void __active_sessions_log_debug(int indent)
{
    const char *sep = NULL;
    bsf_client_sess_node_t *node;

    if (!__self) return;

    ogs_list_for_each(&__self->active_sessions_list, node) {
        if (sep) ogs_debug(sep);
        _bsf_client_sess_log_debug(node->sess, indent);
        sep = "---------------------";
    }
}

#ifdef __cplusplus
}
#endif

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
