/*
License: 5G-MAG Public License (v1.0)
Author: Dev Audsin
Copyright: (C) 2022-2023 British Broadcasting Corporation

For full license terms please see the LICENSE file distributed with this
program. If this file is missing then the license can be retrieved from
https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
*/

#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pcf-cache.h"
#include "network-assistance-session.h"
#include "policy-template.h"
#include "dynamic-policy.h"
#include "pcf-session.h"
#include "context.h"
#include "utilities.h"

static msaf_context_t *self = NULL;

int __msaf_log_domain;

typedef void (*free_ogs_hash_context_free_value_fn)(void *value);
typedef struct free_ogs_hash_context_s {
    free_ogs_hash_context_free_value_fn value_free_fn;
    ogs_hash_t *hash;
} free_ogs_hash_context_t;

static int msaf_context_prepare(void);
static int msaf_context_validation(void);
static int free_ogs_hash_entry(void *free_ogs_hash_context, const void *key, int klen, const void *value);
static void safe_ogs_free(void *memory);

static void msaf_context_application_server_state_certificates_remove_all(void);
static void msaf_context_application_server_state_content_hosting_configuration_remove_all(void);
static void msaf_context_application_server_state_assigned_provisioning_sessions_remove_all(void);
static void msaf_context_application_server_state_remove_all(void);
static void msaf_context_server_sockaddr_remove(void);
static void msaf_context_network_assistance_session_init(void);
static int check_for_network_assistance_support(void);

void msaf_context_init(void)
{
    ogs_assert(self == NULL);

    self = ogs_calloc(1, sizeof(msaf_context_t));
    ogs_assert(self);

    ogs_log_install_domain(&__msaf_log_domain, "msaf", ogs_core()->log.level);

    ogs_list_init(&self->config.applicationServers_list);

    ogs_list_init(&self->application_server_states);

    self->provisioningSessions_map = ogs_hash_make();
    ogs_assert(self->provisioningSessions_map);

    self->content_hosting_configuration_file_map = ogs_hash_make();
    ogs_assert(self->content_hosting_configuration_file_map);

    self->pcf_cache = msaf_pcf_cache_new();

    msaf_server_response_cache_control_set();
    msaf_network_assistance_delivery_boost_set();

    self->dynamic_policies = msaf_dynamic_policy_new();

}

void msaf_context_final(void)
{
    ogs_assert(self);

    if (self->provisioningSessions_map) {
        free_ogs_hash_context_t fohc = {
            (free_ogs_hash_context_free_value_fn)msaf_context_provisioning_session_free,
            self->provisioningSessions_map
        };
        ogs_hash_do(free_ogs_hash_entry, &fohc, self->provisioningSessions_map);
        ogs_hash_destroy(self->provisioningSessions_map);
    }

    if (self->content_hosting_configuration_file_map) {
        free_ogs_hash_context_t fohc = {
            safe_ogs_free,
            self->content_hosting_configuration_file_map
        };
        ogs_hash_do(free_ogs_hash_entry, &fohc, self->content_hosting_configuration_file_map);
        ogs_hash_destroy(self->content_hosting_configuration_file_map);
    }

    if (self->dynamic_policies) {
        free_ogs_hash_context_t fohc = {
            (free_ogs_hash_context_free_value_fn)msaf_context_dynamic_policy_free,
            self->dynamic_policies
        };
        ogs_hash_do(free_ogs_hash_entry, &fohc, self->dynamic_policies);
        ogs_hash_destroy(self->dynamic_policies);

    }

    if (self->config.server_response_cache_control)
    {
        ogs_free(self->config.server_response_cache_control);    
    }
 
    if (self->config.certificateManager)
        ogs_free(self->config.certificateManager);

    msaf_network_assistance_delivery_boost_free();

     if(self->config.offerNetworkAssistance){
        //msaf_na_policy_template_remove_all();
	msaf_network_assistance_session_remove_all_pcf_app_session();
        msaf_network_assistance_session_remove_all();
        msaf_pcf_session_remove_all();
	bsf_terminate();
	pcf_service_consumer_final();
	//msaf_network_assistance_session_remove_all();
	//pcf_terminate();
    }
    
    msaf_pcf_cache_free(self->pcf_cache);
 
    if (self->config.data_collection_dir)
        ogs_free(self->config.data_collection_dir);

    msaf_application_server_remove_all();

    msaf_context_application_server_state_certificates_remove_all();

    msaf_context_application_server_state_content_hosting_configuration_remove_all();

    msaf_context_application_server_state_assigned_provisioning_sessions_remove_all();

    msaf_context_application_server_state_remove_all();

    msaf_context_server_sockaddr_remove();

    ogs_free(self);
    self = NULL;
}

msaf_context_t *msaf_self(void)
{
    return self;
}

int msaf_context_parse_config(void)
{
    int rv;
    yaml_document_t *document = NULL;
    ogs_yaml_iter_t root_iter;

    document = ogs_app()->document;
    ogs_assert(document);

    rv = msaf_context_prepare();
    if (rv != OGS_OK) {
        ogs_debug("msaf_context_prepare() failed");
        return rv;
    }

    ogs_yaml_iter_init(&root_iter, document);
    while (ogs_yaml_iter_next(&root_iter)) {
        const char *root_key = ogs_yaml_iter_key(&root_iter);
        ogs_assert(root_key);
        if (!strcmp(root_key, "msaf")) {
            ogs_yaml_iter_t msaf_iter;
            ogs_yaml_iter_recurse(&root_iter, &msaf_iter);
            while (ogs_yaml_iter_next(&msaf_iter)) {
                const char *msaf_key = ogs_yaml_iter_key(&msaf_iter);
                ogs_assert(msaf_key);
                if (!strcmp(msaf_key, "open5gsIntegration")) {
		    self->config.open5gsIntegration_flag = ogs_yaml_iter_bool(&msaf_iter);
                } else if (!strcmp(msaf_key, "certificateManager")) {
                    self->config.certificateManager = msaf_strdup(ogs_yaml_iter_value(&msaf_iter));
                } else if (!strcmp(msaf_key, "applicationServers")) {
                    ogs_yaml_iter_t as_iter, as_array;
                    char *canonical_hostname = NULL;
                    char *url_path_prefix_format = NULL;
                    int m3_port = 80;
                    char *m3_host = NULL;

                    ogs_yaml_iter_recurse(&msaf_iter, &as_array);
                    if (ogs_yaml_iter_type(&as_array) == YAML_MAPPING_NODE) {
                        memcpy(&as_iter, &as_array, sizeof(ogs_yaml_iter_t));
                    } else if (ogs_yaml_iter_type(&as_array) == YAML_SEQUENCE_NODE) {
                        if (!ogs_yaml_iter_next(&as_array))
                            break;
                        ogs_yaml_iter_recurse(&as_array, &as_iter);
                    } else if (ogs_yaml_iter_type(&as_array) == YAML_SCALAR_NODE) {
                        break;
                    } else {
                        ogs_assert_if_reached();
                    }
                    while (ogs_yaml_iter_next(&as_iter)) {
                        const char *as_key = ogs_yaml_iter_key(&as_iter);
                        ogs_assert(as_key);
                        if (!strcmp(as_key, "canonicalHostname")) {
                            canonical_hostname = msaf_strdup(ogs_yaml_iter_value(&as_iter));
                        } else if (!strcmp(as_key, "urlPathPrefixFormat")) {
                            url_path_prefix_format = msaf_strdup(ogs_yaml_iter_value(&as_iter));
                        } else if (!strcmp(as_key, "m3Port")) {
                            m3_port = ascii_to_long(ogs_yaml_iter_value(&as_iter));
                        } else if (!strcmp(as_key, "m3Host")) {
                            m3_host = msaf_strdup(ogs_yaml_iter_value(&as_iter));
                        }
                    }
                    msaf_application_server_add(canonical_hostname, url_path_prefix_format, m3_port, m3_host);
                } else if (!strcmp(msaf_key, "serverResponseCacheControl")) {
                    ogs_yaml_iter_t cc_iter, cc_array;
                    ogs_yaml_iter_recurse(&msaf_iter, &cc_array);
                    if (ogs_yaml_iter_type(&cc_array) == YAML_MAPPING_NODE) {
                        memcpy(&cc_iter, &cc_array, sizeof(ogs_yaml_iter_t));
                    } else if (ogs_yaml_iter_type(&cc_array) == YAML_SEQUENCE_NODE) {
                        if (!ogs_yaml_iter_next(&cc_array))
                            break;
                        ogs_yaml_iter_recurse(&cc_array, &cc_iter);
                    } else if (ogs_yaml_iter_type(&cc_array) == YAML_SCALAR_NODE) {
                        break;
                    } else
                        ogs_assert_if_reached();

                    int m1_provisioning_session_response_max_age = SERVER_RESPONSE_MAX_AGE;
                    int m1_content_hosting_configurations_response_max_age = SERVER_RESPONSE_MAX_AGE;
                    int m1_server_certificates_response_max_age = SERVER_RESPONSE_MAX_AGE;
                    int m1_content_protocols_response_max_age = M1_CONTENT_PROTOCOLS_RESPONSE_MAX_AGE;
                    int m1_consumption_reporting_response_max_age = SERVER_RESPONSE_MAX_AGE;
                    int m5_service_access_information_response_max_age = SERVER_RESPONSE_MAX_AGE;
                    while (ogs_yaml_iter_next(&cc_iter)) {
                        const char *cc_key = ogs_yaml_iter_key(&cc_iter);
                        ogs_assert(cc_key);
                        if (!strcmp(cc_key, "m1ProvisioningSessions")) {
                            m1_provisioning_session_response_max_age = ascii_to_long(ogs_yaml_iter_value(&cc_iter));
                        } else if (!strcmp(cc_key, "m1ServerCertificates")) {
                            m1_server_certificates_response_max_age = ascii_to_long(ogs_yaml_iter_value(&cc_iter));
                        } else if (!strcmp(cc_key, "m1ContentHostingConfigurations")) {
                            m1_content_hosting_configurations_response_max_age = ascii_to_long(ogs_yaml_iter_value(&cc_iter));
                        } else if (!strcmp(cc_key, "m1ContentProtocols")) {
                            m1_content_protocols_response_max_age = ascii_to_long(ogs_yaml_iter_value(&cc_iter));
                        } else if (!strcmp(cc_key, "m1ConsumptionReportingConfiguration")) {
                            m1_consumption_reporting_response_max_age = ascii_to_long(ogs_yaml_iter_value(&cc_iter));
                        } else if (!strcmp(cc_key, "m5ServiceAccessInformation")) {
                            m5_service_access_information_response_max_age = ascii_to_long(ogs_yaml_iter_value(&cc_iter));
                        }
                    }
                    msaf_server_response_cache_control_set_from_config(
                                m1_provisioning_session_response_max_age, m1_content_hosting_configurations_response_max_age,
                                m1_server_certificates_response_max_age, m1_content_protocols_response_max_age,
                                m1_consumption_reporting_response_max_age, m5_service_access_information_response_max_age);
 
                }  else if ((!strcmp(msaf_key, "sbi") && self->config.open5gsIntegration_flag)) {

                       /* handle config in sbi library */


                }  else if (!strcmp(msaf_key, "sbi") || !strcmp(msaf_key, "m1") || !strcmp(msaf_key, "m5") || !strcmp(msaf_key, "maf")) {
                    
                    ogs_list_t list, list6;
                    ogs_socknode_t *node = NULL, *node6 = NULL;

                    ogs_yaml_iter_t sbi_array, sbi_iter;
                    ogs_yaml_iter_recurse(&msaf_iter, &sbi_array);
                    do {
                        int i, family = AF_UNSPEC;
                        int num = 0;
                        const char *hostname[OGS_MAX_NUM_OF_HOSTNAME];
                        int num_of_advertise = 0;
                        const char *advertise[OGS_MAX_NUM_OF_HOSTNAME];
                      
                        uint16_t port = 0;
                        const char *dev = NULL;
                        ogs_sockaddr_t *addr = NULL;

                        ogs_sockopt_t option;
                        bool is_option = false;

                        if (ogs_yaml_iter_type(&sbi_array) == YAML_MAPPING_NODE) {
                            memcpy(&sbi_iter, &sbi_array, sizeof(ogs_yaml_iter_t));
                        } else if (ogs_yaml_iter_type(&sbi_array) == YAML_SEQUENCE_NODE) {
                            if (!ogs_yaml_iter_next(&sbi_array))
                                break;
                            ogs_yaml_iter_recurse(&sbi_array, &sbi_iter);
                        } else if (ogs_yaml_iter_type(&sbi_array) == YAML_SCALAR_NODE) {
                            break;
                        } else
                            ogs_assert_if_reached();

                        while (ogs_yaml_iter_next(&sbi_iter)) {
                            const char *sbi_key = ogs_yaml_iter_key(&sbi_iter);
                            ogs_assert(sbi_key);
                            if (!strcmp(sbi_key, "family")) {
                                const char *v = ogs_yaml_iter_value(&sbi_iter);
                                if (v) family = atoi(v);
                                if (family != AF_UNSPEC &&
                                        family != AF_INET && family != AF_INET6) {
                                    ogs_warn("Ignore family(%d) : "
                                            "AF_UNSPEC(%d), "
                                            "AF_INET(%d), AF_INET6(%d) ",
                                            family, AF_UNSPEC, AF_INET, AF_INET6);
                                    family = AF_UNSPEC;
                                }
                            } else if (!strcmp(sbi_key, "addr") || !strcmp(sbi_key, "name")) {
                                ogs_yaml_iter_t hostname_iter;
                                ogs_yaml_iter_recurse(&sbi_iter, &hostname_iter);
                                ogs_assert(ogs_yaml_iter_type(&hostname_iter) != YAML_MAPPING_NODE);

                                do {
                                    if (ogs_yaml_iter_type(&hostname_iter) == YAML_SEQUENCE_NODE) {
                                        if (!ogs_yaml_iter_next(&hostname_iter))
                                            break;
                                    }

                                    ogs_assert(num < OGS_MAX_NUM_OF_HOSTNAME);
                                    hostname[num++] = ogs_yaml_iter_value(&hostname_iter);
                                } while (ogs_yaml_iter_type(&hostname_iter) == YAML_SEQUENCE_NODE);
                            } else if (!strcmp(sbi_key, "advertise")) {
                                ogs_yaml_iter_t advertise_iter;
                                ogs_yaml_iter_recurse(&sbi_iter, &advertise_iter);
                                ogs_assert(ogs_yaml_iter_type(&advertise_iter) != YAML_MAPPING_NODE);

                                do {
                                    if (ogs_yaml_iter_type(&advertise_iter) == YAML_SEQUENCE_NODE) {
                                        if (!ogs_yaml_iter_next(&advertise_iter))
                                            break;
                                    }

                                    ogs_assert(num_of_advertise < OGS_MAX_NUM_OF_HOSTNAME);
                                    advertise[num_of_advertise++] = ogs_yaml_iter_value(&advertise_iter);
                                } while (ogs_yaml_iter_type(&advertise_iter) == YAML_SEQUENCE_NODE);
                            } else if (!strcmp(sbi_key, "port")) {
                                const char *v = ogs_yaml_iter_value(&sbi_iter);
                                if (v)
                                    port = atoi(v);
                            } else if (!strcmp(sbi_key, "dev")) {
                                dev = ogs_yaml_iter_value(&sbi_iter);
                            } else if (!strcmp(sbi_key, "option")) {
                                rv = ogs_app_config_parse_sockopt(&sbi_iter, &option);
                                if (rv != OGS_OK) {
                                    ogs_debug("ogs_app_config_parse_sockopt() failed");
                                    return rv;
                                }
                                is_option = true;
                            } else if (!strcmp(sbi_key, "tls")) {
                                ogs_yaml_iter_t tls_iter;
                                ogs_yaml_iter_recurse(&sbi_iter, &tls_iter);

                                while (ogs_yaml_iter_next(&tls_iter)) {
                                    const char *tls_key = ogs_yaml_iter_key(&tls_iter);
                                    ogs_assert(tls_key);

                                    if (!strcmp(tls_key, "key")) {
                                        //key = ogs_yaml_iter_value(&tls_iter);
                                    } else if (!strcmp(tls_key, "pem")) {
                                        //pem = ogs_yaml_iter_value(&tls_iter);
                                    } else
                                        ogs_warn("unknown key `%s`", tls_key);
                                }
                            } else
                                ogs_warn("unknown key `%s`", sbi_key);
                        }
                        
                        if (port == 0){
                            ogs_warn("Specify the [%s] port, otherwise a random port will be used", msaf_key);
                        } 

                        addr = NULL;
                        for (i = 0; i < num; i++) {
                            rv = ogs_addaddrinfo(&addr, family, hostname[i], port, 0);
                            ogs_assert(rv == OGS_OK);
                        }

                        ogs_list_init(&list);
                        ogs_list_init(&list6);

                        if (addr) {
                            if (ogs_app()->parameter.no_ipv4 == 0)
                                ogs_socknode_add(&list, AF_INET, addr, NULL);
                            if (ogs_app()->parameter.no_ipv6 == 0)
                                ogs_socknode_add(&list6, AF_INET6, addr, NULL);
                            ogs_freeaddrinfo(addr);
                        }

                        if (dev) {
                            rv = ogs_socknode_probe(
                                    ogs_app()->parameter.no_ipv4 ? NULL : &list,
                                    ogs_app()->parameter.no_ipv6 ? NULL : &list6,
                                    dev, port, NULL);
                            ogs_assert(rv == OGS_OK);
                        }

                        addr = NULL;
                        for (i = 0; i < num_of_advertise; i++) {
                            rv = ogs_addaddrinfo(&addr,
                                    family, advertise[i], port, 0);
                            ogs_assert(rv == OGS_OK);
                        }

                        node = ogs_list_first(&list);
                        if (node) {
                            int i;
                            int matches = 0;
                            ogs_sbi_server_t *server;
                            for (i=0; i<MSAF_SVR_NUM_IFCS; i++) {
                                if (self->config.servers[i].ipv4 && ogs_sockaddr_is_equal(node->addr, self->config.servers[i].ipv4)) {
                                    server = self->config.servers[i].server_v4;
                                    matches = 1;
                                    break;
                                }
                            }
                            if(!matches) {
                                server = ogs_sbih1_server_add(
                                        node->addr, is_option ? &option : NULL);
                                ogs_assert(server);
                            
                            
                                if (addr && ogs_app()->parameter.no_ipv4 == 0)
                                    ogs_sbi_server_set_advertise(
                                            server, AF_INET, addr);
                            /*
                                if (key) server->tls.key = key;
                                if (pem) server->tls.pem = pem;
                            */
                            }
                            if (!strcmp(msaf_key, "sbi")) {
                                for (i=0; i<MSAF_SVR_NUM_IFCS; i++) {
                                    if (i == MSAF_SVR_SBI || !self->config.servers[i].ipv4) {
                                        ogs_assert(OGS_OK == ogs_copyaddrinfo(&self->config.servers[i].ipv4, server->node.addr));
                                        self->config.servers[i].server_v4 = server;
                                    }
                                }
                            } else if (!strcmp(msaf_key, "m1")) {
                                if(self->config.servers[MSAF_SVR_M1].ipv4){
                                    ogs_freeaddrinfo(self->config.servers[MSAF_SVR_M1].ipv4);
                                    self->config.servers[MSAF_SVR_M1].ipv4 = NULL;
                                }
                                ogs_assert(OGS_OK == ogs_copyaddrinfo(&self->config.servers[MSAF_SVR_M1].ipv4, server->node.addr));
                                self->config.servers[MSAF_SVR_M1].server_v4 = server;
                            } else if (!strcmp(msaf_key, "m5")) {
                                if(self->config.servers[MSAF_SVR_M5].ipv4){
                                    ogs_freeaddrinfo(self->config.servers[MSAF_SVR_M5].ipv4);
                                    self->config.servers[MSAF_SVR_M5].ipv4 = NULL;
                                }
                                ogs_assert(OGS_OK == ogs_copyaddrinfo(&self->config.servers[MSAF_SVR_M5].ipv4, server->node.addr));
                                self->config.servers[MSAF_SVR_M5].server_v4 = server;
                            } else if (!strcmp(msaf_key, "maf")) {
                                if(self->config.servers[MSAF_SVR_MSAF].ipv4){
                                    ogs_freeaddrinfo(self->config.servers[MSAF_SVR_MSAF].ipv4);
                                    self->config.servers[MSAF_SVR_MSAF].ipv4 = NULL;
                                }
                                ogs_assert(OGS_OK == ogs_copyaddrinfo(&self->config.servers[MSAF_SVR_MSAF].ipv4, server->node.addr));
                                self->config.servers[MSAF_SVR_MSAF].server_v4 = server;
                            }
                        }
                        node6 = ogs_list_first(&list6);
                        if (node6) {
                            int i;
                            int matches = 0;
                            ogs_sbi_server_t *server;
                            for (i=0; i<MSAF_SVR_NUM_IFCS; i++) {
                                if (self->config.servers[i].ipv6 && ogs_sockaddr_is_equal(node->addr, self->config.servers[i].ipv6)) {
                                    server = self->config.servers[i].server_v6;
                                    matches = 1;
                                    break;
                                }
                            }
                            if(!matches) {
                                server = ogs_sbih1_server_add(
                                        node->addr, is_option ? &option : NULL);
                                ogs_assert(server);
                            
                                if (addr && ogs_app()->parameter.no_ipv6 == 0)
                                    ogs_sbi_server_set_advertise(
                                            server, AF_INET6, addr);
                            /*
                                if (key) server->tls.key = key;
                                if (pem) server->tls.pem = pem;
                            */
                            }
                            if (!strcmp(msaf_key, "sbi")) {
                                for (i=0; i<MSAF_SVR_NUM_IFCS; i++) {
                                    if (i == MSAF_SVR_SBI || !self->config.servers[i].ipv6) {
                                        ogs_assert(OGS_OK == ogs_copyaddrinfo(&self->config.servers[i].ipv6, server->node.addr));
                                        self->config.servers[i].server_v6 = server;
                                    }
                                }
                            } else if (!strcmp(msaf_key, "m1")) {
                                if(self->config.servers[MSAF_SVR_M1].ipv6){
                                    ogs_freeaddrinfo(self->config.servers[MSAF_SVR_M1].ipv6);
                                    self->config.servers[MSAF_SVR_M1].ipv6 = NULL;
                                }
                                ogs_assert(OGS_OK == ogs_copyaddrinfo(&self->config.servers[MSAF_SVR_M1].ipv6, server->node.addr));
                                self->config.servers[MSAF_SVR_M1].server_v6 = server;
                            } else if (!strcmp(msaf_key, "m5")) {
                                if(self->config.servers[MSAF_SVR_M5].ipv6){
                                    ogs_freeaddrinfo(self->config.servers[MSAF_SVR_M5].ipv6);
                                    self->config.servers[MSAF_SVR_M5].ipv6 = NULL;
                                }
                                ogs_assert(OGS_OK == ogs_copyaddrinfo(&self->config.servers[MSAF_SVR_M5].ipv6, server->node.addr));
                                self->config.servers[MSAF_SVR_M5].server_v6 = server;
                            } else if (!strcmp(msaf_key, "maf")) {
                                if(self->config.servers[MSAF_SVR_MSAF].ipv6){
                                    ogs_freeaddrinfo(self->config.servers[MSAF_SVR_MSAF].ipv6);
                                    self->config.servers[MSAF_SVR_MSAF].ipv6 = NULL;
                                }
                                ogs_assert(OGS_OK == ogs_copyaddrinfo(&self->config.servers[MSAF_SVR_MSAF].ipv6, server->node.addr));
                                self->config.servers[MSAF_SVR_MSAF].server_v6 = server;
                            }
                        }

                        if (addr)
                            ogs_freeaddrinfo(addr);

                        ogs_socknode_remove_all(&list);
                        ogs_socknode_remove_all(&list6);

                    } while (ogs_yaml_iter_type(&sbi_array) == YAML_SEQUENCE_NODE);
                    
                    /* handle config in sbi library */
                } else if (!strcmp(msaf_key, "service_name")) {
                    /* handle config in sbi library */
                } else if (!strcmp(msaf_key, "discovery")) {
                    /* handle config in sbi library */
                } else if (!strcmp(msaf_key, "dataCollectionDir")) {
                    self->config.data_collection_dir = msaf_strdup(ogs_yaml_iter_value(&msaf_iter));
                } else if (!strcmp(msaf_key, "offerNetworkAssistance")) {
                    self->config.offerNetworkAssistance = ogs_yaml_iter_bool(&msaf_iter);
		    msaf_context_network_assistance_session_init();
                } else if (!strcmp(msaf_key, "networkAssistance")) {
                    ogs_yaml_iter_t na_iter, na_array;
                    ogs_yaml_iter_recurse(&msaf_iter, &na_array);
                    if (ogs_yaml_iter_type(&na_array) == YAML_MAPPING_NODE) {
                        memcpy(&na_iter, &na_array, sizeof(ogs_yaml_iter_t));
                    } else if (ogs_yaml_iter_type(&na_array) == YAML_SEQUENCE_NODE) {
                    if (!ogs_yaml_iter_next(&na_array))
                        break;
                    ogs_yaml_iter_recurse(&na_array, &na_iter);
                    } else if (ogs_yaml_iter_type(&na_array) == YAML_SCALAR_NODE) {
                        break;
                    } else
                    ogs_assert_if_reached();
	            
	            //int delivery_boost_min_dl_bit_rate;
	            uint64_t delivery_boost_min_dl_bit_rate;
                    int delivery_boost_period;		    

                    while (ogs_yaml_iter_next(&na_iter)) {
                        const char *na_key = ogs_yaml_iter_key(&na_iter);
                        ogs_assert(na_key);
                        if (!strcmp(na_key, "deliveryBoost")) {
		            ogs_info("deliveryBoost");
			    ogs_yaml_iter_t db_iter, db_array;
                            ogs_yaml_iter_recurse(&na_iter, &db_array);
                            if (ogs_yaml_iter_type(&db_array) == YAML_MAPPING_NODE) {
                                memcpy(&db_iter, &db_array, sizeof(ogs_yaml_iter_t));
                            } else if (ogs_yaml_iter_type(&db_array) == YAML_SEQUENCE_NODE) {
                                if (!ogs_yaml_iter_next(&db_array))
                                    break;
                                ogs_yaml_iter_recurse(&db_array, &db_iter);
                            } else if (ogs_yaml_iter_type(&db_array) == YAML_SCALAR_NODE) {
                                  break;
                            } else
                            ogs_assert_if_reached();

                            while (ogs_yaml_iter_next(&db_iter)) {
                                const char *db_key = ogs_yaml_iter_key(&db_iter);
                                ogs_assert(db_key);
                                if (!strcmp(db_key, "minDlBitRate")) {
                                    ogs_info("deliveryBoost.minDlBitRate");
				    
				    delivery_boost_min_dl_bit_rate = ogs_sbi_bitrate_from_string((char*)ogs_yaml_iter_value(&db_iter)); /* cast safe as ogs_sbi_bitrate_from_string doesn't alter the string */

				    ogs_info("delivery_boost_min_dl_bit_rate: %ld", delivery_boost_min_dl_bit_rate);
				    /*
				    delivery_boost_min_dl_bit_rate = atoi(ogs_yaml_iter_value(&db_iter));
				    ogs_info("delivery_boost_min_dl_bit_rate: %d", delivery_boost_min_dl_bit_rate);
				    */
                                }
				if (!strcmp(db_key, "boostPeriod")) {
                                    ogs_info("deliveryBoost.boostPeriod");
                                    delivery_boost_period = atoi(ogs_yaml_iter_value(&db_iter));
				    ogs_info("delivery_boost_period: %d", delivery_boost_period);
                                }

                            }
			    msaf_network_assistance_delivery_boost_set_from_config( delivery_boost_min_dl_bit_rate, delivery_boost_period);
                        }
                  }
              }
		
		else {
                    ogs_warn("unknown key `%s`", msaf_key);
                }
            }
        }
    }

    rv = check_for_network_assistance_support();
    if (rv != OGS_OK) {
        ogs_debug("check_for_network_assistance_support() failed");
        return rv;
    }

    rv = msaf_context_validation();
    if (rv != OGS_OK) {
        ogs_debug("msaf_context_validation() failed");
        return rv;
    }

    return OGS_OK;
}

const char *
msaf_context_get_content_hosting_configuration_resource_identifier(const char *content_hosting_configuration_file_name) {

    if (!self->content_hosting_configuration_file_map) return NULL;

    return (const char*)ogs_hash_get(self->content_hosting_configuration_file_map, content_hosting_configuration_file_name, OGS_HASH_KEY_STRING);
}

/***** Private functions *****/

static void msaf_context_network_assistance_session_init(void)
{
    ogs_list_init(&self->network_assistance_policy_templates);
    ogs_list_init(&self->pcf_sessions);
    ogs_list_init(&self->network_assistance_sessions);
    ogs_list_init(&self->delete_pcf_app_sessions);
}

static int check_for_network_assistance_support(void){

    if(self->config.offerNetworkAssistance && !self->config.open5gsIntegration_flag) {
        ogs_info("msaf.open5gsIntegration must be true if msaf.offerNetworkAssistance is true. For network assistance set both \"offerNetworkAssistance: true\" and \"open5gsIntegration: true\" in the configuration file");
	return OGS_ERROR;
    }

    return OGS_OK;

}

static void msaf_context_application_server_state_certificates_remove_all(void) {

    ogs_info("Removing all certificates from all Application Servers");

    msaf_application_server_state_node_t *as_state;

    ogs_list_for_each(&self->application_server_states, as_state) {

        resource_id_node_t *certificate, *next = NULL;
        resource_id_node_t *upload_certificate, *next_node = NULL;
        resource_id_node_t *delete_certificate, *node = NULL;

        ogs_debug("Removing all upload certificates");
        ogs_list_for_each_safe(&as_state->upload_certificates, next_node, upload_certificate){
            if (upload_certificate->state)
                ogs_free(upload_certificate->state);
            ogs_list_remove(&as_state->upload_certificates, upload_certificate);
            if(upload_certificate)
                ogs_free(upload_certificate);

        }

        if (as_state->current_certificates) {
            ogs_debug("Removing all current certificates");
            ogs_list_for_each_safe(as_state->current_certificates, next, certificate){
                if (certificate->state)
                    ogs_free(certificate->state);
                ogs_list_remove(as_state->current_certificates, certificate);
                if (certificate) {
                    ogs_free(certificate);
                }

            }
        }

        ogs_list_for_each_safe(&as_state->delete_certificates, node, delete_certificate){
            if (delete_certificate->state)
                ogs_free(delete_certificate->state);
            ogs_list_remove(&as_state->delete_certificates, delete_certificate);
            if (delete_certificate)
                ogs_free(delete_certificate);
        }
    }
}

static void msaf_context_application_server_state_content_hosting_configuration_remove_all(void) {

    ogs_info("Removing all Content Hosting Configurations");
    msaf_application_server_state_node_t *as_state;
    ogs_list_for_each(&self->application_server_states, as_state) {
        resource_id_node_t *content_hosting_configuration, *next = NULL;
        resource_id_node_t *upload_content_hosting_configuration = NULL;
        resource_id_node_t *delete_content_hosting_configuration, *node = NULL;

        ogs_list_for_each_safe(&as_state->upload_content_hosting_configurations, next, upload_content_hosting_configuration){
            if(upload_content_hosting_configuration->state)
                ogs_free(upload_content_hosting_configuration->state);
            ogs_list_remove(&as_state->upload_content_hosting_configurations, upload_content_hosting_configuration);
            ogs_free(upload_content_hosting_configuration);

        }

        if (as_state->current_content_hosting_configurations) {
            ogs_list_for_each_safe(as_state->current_content_hosting_configurations, next, content_hosting_configuration){
                ogs_free(content_hosting_configuration->state);
                ogs_list_remove(as_state->current_content_hosting_configurations, content_hosting_configuration);
                ogs_free(content_hosting_configuration);

            }
        }

        ogs_list_for_each_safe(&as_state->delete_content_hosting_configurations, node, delete_content_hosting_configuration){
            ogs_free(delete_content_hosting_configuration->state);
            ogs_list_remove(&as_state->delete_content_hosting_configurations, delete_content_hosting_configuration);
            ogs_free(delete_content_hosting_configuration);
        }
    }
}

static void msaf_context_application_server_state_assigned_provisioning_sessions_remove_all(void) {
    ogs_info("Removing all assigned provisioning session");
    msaf_application_server_state_node_t *as_state;
    ogs_list_for_each(&self->application_server_states, as_state) {

        assigned_provisioning_sessions_node_t *provisioning_session_resource;
        assigned_provisioning_sessions_node_t *provisioning_session_node = NULL;

        ogs_list_for_each_safe(&as_state->assigned_provisioning_sessions, provisioning_session_node, provisioning_session_resource){
            ogs_list_remove(&as_state->assigned_provisioning_sessions, provisioning_session_resource);
            ogs_free(provisioning_session_resource);

        }
    }
}

static void msaf_context_application_server_state_remove_all(void) {
    ogs_info("Removing all resources");
    msaf_application_server_state_node_t *as_state;
    msaf_application_server_state_node_t *as_state_node;

    ogs_list_for_each_safe(&self->application_server_states, as_state_node, as_state) {
        ogs_list_remove(&self->application_server_states, as_state);
        if(as_state->current_certificates)
            ogs_free(as_state->current_certificates);
        if(as_state->current_content_hosting_configurations)
            ogs_free(as_state->current_content_hosting_configurations);
        ogs_free (as_state);
    }
}

static void msaf_context_server_sockaddr_remove(void){
    int i;
    for (i=0; i<MSAF_SVR_NUM_IFCS; i++) {
        if(self->config.servers[i].ipv4) ogs_freeaddrinfo(self->config.servers[i].ipv4);
        if(self->config.servers[i].ipv6) ogs_freeaddrinfo(self->config.servers[i].ipv6);
    }
}

static int msaf_context_prepare(void)
{
    return OGS_OK;
}

static int
msaf_context_validation(void)
{
    return OGS_OK;
}

static int
free_ogs_hash_entry(void *rec, const void *key, int klen, const void *value)
{
    free_ogs_hash_context_t *fohc = (free_ogs_hash_context_t*)rec;
    fohc->value_free_fn((void*)value);
    ogs_hash_set(fohc->hash, key, klen, NULL);
    ogs_free((void*)key);
    return 1;
}

void
msaf_context_provisioning_session_free(msaf_provisioning_session_t *provisioning_session)
{
    ogs_assert(provisioning_session);

    msaf_provisioning_session_free(provisioning_session);
}

static void
safe_ogs_free(void *memory)
{
    if(memory)
        ogs_free(memory);
}

int msaf_context_server_name_set(void) {

    ogs_sbi_server_t *server = NULL;

    ogs_list_for_each(&ogs_sbi_self()->server_list, server) {
    
	ogs_sockaddr_t *advertise = NULL;
        int res = 0;

        advertise = server->advertise;
        if (!advertise)
            advertise = server->node.addr;
        ogs_assert(advertise);
        res = getnameinfo(&advertise->sa, ogs_sockaddr_len(advertise),
            self->server_name, sizeof(self->server_name),
                          NULL, 0, NI_NAMEREQD);
        if(res) {
            ogs_debug("Unable to retrieve server name: %d\n", res);
            continue;
        } else {
            ogs_debug("node=%s", self->server_name);
            return 1;
        }
    }
    return 0;
}

/* vim:ts=8:sts=4:sw=4:expandtab:
*/
