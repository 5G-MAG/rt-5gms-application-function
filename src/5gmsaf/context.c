/*
License: 5G-MAG Public License (v1.0)
Author: Dev Audsin
Copyright: (C) 2022 British Broadcasting Corporation

For full license terms please see the LICENSE file distributed with this
program. If this file is missing then the license can be retrieved from
https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
*/

#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "context.h"

static msaf_context_t *self = NULL;

int __msaf_log_domain;

typedef void (*free_ogs_hash_context_free_value_fn)(void *value);
typedef struct free_ogs_hash_context_s {
    free_ogs_hash_context_free_value_fn value_free_fn;
    ogs_hash_t *hash;
} free_ogs_hash_context_t;

static OpenAPI_content_hosting_configuration_t *msaf_context_content_hosting_configuration_create(msaf_provisioning_session_t *provisioning_session);
static OpenAPI_content_hosting_configuration_t *msaf_content_hosting_configuration_with_af_unique_cert_id(msaf_provisioning_session_t *provisioning_session);
static OpenAPI_service_access_information_resource_t *msaf_context_service_access_information_create(char *media_player_entry);
static msaf_provisioning_session_t *msaf_context_provisioning_session_find_by_provisioningSessionId(char *provisioningSessionId);
static char *media_player_entry_create(const char *provisioning_session_id, OpenAPI_content_hosting_configuration_t *content_hosting_configuration);
static char *url_path_prefix_create(const char *macro, const char *session_id);
static char *read_file(const char *filename);
static int msaf_context_prepare(void);
static int msaf_context_validation(void);
static void msaf_context_display(void);
static int ogs_hash_do_cert_check(void *rec, const void *key, int klen, const void *value);
static int free_ogs_hash_entry(void *free_ogs_hash_context, const void *key, int klen, const void *value);
static void msaf_context_provisioning_session_free(msaf_provisioning_session_t *provisioning_session);
static ogs_hash_t *msaf_context_certificate_map();
static ogs_hash_t *msaf_context_content_hosting_configuration_file_map(char *provisioning_session_id);
static void msaf_context_inotify_init(void);
static void msaf_context_inotify_event(void);
static void msaf_context_delete_content_hosting_configuration(const char *resource_id);
static void msaf_context_delete_certificate(const char *resource_id);
static void safe_ogs_free(void *memory);
static char *get_path(const char *file);
static int client_notify_cb(int status, ogs_sbi_response_t *response, void *data);
/*static msaf_provisioning_session_t* ogs_hash_do_retrieve_provisioning_sessions_from_map(void *rec, const void *key, int klen, const void *value);*/
/*static msaf_provisioning_session_t *msaf_context_get_provisioning_sessions_from_map(void);*/
static ogs_sbi_client_t *msaf_m3_client_init(const char *hostname, int port);
/*static char *msaf_context_get_certificates_from_map(void);*/
/*static void ogs_hash_do_retrieve_certificates_from_map(void *rec, const void *key, int klen, const void *value);*/
static int m3_client_as_state_requests(msaf_application_server_state_node_t *as_state, const char *type, const char *data, const char *method, const char *component);
static ogs_list_t msaf_context_retrieve_certificates_from_map(msaf_provisioning_session_t *provisioning_session, OpenAPI_content_hosting_configuration_t *contentHostingConfiguration);
/*static void msaf_context_application_server_state_remove(msaf_application_server_state_node_t *msaf_as_state);*/
/*static void msaf_context_application_server_state_remove_all(void);*/
/*static void application_server_state_remove_all(ogs_list_t *app_state_list);*/
/*static void application_server_state_remove(ogs_list_t *app_state_list, resource_id_node_t *as_state);*/
static void msaf_context_application_server_state_set( msaf_provisioning_session_t *provisioning_session, OpenAPI_content_hosting_configuration_t *contentHostingConfiguration);
static void application_server_state_init(void);
static long int ascii_to_long(const char *str);

static void msaf_context_application_server_state_certificates_remove_all(void);
static void msaf_context_application_server_state_content_hosting_configuration_remove_all(void);
static void msaf_context_application_server_state_assigned_provisioning_sessions_remove_all(void);
static void msaf_context_application_server_state_remove_all(void);

/***** Public functions *****/

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
    
    msaf_context_inotify_init();
}

void msaf_context_final(void)
{
    ogs_assert(self);

    msaf_context_display();

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

    if(self->inotify_context)
        ogs_free(self->inotify_context);

    if(self->config.contentHostingConfiguration)
        ogs_free(self->config.contentHostingConfiguration);

    if(self->config.provisioningSessionId)
        ogs_free(self->config.provisioningSessionId);


    if(self->config.mediaPlayerEntrySuffix)
        ogs_free(self->config.mediaPlayerEntrySuffix);


    if(self->config.certificate)
        ogs_free(self->config.certificate);

     if(self->inotify_context->watch_dir)
	    ogs_free(self->inotify_context->watch_dir);    

    msaf_context_application_server_remove_all();

    msaf_context_application_server_state_certificates_remove_all();

    msaf_context_application_server_state_content_hosting_configuration_remove_all();

    msaf_context_application_server_state_assigned_provisioning_sessions_remove_all();

    msaf_context_application_server_state_remove_all();
    
    ogs_pollset_remove(self->inotify_context->poll);

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
    if (rv != OGS_OK) return rv;

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
                    const char *open5gs = ogs_yaml_iter_value(&msaf_iter);
                    if (!strcmp(open5gs, "true")) {
                        self->config.open5gsIntegration_flag = 1;
                    }
                } else if (!strcmp(msaf_key, "certificate")) {
                    self->config.certificate = ogs_strdup(ogs_yaml_iter_value(&msaf_iter));
                } else if (!strcmp(msaf_key, "provisioningSessionId")) {
                    self->config.provisioningSessionId = ogs_strdup(ogs_yaml_iter_value(&msaf_iter));
                } else if (!strcmp(msaf_key, "contentHostingConfiguration")) {
                    self->config.contentHostingConfiguration = ogs_strdup(ogs_yaml_iter_value(&msaf_iter));
                } else if (!strcmp(msaf_key, "mediaPlayerEntrySuffix")) {
                    self->config.mediaPlayerEntrySuffix = ogs_strdup(ogs_yaml_iter_value(&msaf_iter));
                } else if (!strcmp(msaf_key, "applicationServers")) {
                    ogs_yaml_iter_t as_iter, as_array;
                    ogs_yaml_iter_recurse(&msaf_iter, &as_array);
                    if (ogs_yaml_iter_type(&as_array) == YAML_MAPPING_NODE) {
                        memcpy(&as_iter, &as_array, sizeof(ogs_yaml_iter_t));
                    } else if (ogs_yaml_iter_type(&as_array) == YAML_SEQUENCE_NODE) {
                        if (!ogs_yaml_iter_next(&as_array))
                            break;
                        ogs_yaml_iter_recurse(&as_array, &as_iter);
                    } else if (ogs_yaml_iter_type(&as_array) == YAML_SCALAR_NODE) {
                        break;
                    } else
                        ogs_assert_if_reached();
                    char *canonical_hostname = NULL;
                    char *url_path_prefix_format = NULL;
                    int m3_port = 80;
                    while (ogs_yaml_iter_next(&as_iter)) {
                        const char *as_key = ogs_yaml_iter_key(&as_iter);
                        ogs_assert(as_key);
                        if (!strcmp(as_key, "canonicalHostname")) {
                            canonical_hostname = ogs_strdup(ogs_yaml_iter_value(&as_iter));
                        } else if (!strcmp(as_key, "urlPathPrefixFormat")) {
                            url_path_prefix_format = ogs_strdup(ogs_yaml_iter_value(&as_iter));
                        } else if (!strcmp(as_key, "m3Port")) {
                            m3_port = ascii_to_long(ogs_yaml_iter_value(&as_iter));
                        }
                    } 
                    msaf_context_application_server_add(canonical_hostname, url_path_prefix_format, m3_port);  
                } else if (!strcmp(msaf_key, "sbi")) {
                    if(!self->config.open5gsIntegration_flag) {
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
                            const char *key = NULL;
                            const char *pem = NULL;

                            //uint16_t port = self->sbi_port;

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
                                    if (rv != OGS_OK) return rv;
                                    is_option = true;
                                } else if (!strcmp(sbi_key, "tls")) {
                                    ogs_yaml_iter_t tls_iter;
                                    ogs_yaml_iter_recurse(&sbi_iter, &tls_iter);

                                    while (ogs_yaml_iter_next(&tls_iter)) {
                                        const char *tls_key = ogs_yaml_iter_key(&tls_iter);
                                        ogs_assert(tls_key);

                                        if (!strcmp(tls_key, "key")) {
                                            key = ogs_yaml_iter_value(&tls_iter);
                                        } else if (!strcmp(tls_key, "pem")) {
                                            pem = ogs_yaml_iter_value(&tls_iter);
                                        } else
                                            ogs_warn("unknown key `%s`", tls_key);
                                    }
                                } else
                                    ogs_warn("unknown key `%s`", sbi_key);
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
                                ogs_sbi_server_t *server = ogs_sbi_server_add(
                                        node->addr, is_option ? &option : NULL);
                                ogs_assert(server);

                                if (addr && ogs_app()->parameter.no_ipv4 == 0)
                                    ogs_sbi_server_set_advertise(
                                            server, AF_INET, addr);

                                if (key) server->tls.key = key;
                                if (pem) server->tls.pem = pem;
                            }
                            node6 = ogs_list_first(&list6);
                            if (node6) {
                                ogs_sbi_server_t *server = ogs_sbi_server_add(
                                        node6->addr, is_option ? &option : NULL);
                                ogs_assert(server);

                                if (addr && ogs_app()->parameter.no_ipv6 == 0)
                                    ogs_sbi_server_set_advertise(
                                            server, AF_INET6, addr);

                                if (key) server->tls.key = key;
                                if (pem) server->tls.pem = pem;
                            }

                            if (addr)
                                ogs_freeaddrinfo(addr);

                            ogs_socknode_remove_all(&list);
                            ogs_socknode_remove_all(&list6);

                        } while (ogs_yaml_iter_type(&sbi_array) == YAML_SEQUENCE_NODE);

                    }  

                    /* handle config in sbi library */
                } else if (!strcmp(msaf_key, "service_name")) {
                    /* handle config in sbi library */
                } else if (!strcmp(msaf_key, "discovery")) {
                    /* handle config in sbi library */
                } else
                    ogs_warn("unknown key `%s`", msaf_key);
            }
        }
    }

    rv = msaf_context_validation();
    if (rv != OGS_OK) return rv;

    return OGS_OK;
}


msaf_provisioning_session_t *msaf_context_provisioning_session_set(void)
{
    msaf_provisioning_session_t *msaf_provisioning_session;
    char *media_player_entry;

    msaf_provisioning_session = ogs_calloc(1, sizeof(msaf_provisioning_session_t));
    ogs_assert(msaf_provisioning_session);

    msaf_provisioning_session->provisioningSessionId = ogs_strdup(self->config.provisioningSessionId);
    msaf_provisioning_session->certificate_map = msaf_context_certificate_map();
    ogs_hash_set(self->provisioningSessions_map, ogs_strdup(self->config.provisioningSessionId), OGS_HASH_KEY_STRING, msaf_provisioning_session);

    application_server_state_init();
    msaf_context_content_hosting_configuration_file_map(msaf_provisioning_session->provisioningSessionId);

    msaf_provisioning_session->contentHostingConfiguration = msaf_context_content_hosting_configuration_create(msaf_provisioning_session);
    media_player_entry = media_player_entry_create(self->config.provisioningSessionId, msaf_provisioning_session->contentHostingConfiguration);
    ogs_assert(media_player_entry);
    msaf_provisioning_session->serviceAccessInformation = msaf_context_service_access_information_create(media_player_entry);
    return msaf_provisioning_session;
}

void next_action_for_application_server(msaf_application_server_state_node_t *as_state) {

    ogs_assert(as_state);
   
   if (as_state->current_certificates == NULL)  {
        m3_client_as_state_requests(as_state, NULL, NULL, (char *)OGS_SBI_HTTP_METHOD_GET, "certificates");
    }  else if (as_state->current_content_hosting_configurations == NULL) {
        m3_client_as_state_requests(as_state, NULL, NULL, (char *)OGS_SBI_HTTP_METHOD_GET, "content-hosting-configurations");
    } else   if (ogs_list_first(&as_state->upload_certificates) != NULL) {
        const char *upload_cert_filename;
        char *upload_cert_id;
	    char *provisioning_session;
        char *cert_id;
        char *data;
        resource_id_node_t *cert_id_node;

        resource_id_node_t *upload_cert = ogs_list_first(&as_state->upload_certificates);
        ogs_list_for_each(as_state->current_certificates, cert_id_node) {
            if (!strcmp(cert_id_node->state, upload_cert->state)) {
                break;
            }
        }
	    upload_cert_id = ogs_strdup(upload_cert->state);
        provisioning_session = strtok_r(upload_cert_id,":",&cert_id);
	    upload_cert_filename = msaf_context_get_certificate_filename(provisioning_session, cert_id);
        data = read_file(upload_cert_filename);
        const char *component = ogs_msprintf("certificates/%s:%s", provisioning_session, cert_id);

            if (cert_id_node) {
                ogs_info("M3 client: Sending PUT method to Application Server for Certificate: [%s]", upload_cert->state); 
                m3_client_as_state_requests(as_state, "application/x-pem-file", data, (char *)OGS_SBI_HTTP_METHOD_PUT, component);
                free(data);
            } else {
                    ogs_info("M3 client: Sending POST method to Application Server for Certificate: [%s]", upload_cert->state); 
                    m3_client_as_state_requests(as_state, "application/x-pem-file", data, (char *)OGS_SBI_HTTP_METHOD_POST, component);
                    free(data);
            } 
        ogs_free(component);
	    ogs_free(upload_cert_id);   

    } else if (ogs_list_first(&as_state->upload_content_hosting_configurations) !=  NULL) {
	
	    char *upload_chc_id;
        msaf_provisioning_session_t *provisioning_session;
        OpenAPI_content_hosting_configuration_t *chc_with_af_unique_cert_id;
        char *chc_id;
        char *data;
        resource_id_node_t *chc_id_node;
	    cJSON *json;

        resource_id_node_t *upload_chc = ogs_list_first(&as_state->upload_content_hosting_configurations);
        ogs_list_for_each(as_state->current_content_hosting_configurations, chc_id_node) {
            if (!strcmp(chc_id_node->state, upload_chc->state)) {
                break;
            }
        }

        provisioning_session = msaf_context_provisioning_session_find_by_provisioningSessionId(upload_chc->state);

        chc_with_af_unique_cert_id = msaf_content_hosting_configuration_with_af_unique_cert_id(provisioning_session);

	    json = OpenAPI_content_hosting_configuration_convertToJSON(chc_with_af_unique_cert_id);
        data = cJSON_Print(json);

        const char *component = ogs_msprintf("content-hosting-configurations/%s", upload_chc->state);

	    if (chc_id_node) {
            ogs_info("M3 client: Sending PUT method to Application Server for Content Hosting Configuration: [%s]", upload_chc->state); 
	        m3_client_as_state_requests(as_state, "application/json", data, (char *)OGS_SBI_HTTP_METHOD_PUT, component);
        } else {
            ogs_info("M3 client: Sending POST method to Application Server for Content Hosting Configuration:  [%s]", upload_chc->state);
            m3_client_as_state_requests(as_state, "application/json", data, (char *)OGS_SBI_HTTP_METHOD_POST, component);
        }
        if (chc_with_af_unique_cert_id) OpenAPI_content_hosting_configuration_free(chc_with_af_unique_cert_id);
        ogs_free(component);
	    cJSON_Delete(json); 

    }   else if (ogs_list_first(&as_state->delete_content_hosting_configurations) !=  NULL) {
        assigned_provisioning_sessions_node_t *provisioning_session;
        resource_id_node_t *delete_chc = ogs_list_first(&as_state->delete_content_hosting_configurations);
        ogs_info("M3 client: Sending DELETE method for Content Hosting Configuration [%s] to the Application Server", delete_chc->state);
        const char *component = ogs_msprintf("content-hosting-configurations/%s", delete_chc->state);
        m3_client_as_state_requests(as_state, NULL, NULL, (char *)OGS_SBI_HTTP_METHOD_DELETE, component);
        ogs_free(component);
    }   else if (ogs_list_first(&as_state->delete_certificates) !=  NULL) {
            resource_id_node_t *delete_cert = ogs_list_first(&as_state->delete_certificates);
            ogs_info("M3 client: Sending DELETE method for certificate [%s] to the Application Server", delete_cert->state);
            const char *component = ogs_msprintf("certificates/%s", delete_cert->state);
            m3_client_as_state_requests(as_state, NULL, NULL, (char *)OGS_SBI_HTTP_METHOD_DELETE, component);
            ogs_free(component);        
    }  

}   
int msaf_context_distribution_certificate_check(void)
{
    if (self->provisioningSessions_map) {
        return ogs_hash_do(ogs_hash_do_cert_check, NULL, self->provisioningSessions_map);
    }
    return 1;
}

int msaf_context_content_hosting_configuration_certificate_check(msaf_provisioning_session_t *provisioning_session)
{
    ogs_assert(provisioning_session);
    OpenAPI_lnode_t *dist_config_node = NULL;
    OpenAPI_distribution_configuration_t *dist_config = NULL;
    if (provisioning_session->contentHostingConfiguration && provisioning_session->certificate_map) {
        OpenAPI_list_for_each(provisioning_session->contentHostingConfiguration->distribution_configurations, dist_config_node) {
            dist_config = (OpenAPI_distribution_configuration_t*)dist_config_node->data;
            if (dist_config->certificate_id) {
                const char *cert =ogs_hash_get(provisioning_session->certificate_map, dist_config->certificate_id, OGS_HASH_KEY_STRING);
                if(cert){
                    ogs_info("Matching certificate found: %s", cert);
                } else {
                    ogs_error("No matching certificate found %s", dist_config->certificate_id);
                    return 0;
                }
                break;
            }
        } 
    }
    return 1;
}

cJSON *msaf_context_retrieve_service_access_information(char *provisioning_session_id)
{
    msaf_provisioning_session_t *provisioning_session_context = NULL;
    provisioning_session_context = msaf_context_provisioning_session_find_by_provisioningSessionId(provisioning_session_id);
    if (provisioning_session_context == NULL){
        return NULL;
    }
    cJSON *service_access_information = OpenAPI_service_access_information_resource_convertToJSON(provisioning_session_context->serviceAccessInformation);
    return service_access_information;
}

msaf_application_server_node_t *
msaf_context_application_server_add(char *canonical_hostname, char *url_path_prefix_format, int m3_port)
{
    msaf_application_server_node_t *msaf_as = NULL;

    msaf_as = ogs_calloc(1, sizeof(msaf_application_server_node_t));
    ogs_assert(msaf_as);

    msaf_as->canonicalHostname = canonical_hostname;
    msaf_as->urlPathPrefixFormat = url_path_prefix_format;
    msaf_as->m3Port = m3_port;
    ogs_list_add(&self->config.applicationServers_list, msaf_as);

    return msaf_as;
}


void msaf_context_application_server_remove(msaf_application_server_node_t *msaf_as)
{
    ogs_assert(msaf_as);
    ogs_list_remove(&self->config.applicationServers_list, msaf_as);
    if (msaf_as->canonicalHostname) ogs_free(msaf_as->canonicalHostname);
    if (msaf_as->urlPathPrefixFormat) ogs_free(msaf_as->urlPathPrefixFormat);
    ogs_free(msaf_as);
}

void msaf_context_application_server_remove_all()
{
    msaf_application_server_node_t *msaf_as = NULL, *next = NULL;

    ogs_list_for_each_safe(&self->config.applicationServers_list, next, msaf_as)
        msaf_context_application_server_remove(msaf_as);
}

#if 0
void application_server_state_remove(ogs_list_t *app_state_list, resource_id_node_t *as_state)
{
    ogs_assert(as_state);
    ogs_list_remove(app_state_list, as_state);
    if (as_state->state) ogs_free(as_state->state);
    ogs_free(as_state);
}
#endif

void msaf_context_application_server_print_all()
{
    msaf_application_server_node_t *msaf_as = NULL, *next = NULL;;

    ogs_list_for_each_safe(&self->config.applicationServers_list, next, msaf_as)
        ogs_info("AS %s %s", msaf_as->canonicalHostname, msaf_as->urlPathPrefixFormat);
}

msaf_provisioning_session_t *
msaf_context_find_provisioning_session(const char *provisioning_session_id)
{
    msaf_provisioning_session_t *prov_sess;

    if (!self->provisioningSessions_map) return NULL;

    prov_sess = (msaf_provisioning_session_t*)ogs_hash_get(self->provisioningSessions_map, provisioning_session_id, OGS_HASH_KEY_STRING);

    return prov_sess;
}

const char *
msaf_context_get_content_hosting_configuration_resource_identifier(const char *content_hosting_configuration_file_name) {

    if (!self->content_hosting_configuration_file_map) return NULL;

    return (const char*)ogs_hash_get(self->content_hosting_configuration_file_map, content_hosting_configuration_file_name, OGS_HASH_KEY_STRING);
}

const char *
msaf_context_get_certificate_filename(const char *provisioning_session_id, const char *certificate_id)
{
    msaf_provisioning_session_t *provisioning_session;

    provisioning_session = msaf_context_find_provisioning_session(provisioning_session_id);
    ogs_assert(provisioning_session);

    if (provisioning_session->certificate_map == NULL) return NULL;

    return (const char*)ogs_hash_get(provisioning_session->certificate_map, certificate_id, OGS_HASH_KEY_STRING);
}

void msaf_context_inotify_poll_add(void){

	self->inotify_context->fd = inotify_init1(IN_NONBLOCK);
    self->inotify_context->watch_dir = get_path(self->config.contentHostingConfiguration);
	if (self->inotify_context->fd < 0){
		ogs_error("inotify_init() call failed");
	}
	else {
        self->inotify_context->wd = inotify_add_watch(self->inotify_context->fd, self->inotify_context->watch_dir,  IN_DELETE);
		if (self->inotify_context->wd < 0) {
			ogs_error("inotify_add_watch() call failed");
		}	
		self->inotify_context->poll = ogs_pollset_add(ogs_app()->pollset, OGS_POLLIN, self->inotify_context->fd, msaf_context_inotify_event, NULL);
		}
}



/***** Private functions *****/

static ogs_list_t  
msaf_context_retrieve_certificates_from_map(msaf_provisioning_session_t *provisioning_session, OpenAPI_content_hosting_configuration_t *contentHostingConfiguration)
{

    ogs_list_t certs;
    resource_id_node_t *certificate = NULL;
    OpenAPI_lnode_t *dist_config_node = NULL;
    OpenAPI_distribution_configuration_t *dist_config = NULL;

    ogs_assert(provisioning_session);

    ogs_list_init(&certs);
    if (contentHostingConfiguration && provisioning_session->certificate_map) {
       	    OpenAPI_list_for_each(contentHostingConfiguration->distribution_configurations, dist_config_node) {
            dist_config = (OpenAPI_distribution_configuration_t*)dist_config_node->data;
            if (dist_config->certificate_id) {
                const char *cert = ogs_hash_get(provisioning_session->certificate_map, dist_config->certificate_id, OGS_HASH_KEY_STRING);
                if(cert){
                    certificate = ogs_calloc(1, sizeof(resource_id_node_t));
                    ogs_assert(certificate);
		    char *provisioning_session_id_plus_cert_id = ogs_msprintf("%s:%s", provisioning_session->provisioningSessionId, dist_config->certificate_id);
                    certificate->state = provisioning_session_id_plus_cert_id;
                    ogs_list_add(&certs, certificate);
                } else {
		        resource_id_node_t *next;
                        ogs_list_for_each_safe(&certs, next, certificate) {
                        ogs_list_remove(&certs, certificate);
                        if (certificate->state) ogs_free(certificate->state);
                        ogs_free(certificate);
                    }
                }
                break;
            }
        }
    }
    ogs_assert(&certs);
    return certs;
}

static void
msaf_context_application_server_state_set( msaf_provisioning_session_t *provisioning_session, OpenAPI_content_hosting_configuration_t *contentHostingConfiguration)
{
    msaf_application_server_node_t *msaf_as;
    msaf_application_server_state_node_t *as_state;
    resource_id_node_t *chc;
    assigned_provisioning_sessions_node_t *assigned_provisioning_sessions;
    ogs_list_t certs;

    msaf_as = ogs_list_first(&self->config.applicationServers_list); 
    ogs_assert(msaf_as);
    ogs_list_for_each(&self->application_server_states, as_state){
        if(!strcmp(as_state->application_server->canonicalHostname, msaf_as->canonicalHostname)) {

            certs = msaf_context_retrieve_certificates_from_map(provisioning_session, contentHostingConfiguration);	
            ogs_list_copy(&as_state->upload_certificates, &certs);	
            chc = ogs_calloc(1, sizeof(resource_id_node_t)); 
            ogs_assert(chc);
            chc->state = ogs_strdup(provisioning_session->provisioningSessionId);
            ogs_list_add(&as_state->upload_content_hosting_configurations, chc);
            assigned_provisioning_sessions = ogs_calloc(1, sizeof(assigned_provisioning_sessions_node_t));
            ogs_assert(assigned_provisioning_sessions);
            assigned_provisioning_sessions->assigned_provisioning_session = provisioning_session;
            assigned_provisioning_sessions->assigned_provisioning_session->contentHostingConfiguration = contentHostingConfiguration;
            ogs_list_add(&as_state->assigned_provisioning_sessions, assigned_provisioning_sessions);
           
#if 0
	    as_state->current_content_hosting_configurations  = ogs_calloc(1, sizeof(resource_id_node_t));
            ogs_assert(as_state->current_content_hosting_configurations);
            ogs_list_init(as_state->current_content_hosting_configurations);
            ogs_list_copy(as_state->current_content_hosting_configurations, &as_state->upload_content_hosting_configurations);

	    as_state->current_certificates  = ogs_calloc(1, sizeof(resource_id_node_t));
            ogs_assert(as_state->current_certificates);
            ogs_list_init(as_state->current_certificates);
            ogs_list_copy(as_state->current_certificates, &as_state->upload_certificates);
            
	    ogs_list_init(&as_state->delete_certificates);
            ogs_list_copy(&as_state->delete_certificates, as_state->current_certificates);
            ogs_list_copy(&as_state->delete_content_hosting_configurations, as_state->current_content_hosting_configurations);


#endif
	    next_action_for_application_server(as_state);
        break;
        }	
    }
   

}

static void msaf_context_inotify_event(){
	char buf[BUF_LEN];
        int len;
	len = read(self->inotify_context->fd, buf, BUF_LEN);

    if (len > 0)
    {
        int i = 0;
        while (i < len)
        {
            struct inotify_event *event;
            event = (struct inotify_event *) &buf[i];
            if (event->mask & IN_DELETE) {
                const char *chc= ogs_msprintf("%s/%s", self->inotify_context->watch_dir, event->name);
                const char *resource_id = msaf_context_get_content_hosting_configuration_resource_identifier((const char *)chc);
                msaf_context_delete_content_hosting_configuration(resource_id);
                msaf_context_delete_certificate(resource_id);
                ogs_free(chc);
            }
            i += EVENT_SIZE + event->len;
        }
    }
}

static void msaf_context_delete_certificate(const char *resource_id) {
 
    msaf_application_server_state_node_t *as_state;
    ogs_list_for_each(&self->application_server_states, as_state) {
        resource_id_node_t *certificate, *next = NULL;
        resource_id_node_t *upload_certificate, *next_node = NULL;
        resource_id_node_t *delete_certificate, *node = NULL;
	    ogs_list_init(&as_state->delete_certificates);

        if (as_state->current_certificates) {
            
            char *current_cert_id;
            char *provisioning_session;
            char *cert_id;
            
            ogs_list_for_each_safe(as_state->current_certificates, next, certificate){
                
                current_cert_id = ogs_strdup(certificate->state);
                provisioning_session = strtok_r(current_cert_id,":",&cert_id);
                
                if(!strcmp(provisioning_session, resource_id))
                    break;
                }
                
                if(certificate) {
                    
                    ogs_list_add(&as_state->delete_certificates, certificate);
                }
                
                if(current_cert_id)
                ogs_free(current_cert_id);
            }

        if(&as_state->upload_certificates) {
            
            char *upload_cert_id = NULL;
            char *provisioning_session;
            char *cert_id;
        
            ogs_list_for_each_safe(&as_state->upload_certificates, next_node, upload_certificate){
                
                upload_cert_id = ogs_strdup(upload_certificate->state);
                provisioning_session = strtok_r(upload_cert_id,":",&cert_id);
                if(!strcmp(provisioning_session, resource_id))
                    break;
            }
            
            if(upload_certificate) {
        
                ogs_list_remove(&as_state->upload_certificates, upload_certificate);
                
                ogs_list_add(&as_state->delete_certificates, upload_certificate);
                
            }
            
            if(upload_cert_id)
                ogs_free(upload_cert_id);
        }
        
        //next_action_for_application_server(as_state);

    }	 
}

static OpenAPI_content_hosting_configuration_t *
msaf_content_hosting_configuration_with_af_unique_cert_id(msaf_provisioning_session_t *provisioning_session)
{

    ogs_assert(provisioning_session);
    OpenAPI_content_hosting_configuration_t *chc_with_af_unique_cert_id = NULL;
    OpenAPI_lnode_t *dist_config_node = NULL;
    OpenAPI_distribution_configuration_t *dist_config = NULL;
    char *af_unique_cert_id;
    chc_with_af_unique_cert_id = OpenAPI_content_hosting_configuration_copy(chc_with_af_unique_cert_id, provisioning_session->contentHostingConfiguration);
    if (chc_with_af_unique_cert_id) {

       OpenAPI_list_for_each(chc_with_af_unique_cert_id->distribution_configurations, dist_config_node) {
           dist_config = (OpenAPI_distribution_configuration_t*)dist_config_node->data;
           if (dist_config->certificate_id) {
              af_unique_cert_id = ogs_msprintf("%s:%s", provisioning_session->provisioningSessionId, dist_config->certificate_id);
              ogs_free(dist_config->certificate_id);
              dist_config->certificate_id = af_unique_cert_id;
            }
       }
    }
    return chc_with_af_unique_cert_id;
}


static void msaf_context_delete_content_hosting_configuration(const char *resource_id) {
    
    msaf_application_server_state_node_t *as_state;
    ogs_list_for_each(&self->application_server_states, as_state) {

        resource_id_node_t *content_hosting_configuration, *next = NULL;
        resource_id_node_t *upload_content_hosting_configuration, *next_node = NULL;
        resource_id_node_t *delete_content_hosting_configuration, *node = NULL;

        ogs_list_init(&as_state->delete_content_hosting_configurations);

        if (as_state->current_content_hosting_configurations) {

            ogs_list_for_each_safe(as_state->current_content_hosting_configurations, next, content_hosting_configuration){

                if(!strcmp(content_hosting_configuration->state, resource_id))
                    break;
            }
            if(content_hosting_configuration) {
               
                ogs_list_add(&as_state->delete_content_hosting_configurations, content_hosting_configuration);

            }
        }

        if(&as_state->upload_content_hosting_configurations) {

            ogs_list_for_each_safe(&as_state->upload_content_hosting_configurations, next_node, upload_content_hosting_configuration){
                if(!strcmp(upload_content_hosting_configuration->state, resource_id))
                    break;
            }
            if(upload_content_hosting_configuration) {
               
                ogs_list_remove(&as_state->upload_content_hosting_configurations, upload_content_hosting_configuration);

                ogs_list_add(&as_state->delete_content_hosting_configurations, upload_content_hosting_configuration);

            }
        }

	    next_action_for_application_server(as_state);
    }

}

static void msaf_context_application_server_state_certificates_remove_all(void) {

    ogs_info("Removing all certificates");

    msaf_application_server_state_node_t *as_state;

    ogs_list_for_each(&self->application_server_states, as_state) {

        resource_id_node_t *certificate, *next = NULL;
        resource_id_node_t *upload_certificate, *next_node = NULL;
        resource_id_node_t *delete_certificate, *node = NULL;

        if(&as_state->upload_certificates){
		
            ogs_info("Removing all upload certificates");
	        ogs_list_for_each_safe(&as_state->upload_certificates, next_node, upload_certificate){
		        if (upload_certificate->state)    
                    ogs_free(upload_certificate->state);
                ogs_list_remove(&as_state->upload_certificates, upload_certificate);
		        if(upload_certificate) 
		            ogs_free(upload_certificate);

            }
	    }   

        if (as_state->current_certificates) {
            ogs_list_for_each_safe(as_state->current_certificates, next, certificate){
                ogs_info("Removing all current certificates");
                if (certificate->state)   
                    ogs_free(certificate->state);
                ogs_list_remove(as_state->current_certificates, certificate);
                if (certificate) {
                    ogs_free(certificate);
                }

            }
	    }

	    if(&as_state->delete_certificates) {
            ogs_list_for_each_safe(&as_state->delete_certificates, node, delete_certificate){
		    if (delete_certificate->state)    
                ogs_free(delete_certificate->state);
                ogs_list_remove(&as_state->delete_certificates, delete_certificate);
		    if (delete_certificate)
			    ogs_free(delete_certificate);
            }
	    }
    }
}

static void msaf_context_application_server_state_content_hosting_configuration_remove_all(void) {

    ogs_info("Removing all Content Hosting Configurations");
    msaf_application_server_state_node_t *as_state;
    ogs_list_for_each(&self->application_server_states, as_state) {
        resource_id_node_t *content_hosting_configuration, *next = NULL;
        resource_id_node_t *upload_content_hosting_configuration, *next_node = NULL;
        resource_id_node_t *delete_content_hosting_configuration, *node = NULL;

        if(&as_state->upload_content_hosting_configurations){
            ogs_list_for_each_safe(&as_state->upload_content_hosting_configurations, next, upload_content_hosting_configuration){
	       if(upload_content_hosting_configuration->state)
                   ogs_free(upload_content_hosting_configuration->state);
                ogs_list_remove(&as_state->upload_content_hosting_configurations, upload_content_hosting_configuration);
                 ogs_free(upload_content_hosting_configuration);

            }
        }

        if (as_state->current_content_hosting_configurations) {
            ogs_list_for_each_safe(as_state->current_content_hosting_configurations, next, content_hosting_configuration){
                ogs_free(content_hosting_configuration->state);
                ogs_list_remove(as_state->current_content_hosting_configurations, content_hosting_configuration);
                ogs_free(content_hosting_configuration);

            }
        }

        if(&as_state->delete_content_hosting_configurations) {
            ogs_list_for_each_safe(&as_state->delete_content_hosting_configurations, node, delete_content_hosting_configuration){
                ogs_free(delete_content_hosting_configuration->state);
                ogs_list_remove(&as_state->delete_content_hosting_configurations, delete_content_hosting_configuration);
                ogs_free(delete_content_hosting_configuration);
            }
        }
    }
}

static void msaf_context_application_server_state_assigned_provisioning_sessions_remove_all(void) {
    ogs_info("Removing all assigned provisioning session");
    msaf_application_server_state_node_t *as_state;
    ogs_list_for_each(&self->application_server_states, as_state) {

    	assigned_provisioning_sessions_node_t *provisioning_session_resource;
        assigned_provisioning_sessions_node_t *provisioning_session_node = NULL;

        if(&as_state->assigned_provisioning_sessions){
            ogs_list_for_each_safe(&as_state->assigned_provisioning_sessions, provisioning_session_node, provisioning_session_resource){
                ogs_list_remove(&as_state->assigned_provisioning_sessions, provisioning_session_resource);
                ogs_free(provisioning_session_resource);

            }
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


#if 0
static msaf_provisioning_session_t *
msaf_context_get_provisioning_sessions_from_map(void)
{

    msaf_provisioning_session_t *provisioning_session; 

    obtain_ogs_hash_provisioning_session_t oohps = {
        provisioning_session
    };

    if (self->provisioningSessions_map) {
        ogs_hash_do(ogs_hash_do_retrieve_provisioning_sessions_from_map, &oohps, self->provisioningSessions_map);
        return  oohps.provisioning_session;
    }
}

static msaf_provisioning_session_t*
ogs_hash_do_retrieve_provisioning_sessions_from_map(void *rec, const void *key, int klen, const void *value)
{
    obtain_ogs_hash_provisioning_session_t *oohps = (obtain_ogs_hash_provisioning_session_t*)rec;
    oohps->provisioning_session =  msaf_context_provisioning_session_find_by_provisioningSessionId(((msaf_provisioning_session_t*)value)->provisioningSessionId);
}

static char *
msaf_context_get_certificates_from_map(void)
{
    char *certificate;
    obtain_ogs_hash_certificate_t oohc ={
        certificate
    };

    if (self->provisioningSessions_map) {
        ogs_hash_do(ogs_hash_do_retrieve_certificates_from_map, &oohc, self->provisioningSessions_map);
        return  oohc.certificate;
    } 
}

static void
ogs_hash_do_retrieve_certificates_from_map(void *rec, const void *key, int klen, const void *value)
{
    obtain_ogs_hash_certificate_t *oohc = (obtain_ogs_hash_certificate_t*)rec;
    oohc->certificate =  msaf_context_retrieve_certificates_from_map((msaf_provisioning_session_t*)value);
}

static char *
msaf_context_retrieve_certificates_from_map(msaf_provisioning_session_t *provisioning_session)
{
    ogs_assert(provisioning_session);
    OpenAPI_lnode_t *dist_config_node = NULL;
    OpenAPI_distribution_configuration_t *dist_config = NULL;
    if (provisioning_session->contentHostingConfiguration && provisioning_session->certificate_map) {
        OpenAPI_list_for_each(provisioning_session->contentHostingConfiguration->distribution_configurations, dist_config_node) {
            dist_config = (OpenAPI_distribution_configuration_t*)dist_config_node->data;
            if (dist_config->certificate_id) {
                const char *cert =ogs_hash_get(provisioning_session->certificate_map, dist_config->certificate_id, OGS_HASH_KEY_STRING);
                if(cert){
                    return cert;
                } else {
                    return NULL;
                }
                break;
            }
        }
    }
    return NULL;
}

static void msaf_context_application_server_state_remove( msaf_application_server_state_node_t *msaf_as_state)
{
    ogs_assert(msaf_as_state);
    ogs_list_remove(&self->application_server_states, msaf_as_state);

    if (msaf_as_state->application_server) ogs_free(msaf_as_state->application_server);

    if (&msaf_as_state->assigned_provisioning_sessions)
        application_server_state_remove_all(&msaf_as_state->assigned_provisioning_sessions);

    if (msaf_as_state->current_certificates)
        application_server_state_remove_all(msaf_as_state->current_certificates);

    if (&msaf_as_state->upload_certificates) 
        application_server_state_remove_all(&msaf_as_state->upload_certificates);

    if (&msaf_as_state->delete_certificates) 
        application_server_state_remove_all(&msaf_as_state->delete_certificates);

    if (msaf_as_state->current_content_hosting_configurations) 
        application_server_state_remove_all(msaf_as_state->current_content_hosting_configurations);

    if (&msaf_as_state->upload_content_hosting_configurations) 
        application_server_state_remove_all(&msaf_as_state->upload_content_hosting_configurations);

    if (&msaf_as_state->delete_content_hosting_configurations) 
        application_server_state_remove_all(&msaf_as_state->delete_content_hosting_configurations);

    ogs_free(msaf_as_state);
}

static void msaf_context_application_server_state_remove_all()
{
    msaf_application_server_state_node_t *msaf_as_state = NULL, *next = NULL;
    ogs_info("ogs self list len:%d",ogs_list_count(&self->application_server_states));
    ogs_list_for_each_safe(&self->application_server_states, next, msaf_as_state)
        msaf_context_application_server_state_remove(msaf_as_state);
}

static void application_server_state_remove_all(ogs_list_t *app_state_list)
{
    ogs_assert(app_state_list);	 
    resource_id_node_t *as_state = NULL, *next = NULL;
    ogs_list_for_each_safe(app_state_list, next, as_state)
        application_server_state_remove(app_state_list, as_state);
}

#endif

void msaf_context_application_server_state_list(const char* list_name, ogs_list_t *list) {
	resource_id_node_t *state_node;
	if(!list || (ogs_list_count(list) == 0)){
		ogs_info("%s is empty",list_name);
	} else{
		int i = 1;
		ogs_list_for_each(list, state_node){
			ogs_info("%s[%d]: %s\n", list_name, i, state_node->state);
			i++;
		}
	}
}	

static msaf_provisioning_session_t *
msaf_context_provisioning_session_find_by_provisioningSessionId(char *provisioningSessionId)
{
    return ogs_hash_get(self->provisioningSessions_map, provisioningSessionId, OGS_HASH_KEY_STRING);
}

static OpenAPI_service_access_information_resource_t *
msaf_context_service_access_information_create(char *media_player_entry)
{
    OpenAPI_service_access_information_resource_streaming_access_t *streaming_access
        = OpenAPI_service_access_information_resource_streaming_access_create(
                media_player_entry, NULL);
    OpenAPI_service_access_information_resource_t *service_access_information
        = OpenAPI_service_access_information_resource_create(
                ogs_strdup(self->config.provisioningSessionId),
                OpenAPI_provisioning_session_type_DOWNLINK, streaming_access, NULL, NULL,
                NULL, NULL,NULL);
    return service_access_information;
}

static OpenAPI_content_hosting_configuration_t *
msaf_context_content_hosting_configuration_create(msaf_provisioning_session_t *provisioning_session)
{
    char *content_host_config_data = read_file(self->config.contentHostingConfiguration);
    cJSON *content_host_config_json = cJSON_Parse(content_host_config_data);
    OpenAPI_content_hosting_configuration_t *content_hosting_configuration
        = OpenAPI_content_hosting_configuration_parseFromJSON(content_host_config_json);
    cJSON_Delete(content_host_config_json);
    free (content_host_config_data);
    msaf_context_application_server_state_set(provisioning_session, content_hosting_configuration);
    return content_hosting_configuration;
}

static ogs_sbi_client_t *
msaf_m3_client_init(const char *hostname, int port)
{
    int rv;
    ogs_sbi_client_t *client = NULL;
    ogs_sockaddr_t *addr = NULL;

    rv = ogs_getaddrinfo(&addr, AF_UNSPEC, hostname, port, 0);
    if (rv != OGS_OK) {
        ogs_error("getaddrinfo failed");
        return NULL;
    }

    if (addr == NULL) 
        ogs_error("Could not get the address of the Application Server");

    client = ogs_sbi_client_add(addr);
    ogs_assert(client);

    ogs_freeaddrinfo(addr);

    return client;
}

static int
m3_client_as_state_requests(msaf_application_server_state_node_t *as_state,
        const char *type, const char *data, const char *method,
        const char *component)
{
    ogs_sbi_request_t *request;

    request = ogs_sbi_request_new();
    request->h.method = ogs_strdup(method);	
    request->h.uri = ogs_msprintf("http://%s:%i/3gpp-m3/v1/%s",
            as_state->application_server->canonicalHostname,
            as_state->application_server->m3Port, component);
    request->h.api.version = ogs_strdup("v1");
    if (data) {
        request->http.content = ogs_strdup(data);
        request->http.content_length = strlen(data);
    }
    if (type)
        ogs_sbi_header_set(request->http.headers, "Content-Type", type);

    if (as_state->client == NULL) {
        as_state->client = msaf_m3_client_init(
                as_state->application_server->canonicalHostname,
                as_state->application_server->m3Port);
    }

    ogs_sbi_client_send_request(as_state->client, client_notify_cb, request, as_state);

     ogs_sbi_request_free(request);

    return 1;
}	

static int
client_notify_cb(int status, ogs_sbi_response_t *response, void *data)
{
    int rv;
    msaf_event_t *event;

    if (status != OGS_OK) {
        ogs_log_message(
                status == OGS_DONE ? OGS_LOG_DEBUG : OGS_LOG_WARN, 0,
                "client_notify_cb() failed [%d]", status);
        return OGS_ERROR;
    }

    ogs_assert(response);

    event = (msaf_event_t*)ogs_event_new(OGS_EVENT_SBI_CLIENT);
    event->h.sbi.response = response;
    event->application_server_state = data;
    rv = ogs_queue_push(ogs_app()->queue, event);
    if (rv !=OGS_OK) {
        ogs_error("OGS Queue Push failed %d", rv);
        ogs_sbi_response_free(response);
        ogs_event_free(event);
        return OGS_ERROR;
    }

    return OGS_OK;
}

static void msaf_context_inotify_init(void){

    self->inotify_context = ogs_calloc(1, sizeof(inotify_context_t));
    ogs_assert(self->inotify_context);
}	

static char *
media_player_entry_create(const char *session_id, OpenAPI_content_hosting_configuration_t *chc)
{
    char *media_player_entry = NULL;
    OpenAPI_lnode_t *dist_config_node = NULL;
    OpenAPI_distribution_configuration_t *dist_config = NULL;
    static const char macro[] = "{provisioningSessionId}";
    char *url_path_prefix = NULL;
    const char *protocol = "http";
    msaf_application_server_node_t *msaf_as = NULL;

    ogs_assert(session_id);
    ogs_assert(chc);

    OpenAPI_list_for_each(chc->distribution_configurations, dist_config_node) {
        dist_config = (OpenAPI_distribution_configuration_t*)dist_config_node->data;
        if (dist_config->certificate_id) {
            protocol = "https";
            break;
        }
    }

    url_path_prefix = url_path_prefix_create(macro, session_id);
    msaf_as = ogs_list_first(&self->config.applicationServers_list); /* just use first defined AS for now - change later to use AS picked from pool */
    media_player_entry = ogs_msprintf("%s://%s%s%s", protocol, msaf_as->canonicalHostname, url_path_prefix, self->config.mediaPlayerEntrySuffix);

    ogs_free(url_path_prefix);

    return media_player_entry;
}

static char*
url_path_prefix_create(const char* macro, const char* session_id)
{
    char* url_path_prefix;
    char *url_path_prefix_format;
    int i, count = 0;
    int session_id_len = strlen(session_id);
    int macro_len = strlen(macro);
    msaf_application_server_node_t *msaf_as = NULL;

    msaf_as = ogs_list_first(&self->config.applicationServers_list);
    url_path_prefix_format = msaf_as->urlPathPrefixFormat;
    for (i = 0; url_path_prefix_format[i] != '\0'; i++) {
        if (strstr(url_path_prefix_format+i, macro) == url_path_prefix_format+i) {
            count++;
            i += macro_len - 1;
        }
    }

    url_path_prefix = (char*)ogs_malloc(i + count * (session_id_len - macro_len) + 2);

    i = 0;
    while (*url_path_prefix_format) {
        if (strstr(url_path_prefix_format, macro) == url_path_prefix_format) {
            strcpy(url_path_prefix+i, session_id);
            i += session_id_len;
            url_path_prefix_format += macro_len;
        }
        else
            url_path_prefix[i++] = *url_path_prefix_format++;
    }

    if (url_path_prefix[i-1] != '/')
        url_path_prefix[i++] = '/';
    url_path_prefix[i] = '\0';

    return url_path_prefix;
}

static int
msaf_context_prepare(void)
{
    return OGS_OK;
}

static int
msaf_context_validation(void)
{
    return OGS_OK;
}

static void
msaf_context_display()
{
    msaf_provisioning_session_t *provisioning_session_context = NULL;
    cJSON *json;
    char *text;

    provisioning_session_context = msaf_context_provisioning_session_find_by_provisioningSessionId(self->config.provisioningSessionId);
    ogs_assert(provisioning_session_context);
    json = OpenAPI_content_hosting_configuration_convertToJSON(provisioning_session_context->contentHostingConfiguration);
    text = cJSON_Print(json);
    ogs_info("Content Hosting Configuration\n %s\n", text);
    ogs_free(text);
    cJSON_Delete(json);
    json = OpenAPI_service_access_information_resource_convertToJSON(provisioning_session_context->serviceAccessInformation);
    text = cJSON_Print(json);
    ogs_info("Service Access Information\n %s\n", text);
    ogs_free(text);
    cJSON_Delete(json);
}

static char *
read_file(const char *filename)
{
    FILE *f = NULL;
    long len = 0;
    char *data_json = NULL;

    /* open in read binary mode */
    f = fopen(filename,"rb");
    /* get the length */
    fseek(f, 0, SEEK_END);
    len = ftell(f);
    fseek(f, 0, SEEK_SET);
    data_json = (char*)malloc(len + 1);

    fread(data_json, 1, len, f);
    data_json[len] = '\0';
    fclose(f);
    return data_json;

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

static int
ogs_hash_do_cert_check(void *rec, const void *key, int klen, const void *value)
{
    return msaf_context_content_hosting_configuration_certificate_check((msaf_provisioning_session_t*)value);
}

static void
msaf_context_provisioning_session_free(msaf_provisioning_session_t *provisioning_session)
{
    ogs_assert(provisioning_session);
    if (provisioning_session->certificate_map) {
        free_ogs_hash_context_t fohc = {
            safe_ogs_free,
            provisioning_session->certificate_map
        };
        ogs_hash_do(free_ogs_hash_entry, &fohc, provisioning_session->certificate_map);
        ogs_hash_destroy(provisioning_session->certificate_map);
    }
    if (provisioning_session->provisioningSessionId) ogs_free(provisioning_session->provisioningSessionId);
    if (provisioning_session->contentHostingConfiguration) OpenAPI_content_hosting_configuration_free(provisioning_session->contentHostingConfiguration);
    if (provisioning_session->serviceAccessInformation) OpenAPI_service_access_information_resource_free(provisioning_session->serviceAccessInformation);
    ogs_free(provisioning_session);
}

static void
safe_ogs_free(void *memory)
{
    if(memory)
        ogs_free(memory);
}

static ogs_hash_t *
msaf_context_certificate_map(void)
{
    char *path = NULL;
    cJSON *entry;
    ogs_hash_t *certificate_map = ogs_hash_make();
    char *certificate = read_file(self->config.certificate);
    cJSON *cert = cJSON_Parse(certificate);
    path = get_path(self->config.certificate);
    ogs_assert(path);
    cJSON_ArrayForEach(entry, cert) {
        char *abs_path;
        if (entry->valuestring[0] != '/') {
            abs_path = ogs_msprintf("%s/%s", path, entry->valuestring);
        } else {
            abs_path = ogs_strdup(entry->valuestring);
        }
        ogs_hash_set(certificate_map, ogs_strdup(entry->string), OGS_HASH_KEY_STRING, abs_path);
    }
    ogs_free(path);
    cJSON_Delete(entry);
    cJSON_Delete(cert);
    return certificate_map;
}

static ogs_hash_t *
msaf_context_content_hosting_configuration_file_map(char *provisioning_session_id)
{
    char *chc_file = NULL;
    char *chc_file_name = NULL;
    char *path = NULL;
    path = get_path(self->config.contentHostingConfiguration);
    ogs_assert(path);
    chc_file = basename(self->config.contentHostingConfiguration);
    ogs_assert(chc_file);
    chc_file_name = ogs_msprintf("%s/%s", path, chc_file);
    ogs_assert(chc_file);
    ogs_hash_set(self->content_hosting_configuration_file_map, chc_file_name, OGS_HASH_KEY_STRING, ogs_strdup(provisioning_session_id));
    ogs_free(path);
    return self->content_hosting_configuration_file_map;
}

static char *
get_path(const char *file)
{
    char *path = NULL;
    char *file_dir = NULL;

    path = realpath(file, NULL);
    if(path == NULL){
        ogs_error("cannot find file with name[%s]\n", file);
        return NULL;
    } 
    file_dir = ogs_strdup(dirname(path));
    return file_dir;
}

static void
application_server_state_init()
{

    msaf_application_server_node_t *msaf_as = NULL;
    msaf_application_server_state_node_t *as_state = NULL;

    as_state = ogs_calloc(1, sizeof(msaf_application_server_state_node_t));
    ogs_assert(as_state);

    msaf_as = ogs_list_first(&self->config.applicationServers_list); /* just use first defined AS for now - change later to use AS picked from pool */
    ogs_assert(msaf_as);

    as_state->application_server = msaf_as;

    ogs_list_init(&as_state->assigned_provisioning_sessions);
    ogs_list_init(&as_state->upload_certificates);
    ogs_list_init(&as_state->upload_content_hosting_configurations);

    ogs_list_add(&self->application_server_states, as_state);
}

static long int
ascii_to_long(const char *str)
{
    char *endp = NULL;
    long int ret;

    ret = strtol(str, &endp, 10);
    if (endp == NULL || *endp != 0) {
        ogs_error("Failed to convert '%s' to an integer", str);
        ret = 0;
    }
    return ret;
}

/* vim:ts=8:sts=4:sw=4:expandtab:
*/
