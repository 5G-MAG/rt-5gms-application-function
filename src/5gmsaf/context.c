/*
License: 5G-MAG Public License (v1.0)
Author: Dev Audsin
Copyright: (C) 2022 British Broadcasting Corporation

For full license terms please see the LICENSE file distributed with this
program. If this file is missing then the license can be retrieved from
https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "context.h"

static msaf_context_t *self = NULL;

int __msaf_log_domain;

static OpenAPI_content_hosting_configuration_t *msaf_context_content_hosting_configuration_create(void);
static OpenAPI_service_access_information_resource_t *msaf_context_service_access_information_create(char *media_player_entry);
static char *media_player_entry_create(const char *provisioning_session_id, OpenAPI_content_hosting_configuration_t *content_hosting_configuration);
static char *url_path_prefix_create(const char *macro, const char *session_id);
static char *read_file(const char *filename);
static int msaf_context_prepare(void);
static int msaf_context_validation(void);
static void msaf_context_display(void);
static int ogs_hash_do_per_value(void *fn, const void *key, int klen, const void *value);
static void msaf_context_provisioning_session_free(msaf_provisioning_session_t *provisioning_session);

/***** Public functions *****/

void
msaf_context_init(void)
{
    ogs_assert(self == NULL);

    self = ogs_calloc(1, sizeof(msaf_context_t));
    ogs_assert(self);
    
    ogs_log_install_domain(&__msaf_log_domain, "msaf", ogs_core()->log.level);

    ogs_list_init(&self->config.applicationServers_list);
      
    self->provisioningSessions_map = ogs_hash_make();
    ogs_assert(self->provisioningSessions_map);
}

void
msaf_context_final(void)
{
    ogs_assert(self);

    msaf_context_display();

    if (self->provisioningSessions_map) {
	    /* TODO: remove all provisioning sessions */
	    ogs_hash_do(ogs_hash_do_per_value, msaf_context_provisioning_session_free, self->provisioningSessions_map);
	    ogs_hash_destroy(self->provisioningSessions_map);
    }

     if(self->config.contentHostingConfiguration)
            ogs_free(self->config.contentHostingConfiguration);

    if(self->config.provisioningSessionId)
            ogs_free(self->config.provisioningSessionId);


    if(self->config.mediaPlayerEntrySuffix)
            ogs_free(self->config.mediaPlayerEntrySuffix);


    msaf_context_application_server_remove_all();

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
                    while (ogs_yaml_iter_next(&as_iter)) {
                        const char *as_key = ogs_yaml_iter_key(&as_iter);
                        ogs_assert(as_key);
                        if (!strcmp(as_key, "canonicalHostname")) {
                            canonical_hostname = ogs_strdup(ogs_yaml_iter_value(&as_iter));
                        } else if (!strcmp(as_key, "urlPathPrefixFormat")) {
                            url_path_prefix_format = ogs_strdup(ogs_yaml_iter_value(&as_iter));
                        }   
	            } 
                    msaf_context_application_server_add(canonical_hostname, url_path_prefix_format);  
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

                        uint16_t port = self->sbi_port;
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

msaf_provisioning_session_t *
msaf_context_provisioning_session_set() {
    msaf_provisioning_session_t *msaf_provisioning_session = ogs_calloc(1, sizeof(msaf_provisioning_session_t));
    ogs_assert(msaf_provisioning_session);

    msaf_provisioning_session->provisioningSessionId = ogs_strdup(self->config.provisioningSessionId);
    msaf_provisioning_session->contentHostingConfiguration = msaf_context_content_hosting_configuration_create();
    char *media_player_entry = media_player_entry_create(msaf_provisioning_session->provisioningSessionId, msaf_provisioning_session->contentHostingConfiguration);
    ogs_assert(media_player_entry);
    msaf_provisioning_session->serviceAccessInformation = msaf_context_service_access_information_create(media_player_entry);
    ogs_hash_set(self->provisioningSessions_map, ogs_strdup(msaf_provisioning_session->provisioningSessionId), OGS_HASH_KEY_STRING, msaf_provisioning_session);

    return msaf_provisioning_session;
}

cJSON *msaf_context_retrieve_service_access_information(const char *provisioning_session_id)
{
    msaf_provisioning_session_t *provisioning_session_context = NULL;
    provisioning_session_context = msaf_context_provisioning_session_find_by_provisioningSessionId(provisioning_session_id);
    if (provisioning_session_context == NULL) {
	ogs_error("Couldn't find the Provisioning Session ID [%s]", provisioning_session_id);
        return NULL;
    }
    if (provisioning_session_context->serviceAccessInformation == NULL) {
        ogs_error("The provisioning Session [%s] does not have an associated Service Access Information", provisioning_session_id);
        return NULL;
    }
    cJSON *service_access_information = OpenAPI_service_access_information_resource_convertToJSON(provisioning_session_context->serviceAccessInformation);
    return service_access_information;
}

msaf_application_server_node_t *msaf_context_application_server_add(char *canonical_hostname, char *url_path_prefix_format) {
    msaf_application_server_node_t *msaf_as = NULL;
 
    msaf_as = ogs_calloc(1, sizeof(msaf_application_server_node_t));
    ogs_assert(msaf_as);

    msaf_as->canonicalHostname = canonical_hostname;
    msaf_as->urlPathPrefixFormat = url_path_prefix_format;
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
    msaf_application_server_node_t *msaf_as = NULL, *next = NULL;;

    ogs_list_for_each_safe(&self->config.applicationServers_list, next, msaf_as)
        msaf_context_application_server_remove(msaf_as);
}

void msaf_context_application_server_print_all()
{
    msaf_application_server_node_t *msaf_as = NULL, *next = NULL;;

    ogs_list_for_each_safe(&self->config.applicationServers_list, next, msaf_as)
        ogs_info("AS %s %s", msaf_as->canonicalHostname, msaf_as->urlPathPrefixFormat);
}

msaf_provisioning_session_t *
msaf_context_provisioning_session_find_by_provisioningSessionId(const char *provisioningSessionId)
{
    return ogs_hash_get(self->provisioningSessions_map, provisioningSessionId, OGS_HASH_KEY_STRING);
}

/***** Private functions *****/

static OpenAPI_service_access_information_resource_t *
msaf_context_service_access_information_create(char *media_player_entry) {
 OpenAPI_service_access_information_resource_streaming_access_t *streaming_access
	 = OpenAPI_service_access_information_resource_streaming_access_create(
			 media_player_entry, NULL);
 OpenAPI_service_access_information_resource_t *service_access_information
	 = OpenAPI_service_access_information_resource_create(
			 ogs_strdup(self->config.provisioningSessionId),
			 OpenAPI_provisioning_session_type_DOWNLINK, streaming_access, NULL, NULL,
			 NULL, NULL,NULL);
 return (OpenAPI_service_access_information_resource_t *)service_access_information;
}

static OpenAPI_content_hosting_configuration_t *
msaf_context_content_hosting_configuration_create() {
    char *content_host_config_data;
    cJSON *content_host_config_json;

    if(!self->config.contentHostingConfiguration) {
        ogs_error("contentHostingConfiguration not present in the MSAF configuration file");
    }

    ogs_assert(self->config.contentHostingConfiguration);

    content_host_config_data = read_file(self->config.contentHostingConfiguration);
    if (!content_host_config_data) {
	ogs_error("The ContentHostingConfiguration JSON file [%s] cannot be opened", self->config.contentHostingConfiguration);
    }
    ogs_assert(content_host_config_data);

    content_host_config_json = cJSON_Parse(content_host_config_data);
    free(content_host_config_data);

    if (content_host_config_json == NULL){
        ogs_error("Parsing contentHostingConfiguration, from file [%s], to JSON structure failed", self->config.contentHostingConfiguration);
    }
    ogs_assert(content_host_config_json);

    OpenAPI_content_hosting_configuration_t *content_hosting_configuration
	    = OpenAPI_content_hosting_configuration_parseFromJSON(content_host_config_json);

    cJSON_Delete(content_host_config_json);

    ogs_assert(content_hosting_configuration);

    return content_hosting_configuration;
}

static char *
media_player_entry_create(const char *session_id, OpenAPI_content_hosting_configuration_t *chc) {
    char *media_player_entry = NULL;
    OpenAPI_lnode_t *dist_config_node = NULL;
    OpenAPI_distribution_configuration_t *dist_config = NULL;
    static const char macro[] = "{provisioningSessionId}";
    char *url_path_prefix = NULL;
    const char *protocol = "http";
    char *domain_name;

    ogs_assert(session_id);
    ogs_assert(chc);

    OpenAPI_list_for_each(chc->distribution_configurations, dist_config_node) {
	dist_config = (OpenAPI_distribution_configuration_t*)dist_config_node->data;
	if (dist_config->certificate_id) {
	    protocol = "https";
	    break;
	}
    }

    if (dist_config->domain_name_alias && strlen(dist_config->domain_name_alias) > 0) {
        domain_name = dist_config->domain_name_alias;
    } else {
	msaf_application_server_node_t *msaf_as;
	msaf_as = ogs_list_first(&self->config.applicationServers_list);
        domain_name = msaf_as->canonicalHostname;
    }

    url_path_prefix = url_path_prefix_create(macro, session_id);
    media_player_entry = ogs_msprintf("%s://%s%s%s", protocol, domain_name, url_path_prefix, self->config.mediaPlayerEntrySuffix);

    ogs_free(url_path_prefix);

    return media_player_entry;
}

static char* url_path_prefix_create(const char* macro, const char* session_id)
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

static int msaf_context_prepare(void)
{
    return OGS_OK;
}

static int msaf_context_validation(void)
{
    return OGS_OK;
}

static void msaf_context_display()
{
    msaf_provisioning_session_t *provisioning_session_context = NULL;
    provisioning_session_context = msaf_context_provisioning_session_find_by_provisioningSessionId(self->config.provisioningSessionId);
    ogs_assert(provisioning_session_context);
    ogs_info("Content Hosting Configuration\n %s\n",cJSON_Print(OpenAPI_content_hosting_configuration_convertToJSON(provisioning_session_context->contentHostingConfiguration)));
    ogs_info("Service Access Information\n %s\n",cJSON_Print(OpenAPI_service_access_information_resource_convertToJSON(provisioning_session_context->serviceAccessInformation)));
}

static char *read_file(const char *filename)
{
    FILE *f = NULL;
    long len = 0;
    char *data_json = NULL;

    /* open in read binary mode */
    f = fopen(filename,"rb");
    if (!f) {
	ogs_error("Failed to open file %s: %s", filename, strerror(errno));
	return NULL;
    }

    /* get the length */
    fseek(f, 0, SEEK_END);
    len = ftell(f);
    fseek(f, 0, SEEK_SET);
    data_json = (char*)malloc(len + 1);

    ogs_assert(data_json);

    fread(data_json, 1, len, f);
    data_json[len] = '\0';
    fclose(f);
    return data_json;

} 

static int
ogs_hash_do_per_value(void *rec, const void *key, int klen, const void *value)
{
    void (*fn)(const void *value) = rec;
    fn(value);
    return 1;
}

static void
msaf_context_provisioning_session_free(msaf_provisioning_session_t *provisioning_session)
{
    ogs_assert(provisioning_session);
    if (provisioning_session->provisioningSessionId) ogs_free(provisioning_session->provisioningSessionId);
    if (provisioning_session->contentHostingConfiguration) OpenAPI_content_hosting_configuration_free(provisioning_session->contentHostingConfiguration);
    if (provisioning_session->serviceAccessInformation) OpenAPI_service_access_information_resource_free(provisioning_session->serviceAccessInformation);
    ogs_free(provisioning_session);
}
