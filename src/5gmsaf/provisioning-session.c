/*
License: 5G-MAG Public License (v1.0)
Author: Dev Audsin
Copyright: (C) 2022 British Broadcasting Corporation

For full license terms please see the LICENSE file distributed with this
program. If this file is missing then the license can be retrieved from
https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
*/

#include "provisioning-session.h"
#include "application-server.h"
#include "media-player.h"
#include "context.h"
#include "utilities.h"

typedef struct free_ogs_hash_provisioning_session_s {
    char *provisioning_session;
    ogs_hash_t *hash;
} free_ogs_hash_provisioning_session_t;

static regex_t *relative_path_re = NULL;

static int ogs_hash_do_cert_check(void *rec, const void *key, int klen, const void *value);
static int free_ogs_hash_provisioning_session(void *rec, const void *key, int klen, const void *value);
static char* url_path_create(const char* macro, const char* session_id, const msaf_application_server_node_t *msaf_as);
static void tidy_relative_path_re(void);
static int uri_relative_check(char *entry_point_path);


/***** Public functions *****/

OpenAPI_content_hosting_configuration_t *
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
                ogs_info("af_unique_cert_id: %s",af_unique_cert_id);
                ogs_free(dist_config->certificate_id);
                dist_config->certificate_id = af_unique_cert_id;
                ogs_info("dist_config->certificate_id: %s",dist_config->certificate_id);
            }
        }
    }
    return chc_with_af_unique_cert_id;
}

msaf_provisioning_session_t *
msaf_provisioning_session_create(char *provisioning_session_type, char *asp_id, char *external_app_id)
{
    msaf_provisioning_session_t *msaf_provisioning_session;
    char *media_player_entry;

    ogs_uuid_t uuid;
    char id[OGS_UUID_FORMATTED_LENGTH + 1];

    OpenAPI_provisioning_session_t *provisioning_session;

    ogs_uuid_get(&uuid);
    ogs_uuid_format(id, &uuid);

    provisioning_session = OpenAPI_provisioning_session_create(ogs_strdup(id), OpenAPI_provisioning_session_type_FromString(provisioning_session_type), (asp_id)?ogs_strdup(asp_id):NULL, ogs_strdup(external_app_id), NULL, NULL, NULL, NULL, NULL, NULL);

    msaf_provisioning_session = ogs_calloc(1, sizeof(msaf_provisioning_session_t));
    ogs_assert(msaf_provisioning_session);

    msaf_provisioning_session->provisioningSessionId = ogs_strdup(provisioning_session->provisioning_session_id);

    if(msaf_self()->config.provisioningSessionId)
        ogs_free(msaf_self()->config.provisioningSessionId);
    msaf_self()->config.provisioningSessionId =  ogs_strdup(msaf_provisioning_session->provisioningSessionId);

    msaf_provisioning_session->provisioningSessionType = provisioning_session->provisioning_session_type;
    msaf_provisioning_session->aspId = (provisioning_session->asp_id)?ogs_strdup(provisioning_session->asp_id):NULL;
    msaf_provisioning_session->externalApplicationId = ogs_strdup(provisioning_session->external_application_id);

    msaf_provisioning_session->certificate_map = msaf_certificate_map();
    ogs_hash_set(msaf_self()->provisioningSessions_map, ogs_strdup(msaf_provisioning_session->provisioningSessionId), OGS_HASH_KEY_STRING, msaf_provisioning_session);

    /* TODO: remove when inotify is removed */
    msaf_context_content_hosting_configuration_file_map(msaf_provisioning_session->provisioningSessionId);

    msaf_provisioning_session->contentHostingConfiguration = msaf_content_hosting_configuration_create(msaf_provisioning_session);
    media_player_entry = media_player_entry_create(msaf_provisioning_session->provisioningSessionId, msaf_provisioning_session->contentHostingConfiguration);
    ogs_assert(media_player_entry);
    msaf_provisioning_session->serviceAccessInformation = msaf_context_service_access_information_create(media_player_entry);

    OpenAPI_provisioning_session_free(provisioning_session);

    return msaf_provisioning_session;
}

cJSON *
msaf_provisioning_session_get_json(const char *provisioning_session_id)
{

    msaf_provisioning_session_t *msaf_provisioning_session;
    cJSON *provisioning_session_json;

    OpenAPI_provisioning_session_t *provisioning_session = NULL;
    provisioning_session = ogs_malloc(sizeof(OpenAPI_provisioning_session_t));
    ogs_assert(provisioning_session);

    msaf_provisioning_session = msaf_provisioning_session_find_by_provisioningSessionId(provisioning_session_id);

    if (msaf_provisioning_session) {

        provisioning_session->provisioning_session_id = msaf_provisioning_session->provisioningSessionId;
        provisioning_session->provisioning_session_type = msaf_provisioning_session->provisioningSessionType;
        provisioning_session->asp_id = msaf_provisioning_session->aspId;
        provisioning_session->external_application_id = msaf_provisioning_session->externalApplicationId;

        provisioning_session->server_certificate_ids = NULL;
        provisioning_session->content_preparation_template_ids = NULL;
        provisioning_session->metrics_reporting_configuration_ids = NULL;
        provisioning_session->policy_template_ids = NULL;
        provisioning_session->edge_resources_configuration_ids = NULL;
        provisioning_session->event_data_processing_configuration_ids = NULL;

        provisioning_session_json = OpenAPI_provisioning_session_convertToJSON(provisioning_session);
    } else {
        ogs_error("Unable to retrieve Provisioning Session");
        ogs_free(provisioning_session);
        return NULL;
    }
    ogs_free(provisioning_session);
    return provisioning_session_json;
}

int
msaf_distribution_certificate_check(void)
{
    if (msaf_self()->provisioningSessions_map) {
        return ogs_hash_do(ogs_hash_do_cert_check, NULL, msaf_self()->provisioningSessions_map);
    }
    return 1;
}

int
msaf_content_hosting_configuration_certificate_check(msaf_provisioning_session_t *provisioning_session)
{
    ogs_assert(provisioning_session);
    OpenAPI_lnode_t *dist_config_node = NULL;
    OpenAPI_distribution_configuration_t *dist_config = NULL;
    if (provisioning_session->contentHostingConfiguration && provisioning_session->certificate_map) {
        OpenAPI_list_for_each(provisioning_session->contentHostingConfiguration->distribution_configurations, dist_config_node) {
            dist_config = (OpenAPI_distribution_configuration_t*)dist_config_node->data;
            if (dist_config->certificate_id) {
                const char *cert =ogs_hash_get(provisioning_session->certificate_map, dist_config->certificate_id, OGS_HASH_KEY_STRING);
                if (cert) {
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

void
msaf_delete_certificate(char *resource_id)
{

    msaf_application_server_state_node_t *as_state;
    ogs_list_for_each(&msaf_self()->application_server_states, as_state) {
        resource_id_node_t *certificate, *next = NULL;
        resource_id_node_t *upload_certificate, *next_node = NULL;
        resource_id_node_t *delete_cert = NULL;
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

                if(current_cert_id)
                    ogs_free(current_cert_id);

            }

            if (certificate) {
                delete_cert = ogs_calloc(1, sizeof(resource_id_node_t));
                ogs_assert(delete_cert);
                delete_cert->state = ogs_strdup(certificate->state);
                ogs_list_add(&as_state->delete_certificates, delete_cert);

            }

            if (current_cert_id)
                ogs_free(current_cert_id);
        }

        {

            char *upload_cert_id = NULL;
            char *provisioning_session;
            char *cert_id;

            ogs_list_for_each_safe(&as_state->upload_certificates, next_node, upload_certificate) {

                upload_cert_id = ogs_strdup(upload_certificate->state);
                provisioning_session = strtok_r(upload_cert_id,":",&cert_id);
                if(!strcmp(provisioning_session, resource_id))
                    break;
            }

            if (upload_certificate) {

                ogs_list_remove(&as_state->upload_certificates, upload_certificate);

                ogs_list_add(&as_state->delete_certificates, upload_certificate);

            }

            if(upload_cert_id)
                ogs_free(upload_cert_id);
        }

    }	 
}

void
msaf_delete_content_hosting_configuration(char *resource_id)
{

    msaf_application_server_state_node_t *as_state;
    ogs_list_for_each(&msaf_self()->application_server_states, as_state) {

        resource_id_node_t *content_hosting_configuration, *next = NULL;
        resource_id_node_t *upload_content_hosting_configuration, *next_node = NULL;
        resource_id_node_t *delete_chc = NULL;

        ogs_list_init(&as_state->delete_content_hosting_configurations);

        if (as_state->current_content_hosting_configurations) {

            ogs_list_for_each_safe(as_state->current_content_hosting_configurations, next, content_hosting_configuration){

                if (!strcmp(content_hosting_configuration->state, resource_id))
                    break;
            }
            if (content_hosting_configuration) {
                delete_chc = ogs_calloc(1, sizeof(resource_id_node_t));
                ogs_assert(delete_chc);
                delete_chc->state = ogs_strdup(content_hosting_configuration->state);
                ogs_list_add(&as_state->delete_content_hosting_configurations, delete_chc);

            }
        }

        ogs_list_for_each_safe(&as_state->upload_content_hosting_configurations, next_node, upload_content_hosting_configuration){
            if (!strcmp(upload_content_hosting_configuration->state, resource_id))
                break;
        }
        if (upload_content_hosting_configuration) {

            ogs_list_remove(&as_state->upload_content_hosting_configurations, upload_content_hosting_configuration);

            ogs_list_add(&as_state->delete_content_hosting_configurations, upload_content_hosting_configuration);

        }

        next_action_for_application_server(as_state);
    }

}

msaf_provisioning_session_t *
msaf_provisioning_session_find_by_provisioningSessionId(const char *provisioningSessionId)
{
    if (!msaf_self()->provisioningSessions_map) return NULL;
    return (msaf_provisioning_session_t*) ogs_hash_get(msaf_self()->provisioningSessions_map, provisioningSessionId, OGS_HASH_KEY_STRING);
}

ogs_hash_t *
msaf_certificate_map(void)
{
    char *path = NULL;
    cJSON *entry;
    ogs_hash_t *certificate_map = ogs_hash_make();
    char *certificate = read_file(msaf_self()->config.certificate);
    cJSON *cert = cJSON_Parse(certificate);
    path = get_path(msaf_self()->config.certificate);
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
    free(certificate);
    return certificate_map;
}

const char *
msaf_get_certificate_filename(const char *provisioning_session_id, const char *certificate_id)
{
    msaf_provisioning_session_t *provisioning_session;

    provisioning_session = msaf_provisioning_session_find_by_provisioningSessionId(provisioning_session_id);
    ogs_assert(provisioning_session);

    if (provisioning_session->certificate_map == NULL) return NULL;

    return (const char*)ogs_hash_get(provisioning_session->certificate_map, certificate_id, OGS_HASH_KEY_STRING);
}

ogs_list_t*
msaf_retrieve_certificates_from_map(msaf_provisioning_session_t *provisioning_session)
{

    ogs_list_t *certs = NULL;
    resource_id_node_t *certificate = NULL;
    OpenAPI_lnode_t *dist_config_node = NULL;
    OpenAPI_distribution_configuration_t *dist_config = NULL;

    ogs_assert(provisioning_session);

    certs = (ogs_list_t*) ogs_calloc(1,sizeof(*certs));
    ogs_assert(certs);
    ogs_list_init(certs);
    if (provisioning_session->contentHostingConfiguration && provisioning_session->certificate_map) {
        OpenAPI_list_for_each(provisioning_session->contentHostingConfiguration->distribution_configurations, dist_config_node) {
            dist_config = (OpenAPI_distribution_configuration_t*)dist_config_node->data;
            if (dist_config->certificate_id) {
                const char *cert = ogs_hash_get(provisioning_session->certificate_map, dist_config->certificate_id, OGS_HASH_KEY_STRING);
                if (cert){
                    certificate = ogs_calloc(1, sizeof(resource_id_node_t));
                    ogs_assert(certificate);
                    char *provisioning_session_id_plus_cert_id = ogs_msprintf("%s:%s", provisioning_session->provisioningSessionId, dist_config->certificate_id);
                    certificate->state = provisioning_session_id_plus_cert_id;
                    ogs_list_add(certs, certificate);
                } else {
                    ogs_error("Certificate [%s] not found for Content Hosting Configuration [%s]", dist_config->certificate_id, provisioning_session->provisioningSessionId);
                    resource_id_node_t *next;
                    ogs_list_for_each_safe(certs, next, certificate) {
                        ogs_list_remove(certs, certificate);
                        if (certificate->state) ogs_free(certificate->state);
                        ogs_free(certificate);
                    }
                    certs = NULL;
                    break;
                }
            }
        }
    }
    return certs;
}

OpenAPI_content_hosting_configuration_t *
msaf_content_hosting_configuration_create(msaf_provisioning_session_t *provisioning_session)
{
    OpenAPI_lnode_t *dist_config_node = NULL;
    OpenAPI_distribution_configuration_t *dist_config = NULL;
    char *url_path;
    static const char macro[] = "{provisioningSessionId}";
    msaf_application_server_state_node_t *as_state;

    as_state = ogs_list_first(&msaf_self()->application_server_states);

    url_path = url_path_create(macro, provisioning_session->provisioningSessionId, as_state->application_server);

    char *content_host_config_data = read_file(msaf_self()->config.contentHostingConfiguration);
    cJSON *content_host_config_json = cJSON_Parse(content_host_config_data);

    OpenAPI_content_hosting_configuration_t *content_hosting_configuration
        = OpenAPI_content_hosting_configuration_parseFromJSON(content_host_config_json);
    if (!uri_relative_check(content_hosting_configuration->entry_point_path)) {
        cJSON_Delete(content_host_config_json);
        ogs_free(url_path);
        ogs_info(" URI relative check return 0: After reading content_host_config_data: %s", content_host_config_data);
        if (content_hosting_configuration)
            OpenAPI_content_hosting_configuration_free(content_hosting_configuration);
        ogs_free(content_host_config_data);
        return NULL;
    }

    if (content_hosting_configuration->distribution_configurations) {
        OpenAPI_list_for_each(content_hosting_configuration->distribution_configurations, dist_config_node) {
            char *protocol = "http";
            dist_config = (OpenAPI_distribution_configuration_t*)dist_config_node->data;
            if (dist_config->canonical_domain_name)
                ogs_free(dist_config->canonical_domain_name);
            dist_config->canonical_domain_name = ogs_strdup(as_state->application_server->canonicalHostname);
            if (dist_config->certificate_id) {
                protocol = "https";
            }
            if (dist_config->base_url)
                ogs_free(dist_config->base_url);
            dist_config->base_url = ogs_msprintf("%s://%s%s", protocol, dist_config->canonical_domain_name, url_path);
            ogs_info("dist_config->base_url: %s",dist_config->base_url);
        }
    } else {
        ogs_error("The Content Hosting Configuration has no Distribution Configuration");
        if (content_hosting_configuration)
            OpenAPI_content_hosting_configuration_free(content_hosting_configuration);
        ogs_free(content_host_config_data);
        return NULL;
    }

    cJSON_Delete(content_host_config_json);
    ogs_free(url_path);
    free (content_host_config_data);
    provisioning_session->contentHostingConfiguration = content_hosting_configuration;
    msaf_application_server_state_set(as_state, provisioning_session);
    return content_hosting_configuration;
}

void
msaf_provisioning_session_hash_remove(char *provisioning_session_id)
{
    free_ogs_hash_provisioning_session_t fohps = {
        provisioning_session_id,
        msaf_self()->provisioningSessions_map
    };
    ogs_hash_do(free_ogs_hash_provisioning_session, &fohps, msaf_self()->provisioningSessions_map);
}


/***** Private functions *****/

static int
ogs_hash_do_cert_check(void *rec, const void *key, int klen, const void *value)
{
    return msaf_content_hosting_configuration_certificate_check((msaf_provisioning_session_t*)value);
}


static int
free_ogs_hash_provisioning_session(void *rec, const void *key, int klen, const void *value)
{
    free_ogs_hash_provisioning_session_t *fohps = (free_ogs_hash_provisioning_session_t *)rec;
    if (!strcmp(fohps->provisioning_session, (char *)key)) {

        ogs_hash_set(fohps->hash, key, klen, NULL);
        ogs_free((void*)key);

    }
    return 1;
}

static char*
url_path_create(const char* macro, const char* session_id, const msaf_application_server_node_t *msaf_as)
{
    char* url_path_prefix;
    const char *url_path_prefix_format;
    int i, count = 0;
    int session_id_len = strlen(session_id);
    int macro_len = strlen(macro);

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


static void
tidy_relative_path_re(void)
{
    if (relative_path_re != NULL) {
        regfree(relative_path_re);
        ogs_free(relative_path_re);
        relative_path_re = NULL;
    }
}

static int
uri_relative_check(char *entry_point_path)
{
    int result;

    if (relative_path_re == NULL) {
        relative_path_re = (regex_t*) ogs_calloc(1,sizeof(*relative_path_re));
        ogs_assert(relative_path_re != NULL);
        result = regcomp(relative_path_re, "^[^/#?:]{1,}(/[^#?/]{1,})*(\\?[^#]*)?(#.*)?$", REG_EXTENDED);
        if (result) {
            if (result == REG_ESPACE) {
                ogs_error("Regex error: Out of memory");
            } else {
                ogs_error("Syntax error in the regular expression passed");
            }
            ogs_free(relative_path_re);
            relative_path_re = NULL;
            return 0;
        }
        atexit(tidy_relative_path_re);
    }

    result = regexec(relative_path_re, entry_point_path, 0, NULL, 0);

    if (!result) {
        ogs_info("%s matches the regular expression\n", entry_point_path);
        return 1;
    } else if (result == REG_NOMATCH) {
        ogs_info("%s does not match the regular expression\n", entry_point_path);
        return 0;
    } else {
        char *buffer;
        int length;

        length = regerror(result, relative_path_re, NULL, 0);
        buffer = (char*) ogs_calloc(1, length);
        (void) regerror (result, relative_path_re, buffer, length);
        ogs_error("Regex match failed: %s\n", buffer);
        ogs_free(buffer);
        return 0;
    }
}

/* vim:ts=8:sts=4:sw=4:expandtab:
*/
