/*
License: 5G-MAG Public License (v1.0)
Author: Dev Audsin
Copyright: (C) 2022-2023 British Broadcasting Corporation

For full license terms please see the LICENSE file distributed with this
program. If this file is missing then the license can be retrieved from
https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
*/

#include <time.h>
#include "application-server-context.h"
#include "certmgr.h"
#include "consumption-report-configuration.h"
#include "context.h"
#include "utilities.h"
#include "hash.h"
#include "sai-cache.h"

#include "openapi/model/msaf_api_consumption_reporting_configuration.h"
#include "openapi/model/msaf_api_content_hosting_configuration.h"
#include "openapi/model/msaf_api_provisioning_session.h"

#include "provisioning-session.h"

typedef struct free_ogs_hash_provisioning_session_s {
    const char *provisioning_session;
    ogs_hash_t *hash;
} free_ogs_hash_provisioning_session_t;

typedef struct free_ogs_hash_provisioning_session_certificate_s {
    const char *certificate;
    ogs_hash_t *hash;
} free_ogs_hash_provisioning_session_certificate_t;

typedef void (*free_ogs_hash_context_free_value_fn)(void *value);
typedef struct free_ogs_hash_context_s {
    free_ogs_hash_context_free_value_fn value_free_fn;
    ogs_hash_t *hash;
} free_ogs_hash_context_t;

typedef struct msaf_provisioning_session_policy_template_delete_data_s {
    msaf_provisioning_session_t *provisioning_session;
    msaf_policy_template_node_t *policy_template;
} msaf_provisioning_session_policy_template_delete_data_t;

static regex_t *relative_path_re = NULL;

static void safe_ogs_free(void *ptr);
static int ogs_hash_do_cert_check(void *rec, const void *key, int klen, const void *value);
static int free_ogs_hash_entry(void *free_ogs_hash_context, const void *key, int klen, const void *value);
static int free_ogs_hash_provisioning_session(void *rec, const void *key, int klen, const void *value);
static int free_ogs_hash_provisioning_session_certificate(void *rec, const void *key, int klen, const void *value);
static char* url_path_create(const char* macro, const char* session_id, const msaf_application_server_node_t *msaf_as);
static void tidy_relative_path_re(void);
static char *calculate_provisioning_session_hash(msaf_api_provisioning_session_t *provisioning_session);
static ogs_hash_t *msaf_certificate_map();
static ogs_hash_t *msaf_policy_templates_new(void);

static msaf_policy_template_change_state_event_data_t *msaf_policy_template_change_state_event_data_populate(msaf_provisioning_session_t *provisioning_session,  msaf_policy_template_node_t *policy_template, msaf_api_policy_template_state_e new_state, msaf_policy_template_state_change_callback callback, void *user_data);

static void msaf_provisioning_session_policy_template_delete(msaf_provisioning_session_t *msaf_provisioning_session, msaf_policy_template_node_t *policy_template_node, msaf_api_policy_template_state_e new_state, void *user_data);

static int free_ogs_hash_provisioning_session_policy_template(void *rec, const void *key, int klen, const void *value);

/***** Public functions *****/

msaf_api_content_hosting_configuration_t *
msaf_content_hosting_configuration_with_af_unique_cert_id(msaf_provisioning_session_t *provisioning_session)
{

    ogs_assert(provisioning_session);
    msaf_api_content_hosting_configuration_t *chc_with_af_unique_cert_id = NULL;
    OpenAPI_lnode_t *dist_config_node = NULL;
    msaf_api_distribution_configuration_t *dist_config = NULL;
    char *af_unique_cert_id;
    chc_with_af_unique_cert_id = msaf_api_content_hosting_configuration_copyResponse(chc_with_af_unique_cert_id, provisioning_session->contentHostingConfiguration);
    if (chc_with_af_unique_cert_id) {

        OpenAPI_list_for_each(chc_with_af_unique_cert_id->distribution_configurations, dist_config_node) {
            dist_config = (msaf_api_distribution_configuration_t*)dist_config_node->data;
            if (dist_config->certificate_id) {
                af_unique_cert_id = ogs_msprintf("%s:%s", provisioning_session->provisioningSessionId, dist_config->certificate_id);
                ogs_debug("af_unique_cert_id: %s",af_unique_cert_id);
                ogs_free(dist_config->certificate_id);
                dist_config->certificate_id = af_unique_cert_id;
                ogs_debug("dist_config->certificate_id: %s",dist_config->certificate_id);
            }
        }
    }
    return chc_with_af_unique_cert_id;
}

msaf_provisioning_session_t *
msaf_provisioning_session_create(const char *provisioning_session_type, const char *asp_id, const char *external_app_id)
{
    msaf_provisioning_session_t *msaf_provisioning_session;
    ogs_uuid_t uuid;
    char id[OGS_UUID_FORMATTED_LENGTH + 1];
    msaf_api_provisioning_session_t *provisioning_session;
    char *prov_sess_type;

    prov_sess_type = msaf_strdup(provisioning_session_type);
    ogs_uuid_get(&uuid);
    ogs_uuid_format(id, &uuid);
    provisioning_session = msaf_api_provisioning_session_create(msaf_strdup(id), msaf_api_provisioning_session_type_FromString(prov_sess_type), msaf_strdup(asp_id), msaf_strdup(external_app_id), NULL, NULL, NULL, NULL, NULL, NULL);
    ogs_free(prov_sess_type);

    msaf_provisioning_session = ogs_calloc(1, sizeof(msaf_provisioning_session_t));
    ogs_assert(msaf_provisioning_session);
    msaf_provisioning_session->provisioningSessionId = msaf_strdup(provisioning_session->provisioning_session_id);
    msaf_provisioning_session->provisioningSessionType = provisioning_session->provisioning_session_type;
    msaf_provisioning_session->aspId = msaf_strdup(provisioning_session->asp_id);
    msaf_provisioning_session->appId = msaf_strdup(provisioning_session->app_id);
    msaf_provisioning_session->httpMetadata.provisioningSession.received = time(NULL);
    msaf_provisioning_session->httpMetadata.provisioningSession.hash = calculate_provisioning_session_hash(provisioning_session);

    msaf_provisioning_session->certificate_map = msaf_certificate_map();
    msaf_provisioning_session->policy_templates = msaf_policy_templates_new();
    ogs_hash_set(msaf_self()->provisioningSessions_map, msaf_strdup(msaf_provisioning_session->provisioningSessionId), OGS_HASH_KEY_STRING, msaf_provisioning_session);

    msaf_api_provisioning_session_free(provisioning_session);

    return msaf_provisioning_session;
}

void msaf_provisioning_session_free(msaf_provisioning_session_t *provisioning_session)
{
    msaf_application_server_state_ref_node_t *next_as_state_ref, *as_state_ref;

    if (!provisioning_session) return;

    ogs_debug("msaf_provisioning_session_free(%p) [%s]", provisioning_session, provisioning_session->provisioningSessionId);

    if (provisioning_session->certificate_map) {
        free_ogs_hash_context_t fohc = {
            safe_ogs_free,
            provisioning_session->certificate_map
        };
        ogs_hash_do(free_ogs_hash_entry, &fohc, provisioning_session->certificate_map);
        ogs_hash_destroy(provisioning_session->certificate_map);
    }
    safe_ogs_free(provisioning_session->provisioningSessionId);
    safe_ogs_free(provisioning_session->aspId);
    safe_ogs_free(provisioning_session->appId);
    safe_ogs_free(provisioning_session->httpMetadata.provisioningSession.hash);
    if (provisioning_session->contentHostingConfiguration) {
        msaf_api_content_hosting_configuration_free(provisioning_session->contentHostingConfiguration);
    }
    safe_ogs_free(provisioning_session->httpMetadata.contentHostingConfiguration.hash);
    msaf_consumption_report_configuration_deregister(provisioning_session);

    if(provisioning_session->sai_cache)
        msaf_sai_cache_free(provisioning_session->sai_cache);

    if(provisioning_session->policy_templates) 
        msaf_provisioning_session_policy_template_free(provisioning_session->policy_templates);

    ogs_list_for_each_safe(&provisioning_session->application_server_states, next_as_state_ref, as_state_ref) {
        ogs_list_remove(&provisioning_session->application_server_states, as_state_ref);
        ogs_free(as_state_ref);
    }

    ogs_free(provisioning_session);
}

cJSON *
msaf_provisioning_session_get_json(const char *provisioning_session_id)
{

    msaf_provisioning_session_t *msaf_provisioning_session;
    cJSON *provisioning_session_json = NULL;

    msaf_provisioning_session = msaf_provisioning_session_find_by_provisioningSessionId(provisioning_session_id);

    if (msaf_provisioning_session) {
        msaf_api_provisioning_session_t *provisioning_session;
        ogs_hash_index_t *cert_node;

        provisioning_session = ogs_calloc(1,sizeof(*provisioning_session));
        ogs_assert(provisioning_session);

        provisioning_session->provisioning_session_id = msaf_provisioning_session->provisioningSessionId;
        provisioning_session->provisioning_session_type = msaf_provisioning_session->provisioningSessionType;
        provisioning_session->asp_id = msaf_provisioning_session->aspId;
        provisioning_session->app_id = msaf_provisioning_session->appId;

        provisioning_session->server_certificate_ids = (OpenAPI_set_t*)OpenAPI_list_create();
        for (cert_node=ogs_hash_first(msaf_provisioning_session->certificate_map); cert_node; cert_node=ogs_hash_next(cert_node)) {
            ogs_debug("msaf_provisioning_session_get_json: Add cert %s", (const char *)ogs_hash_this_key(cert_node));
            OpenAPI_list_add(provisioning_session->server_certificate_ids, (void*)ogs_hash_this_key(cert_node));
        }

        if (msaf_provisioning_session->policy_templates && ogs_hash_first(msaf_provisioning_session->policy_templates) != NULL) {
            ogs_hash_index_t *pol_node;
            provisioning_session->policy_template_ids = (OpenAPI_set_t*)OpenAPI_list_create();
            for (pol_node=ogs_hash_first(msaf_provisioning_session->policy_templates); pol_node; pol_node=ogs_hash_next(pol_node)) {
                ogs_debug("msaf_provisioning_session_get_json: Add policy template %s", (const char *)ogs_hash_this_key(pol_node));
                OpenAPI_list_add(provisioning_session->policy_template_ids, (void*)ogs_hash_this_key(pol_node));
            }
        }

        provisioning_session_json = msaf_api_provisioning_session_convertResponseToJSON(provisioning_session);

        OpenAPI_list_free(provisioning_session->server_certificate_ids);
        OpenAPI_list_free(provisioning_session->policy_template_ids);
        ogs_free(provisioning_session);
    } else {
        ogs_error("Unable to retrieve Provisioning Session [%s]", provisioning_session_id);
    }
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
    msaf_api_distribution_configuration_t *dist_config = NULL;
    if (provisioning_session->contentHostingConfiguration && provisioning_session->certificate_map) {
        OpenAPI_list_for_each(provisioning_session->contentHostingConfiguration->distribution_configurations, dist_config_node) {
            dist_config = (msaf_api_distribution_configuration_t*)dist_config_node->data;
            if (dist_config->certificate_id) {
                const char *cert =ogs_hash_get(provisioning_session->certificate_map, dist_config->certificate_id, OGS_HASH_KEY_STRING);
                if (cert) {
                    ogs_debug("Matching certificate found: %s", cert);
                } else {
                    ogs_error("No matching certificate found %s", dist_config->certificate_id);
                    return 0;
                }
            }
        }
    }
    return 1;
}

void
msaf_delete_certificates(const char *provisioning_session_id)
{
    msaf_application_server_state_node_t *as_state;

    ogs_list_for_each(&msaf_self()->application_server_states, as_state) {
        resource_id_node_t *upload_certificate, *next_node;

        /* delete certificates already on the AS */
        if (as_state->current_certificates) {
            resource_id_node_t *certificate, *next;

            ogs_list_for_each_safe(as_state->current_certificates, next, certificate){
                char *cert_id;
                char *provisioning_session;
                char *current_cert_id = msaf_strdup(certificate->state);

                provisioning_session = strtok_r(current_cert_id,":",&cert_id);

                if(!strcmp(provisioning_session, provisioning_session_id)) {
                    /* provisioning session matches */
                    resource_id_node_t *delete_cert;
                    delete_cert = ogs_calloc(1, sizeof(resource_id_node_t));
                    ogs_assert(delete_cert);
                    delete_cert->state = msaf_strdup(certificate->state);
                    ogs_list_add(&as_state->delete_certificates, delete_cert);
                }

                if(current_cert_id)
                    ogs_free(current_cert_id);
            }
        }

        /* remove entries from upload queue and try to delete just to be safe */
        ogs_list_for_each_safe(&as_state->upload_certificates, next_node, upload_certificate) {
            char *cert_id;
            char *upload_cert_id = msaf_strdup(upload_certificate->state);
            char *provisioning_session = strtok_r(upload_cert_id,":",&cert_id);

            if (!strcmp(provisioning_session, provisioning_session_id)) {
                ogs_list_remove(&as_state->upload_certificates, upload_certificate);
                ogs_list_add(&as_state->delete_certificates, upload_certificate);
            }
            if (upload_cert_id)
                ogs_free(upload_cert_id);
        }
    }
}

void
msaf_delete_content_hosting_configuration(const char *provisioning_session_id)
{

    msaf_application_server_state_node_t *as_state;
    ogs_list_for_each(&msaf_self()->application_server_states, as_state) {

        resource_id_node_t *content_hosting_configuration, *next = NULL;
        resource_id_node_t *upload_content_hosting_configuration, *next_node = NULL;
        resource_id_node_t *delete_chc = NULL;

        ogs_list_init(&as_state->delete_content_hosting_configurations);

        if (as_state->current_content_hosting_configurations) {

            ogs_list_for_each_safe(as_state->current_content_hosting_configurations, next, content_hosting_configuration){

                if (!strcmp(content_hosting_configuration->state, provisioning_session_id))
                    break;
            }
            if (content_hosting_configuration) {
                delete_chc = ogs_calloc(1, sizeof(resource_id_node_t));
                ogs_assert(delete_chc);
                delete_chc->state = msaf_strdup(content_hosting_configuration->state);
                ogs_list_add(&as_state->delete_content_hosting_configurations, delete_chc);

            }
        }

        ogs_list_for_each_safe(&as_state->upload_content_hosting_configurations, next_node, upload_content_hosting_configuration){
            if (!strcmp(upload_content_hosting_configuration->state, provisioning_session_id))
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

msaf_policy_template_node_t *
msaf_provisioning_session_find_policy_template_by_id(msaf_provisioning_session_t *provisioning_session, const char *policy_template_id)
{
    if(!provisioning_session->policy_templates)	return NULL;
    return (msaf_policy_template_node_t *) ogs_hash_get(provisioning_session->policy_templates, policy_template_id, OGS_HASH_KEY_STRING);
}

msaf_policy_template_node_t *msaf_provisioning_session_get_policy_template_by_id(const char *provisioning_session_id, const char *policy_template_id) {
    msaf_provisioning_session_t *provisioning_session;

    provisioning_session = msaf_provisioning_session_find_by_provisioningSessionId(provisioning_session_id);
    if(!provisioning_session) return NULL;
    return msaf_provisioning_session_find_policy_template_by_id(provisioning_session, policy_template_id);
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
    msaf_api_distribution_configuration_t *dist_config = NULL;

    ogs_assert(provisioning_session);

    certs = (ogs_list_t*) ogs_calloc(1,sizeof(*certs));
    ogs_assert(certs);
    ogs_list_init(certs);
    if (provisioning_session->contentHostingConfiguration && provisioning_session->certificate_map) {
        OpenAPI_list_for_each(provisioning_session->contentHostingConfiguration->distribution_configurations, dist_config_node) {
            dist_config = (msaf_api_distribution_configuration_t*)dist_config_node->data;
            if (dist_config->certificate_id) {
                const char *cert = ogs_hash_get(provisioning_session->certificate_map, dist_config->certificate_id, OGS_HASH_KEY_STRING);
                if (cert){
                    certificate = ogs_calloc(1, sizeof(resource_id_node_t));
                    ogs_assert(certificate);
                    char *provisioning_session_id_plus_cert_id = ogs_msprintf("%s:%s", provisioning_session->provisioningSessionId, dist_config->certificate_id);
                    certificate->state = provisioning_session_id_plus_cert_id;
                    ogs_list_add(certs, certificate);
                } else {
                    ogs_warn("Certificate id [%s] not found for Content Hosting Configuration [%s]", dist_config->certificate_id, provisioning_session->provisioningSessionId);
                    resource_id_node_t *next;
                    ogs_list_for_each_safe(certs, next, certificate) {
                        ogs_list_remove(certs, certificate);
                        if (certificate->state) ogs_free(certificate->state);
                        ogs_free(certificate);
                    }
                    ogs_free(certs);
                    certs = NULL;
                    break;
                }
            }
        }
    }
    return certs;
}

int
msaf_distribution_create(cJSON *content_hosting_config, msaf_provisioning_session_t *provisioning_session, const char **reason_ret)
{
    OpenAPI_lnode_t *dist_config_node = NULL;
    msaf_api_distribution_configuration_t *dist_config = NULL;
    char *url_path;
    char *domain_name;
    static const char macro[] = "{provisioningSessionId}";
    msaf_application_server_node_t *msaf_as = NULL;
    char *content_hosting_config_to_hash = NULL;

    msaf_as = ogs_list_first(&msaf_self()->config.applicationServers_list);

    url_path = url_path_create(macro, provisioning_session->provisioningSessionId, msaf_as);

    msaf_api_content_hosting_configuration_t *content_hosting_configuration
        = msaf_api_content_hosting_configuration_parseRequestFromJSON(content_hosting_config, reason_ret);

    if (!content_hosting_configuration) {
        if (reason_ret) {
            ogs_error("JSON validation of ContentHostingConfiguration failed: %s", *reason_ret);
        } else {
            ogs_error("JSON validation of ContentHostingConfiguration failed");
        }
        cJSON_Delete(content_hosting_config);
        ogs_free(url_path);
        return 0;
    }

    if (content_hosting_configuration->distribution_configurations) {
        OpenAPI_list_for_each(content_hosting_configuration->distribution_configurations, dist_config_node) {
            char *protocol = "http";

            dist_config = (msaf_api_distribution_configuration_t*)dist_config_node->data;

            if(dist_config->entry_point && !uri_relative_check(dist_config->entry_point->relative_path)) {
                if (reason_ret) *reason_ret = "distributionConfiguration.entryPoint.relativePath malformed";
                ogs_error("distributionConfiguration.entryPoint.relativePath malformed for Provisioning Session [%s]", provisioning_session->provisioningSessionId);
                cJSON_Delete(content_hosting_config);
                ogs_free(url_path);
                if (content_hosting_configuration) msaf_api_content_hosting_configuration_free(content_hosting_configuration);
                return 0;
            }

            if (dist_config->entry_point && dist_config->entry_point->profiles && dist_config->entry_point->profiles->first == NULL) {
                if (reason_ret) *reason_ret = "distributionConfiguration.entryPoint.profiles present but empty";
                ogs_error("distributionConfiguration.entryPoint.profiles present but empty for Provisioning Session [%s]", provisioning_session->provisioningSessionId);
                cJSON_Delete(content_hosting_config);
                ogs_free(url_path);
                if (content_hosting_configuration) msaf_api_content_hosting_configuration_free(content_hosting_configuration);
                return 0;
            }

            if (dist_config->canonical_domain_name) ogs_free(dist_config->canonical_domain_name);

            dist_config->canonical_domain_name = msaf_strdup(msaf_as->canonicalHostname);

            if (dist_config->certificate_id) {
                protocol = "https";
            }

            if(dist_config->domain_name_alias){
                domain_name = dist_config->domain_name_alias;
            } else {
                domain_name = dist_config->canonical_domain_name;
            }

            if(dist_config->base_url) ogs_free(dist_config->base_url);

            dist_config->base_url = ogs_msprintf("%s://%s%s", protocol, domain_name, url_path);
        } 
    } else {
        ogs_error("The Content Hosting Configuration has no distributionConfigurations for Provisioning Session [%s]", provisioning_session->provisioningSessionId);
    }

    /* reset Service Access Information cache */
    msaf_sai_cache_clear(provisioning_session->sai_cache);

    if (provisioning_session->contentHostingConfiguration)
        msaf_api_content_hosting_configuration_free(provisioning_session->contentHostingConfiguration);
    provisioning_session->contentHostingConfiguration = content_hosting_configuration;
    if (provisioning_session->contentHostingConfiguration)
    {
        content_hosting_config_to_hash = cJSON_Print(content_hosting_config);
        provisioning_session->httpMetadata.contentHostingConfiguration.received = time(NULL);

        if (provisioning_session->httpMetadata.contentHostingConfiguration.hash)
            ogs_free(provisioning_session->httpMetadata.contentHostingConfiguration.hash);
        provisioning_session->httpMetadata.contentHostingConfiguration.hash = calculate_hash(content_hosting_config_to_hash);
        cJSON_free(content_hosting_config_to_hash);
    }
    ogs_free(url_path);
    cJSON_Delete(content_hosting_config);

    return 1;
}

cJSON *msaf_get_content_hosting_configuration_by_provisioning_session_id(const char *provisioning_session_id) {
    msaf_provisioning_session_t *msaf_provisioning_session;
    cJSON *content_hosting_configuration_json = NULL;

    msaf_provisioning_session = msaf_provisioning_session_find_by_provisioningSessionId(provisioning_session_id);

    if(msaf_provisioning_session && msaf_provisioning_session->contentHostingConfiguration)
    {
       content_hosting_configuration_json = msaf_api_content_hosting_configuration_convertResponseToJSON(msaf_provisioning_session->contentHostingConfiguration);
    } else {
        ogs_error("Unable to retrieve ContentHostingConfiguration for Provisioning Session [%s]", provisioning_session_id);
    }
    return content_hosting_configuration_json;
}

void
msaf_provisioning_session_hash_remove(const char *provisioning_session_id)
{
    free_ogs_hash_provisioning_session_t fohps = {
        provisioning_session_id,
        msaf_self()->provisioningSessions_map
    };
    ogs_hash_do(free_ogs_hash_provisioning_session, &fohps, msaf_self()->provisioningSessions_map);
}

void
msaf_provisioning_session_certificate_hash_remove(const char *provisioning_session_id, const char *certificate_id)
{
    msaf_provisioning_session_t *provisioning_session = NULL;
    provisioning_session = msaf_provisioning_session_find_by_provisioningSessionId(provisioning_session_id);

    free_ogs_hash_provisioning_session_certificate_t fohpsc = {
        certificate_id,
        provisioning_session->certificate_map
    };
    ogs_hash_do(free_ogs_hash_provisioning_session_certificate, &fohpsc, provisioning_session->certificate_map);
}

int uri_relative_check(const char *entry_point_path)
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
        ogs_debug("%s matches the regular expression\n", entry_point_path);
        return 1;
    } else if (result == REG_NOMATCH) {
        ogs_debug("%s does not match the regular expression\n", entry_point_path);
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

char *enumerate_provisioning_sessions(void)
{
    ogs_hash_index_t *hi;
    char *provisioning_sessions = "[]";
    int number_of_provisioning_sessions = ogs_hash_count(msaf_self()->provisioningSessions_map);
    if (number_of_provisioning_sessions)
    {
        provisioning_sessions = ogs_calloc(1, (4 + (sizeof(char)*(OGS_UUID_FORMATTED_LENGTH + 1) *number_of_provisioning_sessions) +1));
        provisioning_sessions[0] = '[';

        for (hi = ogs_hash_first(msaf_self()->provisioningSessions_map); hi; hi = ogs_hash_next(hi)) {
            const char *key = NULL;
            const char *val = NULL;
            char *provisioning_session = NULL;
            key = ogs_hash_this_key(hi);
            ogs_assert(key);
            val = ogs_hash_this_val(hi);
            ogs_assert(val);
            provisioning_session = ogs_msprintf("\"%s\", ", key);
            strcat(provisioning_sessions, provisioning_session);
            ogs_free(provisioning_session);
        }
        provisioning_sessions[strlen(provisioning_sessions) - 2] = ']';
        provisioning_sessions[strlen(provisioning_sessions) - 1] = '\0';
    }
    return provisioning_sessions;

}

bool msaf_provisioning_session_add_policy_template(msaf_provisioning_session_t *provisioning_session, msaf_api_policy_template_t *policy_template, time_t creation_time) {
    
    ogs_uuid_t uuid;
    char id[OGS_UUID_FORMATTED_LENGTH + 1];
    msaf_policy_template_node_t *msaf_policy_template;

    ogs_uuid_get(&uuid);
    ogs_uuid_format(id, &uuid);

    msaf_policy_template_set_id(policy_template, id);
    
    msaf_policy_template = msaf_policy_template_populate(policy_template, creation_time);
    if(!msaf_policy_template) return false;

    ogs_hash_set(provisioning_session->policy_templates, msaf_strdup(id), OGS_HASH_KEY_STRING, msaf_policy_template);

    if(!msaf_provisioning_session_send_policy_template_state_change_event(provisioning_session, msaf_policy_template, msaf_api_policy_template_STATE_PENDING, NULL, NULL))
        return false;

    return true;

}

bool msaf_provisioning_session_update_policy_template(msaf_provisioning_session_t *provisioning_session, msaf_policy_template_node_t *msaf_policy_template, msaf_api_policy_template_t *policy_template) {
    
    char *policy_template_id;	
    ogs_assert(provisioning_session);
    ogs_assert(msaf_policy_template);
    ogs_assert(policy_template);

    policy_template_id = msaf_strdup(msaf_policy_template->policy_template->policy_template_id);

    msaf_policy_template_free(msaf_policy_template->policy_template);
    msaf_policy_template->policy_template = policy_template;
    msaf_policy_template->policy_template->policy_template_id = policy_template_id;
    if(!msaf_provisioning_session_send_policy_template_state_change_event(provisioning_session, msaf_policy_template, msaf_api_policy_template_STATE_PENDING, NULL, NULL))
        return false;

    return true;
}

bool msaf_provisioning_session_send_policy_template_state_change_event(msaf_provisioning_session_t *provisioning_session,  msaf_policy_template_node_t *policy_template, msaf_api_policy_template_state_e new_state, msaf_policy_template_state_change_callback callback, void *user_data)
{
    msaf_event_t *event;
    int rv;	    

    ogs_assert(provisioning_session);
    ogs_assert(policy_template);

    event = (msaf_event_t*)ogs_event_new(MSAF_EVENT_SBI_LOCAL);
    event->local_id = MSAF_LOCAL_EVENT_POLICY_TEMPLATE_STATE_CHANGE;
    event->data = msaf_policy_template_change_state_event_data_populate(provisioning_session, policy_template, new_state, callback, user_data);

    rv = ogs_queue_push(ogs_app()->queue, event);
    if (rv !=OGS_OK) {
        ogs_error("OGS Queue Push failed %d", rv);
        ogs_event_free(event);
        return false;
    }
    return true;

}

bool msaf_provisioning_session_delete_policy_template(msaf_provisioning_session_t *provisioning_session, msaf_policy_template_node_t *policy_template)
{
   if(!policy_template || !policy_template->policy_template) return false;

   if(!msaf_provisioning_session_delete_policy_template_by_id(provisioning_session, policy_template->policy_template->policy_template_id))
       return false;
   return true;
}

bool msaf_provisioning_session_delete_policy_template_by_id(msaf_provisioning_session_t *provisioning_session, const char *policy_template_id) {
    msaf_policy_template_node_t *msaf_policy_template;
    msaf_provisioning_session_policy_template_delete_data_t *msaf_provisioning_session_policy_template_delete_data;

    msaf_policy_template = msaf_provisioning_session_find_policy_template_by_id(provisioning_session, policy_template_id);

    if (!msaf_policy_template) return false;

    msaf_provisioning_session_policy_template_delete_data = (msaf_provisioning_session_policy_template_delete_data_t*)ogs_calloc(1,sizeof(*msaf_provisioning_session_policy_template_delete_data));

    ogs_assert(msaf_provisioning_session_policy_template_delete_data);

    msaf_provisioning_session_policy_template_delete_data->provisioning_session = provisioning_session;
    msaf_provisioning_session_policy_template_delete_data->policy_template = msaf_policy_template;

    if (!msaf_provisioning_session_send_policy_template_state_change_event(provisioning_session, msaf_policy_template, msaf_api_policy_template_STATE_NULL, msaf_provisioning_session_policy_template_delete, msaf_provisioning_session_policy_template_delete_data))
        return false;

    return true;
}

void msaf_provisioning_session_policy_template_free(ogs_hash_t *policy_templates)
{
    msaf_policy_template_clear(policy_templates);
    ogs_hash_destroy(policy_templates);
}

OpenAPI_list_t *msaf_provisioning_session_get_id_of_policy_templates_in_ready_state(msaf_provisioning_session_t *provisioning_session) {
        return get_id_of_policy_templates_in_ready_state(provisioning_session->policy_templates);
}

OpenAPI_list_t *msaf_provisioning_session_get_external_reference_of_policy_templates_in_ready_state(msaf_provisioning_session_t *provisioning_session) {
    return get_external_reference_of_policy_templates_in_ready_state(provisioning_session->policy_templates);
}



/**********************************************************
 * Private functions
 **********************************************************/

static ogs_hash_t *msaf_policy_templates_new(void)
{
    ogs_hash_t *policy_templates = ogs_hash_make();
    return policy_templates;
}

static msaf_policy_template_change_state_event_data_t *msaf_policy_template_change_state_event_data_populate(msaf_provisioning_session_t *provisioning_session,  msaf_policy_template_node_t *policy_template, msaf_api_policy_template_state_e new_state, msaf_policy_template_state_change_callback callback, void *user_data)
{
    msaf_policy_template_change_state_event_data_t *msaf_policy_template_change_state_event_data;

    msaf_policy_template_change_state_event_data = ogs_calloc(1, sizeof(msaf_policy_template_change_state_event_data_t));
    ogs_assert(msaf_policy_template_change_state_event_data);

    msaf_policy_template_change_state_event_data->provisioning_session = provisioning_session;
    msaf_policy_template_change_state_event_data->policy_template_node = policy_template;
    msaf_policy_template_change_state_event_data->new_state = new_state;
    msaf_policy_template_change_state_event_data->callback = callback;
    msaf_policy_template_change_state_event_data->callback_user_data = user_data;
    
    return msaf_policy_template_change_state_event_data; 

}

static void msaf_provisioning_session_policy_template_delete(msaf_provisioning_session_t *msaf_provisioning_session, msaf_policy_template_node_t *policy_template_node, msaf_api_policy_template_state_e new_state, void *user_data)
{
    ogs_assert(msaf_provisioning_session);
    ogs_assert(policy_template_node);
    ogs_assert(user_data);
    
    ogs_hash_do(free_ogs_hash_provisioning_session_policy_template, user_data, msaf_provisioning_session->policy_templates);
}   

static int
free_ogs_hash_provisioning_session_policy_template(void *rec, const void *key, int klen, const void *value)
{

    msaf_provisioning_session_policy_template_delete_data_t *msaf_provisioning_session_policy_template_delete_data =
                (msaf_provisioning_session_policy_template_delete_data_t *)rec;
    msaf_provisioning_session_t *provisioning_session = msaf_provisioning_session_policy_template_delete_data->provisioning_session;
    msaf_policy_template_node_t *msaf_policy_template = msaf_provisioning_session_policy_template_delete_data->policy_template;

/*    if (!strcmp(msaf_policy_template->policy_template->policy_template_id, (char *)key)) {*/
    if (value == msaf_policy_template) {
        msaf_policy_template_node_free(msaf_policy_template);
        ogs_hash_set(provisioning_session->policy_templates, key, klen, NULL);
        ogs_free((void*)key);
        return 0; /* finish search when the first key matches */
    }

    return 1;
}

static void safe_ogs_free(void *ptr)
{
    if (!ptr) return;
    ogs_free(ptr);
}

static ogs_hash_t *
msaf_certificate_map(void)
{
    ogs_hash_t *certificate_map = ogs_hash_make();
    return certificate_map;
}

static char *calculate_provisioning_session_hash(msaf_api_provisioning_session_t *provisioning_session)
{
    cJSON *provisioning_sess = NULL;
    char *provisioning_session_to_hash;
    char *provisioning_session_hashed = NULL;
    provisioning_sess = msaf_api_provisioning_session_convertResponseToJSON(provisioning_session);
    provisioning_session_to_hash = cJSON_Print(provisioning_sess);
    cJSON_Delete(provisioning_sess);
    provisioning_session_hashed = calculate_hash(provisioning_session_to_hash);
    cJSON_free(provisioning_session_to_hash);
    return provisioning_session_hashed;
}

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

static int
free_ogs_hash_provisioning_session_certificate(void *rec, const void *key, int klen, const void *value)
{
    free_ogs_hash_provisioning_session_certificate_t *fohpsc = (free_ogs_hash_provisioning_session_certificate_t *)rec;
    if (!strcmp(fohpsc->certificate, (char *)key)) {

        ogs_hash_set(fohpsc->hash, key, klen, NULL);
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
free_ogs_hash_entry(void *rec, const void *key, int klen, const void *value)
{
    free_ogs_hash_context_t *fohc = (free_ogs_hash_context_t*)rec;
    fohc->value_free_fn((void*)value);
    ogs_hash_set(fohc->hash, key, klen, NULL);
    ogs_free((void*)key);
    return 1;
}

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
