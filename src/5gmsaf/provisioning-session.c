/*
License: 5G-MAG Public License (v1.0)
Author: Dev Audsin
Copyright: (C) 2022 British Broadcasting Corporation

For full license terms please see the LICENSE file distributed with this
program. If this file is missing then the license can be retrieved from
https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
*/

#include <time.h>
#include "application-server-context.h"
#include "certmgr.h"
#include "context.h"
#include "utilities.h"
#include "hash.h"
#include "provisioning-session.h"
#include "openapi/model/metrics_reporting_configuration.c"

typedef struct free_ogs_hash_provisioning_session_s {
    const char *provisioning_session;
    ogs_hash_t *hash;
} free_ogs_hash_provisioning_session_t;

typedef struct free_ogs_hash_provisioning_session_certificate_s {
    const char *certificate;
    ogs_hash_t *hash;
} free_ogs_hash_provisioning_session_certificate_t;

typedef struct free_ogs_hash_provisioning_session_mrc_s{
    const char *mrc;
    ogs_hash_t *hash;
} free_ogs_hash_provisioning_session_mrc_t;

static regex_t *relative_path_re = NULL;

static int ogs_hash_do_cert_check(void *rec, const void *key, int klen, const void *value);
static int free_ogs_hash_provisioning_session(void *rec, const void *key, int klen, const void *value);
static int free_ogs_hash_provisioning_session_certificate(void *rec, const void *key, int klen, const void *value);
static int free_ogs_hash_provisioning_session_mrc(void *rec, const void *key, int klen, const void *value);

static char* url_path_create(const char* macro, const char* session_id, const msaf_application_server_node_t *msaf_as);
static void tidy_relative_path_re(void);
static char *calculate_provisioning_session_hash(OpenAPI_provisioning_session_t *provisioning_session);
static char *calculate_service_access_information_hash(OpenAPI_service_access_information_resource_t *service_access_information);
static char *calculate_metrics_reporting_configuration_hash(OpenAPI_metrics_reporting_configuration_t *metricsReportingConfiguration);

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
                ogs_debug("af_unique_cert_id: %s",af_unique_cert_id);
                ogs_free(dist_config->certificate_id);
                dist_config->certificate_id = af_unique_cert_id;
                ogs_debug("dist_config->certificate_id: %s",dist_config->certificate_id);
            }
        }
    }
    return chc_with_af_unique_cert_id;
}

msaf_provisioning_session_t *msaf_provisioning_session_create(const char *provisioning_session_type, const char *asp_id, const char *external_app_id)
{
    msaf_provisioning_session_t *msaf_provisioning_session;
    ogs_uuid_t uuid;
    char id[OGS_UUID_FORMATTED_LENGTH + 1];
    OpenAPI_provisioning_session_t *provisioning_session;
    char *prov_sess_type;

    prov_sess_type = msaf_strdup(provisioning_session_type);
    ogs_uuid_get(&uuid);
    ogs_uuid_format(id, &uuid);
    provisioning_session = OpenAPI_provisioning_session_create(msaf_strdup(id),
                                                               OpenAPI_provisioning_session_type_FromString(prov_sess_type),
                                                               msaf_strdup(asp_id),
                                                               msaf_strdup(external_app_id),
                                                               NULL,
                                                               NULL,
                                                               NULL,
                                                               NULL,
                                                               NULL,
                                                               NULL);
    ogs_free(prov_sess_type);

    msaf_provisioning_session = ogs_calloc(1, sizeof(msaf_provisioning_session_t));
    ogs_assert(msaf_provisioning_session);

    msaf_provisioning_session->provisioningSessionId = msaf_strdup(provisioning_session->provisioning_session_id);
    msaf_provisioning_session->provisioningSessionType = provisioning_session->provisioning_session_type;
    msaf_provisioning_session->aspId = msaf_strdup(provisioning_session->asp_id);
    msaf_provisioning_session->externalApplicationId = msaf_strdup(provisioning_session->external_application_id);
    msaf_provisioning_session->provisioningSessionReceived = time(NULL);
    msaf_provisioning_session->provisioningSessionHash = calculate_provisioning_session_hash(provisioning_session);

    msaf_provisioning_session->certificate_map = msaf_certificate_map();
    msaf_provisioning_session->metricsReportingMap = msaf_metrics_reporting_map();

    ogs_hash_set(msaf_self()->provisioningSessions_map,
                 msaf_strdup(msaf_provisioning_session->provisioningSessionId),
                 OGS_HASH_KEY_STRING, msaf_provisioning_session);

    OpenAPI_provisioning_session_free(provisioning_session);
    return msaf_provisioning_session;
}

msaf_metrics_reporting_configuration_t *msaf_metrics_reporting_configuration_create(msaf_provisioning_session_t *provisioning_session,
                                                                                    const char *metricsReportingConfigurationId,
                                                                                    const char *scheme,
                                                                                    const char *dataNetworkName,
                                                                                    bool isReportingInterval,
                                                                                    int reportingInterval,
                                                                                    bool isSamplePercentage,
                                                                                    double samplePercentage,
                                                                                    OpenAPI_list_t *urlFilters,
                                                                                    OpenAPI_list_t *metrics)
{

    ogs_assert(provisioning_session);
    msaf_metrics_reporting_configuration_t *msaf_metrics_reporting_configuration;

    OpenAPI_metrics_reporting_configuration_t *metricsReportingConfiguration;

    metricsReportingConfiguration = OpenAPI_metrics_reporting_configuration_create(msaf_strdup(metricsReportingConfigurationId),
                                                                                   msaf_strdup(scheme),
                                                                                   msaf_strdup(dataNetworkName),
                                                                                   isReportingInterval,
                                                                                   reportingInterval,
                                                                                   isSamplePercentage,
                                                                                   samplePercentage,
                                                                                   urlFilters,
                                                                                   metrics);

    msaf_metrics_reporting_configuration = ogs_calloc(1, sizeof(msaf_metrics_reporting_configuration_t));
    ogs_assert(msaf_metrics_reporting_configuration);

    msaf_metrics_reporting_configuration->metricsReportingConfigurationId = msaf_strdup(metricsReportingConfigurationId);
    msaf_metrics_reporting_configuration->scheme = msaf_strdup(metricsReportingConfiguration->scheme);
    msaf_metrics_reporting_configuration->dataNetworkName = msaf_strdup(metricsReportingConfiguration->data_network_name);
    msaf_metrics_reporting_configuration->isReportingInterval = metricsReportingConfiguration->is_reporting_interval;
    msaf_metrics_reporting_configuration->reportingInterval = metricsReportingConfiguration->reporting_interval;
    msaf_metrics_reporting_configuration->isSamplePercentage = metricsReportingConfiguration->is_sample_percentage;
    msaf_metrics_reporting_configuration->samplePercentage = metricsReportingConfiguration->sample_percentage;
    msaf_metrics_reporting_configuration->urlFilters = metricsReportingConfiguration->url_filters;
    msaf_metrics_reporting_configuration->metrics = metricsReportingConfiguration->metrics;
    msaf_metrics_reporting_configuration->etag = NULL;
    msaf_metrics_reporting_configuration->receivedTime = time(NULL);
    msaf_metrics_reporting_configuration->metricsReportingConfigurationHash = calculate_metrics_reporting_configuration_hash(metricsReportingConfiguration);

    if (provisioning_session->metricsReportingMap == NULL) {
        provisioning_session->metricsReportingMap = ogs_hash_make();
    }

    ogs_hash_set(provisioning_session->metricsReportingMap,
                 msaf_strdup(msaf_metrics_reporting_configuration->metricsReportingConfigurationId),
                 OGS_HASH_KEY_STRING,
                 msaf_metrics_reporting_configuration);

    provisioning_session->metricsReportingConfigurationId = msaf_strdup(msaf_metrics_reporting_configuration->metricsReportingConfigurationId);
    return msaf_metrics_reporting_configuration;
}

msaf_metrics_reporting_configuration_t* mrc_update(const char *metricsReportingConfigurationId,
                                                   const char *scheme,
                                                   const char *dataNetworkName,
                                                   bool isReportingInterval,
                                                   int reportingInterval,
                                                   bool isSamplePercentage,
                                                   double samplePercentage,
                                                   OpenAPI_list_t *urlFilters,
                                                   OpenAPI_list_t *metrics)
{
    msaf_metrics_reporting_configuration_t *existing_mrc = mrc_retrieve(metricsReportingConfigurationId);
    if (!existing_mrc) {
        ogs_error("Metrics Reporting Configuration with ID %s not found", metricsReportingConfigurationId);
        return NULL;
    }

    ogs_free(existing_mrc->scheme);
    existing_mrc->scheme = msaf_strdup(scheme);

    ogs_free(existing_mrc->dataNetworkName);
    existing_mrc->dataNetworkName = msaf_strdup(dataNetworkName);

    existing_mrc->isReportingInterval = isReportingInterval;
    existing_mrc->reportingInterval = reportingInterval;
    existing_mrc->isSamplePercentage = isSamplePercentage;
    existing_mrc->samplePercentage = samplePercentage;
    existing_mrc->urlFilters = urlFilters;
    existing_mrc->metrics = metrics;

    existing_mrc->receivedTime = time(NULL);

    return existing_mrc;
}



msaf_metrics_reporting_configuration_t* mrc_retrieve(const char *metricsReportingConfigurationId) {
    ogs_hash_index_t *provisioning_node;
    ogs_hash_index_t *metrics_node;

    if (!metricsReportingConfigurationId) {
        return NULL;
    }

    for (provisioning_node = ogs_hash_first(msaf_self()->provisioningSessions_map); provisioning_node; provisioning_node = ogs_hash_next(provisioning_node)) {
        msaf_provisioning_session_t *provisioning_session = ogs_hash_this_val(provisioning_node);

        for (metrics_node = ogs_hash_first(provisioning_session->metricsReportingMap); metrics_node; metrics_node = ogs_hash_next(metrics_node)) {
            char *currentMetricsId = (char *)ogs_hash_this_key(metrics_node);
            if (strcmp(currentMetricsId, metricsReportingConfigurationId) == 0) {
                return ogs_hash_this_val(metrics_node);
            }
        }
    }

    return NULL;
}

cJSON *msaf_metrics_reporting_configuration_get_json(const char *metrics_reporting_configuration_id) {

    msaf_metrics_reporting_configuration_t *mrc_data;
    cJSON *mrc_json = NULL;

    mrc_data = mrc_retrieve(metrics_reporting_configuration_id);

    if (mrc_data) {
        OpenAPI_metrics_reporting_configuration_t *metrics_reporting_configuration = ogs_calloc(1, sizeof(OpenAPI_metrics_reporting_configuration_t));
        ogs_assert(metrics_reporting_configuration);

        metrics_reporting_configuration->metrics_reporting_configuration_id = mrc_data->metricsReportingConfigurationId;
        metrics_reporting_configuration->scheme = mrc_data->scheme;
        metrics_reporting_configuration->data_network_name = mrc_data->dataNetworkName;
        metrics_reporting_configuration->is_reporting_interval = mrc_data->isReportingInterval;
        metrics_reporting_configuration->reporting_interval = mrc_data->reportingInterval;
        metrics_reporting_configuration->is_sample_percentage = mrc_data->isSamplePercentage;
        metrics_reporting_configuration->sample_percentage = mrc_data->samplePercentage;
        metrics_reporting_configuration->url_filters = mrc_data->urlFilters;
        metrics_reporting_configuration->metrics = mrc_data->metrics;

        mrc_json = OpenAPI_metrics_reporting_configuration_convertToJSON(metrics_reporting_configuration);
        ogs_free(metrics_reporting_configuration);
    } else {
        ogs_error("Unable to retrieve Metrics Reporting Configuration [%s]", metrics_reporting_configuration_id);
    }
    return mrc_json;
}

ogs_hash_t *
msaf_metrics_reporting_map(void)
{
    ogs_hash_t *metricsReportingMap = ogs_hash_make();
    return metricsReportingMap;
}


/*int msaf_metrics_reporting_configuration_delete(const char *metricsReportingConfigurationId)
{
    msaf_application_server_state_node_t *as_state;
    int result = -1;

    ogs_list_for_each(&msaf_self()->application_server_states, as_state) {

        resource_id_node_t *current_mrc, *next = NULL;
        resource_id_node_t *upload_mrc, *next_node = NULL;
        resource_id_node_t *delete_mrc = NULL;

        ogs_list_init(&as_state->delete_mrcs);

        if (&as_state->current_mrcs) {
            ogs_list_for_each_safe(&as_state->current_mrcs, next, current_mrc){
                if (!strcmp(current_mrc->state, metricsReportingConfigurationId))
                    break;
            }
            if (current_mrc) {
                delete_mrc = ogs_calloc(1, sizeof(resource_id_node_t));
                ogs_assert(delete_mrc);
                delete_mrc->state = msaf_strdup(current_mrc->state);
                ogs_list_add(&as_state->delete_mrcs, delete_mrc);
                result = 0;
            }
        }
        ogs_list_for_each_safe(&as_state->upload_mrcs, next_node, upload_mrc) {
            if (!strcmp(upload_mrc->state, metricsReportingConfigurationId))
                break;
        }
        if (upload_mrc) {
            ogs_list_remove(&as_state->upload_mrcs, upload_mrc);
            ogs_list_add(&as_state->delete_mrcs, upload_mrc);
            result = 0;
        }
        next_action_for_application_server(as_state);
    }
    return result;
}*/

int msaf_metrics_reporting_configuration_delete(const char *metricsReportingConfigurationId) {
    ogs_hash_index_t *provisioning_node;
    ogs_hash_index_t *metrics_node;

    if (!metricsReportingConfigurationId) {
        ogs_error("Metrics Reporting Configuration ID is NULL");
        return -1;
    }

    for (provisioning_node = ogs_hash_first(msaf_self()->provisioningSessions_map); provisioning_node; provisioning_node = ogs_hash_next(provisioning_node)) {
        msaf_provisioning_session_t *provisioning_session = ogs_hash_this_val(provisioning_node);

        for (metrics_node = ogs_hash_first(provisioning_session->metricsReportingMap); metrics_node; metrics_node = ogs_hash_next(metrics_node)) {
            char *currentMetricsId = (char *)ogs_hash_this_key(metrics_node);
            if (strcmp(currentMetricsId, metricsReportingConfigurationId) == 0) {
                msaf_metrics_reporting_configuration_t *mrc_to_delete = ogs_hash_this_val(metrics_node);

                // Remove from hash map
                ogs_hash_set(provisioning_session->metricsReportingMap, currentMetricsId, OGS_HASH_KEY_STRING, NULL);

                ogs_free(mrc_to_delete->metricsReportingConfigurationId);
                ogs_free(mrc_to_delete->scheme);
                ogs_free(mrc_to_delete->dataNetworkName);
                ogs_free(mrc_to_delete);

                return 0; // Successfully deleted
            }
        }
    }

    ogs_error("Metrics Reporting Configuration with ID %s not found", metricsReportingConfigurationId);
    return -1; // Not found
}

cJSON *
msaf_provisioning_session_get_json(const char *provisioning_session_id)
{

    msaf_provisioning_session_t *msaf_provisioning_session;
    cJSON *provisioning_session_json = NULL;

    msaf_provisioning_session = msaf_provisioning_session_find_by_provisioningSessionId(provisioning_session_id);

    if (msaf_provisioning_session) {
        OpenAPI_provisioning_session_t *provisioning_session;
        ogs_hash_index_t *cert_node;
        ogs_hash_index_t *metrics_node;

        provisioning_session = ogs_calloc(1,sizeof(OpenAPI_provisioning_session_t));
        ogs_assert(provisioning_session);

        provisioning_session->provisioning_session_id = msaf_provisioning_session->provisioningSessionId;
        provisioning_session->provisioning_session_type = msaf_provisioning_session->provisioningSessionType;
        provisioning_session->asp_id = msaf_provisioning_session->aspId;
        provisioning_session->external_application_id = msaf_provisioning_session->externalApplicationId;

        provisioning_session->server_certificate_ids = (OpenAPI_set_t*)OpenAPI_list_create();
        for (cert_node=ogs_hash_first(msaf_provisioning_session->certificate_map); cert_node; cert_node=ogs_hash_next(cert_node)) {
            ogs_debug("msaf_provisioning_session_get_json: Add cert %s", (const char *)ogs_hash_this_key(cert_node));
            OpenAPI_list_add(provisioning_session->server_certificate_ids, (void*)ogs_hash_this_key(cert_node));
        }

        cJSON *metrics_reporting_configurations_json = cJSON_CreateArray();
        for (metrics_node=ogs_hash_first(msaf_provisioning_session->metricsReportingMap); metrics_node; metrics_node = ogs_hash_next(metrics_node)) {
            const char *config_id = (const char *)ogs_hash_this_key(metrics_node);
            cJSON *config_json = msaf_metrics_reporting_configuration_get_json(config_id);
            if (config_json) {
                cJSON_AddItemToArray(metrics_reporting_configurations_json, config_json);
            }
        }

        provisioning_session_json = OpenAPI_provisioning_session_convertToJSON(provisioning_session);
        cJSON_AddItemToObject(provisioning_session_json, "metricsReportingConfigurations", metrics_reporting_configurations_json);

        OpenAPI_list_free(provisioning_session->server_certificate_ids);
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
    OpenAPI_distribution_configuration_t *dist_config = NULL;
    if (provisioning_session->contentHostingConfiguration && provisioning_session->certificate_map) {
        OpenAPI_list_for_each(provisioning_session->contentHostingConfiguration->distribution_configurations, dist_config_node) {
            dist_config = (OpenAPI_distribution_configuration_t*)dist_config_node->data;
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

ogs_hash_t *
msaf_certificate_map(void)
{
    ogs_hash_t *certificate_map = ogs_hash_make();
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
msaf_distribution_create(cJSON *content_hosting_config, msaf_provisioning_session_t *provisioning_session)
{
    OpenAPI_lnode_t *dist_config_node = NULL;
    OpenAPI_lnode_t *media_entry_point_profile_node = NULL;
    OpenAPI_distribution_configuration_t *dist_config = NULL;
    char *url_path;
    char *domain_name;
    static const char macro[] = "{provisioningSessionId}";
    msaf_application_server_node_t *msaf_as = NULL;
    char *content_hosting_config_to_hash = NULL;
    OpenAPI_list_t *media_entry_point_list;
    OpenAPI_list_t *media_entry_point_profiles_list = NULL;
    OpenAPI_m5_media_entry_point_t *entry_point;
    char *locator_absolute_path;

    msaf_as = ogs_list_first(&msaf_self()->config.applicationServers_list);

    url_path = url_path_create(macro, provisioning_session->provisioningSessionId, msaf_as);

    OpenAPI_content_hosting_configuration_t *content_hosting_configuration
            = OpenAPI_content_hosting_configuration_parseFromJSON(content_hosting_config);

    if (content_hosting_configuration->distribution_configurations) {
        media_entry_point_list = OpenAPI_list_create();
        OpenAPI_list_for_each(content_hosting_configuration->distribution_configurations, dist_config_node) {
            char *protocol = "http";

            dist_config = (OpenAPI_distribution_configuration_t*)dist_config_node->data;

            if(dist_config->entry_point && !uri_relative_check(dist_config->entry_point->relative_path)) {
                OpenAPI_lnode_t *node;
                ogs_error("distributionConfiguration.entryPoint.relativePath malformed for Provisioning Session [%s]", provisioning_session->provisioningSessionId);
                cJSON_Delete(content_hosting_config);
                ogs_free(url_path);
                OpenAPI_list_for_each(media_entry_point_list, node) {
                    OpenAPI_m5_media_entry_point_free(node->data);
                }
                OpenAPI_list_free(media_entry_point_list);
                if (content_hosting_configuration) OpenAPI_content_hosting_configuration_free(content_hosting_configuration);
                return 0;
            }

            if (dist_config->entry_point && dist_config->entry_point->profiles && dist_config->entry_point->profiles->first == NULL) {
                OpenAPI_lnode_t *node;
                ogs_error("distributionConfiguration.entryPoint.profiles present but empty for Provisioning Session [%s]", provisioning_session->provisioningSessionId);
                cJSON_Delete(content_hosting_config);
                ogs_free(url_path);
                OpenAPI_list_for_each(media_entry_point_list, node) {
                    OpenAPI_m5_media_entry_point_free(node->data);
                }
                OpenAPI_list_free(media_entry_point_list);
                if (content_hosting_configuration) OpenAPI_content_hosting_configuration_free(content_hosting_configuration);
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

            if (dist_config->entry_point) {
                locator_absolute_path = ogs_msprintf("%s%s", dist_config->base_url, dist_config->entry_point->relative_path);
                if(dist_config->entry_point->profiles){
                    media_entry_point_profiles_list = OpenAPI_list_create();
                    OpenAPI_list_for_each(dist_config->entry_point->profiles, media_entry_point_profile_node) {
                        OpenAPI_list_add(media_entry_point_profiles_list, msaf_strdup((char *)media_entry_point_profile_node->data));
                    }
                } else {
                    media_entry_point_profiles_list = NULL;
                }

                entry_point = OpenAPI_m5_media_entry_point_create(locator_absolute_path, msaf_strdup(dist_config->entry_point->content_type), media_entry_point_profiles_list);
                OpenAPI_list_add(media_entry_point_list, entry_point);
            }
        }
    } else {
        ogs_error("The Content Hosting Configuration has no distributionConfigurations for Provisioning Session [%s]", provisioning_session->provisioningSessionId);
    }

    if (provisioning_session->serviceAccessInformation)
        OpenAPI_service_access_information_resource_free(provisioning_session->serviceAccessInformation);
    provisioning_session->serviceAccessInformation = msaf_context_service_access_information_create(provisioning_session->provisioningSessionId, media_entry_point_list);
    provisioning_session->serviceAccessInformationCreated = time(NULL);
    if (provisioning_session->serviceAccessInformationHash)
        ogs_free(provisioning_session->serviceAccessInformationHash);
    provisioning_session->serviceAccessInformationHash = calculate_service_access_information_hash(provisioning_session->serviceAccessInformation);

    if (provisioning_session->contentHostingConfiguration)
        OpenAPI_content_hosting_configuration_free(provisioning_session->contentHostingConfiguration);
    provisioning_session->contentHostingConfiguration = content_hosting_configuration;
    if (provisioning_session->contentHostingConfiguration)
    {
        content_hosting_config_to_hash = cJSON_Print(content_hosting_config);
        provisioning_session->contentHostingConfigurationReceived = time(NULL);

        if (provisioning_session->contentHostingConfigurationHash)
            ogs_free(provisioning_session->contentHostingConfigurationHash);
        provisioning_session->contentHostingConfigurationHash = calculate_hash(content_hosting_config_to_hash);
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
        content_hosting_configuration_json = OpenAPI_content_hosting_configuration_convertToJSON(msaf_provisioning_session->contentHostingConfiguration);
    } else {
        ogs_error("Unable to retrieve Provisioning Session [%s]", provisioning_session_id);
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

void
msaf_provisioning_session_mrc_hash_remove(const char *provisioning_session_id, const char *metricsReportingConfigurationId)
{
    msaf_provisioning_session_t *provisioning_session = NULL;
    provisioning_session = msaf_provisioning_session_find_by_provisioningSessionId(provisioning_session_id);

    free_ogs_hash_provisioning_session_mrc_t fohpsmrc = {
            metricsReportingConfigurationId,
            provisioning_session->metricsReportingMap
    };
    ogs_hash_do(free_ogs_hash_provisioning_session_mrc,
                &fohpsmrc,
                provisioning_session->metricsReportingMap);
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

static char *calculate_provisioning_session_hash(OpenAPI_provisioning_session_t *provisioning_session)
{
    cJSON *provisioning_sess = NULL;
    char *provisioning_session_to_hash;
    char *provisioning_session_hashed = NULL;
    provisioning_sess = OpenAPI_provisioning_session_convertToJSON(provisioning_session);
    provisioning_session_to_hash = cJSON_Print(provisioning_sess);
    cJSON_Delete(provisioning_sess);
    provisioning_session_hashed = calculate_hash(provisioning_session_to_hash);
    cJSON_free(provisioning_session_to_hash);
    return provisioning_session_hashed;
}

static char *calculate_service_access_information_hash(OpenAPI_service_access_information_resource_t *service_access_information)
{
    cJSON *service_access_info = NULL;
    char *service_access_information_to_hash;
    char *service_access_information_hashed = NULL;
    service_access_info = OpenAPI_service_access_information_resource_convertToJSON(service_access_information);
    service_access_information_to_hash = cJSON_Print(service_access_info);
    cJSON_Delete(service_access_info);
    service_access_information_hashed = calculate_hash(service_access_information_to_hash);
    cJSON_free(service_access_information_to_hash);
    return service_access_information_hashed;
}

static char *calculate_metrics_reporting_configuration_hash(OpenAPI_metrics_reporting_configuration_t *metricsReportingConfiguration)
{
    cJSON *metrics_reporting_config = NULL;
    char *metricsReportingConfiguration_to_hash;
    char *metricsReportingConfiguration_hashed = NULL;
    metrics_reporting_config = OpenAPI_metrics_reporting_configuration_convertToJSON(metricsReportingConfiguration);
    metricsReportingConfiguration_to_hash = cJSON_Print(metrics_reporting_config);
    cJSON_Delete(metrics_reporting_config);
    metricsReportingConfiguration_hashed = calculate_hash(metricsReportingConfiguration_to_hash);
    cJSON_free(metricsReportingConfiguration_to_hash);
    return metricsReportingConfiguration_hashed;
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

static int
free_ogs_hash_provisioning_session_mrc(void *rec, const void *key, int klen, const void *value)
{
    free_ogs_hash_provisioning_session_mrc_t *fohpsmrc = (free_ogs_hash_provisioning_session_mrc_t *)rec;
    if (!strcmp(fohpsmrc->mrc, (char *)key)) {
        ogs_hash_set(fohpsmrc->hash, key, klen, NULL);
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

/* vim:ts=8:sts=4:sw=4:expandtab:
 */