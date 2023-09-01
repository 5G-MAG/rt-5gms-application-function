/*
License: 5G-MAG Public License (v1.0)
Author: Vuk Stojkovic
Copyright: (C) 2023 Fraunhofer Fokus

For full license terms please see the LICENSE file distributed with this
program. If this file is missing then the license can be retrieved from
https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
*/

#include "metrics-reporting-provisioning.h"
#include "openapi/model/metrics_reporting_configuration.c"
#include "provisioning-session.h"

typedef struct free_ogs_hash_provisioning_session_metrics_reporting_configuration_s{
    const char *mrc;
    ogs_hash_t *hash;
} free_ogs_hash_provisioning_session_metrics_reporting_configuration_t;

static int free_ogs_hash_provisioning_session_metrics_reporting_configuration(void *rec, const void *key, int klen, const void *value);


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

    msaf_metrics_reporting_configuration_t *msaf_metrics_reporting_configuration = ogs_calloc(1, sizeof(msaf_metrics_reporting_configuration_t));
    ogs_assert(msaf_metrics_reporting_configuration);

    msaf_metrics_reporting_configuration->metricsReportingConfigurationId = msaf_strdup(metricsReportingConfigurationId);
    msaf_metrics_reporting_configuration->scheme = msaf_strdup(scheme);
    msaf_metrics_reporting_configuration->dataNetworkName = msaf_strdup(dataNetworkName);
    msaf_metrics_reporting_configuration->isReportingInterval = isReportingInterval;
    msaf_metrics_reporting_configuration->reportingInterval = reportingInterval;
    msaf_metrics_reporting_configuration->isSamplePercentage = isSamplePercentage;
    msaf_metrics_reporting_configuration->samplePercentage = samplePercentage;
    msaf_metrics_reporting_configuration->urlFilters = urlFilters;
    msaf_metrics_reporting_configuration->metrics = metrics;
    msaf_metrics_reporting_configuration->etag = NULL;
    msaf_metrics_reporting_configuration->receivedTime = time(NULL);
    msaf_metrics_reporting_configuration->metricsReportingConfigurationHash = calculate_metrics_reporting_configuration_hash(msaf_metrics_reporting_configuration);  // Assuming this function doesn't leak

    if (provisioning_session->metricsReportingMap == NULL) {
        provisioning_session->metricsReportingMap = ogs_hash_make();
    }

    char *hashKey = msaf_strdup(msaf_metrics_reporting_configuration->metricsReportingConfigurationId);
    ogs_hash_set(provisioning_session->metricsReportingMap, hashKey, OGS_HASH_KEY_STRING, msaf_metrics_reporting_configuration);

    provisioning_session->metricsReportingConfigurationId = msaf_strdup(msaf_metrics_reporting_configuration->metricsReportingConfigurationId);

    return msaf_metrics_reporting_configuration;
}

msaf_metrics_reporting_configuration_t* msaf_metrics_reporting_configuration_update(const char *metricsReportingConfigurationId,
                                                                                    const char *scheme,
                                                                                    const char *dataNetworkName,
                                                                                    bool isReportingInterval,
                                                                                    int reportingInterval,
                                                                                    bool isSamplePercentage,
                                                                                    double samplePercentage,
                                                                                    OpenAPI_list_t *urlFilters,
                                                                                    OpenAPI_list_t *metrics)
{
    msaf_metrics_reporting_configuration_t *existing_mrc = msaf_metrics_reporting_configuration_retrieve(metricsReportingConfigurationId);

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

    if (existing_mrc->urlFilters) {
        OpenAPI_list_free(existing_mrc->urlFilters);
    }
    existing_mrc->urlFilters = urlFilters;

    if (existing_mrc->metrics) {
        OpenAPI_list_free(existing_mrc->metrics);
    }

    existing_mrc->metrics = metrics;
    existing_mrc->receivedTime = time(NULL);

    return existing_mrc;
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


msaf_metrics_reporting_configuration_t* msaf_metrics_reporting_configuration_retrieve(const char *metricsReportingConfigurationId) {
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

    mrc_data = msaf_metrics_reporting_configuration_retrieve(metrics_reporting_configuration_id);

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

static int
free_ogs_hash_provisioning_session_metrics_reporting_configuration(void *rec, const void *key, int klen, const void *value)
{
    free_ogs_hash_provisioning_session_metrics_reporting_configuration_t *fohpsmrc = (free_ogs_hash_provisioning_session_metrics_reporting_configuration_t *)rec;
    if (!strcmp(fohpsmrc->mrc, (char *)key)) {
        ogs_hash_set(fohpsmrc->hash, key, klen, NULL);
        ogs_free((void*)key);
    }
    return 1;
}

void
msaf_provisioning_session_metrics_reporting_configuration_hash_remove(const char *provisioning_session_id, const char *metricsReportingConfigurationId)
{
    msaf_provisioning_session_t *provisioning_session = NULL;
    provisioning_session = msaf_provisioning_session_find_by_provisioningSessionId(provisioning_session_id);

    free_ogs_hash_provisioning_session_metrics_reporting_configuration_t fohpsmrc = {
            metricsReportingConfigurationId,
            provisioning_session->metricsReportingMap
    };
    ogs_hash_do(free_ogs_hash_provisioning_session_metrics_reporting_configuration,
                &fohpsmrc,
                provisioning_session->metricsReportingMap);
}

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

                ogs_hash_set(provisioning_session->metricsReportingMap, currentMetricsId, OGS_HASH_KEY_STRING, NULL);

                ogs_free(mrc_to_delete->metricsReportingConfigurationId);
                ogs_free(mrc_to_delete->scheme);
                ogs_free(mrc_to_delete->dataNetworkName);
                ogs_free(mrc_to_delete);

                return 0;
            }
        }
    }

    ogs_error("Metrics Reporting Configuration with ID %s not found", metricsReportingConfigurationId);
    return -1;
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