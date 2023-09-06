/*
License: 5G-MAG Public License (v1.0)
Author: Vuk Stojkovic
Copyright: (C) 2023 Fraunhofer Fokus

For full license terms please see the LICENSE file distributed with this
program. If this file is missing then the license can be retrieved from
https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
*/

#include "ogs-core.h"

#include "provisioning-session.h"
#include "hash.h"
#include "utilities.h"

#include "metrics-reporting-provisioning.h"

typedef struct free_ogs_hash_provisioning_session_metrics_reporting_configuration_s{
    const char *mrc;
    ogs_hash_t *hash;
} free_ogs_hash_provisioning_session_metrics_reporting_configuration_t;

static char *calculate_metrics_reporting_configuration_hash(OpenAPI_metrics_reporting_configuration_t *metricsReportingConfiguration);
static int free_ogs_hash_provisioning_session_metrics_reporting_configuration(void *rec, const void *key, int klen, const void *value);


msaf_metrics_reporting_configuration_t *msaf_metrics_reporting_configuration_create(msaf_provisioning_session_t *provisioning_session,
                                                                                    char *scheme,
                                                                                    char *dataNetworkName,
                                                                                    bool isReportingInterval,
                                                                                    int reportingInterval,
                                                                                    bool isSamplePercentage,
                                                                                    double samplePercentage,
                                                                                    OpenAPI_list_t *urlFilters,
                                                                                    OpenAPI_list_t *metrics)
{
    ogs_uuid_t uuid;
    char id[OGS_UUID_FORMATTED_LENGTH+1];

    ogs_assert(provisioning_session);

    msaf_metrics_reporting_configuration_t *msaf_metrics_reporting_configuration = ogs_calloc(1, sizeof(msaf_metrics_reporting_configuration_t));
    ogs_assert(msaf_metrics_reporting_configuration);

    ogs_uuid_get(&uuid);
    ogs_uuid_format(id, &uuid);

    msaf_metrics_reporting_configuration->config = OpenAPI_metrics_reporting_configuration_create(msaf_strdup(id), scheme, dataNetworkName, isReportingInterval, reportingInterval, isSamplePercentage, samplePercentage, urlFilters, metrics);
    msaf_metrics_reporting_configuration->etag = calculate_metrics_reporting_configuration_hash(msaf_metrics_reporting_configuration->config);
    msaf_metrics_reporting_configuration->receivedTime = time(NULL);

    if (provisioning_session->metricsReportingMap == NULL) {
        provisioning_session->metricsReportingMap = msaf_metrics_reporting_map();
    }

    char *hashKey = msaf_strdup(msaf_metrics_reporting_configuration->config->metrics_reporting_configuration_id);
    ogs_hash_set(provisioning_session->metricsReportingMap, hashKey, OGS_HASH_KEY_STRING, msaf_metrics_reporting_configuration);

    return msaf_metrics_reporting_configuration;
}

msaf_metrics_reporting_configuration_t* msaf_metrics_reporting_configuration_update(const char *metricsReportingConfigurationId,
                                                                                    char *scheme,
                                                                                    char *dataNetworkName,
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

    OpenAPI_metrics_reporting_configuration_free(existing_mrc->config);
    existing_mrc->config = OpenAPI_metrics_reporting_configuration_create(msaf_strdup(metricsReportingConfigurationId), scheme, dataNetworkName, isReportingInterval, reportingInterval, isSamplePercentage, samplePercentage, urlFilters, metrics);
    if (existing_mrc->etag) ogs_free(existing_mrc->etag);
    existing_mrc->etag = calculate_metrics_reporting_configuration_hash(existing_mrc->config);
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
                return (msaf_metrics_reporting_configuration_t*)ogs_hash_this_val(metrics_node);
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
        mrc_json = OpenAPI_metrics_reporting_configuration_convertToJSON(mrc_data->config);
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
	msaf_metrics_reporting_configuration_t *mrc_data;
        ogs_hash_set(fohpsmrc->hash, key, klen, NULL);
	mrc_data = (msaf_metrics_reporting_configuration_t*)value;
	if (mrc_data->config) OpenAPI_metrics_reporting_configuration_free(mrc_data->config);
	if (mrc_data->etag) ogs_free(mrc_data->etag);
        ogs_free(mrc_data);
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

		if (mrc_to_delete->config) OpenAPI_metrics_reporting_configuration_free(mrc_to_delete->config);
		if (mrc_to_delete->etag) ogs_free(mrc_to_delete->etag);
                ogs_free(mrc_to_delete);

                return 0;
            }
        }
    }

    ogs_error("Metrics Reporting Configuration with ID %s not found", metricsReportingConfigurationId);
    return -1;
}
