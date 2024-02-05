 /*
License: 5G-MAG Public License (v1.0)
Author: Vuk Stojkovic
Copyright: (C) 2023-2024 Fraunhofer Fokus

For full license terms please see the LICENSE file distributed with this
program. If this file is missing then the license can be retrieved from
https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
*/

#include "ogs-core.h"
#include "hash.h"
#include "utilities.h"
#include "provisioning-session.h"
#include "metrics-reporting-configuration.h"


static char *calculate_metrics_reporting_configuration_hash(msaf_api_metrics_reporting_configuration_t *metricsReportingConfiguration);

/* Auxiliary functions */
ogs_hash_t *
msaf_metrics_reporting_map(void)
{
    ogs_hash_t *metrics_reporting_map = ogs_hash_make();
    return metrics_reporting_map;
}

static char *calculate_metrics_reporting_configuration_hash(msaf_api_metrics_reporting_configuration_t *metricsReportingConfiguration)
{
    cJSON *metrics_reporting_config = NULL;
    char *metricsReportingConfiguration_to_hash;
    char *metricsReportingConfiguration_hashed = NULL;
    metrics_reporting_config = msaf_api_metrics_reporting_configuration_convertToJSON(metricsReportingConfiguration, NULL);
    metricsReportingConfiguration_to_hash = cJSON_Print(metrics_reporting_config);
    cJSON_Delete(metrics_reporting_config);
    metricsReportingConfiguration_hashed = calculate_hash(metricsReportingConfiguration_to_hash);
    cJSON_free(metricsReportingConfiguration_to_hash);
    return metricsReportingConfiguration_hashed;
}

msaf_metrics_reporting_configuration_t *msaf_metrics_reporting_configuration_create(msaf_provisioning_session_t *provisioning_session,
                                                                                    char *scheme,
                                                                                    char *data_network_name,
                                                                                    bool is_reporting_interval,
                                                                                    int reporting_interval,
                                                                                    bool is_sample_percentage,
                                                                                    double sample_percentage,
                                                                                    OpenAPI_list_t *url_filters,
                                                                                    int sampling_period,
                                                                                    OpenAPI_list_t *metrics) {


    ogs_uuid_t uuid;
    char id[OGS_UUID_FORMATTED_LENGTH+1];
    const char *parse_err = NULL;
    ogs_assert(provisioning_session);

    ogs_uuid_get(&uuid);
    ogs_uuid_format(id, &uuid);

    msaf_api_metrics_reporting_configuration_t *mrc = msaf_api_metrics_reporting_configuration_create(
            msaf_strdup(id),
            scheme,
            data_network_name,
            is_reporting_interval,
            reporting_interval,
            is_sample_percentage,
            sample_percentage,
            url_filters,
            sampling_period,
            metrics
    );

    if (mrc == NULL) {
        ogs_error("Failed to parse metrics reporting configuration: %s", parse_err);
        return NULL;
    }

    /* Internal msaf_metrics_reporting_configuration object */
    msaf_metrics_reporting_configuration_t *msaf_metrics_reporting_configuration = ogs_calloc(1, sizeof(msaf_metrics_reporting_configuration_t));
    ogs_assert(msaf_metrics_reporting_configuration);
    msaf_metrics_reporting_configuration->config = mrc;
    msaf_metrics_reporting_configuration->config->metrics_reporting_configuration_id = msaf_strdup(id);
    /* ETag & Received time */
    msaf_metrics_reporting_configuration->etag = calculate_metrics_reporting_configuration_hash(msaf_metrics_reporting_configuration->config);
    msaf_metrics_reporting_configuration->receivedTime = time(NULL);

    /* Mapping */
    if (provisioning_session->metrics_reporting_map == NULL) {
        provisioning_session->metrics_reporting_map = msaf_metrics_reporting_map();
    }

    char *hashKey = msaf_strdup(msaf_metrics_reporting_configuration->config->metrics_reporting_configuration_id);
    ogs_hash_set(provisioning_session->metrics_reporting_map,
                 hashKey,
                 OGS_HASH_KEY_STRING,
                 msaf_metrics_reporting_configuration);

    return msaf_metrics_reporting_configuration;
}

 void msaf_metrics_reporting_configuration_free(msaf_metrics_reporting_configuration_t *config) {
     if (config) {

         ogs_free(config->config->metrics_reporting_configuration_id);
         msaf_api_metrics_reporting_configuration_free(config->config);
         ogs_free(config);
     }
 }


