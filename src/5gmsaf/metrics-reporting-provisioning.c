
#include "metrics-reporting-provisioning.h"
#include "ogs-core.h"

// Function that takes new metrics_reporting_configuration and assigns ID value
msaf_metrics_reporting_configuration_t *msaf_metrics_reporting_configuration_create()
{
    // Generating Metrics Reporting ID
    ogs_uuid_t uuid;
    char metricsReportingConfigurationId[OGS_UUID_FORMATTED_LENGTH + 1];
    ogs_uuid_get(&uuid);
    ogs_uuid_format(metricsReportingConfigurationId, &uuid);

    OpenAPI_metrics_reporting_configuration_t *metrics_reporting_configuration = OpenAPI_metrics_reporting_configuration_create(
            ogs_strdup(metricsReportingConfigurationId),
            ogs_strdup(scheme),
            ogs_strdup(data_network_name),
            true,
            reporting_interval,
            true,
            sample_percentage,
            url_filters,
            metrics
    );

    msaf_metrics_reporting_configuration_t *msaf_metrics_reporting_configuration;
    // Allocating memory for internal structure "msaf_metrics_reporting_configuration"
    msaf_metrics_reporting_configuration = ogs_calloc(1, sizeof(msaf_metrics_reporting_configuration));
    // Checking if the newly created object is null.
    ogs_assert(msaf_metrics_reporting_configuration);

    msaf_metrics_reporting_configuration->metricsReportingConfigurationId = ogs_strdup(metrics_reporting_configuration->metrics_reporting_configuration_id);
    msaf_metrics_reporting_configuration->scheme = metrics_reporting_configuration->scheme;
    msaf_metrics_reporting_configuration->dataNetworkName = metrics_reporting_configuration->data_network_name;
    msaf_metrics_reporting_configuration->isReportingInterval = metrics_reporting_configuration->is_reporting_interval;
    msaf_metrics_reporting_configuration->reportingInterval = metrics_reporting_configuration->reporting_interval;
    msaf_metrics_reporting_configuration->isSamplePercentage = metrics_reporting_configuration->is_sample_percentage;
    msaf_metrics_reporting_configuration->samplePercentage = metrics_reporting_configuration->sample_percentage;
    msaf_metrics_reporting_configuration->urlFilters = metrics_reporting_configuration->url_filters;
    msaf_metrics_reporting_configuration->metrics =metrics_reporting_configuration->metrics;

    msaf_provisioning_session->certificate_map = msaf_certificate_map();
    // Metrics Provisioning Mapping!
    ogs_hash_set(msaf_self()->metricsProvisioningMap, ogs_strdup(msaf_metrics_reporting_configuration->metricsReportingConfigurationId), OGS_HASH_KEY_STRING, msaf_metrics_reporting_configuration);
    OpenAPI_metrics_reporting_configuration_free(metrics_reporting_configuration);

    return msaf_metrics_reporting_configuration;
}

static const char *calculate_metrics_reporting_configuration_hash(OpenAPI_metrics_reporting_configuration_t *metrics_reporting_configuration)
{
    cJSON *metrics_rep = NULL;
    char *metrics_reporting_configuration_to_hash;
    const char *metrics_reporting_configuration_hashed = NULL;
    metrics_rep = OpenAPI_metrics_reporting_configuration_convertToJSON(metrics_reporting_configuration);
    metrics_reporting_configuration_to_hash = cJSON_Print(metrics_rep);
    cJSON_Delete(metrics_rep);
    metrics_reporting_configuration_hashed = calculate_hash(metrics_reporting_configuration_to_hash);
    ogs_free(metrics_reporting_configuration_to_hash);
    return metrics_reporting_configuration_hashed;
}