
#include "metrics-reporting-provisioning.h"
#include "ogs-core.h"


// Function that creates MRC and assigns ID value
msaf_metrics_reporting_configuration_t *msaf_metrics_reporting_configuration_create()
{
    // OpenAPI model used to communicate over M1
    OpenAPI_metrics_reporting_configuration_t *metrics_reporting_configuration;
    // Internal model for application context
    msaf_metrics_reporting_configuration_t *msaf_metrics_reporting_configuration;

    // Generating Metrics Reporting ID and formatting as character array.
    ogs_uuid_t uuid;
    char id[OGS_UUID_FORMATTED_LENGTH + 1];
    ogs_uuid_get(&uuid);
    ogs_uuid_format(id, &uuid);

    // Fetching the fields from M1
    metrics_reporting_configuration = OpenAPI_metrics_reporting_configuration_create(
            ogs_strdup(id),
            ogs_strdup(scheme),
            ogs_strdup(data_network_name),
            true,
            reporting_interval,
            true,
            sample_percentage,
            url_filters,
            metrics
    );

    // Memory allocation for internal model "msaf_metrics_reporting_configuration"
    msaf_metrics_reporting_configuration = ogs_calloc(1, sizeof(msaf_metrics_reporting_configuration));
    // Checking if the newly created object is null.
    ogs_assert(msaf_metrics_reporting_configuration);

    // Fulfilling newly created object
    msaf_metrics_reporting_configuration->metricsReportingConfigurationId = ogs_strdup(metrics_reporting_configuration->metrics_reporting_configuration_id);
    msaf_metrics_reporting_configuration->scheme = metrics_reporting_configuration->scheme;
    msaf_metrics_reporting_configuration->dataNetworkName = metrics_reporting_configuration->data_network_name;
    msaf_metrics_reporting_configuration->isReportingInterval = metrics_reporting_configuration->is_reporting_interval;
    msaf_metrics_reporting_configuration->reportingInterval = metrics_reporting_configuration->reporting_interval;
    msaf_metrics_reporting_configuration->isSamplePercentage = metrics_reporting_configuration->is_sample_percentage;
    msaf_metrics_reporting_configuration->samplePercentage = metrics_reporting_configuration->sample_percentage;
    msaf_metrics_reporting_configuration->urlFilters = metrics_reporting_configuration->url_filters;
    msaf_metrics_reporting_configuration->metrics =metrics_reporting_configuration->metrics;

    OpenAPI_provisioning_session_free(metrics_reporting_configuration);
    return msaf_metrics_reporting_configuration;
}

msaf_metrics_reporting_configuration_t *
msaf_metrics_reporting_configuration_find_by_metricsReportingConfigurationId(const char *metricsReportingConfigurationId)
{
    if (!msaf_self()->metricsReportingConfiguration_map) return NULL;
    return (msaf_metrics_reporting_configuration_t *) ogs_hash_get(msaf_self()->metricsReportingConfiguration_map, metricsReportingConfigurationId, OGS_HASH_KEY_STRING);
}