
#include "metrics-reporting-provisioning.h"
#include "ogs-core.h"

msaf_metrics_reporting_configuration_t *msaf_metrics_reporting_configuration_create(
        OpenAPI_list_t *server_addresses,
        char *scheme,
        char *data_network_name,
        bool is_reporting_interval,
        int reporting_interval,
        double sample_percentage,
        OpenAPI_list_t *url_filters,
        OpenAPI_list_t *metrics
) {

    // Generating ID values
    msaf_metrics_reporting_configuration_t *msaf_metrics_reporting_configuration;
    ogs_uuid_t uuid;
    char metrics_reporting_configuration_id[OGS_UUID_FORMATTED_LENGTH + 1];
    OpenAPI_metrics_reporting_configuration_t *metrics_reporting_configuration;


    ogs_uuid_get(&uuid);
    ogs_uuid_format(metrics_reporting_configuration_id, &uuid);

    // Invoking the function defined in openapi/models interface
    metrics_reporting_configuration = OpenAPI_service_access_information_resource_client_metrics_reporting_configuration_create(
            ogs_strdup(metrics_reporting_configuration_id),
            ogs_strdup(scheme),
            ogs_strdup(data_network_name),
            reporting_interval,
            sample_percentage,
            url_filters,
            metrics
    );

    msaf_metrics_reporting_configuration = ogs_calloc(1, sizeof(msaf_metrics_reporting_configuration_t));

    // Checking if memory allocation was successful
    ogs_assert(msaf_metrics_reporting_configuration);

    msaf_metrics_reporting_configuration->metricsReportingConfigurationId = ogs_strdup(metrics_reporting_configuration->metrics_reporting_configuration_id);
    msaf_metrics_reporting_configuration->scheme = ogs_strdup(metrics_reporting_configuration->scheme);
    msaf_metrics_reporting_configuration->dataNetworkName = ogs_strdup(metrics_reporting_configuration->data_network_name);
    msaf_metrics_reporting_configuration->reportingInterval = metrics_reporting_configuration->reporting_interval;
    msaf_metrics_reporting_configuration->samplePercentage = metrics_reporting_configuration->sample_percentage;
    msaf_metrics_reporting_configuration->urlFilters = ogs_list_copy(metrics_reporting_configuration->url_filters);
    msaf_metrics_reporting_configuration->metrics = ogs_list_copy(metrics_reporting_configuration->metrics);

    OpenAPI_service_access_information_resource_client_metrics_reporting_configuration_free(metrics_reporting_configuration);
    return msaf_metrics_reporting_configuration;
}
msaf_metrics_reporting_configuration_t *
msaf_metrics_configuration_find_by_Id(const char *metrics_reporting_configuration_id)
{
    // TBD!
    return 0;
}


/*cJSON *metrics_reporting_get_json(msaf_metrics_reporting_configuration_t *msaf_metrics_reporting_configuration)
{
    if (!msaf_metrics_reporting_configuration)
    {
        return NULL;
    }

    OpenAPI_metrics_reporting_configuration_t *metrics_reporting_configuration = OpenAPI_service_access_information_resource_client_metrics_reporting_configuration_create(
            ogs_strdup(msaf_metrics_reporting_configuration->metricsReportingConfigurationId),
            ogs_strdup(msaf_metrics_reporting_configuration->scheme),
            ogs_strdup(msaf_metrics_reporting_configuration->dataNetworkName),
            msaf_metrics_reporting_configuration->reportingInterval,
            msaf_metrics_reporting_configuration->samplePercentage,
            msaf_metrics_reporting_configuration->urlFilters,
            msaf_metrics_reporting_configuration->metrics
    );

    cJSON *metrics_reportingJSON = OpenAPI_service_access_information_resource_client_metrics_reporting_configuration_convertToJSON(metrics_reporting_configuration);

    OpenAPI_service_access_information_resource_client_metrics_reporting_configuration_free(metrics_reporting_configuration);

    if (!metrics_reportingJSON)
    {
        return NULL;
    }

    return metrics_reportingJSON;
}*/