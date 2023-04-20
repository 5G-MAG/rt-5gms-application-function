
#ifndef RT_5GMS_APPLICATION_FUNCTION_METRICS_REPORTING_PROVISIONING_H
#define RT_5GMS_APPLICATION_FUNCTION_METRICS_REPORTING_PROVISIONING_H

#include "openapi/model/metrics_reporting_configuration.h."

typedef struct msaf_metrics_reporting_configuration_s {
    char *metrics_reporting_configuration_id;
    char *scheme;
    char *data_network_name;
    bool is_reporting_interval;
    int reporting_interval;
    bool is_sample_percentage;
    double sample_percentage;
    OpenAPI_list_t *url_filters;
    OpenAPI_list_t *metrics;
    OpenAPI_metrics_reporting_configuration_t *metricsReportingConfiguration;
    time_t metricsReportingConfigurationReceived;
    char *metricsReportingProvisioningHash;
    ogs_hash_t *certificate_map;
    ogs_list_t application_server_states;
    int marked_for_deletion;
} msaf_metrics_reporting_configuration_t;

#endif //RT_5GMS_APPLICATION_FUNCTION_METRICS_REPORTING_PROVISIONING_H
