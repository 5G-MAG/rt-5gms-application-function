
#ifndef RT_5GMS_APPLICATION_FUNCTION_METRICS_REPORTING_PROVISIONING_H
#define RT_5GMS_APPLICATION_FUNCTION_METRICS_REPORTING_PROVISIONING_H

#include "openapi/model/service_access_information_resource_client_metrics_reporting_configuration.h"

typedef struct msaf_metrics_reporting_configuration_s {
    char *metricsReportingConfigurationId;
    OpenAPI_list_t *serverAddresses;
    char *scheme;
    char *dataNetworkName;
    bool is_reporting_interval;
    int reportingInterval;
    double samplePercentage;
    OpenAPI_list_t *urlFilters;
    OpenAPI_list_t *metrics;
} msaf_metrics_reporting_configuration_t;

#endif //RT_5GMS_APPLICATION_FUNCTION_METRICS_REPORTING_PROVISIONING_H
