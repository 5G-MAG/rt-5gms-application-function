#ifndef MSAF_METRICS_REPORTING_PROVISIONING_H
#define MSAF_METRICS_REPORTING_PROVISIONING_H

#include "openapi/model/metrics_reporting_configuration.h"

typedef struct msaf_metrics_reporting_configuration_s {
    char *metricsReportingConfigurationId;
    char *scheme;
    char *dataNetworkName;
    bool isReportingInterval;
    int reportingInterval;
    bool isSamplePercentage;
    double samplePercentage;
    OpenAPI_list_t *urlFilters;
    OpenAPI_list_t *metrics;
} msaf_metrics_reporting_configuration_t;

// Functions declarations
msaf_metrics_reporting_configuration_t *msaf_metrics_reporting_configuration_create();
void msaf_delete_metrics_reporting_configuration(const char *provisioning_session_id);
msaf_metrics_reporting_configuration_t *msaf_metrics_reporting_configuration_find_by_metricsReportingConfigurationId(const char *metricsReportingConfigurationId);
cJSON *msaf_get_metrics_reporting_configuration_by_provisioning_session_id(const char *provisioning_session_id);

#endif //MSAF_METRICS_REPORTING_PROVISIONING_H
