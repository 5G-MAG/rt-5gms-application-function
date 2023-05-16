
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

extern OpenAPI_metrics_reporting_configuration_t *msaf_metrics_reporting_configuration();

#endif //MSAF_METRICS_REPORTING_PROVISIONING_H
