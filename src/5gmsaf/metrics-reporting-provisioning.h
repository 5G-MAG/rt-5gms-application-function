/*
License: 5G-MAG Public License (v1.0)
Author: Vuk Stojkovic
Copyright: (C) 2023 Fraunhofer Fokus

For full license terms please see the LICENSE file distributed with this
program. If this file is missing then the license can be retrieved from
https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
*/

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
    char *etag;
    time_t receivedTime;
    char *metricsReportingConfigurationHash;
} msaf_metrics_reporting_configuration_t;

extern msaf_metrics_reporting_configuration_t *msaf_metrics_reporting_configuration_create(msaf_provisioning_session_t *provisioning_session,
                                                                                           const char *metricsReportingConfigurationId,
                                                                                           const char *scheme,
                                                                                           const char *dataNetworkName,
                                                                                           bool isReportingInterval,
                                                                                           int reportingInterval,
                                                                                           bool isSamplePercentage,
                                                                                           double samplePercentage,
                                                                                           OpenAPI_list_t *urlFilters,
                                                                                           OpenAPI_list_t *metrics);

extern msaf_metrics_reporting_configuration_t* msaf_metrics_reporting_configuration_update(const char *metricsReportingConfigurationId,
                                                                                           const char *scheme,
                                                                                           const char *dataNetworkName,
                                                                                           bool isReportingInterval,
                                                                                           int reportingInterval,
                                                                                           bool isSamplePercentage,
                                                                                           double samplePercentage,
                                                                                           OpenAPI_list_t *urlFilters,
                                                                                           OpenAPI_list_t *metrics);

extern msaf_metrics_reporting_configuration_t* msaf_metrics_reporting_configuration_retrieve(const char *metricsReportingConfigurationId);
extern cJSON *msaf_metrics_reporting_configuration_get_json(const char *metricsReportingConfigurationId);
extern int msaf_metrics_reporting_configuration_delete(const char *metricsReportingConfigurationId);
extern void msaf_provisioning_session_metrics_reporting_configuration_hash_remove(const char *provisioning_session_id, const char *metricsReportingConfigurationId);
extern int msaf_metrics_reporting_configuration_delete(const char *metricsReportingConfigurationId);
extern ogs_hash_t *msaf_metrics_reporting_map();


#endif //MSAF_METRICS_REPORTING_PROVISIONING_H
