/*
License: 5G-MAG Public License (v1.0)
Author: Vuk Stojkovic
Copyright: (C) 2023-2024 Fraunhofer Fokus

For full license terms please see the LICENSE file distributed with this
program. If this file is missing then the license can be retrieved from
https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
*/

#ifndef MSAF_METRICS_REPORTING_PROVISIONING_H
#define MSAF_METRICS_REPORTING_PROVISIONING_H
#include "openapi/model/msaf_api_metrics_reporting_configuration.h"


typedef struct msaf_metrics_reporting_configuration_s {
    msaf_api_metrics_reporting_configuration_t *config;
    char *etag;
    time_t receivedTime;
} msaf_metrics_reporting_configuration_t;

extern ogs_hash_t *msaf_metrics_reporting_map();
msaf_metrics_reporting_configuration_t *msaf_metrics_reporting_configuration_create(msaf_provisioning_session_t *provisioning_session,
                                                                                    char *scheme,
                                                                                    char *data_network_name,
                                                                                    bool is_reporting_interval,
                                                                                    int reporting_interval,
                                                                                    bool is_sample_percentage,
                                                                                    double sample_percentage,
                                                                                    OpenAPI_list_t *url_filters,
                                                                                    int sampling_period,
                                                                                    OpenAPI_list_t *metrics);


extern msaf_metrics_reporting_configuration_t* msaf_metrics_reporting_configuration_retrieve(const char *metricsReportingConfigurationId);
extern cJSON *msaf_metrics_reporting_configuration_get_json(const char *metrics_reporting_configuration_id);

#endif //MSAF_METRICS_REPORTING_PROVISIONING_H
