/*
License: 5G-MAG Public License (v1.0)
Author: Vuk Stojkovic
Copyright: (C) 2023-2024 Fraunhofer Fokus

For full license terms please see the LICENSE file distributed with this
program. If this file is missing then the license can be retrieved from
https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
*/

#ifndef MSAF_METRICS_REPORTING_CONFIGURATION_H
#define MSAF_METRICS_REPORTING_CONFIGURATION_H
#include "openapi/model/msaf_api_metrics_reporting_configuration.h"


typedef struct msaf_metrics_reporting_configuration_s {
    msaf_api_metrics_reporting_configuration_t *config;
    char *etag;
    time_t receivedTime;
} msaf_metrics_reporting_configuration_t;

extern ogs_hash_t *msaf_metrics_reporting_map();
extern msaf_metrics_reporting_configuration_t* process_and_map_metrics_reporting_configuration(msaf_provisioning_session_t *provisioning_session, msaf_api_metrics_reporting_configuration_t *parsed_config);
extern msaf_metrics_reporting_configuration_t* msaf_metrics_reporting_configuration_retrieve(const msaf_provisioning_session_t *provisioning_session, const char *metrics_configuration_id);
extern cJSON *msaf_metrics_reporting_configuration_convertToJSON(const msaf_metrics_reporting_configuration_t *msaf_metrics_reporting_configuration);
extern int msaf_delete_metrics_configuration(msaf_provisioning_session_t *provisioning_session, const char *metrics_configuration_id);
int update_metrics_configuration(msaf_metrics_reporting_configuration_t *existing_metrics_config, msaf_api_metrics_reporting_configuration_t *updated_config);

#endif //MSAF_METRICS_REPORTING_CONFIGURATION_H
