/*
License: 5G-MAG Public License (v1.0)
Author: David Waring
Copyright: (C) 2023 British Broadcasting Corporation

For full license terms please see the LICENSE file distributed with this
program. If this file is missing then the license can be retrieved from
https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
*/

#ifndef MSAF_CONSUMPTION_REPORT_CONFIGURATION_H
#define MSAF_CONSUMPTION_REPORT_CONFIGURATION_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct msaf_api_consumption_reporting_configuration_s msaf_api_consumption_reporting_configuration_t;
typedef struct msaf_provisioning_session_s msaf_provisioning_session_t;

extern bool msaf_consumption_report_configuration_register(msaf_provisioning_session_t *session /* [no-transfer, not-null] */,
                                                msaf_api_consumption_reporting_configuration_t *config /* [transfer, not-null] */);
extern bool msaf_consumption_report_configuration_update(msaf_provisioning_session_t *session /* [no-transfer, not-null] */,
                                                msaf_api_consumption_reporting_configuration_t *config /* [transfer, not-null] */);
extern bool msaf_consumption_report_configuration_deregister(msaf_provisioning_session_t *session /* [no-transfer, not-null] */);

extern msaf_api_consumption_reporting_configuration_t *msaf_consumption_report_configuration_parseJSON(
                                                cJSON *json /* [no-transfer, not-null] */, const char **err_out /* [out, not-null] */);
extern cJSON *msaf_consumption_report_configuration_json(msaf_provisioning_session_t *session /* [no-transfer, not-null] */);
extern char *msaf_consumption_report_configuration_body(msaf_provisioning_session_t *session /* [no-transfer, not-null] */);
extern time_t msaf_consumption_report_configuration_last_modified(
                                        msaf_provisioning_session_t *session /* [no-transfer, not-null] */);
extern char *msaf_consumption_report_configuration_etag(msaf_provisioning_session_t *session /* [no-transfer, not-null] */);

extern bool msaf_consumption_report_configuration_changed(msaf_provisioning_session_t *session /* [no-transfer, not-null] */,
                                                          time_t modified_since, const char *none_match /* [null] */);

#ifdef __cplusplus
}
#endif

/* vim:ts=8:sts=4:sw=4:expandtab:
 */

#endif /* MSAF_CONSUMPTION_REPORT_CONFIGURATION_H */
