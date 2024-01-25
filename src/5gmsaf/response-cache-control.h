/*
License: 5G-MAG Public License (v1.0)
Author: Dev Audsin
Copyright: (C) 2022 British Broadcasting Corporation

For full license terms please see the LICENSE file distributed with this
program. If this file is missing then the license can be retrieved from
https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
*/

#ifndef MSAF_RESPONSE_CACHE_CONTROL_H
#define MSAF_RESPONSE_CACHE_CONTROL_H

#include "ogs-app.h"

#define SERVER_RESPONSE_MAX_AGE 60
#define M1_CONTENT_PROTOCOLS_RESPONSE_MAX_AGE 86400

#ifdef __cplusplus
extern "C" {
#endif

typedef struct msaf_server_response_cache_control_s {
    int m1_provisioning_session_response_max_age;
    int m1_content_hosting_configurations_response_max_age;
    int m1_server_certificates_response_max_age;
    int m1_content_protocols_response_max_age;
    int m1_consumption_reporting_response_max_age;
    int m5_service_access_information_response_max_age;
}msaf_server_response_cache_control_t;

extern void msaf_server_response_cache_control_set(void);
extern void msaf_server_response_cache_control_set_from_config(int m1_provisioning_session_response_max_age, int m1_content_hosting_configurations_response_max_age, int m1_server_certificates_response_max_age, int m1_content_protocols_response_max_age, int m1_consumption_reporting_response_max_age, int m5_service_access_information_response_max_age);


#ifdef __cplusplus
}
#endif

#endif /* MSAF_RESPONSE_CACHE_CONTROL_H */
