/*
License: 5G-MAG Public License (v1.0)
Author: Dev Audsin
Copyright: (C) 2022 British Broadcasting Corporation

For full license terms please see the LICENSE file distributed with this
program. If this file is missing then the license can be retrieved from
https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
*/

#include "context.h"
#include "response-cache-control.h"

void msaf_server_response_cache_control_set(void)
{
    msaf_server_response_cache_control_t *server_response_cache_control = NULL;
    server_response_cache_control = ogs_calloc(1, sizeof(msaf_server_response_cache_control_t));
    ogs_assert(server_response_cache_control);
    server_response_cache_control->m1_provisioning_session_response_max_age = SERVER_RESPONSE_MAX_AGE;
    server_response_cache_control->m1_content_hosting_configurations_response_max_age = SERVER_RESPONSE_MAX_AGE;
    server_response_cache_control->m1_server_certificates_response_max_age = SERVER_RESPONSE_MAX_AGE;
    server_response_cache_control->m1_content_protocols_response_max_age = M1_CONTENT_PROTOCOLS_RESPONSE_MAX_AGE;
    server_response_cache_control->m1_consumption_reporting_response_max_age = SERVER_RESPONSE_MAX_AGE;
    server_response_cache_control->m5_service_access_information_response_max_age = SERVER_RESPONSE_MAX_AGE;
    msaf_self()->config.server_response_cache_control = server_response_cache_control;
}

void msaf_server_response_cache_control_set_from_config(int m1_provisioning_session_response_max_age,
        int m1_content_hosting_configurations_response_max_age, int m1_server_certificates_response_max_age,
        int m1_content_protocols_response_max_age, int m1_consumption_reporting_response_max_age,
        int m5_service_access_information_response_max_age)
{
    msaf_self()->config.server_response_cache_control->m1_provisioning_session_response_max_age = m1_provisioning_session_response_max_age;
    msaf_self()->config.server_response_cache_control->m1_content_hosting_configurations_response_max_age = m1_content_hosting_configurations_response_max_age;
    msaf_self()->config.server_response_cache_control->m1_server_certificates_response_max_age = m1_server_certificates_response_max_age;
    msaf_self()->config.server_response_cache_control->m1_content_protocols_response_max_age = m1_content_protocols_response_max_age;
    msaf_self()->config.server_response_cache_control->m1_consumption_reporting_response_max_age = m1_consumption_reporting_response_max_age;
    msaf_self()->config.server_response_cache_control->m5_service_access_information_response_max_age = m5_service_access_information_response_max_age;
}

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
