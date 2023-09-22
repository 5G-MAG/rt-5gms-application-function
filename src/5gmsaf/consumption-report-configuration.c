/*
License: 5G-MAG Public License (v1.0)
Author: David Waring
Copyright: (C) 2023 British Broadcasting Corporation

For full license terms please see the LICENSE file distributed with this
program. If this file is missing then the license can be retrieved from
https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
*/

#include "ogs-core.h"

#include "openapi/model/consumption_reporting_configuration.h"
#include "provisioning-session.h"
#include "hash.h"

#include "consumption-report-configuration.h"

bool msaf_consumption_report_configuration_register(msaf_provisioning_session_t *session /* [no-transfer, not-null] */,
                                                  OpenAPI_consumption_reporting_configuration_t *config /* [transfer, not-null] */)
{
    char *body;

    ogs_assert(session);
    ogs_assert(config);

    if (session->consumptionReportingConfiguration) return false;

    session->consumptionReportingConfiguration = config;

    body = msaf_consumption_report_configuration_body(session);
    session->httpMetadata.consumptionReportingConfiguration.hash = calculate_hash(body);
    ogs_free(body);

    time(&session->httpMetadata.consumptionReportingConfiguration.received);

    msaf_sai_cache_clear(session->sai_cache);

    return true;
}

bool msaf_consumption_report_configuration_update(msaf_provisioning_session_t *session /* [no-transfer, not-null] */,
                                                OpenAPI_consumption_reporting_configuration_t *config /* [transfer, not-null] */)
{
    char *body;

    ogs_assert(session);
    ogs_assert(config);

    if (!session->consumptionReportingConfiguration) return false;

    OpenAPI_consumption_reporting_configuration_free(session->consumptionReportingConfiguration);

    if (session->httpMetadata.consumptionReportingConfiguration.hash) {
        ogs_free(session->httpMetadata.consumptionReportingConfiguration.hash);
    }

    session->consumptionReportingConfiguration = config;

    body = msaf_consumption_report_configuration_body(session);
    session->httpMetadata.consumptionReportingConfiguration.hash = calculate_hash(body);
    ogs_free(body);

    time(&session->httpMetadata.consumptionReportingConfiguration.received);

    msaf_sai_cache_clear(session->sai_cache);

    return true;
}

bool msaf_consumption_report_configuration_deregister(msaf_provisioning_session_t *session /* [no-transfer, not-null] */)
{
    ogs_assert(session);

    if (!session->consumptionReportingConfiguration) return false;

    OpenAPI_consumption_reporting_configuration_free(session->consumptionReportingConfiguration);
    session->consumptionReportingConfiguration = NULL;

    if (session->httpMetadata.consumptionReportingConfiguration.hash) {
        ogs_free(session->httpMetadata.consumptionReportingConfiguration.hash);
        session->httpMetadata.consumptionReportingConfiguration.hash = NULL;
    }
    
    session->httpMetadata.consumptionReportingConfiguration.received = 0;

    msaf_sai_cache_clear(session->sai_cache);

    return true;
}

cJSON *msaf_consumption_report_configuration_json(msaf_provisioning_session_t *session /* [no-transfer, not-null] */)
{
    cJSON *json;

    ogs_assert(session);

    if (!session->consumptionReportingConfiguration) return NULL;

    json = OpenAPI_consumption_reporting_configuration_convertToJSON(session->consumptionReportingConfiguration);

    if (!json) {
        ogs_error("Failed to convert ConsumptionReportingConfiguration to JSON");
    }

    return json;
}

char *msaf_consumption_report_configuration_body(msaf_provisioning_session_t *session /* [no-transfer, not-null] */)
{
    cJSON *json;
    char *body;
    
    ogs_assert(session);

    if (!session->consumptionReportingConfiguration) return NULL;

    json = msaf_consumption_report_configuration_json(session);
    if (!json) return NULL;

    body = cJSON_Print(json);

    cJSON_Delete(json);

    return body;
}

time_t msaf_consumption_report_configuration_last_modified(msaf_provisioning_session_t *session /* [no-transfer, not-null] */)
{
    ogs_assert(session);

    return session->httpMetadata.consumptionReportingConfiguration.received;
}

char *msaf_consumption_report_configuration_etag(msaf_provisioning_session_t *session /* [no-transfer, not-null] */)
{
    ogs_assert(session);

    return session->httpMetadata.consumptionReportingConfiguration.hash;
}

bool msaf_consumption_report_configuration_changed(msaf_provisioning_session_t *session /* [no-transfer, not-null] */,
                                                   time_t modified_since, const char *none_match /* [null] */)
{
    ogs_assert(session);

    /* Check modification time (input of 0 time indicates don't check modification time) */
    if (modified_since != 0 && session->httpMetadata.consumptionReportingConfiguration.received != modified_since) {
        return true;
    }

    /* Check ETag (NULL input means don't check ETag) */
    if (none_match && (!session->httpMetadata.consumptionReportingConfiguration.hash ||
                       strcmp(session->httpMetadata.consumptionReportingConfiguration.hash, none_match))) {
        return true;
    }

    return false;
}

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
