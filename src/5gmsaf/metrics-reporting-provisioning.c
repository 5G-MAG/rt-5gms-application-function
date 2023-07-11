/*
License: 5G-MAG Public License (v1.0)
Author: Vuk Stojkovic
Copyright: (C) 2023 Fraunhofer FOKUS
For full license terms please see the LICENSE file distributed with this
program. If this file is missing then the license can be retrieved from
https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
*/

#include "metrics-reporting-provisioning.h"
#include "ogs-core.h"
#include "provisioning-session.h"

msaf_metrics_reporting_configuration_t *msaf_metrics_reporting_configuration_create(void) {

    OpenAPI_metrics_reporting_configuration_t *metrics_reporting_configuration;
    msaf_metrics_reporting_configuration_t *msaf_metrics_reporting_configuration;

    // Generating Metrics Reporting ID and formatting as character array.
    ogs_uuid_t uuid;
    char id[OGS_UUID_FORMATTED_LENGTH + 1];
    ogs_uuid_get(&uuid);
    ogs_uuid_format(id, &uuid);
    metrics_reporting_configuration = OpenAPI_metrics_reporting_configuration_create(
            ogs_strdup(id),
            ogs_strdup(scheme),
            ogs_strdup(data_network_name),
            true,
            reporting_interval,
            true,
            sample_percentage,
            url_filters,
            metrics
    );

    // Memory allocation for internal model "msaf_metrics_reporting_configuration"
    msaf_metrics_reporting_configuration = ogs_calloc(1, sizeof(msaf_metrics_reporting_configuration));
    // Checking if the newly created object is null.
    ogs_assert(msaf_metrics_reporting_configuration);

    msaf_metrics_reporting_configuration->metricsReportingConfigurationId = ogs_strdup(metrics_reporting_configuration->metrics_reporting_configuration_id);
    msaf_metrics_reporting_configuration->scheme = metrics_reporting_configuration->scheme;
    msaf_metrics_reporting_configuration->dataNetworkName = metrics_reporting_configuration->data_network_name;
    msaf_metrics_reporting_configuration->isReportingInterval = metrics_reporting_configuration->is_reporting_interval;
    msaf_metrics_reporting_configuration->reportingInterval = metrics_reporting_configuration->reporting_interval;
    msaf_metrics_reporting_configuration->isSamplePercentage = metrics_reporting_configuration->is_sample_percentage;
    msaf_metrics_reporting_configuration->samplePercentage = metrics_reporting_configuration->sample_percentage;
    msaf_metrics_reporting_configuration->urlFilters = metrics_reporting_configuration->url_filters;
    msaf_metrics_reporting_configuration->metrics = metrics_reporting_configuration->metrics;

    ogs_hash_set(provisioning_session->metrics_reporting_map,
                 ogs_strdup(msaf_metrics_reporting_configuration->metricsReportingConfigurationId),
                 OGS_HASH_KEY_STRING,
                 msaf_metrics_reporting_configuration);

    OpenAPI_metrics_reporting_configuration_free(metrics_reporting_configuration);
    return msaf_metrics_reporting_configuration;
}
void
msaf_delete_metrics_reporting_configuration(const char *provisioning_session_id)
{
    msaf_application_server_state_node_t *as_state;
    ogs_list_for_each(&msaf_self()->application_server_states, as_state) {
        resource_id_node_t *metrics_reporting_configuration, *next = NULL;
        resource_id_node_t *upload_metrics_reporting_configuration, *next_node = NULL;
        resource_id_node_t *delete_mrc = NULL;

        ogs_list_init(&as_state->delete_metrics_reporting_configuration);

        if (as_state->current_metrics_reporting_configuration) {
            ogs_list_for_each_safe(as_state->current_metrics_reporting_configuration, next, metrics_reporting_configuration){
                if (!strcmp(metrics_reporting_configuration)->state, provisioning_session_id))
                break;
            }
            if (metrics_reporting_configuration) {
                delete_mrc = ogs_calloc(1, sizeof(resource_id_node_t));
                ogs_assert(delete_mrc);
                delete_mrc->state = ogs_strdup(metrics_reporting_configuration)->state);
                ogs_list_add(&as_state->delete_metrics_reporting_configuration, delete_mrc);
            }
        }
        ogs_list_for_each_safe(&as_state->upload_metrics_reporting_configurations, next_node, upload_metrics_reporting_configuration){
            if (!strcmp(upload_metrics_reporting_configuration->state, provisioning_session_id))
                break;
        }
        if (upload_metrics_reporting_configuration) {
            ogs_list_remove(&as_state->upload_metrics_reporting_configurations, upload_metrics_reporting_configuration);
            ogs_list_add(&as_state->delete_metrics_reporting_configuration, upload_metrics_reporting_configuration);
        }
        next_action_for_application_server(as_state);
    }
}

msaf_metrics_reporting_configuration_t *
msaf_metrics_reporting_configuration_find_by_metricsReportingConfigurationId(const char *metricsReportingConfigurationId)
{
    if (!msaf_self()->metrics_reporting_map) return NULL;
    return (msaf_metrics_reporting_configuration_t *) ogs_hash_get(msaf_self()->metrics_reporting_map, metricsReportingConfigurationId, OGS_HASH_KEY_STRING);
}

/* Auxiliary functions */

static const char *calculate_metrics_reporting_configuration_hash(OpenAPI_metrics_reporting_configuration_t *metrics_reporting_configuration)
{
    cJSON *metrics_rep = NULL;
    char *metrics_reporting_configuration_to_hash;
    const char *metrics_reporting_configuration_hashed = NULL;
    metrics_rep = OpenAPI_metrics_reporting_configuration_convertToJSON(metrics_reporting_configuration);
    metrics_reporting_configuration_to_hash = cJSON_Print(metrics_rep);
    cJSON_Delete(metrics_rep);
    metrics_reporting_configuration_hashed = calculate_hash(metrics_reporting_configuration_to_hash);
    ogs_free(metrics_reporting_configuration_to_hash);
    return metrics_reporting_configuration_hashed;
}

cJSON *msaf_get_metrics_reporting_configuration_by_provisioning_session_id(const char *provisioning_session_id) {
    msaf_provisioning_session_t *msaf_provisioning_session;
    cJSON *metrics_reporting_configuration_json;

    msaf_provisioning_session = msaf_provisioning_session_find_by_provisioningSessionId(provisioning_session_id);

    if(msaf_provisioning_session && msaf_provisioning_session->metricsReportingConfiguration)
    {
        metrics_reporting_configuration_json = OpenAPI_metrics_reporting_configuration_convertToJSON(msaf_provisioning_session->metricsReportingConfiguration);
    } else {
        ogs_error("Unable to retrieve Provisioning Session");
        return NULL;

    }
    return metrics_reporting_configuration_json;
}
