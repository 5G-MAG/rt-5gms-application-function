
#include "metrics-reporting-provisioning.h"
#include "ogs-core.h"

// Function that takes new MRC and assigns ID value

msaf_metrics_reporting_configuration_t *msaf_metrics_reporting_configuration_create(
        msaf_provisioning_session_t *provisioning_session)
{
    ogs_assert(provisioning_session);

    // Generating Metrics Reporting ID
    ogs_uuid_t uuid;
    char MRC_ID[OGS_UUID_FORMATTED_LENGTH + 1];
    ogs_uuid_get(&uuid);
    ogs_uuid_format(MRC_ID, &uuid);

    // Incoming MRC via M1 interface extended with ID
    OpenAPI_metrics_reporting_configuration_t *MRC = OpenAPI_metrics_reporting_configuration_create(
            ogs_strdup(MRC_ID),
            ogs_strdup(scheme),
            ogs_strdup(data_network_name),
            true,
            reporting_interval,
            true,
            sample_percentage,
            url_filters,
            metrics
    );

    msaf_metrics_reporting_configuration_t *msaf_mrc;
    msaf_mrc = ogs_calloc(1, sizeof(msaf_metrics_reporting_configuration_t));
    ogs_assert(msaf_mrc);

    msaf_mrc->MRC_ID = ogs_strdup(MRC->metrics_reporting_configuration_id);
    msaf_add_metrics_reporting_configuration(provisioning_session, msaf_mrc->MRC_ID, MRC);

    return msaf_mrc;
}

// TBD: List all metrics configurations
cJSON *msaf_get_metrics_reporting_configuration_by_metrics_configuration_id(msaf_metrics_reporting_configuration_t *metrics_reporting_configuration_id){}

// Find configuration by its ID.
msaf_metrics_reporting_configuration_t *
msaf_metrics_configuration_find_by_Id(const char *metrics_reporting_configuration_id)
{
    if (!msaf_self()->metricsConfiguration_map) return NULL;
    return (msaf_provisioning_session_t*) ogs_hash_get(msaf_self()->metricsConfiguration_map, metrics_reporting_configuration_id, OGS_HASH_KEY_STRING);
}

// DELETE MetricsReportingConfiguration
void
msaf_delete_metrics_reporting_configuration(const char *provisioning_session_id)
{
    // This part must be modified to MRC
    msaf_application_server_state_node_t *as_state;
    ogs_list_for_each(&msaf_self()->application_server_states, as_state) {
        resource_id_node_t *metrics_reporting_configuration, *next = NULL;
        // resource_id_node_t *upload_metrics_reporting_configuration, *next_node = NULL;
        // resource_id_node_t *delete_chc = NULL;
        ogs_list_init(&as_state->delete_metrics_reporting_configurations);
        if (as_state->current_content_hosting_configurations) {
            ogs_list_for_each_safe(as_state->current_content_hosting_configurations, next, content_hosting_configuration){
                if (!strcmp(content_hosting_configuration->state, provisioning_session_id))
                    break;            }
            if (content_hosting_configuration) {
                delete_chc = ogs_calloc(1, sizeof(resource_id_node_t));
                ogs_assert(delete_chc);
                delete_chc->state = ogs_strdup(content_hosting_configuration->state);
                ogs_list_add(&as_state->delete_content_hosting_configurations, delete_chc);
            }
        }
        ogs_list_for_each_safe(&as_state->upload_content_hosting_configurations, next_node, upload_content_hosting_configuration){
            if (!strcmp(upload_content_hosting_configuration->state, provisioning_session_id))
                break;
        }
        if (upload_content_hosting_configuration) {
            ogs_list_remove(&as_state->upload_content_hosting_configurations, upload_content_hosting_configuration);
            ogs_list_add(&as_state->delete_content_hosting_configurations, upload_content_hosting_configuration);
        }
        next_action_for_application_server(as_state);
    }
}

cJSON *msaf_get_metrics_reporting_configuration_by_provisioning_session_id(const char *provisioning_session_id) {
    return 0;
}

/*cJSON *metrics_reporting_get_json(msaf_metrics_reporting_configuration_t *msaf_metrics_reporting_configuration)
{
    if (!msaf_metrics_reporting_configuration)
    {
        return NULL;
    }

    OpenAPI_metrics_reporting_configuration_t *metrics_reporting_configuration = OpenAPI_service_access_information_resource_client_metrics_reporting_configuration_create(
            ogs_strdup(msaf_metrics_reporting_configuration->metricsReportingConfigurationId),
            ogs_strdup(msaf_metrics_reporting_configuration->scheme),
            ogs_strdup(msaf_metrics_reporting_configuration->dataNetworkName),
            msaf_metrics_reporting_configuration->reportingInterval,
            msaf_metrics_reporting_configuration->samplePercentage,
            msaf_metrics_reporting_configuration->urlFilters,
            msaf_metrics_reporting_configuration->metrics
    );

    cJSON *metrics_reportingJSON = OpenAPI_service_access_information_resource_client_metrics_reporting_configuration_convertToJSON(metrics_reporting_configuration);

    OpenAPI_service_access_information_resource_client_metrics_reporting_configuration_free(metrics_reporting_configuration);

    if (!metrics_reportingJSON)
    {
        return NULL;
    }

    return metrics_reportingJSON;
}
*/