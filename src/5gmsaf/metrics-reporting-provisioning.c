
#include "metrics-reporting-provisioning.h"
#include "ogs-core.h"

// Placeholders for potential functions


OpenAPI_metrics_reporting_configuration_t * msaf_metrics_reporting_configuration_with_af_unique_cert_id(msaf_provisioning_session_t *provisioning_session) {
        return 0;
};

int msaf_metrics_reporting_configuration_certificate_check(msaf_provisioning_session_t *provisioning_session){
    return 0;
}

void msaf_metrics_reporting_configuration_delete (const char *provisioning_session_id){
    return 0;
}

ogs_hash_t *
msaf_certificate_map(void)
{
    ogs_hash_t *certificate_map = ogs_hash_make();
    return certificate_map;
}

const char *
msaf_get_certificate_filename(const char *provisioning_session_id, const char *certificate_id)
{
    msaf_provisioning_session_t *provisioning_session;

    provisioning_session = msaf_provisioning_session_find_by_provisioningSessionId(provisioning_session_id);
    ogs_assert(provisioning_session);

    if (provisioning_session->certificate_map == NULL) return NULL;

    return (const char*)ogs_hash_get(provisioning_session->certificate_map, certificate_id, OGS_HASH_KEY_STRING);
}


ogs_list_t*
msaf_retrieve_certificates_from_map(msaf_provisioning_session_t *provisioning_session)
{

    ogs_list_t *certs = NULL;
    resource_id_node_t *certificate = NULL;
    OpenAPI_lnode_t *dist_config_node = NULL;
    OpenAPI_distribution_configuration_t *dist_config = NULL;

    ogs_assert(provisioning_session);

    certs = (ogs_list_t*) ogs_calloc(1,sizeof(*certs));
    ogs_assert(certs);
    ogs_list_init(certs);
    if (provisioning_session->contentHostingConfiguration && provisioning_session->certificate_map) {
        OpenAPI_list_for_each(provisioning_session->contentHostingConfiguration->distribution_configurations, dist_config_node) {
            dist_config = (OpenAPI_distribution_configuration_t*)dist_config_node->data;
            if (dist_config->certificate_id) {
                const char *cert = ogs_hash_get(provisioning_session->certificate_map, dist_config->certificate_id, OGS_HASH_KEY_STRING);
                if (cert){
                    certificate = ogs_calloc(1, sizeof(resource_id_node_t));
                    ogs_assert(certificate);
                    char *provisioning_session_id_plus_cert_id = ogs_msprintf("%s:%s", provisioning_session->provisioningSessionId, dist_config->certificate_id);
                    certificate->state = provisioning_session_id_plus_cert_id;
                    ogs_list_add(certs, certificate);
                } else {
                    ogs_warn("Certificate id [%s] not found for Content Hosting Configuration [%s]", dist_config->certificate_id, provisioning_session->provisioningSessionId);
                    resource_id_node_t *next;
                    ogs_list_for_each_safe(certs, next, certificate) {
                        ogs_list_remove(certs, certificate);
                        if (certificate->state) ogs_free(certificate->state);
                        ogs_free(certificate);
                    }
                    ogs_free(certs);
                    certs = NULL;
                    break;
                }
            }
        }
    }
    return certs;
}


cJSON *msaf_get_metrics_reporting_configuration_by_provisioning_session_id(const char *provisioning_session_id) {
    return 0;
}








/*
msaf_metrics_reporting_configuration_t *msaf_metrics_reporting_configuration_create(
        char *metrics_reporting_configuration_id,
        char *scheme,
        char *data_network_name,
        bool is_reporting_interval,
        int reporting_interval,
        bool is_sample_percentage,
        double sample_percentage,
        OpenAPI_list_t *url_filters,
        OpenAPI_list_t *metrics
) {

    // Generating ID values
    msaf_metrics_reporting_configuration_t *msaf_metrics_reporting_configuration;
    ogs_uuid_t uuid;
    char metrics_reporting_configuration_id[OGS_UUID_FORMATTED_LENGTH + 1];
    OpenAPI_metrics_reporting_configuration_t *metrics_reporting_configuration;

    ogs_uuid_get(&uuid);
    ogs_uuid_format(metrics_reporting_configuration_id, &uuid);

    // Invoking the function defined in openapi/models interface
    metrics_reporting_configuration = OpenAPI_metrics_reporting_configuration_create(
            ogs_strdup(metrics_reporting_configuration_id),
            ogs_strdup(scheme),
            ogs_strdup(data_network_name),
            reporting_interval,
            sample_percentage,
            url_filters,
            metrics
    );

    msaf_metrics_reporting_configuration = ogs_calloc(1, sizeof(msaf_metrics_reporting_configuration_t));

    // Checking if memory allocation was successful
    ogs_assert(msaf_metrics_reporting_configuration);

    msaf_metrics_reporting_configuration->metricsReportingConfigurationId = ogs_strdup(metrics_reporting_configuration->metrics_reporting_configuration_id);
    msaf_metrics_reporting_configuration->scheme = ogs_strdup(metrics_reporting_configuration->scheme);
    msaf_metrics_reporting_configuration->dataNetworkName = ogs_strdup(metrics_reporting_configuration->data_network_name);
    msaf_metrics_reporting_configuration->reportingInterval = metrics_reporting_configuration->reporting_interval;
    msaf_metrics_reporting_configuration->samplePercentage = metrics_reporting_configuration->sample_percentage;
    msaf_metrics_reporting_configuration->urlFilters = ogs_list_copy(metrics_reporting_configuration->url_filters);
    msaf_metrics_reporting_configuration->metrics = ogs_list_copy(metrics_reporting_configuration->metrics);

    OpenAPI_metrics_reporting_configuration_free(metrics_reporting_configuration);
    return msaf_metrics_reporting_configuration;
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

cJSON *metrics_reporting_get_json(msaf_metrics_reporting_configuration_t *msaf_metrics_reporting_configuration)
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