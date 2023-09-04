/*
 * License: 5G-MAG Public License (v1.0)
 * Author: Dev Audsin
 * Copyright: (C) 2022 British Broadcasting Corporation
 *
 * For full license terms please see the LICENSE file distributed with this
 * program. If this file is missing then the license can be retrieved from
 * https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
 */


#include "ogs-sbi.h"

#include "sbi-path.h"
#include "context.h"
#include "certmgr.h"
#include "server.h"
#include "response-cache-control.h"
#include "msaf-version.h"
#include "msaf-sm.h"
#include "utilities.h"
#include "ContentProtocolsDiscovery_body.h"
#include "openapi/api/TS26512_M1_ProvisioningSessionsAPI-info.h"
#include "openapi/api/TS26512_M1_ServerCertificatesProvisioningAPI-info.h"
#include "openapi/api/TS26512_M1_ContentHostingProvisioningAPI-info.h"
#include "openapi/api/M3_ServerCertificatesProvisioningAPI-info.h"
#include "openapi/api/M3_ContentHostingProvisioningAPI-info.h"
#include "openapi/api/TS26512_M1_ContentProtocolsDiscoveryAPI-info.h"
#include "openapi/api/Maf_ManagementAPI-info.h"
#include "openapi/api/TS26512_M1_MetricsReportingProvisioningAPI-info.h"


const nf_server_interface_metadata_t
        m1_provisioningsession_api_metadata = {
        M1_PROVISIONINGSESSIONS_API_NAME,
        M1_PROVISIONINGSESSIONS_API_VERSION
};

const nf_server_interface_metadata_t
        m1_metricsreportingprovisioning_api_metadata = {
        M1_METRICSREPORTINGPROVISIONING_API_NAME,
        M1_METRICSREPORTINGPROVISIONING_API_VERSION
};

const nf_server_interface_metadata_t
        m1_contenthostingprovisioning_api_metadata = {
        M1_CONTENTHOSTINGPROVISIONING_API_NAME,
        M1_CONTENTHOSTINGPROVISIONING_API_VERSION
};

const nf_server_interface_metadata_t
        m1_contentprotocolsdiscovery_api_metadata = {
        M1_CONTENTPROTOCOLSDISCOVERY_API_NAME,
        M1_CONTENTPROTOCOLSDISCOVERY_API_VERSION
};

const nf_server_interface_metadata_t
        m1_servercertificatesprovisioning_api_metadata = {
        M1_SERVERCERTIFICATESPROVISIONING_API_NAME,
        M1_SERVERCERTIFICATESPROVISIONING_API_VERSION
};

const nf_server_interface_metadata_t
        m3_contenthostingprovisioning_api_metatdata = {
        M3_CONTENTHOSTINGPROVISIONING_API_NAME,
        M3_CONTENTHOSTINGPROVISIONING_API_VERSION
};

const nf_server_interface_metadata_t
        maf_management_api_metadata = {
        MAF_MANAGEMENT_API_NAME,
        MAF_MANAGEMENT_API_VERSION
};

void msaf_m1_state_initial(ogs_fsm_t *s, msaf_event_t *e)
{
    msaf_sm_debug(e);

    ogs_assert(s);

    OGS_FSM_TRAN(s, &msaf_m1_state_functional);
}

void msaf_m1_state_final(ogs_fsm_t *s, msaf_event_t *e)
{
    msaf_sm_debug(e);

    ogs_assert(s);
}

void msaf_m1_state_functional(ogs_fsm_t *s, msaf_event_t *e)
{
    ogs_sbi_stream_t *stream = NULL;
    ogs_sbi_request_t *request = NULL;
    ogs_sbi_response_t *response = NULL;
    ogs_sbi_message_t *message = NULL;

    msaf_sm_debug(e);

    char *nf_name = ogs_msprintf("5GMSdAF-%s", msaf_self()->server_name);
    const nf_server_app_metadata_t app_metadata = { MSAF_NAME, MSAF_VERSION, nf_name};
    const nf_server_interface_metadata_t *m1_provisioningsession_api = &m1_provisioningsession_api_metadata;
    const nf_server_interface_metadata_t *m1_contenthostingprovisioning_api = &m1_contenthostingprovisioning_api_metadata;
    const nf_server_interface_metadata_t *m1_contentprotocolsdiscovery_api = &m1_contentprotocolsdiscovery_api_metadata;
    const nf_server_interface_metadata_t *m1_servercertificatesprovisioning_api = &m1_servercertificatesprovisioning_api_metadata;
    const nf_server_interface_metadata_t *m3_contenthostingprovisioning_api = &m3_contenthostingprovisioning_api_metatdata;
    const nf_server_interface_metadata_t *maf_management_api = &maf_management_api_metadata;
    const nf_server_app_metadata_t *app_meta = &app_metadata;
    const nf_server_interface_metadata_t *m1_metricsreportingprovisioning_api = &m1_metricsreportingprovisioning_api_metadata;

    ogs_assert(s);

    switch (e->h.id) {
        case OGS_FSM_ENTRY_SIG:
            ogs_info("[%s] MSAF M1 Running", ogs_sbi_self()->nf_instance->id);

            break;

        case OGS_FSM_EXIT_SIG:
            break;

        case OGS_EVENT_SBI_SERVER:
            request = e->h.sbi.request;
            ogs_assert(request);
            stream = e->h.sbi.data;
            ogs_assert(stream);
            message = e->message;

            SWITCH(message->h.service.name)
            CASE("3gpp-m1")
            if (strcmp(message->h.api.version, "v2") != 0) {
                char *error;
                error = ogs_msprintf("Version [%s] not supported", message->h.api.version);
                ogs_error("%s", error);
                ogs_assert(true == nf_server_send_error(stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST, 1, NULL, "Not supported version", error, NULL, NULL, app_meta));
                ogs_free(error);
                break;
            }
            if (!message->h.resource.component[0]) {
                const char *error = "Protocol on M1 requires a resource";
                ogs_error(error);
                ogs_assert(true == nf_server_send_error(stream, 404, 1, NULL, "No resource given", error, NULL, NULL, app_meta));
                break;
            }

            SWITCH(message->h.resource.component[0])
            CASE("provisioning-sessions")
            SWITCH(message->h.method)
            CASE(OGS_SBI_HTTP_METHOD_POST)

            if (message->h.resource.component[1] && message->h.resource.component[2] && message->h.resource.component[3] && !message->h.resource.component[4]) {
                msaf_provisioning_session_t *msaf_provisioning_session;

                if (!strcmp(message->h.resource.component[2],"content-hosting-configuration") && !strcmp(message->h.resource.component[3],"purge")) {
                    ogs_hash_index_t *hi;
                    for (hi = ogs_hash_first(request->http.headers);
                         hi; hi = ogs_hash_next(hi)) {
                        if (!ogs_strcasecmp(ogs_hash_this_key(hi), OGS_SBI_CONTENT_TYPE)) {
                            if (ogs_strcasecmp(ogs_hash_this_val(hi), "application/x-www-form-urlencoded")) {
                                char *err = NULL;
                                const char *type;
                                type = (const char *)ogs_hash_this_val(hi);
                                err = ogs_msprintf( "Unsupported Media Type: received type: %s, should have been application/x-www-form-urlencoded", type);
                                ogs_error("%s", err);

                                ogs_assert(true == nf_server_send_error(stream, 415, 3, message, "Unsupported Media Type.", err, NULL, m1_contenthostingprovisioning_api, app_meta));
                                ogs_free(err);
                                ogs_sbi_message_free(message);
                                ogs_free(message);
                                return;

                            }
                        }
                    }
                    msaf_provisioning_session = msaf_provisioning_session_find_by_provisioningSessionId(message->h.resource.component[1]);
                    if(msaf_provisioning_session) {
                        // process the POST body
                        purge_resource_id_node_t *purge_cache;
                        msaf_application_server_state_ref_node_t *as_state_ref;
                        assigned_provisioning_sessions_node_t *assigned_provisioning_sessions_resource;
                        m1_purge_information_t *m1_purge_info = ogs_calloc(1, sizeof(m1_purge_information_t));
                        m1_purge_info->m1_stream = stream;
                        m1_purge_info->m1_message = *message;

                        ogs_list_for_each(&msaf_provisioning_session->application_server_states, as_state_ref) {
                            msaf_application_server_state_node_t *as_state = as_state_ref->as_state;
                            if (as_state->application_server && as_state->application_server->canonicalHostname) {
                                ogs_list_for_each(&as_state->assigned_provisioning_sessions,assigned_provisioning_sessions_resource){
                                    if(assigned_provisioning_sessions_resource->assigned_provisioning_session == msaf_provisioning_session) {

                                        purge_cache = ogs_calloc(1, sizeof(purge_resource_id_node_t));
                                        ogs_assert(purge_cache);
                                        purge_cache->provisioning_session_id = msaf_strdup(assigned_provisioning_sessions_resource->assigned_provisioning_session->provisioningSessionId);

                                        purge_cache->m1_purge_info = m1_purge_info;
                                        m1_purge_info->refs++;
                                        if(request->http.content)
                                            purge_cache->purge_regex = msaf_strdup(request->http.content);
                                        else
                                            purge_cache->purge_regex = NULL;

                                        if (ogs_list_first(&as_state->purge_content_hosting_cache) == NULL)
                                            ogs_list_init(&as_state->purge_content_hosting_cache);

                                        ogs_list_add(&as_state->purge_content_hosting_cache, purge_cache);
                                    } else {
                                        char *err = NULL;
                                        err = ogs_msprintf("Provisioning Session [%s] is not assigned to an Application Server", message->h.resource.component[1]);
                                        ogs_error("%s", err);
                                        ogs_assert(true == nf_server_send_error(stream, 500, 3, message, "Provisioning session is not assigned to an Application Server.", err, NULL, m1_contenthostingprovisioning_api, app_meta));
                                        ogs_free(err);
                                    }
                                }
                            } else {
                                char *err = NULL;
                                err = ogs_msprintf("Provisioning Session [%s] : Unable to get information about Application Server", message->h.resource.component[1]);
                                ogs_error("%s", err);
                                ogs_assert(true == nf_server_send_error(stream, 500, 3, message, "Unable to get information about Application Server", err, NULL, m1_contenthostingprovisioning_api, app_meta));
                                ogs_free(err);
                            }

                            next_action_for_application_server(as_state);
                        }
                        if (m1_purge_info->refs == 0) {
                            ogs_free(m1_purge_info);
                            // Send 204 back to M1 client
                            ogs_sbi_response_t *response;
                            response = nf_server_new_response(NULL, NULL, 0, NULL, 0, NULL, m1_contenthostingprovisioning_api, app_meta);
                            nf_server_populate_response(response, 0, NULL, 204);
                            ogs_assert(response);
                            ogs_assert(true == ogs_sbi_server_send_response(stream, response));
                        }
                    } else {
                        char *err = NULL;
                        err = ogs_msprintf("Provisioning session [%s] does not exist.", message->h.resource.component[1]);
                        ogs_error("%s", err);
                        ogs_assert(true == nf_server_send_error(stream, 404, 3, message, "Provisioning session does not exist.", err, NULL, m1_contenthostingprovisioning_api, app_meta));
                        ogs_free(err);
                    }

                }

            } else if (message->h.resource.component[1] && message->h.resource.component[2] &&
                       !message->h.resource.component[3]) {
                msaf_provisioning_session_t *msaf_provisioning_session;
                if (!strcmp(message->h.resource.component[2], "metrics-reporting-configurations")) {

                    msaf_provisioning_session = msaf_provisioning_session_find_by_provisioningSessionId(message->h.resource.component[1]);

                    if (msaf_provisioning_session) {
                        int rv;
                        cJSON *mrc_json;
                        cJSON *metrics_reporting_config;

                        ogs_debug("Request body: %s", request->http.content);

                        metrics_reporting_config = cJSON_Parse(request->http.content);
                        {
                            char *txt = cJSON_Print(metrics_reporting_config);
                            ogs_debug("Parsed JSON: %s", txt);
                            cJSON_free(txt);
                        }

                        // If parsing fails
                        if (!metrics_reporting_config) {
                            char *err = NULL;
                            err = ogs_msprintf("Unable to parse Metrics Reporting Configuration as JSON for the Provisioning Session [%s].",
                                               message->h.resource.component[1]);
                            ogs_error("%s", err);
                            ogs_assert(true == nf_server_send_error(stream,
                                                                    400,
                                                                    2,
                                                                    message,
                                                                    "Bad Metrics Reporting Configuration.",
                                                                    err,
                                                                    NULL,
                                                                    m1_metricsreportingprovisioning_api,
                                                                    app_meta));
                            ogs_free(err);

                        }

                        else {
                            if(msaf_provisioning_session->metricsReportingConfiguration) {
                                OpenAPI_metrics_reporting_configuration_free(
                                        msaf_provisioning_session->metricsReportingConfiguration);
                                msaf_provisioning_session->metricsReportingConfiguration = NULL;
                            }

                            // Parsing the data from request body
                            /*cJSON *jsonMetrics_reporting_configuration_id = cJSON_GetObjectItemCaseSensitive(metrics_reporting_config, "metrics_reporting_configuration_id");
                            const char *metrics_reporting_configuration_id = NULL;
                            if (jsonMetrics_reporting_configuration_id) metrics_reporting_configuration_id = cJSON_GetStringValue(jsonMetrics_reporting_configuration_id);*/


                            /* Parsing particular variable from body of POST */
                            cJSON *jsonScheme = cJSON_GetObjectItemCaseSensitive(metrics_reporting_config, "scheme");
                            const char *scheme = NULL;
                            if (jsonScheme) scheme = cJSON_GetStringValue(jsonScheme);

                            cJSON *jsonDataNetworkName = cJSON_GetObjectItemCaseSensitive(metrics_reporting_config, "dataNetworkName");
                            const char *dataNetworkName = NULL;
                            if (jsonDataNetworkName) dataNetworkName = cJSON_GetStringValue(jsonDataNetworkName);

                            cJSON *jsonIsReportingInterval = cJSON_GetObjectItemCaseSensitive(metrics_reporting_config, "isReportingInterval");
                            bool isReportingInterval = false;
                            if (jsonIsReportingInterval) isReportingInterval = cJSON_IsTrue(jsonIsReportingInterval);

                            cJSON *jsonReportingInterval = cJSON_GetObjectItemCaseSensitive(metrics_reporting_config, "reportingInterval");
                            int reportingInterval = 0;
                            if (jsonReportingInterval) reportingInterval = jsonReportingInterval->valueint;

                            cJSON *jsonIsSamplePercentage = cJSON_GetObjectItemCaseSensitive(metrics_reporting_config, "isSamplePercentage");
                            bool isSamplePercentage = false;
                            if (jsonIsSamplePercentage) isSamplePercentage = cJSON_IsTrue(jsonIsSamplePercentage);

                            cJSON *jsonSamplePercentage = cJSON_GetObjectItemCaseSensitive(metrics_reporting_config, "samplePercentage");
                            double samplePercentage = 0;
                            if (jsonSamplePercentage) samplePercentage = jsonSamplePercentage->valuedouble;


                            cJSON *jsonUrlFilters = cJSON_GetObjectItemCaseSensitive(metrics_reporting_config, "urlFilters");
                            OpenAPI_list_t *urlFilters = NULL;

                            if (jsonUrlFilters && cJSON_IsArray(jsonUrlFilters)) {
                                int size = cJSON_GetArraySize(jsonUrlFilters);
                                urlFilters = OpenAPI_list_create();
                                int i;
                                for (i = 0; i < size; i++) {
                                    cJSON *item = cJSON_GetArrayItem(jsonUrlFilters, i);
                                    if (item && cJSON_IsString(item)) {
                                        char* new_string = strdup(item->valuestring);
                                        if(new_string == NULL) {
                                            ogs_error("Failed to allocate memory for new string.");
                                            // Free the list and return an error status
                                            OpenAPI_list_free(urlFilters);
                                            urlFilters = NULL;
                                            return OGS_ERROR;
                                        }
                                        OpenAPI_list_add(urlFilters, new_string);
                                    }
                                }
                            }

                            cJSON *jsonMetrics = cJSON_GetObjectItemCaseSensitive(metrics_reporting_config, "metrics");
                            OpenAPI_list_t *metrics = NULL;
                            if (jsonMetrics && cJSON_IsArray(jsonMetrics)) {
                                int size = cJSON_GetArraySize(jsonMetrics);
                                metrics = OpenAPI_list_create();
                                int i;
                                for (i = 0; i < size; i++) {
                                    cJSON *item = cJSON_GetArrayItem(jsonMetrics, i);
                                    if (item && cJSON_IsString(item)) {
                                        char* new_string = strdup(item->valuestring);
                                        if(new_string == NULL) {
                                            ogs_error("Failed to allocate memory for new string.");
                                            OpenAPI_list_free(metrics);
                                            metrics = NULL;
                                            return OGS_ERROR;
                                        }
                                        OpenAPI_list_add(metrics, new_string);
                                    }
                                }
                            }

                            rv = msaf_metrics_reporting_configuration_create(msaf_provisioning_session,
                                                                             scheme,
                                                                             dataNetworkName,
                                                                             isReportingInterval,
                                                                             reportingInterval,
                                                                             isSamplePercentage,
                                                                             samplePercentage,
                                                                             urlFilters,
                                                                             metrics);

                            if(rv){
                                ogs_debug("Metrics Reporting Configuration created successfully");

                                if (msaf_application_server_state_set_on_post(msaf_provisioning_session)) {

                                    msaf_provisioning_session = msaf_get_metrics_reporting_configuration_by_provisioning_session_id(
                                            message->h.resource.component[1]);

                                    msaf_metrics_reporting_configuration_t *new_mrc = msaf_provisioning_session->metricsReportingConfiguration;

                                    if (new_mrc != NULL) {
                                        msaf_metrics_reporting_configuration_t *new_mrc = msaf_get_metrics_reporting_configuration_by_provisioning_session_id(
                                                message->h.resource.component[1]);

                                        char *text;
                                        msaf_provisioning_session = msaf_get_metrics_reporting_configuration_by_provisioning_session_id(
                                                message->h.resource.component[1]);
                                        response = nf_server_new_response(request->h.uri,
                                                                          "application/json",
                                                                          msaf_provisioning_session->metricsReportingConfigurationReceived,
                                                                          msaf_provisioning_session->metricsReportingConfigurationHash,
                                                                          NULL,
                                                                          NULL,
                                                                          m1_metricsreportingprovisioning_api,
                                                                          app_meta);
                                        ogs_assert(response);
                                        text = cJSON_Print(mrc_json);
                                        ogs_debug("Generated response: %s", text);
                                        nf_server_populate_response(response, strlen(text), text, 201);
                                        ogs_assert(true == ogs_sbi_server_send_response(stream, response));
                                        response = NULL;
                                        cJSON_Delete(mrc_json);
                                    } else {
                                        char *err = NULL;
                                        err = ogs_msprintf("Unable to retrieve the Metrics Reporting Configuration for the Provisioning Session [%s].", message->h.resource.component[1]);
                                        ogs_error("%s", err);
                                        ogs_assert(true == nf_server_send_error(stream, 404, 2, message, "Unable to retrieve the Metrics Reporting Configuration.", err, NULL, m1_metricsreportingprovisioning_api, app_meta));
                                        ogs_free(err);
                                    }
                                } else {
                                    char *err = NULL;
                                    err = ogs_msprintf("Verification error on Metrics Reporting Configuration for the Provisioning Session [%s].", message->h.resource.component[1]);
                                    ogs_error("%s", err);
                                    ogs_assert(true == nf_server_send_error(stream, 400, 2, message, "Bad Metrics Reporting Configuration.", err, NULL, m1_metricsreportingprovisioning_api, app_meta));
                                    ogs_free(err);
                                }
                            } else {
                                char *err = NULL;
                                err = ogs_msprintf("Creation of the Metrics Reporting Configuration failed for the Provisioning Session [%s]", message->h.resource.component[1]);
                                ogs_error("%s", err);
                                ogs_assert(true == nf_server_send_error(stream, 500, 2, message, "Creation of the Metrics Reporting Configuration failed.", err, NULL, m1_metricsreportingprovisioning_api, app_meta));
                                ogs_free(err);
                            }
                        }

                        if (metrics_reporting_config) cJSON_Delete(metrics_reporting_config);

                    } else {
                        char *err = NULL;
                        err = ogs_msprintf("Provisioning session [%s] does not exist.", message->h.resource.component[1]);
                        ogs_error("%s",err);
                        ogs_assert(true == nf_server_send_error(stream, 404, 2, message, "Provisioning session does not exist.", err, NULL, m1_metricsreportingprovisioning_api, app_meta));
                        ogs_free(err);
                    }
                }

                if (!strcmp(message->h.resource.component[2], "content-hosting-configuration")) {
                    msaf_provisioning_session = msaf_provisioning_session_find_by_provisioningSessionId(
                            message->h.resource.component[1]);
                    if (msaf_provisioning_session) {
                        // process the POST body
                        int rv;
                        cJSON *chc;
                        cJSON *content_hosting_config;

                        ogs_debug("Request body: %s", request->http.content);

                        content_hosting_config = cJSON_Parse(request->http.content);
                        {
                            char *txt = cJSON_Print(content_hosting_config);
                            ogs_debug("Parsed JSON: %s", txt);
                            cJSON_free(txt);
                        }

                        if (!content_hosting_config) {
                            char *err = NULL;
                            err = ogs_msprintf("Unable to parse Content Hosting Configuration as JSON for the Provisioning Session [%s].", message->h.resource.component[1]);
                            ogs_error("%s", err);
                            ogs_assert(true == nf_server_send_error(stream, 400, 2, message, "Bad Content Hosting Configuration.", err, NULL, m1_contenthostingprovisioning_api, app_meta));
                            ogs_free(err);
                        } else {

                            if(msaf_provisioning_session->contentHostingConfiguration) {
                                OpenAPI_content_hosting_configuration_free(
                                        msaf_provisioning_session->contentHostingConfiguration);
                                msaf_provisioning_session->contentHostingConfiguration = NULL;
                            }

                            if (msaf_provisioning_session->serviceAccessInformation) {
                                OpenAPI_service_access_information_resource_free(
                                        msaf_provisioning_session->serviceAccessInformation);
                                msaf_provisioning_session->serviceAccessInformation = NULL;
                            }

                            rv = msaf_distribution_create(content_hosting_config, msaf_provisioning_session);
                            content_hosting_config = NULL;

                            if(rv){

                                ogs_debug("Content Hosting Configuration created successfully");
                                if (msaf_application_server_state_set_on_post(msaf_provisioning_session)) {
                                    chc = msaf_get_content_hosting_configuration_by_provisioning_session_id(
                                            message->h.resource.component[1]);
                                    if (chc != NULL) {
                                        char *text;
                                        msaf_provisioning_session = msaf_provisioning_session_find_by_provisioningSessionId(
                                                message->h.resource.component[1]);
                                        response = nf_server_new_response(request->h.uri, "application/json",
                                                                          msaf_provisioning_session->contentHostingConfigurationReceived,
                                                                          msaf_provisioning_session->contentHostingConfigurationHash,
                                                                          msaf_self()->config.server_response_cache_control->m1_content_hosting_configurations_response_max_age,
                                                                          NULL, m1_contenthostingprovisioning_api, app_meta);
                                        ogs_assert(response);
                                        text = cJSON_Print(chc);
                                        nf_server_populate_response(response, strlen(text), text, 201);
                                        ogs_assert(true == ogs_sbi_server_send_response(stream, response));
                                        response = NULL;
                                        cJSON_Delete(chc);
                                    } else {
                                        char *err = NULL;
                                        err = ogs_msprintf("Unable to retrieve the Content Hosting Configuration for the Provisioning Session [%s].", message->h.resource.component[1]);
                                        ogs_error("%s", err);
                                        ogs_assert(true == nf_server_send_error(stream, 404, 2, message, "Unable to retrieve the Content Hosting Configuration.", err, NULL, m1_contenthostingprovisioning_api, app_meta));
                                        ogs_free(err);
                                    }
                                } else {
                                    char *err = NULL;
                                    err = ogs_msprintf("Verification error on Content Hosting Configuration for the Provisioning Session [%s].", message->h.resource.component[1]);
                                    ogs_error("%s", err);
                                    ogs_assert(true == nf_server_send_error(stream, 400, 2, message, "Bad Content Hosting Configuration.", err, NULL, m1_contenthostingprovisioning_api, app_meta));
                                    ogs_free(err);
                                }
                            } else {
                                char *err = NULL;
                                err = ogs_msprintf("Creation of the Content Hosting Configuration failed for the Provisioning Session [%s]", message->h.resource.component[1]);
                                ogs_error("%s", err);
                                ogs_assert(true == nf_server_send_error(stream, 500, 2, message, "Creation of the Content Hosting Configuration failed.", err, NULL, m1_contenthostingprovisioning_api, app_meta));
                                ogs_free(err);
                            }
                        }

                        if (content_hosting_config) cJSON_Delete(content_hosting_config);

                    } else {
                        char *err = NULL;
                        err = ogs_msprintf("Provisioning session [%s]does not exist.", message->h.resource.component[1]);
                        ogs_error("%s",err);
                        ogs_assert(true == nf_server_send_error(stream, 404, 2, message, "Provisioning session does not exist.", err, NULL, m1_contenthostingprovisioning_api, app_meta));
                        ogs_free(err);
                    }

                }
                if (!strcmp(message->h.resource.component[2],"certificates")) {
                    ogs_info("POST certificates");
                    ogs_hash_index_t *hi;
                    char *canonical_domain_name;
                    char *cert;
                    int csr = 0;

                    for (hi = ogs_hash_first(request->http.params);
                         hi; hi = ogs_hash_next(hi)) {
                        if (!ogs_strcasecmp(ogs_hash_this_key(hi), "csr")) {
                            csr = 1;
                            break;
                        }
                    }

                    msaf_provisioning_session = msaf_provisioning_session_find_by_provisioningSessionId(message->h.resource.component[1]);
                    if (msaf_provisioning_session) {
                        msaf_application_server_node_t *msaf_as = NULL;
                        msaf_as = ogs_list_first(&msaf_self()->config.applicationServers_list);
                        canonical_domain_name = msaf_as->canonicalHostname;
                        ogs_info("canonical_domain_name: %s", canonical_domain_name);

                        if (csr) {
                            msaf_certificate_t *csr_cert;
                            char *location;
                            int m1_server_certificates_response_max_age;
                            csr_cert = server_cert_new("newcsr", canonical_domain_name);
                            ogs_hash_set(msaf_provisioning_session->certificate_map, msaf_strdup(csr_cert->id), OGS_HASH_KEY_STRING, msaf_strdup(csr_cert->id));
                            ogs_sbi_response_t *response;
                            location = ogs_msprintf("%s/%s", request->h.uri, csr_cert->id);
                            if(csr_cert->cache_control_max_age){
                                m1_server_certificates_response_max_age = csr_cert->cache_control_max_age;
                            } else {
                                m1_server_certificates_response_max_age = msaf_self()->config.server_response_cache_control->m1_server_certificates_response_max_age;
                            }
                            response = nf_server_new_response(location, "application/x-pem-file",  csr_cert->last_modified, csr_cert->server_certificate_hash, m1_server_certificates_response_max_age, NULL, m1_servercertificatesprovisioning_api, app_meta);

                            nf_server_populate_response(response, strlen(csr_cert->certificate), msaf_strdup(csr_cert->certificate), 200);

                            ogs_assert(response);
                            ogs_assert(true == ogs_sbi_server_send_response(stream, response));
                            ogs_free(location);
                            msaf_certificate_free(csr_cert);

                            break;
                        }

                        cert = check_in_cert_list(canonical_domain_name);
                        if (cert != NULL) {
                            ogs_sbi_response_t *response;
                            char *location;

                            ogs_hash_set(msaf_provisioning_session->certificate_map, msaf_strdup(cert), OGS_HASH_KEY_STRING, cert);

                            location = ogs_msprintf("%s/%s", request->h.uri, cert);
                            response = nf_server_new_response(location, NULL,  0, NULL, 0, NULL, m1_servercertificatesprovisioning_api, app_meta);
                            nf_server_populate_response(response, 0, NULL, 200);
                            ogs_assert(response);
                            ogs_assert(true == ogs_sbi_server_send_response(stream, response));
                            ogs_free(location);
                        } else {
                            msaf_certificate_t *new_cert;
                            int m1_server_certificates_response_max_age;
                            ogs_sbi_response_t *response;
                            char *location;
                            new_cert = server_cert_new("newcert", canonical_domain_name);
                            ogs_hash_set(msaf_provisioning_session->certificate_map, msaf_strdup(new_cert->id), OGS_HASH_KEY_STRING, msaf_strdup(new_cert->id));

                            location = ogs_msprintf("%s/%s", request->h.uri, new_cert->id);
                            if(new_cert->cache_control_max_age){
                                m1_server_certificates_response_max_age = new_cert->cache_control_max_age;
                            } else {
                                m1_server_certificates_response_max_age = msaf_self()->config.server_response_cache_control->m1_server_certificates_response_max_age;
                            }
                            response = nf_server_new_response(location, NULL,  new_cert->last_modified, new_cert->server_certificate_hash, m1_server_certificates_response_max_age, NULL, m1_servercertificatesprovisioning_api, app_meta);
                            nf_server_populate_response(response, 0, NULL, 200);
                            ogs_assert(response);
                            ogs_assert(true == ogs_sbi_server_send_response(stream, response));
                            ogs_free(location);
                            msaf_certificate_free(new_cert);
                        }
                    } else {
                        char *err = NULL;
                        err = ogs_msprintf("Provisioning session [%s] does not exists.", message->h.resource.component[1]);
                        ogs_error("%s", err);
                        ogs_assert(true == nf_server_send_error(stream, 404, 2, message, "Provisioning session does not exists.", err, NULL, m1_servercertificatesprovisioning_api, app_meta));
                        ogs_free(err);
                    }
                }

            } else if (message->h.resource.component[1] && !message->h.resource.component[2]){
                msaf_provisioning_session_t *msaf_provisioning_session;
                msaf_provisioning_session = msaf_provisioning_session_find_by_provisioningSessionId(message->h.resource.component[1]);
                if(msaf_provisioning_session) {
                    char *err = NULL;
                    err = ogs_msprintf("Method [%s] not allowed for [%s].", message->h.method, message->h.resource.component[1]);
                    ogs_error("%s", err);
                    ogs_assert(true == nf_server_send_error(stream, 405, 1, message, "Method not allowed.", err, NULL, m1_provisioningsession_api, app_meta));
                    ogs_free(err);

                } else {
                    char *err = NULL;
                    err = ogs_msprintf("Provisioning session [%s] does not exist.", message->h.resource.component[1]);
                    ogs_error("%s", err);
                    ogs_assert(true == nf_server_send_error(stream, 404, 1, message, "Provisioning session does not exist.", err, NULL, m1_provisioningsession_api, app_meta));
                    ogs_free(err);
                }

            } else {
                cJSON *entry;
                cJSON *prov_sess;
                cJSON *provisioning_session;
                char *provisioning_session_type = NULL, *external_app_id = NULL, *asp_id = NULL;
                msaf_provisioning_session_t *msaf_provisioning_session;

                ogs_debug("createProvisioningSession: received=\"%s\"", request->http.content);

                prov_sess = cJSON_Parse(request->http.content);
                if (!prov_sess) {
                    const char *err = "createProvisioningSession: Could not parse request body as JSON";
                    ogs_error(err);
                    ogs_assert(true == nf_server_send_error(stream, 400, 1, message, "Creation of the Provisioning session failed.", err, NULL, m1_provisioningsession_api, app_meta));
                    break;
                }
                entry = cJSON_GetObjectItemCaseSensitive(prov_sess, "provisioningSessionType");
                if (!entry) {
                    const char *err = "createProvisioningSession: \"provisioningSessionType\" is not present";
                    ogs_error(err);
                    ogs_assert(true == nf_server_send_error(stream, 400, 1, message, "Creation of the Provisioning session failed.", err, NULL, m1_provisioningsession_api, app_meta));
                    break;
                }
                if (!cJSON_IsString(entry)) {
                    const char *err = "createProvisioningSession: \"provisioningSessionType\" is not a string";
                    ogs_error(err);
                    ogs_assert(true == nf_server_send_error(stream, 400, 1, message, "Creation of the Provisioning session failed.", err, NULL, m1_provisioningsession_api, app_meta));
                    break;
                }
                provisioning_session_type = entry->valuestring;

                entry = cJSON_GetObjectItemCaseSensitive(prov_sess, "externalApplicationId");
                if (!entry) {
                    const char *err = "createProvisioningSession: \"externalApplicationId\" is not present";
                    ogs_error(err);
                    ogs_assert(true == nf_server_send_error(stream, 400, 1, message, "Creation of the Provisioning session failed.", err, NULL, m1_provisioningsession_api, app_meta));
                    break;
                }
                if (!cJSON_IsString(entry)) {
                    const char *err = "createProvisioningSession: \"externalApplicationId\" is not a string";
                    ogs_error(err);
                    ogs_assert(true == nf_server_send_error(stream, 400, 1, message, "Creation of the Provisioning session failed.", err, NULL, m1_provisioningsession_api, app_meta));
                    break;
                }
                external_app_id = entry->valuestring;

                entry = cJSON_GetObjectItemCaseSensitive(prov_sess, "aspId");
                if (entry) {
                    if (!cJSON_IsString(entry)) {
                        const char *err = "createProvisioningSession: \"aspId\" is not a string";
                        ogs_error(err);
                        ogs_assert(true == nf_server_send_error(stream, 400, 1, message, "Creation of the Provisioning session failed.", err, NULL, m1_provisioningsession_api, app_meta));
                        break;
                    }
                    asp_id = entry->valuestring;
                }

                msaf_provisioning_session = msaf_provisioning_session_create(provisioning_session_type, asp_id, external_app_id);
                provisioning_session = msaf_provisioning_session_get_json(msaf_provisioning_session->provisioningSessionId);
                if (provisioning_session != NULL) {
                    ogs_sbi_response_t *response;
                    char *text;
                    char *location;
                    text = cJSON_Print(provisioning_session);
                    if (request->h.uri[strlen(request->h.uri)-1] != '/') {
                        location = ogs_msprintf("%s/%s", request->h.uri,msaf_provisioning_session->provisioningSessionId);
                    } else {
                        location = ogs_msprintf("%s%s", request->h.uri,msaf_provisioning_session->provisioningSessionId);
                    }
                    response = nf_server_new_response(location, "application/json",  msaf_provisioning_session->provisioningSessionReceived, msaf_provisioning_session->provisioningSessionHash, msaf_self()->config.server_response_cache_control->m1_provisioning_session_response_max_age, NULL, m1_provisioningsession_api, app_meta);

                    nf_server_populate_response(response, strlen(text), text, 201);
                    ogs_assert(response);
                    ogs_assert(true == ogs_sbi_server_send_response(stream, response));
                    ogs_free(location);
                    cJSON_Delete(provisioning_session);
                } else {
                    const char *err = "Creation of the Provisioning session failed.";
                    ogs_error(err);
                    ogs_assert(true == nf_server_send_error(stream, 404, 1, message, "Creation of the Provisioning session failed.", err, NULL, m1_provisioningsession_api, app_meta));
                }
                if (prov_sess) cJSON_Delete(prov_sess);
            }

            break;

            CASE(OGS_SBI_HTTP_METHOD_GET)
            if (message->h.resource.component[1] && message->h.resource.component[2] && message->h.resource.component[3] && !message->h.resource.component[4]) {
                if (!strcmp(message->h.resource.component[2],"certificates") ) {
                    msaf_provisioning_session_t *msaf_provisioning_session;
                    msaf_provisioning_session = msaf_provisioning_session_find_by_provisioningSessionId(message->h.resource.component[1]);
                    if (msaf_provisioning_session) {
                        msaf_certificate_t *cert;
                        ogs_sbi_response_t *response;
                        const char *provisioning_session_cert;
                        provisioning_session_cert = ogs_hash_get(msaf_provisioning_session->certificate_map, message->h.resource.component[3], OGS_HASH_KEY_STRING);
                        if(!provisioning_session_cert) {
                            char *err = NULL;
                            err = ogs_msprintf("Certificate [%s] not found in provisioning session [%s]", message->h.resource.component[3], message->h.resource.component[1]);
                            ogs_error("%s", err);
                            ogs_assert(true == nf_server_send_error(stream, 404, 3, message, "Certificate not found.", err, NULL, m1_servercertificatesprovisioning_api, app_meta));
                            ogs_free(err);
                            break;
                        }
                        cert = server_cert_retrieve(message->h.resource.component[3]);
                        if (!cert) {
                            char *err = NULL;
                            err = ogs_msprintf("Certificate [%s] management problem", message->h.resource.component[3]);
                            ogs_error("%s", err);
                            ogs_assert(true == nf_server_send_error(stream, 500, 3, message, "Certificate management problem.", err, NULL, m1_servercertificatesprovisioning_api, app_meta));
                            ogs_free(err);
                            break;
                        }

                        if(!cert->return_code) {
                            int m1_server_certificates_response_max_age;
                            if(cert->cache_control_max_age){
                                m1_server_certificates_response_max_age = cert->cache_control_max_age;
                            } else {
                                m1_server_certificates_response_max_age = msaf_self()->config.server_response_cache_control->m1_server_certificates_response_max_age;
                            }
                            response = nf_server_new_response(NULL, "application/x-pem-file",  cert->last_modified, cert->server_certificate_hash, m1_server_certificates_response_max_age, NULL, m1_servercertificatesprovisioning_api, app_meta);
                            nf_server_populate_response(response, strlen(cert->certificate), msaf_strdup(cert->certificate), 200);
                            ogs_assert(response);
                            ogs_assert(true == ogs_sbi_server_send_response(stream, response));
                        } else if(cert->return_code == 4){
                            char *err = NULL;
                            err = ogs_msprintf("Certificate [%s] does not exists.", cert->id);
                            ogs_error("%s", err);
                            ogs_assert(true == nf_server_send_error(stream, 404, 3, message, "Certificate does not exists.", err, NULL, m1_servercertificatesprovisioning_api, app_meta));
                            ogs_free(err);
                        } else if(cert->return_code == 8){
                            ogs_sbi_response_t *response;
                            response = nf_server_new_response(NULL, NULL, 0, NULL, 0, NULL, m1_servercertificatesprovisioning_api, app_meta);
                            nf_server_populate_response(response, 0, NULL, 204);
                            ogs_assert(response);
                            ogs_assert(true == ogs_sbi_server_send_response(stream, response));
                        } else {
                            char *err = NULL;
                            err = ogs_msprintf("Certificate [%s] management problem.", cert->id);
                            ogs_error("%s", err);
                            ogs_assert(true == nf_server_send_error(stream, 500, 3, message, "Certificate management problem.", err, NULL, m1_servercertificatesprovisioning_api, app_meta));
                            ogs_free(err);
                        }
                        msaf_certificate_free(cert);

                    } else {
                        char *err = NULL;
                        err = ogs_msprintf("Provisioning session [%s] is not available.", message->h.resource.component[1]);
                        ogs_error("%s", err);
                        ogs_assert(true == nf_server_send_error(stream, 404, 3, message, "Provisioning session does not exists.", err, NULL, m1_servercertificatesprovisioning_api, app_meta));
                        ogs_free(err);
                    }
                }
            } else if (message->h.resource.component[1] && message->h.resource.component[2] && !message->h.resource.component[3]) {
                msaf_provisioning_session_t *msaf_provisioning_session;
                msaf_provisioning_session = msaf_provisioning_session_find_by_provisioningSessionId(message->h.resource.component[1]);
                if (!strcmp(message->h.resource.component[2],"content-hosting-configuration")) {
                    if(msaf_provisioning_session) {
                        cJSON *chc;
                        chc = msaf_get_content_hosting_configuration_by_provisioning_session_id(message->h.resource.component[1]);
                        if (chc != NULL) {
                            ogs_sbi_response_t *response;
                            char *text;
                            text = cJSON_Print(chc);

                            response = nf_server_new_response(request->h.uri,
                                                              "application/json",
                                                              msaf_provisioning_session->contentHostingConfigurationReceived,
                                                              msaf_provisioning_session->contentHostingConfigurationHash,
                                                              msaf_self()->config.server_response_cache_control->m1_content_hosting_configurations_response_max_age,
                                                              NULL, m1_contenthostingprovisioning_api,
                                                              app_meta);
                            ogs_assert(response);
                            nf_server_populate_response(response, strlen(text), text, 200);
                            ogs_assert(true == ogs_sbi_server_send_response(stream, response));

                            cJSON_Delete(chc);
                        } else {
                            char *err = NULL;
                            err = ogs_msprintf("Provisioning Session [%s]: Unable to retrieve the Content Hosting Configuration", message->h.resource.component[1]);
                            ogs_error("%s", err);
                            ogs_assert(true == nf_server_send_error(stream, 404, 2, message, "Unable to retrieve the Content Hosting Configuration.", err, NULL, m1_contenthostingprovisioning_api, app_meta));
                            ogs_free(err);
                        }

                    } else {
                        char *err = NULL;
                        err = ogs_msprintf("Provisioning Session [%s] does not exist.", message->h.resource.component[1]);
                        ogs_error("%s", err);

                        ogs_assert(true == nf_server_send_error(stream, 404, 2, message, "Provisioning session does not exist.", err, NULL, m1_contenthostingprovisioning_api, app_meta));
                        ogs_free(err);
                    }

                } else if (!strcmp(message->h.resource.component[2],"protocols")) {
                    if(msaf_provisioning_session) {
                        ogs_sbi_response_t *response;
                        ogs_info("CONTENT_PROTOCOLS_DISCOVERY_JSON: %s", CONTENT_PROTOCOLS_DISCOVERY_JSON);
                        response = nf_server_new_response(NULL, "application/json",  CONTENT_PROTOCOLS_DISCOVERY_JSON_TIME, CONTENT_PROTOCOLS_DISCOVERY_JSON_HASH, msaf_self()->config.server_response_cache_control->m1_content_protocols_response_max_age, NULL, m1_contentprotocolsdiscovery_api, app_meta);
                        ogs_assert(response);
                        nf_server_populate_response(response, strlen(CONTENT_PROTOCOLS_DISCOVERY_JSON), msaf_strdup(CONTENT_PROTOCOLS_DISCOVERY_JSON), 200);
                        ogs_assert(true == ogs_sbi_server_send_response(stream, response));
                    } else {
                        char *err = NULL;
                        err = ogs_msprintf("Provisioning Session [%s] does not exist.", message->h.resource.component[1]);
                        ogs_error("%s", err);
                        ogs_assert(true == nf_server_send_error(stream, 404, 2, message, "Provisioning session does not exist.", err, NULL, m1_contentprotocolsdiscovery_api, app_meta));
                        ogs_free(err);
                    }
                }
            } else if (message->h.resource.component[1] && !message->h.resource.component[2]) {
                msaf_provisioning_session_t *msaf_provisioning_session = NULL;
                cJSON *provisioning_session = NULL;

                msaf_provisioning_session = msaf_provisioning_session_find_by_provisioningSessionId(message->h.resource.component[1]);

                provisioning_session = msaf_provisioning_session_get_json(message->h.resource.component[1]);

                if (provisioning_session && msaf_provisioning_session && !msaf_provisioning_session->marked_for_deletion) {
                    ogs_sbi_response_t *response;
                    char *text;
                    text = cJSON_Print(provisioning_session);

                    response = nf_server_new_response(NULL, "application/json",  msaf_provisioning_session->provisioningSessionReceived, msaf_provisioning_session->provisioningSessionHash, msaf_self()->config.server_response_cache_control->m1_provisioning_session_response_max_age, NULL, m1_provisioningsession_api, app_meta);

                    nf_server_populate_response(response, strlen(text), text, 200);
                    ogs_assert(response);
                    ogs_assert(true == ogs_sbi_server_send_response(stream, response));
                } else {
                    char *err = NULL;
                    err = ogs_msprintf("Provisioning Session [%s] is not available.", message->h.resource.component[1]);
                    ogs_error("%s", err);

                    ogs_assert(true == nf_server_send_error(stream, 404, 2, message, "Provisioning session does not exists.", err, NULL, m1_provisioningsession_api, app_meta));
                    ogs_free(err);
                }
                if (provisioning_session) cJSON_Delete(provisioning_session);
            }
            break;

            CASE(OGS_SBI_HTTP_METHOD_PUT)
            if (message->h.resource.component[1] && message->h.resource.component[2]) {

                ogs_info("PUT: %s", message->h.resource.component[1]);
                msaf_provisioning_session_t *msaf_provisioning_session;
                msaf_provisioning_session = msaf_provisioning_session_find_by_provisioningSessionId(message->h.resource.component[1]);
                if(msaf_provisioning_session) {
                    ogs_info("PUT: with msaf_provisioning_session: %s", message->h.resource.component[1]);
                    if (!strcmp(message->h.resource.component[2],"content-hosting-configuration") && !message->h.resource.component[3]) {

                        // process the PUT body
                        int rv;
                        cJSON *content_hosting_config = cJSON_Parse(request->http.content);

                        if (!content_hosting_config) {
                            char *err = NULL;
                            err = ogs_msprintf("While updating the Content Hosting Configuration for the Provisioning Session [%s], Failure parsing ContentHostingConfiguration JSON.",message->h.resource.component[1]);
                            ogs_error("%s", err);
                            ogs_assert(true == nf_server_send_error(stream, 422, 2, message, "Bad ContentHosting Configuration JSON.", err, NULL, m1_contenthostingprovisioning_api, app_meta));
                            ogs_free(err);
                            break;
                        }

                        {
                            char *txt = cJSON_Print(content_hosting_config);
                            ogs_debug("Parsed JSON: %s", txt);
                            cJSON_free(txt);
                        }

                        if(msaf_provisioning_session->contentHostingConfiguration) {
                            OpenAPI_content_hosting_configuration_free(msaf_provisioning_session->contentHostingConfiguration);
                            msaf_provisioning_session->contentHostingConfiguration = NULL;
                        }

                        if (msaf_provisioning_session->serviceAccessInformation) {
                            OpenAPI_service_access_information_resource_free(msaf_provisioning_session->serviceAccessInformation);
                            msaf_provisioning_session->serviceAccessInformation = NULL;
                        }

                        rv = msaf_distribution_create(content_hosting_config, msaf_provisioning_session);
                        content_hosting_config = NULL;
                        if (rv){
                            msaf_application_server_state_update(msaf_provisioning_session);

                            ogs_debug("Content Hosting Configuration updated successfully");

                            ogs_sbi_response_t *response;
                            response = ogs_sbi_response_new();
                            response->status = 204;
                            ogs_sbi_header_set(response->http.headers, "Content-Type", "application/json");
                            ogs_sbi_header_set(response->http.headers, "Location", request->h.uri);
                            ogs_assert(response);
                            ogs_assert(true == ogs_sbi_server_send_response(stream, response));
                        } else {
                            char *err = NULL;
                            err = ogs_msprintf("Provisioning Session [%s]: Update to Content Hosting Configuration failed.", message->h.resource.component[1]);
                            ogs_error("%s", err);
                            ogs_assert(true == nf_server_send_error(stream, 404, 2, message, "Failed to update the contentHostingConfiguration.", err, NULL, m1_contenthostingprovisioning_api, app_meta));
                            ogs_free(err);
                        }
                    }
                    else if (!strcmp(message->h.resource.component[2],"certificates") && message->h.resource.component[3] && !message->h.resource.component[4]) {
                        char *cert_id;
                        char *cert;
                        int rv;
                        ogs_sbi_response_t *response;
                        msaf_provisioning_session_t *msaf_provisioning_session;

                        {
                            ogs_hash_index_t *hi;
                            for (hi = ogs_hash_first(request->http.headers);
                                 hi; hi = ogs_hash_next(hi)) {
                                if (!ogs_strcasecmp(ogs_hash_this_key(hi), OGS_SBI_CONTENT_TYPE)) {
                                    if (ogs_strcasecmp(ogs_hash_this_val(hi), "application/x-pem-file")) {
                                        char *err = NULL;
                                        const char *type;
                                        type = ogs_hash_this_val(hi);
                                        err = ogs_msprintf( "Unsupported Media Type: received type: %s, should have been application/x-pem-file", type);
                                        ogs_error("%s", err);

                                        ogs_assert(true == nf_server_send_error(stream, 415, 3, message, "Unsupported Media Type.", err, NULL, m1_servercertificatesprovisioning_api, app_meta));
                                        ogs_free(err);
                                        ogs_sbi_message_free(message);
                                        ogs_free(message);
                                        return;

                                    }
                                }
                            }
                        }

                        msaf_provisioning_session = msaf_provisioning_session_find_by_provisioningSessionId(message->h.resource.component[1]);

                        if(msaf_provisioning_session) {
                            const char *provisioning_session_cert;
                            provisioning_session_cert = ogs_hash_get(msaf_provisioning_session->certificate_map, message->h.resource.component[3], OGS_HASH_KEY_STRING);
                            cert_id = message->h.resource.component[3];
                            cert = msaf_strdup(request->http.content);
                            rv = server_cert_set(cert_id, cert);
                            // response = ogs_sbi_response_new();

                            if (rv == 0 &&  provisioning_session_cert){
                                response = nf_server_new_response(NULL, NULL,  0, NULL, 0, NULL, m1_servercertificatesprovisioning_api, app_meta);
                                nf_server_populate_response(response, 0, NULL, 204);
                                ogs_assert(response);
                                ogs_assert(true == ogs_sbi_server_send_response(stream, response));
                            } else if (rv == 3 &&  provisioning_session_cert ) {

                                char *err = NULL;
                                err = ogs_msprintf("A server certificate with id [%s] already exist", cert_id);
                                ogs_error("%s", err);
                                ogs_assert(true == nf_server_send_error(stream, 403, 3, message, "A server certificate already exist.", err, NULL, m1_servercertificatesprovisioning_api, app_meta));
                                ogs_free(err);
                            } else if(rv == 4 || ! provisioning_session_cert) {
                                char *err = NULL;
                                err = ogs_msprintf("Server certificate with id [%s] does not exist", cert_id);
                                ogs_error("%s", err);
                                ogs_assert(true == nf_server_send_error(stream, 404, 3, message, "Server certificate does not exist.", err, NULL, m1_servercertificatesprovisioning_api, app_meta));
                                ogs_free(err);
                            } else if(rv == 5) {
                                char *err = NULL;
                                err = ogs_msprintf("CSR was never generated for this certificate Id [%s]", cert_id);
                                ogs_error("%s", err);
                                ogs_assert(true == nf_server_send_error(stream, 400, 3, message, "CSR was never generated for the certificate.", err, NULL, m1_servercertificatesprovisioning_api, app_meta));
                                ogs_free(err);
                            } else if(rv == 6) {
                                char *err = NULL;
                                err = ogs_msprintf("The public certificate [%s] provided does not match the key", cert_id);
                                ogs_error("%s", err);
                                ogs_assert(true == nf_server_send_error(stream, 400, 3, message, "The public certificate provided does not match the key.", err, NULL, m1_servercertificatesprovisioning_api, app_meta));
                                ogs_free(err);
                            } else {
                                char *err = NULL;
                                err = ogs_msprintf("There was a certificate management problem for the certificate id [%s].", cert_id);
                                ogs_error("%s", err);

                                ogs_assert(true == nf_server_send_error(stream, 500, 3, message, "There was a certificate management problem.", err, NULL, m1_servercertificatesprovisioning_api, app_meta));
                                ogs_free(err);
                            }
                            ogs_free(cert);
                        }

                    } else {
                        char *err = NULL;
                        err = ogs_msprintf("[%s]: Resource not found.", message->h.method);
                        ogs_error("%s", err);
                        ogs_assert(true == nf_server_send_error(stream, 404, 1, message, "Resource not found.", err, NULL, m1_provisioningsession_api, app_meta));
                        ogs_free(err);
                    }
                } else {
                    char *err = NULL;
                    err = ogs_msprintf("Provisioning Session [%s] does not exist.", message->h.resource.component[1]);
                    ogs_error("%s", err);
                    ogs_assert(true == nf_server_send_error(stream, 404, 3, message, "Provisioning session does not exist.", err, NULL, m1_servercertificatesprovisioning_api, app_meta));
                    ogs_free(err);
                }


            } else {
                char *err = NULL;
                err = ogs_msprintf("[%s]: Resource not found.", message->h.method);
                ogs_error("%s", err);
                ogs_assert(true == nf_server_send_error(stream, 404, 1, message, "Resource not found.", err, NULL, m1_provisioningsession_api, app_meta));
                ogs_free(err);
            }
            break;

            CASE(OGS_SBI_HTTP_METHOD_DELETE)

            if (message->h.resource.component[1] && message->h.resource.component[2] && !strcmp(message->h.resource.component[2],"certificates") && message->h.resource.component[3] && !message->h.resource.component[4]) {
                ogs_sbi_response_t *response;
                msaf_provisioning_session_t *provisioning_session = NULL;
                provisioning_session = msaf_provisioning_session_find_by_provisioningSessionId(message->h.resource.component[1]);
                if (provisioning_session) {
                    int rv;
                    rv = server_cert_delete(message->h.resource.component[3]);
                    if ((rv == 0) || (rv == 8)){
                        response = nf_server_new_response(NULL, NULL,  0, NULL, 0, NULL, m1_servercertificatesprovisioning_api, app_meta);
                        nf_server_populate_response(response, 0, NULL, 204);
                        ogs_assert(response);
                        ogs_assert(true == ogs_sbi_server_send_response(stream, response));
                        msaf_provisioning_session_certificate_hash_remove(message->h.resource.component[1], message->h.resource.component[3]);

                    } else if (rv == 4 ) {
                        char *err = NULL;
                        err = ogs_msprintf("Certificate [%s] does not exist.", message->h.resource.component[3]);
                        ogs_error("%s", err);

                        ogs_assert(true == nf_server_send_error(stream, 404, 3, message, "Certificate does not exist.", err, NULL, m1_servercertificatesprovisioning_api, app_meta));
                        ogs_free(err);
                    } else {
                        char *err = NULL;
                        err = ogs_msprintf("Certificate management problem for certificate [%s].", message->h.resource.component[3]);
                        ogs_error("%s", err);

                        ogs_assert(true == nf_server_send_error(stream, 500, 3, message, "Certificate management problem.", err, NULL, m1_servercertificatesprovisioning_api, app_meta));
                        ogs_free(err);
                    }

                } else {
                    char *err = NULL;
                    err = ogs_msprintf("Provisioning Session [%s] does not exist.", message->h.resource.component[1]);
                    ogs_error("%s", err);

                    ogs_assert(true == nf_server_send_error(stream, 404, 3, message, "Provisioning session does not exist.", err, NULL, m1_servercertificatesprovisioning_api, app_meta));
                    ogs_free(err);
                }
            } else if (message->h.resource.component[1] && message->h.resource.component[2] && !message->h.resource.component[3]) {
                msaf_provisioning_session_t *msaf_provisioning_session;
                ogs_sbi_response_t *response;
                if (!strcmp(message->h.resource.component[2],"content-hosting-configuration")) {
                    msaf_provisioning_session = msaf_provisioning_session_find_by_provisioningSessionId(message->h.resource.component[1]);
                    if(msaf_provisioning_session){
                        if(msaf_provisioning_session && msaf_provisioning_session->contentHostingConfiguration) {
                            msaf_delete_content_hosting_configuration(message->h.resource.component[1]);
                            OpenAPI_content_hosting_configuration_free(msaf_provisioning_session->contentHostingConfiguration);
                            msaf_provisioning_session->contentHostingConfiguration = NULL;
                            response = nf_server_new_response(NULL, NULL,  0, NULL, 0, NULL, m1_contenthostingprovisioning_api, app_meta);
                            ogs_assert(response);
                            nf_server_populate_response(response, 0, NULL, 204);
                            ogs_assert(true == ogs_sbi_server_send_response(stream, response));
                            break;
                        } else {
                            char *err = NULL;
                            err = ogs_msprintf("Provisioning Session [%s] has no Content Hosting Configuration.", message->h.resource.component[1]);
                            ogs_error("%s", err);
                            ogs_assert(true == nf_server_send_error(stream, 404, 2, message, "Content Hosting Configuration does not exist.", err, NULL, m1_contenthostingprovisioning_api, app_meta));
                            ogs_free(err);
                        }
                    } else {
                        char *err = NULL;
                        err = ogs_msprintf("Provisioning Session [%s] does not exists.", message->h.resource.component[1]);
                        ogs_error("%s", err);
                        ogs_assert(true == nf_server_send_error(stream, 404, 2, message, "Provisioning session does not exist.", err, NULL, m1_contenthostingprovisioning_api, app_meta));
                        ogs_free(err);
                    }

                }

            } else if (message->h.resource.component[1] && !message->h.resource.component[2]) {
                ogs_sbi_response_t *response;
                msaf_provisioning_session_t *provisioning_session = NULL;
                provisioning_session = msaf_provisioning_session_find_by_provisioningSessionId(message->h.resource.component[1]);
                if(!provisioning_session || provisioning_session->marked_for_deletion){
                    char *err = NULL;
                    err = ogs_msprintf("Provisioning session [%s] either not found or already marked for deletion.", message->h.resource.component[1]);

                    ogs_error("%s", err);

                    ogs_assert(true == nf_server_send_error(stream, 500, 3, message, "Provisioning session either not found or already marked for deletion.", err, NULL, m1_provisioningsession_api, app_meta));
                    ogs_free(err);
                } else {
                    provisioning_session->marked_for_deletion = 1;
                    response = nf_server_new_response(NULL, NULL,  0, NULL, 0, NULL, m1_provisioningsession_api, app_meta);
                    ogs_assert(response);
                    nf_server_populate_response(response, 0, NULL, 202);
                    ogs_assert(true == ogs_sbi_server_send_response(stream, response));
                    msaf_delete_content_hosting_configuration(message->h.resource.component[1]);
                    msaf_delete_certificates(message->h.resource.component[1]);
                    msaf_context_provisioning_session_free(provisioning_session);
                    msaf_provisioning_session_hash_remove(message->h.resource.component[1]);
                }
            } else {
                char *err = NULL;
                err = ogs_msprintf("[%s]: Resource not found.", message->h.method);
                ogs_error("%s", err);
                ogs_assert(true == nf_server_send_error(stream, 404, 1, message, "Resource not found.", err, NULL, m1_provisioningsession_api, app_meta));
                ogs_free(err);
            }

            break;
            CASE(OGS_SBI_HTTP_METHOD_OPTIONS)

            if (!strcmp(message->h.resource.component[0],"provisioning-sessions")){
                ogs_sbi_response_t *response;
                char *methods = NULL;

                if (message->h.resource.component[1]) {
                    msaf_provisioning_session_t *provisioning_session = NULL;
                    provisioning_session = msaf_provisioning_session_find_by_provisioningSessionId(message->h.resource.component[1]);
                    if (provisioning_session) {
                        if (message->h.resource.component[2]) {


                            if (!strcmp(message->h.resource.component[2],"certificates")) {
                                if (message->h.resource.component[3]) {
                                    msaf_certificate_t *cert;
                                    cert = server_cert_retrieve(message->h.resource.component[3]);
                                    if(cert){
                                        methods = ogs_msprintf("%s, %s, %s, %s",OGS_SBI_HTTP_METHOD_GET, OGS_SBI_HTTP_METHOD_PUT, OGS_SBI_HTTP_METHOD_DELETE, OGS_SBI_HTTP_METHOD_OPTIONS);
                                        response = nf_server_new_response(request->h.uri, NULL,  0, NULL, 0, methods, m1_servercertificatesprovisioning_api, app_meta);
                                        nf_server_populate_response(response, 0, NULL, 204);
                                        ogs_assert(response);
                                        ogs_assert(true == ogs_sbi_server_send_response(stream, response));
                                        msaf_certificate_free(cert);
                                    } else {
                                        char *err = NULL;
                                        err = ogs_msprintf("Certificate [%s] management problem", message->h.resource.component[3]);
                                        ogs_error("%s", err);
                                        ogs_assert(true == nf_server_send_error(stream, 500, 3, message, "Certificate management problem.", err, NULL, m1_servercertificatesprovisioning_api, app_meta));
                                        ogs_free(err);
                                        break;
                                    }
                                } else {
                                    methods = ogs_msprintf("%s",OGS_SBI_HTTP_METHOD_POST);
                                    response = nf_server_new_response(request->h.uri, NULL,  0, NULL, 0, methods, m1_servercertificatesprovisioning_api, app_meta);
                                    nf_server_populate_response(response, 0, NULL, 204);
                                    ogs_assert(response);
                                    ogs_assert(true == ogs_sbi_server_send_response(stream, response));
                                }

                            }  else if (!strcmp(message->h.resource.component[2],"content-hosting-configuration")) {
                                methods = ogs_msprintf("%s, %s, %s, %s, %s",OGS_SBI_HTTP_METHOD_POST, OGS_SBI_HTTP_METHOD_GET, OGS_SBI_HTTP_METHOD_PUT, OGS_SBI_HTTP_METHOD_DELETE, OGS_SBI_HTTP_METHOD_OPTIONS);
                                response = nf_server_new_response(request->h.uri, NULL,  0, NULL, 0, methods, m1_contenthostingprovisioning_api, app_meta);
                                nf_server_populate_response(response, 0, NULL, 204);
                                ogs_assert(response);
                                ogs_assert(true == ogs_sbi_server_send_response(stream, response));

                            } else {
                                char *err = NULL;
                                err = ogs_msprintf("Method [%s]: Target [%s] not yet supported.", message->h.method, message->h.resource.component[2]);
                                ogs_error("%s", err);
                                ogs_assert(true == nf_server_send_error(stream, 404, 2, message, "Target not yet supported.", err, NULL, NULL, app_meta));
                                ogs_free(err);
                            }
                        } else {
                            methods = ogs_msprintf("%s, %s, %s", OGS_SBI_HTTP_METHOD_GET, OGS_SBI_HTTP_METHOD_DELETE, OGS_SBI_HTTP_METHOD_OPTIONS);
                            response = nf_server_new_response(request->h.uri, NULL,  0, NULL, 0, methods, m1_provisioningsession_api, app_meta);
                            nf_server_populate_response(response, 0, NULL, 204);
                            ogs_assert(response);
                            ogs_assert(true == ogs_sbi_server_send_response(stream, response));

                        }
                        /*
                           nf_server_populate_response(response, 0, NULL, 204);
                           ogs_assert(response);
                           ogs_assert(true == ogs_sbi_server_send_response(stream, response));

                           if(methods) ogs_free(methods);
                           */
                    } else {
                        char *err = NULL;
                        int number_of_components;
                        const nf_server_interface_metadata_t *interface;
                        if (message->h.resource.component[2]){
                            if (!strcmp(message->h.resource.component[2],"certificates")) {
                                number_of_components = 2;
                                if (message->h.resource.component[3]) {
                                    number_of_components = 3;
                                }
                                interface = m1_servercertificatesprovisioning_api;
                            } else if (!strcmp(message->h.resource.component[2],"content-hosting-configuration")) {
                                number_of_components = 2;
                                interface = m1_contenthostingprovisioning_api;

                            }
                        } else if (message->h.resource.component[0]){
                            if (!strcmp(message->h.resource.component[0],"provisioning-sessions")){
                                number_of_components = 0;
                                if (message->h.resource.component[1]) {
                                    number_of_components = 1;
                                }
                                interface = m1_provisioningsession_api;

                            }
                        }
                        err = ogs_msprintf("Method [%s]: [%s] - Provisioning Session [%s] does not exist.", message->h.method, message->h.resource.component[2], message->h.resource.component[1]);
                        ogs_error("%s", err);
                        ogs_assert(true == nf_server_send_error(stream, 404, number_of_components, message, "Provisioning Session does not exists.", err, NULL, interface, app_meta));
                        ogs_free(err);
                    }

                } else {
                    methods = ogs_msprintf("%s, %s",OGS_SBI_HTTP_METHOD_POST, OGS_SBI_HTTP_METHOD_OPTIONS);
                    response = nf_server_new_response(request->h.uri, NULL,  0, NULL, 0, methods, m1_provisioningsession_api, app_meta);
                    nf_server_populate_response(response, 0, NULL, 204);
                    ogs_assert(response);
                    ogs_assert(true == ogs_sbi_server_send_response(stream, response));

                }
                if(methods) ogs_free(methods);
            } else {
                char *err = NULL;
                err = ogs_msprintf("Method [%s]: Target [%s] not yet supported.", message->h.method, message->h.resource.component[0]);
                ogs_error("%s", err);
                ogs_assert(true == nf_server_send_error(stream, 404, 0, message, "Target not yet supported.", err, NULL, m1_provisioningsession_api, app_meta));
                ogs_free(err);
            }
            break;

            DEFAULT
            ogs_error("Invalid HTTP method [%s]", message->h.method);
            ogs_assert(true == nf_server_send_error(stream, OGS_SBI_HTTP_STATUS_FORBIDDEN, 0, message, "Invalid HTTP method.", message->h.method, NULL, NULL, app_meta));
            END
            break;

            DEFAULT
            char *err = NULL;
            err = ogs_msprintf("Invalid resource name [%s]", message->h.resource.component[0]);
            ogs_error("%s", err);
            ogs_assert(true == nf_server_send_error(stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST, 0, message, "Invalid resource name", err, NULL, NULL, app_meta));
            ogs_free(err);
            END
            break;

            CASE("5gmag-rt-management")
            if (strcmp(message->h.api.version, "v1") != 0) {
                char *error;
                error = ogs_msprintf("Version [%s] not supported", message->h.api.version);
                ogs_error("%s", error);
                ogs_assert(true == nf_server_send_error(stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST, 1, NULL, "Not supported version", error, NULL, maf_management_api, app_meta));
                ogs_free(error);
                break;
            }
            if (!message->h.resource.component[0]) {
                const char *error = "Resource required for Management interface";
                ogs_error(error);
                ogs_assert(true == nf_server_send_error(stream, 404, 1, NULL, "Resource name required", error, NULL, maf_management_api, app_meta));
                break;
            }

            SWITCH(message->h.resource.component[0])

            CASE("provisioning-sessions")
            SWITCH(message->h.method)
            CASE(OGS_SBI_HTTP_METHOD_GET)
            char *provisioning_sessions = NULL;
            ogs_sbi_response_t *response;
            provisioning_sessions = enumerate_provisioning_sessions();
            if(provisioning_sessions) {
                response = nf_server_new_response(NULL, "application/json", 0, NULL, msaf_self()->config.server_response_cache_control->m1_provisioning_session_response_max_age, NULL, maf_management_api, app_meta);

                nf_server_populate_response(response, strlen(provisioning_sessions), provisioning_sessions, 200);
                ogs_assert(response);
                ogs_assert(true == ogs_sbi_server_send_response(stream, response));
                break;
            } else {
                ogs_error("Internal Server Error.");
                ogs_assert(true == nf_server_send_error(stream, OGS_SBI_HTTP_STATUS_INTERNAL_SERVER_ERROR, 0, message, "Internal Server Error.", message->h.method, NULL, maf_management_api, app_meta));
            }
            DEFAULT
            ogs_error("Invalid HTTP method [%s]", message->h.method);
            ogs_assert(true == nf_server_send_error(stream, OGS_SBI_HTTP_STATUS_FORBIDDEN, 0, message, "Invalid HTTP method.", message->h.method, NULL, maf_management_api, app_meta));
            END
            break;

            DEFAULT
            char *err = NULL;
            err = ogs_msprintf("Invalid resource name [%s]", message->h.resource.component[0]);
            ogs_error("%s", err);
            ogs_assert(true == nf_server_send_error(stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST, 0, message, "Invalid resource name", err, NULL, NULL, app_meta));
            ogs_free(err);
            END
            break;
            DEFAULT
            ogs_error("Invalid API name [%s]", message->h.service.name);
            ogs_assert(true == nf_server_send_error(stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST, 1, message, "Invalid API name.", message->h.service.name, NULL, NULL, app_meta));
            END
            break;

        case OGS_EVENT_SBI_CLIENT:
            ogs_assert(e);

            response = e->h.sbi.response;
            ogs_assert(response);
            message = e->message;
            {
                ogs_hash_index_t *hi;
                for (hi = ogs_hash_first(response->http.headers);
                     hi; hi = ogs_hash_next(hi)) {
                    if (!ogs_strcasecmp(ogs_hash_this_key(hi), OGS_SBI_CONTENT_TYPE)) {
                        message->http.content_type = ogs_hash_this_val(hi);
                    } else if (!ogs_strcasecmp(ogs_hash_this_key(hi), OGS_SBI_LOCATION)) {
                        message->http.location = ogs_hash_this_val(hi);
                    }
                }
            }

            message->res_status = response->status;

            SWITCH(message->h.service.name)
            CASE("3gpp-m3")
            SWITCH(message->h.resource.component[0])
            CASE("content-hosting-configurations")

            msaf_application_server_state_node_t *as_state;
            as_state = e->application_server_state;
            ogs_assert(as_state);

            if (message->h.resource.component[1] && message->h.resource.component[2]) {

                if (!strcmp(message->h.resource.component[2],"purge")) {

                    SWITCH(message->h.method)
                    CASE(OGS_SBI_HTTP_METHOD_POST)
                    purge_resource_id_node_t *purge_node = e->purge_node;

                    if (response->status == 204 || response->status == 200) {

                        purge_resource_id_node_t *content_hosting_cache, *next = NULL;

                        if (response->status == 200) {
                            //parse the int in response body
                            //Add the integer to purge_node->m1_purge_info->purged_entries_total;
                            ogs_hash_index_t *hi;
                            int purged_items_from_as = 0;
                            cJSON *number_of_cache_entries;

                            for (hi = ogs_hash_first(request->http.headers); hi; hi = ogs_hash_next(hi)) {
                                if (!ogs_strcasecmp(ogs_hash_this_key(hi), OGS_SBI_CONTENT_TYPE)) {
                                    if (ogs_strcasecmp(ogs_hash_this_val(hi), "application/json")) {
                                        char *err = NULL;
                                        const char *type;
                                        type = ogs_hash_this_val(hi);
                                        err = ogs_msprintf( "Unsupported Media Type: received type: %s, should have been application/x-www-form-urlencoded", type);
                                        ogs_error("%s", err);

                                        ogs_assert(true == nf_server_send_error(stream, 415, 2, message, "Provisioning session does not exist.", err, NULL, m3_contenthostingprovisioning_api, app_meta));
                                        ogs_free(err);
                                        ogs_sbi_message_free(message);
                                        ogs_free(message);
                                        return;
                                    }
                                }
                            }

                            number_of_cache_entries = cJSON_Parse(response->http.content);
                            if (number_of_cache_entries && cJSON_IsNumber(number_of_cache_entries)) {
                                ogs_debug("Purged entries return %d\n", number_of_cache_entries->valueint);
                                purged_items_from_as = number_of_cache_entries->valueint;
                            }
                            purge_node->m1_purge_info->purged_entries_total += purged_items_from_as;
                            if (number_of_cache_entries) cJSON_Delete(number_of_cache_entries);

                        }


                        ogs_list_for_each_safe(&as_state->purge_content_hosting_cache, next, content_hosting_cache){
                            if (purge_node->purge_regex) {
                                if(!strcmp(content_hosting_cache->provisioning_session_id, purge_node->provisioning_session_id) && !strcmp(content_hosting_cache->purge_regex, purge_node->purge_regex))
                                    break;
                            } else if(!strcmp(content_hosting_cache->provisioning_session_id, purge_node->provisioning_session_id)) {
                                break;
                            }
                        }
                        if(content_hosting_cache){
                            ogs_list_remove(&as_state->purge_content_hosting_cache, content_hosting_cache);
                            ogs_debug("M1 List Purge refs: %d, Event Purge node refs: %d ", content_hosting_cache->m1_purge_info->refs, purge_node->m1_purge_info->refs);

                            purge_node->m1_purge_info->refs--;
                            ogs_debug(" After decrement, M1 List Purge refs: %d, Event Purge node refs: %d ", content_hosting_cache->m1_purge_info->refs, purge_node->m1_purge_info->refs);
                            if(!purge_node->m1_purge_info->refs){
                                //  send M1 response with total from purge_node->m1_purge_info->purged_entries_total
                                //  ogs_free(purge_node->m1_purge_info);
                                ogs_sbi_response_t *response;
                                cJSON *purged_entries_total_json = cJSON_CreateNumber(purge_node->m1_purge_info->purged_entries_total);
                                char *purged_entries_total = cJSON_Print(purged_entries_total_json);
                                cJSON_Delete(purged_entries_total_json);
                                response = ogs_sbi_response_new();
                                response->http.content_length = strlen(purged_entries_total);
                                response->http.content = purged_entries_total;
                                response->status = 200;
                                ogs_sbi_header_set(response->http.headers, "Content-Type", "application/json");
                                ogs_assert(response);
                                ogs_assert(true == ogs_sbi_server_send_response(purge_node->m1_purge_info->m1_stream, response));

                                if(content_hosting_cache->m1_purge_info) ogs_free(content_hosting_cache->m1_purge_info);
                                if (content_hosting_cache->provisioning_session_id) ogs_free(content_hosting_cache->provisioning_session_id);
                                if(content_hosting_cache->purge_regex) ogs_free(content_hosting_cache->purge_regex);
                                ogs_free(content_hosting_cache);
                            }
                            msaf_application_server_state_log(&as_state->purge_content_hosting_cache, "Purge Content Hosting Cache list");

                        }
                    }


                    if((response->status == 404) || (response->status == 413) || (response->status == 414) || (response->status == 415) || (response->status == 422) || (response->status == 500) || (response->status == 503)) {
                        char *error;
                        purge_resource_id_node_t *content_hosting_cache, *next = NULL;
                        cJSON *purge_cache_err = NULL;
                        if(response->http.content){
                            purge_cache_err = cJSON_Parse(response->http.content);
                            char *txt = cJSON_Print(purge_cache_err);
                            ogs_debug("Parsed JSON: %s", txt);
                            cJSON_free(txt);
                        }

                        if(response->status == 404) {

                            ogs_error("Error message from the Application Server [%s] with response code [%d]: Cache not found\n", as_state->application_server->canonicalHostname, response->status);
                        } else if(response->status == 413) {
                            ogs_error("Error message from the Application Server [%s] with response code [%d]: Pay load too large\n", as_state->application_server->canonicalHostname, response->status);
                        } else if(response->status == 414) {
                            ogs_error("Error message from the Application Server [%s] with response code [%d]: URI too long\n", as_state->application_server->canonicalHostname, response->status);
                        } else if(response->status == 415) {
                            ogs_error("Error message from the Application Server [%s] with response code [%d]: Unsupported media type\n", as_state->application_server->canonicalHostname, response->status);
                        } else if(response->status == 422) {
                            ogs_error("Error message from the Application Server [%s] with response code [%d]: Unprocessable Entity\n", as_state->application_server->canonicalHostname, response->status);
                        } else if(response->status == 500) {
                            ogs_error("Error message from the Application Server [%s] with response code [%d]: Internal server error\n", as_state->application_server->canonicalHostname, response->status);
                        } else if(response->status == 503) {
                            ogs_error("Error message from the Application Server [%s] with response code [%d]: Service Unavailable\n", as_state->application_server->canonicalHostname, response->status);
                        } else {

                            ogs_error("Application Server [%s] sent unrecognised response code [%d]", as_state->application_server->canonicalHostname, response->status);
                        }

                        if (purge_node->purge_regex) {
                            error = ogs_msprintf("Application Server possibly encountered problem with regex %s", purge_node->purge_regex);
                        } else {
                            error = ogs_msprintf("Application Server unable to process the contained instructions");
                        }


                        ogs_assert(true == nf_server_send_error( purge_node->m1_purge_info->m1_stream,
                                                                 response->status, 3, &purge_node->m1_purge_info->m1_message, "Problem occured during cache purge", error, purge_cache_err, m1_contenthostingprovisioning_api, app_meta));
                        ogs_free(error);

                        ogs_list_for_each_safe(&as_state->purge_content_hosting_cache, next, content_hosting_cache){
                            if (purge_node->purge_regex) {
                                if(!strcmp(content_hosting_cache->provisioning_session_id, purge_node->provisioning_session_id) && !strcmp(content_hosting_cache->purge_regex, purge_node->purge_regex)) {

                                    ogs_list_remove(&as_state->purge_content_hosting_cache, content_hosting_cache);
                                    ogs_debug("M1 List Purge refs: %d, Event Purge node refs: %d ", content_hosting_cache->m1_purge_info->refs, purge_node->m1_purge_info->refs);
                                    if(content_hosting_cache->m1_purge_info) ogs_free(content_hosting_cache->m1_purge_info);
                                    if (content_hosting_cache->provisioning_session_id) ogs_free(content_hosting_cache->provisioning_session_id);
                                    if(content_hosting_cache->purge_regex) ogs_free(content_hosting_cache->purge_regex);
                                    ogs_free(content_hosting_cache);

                                }
                            } else if(!strcmp(content_hosting_cache->provisioning_session_id, purge_node->provisioning_session_id)) {

                                ogs_list_remove(&as_state->purge_content_hosting_cache, content_hosting_cache);
                                ogs_debug("M1 List Purge refs: %d, Event Purge node refs: %d ", content_hosting_cache->m1_purge_info->refs, purge_node->m1_purge_info->refs);
                                if(content_hosting_cache->m1_purge_info) ogs_free(content_hosting_cache->m1_purge_info);
                                if (content_hosting_cache->provisioning_session_id) ogs_free(content_hosting_cache->provisioning_session_id);
                                if(content_hosting_cache->purge_regex) ogs_free(content_hosting_cache->purge_regex);
                                ogs_free(content_hosting_cache);

                            }
                        }

                        if (purge_cache_err) cJSON_Delete(purge_cache_err);
                    }

                    next_action_for_application_server(as_state);
                    break;
                    END
                    break;

                }
            } else if (message->h.resource.component[1]) {

                SWITCH(message->h.method)
                CASE(OGS_SBI_HTTP_METHOD_POST)

                if (response->status == 201) {

                    ogs_debug("[%s] Method [%s] with Response [%d] recieved for Content Hosting Configuration [%s]", message->h.resource.component[0], message->h.method, response->status, message->h.resource.component[1]);

                    resource_id_node_t *content_hosting_configuration;
                    ogs_list_for_each(&as_state->upload_content_hosting_configurations,content_hosting_configuration) {
                        if(!strcmp(content_hosting_configuration->state, message->h.resource.component[1]))
                            break;
                    }
                    if(content_hosting_configuration) {

                        ogs_debug("Removing %s from upload_content_hosting_configurations", content_hosting_configuration->state);
                        ogs_list_remove(&as_state->upload_content_hosting_configurations, content_hosting_configuration);
                        ogs_debug("Adding %s to current_content_hosting_configurations",content_hosting_configuration->state);
                        ogs_list_add(as_state->current_content_hosting_configurations, content_hosting_configuration);
                    }

                }
                if(response->status == 405){
                    ogs_error("Content Hosting Configuration resource already exist at the specified path\n");
                }
                if(response->status == 413){
                    ogs_error("Payload too large\n");
                }
                if(response->status == 414){
                    ogs_error("URI too long\n");
                }
                if(response->status == 415){
                    ogs_error("Unsupported media type\n");
                }
                if(response->status == 500){
                    ogs_error("Internal server error\n");
                }
                if(response->status == 503){
                    ogs_error("Service unavailable\n");
                }
                next_action_for_application_server(as_state);
                break;
                CASE(OGS_SBI_HTTP_METHOD_PUT)
                if(response->status == 200 || response->status == 204) {

                    ogs_debug("[%s] Method [%s] with Response [%d] recieved for Content Hosting Configuration [%s]", message->h.resource.component[0], message->h.method, response->status, message->h.resource.component[1]);
                    resource_id_node_t *content_hosting_configuration;
                    ogs_list_for_each(&as_state->upload_content_hosting_configurations,content_hosting_configuration){
                        if(!strcmp(content_hosting_configuration->state, message->h.resource.component[1]))
                            break;
                    }
                    if(content_hosting_configuration) {

                        ogs_debug("Removing %s from upload_content_hosting_configurations", content_hosting_configuration->state);
                        ogs_free(content_hosting_configuration->state);
                        ogs_list_remove(&as_state->upload_content_hosting_configurations, content_hosting_configuration);
                        ogs_free(content_hosting_configuration);
                    }

                }
                if(response->status == 404){
                    ogs_error("Not Found\n");
                }
                if(response->status == 413){
                    ogs_error("Payload too large\n");
                }
                if(response->status == 414){
                    ogs_error("URI too long\n");
                }
                if(response->status == 415){
                    ogs_error("Unsupported Media Type\n");
                }
                if(response->status == 500){
                    ogs_error("Internal Server Error\n");
                }
                if(response->status == 503){
                    ogs_error("Service Unavailable\n");
                }
                next_action_for_application_server(as_state);
                break;
                CASE(OGS_SBI_HTTP_METHOD_DELETE)
                if(response->status == 204) {

                    ogs_debug("[%s] Method [%s] with Response [%d] recieved for Content Hosting Configuration [%s]", message->h.resource.component[0], message->h.method, response->status,message->h.resource.component[1]);

                    resource_id_node_t *content_hosting_configuration, *next = NULL;
                    resource_id_node_t *delete_content_hosting_configuration, *node = NULL;

                    if(as_state->current_content_hosting_configurations) {

                        ogs_list_for_each_safe(as_state->current_content_hosting_configurations, next, content_hosting_configuration){

                            if(!strcmp(content_hosting_configuration->state, message->h.resource.component[1]))
                                break;
                        }
                    }

                    if(content_hosting_configuration) {

                        msaf_application_server_state_log(as_state->current_content_hosting_configurations, "Current Content Hosting Configurations");

                        ogs_debug("Removing %s from current_content_hosting_configurations", content_hosting_configuration->state);
                        ogs_free(content_hosting_configuration->state);
                        ogs_list_remove(as_state->current_content_hosting_configurations, content_hosting_configuration);
                        ogs_free(content_hosting_configuration);
                        msaf_application_server_state_log(as_state->current_content_hosting_configurations, "Current Content Hosting Configurations");
                    }

                    ogs_list_for_each_safe(&as_state->delete_content_hosting_configurations, node, delete_content_hosting_configuration) {

                        if (!strcmp(delete_content_hosting_configuration->state, message->h.resource.component[1])) {

                            msaf_application_server_state_log(&as_state->delete_content_hosting_configurations, "Delete Content Hosting Configurations");

                            ogs_debug("Destroying Content Hosting Configuration: %s", delete_content_hosting_configuration->state);
                            ogs_free(delete_content_hosting_configuration->state);
                            ogs_list_remove(&as_state->delete_content_hosting_configurations, delete_content_hosting_configuration);
                            ogs_free(delete_content_hosting_configuration);

                            msaf_application_server_state_log(&as_state->delete_content_hosting_configurations, "Delete Content Hosting Configurations");
                        }
                    }

                }
                if(response->status == 404){
                    ogs_error("Not Found\n");
                }
                if(response->status == 413){
                    ogs_error("Payload too large\n");
                }
                if(response->status == 414){
                    ogs_error("URI too long\n");
                }
                if(response->status == 415){
                    ogs_error("Unsupported Media Type\n");
                }
                if(response->status == 500){
                    ogs_error("Internal Server Error\n");
                }
                if(response->status == 503){
                    ogs_error("Service Unavailable\n");
                }
                next_action_for_application_server(as_state);
                break;
                DEFAULT
                ogs_error("Unknown M3 Content Hosting Configuration operation [%s]", message->h.resource.component[1]);
                ogs_assert(true == nf_server_send_error(stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST, 0, message, "Unknown M3 Content Hosting Configuration operation", message->h.resource.component[1], NULL, NULL, app_meta));
                break;
                END
                break;
            } else {
                cJSON *entry;
                cJSON *chc_array = cJSON_Parse(response->http.content);
                resource_id_node_t *current_chc;
                SWITCH(message->h.method)
                CASE(OGS_SBI_HTTP_METHOD_GET)

                if(response->status == 200) {

                    ogs_debug("[%s] Method [%s] with Response [%d] for Content Hosting Configuration operation [%s]",
                              message->h.resource.component[0], message->h.method, response->status, message->h.resource.component[1]);

                    if (as_state->current_content_hosting_configurations == NULL) {
                        as_state->current_content_hosting_configurations = ogs_calloc(1,sizeof(*as_state->current_content_hosting_configurations));
                        ogs_assert(as_state->current_content_hosting_configurations);
                        ogs_list_init(as_state->current_content_hosting_configurations);

                    } else {
                        resource_id_node_t *next, *node;
                        ogs_list_for_each_safe(as_state->current_content_hosting_configurations, next, node) {
                            ogs_free(node->state);
                            ogs_list_remove(as_state->current_content_hosting_configurations, node);
                            ogs_free(node);
                        }
                    }
                    if (chc_array && cJSON_IsArray(chc_array)) {
                        cJSON_ArrayForEach(entry, chc_array) {
                            if (cJSON_IsString(entry)) {
                                char *id = strrchr(entry->valuestring, '/');
                                if (id == NULL) {
                                    id = entry->valuestring;
                                } else {
                                    id++;
                                }
                                current_chc = ogs_calloc(1, sizeof(*current_chc));
                                current_chc->state = msaf_strdup(id);
                                ogs_debug("Adding [%s] to the current Content Hosting Configuration list",
                                          current_chc->state);
                                ogs_list_add(as_state->current_content_hosting_configurations, current_chc);
                            } else {
                                char *txt = cJSON_Print(entry);
                                ogs_error("Expected array entries to be provisioning session id strings, got: %s", txt);
                                cJSON_free(txt);
                            }
                        }
                    } else {
                        ogs_error("Expected an array of provisioning session ids in response on M3, got: %s",
                                  response->http.content);
                    }
                }
                if (response->status == 500){
                    ogs_error("Received Internal Server error\n");
                }
                if (response->status == 503) {
                    ogs_error("Service Unavailable\n");
                }
                next_action_for_application_server(as_state);
                break;
                DEFAULT
                char *err = NULL;
                err = ogs_msprintf( "Unknown M3 Content Hosting Configuration operation [%s] with method [%s]", message->h.resource.component[1], message->h.method);
                ogs_error("%s", err);
                ogs_assert(true == nf_server_send_error(stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST, 0, message, "Unknown M3 Content Hosting Configuration operation", err, NULL, NULL, app_meta));
                ogs_free(err);
                break;
                END
                if (chc_array) cJSON_Delete(chc_array);
                break;
            }
            next_action_for_application_server(as_state);

            break;

            CASE("certificates")

            msaf_application_server_state_node_t *as_state;
            as_state = e->application_server_state;
            ogs_assert(as_state);
            if (message->h.resource.component[1]) {
                SWITCH(message->h.method)
                CASE(OGS_SBI_HTTP_METHOD_POST)
                if(response->status == 201) {

                    ogs_debug("[%s] Method [%s] with Response [%d] recieved for certificate [%s]", message->h.resource.component[0], message->h.method, response->status, message->h.resource.component[1]);

                    resource_id_node_t *certificate;

                    //Iterate upload_certs and find match strcmp resource component 0
                    ogs_list_for_each(&as_state->upload_certificates,certificate){
                        if(!strcmp(certificate->state, message->h.resource.component[1]))
                            break;
                    }
                    if(certificate) {

                        ogs_debug("Removing certificate [%s] from upload_certificates", certificate->state);

                        ogs_list_remove(&as_state->upload_certificates, certificate);

                        ogs_debug("Adding certificate [%s] to  current_certificates", certificate->state);

                        ogs_list_add(as_state->current_certificates, certificate);
                        // ogs_free(upload_cert_id);
                    }
                }
                if(response->status == 405){
                    ogs_error("Server Certificate resource already exist at the specified path\n");
                }
                if(response->status == 413){
                    ogs_error("Payload too large\n");
                }
                if(response->status == 414){
                    ogs_error("URI too long\n");
                }
                if(response->status == 415){
                    ogs_error("Unsupported media type\n");
                }
                if(response->status == 500){
                    ogs_error("Internal server error\n");
                }
                if(response->status == 503){
                    ogs_error("Service unavailable\n");
                }
                next_action_for_application_server(as_state);
                break;
                CASE(OGS_SBI_HTTP_METHOD_PUT)
                if(response->status == 200 || response->status == 204) {

                    ogs_debug("[%s] Method [%s] with Response [%d] recieved for certificate [%s]", message->h.resource.component[0], message->h.method, response->status,message->h.resource.component[1]);

                    resource_id_node_t *certificate;

                    msaf_application_server_state_log(&as_state->upload_certificates, "Upload Certificates");

                    //Iterate upload_certs and find match strcmp resource component 0
                    ogs_list_for_each(&as_state->upload_certificates,certificate){

                        if(!strcmp(certificate->state, message->h.resource.component[1]))
                            break;
                    }

                    if(!certificate){
                        ogs_debug("Certificate %s not found in upload certificates", message->h.resource.component[1]);
                    } else {
                        ogs_debug("Removing certificate [%s] from upload_certificates", certificate->state);
                        ogs_free(certificate->state);

                        ogs_list_remove(&as_state->upload_certificates, certificate);
                        ogs_free(certificate);
                    }
                }
                if(response->status == 404){
                    ogs_error("Not Found\n");
                }
                if(response->status == 413){
                    ogs_error("Payload too large\n");
                }
                if(response->status == 414){
                    ogs_error("URI too long\n");
                }
                if(response->status == 415){
                    ogs_error("Unsupported Media Type\n");
                }
                if(response->status == 500){
                    ogs_error("Internal Server Error\n");
                }
                if(response->status == 503){
                    ogs_error("Service Unavailable\n");
                }
                next_action_for_application_server(as_state);
                break;
                CASE(OGS_SBI_HTTP_METHOD_DELETE)
                if(response->status == 204) {

                    ogs_debug("[%s] Method [%s] with Response [%d] recieved for Certificate [%s]", message->h.resource.component[0], message->h.method, response->status,message->h.resource.component[1]);

                    resource_id_node_t *certificate, *next = NULL;
                    resource_id_node_t *delete_certificate, *node = NULL;

                    if(as_state->current_certificates) {
                        ogs_list_for_each_safe(as_state->current_certificates, next, certificate){

                            if(!strcmp(certificate->state, message->h.resource.component[1]))
                                break;
                        }
                    }

                    if(certificate) {

                        msaf_application_server_state_log(as_state->current_certificates, "Current Certificates");

                        ogs_debug("Removing certificate [%s] from current_certificates", certificate->state);
                        ogs_free(certificate->state);

                        ogs_list_remove(as_state->current_certificates, certificate);
                        ogs_free(certificate);
                        msaf_application_server_state_log(as_state->current_certificates, "Current Certificates");
                    }


                    ogs_list_for_each_safe(&as_state->delete_certificates, node, delete_certificate){

                        if(!strcmp(delete_certificate->state, message->h.resource.component[1])) {
                            msaf_application_server_state_log(&as_state->delete_certificates, "Delete Certificates");

                            ogs_debug("Destroying Certificate: %s", delete_certificate->state);
                            ogs_free(delete_certificate->state);
                            ogs_list_remove(&as_state->delete_certificates, delete_certificate);
                            ogs_free(delete_certificate);
                            msaf_application_server_state_log(&as_state->delete_certificates, "Delete Certificates");

                        }
                    }
                }
                if(response->status == 404){
                    ogs_error("Not Found\n");
                }
                if(response->status == 413){
                    ogs_error("Payload too large\n");
                }
                if(response->status == 414){
                    ogs_error("URI too long\n");
                }
                if(response->status == 415){
                    ogs_error("Unsupported Media Type\n");
                }
                if(response->status == 500){
                    ogs_error("Internal Server Error\n");
                }
                if(response->status == 503){
                    ogs_error("Service Unavailable\n");
                }
                next_action_for_application_server(as_state);
                break;
                DEFAULT
                ogs_error("Unknown M3 certificate operation [%s]", message->h.resource.component[1]);
                ogs_assert(true == nf_server_send_error(stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST, 0, message, "Unknown M3 certificate operation.", message->h.resource.component[1], NULL, NULL, app_meta));
                break;
                END
                break;
            } else {
                cJSON *entry;
                cJSON *cert_array = cJSON_Parse(response->http.content);
                resource_id_node_t *current_cert;
                SWITCH(message->h.method)
                CASE(OGS_SBI_HTTP_METHOD_GET)

                if(response->status == 200) {

                    ogs_debug("[%s] Method [%s] with Response [%d] received",
                              message->h.resource.component[0], message->h.method, response->status);

                    if (as_state->current_certificates == NULL) {
                        as_state->current_certificates = ogs_calloc(1,sizeof(*as_state->current_certificates));
                        ogs_assert(as_state->current_certificates);
                        ogs_list_init(as_state->current_certificates);

                    } else {
                        resource_id_node_t *next, *node;
                        ogs_list_for_each_safe(as_state->current_certificates, next, node) {

                            ogs_debug("Removing certificate [%s] from current_certificates", node->state);

                            ogs_free(node->state);
                            ogs_list_remove(as_state->current_certificates, node);
                            ogs_free(node);
                        }
                    }
                    if (cert_array && cJSON_IsArray(cert_array)) {
                        cJSON_ArrayForEach(entry, cert_array) {
                            if (cJSON_IsString(entry)) {
                                char *id = strrchr(entry->valuestring, '/');
                                if (id == NULL) {
                                    id = entry->valuestring;
                                } else {
                                    id++;
                                }
                                current_cert = ogs_calloc(1, sizeof(*current_cert));
                                current_cert->state = msaf_strdup(id);
                                ogs_debug("Adding certificate [%s] to Current certificates", current_cert->state);
                                ogs_list_add(as_state->current_certificates, current_cert);
                            } else {
                                char *txt = cJSON_Print(entry);
                                ogs_error("Expected array entries to be certificate id strings, got: %s", txt);
                                cJSON_free(txt);
                            }
                        }
                    } else {
                        ogs_error("Expected an array of certificate ids in M3 response, got: %s",
                                  response->http.content);
                    }
                }
                if (response->status == 500){
                    ogs_error("Received Internal Server error");
                }
                if (response->status == 503) {
                    ogs_error("Service Unavailable");
                }
                next_action_for_application_server(as_state);
                break;
                DEFAULT
                char *err = NULL;
                err = ogs_msprintf( "Unsupported M3 Certificate operation [%s] with method [%s]", message->h.resource.component[1], message->h.method);
                ogs_error("%s", err);
                ogs_assert(true == nf_server_send_error(stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST, 0, message, "Unknown M3 Certificate operation", err, NULL, NULL, app_meta));
                ogs_free(err);
                break;
                END

                if (cert_array) cJSON_Delete(cert_array);
                break;
            }
            next_action_for_application_server(as_state);

            break;

            DEFAULT
            ogs_error("Unknown M3 operation [%s]", message->h.resource.component[0]);
            ogs_assert(true == nf_server_send_error(stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST, 0, message, "Unsupported M3 operation", message->h.resource.component[0], NULL, NULL, app_meta));
            break;
            END
            break;
            DEFAULT
            ogs_error("Invalid service name [%s]", message->h.service.name);
            ogs_assert_if_reached();
            END
            if (response) ogs_sbi_response_free(response);
            break;
        default:
            ogs_error("No handler for event %s", msaf_event_get_name(e));
            break;
    }
    if (message) {
        ogs_sbi_message_free(message);
        ogs_free(message);
    }
    ogs_free(nf_name);
}

/* vim:ts=8:sts=4:sw=4:expandtab:
*/