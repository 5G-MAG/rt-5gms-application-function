/*
License: 5G-MAG Public License (v1.0)
Author: Dev Audsin
Copyright: (C) 2022-2023 British Broadcasting Corporation

For full license terms please see the LICENSE file distributed with this
program. If this file is missing then the license can be retrieved from
https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
*/

#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ogs-core.h"

#include "context.h"
#include "provisioning-session.h"
#include "sai-cache.h"
#include "utilities.h"

#include "openapi/model/msaf_api_consumption_reporting_configuration.h"
#include "openapi/model/msaf_api_content_hosting_configuration.h"
#include "openapi/model/msaf_api_m5_media_entry_point.h"
#include "openapi/model/msaf_api_provisioning_session.h"
#include "openapi/model/msaf_api_service_access_information_resource.h"

#include "service-access-information.h"

static OpenAPI_list_t *_policy_templates_hash_to_list_of_ready_bindings(ogs_hash_t *policy_templates);

msaf_api_service_access_information_resource_t *
msaf_context_service_access_information_create(msaf_provisioning_session_t *provisioning_session, bool is_tls, const char *svr_hostname)
{
    msaf_api_service_access_information_resource_t *service_access_information;
    msaf_api_service_access_information_resource_streaming_access_t *streaming_access;
    msaf_configuration_t *config = &msaf_self()->config;
    msaf_api_service_access_information_resource_dynamic_policy_invocation_configuration_t *dpic = NULL;
    msaf_api_service_access_information_resource_client_consumption_reporting_configuration_t *ccrc = NULL;
    msaf_api_service_access_information_resource_network_assistance_configuration_t *nac = NULL;
    OpenAPI_list_t *entry_points = NULL;

    /* streaming entry points */
    ogs_debug("Adding streams to ServiceAccessInformation [%s]", provisioning_session->provisioningSessionId);
    if (provisioning_session->contentHostingConfiguration) {
        OpenAPI_lnode_t *node;
        OpenAPI_list_for_each(provisioning_session->contentHostingConfiguration->distribution_configurations, node) {
            msaf_api_distribution_configuration_t *dist_conf = node->data;
            if (dist_conf->entry_point && dist_conf->base_url) {
                msaf_api_m5_media_entry_point_t *m5_entry;
                char *url;
                OpenAPI_list_t *m5_profiles = NULL;

                if (dist_conf->entry_point->profiles) {
                    OpenAPI_lnode_t *prof_node;
                    m5_profiles = OpenAPI_list_create();
                    OpenAPI_list_for_each(dist_conf->entry_point->profiles, prof_node) {
                        OpenAPI_list_add(m5_profiles, ogs_strdup(prof_node->data));
                    }
                }

                url = ogs_msprintf("%s%s", dist_conf->base_url, dist_conf->entry_point->relative_path);
                m5_entry = msaf_api_m5_media_entry_point_create(url, ogs_strdup(dist_conf->entry_point->content_type), m5_profiles);
                ogs_assert(m5_entry);
                if (!entry_points) entry_points = OpenAPI_list_create();
                OpenAPI_list_add(entry_points, m5_entry);
            }
        }
    }
    streaming_access = msaf_api_service_access_information_resource_streaming_access_create(entry_points, NULL);

    // Dynamic policy invocation configuration
    if (provisioning_session->policy_templates) {
        OpenAPI_list_t *policy_templates_svr_list;
        OpenAPI_list_t *policy_template_bindings;
        msaf_api_sdf_method_e sdf_method = msaf_api_sdf_method__5_TUPLE;
        OpenAPI_list_t *sdf_methods;

        policy_template_bindings = _policy_templates_hash_to_list_of_ready_bindings(provisioning_session->policy_templates);

        if (policy_template_bindings) {
            if (policy_template_bindings->first != NULL) {
                ogs_debug("Adding dynamicPolicyInvocationConfiguration to ServiceAccessInformation [%s]",
                           provisioning_session->provisioningSessionId);

                policy_templates_svr_list = OpenAPI_list_create();
                ogs_assert(policy_templates_svr_list);
                OpenAPI_list_add(policy_templates_svr_list, ogs_msprintf("http%s://%s/3gpp-m5/v2/", is_tls?"s":"", svr_hostname));

                sdf_methods = OpenAPI_list_create();
                ogs_assert(sdf_methods);
                OpenAPI_list_add(sdf_methods, (void *)sdf_method);
        
                dpic = msaf_api_service_access_information_resource_dynamic_policy_invocation_configuration_create(
                            policy_templates_svr_list, policy_template_bindings, sdf_methods);
            } else {
                OpenAPI_list_free(policy_template_bindings);
            }
        }
    }


    /* client consumption reporting configuration */
    if (provisioning_session->consumptionReportingConfiguration) {
        OpenAPI_list_t *ccrc_svr_list;

        ogs_debug("Adding clientConsumptionReportingConfiguration to ServiceAccessInformation [%s]",
                  provisioning_session->provisioningSessionId);

        ccrc_svr_list = OpenAPI_list_create();
        ogs_assert(ccrc_svr_list);
        OpenAPI_list_add(ccrc_svr_list, ogs_msprintf("http%s://%s/3gpp-m5/v2/", is_tls?"s":"", svr_hostname));
        ccrc = msaf_api_service_access_information_resource_client_consumption_reporting_configuration_create(
                    provisioning_session->consumptionReportingConfiguration->reporting_interval?true:false,
                    *provisioning_session->consumptionReportingConfiguration->reporting_interval,
                    ccrc_svr_list,
                    provisioning_session->consumptionReportingConfiguration->is_location_reporting?
                        provisioning_session->consumptionReportingConfiguration->location_reporting:
                        0,
                    provisioning_session->consumptionReportingConfiguration->is_access_reporting?
                        provisioning_session->consumptionReportingConfiguration->access_reporting:
                        0,
                    provisioning_session->consumptionReportingConfiguration->is_sample_percentage?
                        provisioning_session->consumptionReportingConfiguration->sample_percentage:
                        100.0
                    );
        ogs_assert(ccrc);
    }

    /* Network Assistance Configuration */
    if (config->offerNetworkAssistance) {
        OpenAPI_list_t *na_svr_list;

        na_svr_list = OpenAPI_list_create();
        ogs_assert(na_svr_list);
        OpenAPI_list_add(na_svr_list, ogs_msprintf("http%s://%s/3gpp-m5/v2/", is_tls?"s":"", svr_hostname));
        nac = msaf_api_service_access_information_resource_network_assistance_configuration_create(na_svr_list);
        ogs_assert(nac);
    }

    /* Create SAI */
    service_access_information = msaf_api_service_access_information_resource_create(
                msaf_strdup(provisioning_session->provisioningSessionId),
                msaf_api_provisioning_session_type_DOWNLINK,
                streaming_access,
                ccrc /* client_consumption_reporting_configuration */,
                dpic /* dynamic_policy */,
                NULL /* client_metrics_reporting */,
                nac  /* network_assistance_configuration */,
                NULL /* client_edge_resources */);

    ogs_assert(service_access_information);

    return service_access_information;
}

const msaf_sai_cache_entry_t *msaf_context_retrieve_service_access_information(const char *provisioning_session_id, bool is_tls, const char *authority)
{
    msaf_provisioning_session_t *provisioning_session_context;
    const msaf_sai_cache_entry_t *sai_entry = NULL;

    provisioning_session_context = msaf_provisioning_session_find_by_provisioningSessionId(provisioning_session_id);
    if (provisioning_session_context == NULL){
        ogs_error("Couldn't find the Provisioning Session ID [%s]", provisioning_session_id);    
        return NULL;
    }

    if (!provisioning_session_context->sai_cache) {
        provisioning_session_context->sai_cache = msaf_sai_cache_new();
    } else {
        sai_entry = msaf_sai_cache_find(provisioning_session_context->sai_cache, is_tls, authority);
    }

    if (!sai_entry) {
        msaf_api_service_access_information_resource_t *sai;

        ogs_debug("Create new SAI for http%s://%s on provisioning session [%s]", is_tls?"s":"", authority, provisioning_session_id);

        sai = msaf_context_service_access_information_create(provisioning_session_context, is_tls, authority);
        msaf_sai_cache_add(provisioning_session_context->sai_cache, is_tls, authority, sai);
        msaf_api_service_access_information_resource_free(sai);
        sai_entry = msaf_sai_cache_find(provisioning_session_context->sai_cache, is_tls, authority);
    } else {
        ogs_debug("Found existing SAI cache entry");
    }

    if (sai_entry == NULL){
       ogs_error("The provisioning Session [%s] does not have an associated Service Access Information", provisioning_session_id);
    }

    return sai_entry;
}

static OpenAPI_list_t *_policy_templates_hash_to_list_of_ready_bindings(ogs_hash_t *policy_templates)
{
    msaf_policy_template_node_t *policy_template_node;
    OpenAPI_list_t *policy_template_bindings;
    ogs_hash_index_t *hi;
    msaf_api_service_access_information_resource_dynamic_policy_invocation_configuration_policy_template_bindings_inner_t *policy_template_binding;

    policy_template_bindings = OpenAPI_list_create();

    for (hi = ogs_hash_first(policy_templates);
            hi; hi = ogs_hash_next(hi)) {
        policy_template_node = (msaf_policy_template_node_t *)ogs_hash_this_val(hi);
        if (policy_template_node->policy_template->state == msaf_api_policy_template_STATE_READY) {
            policy_template_binding = msaf_api_service_access_information_resource_dynamic_policy_invocation_configuration_policy_template_bindings_inner_create(msaf_strdup(policy_template_node->policy_template->external_reference), msaf_strdup(policy_template_node->policy_template->policy_template_id));
            OpenAPI_list_add(policy_template_bindings, policy_template_binding);
        }
    }
    return policy_template_bindings;
}


/* vim:ts=8:sts=4:sw=4:expandtab:
 */
