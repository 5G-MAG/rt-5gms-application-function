/*
License: 5G-MAG Public License (v1.0)
Author: Dev Audsin
Copyright: (C) 2022 British Broadcasting Corporation

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
#include "utilities.h"
#include "provisioning-session.h"

#include "openapi/model/service_access_information_resource.h"

#include "service-access-information.h"

OpenAPI_service_access_information_resource_t *
msaf_context_service_access_information_create(msaf_provisioning_session_t *provisioning_session, bool is_tls, const char *svr_hostname)
{
    OpenAPI_service_access_information_resource_t *service_access_information;
    OpenAPI_service_access_information_resource_streaming_access_t *streaming_access;
    //msaf_configuration_t *config = &msaf_self()->config;
    OpenAPI_service_access_information_resource_client_consumption_reporting_configuration_t *ccrc = NULL;
    OpenAPI_list_t *entry_points = NULL;

    /* streaming entry points */
    ogs_debug("Adding streams to ServiceAccessInformation [%s]", provisioning_session->provisioningSessionId);
    if (provisioning_session->contentHostingConfiguration) {
        OpenAPI_lnode_t *node;
        OpenAPI_list_for_each(provisioning_session->contentHostingConfiguration->distribution_configurations, node) {
            OpenAPI_distribution_configuration_t *dist_conf = node->data;
	    if (dist_conf->entry_point && dist_conf->base_url) {
		OpenAPI_m5_media_entry_point_t *m5_entry;
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
		m5_entry = OpenAPI_m5_media_entry_point_create(url, ogs_strdup(dist_conf->entry_point->content_type), m5_profiles);
		ogs_assert(m5_entry);
		if (!entry_points) entry_points = OpenAPI_list_create();
		OpenAPI_list_add(entry_points, m5_entry);
	    }
	}
    }
    streaming_access = OpenAPI_service_access_information_resource_streaming_access_create(entry_points, NULL);

    /* client consumption reporting configuration */
    if (provisioning_session->consumptionReportingConfiguration) {
        OpenAPI_list_t *ccrc_svr_list;

        ogs_debug("Adding clientConsumptionReportingConfiguration to ServiceAccessInformation [%s]",
                  provisioning_session->provisioningSessionId);

        ccrc_svr_list = OpenAPI_list_create();
	ogs_assert(ccrc_svr_list);
        OpenAPI_list_add(ccrc_svr_list, ogs_msprintf("http%s://%s/3gpp-m5/v2/", is_tls?"s":"", svr_hostname));
        ccrc = OpenAPI_service_access_information_resource_client_consumption_reporting_configuration_create(
                    provisioning_session->consumptionReportingConfiguration->is_reporting_interval,
                    provisioning_session->consumptionReportingConfiguration->reporting_interval,
                    ccrc_svr_list,
                    provisioning_session->consumptionReportingConfiguration->is_location_reporting?
                        provisioning_session->consumptionReportingConfiguration->location_reporting:
                        0,
                    true, /* TS 26.512 Table 11.2.3.1-1 says the accessReporting field is mandatory */
                    provisioning_session->consumptionReportingConfiguration->is_access_reporting?
                        provisioning_session->consumptionReportingConfiguration->access_reporting:
                        0,
                    provisioning_session->consumptionReportingConfiguration->is_sample_percentage?
                        provisioning_session->consumptionReportingConfiguration->sample_percentage:
                        100.0
                    );
        ogs_assert(ccrc);
    }

    /* Create SAI */
    service_access_information = OpenAPI_service_access_information_resource_create(
                msaf_strdup(provisioning_session->provisioningSessionId),
                OpenAPI_provisioning_session_type_DOWNLINK,
                streaming_access,
                ccrc /* client_consumption_reporting_configuration */,
                NULL /* dynamic_policy */,
                NULL /* client_metrics_reporting */,
                NULL /* network_assistance_configuration */,
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
	OpenAPI_service_access_information_resource_t *sai;

        ogs_debug("Create new SAI for http%s://%s on provisioning session [%s]", is_tls?"s":"", authority, provisioning_session_id);

	sai = msaf_context_service_access_information_create(provisioning_session_context, is_tls, authority);
	msaf_sai_cache_add(provisioning_session_context->sai_cache, is_tls, authority, sai);
	OpenAPI_service_access_information_resource_free(sai);
	sai_entry = msaf_sai_cache_find(provisioning_session_context->sai_cache, is_tls, authority);
    } else {
        ogs_debug("Found existing SAI cache entry");
    }

    if (sai_entry == NULL){
       ogs_error("The provisioning Session [%s] does not have an associated Service Access Information", provisioning_session_id);
    }

    return sai_entry;
}

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
