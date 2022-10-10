/*
License: 5G-MAG Public License (v1.0)
Author: Dev Audsin
Copyright: (C) 2022 British Broadcasting Corporation

For full license terms please see the LICENSE file distributed with this
program. If this file is missing then the license can be retrieved from
https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
 */

#include "sbi-path.h"
#include "nnrf-handler.h"

void msaf_nnrf_handle_nf_discover(
        ogs_sbi_xact_t *xact, ogs_sbi_message_t *recvmsg)
{
    ogs_sbi_nf_instance_t *nf_instance = NULL;
    ogs_sbi_object_t *sbi_object = NULL;
    ogs_sbi_service_type_e service_type = OGS_SBI_SERVICE_TYPE_NULL;
    ogs_sbi_discovery_option_t *discovery_option = NULL;

    OpenAPI_nf_type_e target_nf_type = OpenAPI_nf_type_NULL;
    OpenAPI_search_result_t *SearchResult = NULL;

    ogs_assert(recvmsg);
    ogs_assert(xact);
    sbi_object = xact->sbi_object;
    ogs_assert(sbi_object);
    service_type = xact->service_type;
    ogs_assert(service_type);
    target_nf_type = ogs_sbi_service_type_to_nf_type(service_type);
    ogs_assert(target_nf_type);

    discovery_option = xact->discovery_option;

    SearchResult = recvmsg->SearchResult;
    if (!SearchResult) {
        ogs_error("No Service found");
        return;
    }

    ogs_nnrf_handle_nf_discover_search_result(SearchResult);

    nf_instance = ogs_sbi_nf_instance_find_by_discovery_param(
                    target_nf_type, discovery_option);
    if (!nf_instance) {
        ogs_error("Discovering NF: No [%s] found",
                    ogs_sbi_service_type_to_name(service_type));
        return;
    }

    OGS_SBI_SETUP_NF_INSTANCE(
            sbi_object->service_type_array[service_type], nf_instance);

    ogs_expect(true == msaf_sbi_send_request(nf_instance, xact));
}
