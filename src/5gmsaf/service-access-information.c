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
#include "context.h"
#include "utilities.h"
#include "provisioning-session.h"

OpenAPI_service_access_information_resource_t *
msaf_context_service_access_information_create(const char *provisioning_session_id, OpenAPI_list_t *entry_points)
{
    OpenAPI_service_access_information_resource_streaming_access_t *streaming_access
        = OpenAPI_service_access_information_resource_streaming_access_create(entry_points, NULL);
    OpenAPI_service_access_information_resource_t *service_access_information
        = OpenAPI_service_access_information_resource_create(
                ogs_strdup(provisioning_session_id),
                OpenAPI_provisioning_session_type_DOWNLINK, streaming_access, NULL, NULL,
                NULL, NULL,NULL);
    return service_access_information;
}

cJSON *msaf_context_retrieve_service_access_information(char *provisioning_session_id)
{
    msaf_provisioning_session_t *provisioning_session_context = NULL;
    provisioning_session_context = msaf_provisioning_session_find_by_provisioningSessionId(provisioning_session_id);
    if (provisioning_session_context == NULL){
	    ogs_error("Couldn't find the Provisioning Session ID [%s]", provisioning_session_id);    
        return NULL;
    }
    if (provisioning_session_context->serviceAccessInformation == NULL){
       ogs_error("The provisioning Session [%s] does not have an associated Service Access Information", provisioning_session_id);
       return NULL;
    }
    cJSON *service_access_information = OpenAPI_service_access_information_resource_convertToJSON(provisioning_session_context->serviceAccessInformation);
    return service_access_information;
}


