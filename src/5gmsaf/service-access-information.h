/*
License: 5G-MAG Public License (v1.0)
Author: Dev Audsin
Copyright: (C) 2022 British Broadcasting Corporation

For full license terms please see the LICENSE file distributed with this
program. If this file is missing then the license can be retrieved from
https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
*/

#ifndef MSAF_SERVICE_ACCESS_INFORMATION_H
#define MSAF_SERVICE_ACCESS_INFORMATION_H

#include <unistd.h>

#include "ogs-sbi.h"
#include "ogs-app.h"

#include "event.h"
#include "msaf-sm.h"

#include <stdio.h>
#include <stdlib.h>
#include "openapi/model/service_access_information_resource.h"
#include "provisioning-session.h"
#include "application-server-context.h"
#include "sai-cache.h"

#ifdef __cplusplus
extern "C" {
#endif

OpenAPI_service_access_information_resource_t *msaf_context_service_access_information_create(msaf_provisioning_session_t *provisioning_session, bool is_tls, const char *svr_hostname);
const msaf_sai_cache_entry_t *msaf_context_retrieve_service_access_information(const char *provisioning_session_id, bool is_tls, const char *authority);

#ifdef __cplusplus
}
#endif

#endif /* MSAF_SERVICE_ACCESS_INFORMATION_H */
