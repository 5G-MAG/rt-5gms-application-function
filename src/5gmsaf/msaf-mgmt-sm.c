/*
 * License: 5G-MAG Public License (v1.0)
 * Author: Dev Audsin
 * Copyright: (C) 2023 British Broadcasting Corporation
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
#include "openapi/api/Maf_ManagementAPI-info.h"
  
#include "msaf-mgmt-sm.h"

static const nf_server_interface_metadata_t
maf_mgmt_api_metadata = {
    MAF_MANAGEMENT_API_NAME,
    MAF_MANAGEMENT_API_VERSION
};

void msaf_maf_mgmt_state_initial(ogs_fsm_t *s, msaf_event_t *e)
{
    msaf_sm_debug(e);

    ogs_assert(s);

    OGS_FSM_TRAN(s, &msaf_maf_mgmt_state_functional);
}

void msaf_maf_mgmt_state_final(ogs_fsm_t *s, msaf_event_t *e)
{
    msaf_sm_debug(e);

    ogs_assert(s);
}

void msaf_maf_mgmt_state_functional(ogs_fsm_t *s, msaf_event_t *e)
{
    ogs_sbi_stream_t *stream = NULL;
    ogs_sbi_request_t *request = NULL;
    ogs_sbi_message_t *message = NULL;

    static const nf_server_interface_metadata_t *maf_management_api = &maf_mgmt_api_metadata;
    const nf_server_app_metadata_t *app_meta = msaf_app_metadata();

    msaf_sm_debug(e);

    ogs_assert(s);

    switch (e->h.id) {
        case OGS_FSM_ENTRY_SIG:
            ogs_info("[%s] MSAF Management Interface Running", ogs_sbi_self()->nf_instance->id);
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
            CASE("5gmag-rt-management")
                ogs_fsm_dispatch(&msaf_self()->msaf_fsm.msaf_m1_sm, e);
                message = NULL;
                break;
         
            DEFAULT
                ogs_error("Resource [%s] not found.", message->h.service.name);
                ogs_assert(true == nf_server_send_error(stream, OGS_SBI_HTTP_STATUS_NOT_FOUND, 0, message, "Not Found.", message->h.service.name, NULL, maf_management_api, app_meta));

            END
            break;
        default:
            ogs_error("No handler for event %s", msaf_event_get_name(e));
            break;
    }
    if (message) {
        ogs_sbi_message_free(message);
        ogs_free(message);
    }
}

/* vim:ts=8:sts=4:sw=4:expandtab:
*/
