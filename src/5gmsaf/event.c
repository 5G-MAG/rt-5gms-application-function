/*
License: 5G-MAG Public License (v1.0)
Author: Dev Audsin
Copyright: (C) 2022-2023 British Broadcasting Corporation

For full license terms please see the LICENSE file distributed with this
program. If this file is missing then the license can be retrieved from
https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
 */

#include "context.h"

#include "utilities.h"
#include "event.h"

const char *msaf_event_get_name(msaf_event_t *e)
{
    if (e == NULL) {
        return OGS_FSM_NAME_INIT_SIG;
    }

    switch (e->h.id) {
    case MSAF_EVENT_SBI_LOCAL:
        return "MSAF_EVENT_SBI_LOCAL";

    default:
       break;
    }

    return ogs_event_get_name(&e->h);
}

int check_event_addresses(msaf_event_t *e, ogs_sockaddr_t *sockaddr_v4, ogs_sockaddr_t *sockaddr_v6)
{
    ogs_sbi_stream_t *stream = e->h.sbi.data;

    if (stream) {
        ogs_sbi_server_t *server;

        server = ogs_sbi_server_from_stream(stream);
        ogs_assert(server);

        if ((sockaddr_v4 && ogs_sockaddr_is_equal(server->node.addr, sockaddr_v4)) ||
            (sockaddr_v6 && ogs_sockaddr_is_equal(server->node.addr, sockaddr_v6))
           ) {
            return 1;
        }     
    }

    return 0;
}

msaf_event_t *populate_msaf_event_with_metadata(msaf_event_t *e, const nf_server_interface_metadata_t *nf_server_interface_metadata,
                                                const nf_server_app_metadata_t *app_meta)
{
    msaf_event_t *event;
    int rv;
    event = (msaf_event_t*) ogs_event_new(OGS_EVENT_SBI_SERVER);

    event->h.sbi.data = e->h.sbi.data;
    ogs_assert(event->h.sbi.data);
    event->message = ogs_calloc(1, sizeof(ogs_sbi_message_t));
    ogs_assert(event->message);

    rv = ogs_sbi_parse_header(event->message, &e->h.sbi.request->h);
    if (rv != OGS_OK) {
        ogs_error("ogs_sbi_parse_header() failed");
    }
    
    event->nf_server_interface_metadata = nf_server_interface_metadata;
    event->app_meta = msaf_app_metadata();

    return event;
}


void msaf_event_free(msaf_event_t *e)
{
    if (e->message) {
        ogs_sbi_message_free(e->message);
        ogs_free(e->message);
    }

    ogs_event_free(e);
}

/* vim:ts=8:sts=4:sw=4:expandtab:
*/
