/*
License: 5G-MAG Public License (v1.0)
Copyright: (C) 2022 British Broadcasting Corporation

For full license terms please see the LICENSE file distributed with this
program. If this file is missing then the license can be retrieved from
https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
 */

#include "context.h"

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

        if(sockaddr_v4 && (ogs_sockaddr_is_equal(server->node.addr, sockaddr_v4) || (sockaddr_v6 && ogs_sockaddr_is_equal(server->node.addr, sockaddr_v6)) )){
      
            return 1;
        }     
       
    }
    return 0;

}

/* vim:ts=8:sts=4:sw=4:expandtab:
*/
