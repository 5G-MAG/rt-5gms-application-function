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

int get_server_type_from_event(msaf_event_t *e)
{
    ogs_sbi_stream_t *stream = e->h.sbi.data;

    if (stream) {
        ogs_sbi_server_t *server;

        server = ogs_sbi_server_from_stream(stream);
        ogs_assert(server);

        if (ogs_sockaddr_is_equal(server->node.addr, msaf_self()->config.app_server_sockaddr) == true) {
            ogs_info("returns MSAF_APP_SERVER");
            return MSAF_APP_SERVER;
        }

        if (ogs_sockaddr_is_equal(server->node.addr, msaf_self()->config.mgmt_server_sockaddr) == true) {
            ogs_info("returns MSAF_MGMT_SERVER");
            return MSAF_MGMT_SERVER;
        }

        if (ogs_sockaddr_is_equal(server->node.addr, msaf_self()->config.app_server_sockaddr_v6) == true) {
            ogs_info("returns MSAF_APP_SERVER");
            return MSAF_APP_SERVER;
        }

        if (ogs_sockaddr_is_equal(server->node.addr, msaf_self()->config.mgmt_server_sockaddr_v6) == true) {
            ogs_info("returns MSAF_MGMT_SERVER");
            return MSAF_MGMT_SERVER;

        }
    }
    return MSAF_APP_SERVER;

}

/* vim:ts=8:sts=4:sw=4:expandtab:
*/
