/*
License: 5G-MAG Public License (v1.0)
Copyright: (C) 2023 British Broadcasting Corporation

For full license terms please see the LICENSE file distributed with this
program. If this file is missing then the license can be retrieved from
https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
*/

#include "ogs-app.h"
#include "ogs-proto.h"

#include "bsf-client-sess.h"
#include "context.h"
#include "log.h"

#include "local.h"

#ifdef __cplusplus
extern "C" {
#endif

bool _bsf_client_local_discover_and_send(bsf_client_sess_t *sess)
{
    int rv;
    bsf_client_event_t *ev;

    ev = ogs_event_size(BSF_CLIENT_LOCAL_EVENT, sizeof(*ev));
    ogs_assert(ev);

    ev->id = BSF_CLIENT_LOCAL_DISCOVER_AND_SEND;
    ev->h.sbi.data = sess;

    ogs_debug("Queueing discover & send event (%p)", ev);
    rv = ogs_queue_push(ogs_app()->queue, &ev->h);
    if (rv != OGS_OK) {
        ogs_error("Failed to push discover and send event onto the queue");
        return false;
    }

    /* process the event queue */
    ogs_pollset_notify(ogs_app()->pollset);

    ogs_debug("event queued");

    return true;
}

bool _bsf_client_local_process_event(ogs_event_t *e)
{
    bsf_client_sess_t *sess;

    if (!e) return false;
    if (e->id != BSF_CLIENT_LOCAL_EVENT) return false;

    sess = (bsf_client_sess_t*)e->sbi.data;
    if (_bsf_client_context_active_sessions_exists(sess)) {
        bsf_client_event_t *bsf_event = ogs_container_of(e, bsf_client_event_t, h);
        switch (bsf_event->id) {
            case BSF_CLIENT_LOCAL_DISCOVER_AND_SEND:
                ogs_debug("Discover & Send event");
                _bsf_client_sess_discover_and_send(sess);
                break;
            default:
        }
        return true;
    }
    return false;
}

#ifdef __cplusplus
}
#endif

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
