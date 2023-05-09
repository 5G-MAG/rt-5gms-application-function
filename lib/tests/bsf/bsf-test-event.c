/*
 * License: 5G-MAG Public License (v1.0)
 * Copyright: (C) 2023 British Broadcasting Corporation
 *
 * For full license terms please see the LICENSE file distributed with this
 * program. If this file is missing then the license can be retrieved from
 * https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
*/

#include "ogs-proto.h"

#include "bsf-test-event.h"

#ifdef __cplusplus
extern "C" {
#endif

bsf_test_event_t *bsf_test_event_new(int id)
{
    bsf_test_event_t *e = NULL;

    e = ogs_event_size(id, sizeof(bsf_test_event_t));
    ogs_assert(e);

    e->h.id = id;

    return e;
}

const char *bsf_test_event_get_name(bsf_test_event_t*e)
{
    if (e == NULL) {
        return OGS_FSM_NAME_INIT_SIG;
    }

    switch (e->h.id) {
    case BSF_TEST_EVENT_SBI_LOCAL:
        return "BSF_TEST_EVENT_SBI_LOCAL";

    default:
        break;
    }

    return ogs_event_get_name(&e->h);
}

#ifdef __cplusplus
}
#endif

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
