/*
 * License: 5G-MAG Public License (v1.0)
 * Copyright: (C) 2023 British Broadcasting Corporation
 *
 * For full license terms please see the LICENSE file distributed with this
 * program. If this file is missing then the license can be retrieved from
 * https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
*/

#ifndef __TESTS_BSF_TEST_EVENT_H
#define __TESTS_BSF_TEST_EVENT_H

#include "ogs-proto.h"
#include "ogs-sbi.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct bsf_test_sess_s bsf_test_sess_t;

typedef enum {
    BSF_TEST_EVENT_BASE = OGS_MAX_NUM_OF_PROTO_EVENT,

    BSF_TEST_EVENT_SBI_LOCAL,

    MAX_NUM_OF_BSF_TEST_EVENT,

} bsf_test_event_e;

typedef struct bsf_test_event_s {
    ogs_event_t h;
    int local_id;

    ogs_pkbuf_t *pkbuf;

    struct {
        ogs_sbi_service_type_e service_type;
        void *data;
        ogs_sbi_request_t *(*build)(bsf_test_sess_t *sess, void *data);
    } local;

    bsf_test_sess_t *sess;
} bsf_test_event_t;

OGS_STATIC_ASSERT(OGS_EVENT_SIZE >= sizeof(bsf_test_event_t));

extern bsf_test_event_t *bsf_test_event_new(int id);
extern const char *bsf_test_event_get_name(bsf_test_event_t *e);

#ifdef __cplusplus
}
#endif

#endif /* ifndef __TESTS_BSF_TEST_EVENT_H */

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
