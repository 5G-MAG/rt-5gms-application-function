/*
License: 5G-MAG Public License (v1.0)
Copyright: (C) 2023 British Broadcasting Corporation

For full license terms please see the LICENSE file distributed with this
program. If this file is missing then the license can be retrieved from
https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
*/

#ifndef BSF_CLIENT_LOCAL_H
#define BSF_CLIENT_LOCAL_H

#include "ogs-proto.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct bsf_client_sess_s bsf_client_sess_t;

enum {
	BSF_CLIENT_LOCAL_EVENT = OGS_MAX_NUM_OF_PROTO_EVENT
};

typedef enum {
	BSF_CLIENT_LOCAL_NULL = 0,
	BSF_CLIENT_LOCAL_DISCOVER_AND_SEND,
	BSF_CLIENT_LOCAL_MAX
} bsf_client_local_event_type_e;

typedef struct bsf_client_event_s {
    ogs_event_t h;
    bsf_client_local_event_type_e id;
} bsf_client_event_t;

bool _bsf_client_local_discover_and_send(bsf_client_sess_t *sess);

bool _bsf_client_local_process_event(ogs_event_t *e);

#ifdef __cplusplus
}
#endif

/* vim:ts=8:sts=4:sw=4:expandtab:
 */

#endif /* ifndef BSF_CLIENT_LOCAL_H */
