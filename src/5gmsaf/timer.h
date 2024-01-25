/*
License: 5G-MAG Public License (v1.0)
Author: Dev Audsin
Copyright: (C) 2023 British Broadcasting Corporation

For full license terms please see the LICENSE file distributed with this
program. If this file is missing then the license can be retrieved from
https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
*/

#ifndef MSAF_TIMER_H
#define MSAF_TIMER_H

#include "ogs-proto.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    MSAF_TIMER_BASE = OGS_MAX_NUM_OF_PROTO_TIMER,

    MSAF_TIMER_DELIVERY_BOOST,

    MAX_NUM_OF_MSAF_TIMER,

} msaf_timer_e;

const char *msaf_timer_get_name(int timer_id);
void msaf_timer_delivery_boost(void *data);

#ifdef __cplusplus
}
#endif

#endif /* MSAF_TIMER_H */
