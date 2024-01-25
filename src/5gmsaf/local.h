/*
License: 5G-MAG Public License (v1.0)
Author: Dev Audsin
Copyright: (C) 2022 British Broadcasting Corporation

For full license terms please see the LICENSE file distributed with this
program. If this file is missing then the license can be retrieved from
https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
 */

#ifndef MSAF_LOCAL_SM_H
#define MSAF_LOCAL_SM_H

#include "event.h"

#ifdef __cplusplus
extern "C" {
#endif

bool local_process_event(msaf_event_t *e);

#ifdef __cplusplus
}
#endif

#endif
