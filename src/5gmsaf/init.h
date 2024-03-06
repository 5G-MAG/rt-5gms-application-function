/*
 * License: 5G-MAG Public License (v1.0)
 * Author: Dev Audsin <dev.audsin@bbc.co.uk>
 * Copyright: (C) 2022 British Broadcasting Corporation
 *
 * For full license terms please see the LICENSE file distributed with this
 * program. If this file is missing then the license can be retrieved from
 * https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
 */

#ifndef MSAF_INIT_H
#define MSAF_INIT_H

#include "ogs-app.h"

#ifdef __cplusplus
extern "C" {
#endif

extern int msaf_initialize(void);
extern void msaf_terminate(void);

#ifdef __cplusplus
}
#endif

#endif
