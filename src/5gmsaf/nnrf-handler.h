/*
License: 5G-MAG Public License (v1.0)
Author: Dev Audsin
Copyright: (C) 2022 British Broadcasting Corporation

For full license terms please see the LICENSE file distributed with this
program. If this file is missing then the license can be retrieved from
https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
 */

#ifndef MSAF_NNRF_HANDLER_H
#define MSAF_NNRF_HANDLER_H

#include "context.h"

#ifdef __cplusplus
extern "C" {
#endif

void msaf_nnrf_handle_nf_discover(
        ogs_sbi_xact_t *xact, ogs_sbi_message_t *recvmsg);

#ifdef __cplusplus
}
#endif

#endif
