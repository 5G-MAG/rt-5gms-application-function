/*
 * License: 5G-MAG Public License (v1.0)
 * Copyright: (C) 2022 British Broadcasting Corporation
 *
 * For full license terms please see the LICENSE file distributed with this
 * program. If this file is missing then the license can be retrieved from
 * https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
 */

#include "ogs-core.h"

#ifdef __cplusplus
extern "C" {
#endif

int __bsf_log_domain = 0;

/* Library Internals */
void _log_init(void){
    ogs_log_install_domain(&__bsf_log_domain, "bsf-client", ogs_core()->log.level);
}

#ifdef __cplusplus
}
#endif

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
