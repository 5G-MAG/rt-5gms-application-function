/*
License: 5G-MAG Public License (v1.0)
Author: Dev Audsin
Copyright: (C) 2022 British Broadcasting Corporation

For full license terms please see the LICENSE file distributed with this
program. If this file is missing then the license can be retrieved from
https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
 */

#ifndef MSAF_SBI_PATH_H
#define MSAF_SBI_PATH_H

 #include "context.h"


#ifdef __cplusplus
extern "C" {
#endif

int msaf_sbi_open(void);
void msaf_sbi_close(void);

bool msaf_sbi_send_request(ogs_sbi_nf_instance_t *nf_instance, void *data);

#ifdef __cplusplus
}
#endif

#endif
