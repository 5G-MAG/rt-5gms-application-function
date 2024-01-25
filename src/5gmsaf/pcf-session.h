/*
License: 5G-MAG Public License (v1.0)
Author: Dev Audsin
Copyright: (C) 2023 British Broadcasting Corporation

For full license terms please see the LICENSE file distributed with this
program. If this file is missing then the license can be retrieved from
https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
*/

#ifndef MSAF_PCF_SESSION_H
#define MSAF_PCF_SESSION_H


#include "pcf-service-consumer.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct msaf_pcf_session_s {
    ogs_lnode_t node;	
    pcf_session_t *pcf_session;
} msaf_pcf_session_t;

pcf_session_t *msaf_pcf_session_new(const ogs_sockaddr_t *pcf_address);

extern void msaf_pcf_session_remove_all(void);

#ifdef __cplusplus
}
#endif

#endif /* MSA_PCF_SESSION_H */
