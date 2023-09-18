/*
License: 5G-MAG Public License (v1.0)
Copyright: (C) 2022 British Broadcasting Corporation

For full license terms please see the LICENSE file distributed with this
program. If this file is missing then the license can be retrieved from
https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
*/

#ifndef MSAF_FSM_H
#define MSAF_FSM_H

#include "ogs-app.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct msaf_fsm_s {
    ogs_fsm_t msaf_sbi_sm;
    ogs_fsm_t msaf_m1_sm;
    ogs_fsm_t msaf_m5_sm;
    ogs_fsm_t msaf_maf_mgmt_sm;
} msaf_fsm_t;

extern void msaf_fsm_init(void);
extern void msaf_fsm_fini(void);

#ifdef __cplusplus
}
#endif

#endif /* MSAF_FSM_H */
