/*
License: 5G-MAG Public License (v1.0)
Author: David Waring
Copyright: (C) 2023 British Broadcasting Corporation

For full license terms please see the LICENSE file distributed with this
program. If this file is missing then the license can be retrieved from
https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
 */

#ifndef MSAF_MGMT_SM_H
#define MSAF_MGMT_SM_H

#include "ogs-core.h"

#include "event.h"

#ifdef __cplusplus
extern "C" {
#endif

void msaf_maf_mgmt_state_initial(ogs_fsm_t *s, msaf_event_t *e);
void msaf_maf_mgmt_state_final(ogs_fsm_t *s, msaf_event_t *e);
void msaf_maf_mgmt_state_functional(ogs_fsm_t *s, msaf_event_t *e);
void msaf_maf_mgmt_state_exception(ogs_fsm_t *s, msaf_event_t *e);

#ifdef __cplusplus
}
#endif

/* vim:ts=8:sts=4:sw=4:expandtab:
 */

#endif /* ifndef MSAF_MGMT_SM_H */
