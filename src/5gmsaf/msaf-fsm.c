/*
License: 5G-MAG Public License (v1.0)
Author: Dev Audsin
Copyright: (C) 2023 British Broadcasting Corporation

For full license terms please see the LICENSE file distributed with this
program. If this file is missing then the license can be retrieved from
https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
*/

#include "msaf-sm.h"
#include "msaf-m1-sm.h"
#include "msaf-m5-sm.h"
#include "msaf-mgmt-sm.h"

#include "msaf-fsm.h"

void msaf_fsm_init(void) {
    ogs_fsm_init(&msaf_self()->msaf_fsm.msaf_m1_sm, msaf_m1_state_initial, msaf_m1_state_final, 0);
    ogs_fsm_init(&msaf_self()->msaf_fsm.msaf_m5_sm, msaf_m5_state_initial, msaf_m5_state_final, 0);    
    if(msaf_self()->config.servers[MSAF_SVR_MSAF].ipv4 || msaf_self()->config.servers[MSAF_SVR_MSAF].ipv6) {
        ogs_fsm_init(&msaf_self()->msaf_fsm.msaf_maf_mgmt_sm, msaf_maf_mgmt_state_initial, msaf_maf_mgmt_state_final, 0);
    }
}

void msaf_fsm_fini(void) {
    ogs_fsm_fini(&msaf_self()->msaf_fsm.msaf_m1_sm, 0);
    ogs_fsm_fini(&msaf_self()->msaf_fsm.msaf_m5_sm, 0);
    if(msaf_self()->config.servers[MSAF_SVR_MSAF].ipv4 || msaf_self()->config.servers[MSAF_SVR_MSAF].ipv6) {
        ogs_fsm_fini(&msaf_self()->msaf_fsm.msaf_maf_mgmt_sm, 0);
    }
}
