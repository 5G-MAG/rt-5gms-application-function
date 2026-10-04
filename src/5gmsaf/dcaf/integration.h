/* License: 5G-MAG Public License (v1.0). See LICENSE. */
#ifndef MSAF_DCAF_INTEGRATION_H
#define MSAF_DCAF_INTEGRATION_H

#include "ogs-proto.h"

int msaf_dcaf_initialize(void);
void msaf_dcaf_finalise(void);
bool msaf_dcaf_process_event(ogs_event_t *event);

#endif
