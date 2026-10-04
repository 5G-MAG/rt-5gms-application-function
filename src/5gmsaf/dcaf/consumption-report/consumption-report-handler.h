/* License: 5G-MAG Public License (v1.0). See LICENSE. */
#ifndef MSAF_CONSUMPTION_REPORT_HANDLER_H
#define MSAF_CONSUMPTION_REPORT_HANDLER_H

#include "data-collection-sp/data-collection.h"
#include "provisioning-session.h"

extern const data_collection_data_report_handler_t msaf_consumption_report_handler;

bool msaf_consumption_report_submit(msaf_provisioning_session_t *provisioning,
                                   cJSON *json, char **error, char **parameter);

#endif
