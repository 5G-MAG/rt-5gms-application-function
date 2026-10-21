#ifndef MSAF_DATABUCKET_H
#define MSAF_DATABUCKET_H

#include <time.h>

#include "ogs-core.h"
#include "openapi/model/msaf_api_consumption_report.h"

typedef struct msaf_event_s msaf_event_t;

typedef struct msaf_databucket_consumption_report_s {
    ogs_lnode_t node;
    char *provisioning_session_id;
    struct timespec received_at;
    msaf_api_consumption_report_t *report;
} msaf_databucket_consumption_report_t;

bool msaf_databucket_add_consumption_report(const char *provisioning_session_id,
                                          const msaf_api_consumption_report_t *report,
                                          const struct timespec *received_at);
const ogs_list_t *msaf_databucket_consumption_reports(void);
cJSON *msaf_databucket_json(void);
bool msaf_databucket_handle_request(msaf_event_t *event);
void msaf_databucket_clear(void);

#endif