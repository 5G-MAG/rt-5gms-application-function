#include "databucket.h"
#include "context.h"
#include "ogs-core.h"
#include "server.h"
#include "msaf-sm.h"

static ogs_list_t consumption_reports;

bool msaf_databucket_add_consumption_report(const char *provisioning_session_id,
                                          const msaf_api_consumption_report_t *report,
                                          const struct timespec *received_at)
{
    msaf_databucket_consumption_report_t *entry;
    msaf_api_consumption_report_t *copy;

    if (!provisioning_session_id || !*provisioning_session_id || !report || !received_at) return false;

    copy = msaf_api_consumption_report_copyRequest(NULL, report);
    if (!copy) return false;

    entry = ogs_calloc(1, sizeof(*entry));
    entry->provisioning_session_id = ogs_strdup(provisioning_session_id);
    entry->received_at = *received_at;
    entry->report = copy;
    ogs_list_add(&consumption_reports, entry);
    return true;
}





const ogs_list_t *msaf_databucket_consumption_reports(void)
{
    return &consumption_reports;
}

void msaf_databucket_clear(void){
    msaf_databucket_consumption_report_t  *entry;
    msaf_databucket_consumption_report_t *next;
    ogs_list_for_each_safe(&consumption_reports, next, entry){
        ogs_list_remove(&consumption_reports, entry);
        msaf_api_consumption_report_free(entry->report);
        ogs_free(entry->provisioning_session_id);
        ogs_free(entry);
    }
}
