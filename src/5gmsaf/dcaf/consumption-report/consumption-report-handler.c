/* License: 5G-MAG Public License (v1.0). See LICENSE. */
#include <time.h>

#include "consumption-report-handler.h"
#include "openapi/model/msaf_api_consumption_report.h"

/* Local declarations */

static void *sample_parse(const data_collection_reporting_session_t *session,
                          cJSON *json, char **error, char **error_class, char **parameter);
static void *sample_clone(const void *data);
static void sample_free(void *data);
static cJSON *sample_json(const void *data);
static struct timespec *sample_timestamp(const void *data);
static char *sample_tag(const void *data);
static char *sample_serialise(const void *data);
static const char *sample_aggregation_name(const void *data);
static ogs_list_t *sample_apply_aggregation(const char *function_name, const ogs_list_t *records);
static void *sample_proportion_record(const void *record, const struct timespec *start, const struct timespec *end);
static ogs_list_t *sample_context_ids(const void *data);
static struct timespec *sample_start(const void *data);
static struct timespec *sample_end(const void *data);
static bool parse_time(const char *text, struct timespec *result);

/* Handler registration */

static const char * const consumption_aggregations[] = { "NONE", "COUNT", NULL};

const data_collection_data_report_handler_t msaf_consumption_report_handler = {
    .type_name = "Media Services Consumption Report",
    .data_report_property = 0,
    .data_domain = "APPLICATION_SPECIFIC",
    .event_type = "MS_CONSUMPTION",
    .applicable_aggregations = consumption_aggregations,
    .parse_report_data = sample_parse,
    .clone_report_data = sample_clone,
    .free_report_data = sample_free,
    .json_for_report_data = sample_json,
    .timestamp_for_report_data = sample_timestamp,
    .tag_for_report_data = sample_tag,
    .serialise_report_data = sample_serialise,
    .aggregation_name = sample_aggregation_name,
    .apply_aggregation = sample_apply_aggregation,
    .proportion_record = sample_proportion_record,
    .context_ids = sample_context_ids,
    .sample_start = sample_start,
    .sample_end = sample_end,
};

/* Public API */

bool msaf_consumption_report_submit(msaf_provisioning_session_t *provisioning,
                                   cJSON *json, char **error, char **parameter)
{
    (void)provisioning;
    (void)json;
    (void)error;
    (void)parameter;
    return false;
}

/* Callbacks in handler order */

static void *sample_parse(const data_collection_reporting_session_t *session,
                          cJSON *json, char **error, char **error_class, char **parameter)
{
    (void)session;
    (void)json;
    (void)error;
    (void)error_class;
    (void)parameter;
    return NULL;
}

static void *sample_clone(const void *data)
{
    const msaf_api_consumption_report_t *report = data;
    if (!report) return NULL;
    return msaf_api_consumption_report_copyRequest(NULL, report);
}

static void sample_free(void *data)
{
    msaf_api_consumption_report_t *report = data;
    if (!report) return;
    msaf_api_consumption_report_free(report);
}

static cJSON *sample_json(const void *data)
{
    const msaf_api_consumption_report_t *report = data;
    if (!report) return NULL;
    return msaf_api_consumption_report_convertRequestToJSON(report);
}

static struct timespec *sample_timestamp(const void *data)
{
    (void)data;
    return NULL;
}

static char *sample_tag(const void *data)
{
    (void)data;
    return NULL;
}

static char *sample_serialise(const void *data)
{
    cJSON *json = sample_json(data);
    char *text;
    if (!json) return NULL;
    text = cJSON_PrintUnformatted(json);
    cJSON_Delete(json);
    return text;
}

static const char *sample_aggregation_name(const void *data)
{
    (void)data;
    return NULL;
}

static ogs_list_t *sample_apply_aggregation(const char *function_name, const ogs_list_t *records)
{
    (void)function_name;
    (void)records;
    return NULL;
}

static void *sample_proportion_record(const void *record, const struct timespec *start, const struct timespec *end)
{
    (void)record;
    (void)start;
    (void)end;
    return NULL;
}

static ogs_list_t *sample_context_ids(const void *data)
{
    (void)data;
    return NULL;
}

static struct timespec *sample_start(const void *data)
{
    (void)data;
    return NULL;
}

static struct timespec *sample_end(const void *data)
{
    (void)data;
    return NULL;
}

/* Time conversion */

static bool parse_time(const char *text, struct timespec *result)
{
    (void)text;
    (void)result;
    return false;
}
