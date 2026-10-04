/* License: 5G-MAG Public License (v1.0). See LICENSE. */
#include <time.h>

#include "consumption-report-handler.h"
#include "openapi/model/msaf_api_consumption_report.h"

/* Local types */

typedef struct consumption_sample_s {
    msaf_api_consumption_report_t *report;
    struct timespec start;
    struct timespec end;
    struct timespec received;
} consumption_sample_t;

/* Local declarations */

static void *sample_parse(const data_collection_reporting_session_t *session,
                          cJSON *json, char **error, char **error_class, char **parameter);
static void *sample_clone(const void *data);
static void sample_free(void *data);
static cJSON *sample_json(const void *data);
static struct timespec *sample_timestamp(const void *data);
static char *sample_tag(const void *data);
static char *sample_serialise(const void *data);
static ogs_list_t *sample_context_ids(const void *data);
static struct timespec *sample_start(const void *data);
static struct timespec *sample_end(const void *data);
static bool parse_time(const char *text, struct timespec *result);

/* Handler registration */

static const char * const consumption_aggregations[] = { NULL };

const data_collection_data_report_handler_t msaf_consumption_report_handler = {
    .type_name = "ConsumptionReport",
    .data_report_property = DATA_COLLECTION_DATA_REPORT_PROPERTY_APP_SPECIFIC,
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
    .context_ids = sample_context_ids,
    .sample_start = sample_start,
    .sample_end = sample_end
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
    (void)data;
    return NULL;
}

static void sample_free(void *data)
{
    (void)data;
}

static cJSON *sample_json(const void *data)
{
    (void)data;
    return NULL;
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
    (void)data;
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
