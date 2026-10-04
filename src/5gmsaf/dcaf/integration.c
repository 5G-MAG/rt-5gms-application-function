/* License: 5G-MAG Public License (v1.0). See LICENSE. */
#include "integration.h"
#include "consumption-report/consumption-report-handler.h"
#include "msaf-version.h"

static const data_collection_data_report_handler_t * const data_report_handlers[] = {
    &msaf_consumption_report_handler, NULL
};

static const data_collection_configuration_t data_collection_configuration = {
    .configuration_section = "dataCollection",

    .disable_features =
        DATA_COLLECTION_FEATURE_SERVER_DATA_REPORTING_PROVISIONING_R1 |
        DATA_COLLECTION_FEATURE_SERVER_DATA_REPORTING_R2 |
        DATA_COLLECTION_FEATURE_SERVER_DATA_REPORTING_R3,

    .event_exposure_supported_features =
        DATA_COLLECTION_SUPPORTED_FEATURE_EVENT_UE_COMMUNICATION,

    .af_name = MSAF_NAME,
    .af_version = MSAF_VERSION,
    .af_type = "AF",

    .data_report_handlers = data_report_handlers,
    .event_generation_callback = NULL
};

int msaf_dcaf_initialize(void)
{
    return data_collection_initialise(&data_collection_configuration);
}

void msaf_dcaf_finalise(void)
{
    data_collection_finalise();
}

bool msaf_dcaf_process_event(ogs_event_t *event)
{
    return data_collection_process_event(event);
}
