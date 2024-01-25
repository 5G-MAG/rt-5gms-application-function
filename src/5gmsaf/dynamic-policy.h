/*
License: 5G-MAG Public License (v1.0)
Author: Dev Audsin
Copyright: (C) 2022-2023 British Broadcasting Corporation

For full license terms please see the LICENSE file distributed with this
program. If this file is missing then the license can be retrieved from
https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
*/

#ifndef MSAF_DYN_POLICY_H
#define MSAF_DYN_POLICY_H


#include "openapi/model/msaf_api_dynamic_policy.h"
#include "openapi/model/msaf_api_m5_qo_s_specification.h"
#include "openapi/model/msaf_api_service_data_flow_description.h"
#include "openapi/api/TS26512_M5_DynamicPoliciesAPI-info.h"
#include "server.h"
#include "bsf-service-consumer.h"
#include "pcf-service-consumer.h"
#include "policy-template.h"
#include "event.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ue_network_identifier_s ue_network_identifier_t;
typedef struct msaf_event_s msaf_event_t;

typedef struct msaf_dynamic_policy_local_metadata_s {
    msaf_event_t *create_event;
    msaf_event_t *delete_event;
} msaf_dynamic_policy_local_metadata_t;

typedef struct msaf_dynamic_policy_s {
    char *dynamicPolicyId;
    msaf_dynamic_policy_local_metadata_t *metadata;
    msaf_api_dynamic_policy_t *DynamicPolicy;
    pcf_app_session_t *pcf_app_session;
    char *hash;
    time_t dynamic_policy_created;
} msaf_dynamic_policy_t;

extern ogs_hash_t *msaf_dynamic_policy_new(void);
extern int msaf_dynamic_policy_create(cJSON *dynamicPolicy, msaf_event_t *dynamic_policy_event);
extern int msaf_dynamic_policy_update_pcf(msaf_dynamic_policy_t *msaf_dynamic_policy, msaf_api_dynamic_policy_t *dynamic_policy);
extern void msaf_dynamic_policy_delete_by_id(const char *dynamic_policy_id, msaf_event_t *delete_event);
extern msaf_dynamic_policy_t *msaf_dynamic_policy_find_by_dynamicPolicyId(const char *dynamicPolicyId);
cJSON *msaf_dynamic_policy_get_json(const char *dynamic_policy_id);
extern void msaf_context_dynamic_policy_free(msaf_dynamic_policy_t *dynamic_policy);

#ifdef __cplusplus
}
#endif

#endif /* MSAF_DYN_POLICY_H */
