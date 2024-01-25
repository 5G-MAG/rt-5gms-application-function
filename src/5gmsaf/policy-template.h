/*
License: 5G-MAG Public License (v1.0)
Author: Dev Audsin
Copyright: (C) 2023 British Broadcasting Corporation

For full license terms please see the LICENSE file distributed with this
program. If this file is missing then the license can be retrieved from
https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
*/

#ifndef MSAF_POLICY_TEMPLATE_H
#define MSAF_POLICY_TEMPLATE_H

#include "provisioning-session.h"
#include "openapi/model/msaf_api_policy_template.h"


#ifdef __cplusplus
extern "C" {
#endif

#define msaf_policy_template_free(policy_template) msaf_api_policy_template_free(policy_template)

extern bool msaf_policy_template_set_state(msaf_api_policy_template_t *policy_template, msaf_api_policy_template_state_e new_state, msaf_provisioning_session_t *provisioning_session);

extern void msaf_policy_template_set_id(msaf_api_policy_template_t *policy_template, const char *policy_template_id);

extern msaf_api_policy_template_t *msaf_policy_template_create(cJSON *policy_template);

extern msaf_api_policy_template_t *msaf_policy_template_parseFromJSON(cJSON *policy_templateJSON, const char **reason);

extern cJSON *msaf_policy_template_convertToJSON(msaf_api_policy_template_t *policy_template);

extern char *calculate_policy_template_hash(msaf_api_policy_template_t *policy_template);

extern msaf_policy_template_node_t *msaf_policy_template_populate(msaf_api_policy_template_t *policy_template, time_t creation_time);

extern OpenAPI_list_t *get_id_of_policy_templates_in_ready_state(ogs_hash_t *policy_templates);

extern OpenAPI_list_t *get_external_reference_of_policy_templates_in_ready_state(ogs_hash_t *policy_templates);

extern bool msaf_policy_template_clear(ogs_hash_t *policy_templates);

extern void msaf_policy_template_node_free(msaf_policy_template_node_t *node);

cJSON *msaf_policy_template_convert_to_json(msaf_api_policy_template_t *policy_template);
	
#ifdef __cplusplus
}
#endif

#endif /* MSAF_POLICY_TEMPLATE_H */
