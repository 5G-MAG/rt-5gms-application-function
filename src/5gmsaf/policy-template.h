/*
License: 5G-MAG Public License (v1.0)
Copyright: (C) 2022 British Broadcasting Corporation

For full license terms please see the LICENSE file distributed with this
program. If this file is missing then the license can be retrieved from
https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
*/

#ifndef MSAF_POLICY_TEMPLATE_H
#define MSAF_POLICY_TEMPLATE_H

#include "openapi/model/policy_template.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct msaf_network_assistance_policy_template_s {
    ogs_lnode_t node;
    char *policy_template_id;
    OpenAPI_policy_template_t *policy_template;
} msaf_network_assistance_policy_template_t;

extern int msaf_na_policy_template_create(cJSON *policy_template);
extern void msaf_na_policy_template_remove_all(void);
extern msaf_network_assistance_policy_template_t *get_policy_template_by_id(char *policy_template_id);


	
#ifdef __cplusplus
}
#endif

#endif /* MSAF_POLICY_TEMPLATE_H */
