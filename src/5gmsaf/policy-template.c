/*
License: 5G-MAG Public License (v1.0)
Copyright: (C) 2022 British Broadcasting Corporation

For full license terms please see the LICENSE file distributed with this
program. If this file is missing then the license can be retrieved from
https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
*/

#include "context.h"
#include "policy-template.h"
#include "utilities.h"

static void msaf_na_policy_template_remove(msaf_network_assistance_policy_template_t *msaf_network_assistance_policy_template);
static OpenAPI_policy_template_t *dummy_policy_template(void);

/***** Public functions *****/

int msaf_na_policy_template_create(cJSON *policy_template){
    OpenAPI_policy_template_t *na_policy_template;
    msaf_network_assistance_policy_template_t *msaf_network_assistance_policy_template;

    msaf_network_assistance_policy_template = ogs_calloc(1, sizeof(msaf_network_assistance_policy_template_t));
    ogs_assert(msaf_network_assistance_policy_template);

    na_policy_template = dummy_policy_template();

    msaf_network_assistance_policy_template->policy_template_id = msaf_strdup(na_policy_template->policy_template_id);

    msaf_network_assistance_policy_template->policy_template = na_policy_template;

    ogs_list_add(&msaf_self()->network_assistance_policy_templates, msaf_network_assistance_policy_template);
    
    return 1;

}

msaf_network_assistance_policy_template_t *get_policy_template_by_id(char *policy_template_id){

    msaf_network_assistance_policy_template_t *msaf_network_assistance_policy_template = NULL, *next = NULL;

    ogs_list_for_each_safe(&msaf_self()->network_assistance_policy_templates, next, msaf_network_assistance_policy_template){
	    if(!strcmp(msaf_network_assistance_policy_template->policy_template_id, policy_template_id))
		break;
    }
    if(msaf_network_assistance_policy_template)
        return msaf_network_assistance_policy_template;

    return NULL; 
}

void msaf_na_policy_template_remove_all()
{
    msaf_network_assistance_policy_template_t *msaf_network_assistance_policy_template = NULL, *next = NULL;

    ogs_list_for_each_safe(&msaf_self()->network_assistance_policy_templates, next, msaf_network_assistance_policy_template)
    {    
        ogs_list_remove(&msaf_self()->network_assistance_policy_templates, msaf_network_assistance_policy_template);
	msaf_na_policy_template_remove(msaf_network_assistance_policy_template);
    }
}


/***** Private functions *****/

static void msaf_na_policy_template_remove(msaf_network_assistance_policy_template_t *msaf_network_assistance_policy_template)
{
    ogs_assert(msaf_network_assistance_policy_template);
    if (msaf_network_assistance_policy_template->policy_template_id) ogs_free(msaf_network_assistance_policy_template->policy_template_id);
    if (msaf_network_assistance_policy_template->policy_template) OpenAPI_policy_template_free(msaf_network_assistance_policy_template->policy_template);
    ogs_free(msaf_network_assistance_policy_template);
}


static OpenAPI_policy_template_t *dummy_policy_template(void)
{
    char *dnn = "internet";

    char *max_auth_btr_dl;
    char *max_auth_btr_ul;
    char *max_btr_dl;
    char *max_btr_ul;

    OpenAPI_m1_qo_s_specification_t *m1_qos;
    OpenAPI_policy_template_application_session_context_t *policy_template_application_session_context;
    OpenAPI_policy_template_t *policy_template;
    char *policy_template_id = "POLICYUUID";


    max_auth_btr_dl = ogs_sbi_bitrate_to_string(86000, OGS_SBI_BITRATE_BPS);
    max_auth_btr_ul = ogs_sbi_bitrate_to_string(86000, OGS_SBI_BITRATE_BPS);
    max_btr_dl = ogs_sbi_bitrate_to_string(96000, OGS_SBI_BITRATE_BPS);
    max_btr_ul = ogs_sbi_bitrate_to_string(96000, OGS_SBI_BITRATE_BPS);

    m1_qos = OpenAPI_m1_qo_s_specification_create(false, 0, false, 0, max_auth_btr_dl, max_auth_btr_ul, max_btr_dl, max_btr_ul, NULL);

    policy_template_application_session_context = OpenAPI_policy_template_application_session_context_create(msaf_strdup(dnn), NULL);

    policy_template = OpenAPI_policy_template_create(policy_template_application_session_context, NULL, NULL, msaf_strdup(policy_template_id), m1_qos, OpenAPI_policy_template_STATE_READY, NULL);

    return policy_template;
}



/* vim:ts=8:sts=4:sw=4:expandtab:
*/
