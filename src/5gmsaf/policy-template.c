/*
License: 5G-MAG Public License (v1.0)
Copyright: (C) 2023 British Broadcasting Corporation

For full license terms please see the LICENSE file distributed with this
program. If this file is missing then the license can be retrieved from
https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
*/

#include "context.h"
#include "policy-template.h"
#include "utilities.h"
#include "hash.h"
#include "sai-cache.h"

#if 0
static msaf_api_m1_qo_s_specification_t *msaf_policy_template_qos_specification_new(cJSON *policy_template);
static msaf_api_policy_template_application_session_context_t *msaf_policy_template_application_session_context(cJSON *policy_template);
static msaf_api_charging_specification_t *msaf_policy_template_charging_specification(cJSON *policy_template);
#endif

/***** Public functions *****/

msaf_api_policy_template_t *msaf_policy_template_parseFromJSON(cJSON *policy_templateJSON)
{
    return msaf_api_policy_template_parseRequestFromJSON(policy_templateJSON);
}

void msaf_policy_template_set_id(msaf_api_policy_template_t *policy_template, const char *policy_template_id)
{
    ogs_assert(policy_template);
    if(policy_template->policy_template_id) ogs_free(policy_template->policy_template_id);
    policy_template->policy_template_id = msaf_strdup(policy_template_id);
}

char *calculate_policy_template_hash(msaf_api_policy_template_t *policy_template)
{
    cJSON *policy_template_json = NULL;
    char *policy_template_to_hash;
    char *policy_template_hashed = NULL;
    policy_template_json = msaf_policy_template_convertToJSON(policy_template);
    policy_template_to_hash = cJSON_Print(policy_template_json);
    cJSON_Delete(policy_template_json);
    policy_template_hashed = calculate_hash(policy_template_to_hash);
    cJSON_free(policy_template_to_hash);
    return policy_template_hashed;
}

msaf_policy_template_node_t *msaf_policy_template_populate(msaf_api_policy_template_t *policy_template, time_t creation_time)
{

    msaf_policy_template_node_t *msaf_policy_template;

    msaf_policy_template = ogs_calloc(1, sizeof(msaf_policy_template_node_t));
    ogs_assert(msaf_policy_template);

    msaf_policy_template->policy_template = policy_template;
    msaf_policy_template->last_modified = creation_time;
    msaf_policy_template->hash  = calculate_policy_template_hash(policy_template);

    return msaf_policy_template;
}

bool msaf_policy_template_set_state(msaf_api_policy_template_t *policy_template, msaf_api_policy_template_state_e new_state, msaf_provisioning_session_t *provisioning_session) {


   ogs_assert(policy_template);
   ogs_assert(provisioning_session);

   if(policy_template->state == msaf_api_policy_template_STATE_NULL) {
       if(new_state == msaf_api_policy_template_STATE_NULL) return false;

       if(new_state == msaf_api_policy_template_STATE_PENDING) {
	   policy_template->state = msaf_api_policy_template_STATE_PENDING;
           return true;
       }

       if(new_state == msaf_api_policy_template_STATE_READY || new_state == msaf_api_policy_template_STATE_INVALID ||  new_state == msaf_api_policy_template_STATE_SUSPENDED) {
	   ogs_error("Invalid state change");	
           return false;
       }	  
   }

   if(policy_template->state == msaf_api_policy_template_STATE_PENDING) {

       if(new_state == msaf_api_policy_template_STATE_NULL) {
           policy_template->state = msaf_api_policy_template_STATE_NULL;
	   return true;
       }

       if(new_state == msaf_api_policy_template_STATE_PENDING) return false;

       if(new_state == msaf_api_policy_template_STATE_READY) {
	   if(provisioning_session->sai_cache)    
               msaf_sai_cache_clear(provisioning_session->sai_cache);
	   policy_template->state = msaf_api_policy_template_STATE_READY;
	   return true;
       }
       
       if(new_state == msaf_api_policy_template_STATE_INVALID) {
           policy_template->state = msaf_api_policy_template_STATE_INVALID;
           return true;
       }
       
       if(new_state ==  msaf_api_policy_template_STATE_SUSPENDED) {
           ogs_error("Invalid state change");
           return false;
       }


   }

   if(policy_template->state == msaf_api_policy_template_STATE_READY) {

       if(new_state == msaf_api_policy_template_STATE_NULL) {
	   if (provisioning_session->sai_cache)    
               msaf_sai_cache_clear(provisioning_session->sai_cache);
           policy_template->state = msaf_api_policy_template_STATE_NULL;
           return true;
       }	

       if(new_state == msaf_api_policy_template_STATE_PENDING) {
	   if(provisioning_session->sai_cache)    
               msaf_sai_cache_clear(provisioning_session->sai_cache);
           policy_template->state = msaf_api_policy_template_STATE_PENDING;
           return true;
       }
       
       if(new_state == msaf_api_policy_template_STATE_READY) return false;
           
       if(new_state == msaf_api_policy_template_STATE_INVALID) {
           ogs_error("Invalid state change");
           return false;
       }
       
       if(new_state ==  msaf_api_policy_template_STATE_SUSPENDED) {
	   char *detail = "Policy template state transitioned from READY to SUSPENDED.";
	   char *title = "Operator Decision.";
           if (provisioning_session->sai_cache)    
	       msaf_sai_cache_clear(provisioning_session->sai_cache);
           policy_template->state = msaf_api_policy_template_STATE_SUSPENDED;
           return true;
       }
   }

   if(policy_template->state == msaf_api_policy_template_STATE_INVALID) {
   
       if(new_state == msaf_api_policy_template_STATE_NULL) {
           policy_template->state = msaf_api_policy_template_STATE_NULL;
	   return true;
       }

       if(new_state == msaf_api_policy_template_STATE_PENDING) {
           policy_template->state = msaf_api_policy_template_STATE_PENDING;
	   return true;
       }

       if(new_state == msaf_api_policy_template_STATE_READY || new_state ==  msaf_api_policy_template_STATE_SUSPENDED) {
           ogs_error("Invalid state change");
           return false;
       }

       if(new_state == msaf_api_policy_template_STATE_INVALID) return false;
   }

   if(policy_template->state == msaf_api_policy_template_STATE_SUSPENDED) {
       	   
       if(new_state == msaf_api_policy_template_STATE_NULL) {
           policy_template->state = msaf_api_policy_template_STATE_NULL;
	   return true;
       }

       if(new_state == msaf_api_policy_template_STATE_PENDING) {
           policy_template->state = msaf_api_policy_template_STATE_PENDING;
	   return true;
       }

       if(new_state == msaf_api_policy_template_STATE_READY || (new_state == msaf_api_policy_template_STATE_INVALID)) {
           ogs_error("Invalid state change");
           return false;
       }

       if(new_state == msaf_api_policy_template_STATE_SUSPENDED) return false;
   }
   return false;

}

msaf_api_policy_template_t *msaf_policy_template_new(const char *external_reference, msaf_api_m1_qo_s_specification_t *qos_specification, msaf_api_policy_template_application_session_context_t *application_session_context, msaf_api_charging_specification_t *charging_specification)
{
    msaf_api_policy_template_t *policy_template;
    char *policy_template_id = NULL;
    msaf_api_policy_template_state_e state = msaf_api_policy_template_STATE_NULL;

    policy_template = msaf_api_policy_template_create(application_session_context, charging_specification,
                    msaf_strdup(external_reference), policy_template_id, qos_specification, state, NULL);

    return policy_template;
}

cJSON *msaf_policy_template_convertToJSON(msaf_api_policy_template_t *policy_template)
{
    return msaf_api_policy_template_convertResponseToJSON(policy_template);
}

/***** Private functions *****/

#if 0
static msaf_api_m1_qo_s_specification_t *msaf_policy_template_qos_specification_new(cJSON *policy_template)
{

    msaf_api_m1_qo_s_specification_t *qos_specification;
    qos_specification = msaf_api_m1_qo_s_specification_parseRequestFromJSON(policy_template);
    ogs_assert(qos_specification);
    return qos_specification; 

}

static msaf_api_policy_template_application_session_context_t *msaf_policy_template_application_session_context(cJSON *policy_template)
{
    msaf_api_policy_template_application_session_context_t *policy_template_application_session_context;
    policy_template_application_session_context = msaf_api_policy_template_application_session_context_parseRequestFromJSON(policy_template);
    ogs_assert(policy_template_application_session_context);
    return policy_template_application_session_context;    
}

static msaf_api_charging_specification_t *msaf_policy_template_charging_specification(cJSON *policy_template)
{
    msaf_api_charging_specification_t *charging_specification;
    charging_specification = msaf_api_charging_specification_parseRequestFromJSON(policy_template);
    ogs_assert(charging_specification);
    return charging_specification;    
}
#endif

/* vim:ts=8:sts=4:sw=4:expandtab:
*/
