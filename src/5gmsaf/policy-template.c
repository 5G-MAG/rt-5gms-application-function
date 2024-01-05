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

static void msaf_policy_template_set_state_reason(msaf_api_policy_template_t *policy_template, char *cause, char *detail, char *instance, char *nrf_id, char *supported_features, char *title, char *type);

/***** Public functions *****/

msaf_api_policy_template_t *msaf_policy_template_parseFromJSON(cJSON *policy_templateJSON, const char **reason)
{
    return msaf_api_policy_template_parseRequestFromJSON(policy_templateJSON, reason);
}

void msaf_policy_template_set_id(msaf_api_policy_template_t *policy_template, const char *policy_template_id)
{
    ogs_assert(policy_template);
    if(policy_template->policy_template_id) ogs_free(policy_template->policy_template_id);
    policy_template->policy_template_id = policy_template_id?ogs_strdup(policy_template_id):NULL;
}

char *calculate_policy_template_hash(msaf_api_policy_template_t *policy_template)
{
    cJSON *policy_template_json = NULL;
    char *policy_template_to_hash;
    char *policy_template_hashed = NULL;
    policy_template_json = msaf_policy_template_convert_to_json(policy_template);
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
           msaf_policy_template_set_state_reason(policy_template, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
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
	   msaf_policy_template_set_state_reason(policy_template, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
	   return true;
       }

       if(new_state == msaf_api_policy_template_STATE_PENDING) return false;

       if(new_state == msaf_api_policy_template_STATE_READY) {
	   if(provisioning_session->sai_cache)    
               msaf_sai_cache_clear(provisioning_session->sai_cache);
	   policy_template->state = msaf_api_policy_template_STATE_READY;
           msaf_policy_template_set_state_reason(policy_template, NULL, NULL, NULL, NULL, NULL, NULL, NULL);

	   return true;
       }
       
       if(new_state == msaf_api_policy_template_STATE_INVALID) {
	   char *detail = "Policy template state transitioned from PENDING to INVALID.";
	   char *title = "Provider decision.";
           policy_template->state = msaf_api_policy_template_STATE_INVALID;
	   msaf_policy_template_set_state_reason(policy_template, NULL, msaf_strdup(detail), NULL, NULL, NULL, msaf_strdup(title), NULL);
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
           msaf_policy_template_set_state_reason(policy_template, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
           return true;
       }	

       if(new_state == msaf_api_policy_template_STATE_PENDING) {
	   if(provisioning_session->sai_cache)    
               msaf_sai_cache_clear(provisioning_session->sai_cache);
           policy_template->state = msaf_api_policy_template_STATE_PENDING;
           msaf_policy_template_set_state_reason(policy_template, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
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
	   msaf_policy_template_set_state_reason(policy_template, NULL, msaf_strdup(detail), NULL, NULL, NULL, msaf_strdup(title), NULL);
           return true;
       }
   }

   if(policy_template->state == msaf_api_policy_template_STATE_INVALID) {
   
       if(new_state == msaf_api_policy_template_STATE_NULL) {
           policy_template->state = msaf_api_policy_template_STATE_NULL;
           msaf_policy_template_set_state_reason(policy_template, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
	   return true;
       }

       if(new_state == msaf_api_policy_template_STATE_PENDING) {
           policy_template->state = msaf_api_policy_template_STATE_PENDING;
           msaf_policy_template_set_state_reason(policy_template, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
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
           msaf_policy_template_set_state_reason(policy_template, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
	   return true;
       }

       if(new_state == msaf_api_policy_template_STATE_PENDING) {
           policy_template->state = msaf_api_policy_template_STATE_PENDING;
           msaf_policy_template_set_state_reason(policy_template, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
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

cJSON *msaf_policy_template_convertToJSON(msaf_api_policy_template_t *policy_template)
{
    return msaf_api_policy_template_convertResponseToJSON(policy_template);
}

cJSON *msaf_policy_template_convert_to_json(msaf_api_policy_template_t *policy_template) {

    return msaf_api_policy_template_convertRequestToJSON(policy_template);
}

OpenAPI_list_t *get_id_of_policy_templates_in_ready_state(ogs_hash_t *policy_templates)
{
    msaf_policy_template_node_t *policy_template_node;
    OpenAPI_list_t *valid_policy_template_ids;
    ogs_hash_index_t *hi;

    valid_policy_template_ids = OpenAPI_list_create();

    for (hi = ogs_hash_first(policy_templates);
            hi; hi = ogs_hash_next(hi)) {
        policy_template_node = (msaf_policy_template_node_t *)ogs_hash_this_val(hi);
        if (policy_template_node->policy_template->state == msaf_api_policy_template_STATE_READY) {
            OpenAPI_list_add(valid_policy_template_ids, msaf_strdup(policy_template_node->policy_template->policy_template_id));
        }
    }
    return valid_policy_template_ids;
}

OpenAPI_list_t *get_external_reference_of_policy_templates_in_ready_state(ogs_hash_t *policy_templates) {

    msaf_policy_template_node_t *policy_template_node;
    OpenAPI_list_t *external_references;
    ogs_hash_index_t *hi;

    external_references = OpenAPI_list_create();

    for (hi = ogs_hash_first(policy_templates);
            hi; hi = ogs_hash_next(hi)) {
        policy_template_node = (msaf_policy_template_node_t *)ogs_hash_this_val(hi);
        if (policy_template_node->policy_template->state == msaf_api_policy_template_STATE_READY) {
            OpenAPI_list_add(external_references, msaf_strdup(policy_template_node->policy_template->external_reference));
        }
    }
    return external_references;
}

bool msaf_policy_template_clear(ogs_hash_t *policy_templates)
{
    ogs_hash_index_t *hi;

    for (hi = ogs_hash_first(policy_templates); hi; hi = ogs_hash_next(hi)) {
        const void *key;
        int key_len;
        msaf_policy_template_node_t *node;

        ogs_hash_this(hi, &key, &key_len, (void**)(&node));
        ogs_hash_set(policy_templates, key, key_len, NULL);
        msaf_policy_template_node_free(node);
        ogs_free((void*)key);
    }

    return true;
}

void msaf_policy_template_node_free(msaf_policy_template_node_t *node)
{
    if (!node) return;

    if (node->policy_template) msaf_policy_template_free(node->policy_template);
    if (node->hash) ogs_free(node->hash);

    ogs_free(node);
}

/***** Private functions *****/

static void msaf_policy_template_set_state_reason(msaf_api_policy_template_t *policy_template, char *cause, char *detail, char *instance, char *nrf_id, char *supported_features, char *title, char *type)
{

    if(policy_template->state_reason) msaf_api_problem_details_free(policy_template->state_reason);
    policy_template->state_reason = msaf_api_problem_details_create(NULL, NULL, cause, detail, instance, NULL, nrf_id, 0, 0, supported_features, title, type);

}

/* vim:ts=8:sts=4:sw=4:expandtab:
*/
