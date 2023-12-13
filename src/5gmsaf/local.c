/*
License: 5G-MAG Public License (v1.0)
Author: Dev Audsin
Copyright: (C) 2023 British Broadcasting Corporation

For full license terms please see the LICENSE file distributed with this
program. If this file is missing then the license can be retrieved from
https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
*/

#include "ogs-proto.h"
#include "ogs-sbi.h"

#include "context.h"
#include "local.h"
#include "policy-template.h"
#include "utilities.h"

#ifdef __cplusplus
extern "C" {
#endif

static void policy_template_state_change_local_event_data_free(msaf_event_t *e);

bool local_process_event(msaf_event_t *e)
{
   ogs_debug("local_process_event: %s", msaf_event_get_name(e));

   switch (e->h.id) {
       case MSAF_EVENT_SBI_LOCAL:
       {
           if(e->local_id == MSAF_LOCAL_EVENT_POLICY_TEMPLATE_STATE_CHANGE) {
	       msaf_policy_template_change_state_event_data_t *msaf_policy_template_change_state_event_data;
	       msaf_provisioning_session_t *provisioning_session;
	       msaf_provisioning_session_t *provisioning_sess;
	       msaf_policy_template_node_t *msaf_policy_template_node;
	       msaf_policy_template_node_t *msaf_policy_template;
	       const char *policy_template_id;
	       const char *provisioning_session_id;

               msaf_policy_template_change_state_event_data =  (msaf_policy_template_change_state_event_data_t *)e->data;
	       provisioning_session = msaf_policy_template_change_state_event_data->provisioning_session;
               msaf_policy_template_node = msaf_policy_template_change_state_event_data->policy_template_node;
	       policy_template_id = msaf_policy_template_node->policy_template->policy_template_id;

	       provisioning_session_id = provisioning_session->provisioningSessionId;

	       provisioning_sess = msaf_provisioning_session_find_by_provisioningSessionId(provisioning_session_id);
	       if(provisioning_sess) {
		   msaf_policy_template = msaf_provisioning_session_find_policy_template_by_id(provisioning_session, policy_template_id);    
	           if(msaf_policy_template && (msaf_policy_template_node == msaf_policy_template)) {
			   
		       if(msaf_policy_template_set_state(msaf_policy_template->policy_template, msaf_policy_template_change_state_event_data->new_state, provisioning_sess)) {
			   ogs_info("msaf_policy_template->policy_template->state: %d", msaf_policy_template->policy_template->state);    
		           msaf_policy_template->last_modified = time(NULL);
			   if(msaf_policy_template->hash) ogs_free(msaf_policy_template->hash);
                           msaf_policy_template->hash  = calculate_policy_template_hash(msaf_policy_template->policy_template);
		           //MVP: going straight to READY state from PENDING
			   if(msaf_policy_template->policy_template->state == msaf_api_policy_template_STATE_PENDING) {	
			       ogs_debug("MVP: set to msaf_api_policy_template_STATE_READY");	   
			       msaf_provisioning_session_send_policy_template_state_change_event(provisioning_sess, msaf_policy_template, msaf_api_policy_template_STATE_READY, NULL, NULL);
			   }	
			   ogs_info("msaf_policy_template->policy_template->state: %d", msaf_policy_template->policy_template->state);

			   if(msaf_policy_template_change_state_event_data->callback) {
			       msaf_policy_template_change_state_event_data->callback(msaf_policy_template_change_state_event_data->provisioning_session, msaf_policy_template_change_state_event_data->policy_template_node, msaf_policy_template_change_state_event_data->new_state, msaf_policy_template_change_state_event_data->callback_user_data);
	      
			   }

		       }	 

		   } else {
		        ogs_error("Policy template not found");
		        policy_template_state_change_local_event_data_free(e);
                        return false;
			   

		   }		   

	       }

               ogs_debug("taking event for OGS_EVENT_SBI_LOCAL");
	       policy_template_state_change_local_event_data_free(e);
	       return true;

	   }
           	   
           //break;
            //DEFAULT
            //END

            //ogs_debug("end OGS_EVENT_SBI_LOCAL");
            //break;
       }
       break;    
       default:
           break;
   }

   return false;    
}

static void policy_template_state_change_local_event_data_free(msaf_event_t *e) {
    if(e->data) ogs_free(e->data);
}


#ifdef __cplusplus
}
#endif

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
