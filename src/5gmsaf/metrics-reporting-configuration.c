 /*
License: 5G-MAG Public License (v1.0)
Author: Vuk Stojkovic
Copyright: (C) 2023-2024 Fraunhofer FOKUS

For full license terms please see the LICENSE file distributed with this
program. If this file is missing then the license can be retrieved from
https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
*/

#include "ogs-core.h"
#include "hash.h"
#include "utilities.h"
#include "provisioning-session.h"
#include "metrics-reporting-configuration.h"


 ogs_hash_t * msaf_metrics_reporting_map(void){
     ogs_hash_t *metrics_reporting_map = ogs_hash_make();
     return metrics_reporting_map;
 }

 static char *calculate_metrics_reporting_configuration_hash(msaf_api_metrics_reporting_configuration_t *metrics_reporting_configuration)
 {
     if (!metrics_reporting_configuration) {
         ogs_error("Metrics object not found.");
         return NULL;
     }

     cJSON *metrics_configuration_json = msaf_api_metrics_reporting_configuration_convertResponseToJSON(metrics_reporting_configuration);

     if (!metrics_configuration_json) {
         ogs_error("Conversion to JSON failed.");
         return NULL;
     }

     char *metrics_configuration_to_hash = cJSON_PrintUnformatted(metrics_configuration_json);

     if (!metrics_configuration_to_hash) {
         cJSON_Delete(metrics_configuration_json);
         return NULL;
     }

     char *metrics_configuration_hashed = calculate_hash(metrics_configuration_to_hash);

     cJSON_free(metrics_configuration_to_hash);
     cJSON_Delete(metrics_configuration_json);

     return metrics_configuration_hashed;
 }

 msaf_metrics_reporting_configuration_t* process_and_map_metrics_reporting_configuration(msaf_provisioning_session_t *provisioning_session, msaf_api_metrics_reporting_configuration_t *parsed_config) {

     ogs_assert(provisioning_session);
     ogs_assert(parsed_config);

     ogs_uuid_t uuid;
     ogs_uuid_get(&uuid);
     char new_id[OGS_UUID_FORMATTED_LENGTH + 1];
     ogs_uuid_format(new_id, &uuid);

     if (parsed_config->metrics_reporting_configuration_id != NULL) {
         ogs_free(parsed_config->metrics_reporting_configuration_id);
     }
     parsed_config->metrics_reporting_configuration_id = msaf_strdup(new_id);

     msaf_metrics_reporting_configuration_t *msaf_metrics_config = ogs_calloc(1, sizeof(msaf_metrics_reporting_configuration_t));

     if (!msaf_metrics_config) {
         ogs_error("Failed to allocate msaf_metrics_reporting_configuration");
         return NULL;
     }

     msaf_metrics_config->config = parsed_config;
     msaf_metrics_config->etag = calculate_metrics_reporting_configuration_hash(msaf_metrics_config->config);
     msaf_metrics_config->receivedTime = time(NULL);

     if (provisioning_session->metrics_reporting_map == NULL) {
         provisioning_session->metrics_reporting_map = msaf_metrics_reporting_map();
     }

     char *hashKey = msaf_strdup(msaf_metrics_config->config->metrics_reporting_configuration_id);
     ogs_hash_set(provisioning_session->metrics_reporting_map, hashKey, OGS_HASH_KEY_STRING, msaf_metrics_config);

     return msaf_metrics_config;
 }

 msaf_metrics_reporting_configuration_t* msaf_metrics_reporting_configuration_retrieve(const msaf_provisioning_session_t *provisioning_session, const char *metrics_configuration_id) {
     if (!provisioning_session || !metrics_configuration_id) {
         return NULL;
     }
     return (msaf_metrics_reporting_configuration_t*)ogs_hash_get(provisioning_session->metrics_reporting_map, metrics_configuration_id, OGS_HASH_KEY_STRING);
 }

 int msaf_delete_metrics_configuration(msaf_provisioning_session_t *provisioning_session, const char *metrics_configuration_id) {

     if (!provisioning_session || !metrics_configuration_id) {
         return -1;
     }

     msaf_metrics_reporting_configuration_t *metrics_config = (msaf_metrics_reporting_configuration_t *)ogs_hash_get(provisioning_session->metrics_reporting_map, metrics_configuration_id, OGS_HASH_KEY_STRING);

     if (metrics_config) {

         ogs_hash_set(provisioning_session->metrics_reporting_map, metrics_configuration_id, OGS_HASH_KEY_STRING, NULL);

         if (metrics_config->config) {
             msaf_api_metrics_reporting_configuration_free(metrics_config->config);
             metrics_config->config = NULL;
         }

         if (metrics_config->etag) ogs_free(metrics_config->etag);
         ogs_free(metrics_config);
         return 0;
     }
     else {
         ogs_error("Metrics Reporting Configuration with ID %s not found", metrics_configuration_id);
         return -1;
     }
 }

 int update_metrics_configuration(msaf_metrics_reporting_configuration_t *existing_metrics_config, msaf_api_metrics_reporting_configuration_t *updated_config) {

     if (!existing_metrics_config || !updated_config) {
         ogs_error("Null pointers passed");
         return -1;
     }

     msaf_api_metrics_reporting_configuration_free(existing_metrics_config->config);

     existing_metrics_config->config = updated_config;
     if (existing_metrics_config->etag) {
         ogs_free(existing_metrics_config->etag);
     }
     existing_metrics_config->etag = calculate_metrics_reporting_configuration_hash(updated_config);
     existing_metrics_config->receivedTime = time(NULL);

     return 0;
 }


