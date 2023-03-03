/*
License: 5G-MAG Public License (v1.0)
Author: Dev Audsin
Copyright: (C) 2022 British Broadcasting Corporation

For full license terms please see the LICENSE file distributed with this
program. If this file is missing then the license can be retrieved from
https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
*/

#include "certmgr.h"


#define MAX_CHILD_PROCESS               16
#define OGS_ARG_MAX                     256

static ogs_proc_t process[MAX_CHILD_PROCESS];
static int process_num = 0;

static msaf_certificate_t *msaf_certificate_populate(char *certid, char *cert, int out_return_code);

int server_cert_delete(char *certid)
{
    const char *commandLine[OGS_ARG_MAX];
    ogs_proc_t *current = NULL;
    FILE *out = NULL;
    char buf[OGS_HUGE_LEN];
    int ret = 0, out_return_code = 0;
    char *command;
    char *rv = NULL;

    command = ogs_msprintf("-c delete %s", certid);

    commandLine[0] =  msaf_self()->config.certificateManager;
    commandLine[1] = command;
    commandLine[2] = NULL;

    current = &process[process_num++];
    ret = ogs_proc_create(commandLine,
        ogs_proc_option_combined_stdout_stderr|
        ogs_proc_option_inherit_environment,
        current);
    ogs_assert(ret == 0);
    out = ogs_proc_stdout(current);
    ogs_assert(out);

    while(fgets(buf, OGS_HUGE_LEN, out)) {
        printf("%s", buf);
    }
    ret = ogs_proc_join(current, &out_return_code);
    ogs_assert(ret == 0);
    ret = ogs_proc_destroy(current);
    ogs_assert(ret == 0);
    ogs_free(command);

    return out_return_code;
}

msaf_certificate_t *server_cert_retrieve(char *certid)
{  
    const char *commandLine[OGS_ARG_MAX];
    ogs_proc_t *current = NULL;
    FILE *out = NULL;
    char buf[OGS_HUGE_LEN];
    char *cert = NULL;
    int ret = 0, out_return_code = 0;
    msaf_certificate_t *msaf_certificate = NULL;
    char *command;
    char *rv = NULL;
    size_t cert_size = 0;
    size_t cert_reserved = 0;   
     
    command = ogs_msprintf("-c publiccert %s", certid);

    commandLine[0] =  msaf_self()->config.certificateManager;
    commandLine[1] = command;
    commandLine[2] = NULL;

    current = &process[process_num++];
    ret = ogs_proc_create(commandLine,
        ogs_proc_option_combined_stdout_stderr|
        ogs_proc_option_inherit_environment,
        current);
    ogs_assert(ret == 0);
    out = ogs_proc_stdout(current);
    ogs_assert(out);

    cert = ogs_calloc(1, 4096);
    cert_reserved = 4096;

    while(fgets(buf, OGS_HUGE_LEN, out)) {
        cert_size += strlen (buf);
        if(cert_size > cert_reserved - 1) {
            cert_reserved +=4096;
            cert = ogs_realloc(cert,cert_reserved);
	}
	strcat(cert,buf);
    }      
    ret = ogs_proc_join(current, &out_return_code);
    ogs_assert(ret == 0);
    ret = ogs_proc_destroy(current);
    ogs_assert(ret == 0);
    ogs_free(command);
    if(!out_return_code){
        msaf_certificate = msaf_certificate_populate(certid, cert, out_return_code);
        ogs_assert(msaf_certificate);
    }
    return msaf_certificate;
}

int server_cert_set(char *cert_id, char *cert)
{
    const char *commandLine[OGS_ARG_MAX];
    ogs_proc_t *current = NULL;
    FILE *in = NULL;
    char *bufin;
    int ret = 0, out_return_code = 0, rv = 0;
    char *operation;

    operation = ogs_msprintf("-c setcert %s", cert_id);

    commandLine[0] =  msaf_self()->config.certificateManager;
    commandLine[1] = operation;
    commandLine[2] = NULL;

    current = &process[process_num++];
    ret = ogs_proc_create(commandLine, 
        ogs_proc_option_inherit_environment,
        current);
    ogs_assert(ret == 0);
   
    in = ogs_proc_stdin(current);
    ogs_assert(in);

    if(cert)
    {
        fprintf(in, "%s", cert);
    }

    ret = ogs_proc_join(current, &out_return_code);
    ogs_assert(ret == 0);
    ret = ogs_proc_destroy(current);
    ogs_assert(ret == 0);
    ogs_free(operation);
    return out_return_code;
}


msaf_certificate_t *server_cert_new(char *operation, char *operation_params)
{
    const char *commandLine[OGS_ARG_MAX];
    ogs_proc_t *current = NULL;
    FILE *out = NULL;
    FILE *in = NULL;
    char buf[4096];
    char *cert;
    int ret = 0, out_return_code = 0;
    char *canonical_domain_name;
    char *certificate;
    msaf_certificate_t *msaf_certificate = NULL;
    size_t cert_size = 0;
    size_t cert_reserved = 0;    
    msaf_application_server_node_t *msaf_as = NULL;
    msaf_as = ogs_list_first(&msaf_self()->config.applicationServers_list);
    canonical_domain_name = msaf_as->canonicalHostname;

    ogs_uuid_t uuid;
    char *command;
    char id[OGS_UUID_FORMATTED_LENGTH + 1];
    char *rv = NULL;

    ogs_uuid_get(&uuid);
    ogs_uuid_format(id, &uuid);

    command = ogs_msprintf("-c %s %s %s", operation, id, canonical_domain_name);

    commandLine[0] =  msaf_self()->config.certificateManager;
    commandLine[1] = command;
    commandLine[2] = NULL;

    current = &process[process_num++];
    ret = ogs_proc_create(commandLine,
        ogs_proc_option_combined_stdout_stderr|
        ogs_proc_option_inherit_environment,
        current);
    ogs_assert(ret == 0);
    out = ogs_proc_stdout(current);
    ogs_assert(out);

    cert = ogs_calloc(1, 4096);
    cert_reserved = 4096;

    while(fgets(buf, OGS_HUGE_LEN, out)) {
        cert_size += strlen (buf);
	if(cert_size > cert_reserved - 1) {
	    cert_reserved =+ 4096;	
            cert = ogs_realloc(cert,cert_reserved);
	}
        strcat(cert,buf);
    }
    ret = ogs_proc_join(current, &out_return_code);
    ogs_assert(ret == 0);
    ret = ogs_proc_destroy(current);
    ogs_assert(ret == 0);
    ogs_free(command);
    msaf_certificate = msaf_certificate_populate(id, cert, out_return_code);    
    ogs_assert(msaf_certificate); 
    return msaf_certificate;
}

char *check_in_cert_list(char *canonical_domain_name)
{
    const char *commandLine[OGS_ARG_MAX];
    ogs_proc_t *current = NULL;
    FILE *out = NULL;
    char buf[OGS_HUGE_LEN];
    int ret = 0, out_return_code = 0;
    char *certificate = NULL;
    char *cert_id;

    char *operation;

    operation = ogs_msprintf("-c list");

    commandLine[0] =  msaf_self()->config.certificateManager;
    commandLine[1] = operation;
    commandLine[2] = NULL;

    current = &process[process_num++];
    ret = ogs_proc_create(commandLine, 
        ogs_proc_option_combined_stdout_stderr|
        ogs_proc_option_inherit_environment,
        current);
    ogs_assert(ret == 0);
    out = ogs_proc_stdout(current);
    ogs_assert(out);

    while(fgets(buf, OGS_HUGE_LEN, out)) {

      if (str_match(buf, canonical_domain_name)) {
  	certificate = strtok_r(buf,"\t",&cert_id);	
	break;
      }
    }

    ret = ogs_proc_join(current, &out_return_code);
    ogs_assert(ret == 0);
    ret = ogs_proc_destroy(current);
    ogs_assert(ret == 0);
    ogs_free(operation);
    return certificate;
}

static msaf_certificate_t *msaf_certificate_populate(char *certid, char *cert, int out_return_code)
{
	msaf_certificate_t *msaf_certificate = NULL;    
	char *token; 
	char *string;
	char *key;
    char *val;
	char *value;
	char *ptr;
    char *populated_certificate;
  	msaf_certificate = ogs_calloc(1, sizeof(msaf_certificate_t));
  	ogs_assert(msaf_certificate);
  	msaf_certificate->id = certid;
  	msaf_certificate->return_code = out_return_code;
    populated_certificate = ogs_calloc(1, strlen(cert));
    ptr = string = ogs_strdup(cert);
    while ((token = strsep(&string, "\n")) != NULL)
    {
		if(strstr(token, "Last-Modified:") || strstr(token, "ETag:") || strstr(token, "Cache-Control: max-age=")){
			key = strtok_r(token,":",&val);
	           ogs_info("key: %s, value: %s", key, val);
            value = ogs_calloc(1, strlen(val));
            without_spaces(value, val);
            ogs_assert(value);   			   
		   	if (!strcmp(key,"Last-Modified")){
	            ogs_debug("key: %s, value: %s", key, value);			   
                msaf_certificate->last_modified = str_to_time(value);
                ogs_free(value);
		   	} else if (!strcmp(key,"Cache-Control")){
                char *max_age_key;
                char *max_age_value;
                char *max_age = ogs_strdup(value);
                max_age_key = strtok_r(max_age,"=",&max_age_value);
                without_spaces(value, max_age_value);                
	            ogs_debug("key: %s, value: %s", key, value);
		        if(!strcmp(value,"")){
			    	msaf_certificate->cache_control_max_age = 0;
				} else { 
			    	msaf_certificate->cache_control_max_age =  ascii_to_long(value);
				}
                ogs_free(max_age);
                ogs_free(value);
		   	} else if (!strcmp(key,"ETag")){
	            ogs_debug("key: %s, value: %s", key, value);			   
                msaf_certificate->server_certificate_hash = value;
		   	} else {
	            ogs_debug("Unrecognised key: %s, value: %s", key, value);			   
		   	}

        } else {        
            strcat(populated_certificate,token);
            strcat(populated_certificate,"\n");
        }
    }
    msaf_certificate->certificate = populated_certificate; 
	ogs_free(ptr);
	return msaf_certificate;
}
