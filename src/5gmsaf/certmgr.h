/*
License: 5G-MAG Public License (v1.0)
Author: Dev Audsin
Copyright: (C) 2022 British Broadcasting Corporation

For full license terms please see the LICENSE file distributed with this
program. If this file is missing then the license can be retrieved from
https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
 */

#ifndef MSAF_CERT_MGR_H
#define MSAF_CERT_MGR_H

#include "context.h"


#ifdef __cplusplus
extern "C" {
#endif

typedef struct msaf_certificate_s {
    char *id;
    char *certificate;
    time_t last_modified;
    char *server_certificate_hash;
    int cache_control_max_age;
    int return_code;
} msaf_certificate_t;


typedef struct msaf_assigned_certificate_s {
    ogs_lnode_t       node;	
    char *certificate_id;
} msaf_assigned_certificate_t;

extern msaf_certificate_t  *server_cert_new(char *operation, char *operation_params);
extern int server_cert_set(char *cert_id, char *cert);
extern msaf_certificate_t *server_cert_retrieve(char *certid);
extern char *check_in_cert_list(char *canonical_domain_name);
extern int server_cert_delete(char *certid);

#ifdef __cplusplus
}
#endif

#endif /* MSAF_CERT_MGR_H */
