/*
 * License: 5G-MAG Public License (v1.0)
 * Author: Dev Audsin
 * Copyright: (C) 2022 British Broadcasting Corporation
 *
 * For full license terms please see the LICENSE file distributed with this
 * program. If this file is missing then the license can be retrieved from
 * https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
 */

#ifndef MSAF_CERT_MGR_H
#define MSAF_CERT_MGR_H

#include "context.h"
#include "headers.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct msaf_certificate_s {
    char *id;
    char *certificate;
    time_t last_modified;
    char *server_certificate_hash;
    nf_headers_t *headers;
    int cache_control_max_age;
    int return_code;
} msaf_certificate_t;

typedef struct msaf_assigned_certificate_s {
    ogs_lnode_t node;
    char *certificate_id;
} msaf_assigned_certificate_t;

typedef struct fqdn_list_node_s {
    ogs_lnode_t node;
    char *fqdn;
} fqdn_list_node_t;

extern msaf_certificate_t *server_cert_new(const char *operation, const char *common_name, ogs_list_t *extra_fqdns);
extern int server_cert_set(const char *cert_id, const char *cert);
extern msaf_certificate_t *server_cert_retrieve(const char *certid);
extern msaf_certificate_t *server_cert_get_servercert(const char *certid);
extern char *check_in_cert_list(const char *canonical_domain_name);
extern int server_cert_delete(const char *certid);
extern void msaf_certificate_free(msaf_certificate_t *cert);

#ifdef __cplusplus
}
#endif

/* vim:ts=8:sts=4:sw=4:expandtab:
 */

#endif /* MSAF_CERT_MGR_H */
