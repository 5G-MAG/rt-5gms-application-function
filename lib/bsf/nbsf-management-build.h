/*
License: 5G-MAG Public License (v1.0)
Copyright: (C) 2023 British Broadcasting Corporation

For full license terms please see the LICENSE file distributed with this
program. If this file is missing then the license can be retrieved from
https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
*/

#ifndef BSF_MANAGEMENT_BUILD_H
#define BSF_MANAGEMENT_BUILD_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct bsf_client_sess_s bsf_client_sess_t;
typedef struct ogs_sbi_request_s ogs_sbi_request_t;

ogs_sbi_request_t *_nbsf_management_pcf_binding_build(bsf_client_sess_t *sess, void *data);

#ifdef __cplusplus
}
#endif

/* vim:ts=8:sts=4:sw=4:expandtab:
 */

#endif /* ifndef BSF_MANAGEMENT_BUILD_H */
