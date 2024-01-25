/*
License: 5G-MAG Public License (v1.0)
Author: Dev Audsin
Copyright: (C) 2022 British Broadcasting Corporation

For full license terms please see the LICENSE file distributed with this
program. If this file is missing then the license can be retrieved from
https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
 */

#ifndef NF_SERVER_H
#define NF_SERVER_H

#include "context.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct nf_server_interface_metadata_s {
    const char *api_title;
    const char *api_version;
} nf_server_interface_metadata_t;

typedef struct nf_server_app_metadata_s {
    const char *app_name;
    const char *app_version;
    const char *server_name;
} nf_server_app_metadata_t;

extern bool nf_server_send_error(ogs_sbi_stream_t *stream,
        int status, int number_of_components, ogs_sbi_message_t *message,
        const char *title, const char *detail, cJSON * problem_detail, const nf_server_interface_metadata_t *interface,
        const nf_server_app_metadata_t *app);

extern ogs_sbi_response_t *nf_server_new_response(char *location, char *content_type, time_t last_modified, char *etag,
        int cache_control, char *allow_methods, const nf_server_interface_metadata_t *interface,
        const nf_server_app_metadata_t *app);
extern ogs_sbi_response_t *nf_server_populate_response(ogs_sbi_response_t *response, int content_length, char *content, int status);

#ifdef __cplusplus
}
#endif

#endif
