/*
License: 5G-MAG Public License (v1.0)
Copyright: (C) 2023 British Broadcasting Corporation

For full license terms please see the LICENSE file distributed with this
program. If this file is missing then the license can be retrieved from
https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
*/

#ifndef BSF_CLIENT_H
#define BSF_CLIENT_H

/* Open5GS includes */
#include "ogs-proto.h"
#include "ogs-core.h"
#include "ogs-sbi.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef BUILD_BSF_CLIENT_LIB
    #if defined _WIN32 || defined __CYGWIN__
        #ifdef __GNUC__
            #define BSF_CLIENT_API __attribute__ ((dllexport))
        #else
            #define BSF_CLIENT_API __declspec(dllexport)
        #endif
    #else
        #if __GNUC__ >= 4
            #define BSF_CLIENT_API __attribute__ ((visibility ("default")))
        #else
            #define BSF_CLIENT_API
        #endif
    #endif
#else
    #if defined _WIN32 || defined __CYGWIN__
        #ifdef __GNUC__
            #define BSF_CLIENT_API __attribute__ ((dllimport))
        #else
            #define BSF_CLIENT_API __declspec(dllimport) // Note: actually gcc seems to also supports this syntax.
        #endif
    #else
        #define BSF_CLIENT_API
    #endif
#endif

typedef bool (*bsf_retrieve_callback_f)(OpenAPI_pcf_binding_t *pcf_binding, void *user_data);

BSF_CLIENT_API bool bsf_parse_config(const char *bsf_sect, const char *bsf_client_sect);
BSF_CLIENT_API bool bsf_retrieve_pcf_binding_for_pdu_session(ogs_sockaddr_t *ue_address, bsf_retrieve_callback_f callback, void *user_data);
BSF_CLIENT_API bool bsf_process_event(ogs_event_t *e);
BSF_CLIENT_API void bsf_terminate(void);

#ifdef __cplusplus
}
#endif

/* vim:ts=8:sts=4:sw=4:expandtab:
 */

#endif /* BSF_CLIENT_H */
