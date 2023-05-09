/*
License: 5G-MAG Public License (v1.0)
Copyright: (C) 2023 British Broadcasting Corporation

For full license terms please see the LICENSE file distributed with this
program. If this file is missing then the license can be retrieved from
https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
*/

#ifndef BSF_PCF_BIND_H
#define BSF_PCF_BIND_H

#include "bsf-client.h"

#ifdef __cplusplus
extern "C" {
#endif

bool _bsf_retrieve_pcf_binding_for_pdu_session(ogs_sockaddr_t *ue_address, bsf_retrieve_callback_f callback, void *user_data);

#ifdef __cplusplus
}
#endif

/* vim:ts=8:sts=4:sw=4:expandtab:
 */

#endif /* BSF_PCF_BIND_H */
