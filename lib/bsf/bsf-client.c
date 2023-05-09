/*
License: 5G-MAG Public License (v1.0)
Copyright: (C) 2023 British Broadcasting Corporation

For full license terms please see the LICENSE file distributed with this
program. If this file is missing then the license can be retrieved from
https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
*/

/* Open5GS includes */
#include "ogs-proto.h"
#include "ogs-core.h"
#include "sbi/openapi/model/pcf_binding.h"

/* Local includes */
#include "nbsf-process.h"
#include "context.h"
#include "pcf-bind.h"

#include "bsf-client.h"

#ifdef __cplusplus
extern "C" {
#endif

BSF_CLIENT_API bool bsf_parse_config(const char *bsf_sect, const char *bsf_client_sect)
{
    /*return _bsf_parse_config(bsf_sect, bsf_client_sect);*/
    return _bsf_parse_config(bsf_sect);
}

BSF_CLIENT_API bool bsf_retrieve_pcf_binding_for_pdu_session(ogs_sockaddr_t *ue_address, bsf_retrieve_callback_f callback, void *user_data)
{
    return _bsf_retrieve_pcf_binding_for_pdu_session(ue_address, callback, user_data);
}

BSF_CLIENT_API bool bsf_process_event(ogs_event_t *e)
{
    return _bsf_process_event(e);
}

BSF_CLIENT_API void bsf_terminate(void)
{
    _bsf_client_context_final();
}

#ifdef __cplusplus
}
#endif

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
