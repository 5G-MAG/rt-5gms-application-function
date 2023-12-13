/*
License: 5G-MAG Public License (v1.0)
Author: Dev Audsin
Copyright: (C) 2023 British Broadcasting Corporation

For full license terms please see the LICENSE file distributed with this
program. If this file is missing then the license can be retrieved from
https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
*/

#include "context.h"
#include "pcf-session.h"

static void msaf_pcf_session_remove(msaf_pcf_session_t *pcf_sess);

pcf_session_t *msaf_pcf_session_new(const ogs_sockaddr_t *pcf_address)
{
    msaf_pcf_session_t *msaf_pcf_session;	
    msaf_pcf_session = ogs_calloc(1, sizeof(msaf_pcf_session_t));
    msaf_pcf_session->pcf_session = pcf_session_new(pcf_address);
    ogs_list_add(&msaf_self()->pcf_sessions, msaf_pcf_session);
    return msaf_pcf_session->pcf_session;
}

void msaf_pcf_session_remove_all()
{
    msaf_pcf_session_t *msaf_pcf_session = NULL, *next = NULL;

    ogs_list_for_each_safe(&msaf_self()->pcf_sessions, next, msaf_pcf_session){
	ogs_list_remove(&msaf_self()->pcf_sessions, msaf_pcf_session);    
        msaf_pcf_session_remove(msaf_pcf_session);
    }
}


static void msaf_pcf_session_remove(msaf_pcf_session_t *msaf_pcf_session) {
    ogs_assert(msaf_pcf_session);
    if (msaf_pcf_session->pcf_session) pcf_session_free(msaf_pcf_session->pcf_session);
    ogs_free(msaf_pcf_session);

}


/* vim:ts=8:sts=4:sw=4:expandtab:
 */
