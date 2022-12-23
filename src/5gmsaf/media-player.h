/*
License: 5G-MAG Public License (v1.0)
Author: Dev Audsin
Copyright: (C) 2022 British Broadcasting Corporation

For full license terms please see the LICENSE file distributed with this
program. If this file is missing then the license can be retrieved from
https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
*/

#ifndef MSAF_MEDIA_PLAYER_H
#define MSAF_MEDIA_PLAYER_H

#include "provisioning-session.h"


#ifdef __cplusplus
extern "C" {
#endif

extern char *media_player_entry_create(const char *session_id, OpenAPI_content_hosting_configuration_t *chc);

#ifdef __cplusplus
}
#endif

#endif /* MSAF_MEDIA_PLAYER_H */