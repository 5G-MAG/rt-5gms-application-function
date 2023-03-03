/*
License: 5G-MAG Public License (v1.0)
Author: Dev Audsin
Copyright: (C) 2022 British Broadcasting Corporation

For full license terms please see the LICENSE file distributed with this
program. If this file is missing then the license can be retrieved from
https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
*/

#ifndef MSAF_HASH_H
#define MSAF_HASH_H

#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include "ogs-app.h"
#include "context.h"

#ifdef __cplusplus
extern "C" {
#endif

extern const char *calculate_hash(const char *buf);

#ifdef __cplusplus
}
#endif

#endif /* MSAF_HASH_H */
