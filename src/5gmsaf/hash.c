/*
License: 5G-MAG Public License (v1.0)
Author: Dev Audsin
Copyright: (C) 2022 British Broadcasting Corporation

For full license terms please see the LICENSE file distributed with this
program. If this file is missing then the license can be retrieved from
https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
*/

#include "hash.h"

const char *calculate_hash(const char *buf) {
    unsigned char *result = NULL;
    size_t result_len;
    gnutls_datum_t data;
    static char hash[1024];
    size_t i;

    result_len = gnutls_hash_get_len(GNUTLS_DIG_SHA256);
    data.data = (unsigned char *)buf;
    data.size = strlen(buf);
    result = ogs_calloc(1, result_len);
    gnutls_fingerprint(GNUTLS_DIG_SHA256, &data, result, &result_len);
    for (i = 0; i < result_len; i++)
    {
        sprintf(&(hash[i*2]), "%02x", result[i]);
    }
    hash[sizeof (hash) - 1] = '\0';
    ogs_free(result);
    return hash;
}
