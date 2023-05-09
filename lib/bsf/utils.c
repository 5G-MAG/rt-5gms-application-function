/*
 * License: 5G-MAG Public License (v1.0)
 * Copyright: (C) 2022 British Broadcasting Corporation
 *
 * For full license terms please see the LICENSE file distributed with this
 * program. If this file is missing then the license can be retrieved from
 * https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
 */

#include "ogs-core.h"
#include "ogs-sbi.h"

#include "utils.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Library Internals */
char *_sockaddr_string(const ogs_sockaddr_t *addr)
{
    return ogs_ipstrdup((ogs_sockaddr_t*)addr); /* safe to remove const as OGS routines just use it read-only */
}

char *_time_string(ogs_time_t t)
{
    char timestamp[32];
    struct tm ts_tm;

    ogs_gmtime(t, &ts_tm);
    ogs_strftime(timestamp, sizeof(timestamp), "%c", &ts_tm);

    return ogs_strdup(timestamp);
}

ogs_time_t _response_to_expiry_time(ogs_sbi_response_t *response)
{
    ogs_hash_index_t *hi;
    ogs_time_t base_time;
    ogs_time_t max_age = 5; /* default 5 seconds from now */
    ogs_time_t current_age = 0;

    base_time = ogs_time_now();

    for (hi = ogs_hash_first(response->http.headers); hi; hi = ogs_hash_next(hi)) {
        if (!ogs_strcasecmp(ogs_hash_this_key(hi), "Age")) {
            /* remember the age in seconds of the response object */
            current_age = atoi(ogs_hash_this_val(hi));
        } else if (!ogs_strcasecmp(ogs_hash_this_key(hi), "Cache-Control")) {
            /* parse Cache-Control header for cache rules */
            const char *cache_control = ogs_hash_this_val(hi);
            max_age = _cache_control_to_cache_age(cache_control);
        } else if (!ogs_strcasecmp(ogs_hash_this_key(hi), "Date")) {
            /* Use server date-time as base for expiry time */
            struct tm tm;
            ogs_strptime(ogs_hash_this_val(hi), "%a, %d %b %Y %H:%M:%S GMT", &tm);
            ogs_time_from_gmt(&base_time, &tm, 0);
        }
    }

    max_age -= current_age;
    if (max_age < 0) max_age = 0;
    return base_time + max_age;
}

ogs_time_t _cache_control_to_cache_age(const char *cache_control)
{
    char *saveptr = NULL;
    char *value;
    char *ptr;
    ogs_time_t ret = 0;

    value = ogs_strdup(cache_control);
    for (ptr = ogs_strtok_r(value, ",", &saveptr); ptr; ptr = ogs_strtok_r(NULL, ",", &saveptr)) {
        char *op;
        op = ogs_trimwhitespace(ptr);
        if (!ogs_strcasecmp(op, "no-cache") || !ogs_strcasecmp(op, "no-store")) {
            ret = 0;
            break;
        } else if (!ogs_strncasecmp(op, "max-age=", 8)) {
            ret = atoi(op+8);
        }
    }
    ogs_free(value);
    return ret;
}

#ifdef __cplusplus
}
#endif

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
