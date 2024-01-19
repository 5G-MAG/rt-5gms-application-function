/*
 * License: 5G-MAG Public License (v1.0)
 * Author: Dev Audsin
 * Copyright: (C) 2022-2023 British Broadcasting Corporation
 * 
 * For full license terms please see the LICENSE file distributed with this
 * program. If this file is missing then the license can be retrieved from
 * https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
 */

#ifndef MSAF_UTILITIES_H
#define MSAF_UTILITIES_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <features.h>

#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE
#endif

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "ogs-app.h"
#include "context.h"

#ifdef __cplusplus
extern "C" {
#endif

extern char *read_file(const char *filename);
extern char *get_path(const char *file);
extern char *rebase_path(const char *base, const char *file);
extern long int ascii_to_long(const char *str);
extern uint16_t ascii_to_uint16(const char *str);
extern int str_match(const char *line, const char *word_to_find);
extern const char *get_time(time_t time_epoch);
extern time_t str_to_time(const char *str_time);
extern double str_to_bitrate(const char *ts29571_bitrate, const char **err);

extern char *check_http_content_type(ogs_sbi_http_message_t http, char *content_type);

extern char *traceable_strdup(const char *str, const char *location);

#define msaf_strdup(s) traceable_strdup((s), __location__)

#ifdef __cplusplus
}
#endif

#endif /* MSAF_UTILITIES_H */
