/*
License: 5G-MAG Public License (v1.0)
Author: Dev Audsin
Copyright: (C) 2022 British Broadcasting Corporation

For full license terms please see the LICENSE file distributed with this
program. If this file is missing then the license can be retrieved from
https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
*/

#ifndef MSAF_UTILITIES_H
#define MSAF_UTILITIES_H

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include "ogs-app.h"

#ifdef __cplusplus
extern "C" {
#endif

extern char *read_file(const char *filename);
extern char *get_path(const char *file);
extern char *rebase_path(const char *base, const char *file);
extern long int ascii_to_long(const char *str);

#ifdef __cplusplus
}
#endif

#endif /* MSAF_UTILITIES_H */
