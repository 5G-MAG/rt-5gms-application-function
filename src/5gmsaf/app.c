/*
 * License: 5G-MAG Public License (v1.0)
 * Author: Dev Audsin <dev.audsin@bbc.co.uk>
 * Copyright: (C) 2022 British Broadcasting Corporation
 *
 * For full license terms please see the LICENSE file distributed with this
 * program. If this file is missing then the license can be retrieved from
 * https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
 */

#include "ogs-app.h"

#include "init.h"

int app_initialize(const char *const argv[])
{
    int rv;

    rv = msaf_initialize();
    if (rv != OGS_OK) {
        ogs_warn("Failed to intialize 5GMSAF");
        return rv;
    }
    ogs_info("5GMSAF initialize...done");

    return OGS_OK;
}

void app_terminate(void)
{
    msaf_terminate();
    ogs_info("5GMSAF terminate...done");
}

