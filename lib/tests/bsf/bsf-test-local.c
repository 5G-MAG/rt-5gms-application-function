/*
 * License: 5G-MAG Public License (v1.0)
 * Copyright: (C) 2023 British Broadcasting Corporation
 *
 * For full license terms please see the LICENSE file distributed with this
 * program. If this file is missing then the license can be retrieved from
 * https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
*/

#include "bsf-test-local.h"

#ifdef __cplusplus
extern "C" {
#endif

const char *bsf_test_local_get_name(bsf_test_local_e typ)
{
    switch (typ) {
    case BSF_TEST_LOCAL_DISCOVER_AND_SEND:
        return "BSF_TEST_LOCAL_DISCOVER_AND_SEND";
    case BSF_TEST_LOCAL_SEND_TO_PCF:
        return "BSF_TEST_LOCAL_SEND_TO_PCF";
    default:
        break;
    }

    return "BSF_TEST_LOCAL_UNKNOWN_EVENT";
}

#ifdef __cplusplus
}
#endif

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
