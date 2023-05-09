/*
License: 5G-MAG Public License (v1.0)
Copyright: (C) 2022 British Broadcasting Corporation

For full license terms please see the LICENSE file distributed with this
program. If this file is missing then the license can be retrieved from
https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
*/

#include "ogs-sbi.h"
#include "core/abts.h"

#include "test-common.h"

static void bsf_client_init_config_test(abts_case *tc, void *data)
{
    int rv;
    rv = ogs_sbi_context_parse_config(NULL, "nrf", "scp");
    ABTS_INT_EQUAL(tc, OGS_OK, rv);
    rv = bsf_parse_config("bsf");
    ABTS_INT_EQUAL(tc, OGS_OK, rv);
}

abts_suite *test_bsf_init_config(abts_suite *suite)
{
    suite = ADD_SUITE(suite)
    abts_run_test(suite, bsf_client_init_config_test, NULL);
    return suite;
}
