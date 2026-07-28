/*
License: 5G-MAG Public License (v1.0)
Copyright: (C) 2022 British Broadcasting Corporation

For full license terms please see the LICENSE file distributed with this
program. If this file is missing then the license can be retrieved from
https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
*/

#include "test-app.h"
#include "af/init.h"
#include "af/sbi-path.h"

#include "context.h" /* declares extern int __msaf_log_domain; the one real definition is in context.c */

#include "tests.h"

static void terminate(void)
{
    ogs_msleep(50);
    af_terminate();

    msaf_context_final();

    test_child_terminate();
    app_terminate();

    test_5gc_final();
    ogs_app_terminate();
}

static void initialize(const char *const argv[])
{
    int rv;
    rv = ogs_app_initialize(NULL, NULL, argv);
    ogs_assert(rv == OGS_OK);
    test_5gc_init();

    /* Despite the name, af_initialize()/af_terminate() (from "af/init.h") do not initialize
     * this project's 5GMS AF. They resolve to subprojects/open5gs/tests/af/init.c,
     * open5gs's own generic 3GPP-"AF"-role test double built to drive open5gs's PCF
     * (Npcf_PolicyAuthorization) and BSF (Nbsf_Management) test suites as a client peer --
     * it never touches msaf_self(). Without this call, msaf_self()->provisioningSessions_map
     * (and the rest of the real msaf context) stays NULL, and any test that creates a
     * provisioning session (or otherwise touches msaf_self()) segfaults. Initialize the real
     * context directly here instead of relying on af_initialize() for it. */
    msaf_context_init();

    ogs_log_install_domain(&__msaf_log_domain, "test-msaf", ogs_core()->log.level);

    rv = app_initialize(argv);
    ogs_assert(rv == OGS_OK);

    rv = af_initialize();
    ogs_assert(rv == OGS_OK);

    /* ogs_log_set_mask_level(NULL, OGS_LOG_DEBUG); */ /* Uncomment to force DEBUG output in unit test */
}

int main(int argc, const char *const argv[])
{
    int i;
    abts_suite *suite = NULL;

    atexit(terminate);
    test_app_run(argc, argv, "sample.yaml", initialize);

    suite = tests_run(suite);

    return abts_report(suite);
}

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
