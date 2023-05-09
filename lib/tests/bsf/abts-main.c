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

#include "bsf-client.h"

abts_suite *test_bsf_init_config(abts_suite *suite);
abts_suite *test_bsf(abts_suite *suite);

int bsf_test_initialise(void);
void bsf_test_terminate(void);

const struct testlist {
    abts_suite *(*func)(abts_suite *suite);
} alltests[] = {
    {test_bsf_init_config},
    {test_bsf},
    {NULL},
};

static void terminate(void)
{
    ogs_msleep(50);
    bsf_terminate();
    test_child_terminate();
    af_sbi_close();
    bsf_test_terminate();
    app_terminate();
    test_5gc_final();
    ogs_app_terminate();

}

static void initialize(const char *const argv[])
{
    int rv;
    rv = ogs_app_initialize(NULL, NULL, argv);

    //ogs_core()->log.level = OGS_LOG_DEBUG;

    ogs_assert(rv == OGS_OK);
    test_5gc_init();
    rv = app_initialize(argv);
    ogs_assert(rv == OGS_OK);

    rv = bsf_test_initialise();
    ogs_assert(rv == OGS_OK);

    //ogs_log_set_mask_level(NULL, ogs_core()->log.level);

    rv = af_sbi_open();
    ogs_assert(rv == OGS_OK);

    ogs_msleep(100);
}

int main(int argc, const char *const argv[])
{
    int i;
    abts_suite *suite = NULL;

    atexit(terminate);
    test_app_run(argc, argv, "sample.yaml", initialize);

    for (i = 0; alltests[i].func; i++)
        suite = alltests[i].func(suite);

    return abts_report(suite);
}
