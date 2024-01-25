/*
 * License: 5G-MAG Public License (v1.0)
 * Author: David Waring
 * Copyright: (C) 2023 British Broadcasting Corporation
 *
 * For full license terms please see the LICENSE file distributed with this
 * program. If this file is missing then the license can be retrieved from
 * https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
*/

/* Open5GS includes */
#include "test-common.h"

/* MSAF includes */
#include "pcf-cache.h"

/* Test includes */
#include "pcf-cache-test.h"

#ifdef __cplusplus
extern "C" {
#endif /* ifdef __cplusplus */

/* Create and tidy up a cache */
static void test_pcf_cache_1(abts_case *tc, void *data)
{
    msaf_pcf_cache_t *cache;

    cache = msaf_pcf_cache_new();
    ABTS_PTR_NOTNULL(tc, cache);

    msaf_pcf_cache_free(cache);
}

/* Populate a cache and find entry before and after expiry */
static void test_pcf_cache_2(abts_case *tc, void *data)
{
    msaf_pcf_cache_t *cache;

    cache = msaf_pcf_cache_new();
    ABTS_PTR_NOTNULL(tc, cache);

    /* add cache entry with 2s expiry */

    /* find cache entry */

    /* wait for expiry and find again */

    msaf_pcf_cache_free(cache);
}

/* Find unknown key in populated cache */
static void test_pcf_cache_3(abts_case *tc, void *data)
{
    msaf_pcf_cache_t *cache;

    cache = msaf_pcf_cache_new();
    ABTS_PTR_NOTNULL(tc, cache);

    /* add cache entry with 20s expiry */

    /* find unregistered key cache entry is NULL */

    msaf_pcf_cache_free(cache);
}

static struct {
    void (*func)(abts_case *tc, void *data);
} test_cases[] = {
    {test_pcf_cache_1},
    {test_pcf_cache_2},
    {test_pcf_cache_3}
};

abts_suite *test_pcf_cache(abts_suite *suite)
{
    int i;

    suite = ADD_SUITE(suite)

    for (i=0; i<(sizeof(test_cases)/sizeof(test_cases[0])); i++) {
        abts_run_test(suite, test_cases[i].func, NULL);
    }

    return suite;
}

#ifdef __cplusplus
}
#endif /* ifdef __cplusplus */

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
