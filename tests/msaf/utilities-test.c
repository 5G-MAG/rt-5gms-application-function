/*
 * License: 5G-MAG Public License (v1.0)
 * Author: David Waring
 * Copyright: (C) 2023 British Broadcasting Corporation
 *
 * For full license terms please see the LICENSE file distributed with this
 * program. If this file is missing then the license can be retrieved from
 * https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
*/

/* System includes */
#include <math.h>

/* Open5GS includes */
#include "test-common.h"

/* MSAF includes */
#include "utilities.h"

/* Test includes */
#include "utilities-test.h"

#define ABTS_PTR_NULL(a, b) ABTS_PTR_EQUAL((a), (b), NULL)
#define ABTS_DOUBLE_NOT_NAN(a, b) do { char *_ab_msg = ogs_msprintf("Double is not NaN failed, saw " #b " is %f", b); ABTS_ASSERT((a), _ab_msg, !isnan(b)); ogs_free(_ab_msg); } while (0)
#define ABTS_DOUBLE_IS_NAN(a, b) do { char *_ab_msg = ogs_msprintf("Double is NaN failed, saw " #b " is %f", b); ABTS_ASSERT((a), _ab_msg, isnan(b)); ogs_free(_ab_msg); } while (0)
#define ABTS_DOUBLE_EQUAL(a, b, c) do { char *_ab_msg = ogs_msprintf("Double values are equal failed, saw " #b " (%f) != " #c " (%f)", (b), (c)); ABTS_ASSERT((a), _ab_msg, (b) == (c)); ogs_free(_ab_msg); } while (0)

#ifdef __cplusplus
extern "C" {
#endif /* ifdef __cplusplus */

/* Test good bps bitrate */
static void test_utilities_str_to_bitrate_bps(abts_case *tc, void *data)
{
    const char *err = NULL;
    double bitrate;

    bitrate = str_to_bitrate("10.0 bps", &err);

    ABTS_PTR_NULL(tc, err);
    ABTS_DOUBLE_NOT_NAN(tc, bitrate);
    ABTS_DOUBLE_EQUAL(tc, bitrate, 10.0);
}

/* Test good Kbps bitrate */
static void test_utilities_str_to_bitrate_Kbps(abts_case *tc, void *data)
{
    const char *err = NULL;
    double bitrate;

    bitrate = str_to_bitrate("10.0 Kbps", &err);

    ABTS_PTR_NULL(tc, err);
    ABTS_DOUBLE_NOT_NAN(tc, bitrate);
    ABTS_DOUBLE_EQUAL(tc, bitrate, 10000.0);
}

/* Test good Mbps bitrate */
static void test_utilities_str_to_bitrate_Mbps(abts_case *tc, void *data)
{
    const char *err = NULL;
    double bitrate;

    bitrate = str_to_bitrate("10.0 Mbps", &err);

    ABTS_PTR_NULL(tc, err);
    ABTS_DOUBLE_NOT_NAN(tc, bitrate);
    ABTS_DOUBLE_EQUAL(tc, bitrate, 10000000.0);
}

/* Test good Gbps bitrate */
static void test_utilities_str_to_bitrate_Gbps(abts_case *tc, void *data)
{
    const char *err = NULL;
    double bitrate;

    bitrate = str_to_bitrate("10.0 Gbps", &err);

    ABTS_PTR_NULL(tc, err);
    ABTS_DOUBLE_NOT_NAN(tc, bitrate);
    ABTS_DOUBLE_EQUAL(tc, bitrate, 10000000000.0);
}

/* Test good Tbps bitrate */
static void test_utilities_str_to_bitrate_Tbps(abts_case *tc, void *data)
{
    const char *err = NULL;
    double bitrate;

    bitrate = str_to_bitrate("10.0 Tbps", &err);

    ABTS_PTR_NULL(tc, err);
    ABTS_DOUBLE_NOT_NAN(tc, bitrate);
    ABTS_DOUBLE_EQUAL(tc, bitrate, 10000000000000.0);
}

/* Test bad bitrate (no units) */
static void test_utilities_str_to_bitrate_no_units(abts_case *tc, void *data)
{
    const char *err = NULL;
    double bitrate;

    bitrate = str_to_bitrate("10.0", &err);

    ABTS_DOUBLE_IS_NAN(tc, bitrate);
    ABTS_PTR_NOTNULL(tc, err);
}

/* Test bad bitrate (unknown units) */
static void test_utilities_str_to_bitrate_bad_units(abts_case *tc, void *data)
{
    const char *err = NULL;
    double bitrate;

    bitrate = str_to_bitrate("10.0 rubbish", &err);

    ABTS_DOUBLE_IS_NAN(tc, bitrate);
    ABTS_PTR_NOTNULL(tc, err);
}

/* Test bad bitrate (no number) */
static void test_utilities_str_to_bitrate_no_number(abts_case *tc, void *data)
{
    const char *err = NULL;
    double bitrate;

    bitrate = str_to_bitrate(" bps", &err);

    ABTS_DOUBLE_IS_NAN(tc, bitrate);
    ABTS_PTR_NOTNULL(tc, err);
}

/* Test good bitrate (int not float) */
static void test_utilities_str_to_bitrate_int_number(abts_case *tc, void *data)
{
    const char *err = NULL;
    double bitrate;

    bitrate = str_to_bitrate("10 bps", &err);

    ABTS_PTR_NULL(tc, err);
    ABTS_DOUBLE_NOT_NAN(tc, bitrate);
    ABTS_DOUBLE_EQUAL(tc, bitrate, 10.0);
}

/* Test bad bitrate (bad number format) */
static void test_utilities_str_to_bitrate_bad_number(abts_case *tc, void *data)
{
    const char *err = NULL;
    double bitrate;

    bitrate = str_to_bitrate("garbage bps", &err);

    ABTS_DOUBLE_IS_NAN(tc, bitrate);
    ABTS_PTR_NOTNULL(tc, err);
}

static struct {
    void (*func)(abts_case *tc, void *data);
} test_cases[] = {
    /* str_to_bitrate() tests */
    {test_utilities_str_to_bitrate_bps},
    {test_utilities_str_to_bitrate_Kbps},
    {test_utilities_str_to_bitrate_Mbps},
    {test_utilities_str_to_bitrate_Gbps},
    {test_utilities_str_to_bitrate_Tbps},
    {test_utilities_str_to_bitrate_no_units},
    {test_utilities_str_to_bitrate_bad_units},
    {test_utilities_str_to_bitrate_no_number},
    {test_utilities_str_to_bitrate_int_number},
    {test_utilities_str_to_bitrate_bad_number}
};

abts_suite *test_utilities(abts_suite *suite)
{
    int i;
    msaf_sai_cache_t *cache = NULL;

    suite = ADD_SUITE(suite)

    for (i=0; i<(sizeof(test_cases)/sizeof(test_cases[0])); i++) {
        abts_run_test(suite, test_cases[i].func, &cache);
    }

    return suite;
}

#ifdef __cplusplus
}
#endif /* ifdef __cplusplus */

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
