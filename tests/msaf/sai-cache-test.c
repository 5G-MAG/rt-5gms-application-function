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
#include "sai-cache.h"
#include "openapi/model/msaf_api_service_access_information_resource.h"

/* Test includes */
#include "sai-cache-test.h"

#define ABTS_PTR_NULL(a, b) ABTS_PTR_EQUAL(a, b, NULL)

#ifdef __cplusplus
extern "C" {
#endif /* ifdef __cplusplus */

/* Create and tidy up a cache */
static void test_sai_cache_create(abts_case *tc, void *data)
{
    msaf_sai_cache_t *cache;

    cache = msaf_sai_cache_new();
    ABTS_PTR_NOTNULL(tc, cache);

    *((msaf_sai_cache_t**)data) = cache;
}

static void test_sai_cache_add(abts_case *tc, void *data)
{
    msaf_api_service_access_information_resource_t *sai;
    msaf_api_service_access_information_resource_streaming_access_t *streams = NULL;
    msaf_api_service_access_information_resource_network_assistance_configuration_t *nac = NULL;
    OpenAPI_list_t *entry_points;
    OpenAPI_list_t *dash_profiles;
    OpenAPI_list_t *nac_addresses;
    msaf_sai_cache_t *cache = *((msaf_sai_cache_t**)data);
    ABTS_PTR_NOTNULL(tc, cache);

    dash_profiles = OpenAPI_list_create();
    ABTS_PTR_NOTNULL(tc, dash_profiles);
    OpenAPI_list_add(dash_profiles, ogs_strdup("urn:mpeg:dash:profile:isoff-live:2011"));

    entry_points = OpenAPI_list_create();
    ABTS_PTR_NOTNULL(tc, entry_points);
    OpenAPI_list_add(entry_points, msaf_api_m5_media_entry_point_create(ogs_strdup("http://as.exmaple.com/m4d/manifest.mpd"), ogs_strdup("application/dash+xml"), dash_profiles));
    OpenAPI_list_add(entry_points, msaf_api_m5_media_entry_point_create(ogs_strdup("http://as.exmaple.com/m4d/manifest.m3u8"), ogs_strdup("application/vnd.apple.mpegurl"), NULL));

    streams = msaf_api_service_access_information_resource_streaming_access_create(entry_points, NULL);
    ABTS_PTR_NOTNULL(tc, streams);

    nac_addresses = OpenAPI_list_create();
    ABTS_PTR_NOTNULL(tc, nac_addresses);
    OpenAPI_list_add(nac_addresses, ogs_strdup("http://af.example.com:9876/3gpp-m5/v2/"));

    nac = msaf_api_service_access_information_resource_network_assistance_configuration_create(nac_addresses);
    ABTS_PTR_NOTNULL(tc, nac);

    sai = msaf_api_service_access_information_resource_create(ogs_strdup("Provisioning-Session-Id"), msaf_api_provisioning_session_type_DOWNLINK, streams, NULL, NULL, NULL, nac, NULL);
    ABTS_PTR_NOTNULL(tc, sai);

    ABTS_TRUE(tc, msaf_sai_cache_add(cache, true, "af.example.com:443", sai));

    msaf_api_service_access_information_resource_free(sai);
}

static void test_sai_cache_find_exists(abts_case *tc, void *data)
{
    const msaf_sai_cache_entry_t *entry;
    msaf_sai_cache_t *cache = *((msaf_sai_cache_t**)data);
    ABTS_PTR_NOTNULL(tc, cache);

    entry = msaf_sai_cache_find(cache, true, "af.example.com:443");
    ABTS_PTR_NOTNULL(tc, entry);
}

static void test_sai_cache_find_not_exists1(abts_case *tc, void *data)
{
    /* wrong TLS flag */
    const msaf_sai_cache_entry_t *entry;
    msaf_sai_cache_t *cache = *((msaf_sai_cache_t**)data);
    ABTS_PTR_NOTNULL(tc, cache);

    entry = msaf_sai_cache_find(cache, false, "af.example.com:443");
    ABTS_PTR_NULL(tc, entry);
}

static void test_sai_cache_find_not_exists2(abts_case *tc, void *data)
{
    /* wrong authority */
    const msaf_sai_cache_entry_t *entry;
    msaf_sai_cache_t *cache = *((msaf_sai_cache_t**)data);
    ABTS_PTR_NOTNULL(tc, cache);

    entry = msaf_sai_cache_find(cache, true, "not-af.example.com:443");
    ABTS_PTR_NULL(tc, entry);
}

static void test_sai_cache_clear(abts_case *tc, void *data)
{
    msaf_sai_cache_t *cache = *((msaf_sai_cache_t**)data);
    ABTS_PTR_NOTNULL(tc, cache);

    msaf_sai_cache_clear(cache);
}

static void test_sai_cache_find_removed(abts_case *tc, void *data)
{
    const msaf_sai_cache_entry_t *entry;
    msaf_sai_cache_t *cache = *((msaf_sai_cache_t**)data);
    ABTS_PTR_NOTNULL(tc, cache);

    entry = msaf_sai_cache_find(cache, true, "af.example.com:443");
    ABTS_PTR_NULL(tc, entry);
}

static void test_sai_cache_free(abts_case *tc, void *data)
{   
    msaf_sai_cache_t *cache = *((msaf_sai_cache_t**)data);

    ABTS_PTR_NOTNULL(tc, cache);

    msaf_sai_cache_free(cache);
}

static struct {
    void (*func)(abts_case *tc, void *data);
} test_cases[] = {
    {test_sai_cache_create},
    {test_sai_cache_add},
    {test_sai_cache_find_exists},
    {test_sai_cache_find_not_exists1},
    {test_sai_cache_find_not_exists2},
    {test_sai_cache_clear},
    {test_sai_cache_find_removed},
    {test_sai_cache_free}
};

abts_suite *test_sai_cache(abts_suite *suite)
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
