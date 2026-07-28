/*
 * License: 5G-MAG Public License (v1.0)
 * Author: Nils Duval <nils.duval@motionspell.com>
 * Copyright: (C) 2026 Motion Spell
 *
 * For full license terms please see the LICENSE file distributed with this
 * program. If this file is missing then the license can be retrieved from
 * https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
*/

/* Open5GS includes */
#include "test-common.h"

/* MSAF includes */
#include "rtc-configuration.h"
#include "provisioning-session.h"
#include "openapi/model/msaf_api_rtc_configuration.h"

/* Test includes */
#include "rtc-configuration-test.h"

#define ABTS_PTR_NULL(a, b) ABTS_PTR_EQUAL(a, b, NULL)

#ifdef __cplusplus
extern "C" {
#endif /* ifdef __cplusplus */

static msaf_api_rtc_configuration_t *test_rtc_config_new(bool enable_stun)
{
    return msaf_api_rtc_configuration_create(
                NULL /* edge_resources_configuration */,
                true, enable_stun?1:0,
                NULL /* stun_endpoints */,
                false, 0,
                NULL /* turn_endpoints */,
                false, 0,
                NULL /* swap_endpoints */);
}

static void test_rtc_configuration_register_and_retrieve(abts_case *tc, void *data)
{
    msaf_provisioning_session_t *session;
    msaf_api_rtc_configuration_t *config;
    char *body;

    session = msaf_provisioning_session_create("RTC", NULL, "test-app-id", NULL, false);
    ABTS_PTR_NOTNULL(tc, session);

    config = test_rtc_config_new(true);
    ABTS_PTR_NOTNULL(tc, config);

    ABTS_TRUE(tc, msaf_rtc_configuration_register(session, config));

    body = msaf_rtc_configuration_body(session);
    ABTS_PTR_NOTNULL(tc, body);
    ogs_free(body);

    ABTS_PTR_NOTNULL(tc, msaf_rtc_configuration_etag(session));
    ABTS_TRUE(tc, msaf_rtc_configuration_last_modified(session) != 0);

    /* A second registration attempt must fail -- RTCConfiguration is a singleton per provisioning session */
    {
        msaf_api_rtc_configuration_t *second_config = test_rtc_config_new(false);
        ABTS_TRUE(tc, !msaf_rtc_configuration_register(session, second_config));
        msaf_api_rtc_configuration_free(second_config);
    }

    msaf_provisioning_session_hash_remove(session->provisioningSessionId);
    msaf_provisioning_session_free(session);
}

static void test_rtc_configuration_update_replaces_existing(abts_case *tc, void *data)
{
    msaf_provisioning_session_t *session;
    msaf_api_rtc_configuration_t *config;
    msaf_api_rtc_configuration_t *replacement;
    char *first_etag;

    session = msaf_provisioning_session_create("RTC", NULL, "test-app-id", "external-svc-id", true);
    ABTS_PTR_NOTNULL(tc, session);
    ABTS_STR_EQUAL(tc, "external-svc-id", session->externalServiceId);
    ABTS_TRUE(tc, session->locationReporting);

    config = test_rtc_config_new(true);
    ABTS_TRUE(tc, msaf_rtc_configuration_register(session, config));

    first_etag = ogs_strdup(msaf_rtc_configuration_etag(session));

    replacement = test_rtc_config_new(false);
    ABTS_TRUE(tc, msaf_rtc_configuration_update(session, replacement));

    /* the config content differs (stun enabled vs disabled) so the recalculated hash/etag must differ too */
    ABTS_TRUE(tc, strcmp(first_etag, msaf_rtc_configuration_etag(session)) != 0);

    ogs_free(first_etag);
    msaf_provisioning_session_hash_remove(session->provisioningSessionId);
    msaf_provisioning_session_free(session);
}

static void test_rtc_configuration_deregister(abts_case *tc, void *data)
{
    msaf_provisioning_session_t *session;
    msaf_api_rtc_configuration_t *config;

    session = msaf_provisioning_session_create("RTC", NULL, "test-app-id", NULL, false);
    ABTS_PTR_NOTNULL(tc, session);

    config = test_rtc_config_new(true);
    ABTS_TRUE(tc, msaf_rtc_configuration_register(session, config));

    ABTS_TRUE(tc, msaf_rtc_configuration_deregister(session));
    ABTS_PTR_NULL(tc, msaf_rtc_configuration_body(session));

    /* nothing left to deregister */
    ABTS_TRUE(tc, !msaf_rtc_configuration_deregister(session));

    msaf_provisioning_session_hash_remove(session->provisioningSessionId);
    msaf_provisioning_session_free(session);
}

static struct {
    void (*func)(abts_case *tc, void *data);
} test_cases[] = {
    {test_rtc_configuration_register_and_retrieve},
    {test_rtc_configuration_update_replaces_existing},
    {test_rtc_configuration_deregister}
};

abts_suite *test_rtc_configuration(abts_suite *suite)
{
    int i;

    /* msaf_provisioning_session_create() needs the global msaf context (msaf_self()) to be
     * initialized -- see abts-main.c's initialize(), which calls msaf_context_init() for
     * exactly this reason. */
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
