/*
 * License: 5G-MAG Public License (v1.0)
 * Copyright: (C) 2023 British Broadcasting Corporation
 *            (C) 2019-2023 by Sukchan Lee <acetcom@gmail.com>
 *
 * For full license terms please see the LICENSE file distributed with this
 * program. If this file is missing then the license can be retrieved from
 * https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
*/

#include "af/context.h"
#include "bsf-test-context.h"

#ifdef __cplusplus
extern "C" {
#endif

static bsf_test_context_t self;

int __bsf_test_log_domain;

static OGS_POOL(bsf_test_sess_pool, bsf_test_sess_t);

static int context_initialized = 0;

static void clear_pcf_app_session_id(bsf_test_sess_t *sess);

void bsf_test_context_init(void)
{
    ogs_assert(context_initialized == 0);

    /* Initialize AF context */
    memset(&self, 0, sizeof(bsf_test_context_t));

    ogs_log_install_domain(&__bsf_test_log_domain, "bsf-test", ogs_core()->log.level);
    af_context_init();
    //ogs_log_install_domain(&__af_log_domain, "af", ogs_core()->log.level);
    
    ogs_pool_init(&bsf_test_sess_pool, ogs_app()->pool.sess);

    self.supi_hash = ogs_hash_make();
    ogs_assert(self.supi_hash);
    self.ipv4_hash = ogs_hash_make();
    ogs_assert(self.ipv4_hash);
    self.ipv6_hash = ogs_hash_make();
    ogs_assert(self.ipv6_hash);
    self.pcf_app_session_id_hash = ogs_hash_make();
    ogs_assert(self.pcf_app_session_id_hash);

    context_initialized = 1;
}

void bsf_test_context_final(void)
{
    ogs_assert(context_initialized == 1);

    bsf_test_sess_remove_all();

    ogs_assert(self.supi_hash);
    ogs_hash_destroy(self.supi_hash);
    ogs_assert(self.ipv4_hash);
    ogs_hash_destroy(self.ipv4_hash);
    ogs_assert(self.ipv6_hash);
    ogs_hash_destroy(self.ipv6_hash);
    ogs_assert(self.pcf_app_session_id_hash);
    ogs_hash_destroy(self.pcf_app_session_id_hash);

    ogs_pool_final(&bsf_test_sess_pool);

    af_context_final();

    context_initialized = 0;
}

bsf_test_context_t *bsf_test_self(void)
{
    return &self;
}

int bsf_test_context_parse_config(void)
{
    int rv;
    yaml_document_t *document = NULL;
    ogs_yaml_iter_t root_iter;

    document = ogs_app()->document;
    ogs_assert(document);

    /*rv = af_context_prepare();
    if (rv != OGS_OK) return rv;*/

    ogs_yaml_iter_init(&root_iter, document);
    while (ogs_yaml_iter_next(&root_iter)) {
        const char *root_key = ogs_yaml_iter_key(&root_iter);
        ogs_assert(root_key);
        if (!strcmp(root_key, "af")) {
            ogs_yaml_iter_t af_iter;
            ogs_yaml_iter_recurse(&root_iter, &af_iter);
            while (ogs_yaml_iter_next(&af_iter)) {
                const char *af_key = ogs_yaml_iter_key(&af_iter);
                ogs_assert(af_key);
                if (!strcmp(af_key, "sbi")) {
                    /* handle config in sbi library */
                } else if (!strcmp(af_key, "service_name")) {
                    /* handle config in sbi library */
                } else if (!strcmp(af_key, "discovery")) {
                    /* handle config in sbi library */
                } else
                    ogs_warn("unknown key `%s`", af_key);
            }
        }
    }

    /*rv = af_context_validation();
    if (rv != OGS_OK) return rv;*/

    return OGS_OK;
}

bsf_test_sess_t *bsf_test_sess_add_by_ue_address(ogs_ip_t *ue_address)
{
    bsf_test_sess_t *sess = NULL;

    ogs_assert(ue_address);
    ogs_assert(ue_address->ipv4 || ue_address->ipv6);

    ogs_pool_alloc(&bsf_test_sess_pool, &sess);
    ogs_assert(sess);
    memset(sess, 0, sizeof *sess);

    sess->af_app_session_id = ogs_msprintf("%d",
            (int)ogs_pool_index(&bsf_test_sess_pool, sess));
    ogs_assert(sess->af_app_session_id);

    if (ue_address->ipv4) {
        sess->ipv4addr = ogs_ipv4_to_string(ue_address->addr);
        ogs_assert(sess->ipv4addr);
    }

    if (ue_address->ipv6) {
        sess->ipv6addr = ogs_ipv6addr_to_string(ue_address->addr6);
        ogs_assert(sess->ipv6addr);
        sess->ipv6prefix = ogs_ipv6prefix_to_string(
                ue_address->addr6, OGS_IPV6_128_PREFIX_LEN);
        ogs_assert(sess->ipv6prefix);
    }

    OGS_SBI_FEATURES_SET(sess->policyauthorization_features,
            OGS_SBI_NPCF_POLICYAUTHORIZATION_SPONSORED_CONNECTIVITY);
    OGS_SBI_FEATURES_SET(sess->policyauthorization_features,
            OGS_SBI_NPCF_POLICYAUTHORIZATION_IMS_SBI);

    ogs_list_add(&self.sess_list, sess);

    return sess;
}

void bsf_test_sess_remove(bsf_test_sess_t *sess)
{
    int i;

    ogs_assert(sess);

    ogs_list_remove(&self.sess_list, sess);

    /* Free SBI object memory */
    ogs_sbi_object_free(&sess->sbi);

    if (sess->af_app_session_id)
        ogs_free(sess->af_app_session_id);

    clear_pcf_app_session_id(sess);

    if (sess->ipv4addr)
        ogs_free(sess->ipv4addr);
    if (sess->ipv6addr)
        ogs_free(sess->ipv6addr);
    if (sess->ipv6prefix)
        ogs_free(sess->ipv6prefix);

    if (sess->supi)
        ogs_free(sess->supi);
    if (sess->gpsi)
        ogs_free(sess->gpsi);

    if (sess->dnn)
        ogs_free(sess->dnn);

    if (sess->pcf.fqdn)
        ogs_free(sess->pcf.fqdn);

    for (i = 0; i < sess->pcf.num_of_ip; i++) {
        if (sess->pcf.ip[i].addr)
            ogs_freeaddrinfo(sess->pcf.ip[i].addr);
        if (sess->pcf.ip[i].addr6)
            ogs_freeaddrinfo(sess->pcf.ip[i].addr6);
    }
    sess->pcf.num_of_ip = 0;

    if (sess->pcf.client)
        ogs_sbi_client_remove(sess->pcf.client);

    ogs_pool_free(&bsf_test_sess_pool, sess);
}

void bsf_test_sess_remove_all(void)
{
    bsf_test_sess_t *sess = NULL, *next_sess = NULL;

    ogs_list_for_each_safe(&self.sess_list, next_sess, sess)
        bsf_test_sess_remove(sess);
}

static void clear_pcf_app_session_id(bsf_test_sess_t *sess)
{
    ogs_assert(sess);

    if (sess->pcf_app_session_id) {
        ogs_hash_set(self.pcf_app_session_id_hash,
            &sess->pcf_app_session_id, sizeof(sess->pcf_app_session_id), NULL);
        ogs_free(sess->pcf_app_session_id);
    }
}

bool bsf_test_sess_set_pcf_app_session_id(bsf_test_sess_t *sess, char *pcf_app_session_id)
{
    ogs_assert(sess);
    ogs_assert(pcf_app_session_id);

    clear_pcf_app_session_id(sess);

    sess->pcf_app_session_id = ogs_strdup(pcf_app_session_id);
    ogs_assert(sess->pcf_app_session_id);

    ogs_hash_set(self.pcf_app_session_id_hash,
            &sess->pcf_app_session_id, strlen(sess->pcf_app_session_id), sess);

    return true;
}

bsf_test_sess_t *bsf_test_sess_find(uint32_t index)
{
    return ogs_pool_find(&bsf_test_sess_pool, index);
}

bsf_test_sess_t *bsf_test_sess_find_by_af_app_session_id(char *af_app_session_id)
{
    ogs_assert(af_app_session_id);
    return bsf_test_sess_find(atoll(af_app_session_id));
}

bsf_test_sess_t *bsf_test_sess_find_by_pcf_app_session_id(char *pcf_app_session_id)
{
    ogs_assert(pcf_app_session_id);
    return (bsf_test_sess_t *)ogs_hash_get(self.pcf_app_session_id_hash,
                        pcf_app_session_id, strlen(pcf_app_session_id));
}

static ogs_sbi_client_t *find_client_by_fqdn(
        OpenAPI_uri_scheme_e scheme, char *fqdn)
{
    int rv;
    ogs_sockaddr_t *addr = NULL;
    ogs_sbi_client_t *client = NULL;

    ogs_assert(scheme == OpenAPI_uri_scheme_https ||
                scheme == OpenAPI_uri_scheme_http);
    ogs_assert(fqdn);

    rv = ogs_getaddrinfo(
            &addr, AF_UNSPEC, fqdn,
            scheme == OpenAPI_uri_scheme_https ?
                OGS_SBI_HTTPS_PORT : OGS_SBI_HTTP_PORT,
            0);
    if (rv != OGS_OK) {
        ogs_error("Invalid NFProfile.fqdn");
        return NULL;
    }

    client = ogs_sbi_client_find(scheme, addr);
    if (!client) {
        client = ogs_sbi_client_add(scheme, addr);
        ogs_assert(client);
    }

    ogs_freeaddrinfo(addr);

    return client;
}

void bsf_test_sess_associate_pcf_client(bsf_test_sess_t *sess)
{
    ogs_sbi_client_t *client = NULL;
    ogs_sockaddr_t *addr = NULL;
    OpenAPI_uri_scheme_e scheme = OpenAPI_uri_scheme_NULL;

    ogs_assert(sess);

    scheme = ogs_app()->sbi.client.no_tls == false ?
                OpenAPI_uri_scheme_https : OpenAPI_uri_scheme_http;

    if (sess->pcf.fqdn && strlen(sess->pcf.fqdn))
        client = find_client_by_fqdn(scheme, sess->pcf.fqdn);

    if (!client) {
        /* At this point, CLIENT selection method is very simple. */
        if (sess->pcf.num_of_ip) {
            addr = sess->pcf.ip[0].addr6;
            if (!addr)
                addr = sess->pcf.ip[0].addr;
        }

        if (addr) {
            client = ogs_sbi_client_find(scheme, addr);
            if (!client) {
                client = ogs_sbi_client_add(scheme, addr);
                ogs_assert(client);
            }
        }
    }

    if (client)
        OGS_SBI_SETUP_CLIENT(&sess->pcf, client);
}

#ifdef __cplusplus
}
#endif

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
