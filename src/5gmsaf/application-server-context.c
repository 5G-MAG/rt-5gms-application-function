/*
License: 5G-MAG Public License (v1.0)
Author: Dev Audsin
Copyright: (C) 2022 British Broadcasting Corporation

For full license terms please see the LICENSE file distributed with this
program. If this file is missing then the license can be retrieved from
https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
*/

#include "ogs-core.h"
#include "ogs-sbi.h"

#include "certmgr.h"
#include "context.h"
#include "provisioning-session.h"
#include "utilities.h"

#include "openapi/model/msaf_api_content_hosting_configuration.h"

#include "application-server-context.h"

typedef struct client_request_info {
    msaf_application_server_state_node_t *as_state;
    purge_resource_id_node_t *purge_node;

} client_request_info_t;


static void application_server_state_init(msaf_application_server_node_t *msaf_as);
static ogs_sbi_client_t *msaf_m3_client_init(const char *hostname, int port);
static int
m3_client_as_state_requests(msaf_application_server_state_node_t *as_state, purge_resource_id_node_t *purge_node,const char *type, const char *data, const char *method, const char *component);
static int client_notify_cb(int status, ogs_sbi_response_t *response, void *data);
static void msaf_application_server_remove(msaf_application_server_node_t *msaf_as);

/***** Public functions *****/

int
msaf_application_server_state_set_on_post( msaf_provisioning_session_t *provisioning_session)
{
    msaf_application_server_node_t *msaf_as;
    msaf_application_server_state_node_t *as_state;
    resource_id_node_t *chc;
    assigned_provisioning_sessions_node_t *assigned_provisioning_sessions;
    ogs_list_t *certs;
    ogs_lnode_t *node, *next_node;

    msaf_as = ogs_list_first(&msaf_self()->config.applicationServers_list);
    ogs_assert(msaf_as);
    ogs_list_for_each(&msaf_self()->application_server_states, as_state){
        if (as_state->application_server == msaf_as) {
            msaf_application_server_state_ref_node_t *as_state_ref;

            certs = msaf_retrieve_certificates_from_map(provisioning_session);
            if (certs) {
                ogs_list_for_each_safe(certs, next_node, node) {
                    ogs_list_remove(certs, node);
                    ogs_list_add(&as_state->upload_certificates, node);
                }
                ogs_free(certs);
            } else {
                return 0;
            }

            chc = ogs_calloc(1, sizeof(resource_id_node_t));
            ogs_assert(chc);
            chc->state = msaf_strdup(provisioning_session->provisioningSessionId);
            ogs_list_add(&as_state->upload_content_hosting_configurations, chc);

            assigned_provisioning_sessions = ogs_calloc(1, sizeof(assigned_provisioning_sessions_node_t));
            ogs_assert(assigned_provisioning_sessions);
            assigned_provisioning_sessions->assigned_provisioning_session = provisioning_session;
            ogs_list_add(&as_state->assigned_provisioning_sessions, assigned_provisioning_sessions);

            ogs_list_init(&provisioning_session->application_server_states);
            as_state_ref = ogs_calloc(1, sizeof(msaf_application_server_state_ref_node_t));
            ogs_assert(as_state_ref);
            as_state_ref->as_state = as_state;
            ogs_list_add(&provisioning_session->application_server_states, as_state_ref);

            next_action_for_application_server(as_state);
        }
    }
    return 1;
}

void
msaf_application_server_state_update( msaf_provisioning_session_t *provisioning_session)
{
    msaf_application_server_state_ref_node_t *as_state_ref;

    ogs_list_for_each(&provisioning_session->application_server_states, as_state_ref){
        resource_id_node_t *chc;
        msaf_application_server_state_node_t *as_state = as_state_ref->as_state;
        ogs_list_t *certs = msaf_retrieve_certificates_from_map(provisioning_session);
        if (certs) {
            resource_id_node_t *next_node, *node;
            ogs_list_for_each_safe(certs, next_node, node) {
                int upload_cert = 1;
                resource_id_node_t *cur_cert;
                /* Check if the certificate is already uploaded */
                ogs_list_for_each(as_state->current_certificates, cur_cert) {
                    if (!strcmp(node->state, cur_cert->state)) {
                        upload_cert = 0;
                        break;
                    }

                }
                /* If there is a new certificate for this AS, upload it */
                if (upload_cert) {
                    ogs_list_remove(certs, node);
                    ogs_list_add(&as_state->upload_certificates, node);
                }
            }
            /* free any cert map nodes left in the list (didn't need update) */
            ogs_list_for_each_safe(certs, next_node, node) {
                ogs_list_remove(certs, node);
                if (node->state) ogs_free(node->state);
                ogs_free(node);
            }
            ogs_free(certs);
        } else {
            continue;
        }

        chc = ogs_calloc(1, sizeof(resource_id_node_t));
        ogs_assert(chc);
        chc->state = msaf_strdup(provisioning_session->provisioningSessionId);
        ogs_list_add(&as_state->upload_content_hosting_configurations, chc);

        next_action_for_application_server(as_state);
    }
}

int
msaf_application_server_state_set(msaf_application_server_state_node_t *as_state, msaf_provisioning_session_t *provisioning_session)
{
    resource_id_node_t *chc;
    assigned_provisioning_sessions_node_t *assigned_provisioning_sessions;
    ogs_list_t *certs;
    ogs_lnode_t *node, *next_node;

    certs = msaf_retrieve_certificates_from_map(provisioning_session);
    if (certs) {
        ogs_list_for_each_safe(certs, next_node, node) {
            ogs_list_remove(certs, node);
            ogs_list_add(&as_state->upload_certificates, node);
        }
        ogs_free(certs);
    } else {
        return 0;
    }

    chc = ogs_calloc(1, sizeof(resource_id_node_t));
    ogs_assert(chc);
    chc->state = msaf_strdup(provisioning_session->provisioningSessionId);
    ogs_list_add(&as_state->upload_content_hosting_configurations, chc);

    assigned_provisioning_sessions = ogs_calloc(1, sizeof(assigned_provisioning_sessions_node_t));
    ogs_assert(assigned_provisioning_sessions);
    assigned_provisioning_sessions->assigned_provisioning_session = provisioning_session;
    ogs_list_add(&as_state->assigned_provisioning_sessions, assigned_provisioning_sessions);

    next_action_for_application_server(as_state);

    return 1;
}

msaf_application_server_node_t *
msaf_application_server_add(char *canonical_hostname, char *url_path_prefix_format, int m3_port, char *m3_host)
{
    msaf_application_server_node_t *msaf_as = NULL;

    msaf_as = ogs_calloc(1, sizeof(msaf_application_server_node_t));
    ogs_assert(msaf_as);

    msaf_as->canonicalHostname = canonical_hostname;
    msaf_as->urlPathPrefixFormat = url_path_prefix_format;
    msaf_as->m3Port = m3_port;
    msaf_as->m3Host = m3_host;
    ogs_list_add(&msaf_self()->config.applicationServers_list, msaf_as);

    application_server_state_init(msaf_as);

    return msaf_as;
}

void msaf_application_server_state_log(ogs_list_t *list, const char* list_name) {
    resource_id_node_t *state_node;
    if(!list || (ogs_list_count(list) == 0)){
        ogs_debug("%s is empty",list_name);
    } else{
        int i = 1;
        ogs_list_for_each(list, state_node){
            ogs_debug("%s[%d]: %s\n", list_name, i, state_node->state);
            i++;
        }
    }
}

void next_action_for_application_server(msaf_application_server_state_node_t *as_state) {

    ogs_assert(as_state);

    if (as_state->current_certificates == NULL)  {
        m3_client_as_state_requests(as_state, NULL, NULL, NULL, (char *)OGS_SBI_HTTP_METHOD_GET, "certificates");
    } else if (as_state->current_content_hosting_configurations == NULL) {
        m3_client_as_state_requests(as_state, NULL, NULL, NULL, (char *)OGS_SBI_HTTP_METHOD_GET, "content-hosting-configurations");
    } else if (ogs_list_first(&as_state->upload_certificates) != NULL) {
        char *upload_cert_id;
        char *provisioning_session;
        char *cert_id;
        char *component;
        resource_id_node_t *cert_id_node;
        msaf_certificate_t *certificate;

        resource_id_node_t *upload_cert = ogs_list_first(&as_state->upload_certificates);
        ogs_list_for_each(as_state->current_certificates, cert_id_node) {
            if (!strcmp(cert_id_node->state, upload_cert->state)) {
                break;
            }
        }
        upload_cert_id = msaf_strdup(upload_cert->state);
        provisioning_session = strtok_r(upload_cert_id,":",&cert_id);
        certificate = server_cert_get_servercert(cert_id);
        component = ogs_msprintf("certificates/%s:%s", provisioning_session, cert_id);

        if (cert_id_node) {
            ogs_debug("M3 client: Sending PUT method to Application Server [%s] for Certificate: [%s]", as_state->application_server->canonicalHostname, upload_cert->state);
            m3_client_as_state_requests(as_state, NULL, "application/x-pem-file", certificate->certificate, (char *)OGS_SBI_HTTP_METHOD_PUT, component);
        } else {
            ogs_debug("M3 client: Sending POST method to Application Server [%s] for Certificate: [%s]", as_state->application_server->canonicalHostname, upload_cert->state);
            m3_client_as_state_requests(as_state, NULL, "application/x-pem-file", certificate->certificate, (char *)OGS_SBI_HTTP_METHOD_POST, component);
        }
        msaf_certificate_free(certificate);
        ogs_free(component);
        ogs_free(upload_cert_id);

    } else if (ogs_list_first(&as_state->upload_content_hosting_configurations) !=  NULL) {

        msaf_provisioning_session_t *provisioning_session;
        msaf_api_content_hosting_configuration_t *chc_with_af_unique_cert_id;
        char *data;
        char *component;
        resource_id_node_t *chc_id_node;
        cJSON *json;

        resource_id_node_t *upload_chc = ogs_list_first(&as_state->upload_content_hosting_configurations);
        ogs_list_for_each(as_state->current_content_hosting_configurations, chc_id_node) {
            if (!strcmp(chc_id_node->state, upload_chc->state)) {
                break;
            }
        }

        provisioning_session = msaf_provisioning_session_find_by_provisioningSessionId(upload_chc->state);

        chc_with_af_unique_cert_id = msaf_content_hosting_configuration_with_af_unique_cert_id(provisioning_session);

        json = msaf_api_content_hosting_configuration_convertResponseToJSON(chc_with_af_unique_cert_id);
        data = cJSON_Print(json);

        component = ogs_msprintf("content-hosting-configurations/%s", upload_chc->state);

        if (chc_id_node) {
            ogs_debug("M3 client: Sending PUT method to Application Server [%s] for Content Hosting Configuration: [%s]", as_state->application_server->canonicalHostname, upload_chc->state);
            m3_client_as_state_requests(as_state, NULL, "application/json", data, (char *)OGS_SBI_HTTP_METHOD_PUT, component);
        } else {
            ogs_debug("M3 client: Sending POST method to Application Server [%s] for Content Hosting Configuration:  [%s]", as_state->application_server->canonicalHostname, upload_chc->state);
            m3_client_as_state_requests(as_state, NULL, "application/json", data, (char *)OGS_SBI_HTTP_METHOD_POST, component);
        }
        if (chc_with_af_unique_cert_id) msaf_api_content_hosting_configuration_free(chc_with_af_unique_cert_id);
        ogs_free(component);
        cJSON_Delete(json);
        cJSON_free(data);

    }   else if (ogs_list_first(&as_state->delete_content_hosting_configurations) !=  NULL) {
        char *component;
        resource_id_node_t *delete_chc = ogs_list_first(&as_state->delete_content_hosting_configurations);
        ogs_debug("M3 client: Sending DELETE method for Content Hosting Configuration [%s] to the Application Server [%s]", delete_chc->state, as_state->application_server->canonicalHostname);
        component = ogs_msprintf("content-hosting-configurations/%s", delete_chc->state);
        m3_client_as_state_requests(as_state, NULL, NULL, NULL, (char *)OGS_SBI_HTTP_METHOD_DELETE, component);
        ogs_free(component);
    }   else if (ogs_list_first(&as_state->delete_certificates) !=  NULL) {
        char *component;
        resource_id_node_t *delete_cert = ogs_list_first(&as_state->delete_certificates);
        ogs_debug("M3 client: Sending DELETE method for certificate [%s] to the Application Server [%s]", delete_cert->state, as_state->application_server->canonicalHostname);
        component = ogs_msprintf("certificates/%s", delete_cert->state);
        m3_client_as_state_requests(as_state, NULL, NULL, NULL, (char *)OGS_SBI_HTTP_METHOD_DELETE, component);
        ogs_free(component);
    }  else if(ogs_list_first(&as_state->purge_content_hosting_cache) != NULL){
        purge_resource_id_node_t *purge_chc = ogs_list_first(&as_state->purge_content_hosting_cache);
        ogs_assert(purge_chc);
        ogs_assert(purge_chc->provisioning_session_id);
        char *component =  ogs_msprintf("content-hosting-configurations/%s/purge", purge_chc->provisioning_session_id);
        if(purge_chc->purge_regex) {
            ogs_debug("M3 client: Sending cache purge operation for resource [%s] to the Application Server", purge_chc->provisioning_session_id);
            m3_client_as_state_requests(as_state, purge_chc, "application/x-www-form-urlencoded", purge_chc->purge_regex, OGS_SBI_HTTP_METHOD_POST, component);
        } else {
            ogs_debug("M3 client: Sending Purge operation for cache [%s] to the Application Server", purge_chc->provisioning_session_id);
            m3_client_as_state_requests(as_state, purge_chc, "application/x-www-form-urlencoded", NULL, OGS_SBI_HTTP_METHOD_POST, component);
        }
        ogs_free(component);

    }


}


void msaf_application_server_remove_all()
{
    msaf_application_server_node_t *msaf_as = NULL, *next = NULL;

    ogs_list_for_each_safe(&msaf_self()->config.applicationServers_list, next, msaf_as)
        msaf_application_server_remove(msaf_as);
}

void msaf_application_server_print_all()
{
    msaf_application_server_node_t *msaf_as = NULL, *next = NULL;;

    ogs_list_for_each_safe(&msaf_self()->config.applicationServers_list, next, msaf_as)
        ogs_debug("AS %s %s", msaf_as->canonicalHostname, msaf_as->urlPathPrefixFormat);
}


/***** Private functions *****/

static void application_server_state_init(msaf_application_server_node_t *msaf_as)
{
    msaf_application_server_state_node_t *as_state = NULL;

    as_state = ogs_calloc(1, sizeof(msaf_application_server_state_node_t));
    ogs_assert(as_state);

    as_state->application_server = msaf_as;

    ogs_list_init(&as_state->assigned_provisioning_sessions);
    ogs_list_init(&as_state->upload_certificates);
    ogs_list_init(&as_state->upload_content_hosting_configurations);

    ogs_list_add(&msaf_self()->application_server_states, as_state);
}

static void msaf_application_server_remove(msaf_application_server_node_t *msaf_as)
{
    ogs_assert(msaf_as);
    ogs_list_remove(&msaf_self()->config.applicationServers_list, msaf_as);
    if (msaf_as->canonicalHostname) ogs_free(msaf_as->canonicalHostname);
    if (msaf_as->urlPathPrefixFormat) ogs_free(msaf_as->urlPathPrefixFormat);
    if (msaf_as->m3Host) ogs_free(msaf_as->m3Host);
    ogs_free(msaf_as);
}

static ogs_sbi_client_t *msaf_m3_client_init(const char *hostname, int port)
{
    int rv;
    ogs_sbi_client_t *client = NULL;
    ogs_sockaddr_t *addr = NULL;
    OpenAPI_uri_scheme_e scheme = OpenAPI_uri_scheme_http;

    rv = ogs_getaddrinfo(&addr, AF_UNSPEC, hostname, port, 0);
    if (rv != OGS_OK) {
        ogs_error("getaddrinfo failed");
        return NULL;
    }

    if (addr == NULL)
        ogs_error("Could not get the address of the Application Server");

    client = ogs_sbi_client_add(scheme, addr);
    ogs_assert(client);

    ogs_freeaddrinfo(addr);

    return client;
}

static int m3_client_as_state_requests(msaf_application_server_state_node_t *as_state,
        purge_resource_id_node_t *purge_node, const char *type, const char *data, const char *method,
        const char *component)
{
    ogs_sbi_request_t *request;
    const char *m3_host;

    m3_host = as_state->application_server->m3Host?
            as_state->application_server->m3Host:
            as_state->application_server->canonicalHostname;
    request = ogs_sbi_request_new();
    request->h.method = msaf_strdup(method);
    request->h.uri = ogs_msprintf("http://%s:%i/3gpp-m3/v1/%s", m3_host, as_state->application_server->m3Port, component);
    request->h.api.version = msaf_strdup("v1");
    if (data) {
        request->http.content = msaf_strdup(data);
        request->http.content_length = strlen(data);
    }
    if (type)
        ogs_sbi_header_set(request->http.headers, "Content-Type", type);

    if (as_state->client == NULL) {
        as_state->client = msaf_m3_client_init(m3_host, as_state->application_server->m3Port);
    }
    client_request_info_t *request_info = ogs_calloc(1, sizeof(client_request_info_t));
    request_info->as_state = as_state;
    request_info->purge_node = purge_node;

    ogs_sbi_client_send_request(as_state->client, client_notify_cb, request, request_info);

    ogs_sbi_request_free(request);

    return 1;
}

static int client_notify_cb(int status, ogs_sbi_response_t *response, void *data)
{
    int rv;
    client_request_info_t *client_request_info = data;
    msaf_event_t *event;

    if (status != OGS_OK) {
        ogs_log_message(
                status == OGS_DONE ? OGS_LOG_DEBUG : OGS_LOG_WARN, 0,
                "client_notify_cb() failed [%d]", status);
        if (client_request_info) ogs_free(client_request_info);
        if (response) ogs_sbi_response_free(response);
        return OGS_ERROR;
    }

    ogs_assert(response);

    event = (msaf_event_t*)ogs_event_new(OGS_EVENT_SBI_CLIENT);
    event->h.sbi.response = response;
    event->application_server_state = client_request_info->as_state;
    event->purge_node = client_request_info->purge_node;
    rv = ogs_queue_push(ogs_app()->queue, event);
    if (rv !=OGS_OK) {
        ogs_error("OGS Queue Push failed %d", rv);
        ogs_sbi_response_free(response);
        ogs_event_free(event);
        return OGS_ERROR;
    }
    if (client_request_info->purge_node == NULL) ogs_free(client_request_info->purge_node);
    ogs_free(client_request_info);
    return OGS_OK;
}

/* vim:ts=8:sts=4:sw=4:expandtab:
*/
