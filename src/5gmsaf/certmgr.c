/*
 * License: 5G-MAG Public License (v1.0)
 * Authors: Dev Audsin & David Waring
 * Copyright: (C) 2023 British Broadcasting Corporation
 *
 * For full license terms please see the LICENSE file distributed with this
 * program. If this file is missing then the license can be retrieved from
 * https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
 */

#include "ogs-core.h"

#include "utilities.h"

#include "certmgr.h"

#define MAX_CHILD_PROCESS               16

static msaf_certificate_t *msaf_certificate_populate(const char *certid, const char *cert, int out_return_code);

int server_cert_delete(const char *certid)
{
    const char *commandLine[OGS_ARG_MAX];
    ogs_proc_t *current = NULL;
    FILE *out = NULL;
    char buf[OGS_HUGE_LEN];
    int ret = 0, out_return_code = 0;

    commandLine[0] = msaf_self()->config.certificateManager;
    commandLine[1] = "-c";
    commandLine[2] = "delete";
    commandLine[3] = certid;
    commandLine[4] = NULL;

    current = (ogs_proc_t*)ogs_calloc(1, sizeof(*current));
    ret = ogs_proc_create(commandLine,
        ogs_proc_option_combined_stdout_stderr|
        ogs_proc_option_inherit_environment,
        current);
    ogs_assert(ret == 0);
    out = ogs_proc_stdout(current);
    ogs_assert(out);

    while(fgets(buf, OGS_HUGE_LEN, out)) {
        printf("%s", buf);
    }
    ret = ogs_proc_join(current, &out_return_code);
    ogs_assert(ret == 0);
    ret = ogs_proc_destroy(current);
    ogs_assert(ret == 0);

    ogs_free(current);

    return out_return_code;
}

msaf_certificate_t *server_cert_retrieve(const char *certid)
{
    const char *commandLine[OGS_ARG_MAX];
    ogs_proc_t *current = NULL;
    FILE *out = NULL;
    char buf[OGS_HUGE_LEN];
    char *cert = NULL;
    int ret = 0, out_return_code = 0;
    msaf_certificate_t *msaf_certificate = NULL;
    size_t cert_size = 0;
    size_t cert_reserved = 0;

    commandLine[0] =  msaf_self()->config.certificateManager;
    commandLine[1] = "-c";
    commandLine[2] = "publiccert";
    commandLine[3] = certid;
    commandLine[4] = NULL;

    current = (ogs_proc_t*)ogs_calloc(1, sizeof(*current));
    ret = ogs_proc_create(commandLine,
        ogs_proc_option_combined_stdout_stderr|
        ogs_proc_option_inherit_environment,
        current);
    ogs_assert(ret == 0);
    out = ogs_proc_stdout(current);
    ogs_assert(out);

    cert = ogs_calloc(1, 4096);
    cert_reserved = 4096;

    while(fgets(buf, OGS_HUGE_LEN, out)) {
        cert_size += strlen (buf);
        if(cert_size > cert_reserved - 1) {
            cert_reserved +=4096;
            cert = ogs_realloc(cert,cert_reserved);
        }
        strcat(cert,buf);
    }
    ret = ogs_proc_join(current, &out_return_code);
    ogs_assert(ret == 0);
    ret = ogs_proc_destroy(current);
    ogs_assert(ret == 0);
    ogs_free(current);

    if(out_return_code == 0 || out_return_code == 4 || out_return_code == 8){
        msaf_certificate = msaf_certificate_populate(certid, cert, out_return_code);
        ogs_assert(msaf_certificate);
    }
    ogs_free(cert);
    return msaf_certificate;
}

msaf_certificate_t *server_cert_get_servercert(const char *certid)
{
    const char *commandLine[OGS_ARG_MAX];
    ogs_proc_t *current = NULL;
    FILE *out = NULL;
    char buf[OGS_HUGE_LEN];
    char *cert = NULL;
    int ret = 0, out_return_code = 0;
    msaf_certificate_t *msaf_certificate = NULL;
    size_t cert_size = 0;
    size_t cert_reserved = 0;

    commandLine[0] =  msaf_self()->config.certificateManager;
    commandLine[1] = "-c";
    commandLine[2] = "servercert";
    commandLine[3] = certid;
    commandLine[4] = NULL;

    current = (ogs_proc_t*)ogs_calloc(1, sizeof(*current));
    ret = ogs_proc_create(commandLine,
        ogs_proc_option_combined_stdout_stderr|
        ogs_proc_option_inherit_environment,
        current);
    ogs_assert(ret == 0);
    out = ogs_proc_stdout(current);
    ogs_assert(out);

    cert = ogs_calloc(1, 4096);
    cert_reserved = 4096;

    while(fgets(buf, OGS_HUGE_LEN, out)) {
        cert_size += strlen (buf);
        if(cert_size > cert_reserved - 1) {
            cert_reserved +=4096;
            cert = ogs_realloc(cert,cert_reserved);
        }
        strcat(cert,buf);
    }
    ret = ogs_proc_join(current, &out_return_code);
    ogs_assert(ret == 0);
    ret = ogs_proc_destroy(current);
    ogs_assert(ret == 0);
    ogs_free(current);

    if(!out_return_code){
        msaf_certificate = msaf_certificate_populate(certid, cert, out_return_code);
        ogs_assert(msaf_certificate);
    }
    ogs_free(cert);
    return msaf_certificate;
}

int server_cert_set(const char *cert_id, const char *cert)
{
    const char *commandLine[OGS_ARG_MAX];
    ogs_proc_t *current = NULL;
    FILE *in = NULL;
    int ret = 0, out_return_code = 0;

    commandLine[0] =  msaf_self()->config.certificateManager;
    commandLine[1] = "-c";
    commandLine[2] = "setcert";
    commandLine[3] = cert_id;
    commandLine[4] = NULL;

    current = (ogs_proc_t*)ogs_calloc(1, sizeof(*current));
    ret = ogs_proc_create(commandLine,
        ogs_proc_option_inherit_environment,
        current);
    ogs_assert(ret == 0);

    in = ogs_proc_stdin(current);
    ogs_assert(in);

    if (cert) {
        fputs(cert, in);
    }

    ret = ogs_proc_join(current, &out_return_code);
    ogs_assert(ret == 0);
    ret = ogs_proc_destroy(current);
    ogs_assert(ret == 0);
    ogs_free(current);

    return out_return_code;
}

msaf_certificate_t *server_cert_new(const char *operation, const char *common_name, ogs_list_t *extra_fqdns)
{
    const char *commandLine[OGS_ARG_MAX];
    ogs_proc_t *current = NULL;
    FILE *out = NULL;
    char buf[OGS_HUGE_LEN];
    char *cert;
    int ret = 0, out_return_code = 0, n = 0;
    msaf_certificate_t *msaf_certificate = NULL;
    size_t cert_size = 0;
    size_t cert_reserved = 0;

    ogs_uuid_t uuid;
    char id[OGS_UUID_FORMATTED_LENGTH + 1];

    ogs_uuid_get(&uuid);
    ogs_uuid_format(id, &uuid);

    commandLine[n++] = msaf_self()->config.certificateManager;
    commandLine[n++] = "-c";
    commandLine[n++] = operation;
    commandLine[n++] = id;
    commandLine[n++] = common_name;

    if (extra_fqdns) {
        fqdn_list_node_t *node;

        ogs_list_for_each(extra_fqdns, node) {
            if (n >= OGS_ARG_MAX-1) {
                n = OGS_ARG_MAX-1;
                ogs_error("Too many extra domain names for certificate %s, only using first %i extra domain names", id, OGS_ARG_MAX-6);
                break;
            }
            commandLine[n++] = node->fqdn;
        }
    }

    commandLine[n] = NULL;

    current = (ogs_proc_t*)ogs_calloc(1, sizeof(*current));
    ret = ogs_proc_create(commandLine,
        ogs_proc_option_combined_stdout_stderr|
        ogs_proc_option_inherit_environment,
        current);
    ogs_assert(ret == 0);
    out = ogs_proc_stdout(current);
    ogs_assert(out);

    cert = ogs_calloc(1, 4096);
    cert_reserved = 4096;

    while(fgets(buf, OGS_HUGE_LEN, out)) {
        cert_size += strlen (buf);
        if(cert_size > cert_reserved - 1) {
            cert_reserved =+ 4096;
            cert = ogs_realloc(cert,cert_reserved);
        }
        strcat(cert,buf);
    }
    ret = ogs_proc_join(current, &out_return_code);
    ogs_assert(ret == 0);
    ret = ogs_proc_destroy(current);
    ogs_assert(ret == 0);
    ogs_free(current);
    msaf_certificate = msaf_certificate_populate(id, cert, out_return_code);
    ogs_assert(msaf_certificate);
    ogs_free(cert);
    return msaf_certificate;
}

char *check_in_cert_list(const char *canonical_domain_name)
{
    const char *commandLine[OGS_ARG_MAX];
    ogs_proc_t *current = NULL;
    FILE *out = NULL;
    char buf[OGS_HUGE_LEN];
    int ret = 0, out_return_code = 0;
    char *certificate = NULL;
    char *cert_id = NULL;
    char *status = NULL;
    char *saveptr;

    commandLine[0] = msaf_self()->config.certificateManager;
    commandLine[1] = "-c";
    commandLine[2] = "list";
    commandLine[3] = NULL;

    current = (ogs_proc_t*)ogs_calloc(1, sizeof(*current));
    ret = ogs_proc_create(commandLine,
        ogs_proc_option_combined_stdout_stderr|
        ogs_proc_option_inherit_environment,
        current);
    ogs_assert(ret == 0);
    out = ogs_proc_stdout(current);
    ogs_assert(out);

    while(fgets(buf, OGS_HUGE_LEN, out)) {

        ogs_debug("buf=\"%s\", canonical_domain_name=\"%s\"", buf, canonical_domain_name);
        if (str_match(buf, canonical_domain_name)) {
            certificate = strtok_r(buf,"\t",&saveptr);
            if (certificate) cert_id = strtok_r(NULL,"\t",&saveptr);
            if (cert_id) status = strtok_r(NULL,"\t",&saveptr);
            if (status == NULL || strlen(status) <= 1 || str_match(status,"Awaiting")) {
                // Empty or "Awaiting" status can be returned, ignore anything else (i.e. expired or due to expire)
                ogs_debug("buf=\"%s\", certificate=\"%s\", cert_id=\"%s\", status=\"%s\"", buf, certificate, cert_id, status);
                break;
            }
            certificate = NULL;
            cert_id = NULL;
            status = NULL;
        }
    }

    ret = ogs_proc_join(current, &out_return_code);
    ogs_assert(ret == 0);
    ret = ogs_proc_destroy(current);
    ogs_assert(ret == 0);
    ogs_free(current);

    return msaf_strdup(certificate);
}

static msaf_certificate_t *msaf_certificate_populate(const char *certid, const char *cert, int out_return_code)
{
    msaf_certificate_t *msaf_certificate;
    const char *line;
    const char *eol;
    const char *hdr_value;
    static const char begin_marker[] = "-----BEGIN";
    static const char max_age_str[] = "max-age=";

    msaf_certificate = ogs_calloc(1, sizeof(msaf_certificate_t));
    ogs_assert(msaf_certificate);

    msaf_certificate->id = msaf_strdup(certid);
    msaf_certificate->return_code = out_return_code;

    msaf_certificate->headers = nf_headers_new();
    ogs_assert(msaf_certificate->headers);

    line = cert;
    while ((eol = strchr(line, '\n')) != NULL) {
        const char *end_field;
        /* Stop when we get to the certificate, key or CSR */
        if (strncmp(line, begin_marker, sizeof(begin_marker)-1) == 0)
            break;
        /* otherwise try and interpret as "Field: Value" */
        end_field = strchr(line, ':');
        if (end_field) {
            char *field;
            char *value;
            const char *value_start;
            const char *value_end;
            field = ogs_strndup(line, end_field-line);
            value_start = end_field+1;
            while (*value_start && *value_start == ' ') value_start++;
            value_end = eol-1;
            while (value_end>value_start && *value_end == ' ') value_end--;
            value = ogs_strndup(value_start, value_end-value_start+1);
            nf_headers_set(msaf_certificate->headers, field, value);
            ogs_free(field);
            ogs_free(value);
        }
        line = eol+1;
    }

    msaf_certificate->certificate = msaf_strdup(line);

    hdr_value = nf_headers_get(msaf_certificate->headers, "Last-Modified");
    if (hdr_value) {
        msaf_certificate->last_modified = str_to_time(hdr_value);
    }

    hdr_value = nf_headers_get(msaf_certificate->headers, "Cache-Control");
    if (hdr_value && strncmp(hdr_value, max_age_str, sizeof(max_age_str)-1)==0) {
        msaf_certificate->cache_control_max_age = ascii_to_long(hdr_value+sizeof(max_age_str)-1);
    }

    hdr_value = nf_headers_get(msaf_certificate->headers, "ETag");
    msaf_certificate->server_certificate_hash = msaf_strdup(hdr_value);

    return msaf_certificate;
}

void msaf_certificate_free(msaf_certificate_t *cert)
{
    if (cert->headers) nf_headers_free(cert->headers);
    if (cert->certificate) ogs_free(cert->certificate);
    if (cert->server_certificate_hash) ogs_free(cert->server_certificate_hash);
    if (cert->id) ogs_free(cert->id);
    ogs_free(cert);
}

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
