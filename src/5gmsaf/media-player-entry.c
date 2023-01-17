/*
License: 5G-MAG Public License (v1.0)
Author: Dev Audsin
Copyright: (C) 2022 British Broadcasting Corporation

For full license terms please see the LICENSE file distributed with this
program. If this file is missing then the license can be retrieved from
https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
*/

#include "media-player-entry.h"
#include "context.h"

static char *url_path_prefix_create(const char *macro, const char *session_id);

/***** Public functions *****/

char *media_player_entry_create(const char *session_id, OpenAPI_content_hosting_configuration_t *chc)
{
    char *media_player_entry = NULL;
    OpenAPI_lnode_t *dist_config_node = NULL;
    OpenAPI_distribution_configuration_t *dist_config = NULL;
    static const char macro[] = "{provisioningSessionId}";
    char *url_path_prefix = NULL;
    const char *protocol = "http";
    msaf_application_server_node_t *msaf_as = NULL;

    ogs_assert(session_id);
    ogs_assert(chc);

    OpenAPI_list_for_each(chc->distribution_configurations, dist_config_node) {
        dist_config = (OpenAPI_distribution_configuration_t*)dist_config_node->data;
        if (dist_config->certificate_id) {
            protocol = "https";
            break;
        }
    }

    url_path_prefix = url_path_prefix_create(macro, session_id);
    msaf_as = ogs_list_first(&msaf_self()->config.applicationServers_list); /* just use first defined AS for now - change later to use AS picked from pool */
    media_player_entry = ogs_msprintf("%s://%s%s%s", protocol, msaf_as->canonicalHostname, url_path_prefix, chc->entry_point_path);

    ogs_free(url_path_prefix);

    return media_player_entry;
}

/***** Private functions *****/

static char*
url_path_prefix_create(const char* macro, const char* session_id)
{
    char* url_path_prefix;
    char *url_path_prefix_format;
    int i, count = 0;
    int session_id_len = strlen(session_id);
    int macro_len = strlen(macro);
    msaf_application_server_node_t *msaf_as = NULL;

    msaf_as = ogs_list_first(&msaf_self()->config.applicationServers_list);
    url_path_prefix_format = msaf_as->urlPathPrefixFormat;
    for (i = 0; url_path_prefix_format[i] != '\0'; i++) {
        if (strstr(url_path_prefix_format+i, macro) == url_path_prefix_format+i) {
            count++;
            i += macro_len - 1;
        }
    }

    url_path_prefix = (char*)ogs_malloc(i + count * (session_id_len - macro_len) + 2);

    i = 0;
    while (*url_path_prefix_format) {
        if (strstr(url_path_prefix_format, macro) == url_path_prefix_format) {
            strcpy(url_path_prefix+i, session_id);
            i += session_id_len;
            url_path_prefix_format += macro_len;
        }
        else
            url_path_prefix[i++] = *url_path_prefix_format++;
    }

    if (url_path_prefix[i-1] != '/')
        url_path_prefix[i++] = '/';
    url_path_prefix[i] = '\0';

    return url_path_prefix;
}
