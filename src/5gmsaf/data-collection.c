/*
License: 5G-MAG Public License (v1.0)
Author: David Waring
Copyright: (C) 2023 British Broadcasting Corporation

For full license terms please see the LICENSE file distributed with this
program. If this file is missing then the license can be retrieved from
https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
 */

#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <stdbool.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "ogs-core.h"

#include "context.h"

#include "data-collection.h"

/*****************************************************
 ***** Local declarations
 *****************************************************/

static bool ensure_directory(const char *path);
static int open_data_store_file(const char *provisioning_session_id, const char *report_class, const char *client_id,
                                const char *session_id, const char *report_time, const char *format);

/*****************************************************
 ***** Public functions
 *****************************************************/

bool msaf_data_collection_store(const char *provisioning_session_id, const char *report_class, const char *client_id,
                                const char *session_id, const char *report_time, const char *format, const char *report_body)
{
    int fd;
    size_t body_len;

    fd = open_data_store_file(provisioning_session_id, report_class, client_id, session_id, report_time, format);
    
    if (fd < 0) {
        return false;
    }

    body_len = strlen(report_body);

    if (write(fd, report_body, body_len) != body_len) {
        ogs_error("Failed to write %s data report: %s", report_class, strerror(errno));
        return false;
    }

    return true;
}

/*****************************************************
 ***** Private functions
 *****************************************************/

static bool ensure_directory(const char *path)
{
    struct stat statbuf;
    bool ret = false;

    if ((path[0] == '/' || path[0] == '.') && path[1] == '\0') return true;

    if (!stat(path, &statbuf)) {
        if ((statbuf.st_mode & S_IFMT) == S_IFDIR) {
            ret = true;
        }
    } else {
        /* path doesn't exist so ensure parent directory is present and try to create wanted directory */
        char *path_copy = ogs_strdup(path); 
        if (ensure_directory(dirname(path_copy)) && !mkdir(path, 0755)) {
            ret = true;
        }
        ogs_free(path_copy);
    }

    return ret;
}

static int open_data_store_file(const char *provisioning_session_id, const char *report_class, const char *client_id,
                                const char *session_id, const char *report_time, const char *format)
{
    int fd = -1;
    char *filepath;
    char *reportdir;
    const char *report_root;

    report_root = msaf_self()->config.data_collection_dir;
    if (!report_root) return -1;

    reportdir = ogs_msprintf("%s/%s/%s", report_root, provisioning_session_id, report_class);

    if (!ensure_directory(reportdir)) {
        ogs_error("Unable to create report directory %s", reportdir);
        ogs_free(reportdir);
        return -1;
    }

    filepath = ogs_msprintf("%s/%s%s%s_%s.%s", reportdir, client_id, session_id?"_":"", session_id?session_id:"", report_time, format);
    ogs_free(reportdir);

    fd = open(filepath, O_CREAT|O_WRONLY|O_EXCL, 0664);

    if (fd < 0) {
        ogs_error("Unable to create %s for writing: %s", filepath, strerror(errno));
    }

    ogs_free(filepath);

    return fd;
}

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
