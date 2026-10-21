#ifndef MSAF_DATABUCKET_H
#define MSAF_DATABUCKET_H

#include <time.h>

#include "ogs-core.h"

typedef struct msaf_databucket_entry_s {
    ogs_lnode_t node;
    char *provisioning_session_id;
    struct timespec received_at;
    void *data;
} msaf_databucket_entry_t;

typedef struct msaf_databucket_s {
    ogs_list_t entries;
} msaf_databucket_t;

bool msaf_databucket_add(msaf_databucket_t *bucket, const char *provisioning_session_id,
                        void *data, const struct timespec *received_at);
const ogs_list_t *msaf_databucket_entries(const msaf_databucket_t *bucket);
void msaf_databucket_clear(msaf_databucket_t *bucket, void (*free_data)(void *data));

#endif