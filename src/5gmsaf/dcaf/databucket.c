#include "databucket.h"

bool msaf_databucket_add(msaf_databucket_t *bucket, const char *provisioning_session_id,
                        void *data, const struct timespec *received_at)
{
    msaf_databucket_entry_t *entry;

    if (!bucket ||
        !provisioning_session_id || !*provisioning_session_id || !data || !received_at) return false;

    entry = ogs_calloc(1, sizeof(*entry));
    entry->provisioning_session_id = ogs_strdup(provisioning_session_id);
    entry->received_at = *received_at;
    entry->data = data;
    ogs_list_add(&bucket->entries, entry);
    return true;
}

const ogs_list_t *msaf_databucket_entries(const msaf_databucket_t *bucket)
{
    return bucket ? &bucket->entries : NULL;
}

void msaf_databucket_clear(msaf_databucket_t *bucket, void (*free_data)(void *data))
{
    msaf_databucket_entry_t *entry;
    msaf_databucket_entry_t *next;

    if (!bucket || !free_data) return;

    ogs_list_for_each_safe(&bucket->entries, next, entry) {
        ogs_list_remove(&bucket->entries, entry);
        free_data(entry->data);
        ogs_free(entry->provisioning_session_id);
        ogs_free(entry);
    }
}
