/*
 * License: 5G-MAG Public License (v1.0)
 * Author: David Waring
 * Copyright: (C) 2023 British Broadcasting Corporation
 *
 * For full license terms please see the LICENSE file distributed with this
 * program. If this file is missing then the license can be retrieved from
 * https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
 */

#ifndef NF_HEADERS_H
#define NF_HEADERS_H

#include "ogs-core.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct nf_headers_s {
    ogs_hash_t *hdrs;
} nf_headers_t;

typedef struct nf_headers_iter_s {
    ogs_hash_index_t *ptr;
} nf_headers_iter_t;

typedef int (nf_headers_do_callback_fn_t)(const char *fieldname, const char *value, void *data);

/* nf_headers_t methods */
extern nf_headers_t *nf_headers_new();
extern void nf_headers_free(nf_headers_t *);

extern const char *nf_headers_get(nf_headers_t *headers, const char *fieldname);
extern int nf_headers_set(nf_headers_t *headers, const char *fieldname, const char *value);
extern int nf_headers_add(nf_headers_t *headers, const char *fieldname, const char *value);
extern int nf_headers_delete(nf_headers_t *headers, const char *fieldname);

extern int nf_headers_clear(nf_headers_t *headers);

extern int nf_headers_count(nf_headers_t *headers);

extern int nf_headers_do(nf_headers_t *headers, nf_headers_do_callback_fn_t *fn, void *data);

/* Iterator for nf_headers_t */
extern nf_headers_iter_t *nf_headers_iter_new(nf_headers_t *headers);
extern nf_headers_iter_t *nf_headers_iter_next(nf_headers_iter_t *);
extern const char *nf_headers_iter_fieldname(nf_headers_iter_t *);
extern const char *nf_headers_iter_value(nf_headers_iter_t *);
extern nf_headers_iter_t *nf_headers_iter_find(nf_headers_t *headers, const char *fieldname);
extern void nf_headers_iter_free(nf_headers_iter_t *);

#ifdef __cplusplus
}
#endif

#endif /* NF_HEADERS_H */
