#!/bin/sh
#==============================================================================
# 5G-MAG Reference Tools - Open5GS apply patches
#==============================================================================
# Author: David Waring
# License: 5G-MAG Public License (v1.0)
# Copyright: ©2022-2023 British Broadcasting Corporation
#
# For full license terms please see the LICENSE file distributed with this
# program. If this file is missing then the license can be retrieved from
# https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
#==============================================================================

cd `dirname "$0"`

open5gs_src=`realpath "$1"`
patch_cmd=`which patch`

if ! grep -q '/\* rt-5gms-applicatiopn-function patch applied \*/' "$open5gs_src/lib/sbi/server.c"; then
    (cd "$open5gs_src"; "$patch_cmd" -p1 <<EOF
diff --git a/configs/meson.build b/configs/meson.build
index 9e625248a..2f2f3157b 100644
--- a/configs/meson.build
+++ b/configs/meson.build
@@ -26,7 +26,7 @@ build_configs_dir = join_paths(open5gs_build_dir, 'configs')
 conf_data.set('build_configs_dir', build_configs_dir)
 
 build_subprojects_freeDiameter_extensions_dir = join_paths(
-        open5gs_build_dir, 'subprojects', 'freeDiameter', 'extensions')
+        meson.global_build_root(), 'subprojects', 'freeDiameter', 'extensions')
 conf_data.set('build_subprojects_freeDiameter_extensions_dir',
         build_subprojects_freeDiameter_extensions_dir)
 
diff --git a/lib/pfcp/context.c b/lib/pfcp/context.c
index 8964b49dd..d8ea407b1 100644
--- a/lib/pfcp/context.c
+++ b/lib/pfcp/context.c
@@ -72,7 +72,7 @@ void ogs_pfcp_context_init(void)
     ogs_pool_random_id_generate(&ogs_pfcp_pdr_teid_pool);
 
     pdr_random_to_index = ogs_calloc(
-            sizeof(ogs_pool_id_t), ogs_pfcp_pdr_pool.size);
+            sizeof(ogs_pool_id_t), ogs_pfcp_pdr_pool.size+1);
     ogs_assert(pdr_random_to_index);
     for (i = 0; i < ogs_pfcp_pdr_pool.size; i++)
         pdr_random_to_index[ogs_pfcp_pdr_teid_pool.array[i]] = i;
diff --git a/lib/sbi/mhd-server.c b/lib/sbi/mhd-server.c
index 817a448aa..1ef4e8a76 100644
--- a/lib/sbi/mhd-server.c
+++ b/lib/sbi/mhd-server.c
@@ -39,8 +39,6 @@ static bool server_send_rspmem_persistent(
 static bool server_send_response(
         ogs_sbi_stream_t *stream, ogs_sbi_response_t *response);
 
-static ogs_sbi_server_t *server_from_stream(ogs_sbi_stream_t *stream);
-
 const ogs_sbi_server_actions_t ogs_mhd_server_actions = {
     server_init,
     server_final,
@@ -49,9 +47,7 @@ const ogs_sbi_server_actions_t ogs_mhd_server_actions = {
     server_stop,
 
     server_send_rspmem_persistent,
-    server_send_response,
-
-    server_from_stream,
+    server_send_response
 };
 
 static void run(short when, ogs_socket_t fd, void *data);
@@ -77,12 +73,11 @@ static void notify_completed(
 static void session_timer_expired(void *data);
 
 typedef struct ogs_sbi_session_s {
-    ogs_lnode_t             lnode;
+    ogs_sbi_stream_common_t  common;
 
     struct MHD_Connection   *connection;
 
     ogs_sbi_request_t       *request;
-    ogs_sbi_server_t        *server;
 
     /*
      * If the HTTP client closes the socket without sending an HTTP response,
@@ -129,7 +124,7 @@ static ogs_sbi_session_t *session_add(ogs_sbi_server_t *server,
     ogs_assert(sbi_sess);
     memset(sbi_sess, 0, sizeof(ogs_sbi_session_t));
 
-    sbi_sess->server = server;
+    sbi_sess->common.server = server;
     sbi_sess->request = request;
     sbi_sess->connection = connection;
 
@@ -157,7 +152,7 @@ static void session_remove(ogs_sbi_session_t *sbi_sess)
     ogs_sbi_server_t *server = NULL;
 
     ogs_assert(sbi_sess);
-    server = sbi_sess->server;
+    server = sbi_sess->common.server;
     ogs_assert(server);
 
     ogs_list_remove(&server->session_list, sbi_sess);
@@ -598,13 +593,3 @@ static void notify_completed(
 
     ogs_sbi_request_free(request);
 }
-
-static ogs_sbi_server_t *server_from_stream(ogs_sbi_stream_t *stream)
-{
-    ogs_sbi_session_t *sbi_sess = (ogs_sbi_session_t *)stream;
-
-    ogs_assert(sbi_sess);
-    ogs_assert(sbi_sess->server);
-
-    return sbi_sess->server;
-}
diff --git a/lib/sbi/nghttp2-server.c b/lib/sbi/nghttp2-server.c
index d9e3fa2e5..56332f77b 100644
--- a/lib/sbi/nghttp2-server.c
+++ b/lib/sbi/nghttp2-server.c
@@ -37,8 +37,6 @@ static bool server_send_rspmem_persistent(
 static bool server_send_response(
         ogs_sbi_stream_t *stream, ogs_sbi_response_t *response);
 
-static ogs_sbi_server_t *server_from_stream(ogs_sbi_stream_t *stream);
-
 const ogs_sbi_server_actions_t ogs_nghttp2_server_actions = {
     server_init,
     server_final,
@@ -48,8 +46,6 @@ const ogs_sbi_server_actions_t ogs_nghttp2_server_actions = {
 
     server_send_rspmem_persistent,
     server_send_response,
-
-    server_from_stream,
 };
 
 struct h2_settings {
@@ -79,7 +75,7 @@ typedef struct ogs_sbi_session_s {
 } ogs_sbi_session_t;
 
 typedef struct ogs_sbi_stream_s {
-    ogs_lnode_t             lnode;
+    ogs_sbi_stream_common_t common;
 
     int32_t                 stream_id;
     ogs_sbi_request_t       *request;
@@ -661,18 +657,6 @@ static bool server_send_response(
     return rc;
 }
 
-static ogs_sbi_server_t *server_from_stream(ogs_sbi_stream_t *stream)
-{
-    ogs_sbi_session_t *sbi_sess = NULL;
-
-    ogs_assert(stream);
-    sbi_sess = stream->session;
-    ogs_assert(sbi_sess);
-    ogs_assert(sbi_sess->server);
-
-    return sbi_sess->server;
-}
-
 static ogs_sbi_stream_t *stream_add(
         ogs_sbi_session_t *sbi_sess, int32_t stream_id)
 {
@@ -698,6 +682,7 @@ static ogs_sbi_stream_t *stream_add(
     sbi_sess->last_stream_id = stream_id;
 
     stream->session = sbi_sess;
+    stream->common.server = sbi_sess->server;
 
     ogs_list_add(&sbi_sess->stream_list, stream);
 
diff --git a/lib/sbi/openapi/meson.build b/lib/sbi/openapi/meson.build
index b3a507bd3..5f6388a0f 100644
--- a/lib/sbi/openapi/meson.build
+++ b/lib/sbi/openapi/meson.build
@@ -1370,6 +1370,7 @@ libsbi_openapi_sources = files('''
 '''.split())
 
 libsbi_openapi_inc = include_directories('.')
+libsbi_openapi_model_inc = include_directories('model')
 
 sbi_openapi_cc_flags = ['-DOGS_SBI_COMPILATION']
 
diff --git a/lib/sbi/server.c b/lib/sbi/server.c
index af5cb8aad..518420c5c 100644
--- a/lib/sbi/server.c
+++ b/lib/sbi/server.c
@@ -29,6 +29,7 @@ static OGS_POOL(server_pool, ogs_sbi_server_t);
 
 void ogs_sbi_server_init(int num_of_session_pool, int num_of_stream_pool)
 {
+    /* rt-5gms-applicatiopn-function patch applied */
     if (ogs_sbi_server_actions_initialized == false) {
 #if 1 /* Use HTTP2 */
         ogs_sbi_server_actions = ogs_nghttp2_server_actions;
@@ -37,7 +38,8 @@ void ogs_sbi_server_init(int num_of_session_pool, int num_of_stream_pool)
 #endif
     }
 
-    ogs_sbi_server_actions.init(num_of_session_pool, num_of_stream_pool);
+    ogs_nghttp2_server_actions.init(num_of_session_pool, num_of_stream_pool);
+    ogs_mhd_server_actions.init(num_of_session_pool, num_of_stream_pool);
 
     ogs_list_init(&ogs_sbi_self()->server_list);
     ogs_pool_init(&server_pool, ogs_app()->pool.nf);
@@ -49,7 +51,8 @@ void ogs_sbi_server_final(void)
 
     ogs_pool_final(&server_pool);
 
-    ogs_sbi_server_actions.cleanup();
+    ogs_mhd_server_actions.cleanup();
+    ogs_nghttp2_server_actions.cleanup();
 }
 
 ogs_sbi_server_t *ogs_sbi_server_add(
@@ -67,6 +70,30 @@ ogs_sbi_server_t *ogs_sbi_server_add(
     if (option)
         server->node.option = ogs_memdup(option, sizeof *option);
 
+    server->actions = &ogs_nghttp2_server_actions;
+
+    ogs_list_add(&ogs_sbi_self()->server_list, server);
+
+    return server;
+}
+
+ogs_sbi_server_t *ogs_sbih1_server_add(
+        ogs_sockaddr_t *addr, ogs_sockopt_t *option)
+{
+    ogs_sbi_server_t *server = NULL;
+
+    ogs_assert(addr);
+
+    ogs_pool_alloc(&server_pool, &server);
+    ogs_assert(server);
+    memset(server, 0, sizeof(ogs_sbi_server_t));
+
+    ogs_assert(OGS_OK == ogs_copyaddrinfo(&server->node.addr, addr));
+    if (option)
+        server->node.option = ogs_memdup(option, sizeof *option);
+
+    server->actions = &ogs_mhd_server_actions;
+
     ogs_list_add(&ogs_sbi_self()->server_list, server);
 
     return server;
@@ -118,7 +145,7 @@ int ogs_sbi_server_start_all(
     ogs_sbi_server_t *server = NULL, *next_server = NULL;
 
     ogs_list_for_each_safe(&ogs_sbi_self()->server_list, next_server, server)
-        if (ogs_sbi_server_actions.start(server, cb) != OGS_OK)
+        if (server->actions->start(server, cb) != OGS_OK)
             return OGS_ERROR;
 
     return OGS_OK;
@@ -129,19 +156,21 @@ void ogs_sbi_server_stop_all(void)
     ogs_sbi_server_t *server = NULL, *next_server = NULL;
 
     ogs_list_for_each_safe(&ogs_sbi_self()->server_list, next_server, server)
-        ogs_sbi_server_actions.stop(server);
+        server->actions->stop(server);
 }
 
 bool ogs_sbi_server_send_rspmem_persistent(
         ogs_sbi_stream_t *stream, ogs_sbi_response_t *response)
 {
-    return ogs_sbi_server_actions.send_rspmem_persistent(stream, response);
+    ogs_sbi_server_t *server = ogs_sbi_server_from_stream(stream);
+    return server->actions->send_rspmem_persistent(stream, response);
 }
 
 bool ogs_sbi_server_send_response(
         ogs_sbi_stream_t *stream, ogs_sbi_response_t *response)
 {
-    return ogs_sbi_server_actions.send_response(stream, response);
+    ogs_sbi_server_t *server = ogs_sbi_server_from_stream(stream);
+    return server->actions->send_response(stream, response);
 }
 
 bool ogs_sbi_server_send_problem(
@@ -208,5 +237,6 @@ bool ogs_sbi_server_send_error(ogs_sbi_stream_t *stream,
 
 ogs_sbi_server_t *ogs_sbi_server_from_stream(ogs_sbi_stream_t *stream)
 {
-    return ogs_sbi_server_actions.from_stream(stream);
+    ogs_sbi_stream_common_t *cstream = (ogs_sbi_stream_common_t*)stream;
+    return cstream->server;
 }
diff --git a/lib/sbi/server.h b/lib/sbi/server.h
index c112f9330..53467171a 100644
--- a/lib/sbi/server.h
+++ b/lib/sbi/server.h
@@ -32,6 +32,7 @@ extern "C" {
 #include <openssl/err.h>
 
 typedef struct ogs_sbi_stream_s ogs_sbi_stream_t;
+typedef struct ogs_sbi_server_actions_s ogs_sbi_server_actions_t;
 
 typedef struct ogs_sbi_server_s {
     ogs_socknode_t  node;
@@ -43,6 +44,7 @@ typedef struct ogs_sbi_server_s {
     ogs_list_t      session_list;
 
     void            *mhd; /* Used by MHD */
+    const ogs_sbi_server_actions_t *actions;
 } ogs_sbi_server_t;
 
 typedef struct ogs_sbi_server_actions_s {
@@ -58,14 +60,20 @@ typedef struct ogs_sbi_server_actions_s {
     bool (*send_response)(
             ogs_sbi_stream_t *stream, ogs_sbi_response_t *response);
 
-    ogs_sbi_server_t *(*from_stream)(ogs_sbi_stream_t *stream);
 } ogs_sbi_server_actions_t;
 
+typedef struct ogs_sbi_stream_common_s {
+    ogs_lnode_t             lnode;
+    ogs_sbi_server_t       *server;
+} ogs_sbi_stream_common_t;
+
 void ogs_sbi_server_init(int num_of_session_pool, int num_of_stream_pool);
 void ogs_sbi_server_final(void);
 
 ogs_sbi_server_t *ogs_sbi_server_add(
         ogs_sockaddr_t *addr, ogs_sockopt_t *option);
+ogs_sbi_server_t *ogs_sbih1_server_add(
+        ogs_sockaddr_t *addr, ogs_sockopt_t *option);
 void ogs_sbi_server_remove(ogs_sbi_server_t *server);
 void ogs_sbi_server_remove_all(void);
 
diff --git a/src/main.c b/src/main.c
index 329d5b108..0f993a6a6 100644
--- a/src/main.c
+++ b/src/main.c
@@ -111,7 +111,7 @@ int main(int argc, const char *const argv[])
         bool enable_debug;
         bool enable_trace;
     } optarg;
-    const char *argv_out[argc];
+    const char *argv_out[argc+1];
 
     memset(&optarg, 0, sizeof(optarg));
 
diff --git a/src/meson.build b/src/meson.build
index d313b6932..2e25dbd93 100644
--- a/src/meson.build
+++ b/src/meson.build
@@ -33,6 +33,8 @@ version_conf = configuration_data()
 version_conf.set_quoted('OPEN5GS_VERSION', package_version)
 configure_file(output : 'version.h', configuration : version_conf)
 
+app_main_c = files(['main.c'])
+
 subdir('mme')
 subdir('hss')
 subdir('sgwc')
diff --git a/tests/common/application.c b/tests/common/application.c
index 1bf1a0528..501693a45 100644
--- a/tests/common/application.c
+++ b/tests/common/application.c
@@ -26,8 +26,8 @@ static void run(int argc, const char *const argv[],
     int rv;
     bool user_config;
 
-    /* '-f sample-XXXX.conf -e error' is always added */
-    const char *argv_out[argc+4], *new_argv[argc+4];
+    /* '-f sample-XXXX.conf -e error' + null is always added */
+    const char *argv_out[argc+5], *new_argv[argc+5];
     int argc_out;
 
     char conf_file[OGS_MAX_FILEPATH_LEN];
EOF
)
fi
exit 0
