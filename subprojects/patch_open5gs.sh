#!/bin/sh
#==============================================================================
# 5G-MAG Reference Tools - Open5GS apply patches
#==============================================================================
# Author: David Waring
# License: 5G-MAG Public License (v1.0)
# Copyright: ©2022 British Broadcasting Corporation
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
diff --git a/lib/sbi/meson.build b/lib/sbi/meson.build
index 67a1badc7..573582c2e 100644
--- a/lib/sbi/meson.build
+++ b/lib/sbi/meson.build
@@ -46,6 +46,8 @@ libsbi_sources = files('''
 libsbi_inc = include_directories('.')

 sbi_cc_flags = ['-DOGS_SBI_COMPILATION']
+sbi_h1_flag = ['-DSBI_USE_HTTP_1']
+sbi_h1_cc_flags = sbi_cc_flags + sbi_h1_flag

 libgnutls_dep = dependency('gnutls', required : true)
 libssl_dep = dependency('libssl', required : true)
@@ -83,3 +85,33 @@ libsbi_dep = declare_dependency(
                     libnghttp2_dep,
                     libmicrohttpd_dep,
                     libcurl_dep])
+
+libsbih1 = library('ogssbih1',
+    sources : libsbi_sources,
+    version : libogslib_version,
+    c_args : sbi_h1_cc_flags,
+    include_directories : [libsbi_inc, libinc],
+    dependencies : [libcrypt_dep,
+                    libapp_dep,
+                    libsbi_openapi_dep,
+                    libgnutls_dep,
+                    libssl_dep,
+                    libcrypto_dep,
+                    libnghttp2_dep,
+                    libmicrohttpd_dep,
+                    libcurl_dep],
+    install_rpath : libdir,
+    install : true)
+
+libsbih1_dep = declare_dependency(
+    link_with : libsbih1,
+    include_directories : [libsbi_inc, libinc],
+    dependencies : [libcrypt_dep,
+                    libapp_dep,
+                    libsbi_openapi_dep,
+                    libgnutls_dep,
+                    libssl_dep,
+                    libcrypto_dep,
+                    libnghttp2_dep,
+                    libmicrohttpd_dep,
+                    libcurl_dep])
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
index af5cb8aad..5a20728a9 100644
--- a/lib/sbi/server.c
+++ b/lib/sbi/server.c
@@ -30,9 +30,9 @@ static OGS_POOL(server_pool, ogs_sbi_server_t);
 void ogs_sbi_server_init(int num_of_session_pool, int num_of_stream_pool)
 {
     if (ogs_sbi_server_actions_initialized == false) {
-#if 1 /* Use HTTP2 */
+#ifndef SBI_USE_HTTP_1 /* Use HTTP2 */ /* rt-5gms-applicatiopn-function patch applied */
         ogs_sbi_server_actions = ogs_nghttp2_server_actions;
-#else
+#else /* Use HTTP/1.1 */
         ogs_sbi_server_actions = ogs_mhd_server_actions;
 #endif
     }
diff --git a/lib/sbi/support/r17-20230301-openapitools-6.4.0/openapi-generator/templates/model-header.mustache b/lib/sbi/support/r17-20230301-openapitools-6.4.0/openapi-generator/templates/model-header.mustache
index d702deb6d..50e9e1fb1 100644
--- a/lib/sbi/support/r17-20230301-openapitools-6.4.0/openapi-generator/templates/model-header.mustache
+++ b/lib/sbi/support/r17-20230301-openapitools-6.4.0/openapi-generator/templates/model-header.mustache
@@ -16,6 +16,10 @@
 #include "{{{.}}}.h"
 {{/imports}}

+#define OpenAPI_{{classVarName}}_info_title "{{appName}}"
+#define OpenAPI_{{classVarName}}_info_version "{{appVersion}}"
+#define OpenAPI_{{classVarName}}_info_description "{{appDescription}}"
+
 #ifdef __cplusplus
 extern "C" {
 #endif
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
EOF
)
fi
exit 0
