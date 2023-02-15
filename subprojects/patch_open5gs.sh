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
diff --git a/lib/sbi/server.c b/lib/sbi/server.c
index 79789d0c9..3348a1798 100644
--- a/lib/sbi/server.c
+++ b/lib/sbi/server.c
@@ -30,9 +30,9 @@ static OGS_POOL(server_pool, ogs_sbi_server_t);
 void ogs_sbi_server_init(int num_of_session_pool, int num_of_stream_pool)
 {
     if (ogs_sbi_server_actions_initialized == false) {
-#if 1 /* Use HTTP2 */
+#if 0 /* Use HTTP2 */ /* rt-5gms-applicatiopn-function patch applied */
         ogs_sbi_server_actions = ogs_nghttp2_server_actions;
-#else
+#else /* Use HTTP/1.1 */
         ogs_sbi_server_actions = ogs_mhd_server_actions;
 #endif
     }
diff --git a/lib/sbi/support/20210629/openapi-generator/templates/model-header.mustache b/lib/sbi/support/20210629/openapi-generator/templates/model-header.mustache
index 1f32ae27e..5e5af2155 100644
--- a/lib/sbi/support/20210629/openapi-generator/templates/model-header.mustache
+++ b/lib/sbi/support/20210629/openapi-generator/templates/model-header.mustache
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
index d53fce06b..b512110eb 100644
--- a/src/meson.build
+++ b/src/meson.build
@@ -29,6 +29,8 @@ version_conf = configuration_data()
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
