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
--- open5gs.orig/lib/sbi/server.c	2022-10-28 09:40:30.867621595 +0100
+++ open5gs/lib/sbi/server.c	2022-10-28 09:41:38.004798078 +0100
@@ -30,9 +30,9 @@
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
EOF
)
fi
exit 0
