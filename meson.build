# License: 5G-MAG Public License (v1.0)
# Author: Dev Audsin
# Copyright: (C) 2022 British Broadcasting Corporation
#
# For full license terms please see the LICENSE file distributed with this
# program. If this file is missing then the license can be retrieved from
# https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view

project('rt-5gms-af', 'c',
    version : '1.1.1',
    license : '5G-MAG Public',
    meson_version : '>= 0.47.0',
    default_options : [
        'c_std=gnu89',
    ],
)
sh_cmd = find_program('sh')
patch_open5gs_result = run_command([sh_cmd, '-c', '"$MESON_SOURCE_ROOT/subprojects/patch_open5gs.sh" open5gs'], check: true, capture: false)
open5gs_project=subproject('open5gs',required:true)
subdir('src')
