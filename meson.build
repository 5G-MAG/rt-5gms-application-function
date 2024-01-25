# License: 5G-MAG Public License (v1.0)
# Author: Dev Audsin
# Copyright: (C) 2022 British Broadcasting Corporation
#
# For full license terms please see the LICENSE file distributed with this
# program. If this file is missing then the license can be retrieved from
# https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view

# Meson module fs and its functions like fs.hash_file require atleast meson 0.59.0 

project('rt-5gms-application-function', 'c',
    version : '1.4.0',
    license : '5G-MAG Public',
    meson_version : '>= 0.59.0',
    default_options : [
        'c_std=gnu89',
    ],
)

sh_cmd = find_program('sh')
patch_open5gs_result = run_command([sh_cmd, '-c', '"$MESON_SOURCE_ROOT/subprojects/patch_open5gs.sh" open5gs'], check: true, capture: false)
open5gs_project=subproject('open5gs',required:true)
svc_consumers_project=subproject('rt-5gc-service-consumers',required:true)

build_tests = open5gs_project.get_variable('build_tests')

subdir('tools')
subdir('src')

systemd_path_cmd = find_program('systemd-path', required : false)
if systemd_path_cmd.found()
  subdir('systemd')
endif
if build_tests
    subdir('tests')
endif
