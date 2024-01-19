# License: 5G-MAG Public License (v1.0)
# Author: David Waring
# Copyright: (C) 2022-2023 British Broadcasting Corporation
#
# For full license terms please see the LICENSE file distributed with this
# program. If this file is missing then the license can be retrieved from
# https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view

libtest5gc_dep = open5gs_project.get_variable('libtest5gc_dep')
testunit_core_cc_flags = open5gs_project.get_variable('testunit_core_cc_flags')
sbi_openapi_inc = open5gs_project.get_variable('libsbi_openapi_model_inc')
srcinc = open5gs_project.get_variable('srcinc')

test_msaf_sources = files('''
    abts-main.c

    pcf-cache-test.c
    pcf-cache-test.h
    sai-cache-test.c
    sai-cache-test.h
    utilities-test.c
    utilities-test.h

    tests.c
    tests.h
'''.split())

test_msaf_exe = executable('test-msaf',
    sources : test_msaf_sources,
    c_args : testunit_core_cc_flags,
    include_directories : [srcinc, msaf_include, sbi_openapi_inc],
    dependencies : [libtest5gc_dep, libmsaf_dep])

test('test-msaf',
    test_msaf_exe,
    is_parallel : false,
    suite: 'app')
