# License: 5G-MAG Public License (v1.0)
# Copyright: (C) 2022 British Broadcasting Corporation
#
# For full license terms please see the LICENSE file distributed with this
# program. If this file is missing then the license can be retrieved from
# https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view

libtest5gc_dep = open5gs_project.get_variable('libtest5gc_dep')
srcinc = open5gs_project.get_variable('srcinc')
testunit_core_cc_flags = open5gs_project.get_variable('testunit_core_cc_flags')

test5gc_bsf_sources = files('''
    abts-main.c
    bsf-config.c
    bsf-test.c
    bsf-test-context.c
    bsf-test-event.c
    bsf-test-sm.c
    bsf-test-local.c
   
    bsf-test.h
    bsf-test-context.h
    bsf-test-sm.h
    bsf-test-event.h
    bsf-test-sbi.h
    bsf-test-local.h
'''.split())

test5gc_bsf_exe = executable('bsf-client',
    sources : test5gc_bsf_sources,
    c_args : testunit_core_cc_flags,
    include_directories : srcinc,
    dependencies : [libtest5gc_dep, libbsfclient_dep])

test('bsf-client',
    test5gc_bsf_exe,
    is_parallel : false,
    suite: 'app')


