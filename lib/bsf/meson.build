# License: 5G-MAG Public License (v1.0)
# Copyright: (C) 2022 British Broadcasting Corporation
#
# For full license terms please see the LICENSE file distributed with this
# program. If this file is missing then the license can be retrieved from
# https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view

libapp_dep = open5gs_project.get_variable('libapp_dep')
libcore_dep = open5gs_project.get_variable('libcore_dep')
libcrypt_dep = open5gs_project.get_variable('libcrypt_dep')
libsbi_dep = open5gs_project.get_variable('libsbi_dep')
libinc = open5gs_project.get_variable('libinc')

libbsfclient_sources = files('''
    bsf-client.c
    bsf-client.h
    bsf-client-sess.c
    bsf-client-sess.h
    bsf-configuration.c
    bsf-configuration.h
    context.c
    context.h
    local.c
    local.h
    log.c
    log.h
    nbsf-management-build.c
    nbsf-management-build.h
    nbsf-process.c
    nbsf-process.h
    pcf-bind.c
    pcf-bind.h
    pcf-bindings-cache.c
    pcf-bindings-cache.h
    utils.c
    utils.h
'''.split())

libbsfclient_inc = include_directories('.')

libbsfclient = static_library('bsfclient',
    sources : libbsfclient_sources,
    c_args : '-DOGS_APP_COMPILATION',
    include_directories : [libbsfclient_inc, libinc],
    gnu_symbol_visibility : 'hidden',
    dependencies : [libapp_dep,
                    libcore_dep,
                    libcrypt_dep,
		    libsbi_dep],
    install : true)

libbsfclient_dep = declare_dependency(
    link_with : libbsfclient,
    include_directories : [libbsfclient_inc, libinc],
    sources : libbsfclient_sources,
    dependencies : [libapp_dep,
                    libcore_dep,
                    libcrypt_dep,
		    libsbi_dep]
)

