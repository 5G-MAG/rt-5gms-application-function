# License: 5G-MAG Public License (v1.0)
# Author: Dev Audsin
# Copyright: (C) 2022-2023 British Broadcasting Corporation
#
# For full license terms please see the LICENSE file distributed with this
# program. If this file is missing then the license can be retrieved from
# https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view


libapp_dep = open5gs_project.get_variable('libapp_dep')
libcrypt_dep = open5gs_project.get_variable('libcrypt_dep')
libsbi_dep = open5gs_project.get_variable('libsbi_dep')
libsbi_openapi_dep = open5gs_project.get_variable('libsbi_openapi_dep')
open5gs_sysconfdir = open5gs_project.get_variable('open5gs_sysconfdir')
srcinc = open5gs_project.get_variable('srcinc')
libdir = open5gs_project.get_variable('libdir')
python3_exe = open5gs_project.get_variable('python3_exe')
mkdir_p = open5gs_project.get_variable('mkdir_p')
install_conf = open5gs_project.get_variable('install_conf')
sbi_openapi_inc = open5gs_project.get_variable('libsbi_openapi_model_inc')

libscbsf_dep = svc_consumers_project.get_variable('libscbsf_dep')
libscpcf_dep = svc_consumers_project.get_variable('libscpcf_dep')

latest_apis = get_option('latest_apis')
fiveg_api_approval = get_option('fiveg_api_approval')
fiveg_api_release = get_option('fiveg_api_release')


fs = import('fs')

libmsaf_dist_sources = files('''
    application-server-context.h
    application-server-context.c
    certmgr.c
    certmgr.h
    consumption-report-configuration.c
    consumption-report-configuration.h
    context.c
    context.h
    data-collection.c
    data-collection.h
    event.c
    event.h
    hash.h
    hash.c
    headers.h
    headers.c
    init.h
    init.c
    msaf-fsm.h
    msaf-fsm.c
    msaf-m1-sm.h
    msaf-m1-sm.c
    msaf-m5-sm.h
    msaf-m5-sm.c
    msaf-mgmt-sm.h
    msaf-mgmt-sm.c
    msaf-sm.h
    msaf-sm.c
    network-assistance-session.h
    network-assistance-session.c
    timer.h
    timer.c
    local.h
    local.c
    network-assistance-delivery-boost.h
    network-assistance-delivery-boost.c
    pcf-cache.c
    pcf-cache.h
    pcf-session.h
    pcf-session.c
    policy-template.h
    policy-template.c
    provisioning-session.h
    provisioning-session.c
    response-cache-control.h
    response-cache-control.c
    sai-cache.h
    sai-cache.c
    sbi-path.h
    sbi-path.c
    server.h
    server.c
    service-access-information.h
    service-access-information.c
    dynamic-policy.h
    dynamic-policy.c
    utilities.h
    utilities.c
'''.split())

msaf_test_sources = files('''
    hash.c
    hash.h
    pcf-cache.c
    pcf-cache.h
    sai-cache.c
    sai-cache.h
'''.split())

api_tag = latest_apis?'REL-'+fiveg_api_release:'TSG'+fiveg_api_approval+'-Rel'+fiveg_api_release

gen_5gmsaf_openapi = find_program('sh')
message('Generating OpenAPI bindings for version '+api_tag+' of the 5G APIs...')
openapi_dep_file = meson.current_source_dir() / '.openapi.deps'
openapi_gen_result = run_command([gen_5gmsaf_openapi,'-c','"$MESON_SOURCE_ROOT/$MESON_SUBDIR/generator-5gmsaf" -M '+openapi_dep_file+' -b '+api_tag], check: true, capture: true)
libmsaf_gen_sources = files(fs.read(openapi_dep_file).split())

msaf_test_sources += libmsaf_gen_sources

json_file = files(['ContentProtocolsDiscovery_body.json'])
file_content = ''
data = fs.read(json_file).split('\n')

foreach line : data
   file_content = file_content + ''.join(line + '\\n')
endforeach

file_hash = fs.hash(json_file, 'sha256')
json_file_time = run_command(['stat', '-c', '%Y', json_file], check: true)
file_time = json_file_time.stdout().strip()

content_hosting_discovery_protocols_conf = configuration_data()
content_hosting_discovery_protocols_conf.set_quoted('CONTENT_PROTOCOLS_DISCOVERY_JSON', file_content)
content_hosting_discovery_protocols_conf.set_quoted('CONTENT_PROTOCOLS_DISCOVERY_JSON_HASH', file_hash)
content_hosting_discovery_protocols_conf.set('CONTENT_PROTOCOLS_DISCOVERY_JSON_TIME', file_time)
libmsaf_gen_sources += [configure_file(output : 'ContentProtocolsDiscovery_body.h', configuration : content_hosting_discovery_protocols_conf)]

version_conf = configuration_data()
version_conf.set_quoted('MSAF_NAME', meson.project_name())
version_conf.set_quoted('MSAF_VERSION', meson.project_version())
version_conf.set_quoted('FIVEG_API_RELEASE', fiveg_api_release)
libmsaf_gen_sources += [configure_file(output : 'msaf-version.h', configuration : version_conf)]

libmsaf_sources = libmsaf_dist_sources + libmsaf_gen_sources

libmsaf = static_library('msaf',
    sources : libmsaf_sources,
    include_directories : sbi_openapi_inc,
    dependencies : [libsbi_dep,
                    libsbi_openapi_dep,
                    libapp_dep,
                    libscbsf_dep,
                    libscpcf_dep,
                    libcrypt_dep],
    install : false)

libmsaf_dep = declare_dependency(
    link_with : libmsaf,
    dependencies : [libsbi_dep,
                    libsbi_openapi_dep,
                    libapp_dep,
                    libscbsf_dep,
                    libscpcf_dep,
                    libcrypt_dep])

msaf_sources = files('''
    app.c
'''.split()) + open5gs_project.get_variable('app_main_c')

msaf_config_source = '''
    msaf.yaml
'''.split()

msaf_include = include_directories('.')

executable('open5gs-msafd',
    sources : msaf_sources,
    c_args : '-DDEFAULT_CONFIG_FILENAME="@0@/msaf.yaml"'.format(open5gs_sysconfdir),
    include_directories : srcinc,
    dependencies : [libmsaf_dep],
    install_rpath : libdir,
    install : true)

meson.add_install_script(python3_exe, '-c', mkdir_p.format(open5gs_sysconfdir))
conf_configuration = configuration_data()
conf_configuration.set('default-certmgr', get_option('prefix') / self_signed_certmgr_runtime)
conf_configuration.set('data-collection-dir', get_option('prefix') / get_option('localstatedir') / 'log' / 'open5gs' / 'reports')
foreach conf_file : msaf_config_source
    gen = configure_file(input : conf_file + '.in', configuration : conf_configuration, output : conf_file)
    meson.add_install_script(python3_exe, '-c', install_conf.format(gen, open5gs_sysconfdir))
endforeach
