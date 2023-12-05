# License: 5G-MAG Public License (v1.0)
# Authors: Dev Audsin & David Waring
# Copyright: (C) 2023 British Broadcasting Corporation
#
# For full license terms please see the LICENSE file distributed with this
# program. If this file is missing then the license can be retrieved from
# https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view

pymod = import('python')
fs = import('fs')

python3 = pymod.find_installation('python3')

support_scripts_dir = get_option('libexecdir') / 'rt-5gms'

scripts = {
  'python3/m1_sync_config.py': 'msaf-configuration',
  'python3/m1_client_cli.py': 'm1-client',
  'python3/m1_session_cli.py': 'm1-session'
}

support_scripts = {
  'bash/certmgr': 'self-signed-certmgr',
  'bash/le-certmgr': 'lets-encrypt-certmgr'
}

self_signed_certmgr_runtime = support_scripts_dir / 'self-signed-certmgr'

python3_modules = [
  'python3/lib/rt_m1_client',
]

scripts_conf_data = configuration_data({'python_packages_dir': python3.get_install_dir()})
script_conf_options = [
  'prefix', 'bindir', 'libdir', 'libexecdir', 'localstatedir', 'sbindir',
  'sysconfdir',
  ]
foreach opt : script_conf_options
  scripts_conf_data.set(opt, get_option(opt))
endforeach

foreach src, dst : scripts
  scriptfile = configure_file(input: src, configuration: scripts_conf_data, output: dst)
  install_data(scriptfile, install_dir: get_option('bindir'), install_mode: 'rwxr-xr-x')
endforeach

foreach src, dst : support_scripts
  scriptfile = configure_file(input: src, configuration: scripts_conf_data, output: dst)
  install_data(scriptfile, install_dir: support_scripts_dir, install_mode: 'rwxr-xr-x')
endforeach

sh = find_program('sh')
foreach pm : python3_modules
  mod_files = run_command([sh, '-c', 'cd "$MESON_SOURCE_ROOT/$MESON_SUBDIR/'+fs.parent(pm)+'"; find "' + fs.name(pm) + '" -type f -name "*.py" -print'], check: false).stdout().strip().split('\n')
  foreach mod_filepath : mod_files
    mod_file = files([fs.parent(pm) / mod_filepath])
    python3.install_sources(mod_file, subdir: fs.parent(mod_filepath))
  endforeach
endforeach
