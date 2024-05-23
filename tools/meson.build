# License: 5G-MAG Public License (v1.0)
# Authors: Dev Audsin & David Waring
# Copyright: (C) 2023 British Broadcasting Corporation
#
# For full license terms please see the LICENSE file distributed with this
# program. If this file is missing then the license can be retrieved from
# https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view

fs = import('fs')

support_scripts_dir = get_option('libexecdir') / 'rt-5gms'

support_scripts = {
  'bash/certmgr': 'self-signed-certmgr',
  'bash/le-certmgr': 'lets-encrypt-certmgr'
}

self_signed_certmgr_runtime = support_scripts_dir / 'self-signed-certmgr'

scripts_conf_data = configuration_data()
script_conf_options = [
  'prefix', 'bindir', 'libdir', 'libexecdir', 'localstatedir', 'sbindir',
  'sysconfdir',
  ]
foreach opt : script_conf_options
  scripts_conf_data.set(opt, get_option(opt))
endforeach

foreach src, dst : support_scripts
  scriptfile = configure_file(input: src, configuration: scripts_conf_data, output: dst)
  install_data(scriptfile, install_dir: support_scripts_dir, install_mode: 'rwxr-xr-x')
endforeach
