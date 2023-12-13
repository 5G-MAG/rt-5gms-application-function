# License: 5G-MAG Public License (v1.0)
# Authors: David Waring
# Copyright: (C) 2023 British Broadcasting Corporation
#
# For full license terms please see the LICENSE file distributed with this
# program. If this file is missing then the license can be retrieved from
# https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view

prefix = get_option('prefix')
bindir = prefix / get_option('bindir')
libdir = prefix / get_option('libdir')

systemd_search_system_unit_paths = run_command([systemd_path_cmd,'systemd-search-system-unit'], check:false).stdout().strip().split(':')
systemd_system_unit_dir = ''
foreach unit_path : systemd_search_system_unit_paths
  if unit_path.startswith(prefix) and unit_path.endswith('systemd' / 'system')
    systemd_system_unit_dir = unit_path
    break
  endif
endforeach

if systemd_system_unit_dir != ''
  systemd_system_preset_dir = systemd_system_unit_dir+'-preset'
else
  systemd_system_unit_dir = libdir / 'systemd' / 'system'
  systemd_system_preset_dir = libdir / 'systemd' / 'system-preset'
endif

summary({
  'System units': systemd_system_unit_dir,
  'System presets': systemd_system_preset_dir
  }, section : 'Systemd Directories')

units = [
  '5gms-application-function.service'
]

presets = files([
  '90-5gms-application-function.preset'
])

units_conf_data = configuration_data({
  'bindir': bindir
})

foreach unit : units
  unitfile = configure_file(input: unit+'.in', configuration: units_conf_data, output: unit)
  install_data(unitfile, install_dir: systemd_system_unit_dir, install_mode: 'rw-r--r--')
endforeach

install_data(presets, install_dir: systemd_system_preset_dir, install_mode: 'rw-r--r--')
