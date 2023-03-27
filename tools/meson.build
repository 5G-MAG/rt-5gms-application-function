pymod = import('python')
fs = import('fs')

support_scripts_dir = get_option('libexecdir') / 'rt-5gms'

scripts = {
'python3/m1_client_cli.py': 'm1-client',
'python3/m1_session_cli.py': 'm1-session'
}

support_scripts = {
'bash/certmgr': 'self-signed-certmgr'
}

self_signed_certmgr_runtime = support_scripts_dir / 'self-signed-certmgr'

python3_modules = [
  'python3/lib/rt_m1_client',
]

scripts_conf_data = configuration_data()
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

python3 = pymod.find_installation('python3')
sh = find_program('sh')
foreach pm : python3_modules
  mod_files = files(run_command(sh, '-c', 'cd "$MESON_SOURCE_ROOT/$MESON_SUBDIR"; find "' + pm + '" -type f -name "*.py" -print').stdout().strip().split('\n'))
  python3.install_sources(mod_files, subdir: fs.name(pm))
endforeach
