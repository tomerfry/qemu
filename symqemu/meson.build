bitwuzla_dep = dependency('bitwuzla', required: true)
cpp_stdlib = meson.get_compiler('c').find_library('stdc++')

symqemu_ss = ss.source_set()
symqemu_ss.add(files(
  'src/sym_state.c',
  'src/sym_ops.c',
  'src/sym_solver.c',
  'src/symqemu_runtime.c',
))
symqemu_ss.add(when: 'CONFIG_LINUX_USER', if_true: [bitwuzla_dep, cpp_stdlib])

specific_ss.add_all(when: 'CONFIG_LINUX_USER', if_true: symqemu_ss)
