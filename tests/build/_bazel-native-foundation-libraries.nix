##! Checks declared native metadata without consulting ambient pkg-config paths.
{pkgs}: let
  libraries = pkgs.aosBazelNativeFoundationLibraries;
  zlib = {
    package = pkgs.zlib;
    libraryFile = "lib/libz.so";
    pkgConfigFiles = ["lib/pkgconfig/zlib.pc"];
  };
  invalid = specification:
    !(builtins.tryEval (builtins.deepSeq (pkgs.mkAosBazelNativeLibraries {libraries = specification;}).drvPath true)).success;
in
  assert invalid {zlib = zlib // {pkgConfigDependencies = ["missing"];};};
  assert invalid {zlib = zlib // {compilerResponseFile = "true";};};
  assert invalid {zlib = zlib // {pkgConfigDependencies = ["zlib"];};};
  assert invalid {
    zlib = zlib // {pkgConfigDependencies = ["other" "other"];};
    other = zlib;
  };
  assert invalid {
    zlib = zlib // {pkgConfigDependencies = ["other"];};
    other = zlib // {pkgConfigFiles = [];};
  };
    pkgs.runCommand "aos-bazel-native-foundation-library-metadata" {
      buildDeps = [pkgs.python3 libraries];
    } ''
      mkdir -p "$out"
      ${pkgs.python3}/bin/python3 - ${libraries} "$out/report.json" <<'PY'
      import json
      import os
      from pathlib import Path
      import subprocess
      import sys

      root, output = map(Path, sys.argv[1:])
      expected = {
          'openssl': ('openssl', ['-lssl', '-lcrypto']),
          'ssh': ('libssh2', ['-lssh2']),
          'zlib': ('zlib', ['-lz']),
          'zstd': ('libzstd', ['-lzstd']),
      }
      reports = {}
      for name, (package, flags) in expected.items():
          environment = dict(os.environ, PKG_CONFIG_PATH='/ambient-invalid', PKG_CONFIG_LIBDIR='/ambient-invalid')
          result = subprocess.run(
              [str(root / name / 'pkg-config'), '--cflags', '--libs', package],
              env=environment, capture_output=True, text=True, check=True,
          )
          if not all(flag in result.stdout.split() for flag in flags) or '/ambient-invalid' in result.stdout:
              raise ValueError(f'native library metadata differs: {name}: {result.stdout}')
          reports[name] = {
              'pkg_config': result.stdout.strip(),
              'closure': json.loads((root / name / 'closure.json').read_text()),
          }
      # cc-rs passes response files through to the declared AOS compiler. This
      # exercises libz-sys's compile-and-link probe without ambient search paths.
      response = root / 'zlib/cflags'
      probe = Path(os.environ['TMPDIR']) / 'zlib-probe'
      linked = subprocess.run(
          ['cc', '@' + str(response), '-x', 'c', '-', '-Wl,-t', '-o', str(probe), '-lz'],
          input='#include <zlib.h>\nint main(void) { return zlibVersion() == 0; }\n',
          env=dict(os.environ, C_INCLUDE_PATH="", CPATH="", LIBRARY_PATH=""),
          capture_output=True, text=True, check=True,
      )
      selected = reports['zlib']['closure']
      library = str(Path(selected['package']) / selected['libraryFile'])
      if library not in linked.stdout.splitlines():
          raise ValueError('compiler probe did not link the declared AOS zlib: ' + linked.stdout)
      reports['zlib']['compiler_response_file'] = response.read_text().strip()
      reports['zlib']['linked_probe_library'] = library
      output.write_text(json.dumps(reports, indent=2, sort_keys=True) + '\n')
      PY
    ''
