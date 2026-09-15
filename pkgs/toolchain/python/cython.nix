##! Cython — C extensions for Python
{
  lib,
  mkDerivation,
  fetchurl,
  python3,
  setuptools,
}: let
  version = "3.0.12";
in
  mkDerivation {
    pname = "cython";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Cython emits a C extension implementation for the declared module.";
        "files" = {
          "probe.pyx" = "cpdef int add(int left, int right):\n    return left + right\n";
        };
        "input" = "A typed Cython function adding two C integers.";
        "operation" = "Translate the module to C and inspect its generated initialization entry point.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/cython"
              "--3str"
              "--output-file"
              "probe.c"
              "probe.pyx"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "";
            };
          }
          {
            "argv" = [
              "@python@"
              "-c"
              "from pathlib import Path; source = Path('probe.c').read_text(); assert 'PyInit_probe' in source; print('cython generation passed')"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "cython generation passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Cython rejects the syntax error with status 1.";
        "files" = {
          "invalid.pyx" = "cpdef int broken(int):\n    return 42\n";
        };
        "input" = "A Cython function declaration with a missing parameter name.";
        "operation" = "Translate the malformed module to C.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/cython"
              "--3str"
              "--output-file"
              "invalid.c"
              "invalid.pyx"
            ];
            "exit_code" = 1;
            "observes_rejection" = true;
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
    };

    inherit version;

    src = fetchurl {
      urls = [
        "https://files.pythonhosted.org/packages/source/C/Cython/cython-${version}.tar.gz"
      ];
      hash = "sha256-uYi7KXznbGceKMl9AXuVQRAQ98d/pmI90LtH7tGu4bw=";
    };

    buildDeps = [
      python3
      setuptools
    ];
    runtimeDeps = [
      python3
      setuptools
    ];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd cython-${version}
        '';
      }
      {
        name = "install";
        script = ''
          # Direct copy install — Cython is installed as pure Python (without
          # compiling its own .pyx extensions) to avoid bootstrapping problems.
          # The pure-Python fallback works fine for compiling other packages.
          SITE=$out/lib/python3.14/site-packages
          mkdir -p $SITE $out/bin

          cp -r Cython $SITE/
          cp -r pyximport $SITE/
          cp cython.py $SITE/

          # Install CLI scripts
          for script in cython cythonize cygdb; do
            if [ -f bin/$script ]; then
              install -m 755 bin/$script $out/bin/$script
              sed -i "1s|.*|#!${python3}/bin/python3|" $out/bin/$script
            fi
          done

          # Write metadata
          mkdir -p $SITE/Cython-${version}.dist-info
          printf 'Metadata-Version: 2.1\nName: Cython\nVersion: ${version}\n' \
            > $SITE/Cython-${version}.dist-info/METADATA
          printf 'Cython\npyximport\ncython\n' \
            > $SITE/Cython-${version}.dist-info/top_level.txt
          touch $SITE/Cython-${version}.dist-info/INSTALLER
        '';
      }
    ];

    meta = {
      description = "Cython — C extensions compiler for Python";
      homepage = "https://cython.org/";
      license = "Apache-2.0";
    };
  }
