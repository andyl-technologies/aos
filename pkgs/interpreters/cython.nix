##! Cython — C extensions for Python
{
  mkDerivation,
  fetchurl,
  python3,
  setuptools,
}: let
  version = "3.0.12";
in
  mkDerivation {
    pname = "cython";
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
          SITE=$out/lib/python3.12/site-packages
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
