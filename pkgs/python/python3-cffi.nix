##! python3-cffi — Foreign-function interface for Python
{
  mkDerivation,
  fetchurl,
  python3,
  setuptools,
  pkg-config,
  libffi,
  python3-pycparser,
}: let
  version = "2.1.1";
  sitePackages = "lib/python3.14/site-packages";
  pythonPath = "${setuptools}/${sitePackages}:${python3-pycparser}/${sitePackages}";
in
  mkDerivation {
    pname = "python3-cffi";
    inherit version;

    src = fetchurl {
      urls = [
        "https://files.pythonhosted.org/packages/source/c/cffi/cffi-${version}.tar.gz"
      ];
      hash = "sha256-3TH1LqEIZRO7nfMPj87puJGDI64Gej1beLyCagAHEr4=";
    };

    buildDeps = [python3 setuptools pkg-config];
    runtimeDeps = [python3 libffi python3-pycparser];
    propagatedDeps = [python3 libffi python3-pycparser];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd cffi-${version}
        '';
      }
      {
        name = "build";
        script = ''
          # Setuptools 75 predates the string form of PEP 639 licenses.
          sed -i 's/license = "MIT-0"/license = { text = "MIT-0" }/' pyproject.toml
          sed -i '/^license-files =/d' pyproject.toml

          export PYTHONPATH=${pythonPath}
          ${python3}/bin/python3 setup.py build
        '';
      }
      {
        name = "install";
        script = ''
          export PYTHONPATH=${pythonPath}
          ${python3}/bin/python3 setup.py install --prefix="$out"

          PYTHONPATH="$out/${sitePackages}:${python3-pycparser}/${sitePackages}" \
            ${python3}/bin/python3 -c \
              'from cffi import FFI; assert FFI().typeof("int").cname == "int"'
        '';
      }
    ];

    meta = {
      description = "Foreign-function interface for calling C code from Python";
      homepage = "https://cffi.readthedocs.io/";
      license = "MIT-0";
    };
  }
