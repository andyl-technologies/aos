##! python3-pycparser — C parser implemented in Python
{
  mkDerivation,
  fetchurl,
  python3,
  setuptools,
}: let
  version = "3.0";
  sitePackages = "lib/python3.14/site-packages";
in
  mkDerivation {
    pname = "python3-pycparser";
    inherit version;

    src = fetchurl {
      urls = [
        "https://files.pythonhosted.org/packages/source/p/pycparser/pycparser-${version}.tar.gz"
      ];
      hash = "sha256-YA9J0hcwSlkCrDw34Sgcn+lOTQSJ3mQ6lQTFzf38ayk=";
    };

    buildDeps = [python3 setuptools];
    runtimeDeps = [python3];
    propagatedDeps = [python3];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd pycparser-${version}
        '';
      }
      {
        name = "build";
        script = ''
          # Setuptools 75 predates the string form of PEP 639 licenses.
          sed -i 's/license = "BSD-3-Clause"/license = { text = "BSD-3-Clause" }/' pyproject.toml
          sed -i '/^license-files =/d' pyproject.toml

          export PYTHONPATH=${setuptools}/${sitePackages}
          ${python3}/bin/python3 setup.py build
        '';
      }
      {
        name = "install";
        script = ''
          export PYTHONPATH=${setuptools}/${sitePackages}
          ${python3}/bin/python3 setup.py install --prefix="$out"

          PYTHONPATH="$out/${sitePackages}" ${python3}/bin/python3 -c \
            'from pycparser import c_parser; c_parser.CParser().parse("int value;")'
        '';
      }
    ];

    meta = {
      description = "C parser implemented in Python";
      homepage = "https://github.com/eliben/pycparser";
      license = "BSD-3-Clause";
    };
  }
