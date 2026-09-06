##! python3-markupsafe — Safe markup strings for Python
{
  mkDerivation,
  fetchurl,
  python3,
  setuptools,
}: let
  version = "3.0.3";
  sitePackages = "lib/python3.14/site-packages";
in
  mkDerivation {
    pname = "python3-markupsafe";
    inherit version;

    src = fetchurl {
      urls = ["https://github.com/pallets/markupsafe/archive/refs/tags/${version}.tar.gz"];
      hash = "sha256-8dnQbDRRXdOtIQ7HadphMFe1NtEdbAORg7h3V6iDolQ=";
    };

    buildDeps = [python3 setuptools];
    runtimeDeps = [python3];
    propagatedDeps = [python3];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd markupsafe-${version}
        '';
      }
      {
        name = "patch";
        script = ''
          # Setuptools 75 implements the table form from the PEP 621 version
          # current when it was released.
          sed -i 's/license = "BSD-3-Clause"/license = { text = "BSD-3-Clause" }/' pyproject.toml
          sed -i '/^license-files =/d' pyproject.toml
        '';
      }
      {
        name = "build";
        script = ''
          export PYTHONPATH=${setuptools}/lib/python3.14/site-packages
          ${python3}/bin/python3 setup.py build
        '';
      }
      {
        name = "install";
        script = ''
          export PYTHONPATH=${setuptools}/lib/python3.14/site-packages
          ${python3}/bin/python3 setup.py install --prefix="$out"
          PYTHONPATH="$out/${sitePackages}" ${python3}/bin/python3 -c \
            'from markupsafe import escape; assert str(escape("<")) == "&lt;"'
        '';
      }
    ];

    meta = {
      description = "Implements safe XML and HTML markup strings for Python";
      homepage = "https://markupsafe.palletsprojects.com/";
      license = "BSD-3-Clause";
    };
  }
