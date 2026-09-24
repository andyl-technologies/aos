##! python3-markupsafe — Safe markup strings for Python
{
  mkDerivation,
  fetchurl,
  python3,
  setuptools,
  buildPackages,
  stdenv,
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

    buildDeps =
      if stdenv.isCross && stdenv.hostPlatform.isDarwin
      then [buildPackages.python3 buildPackages.setuptools]
      else [python3 setuptools];
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
        script =
          if stdenv.isCross && stdenv.hostPlatform.isDarwin
          then ''
            # Generate distribution metadata on the build machine, then
            # compile the extension against the target Python headers.
            PYTHONPATH=${buildPackages.setuptools}/${sitePackages} \
              ${buildPackages.python3}/bin/python3 setup.py egg_info
            "$CC" -O2 -fPIC -bundle -Wl,-undefined,dynamic_lookup \
              -I${python3}/include/python3.14 \
              -o _speedups.so src/markupsafe/_speedups.c
          ''
          else ''
            export PYTHONPATH=${setuptools}/lib/python3.14/site-packages
            ${python3}/bin/python3 setup.py build
          '';
      }
      {
        name = "install";
        script =
          if stdenv.isCross && stdenv.hostPlatform.isDarwin
          then ''
            mkdir -p "$out/${sitePackages}" "$out/share/licenses/python3-markupsafe"
            cp -R src/markupsafe "$out/${sitePackages}/"
            install -m 755 _speedups.so "$out/${sitePackages}/markupsafe/_speedups.so"
            cp -R src/MarkupSafe.egg-info \
              "$out/${sitePackages}/MarkupSafe-${version}-py3.14.egg-info"
            cp LICENSE.txt "$out/share/licenses/python3-markupsafe/"
          ''
          else ''
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
