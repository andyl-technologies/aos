##! python3-lxml — Python bindings for libxml2 and libxslt
{
  mkDerivation,
  fetchurl,
  python3,
  setuptools,
  cython,
  pkg-config,
  libxml2,
  libxslt,
  zlib,
}: let
  version = "6.0.2";
  sitePackages = "lib/python3.14/site-packages";
in
  mkDerivation {
    pname = "python3-lxml";
    inherit version;

    src = fetchurl {
      urls = ["https://github.com/lxml/lxml/archive/refs/tags/lxml-${version}.tar.gz"];
      hash = "sha256-IfKTH8GqPCbyyqQHQundSR08No8c7sPDQZKav/MCNTU=";
    };

    buildDeps = [python3 setuptools cython pkg-config];
    runtimeDeps = [python3 libxml2 libxslt zlib];
    propagatedDeps = [python3 libxml2 libxslt zlib];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd lxml-lxml-${version}
        '';
      }
      {
        name = "patch";
        script = ''
          sed -i 's/Cython>=3.1.4/Cython/' pyproject.toml
        '';
      }
      {
        name = "build";
        script = ''
          export PYTHONPATH=${setuptools}/lib/python3.14/site-packages:${cython}/lib/python3.14/site-packages
          ${python3}/bin/python3 setup.py build --with-cython
        '';
      }
      {
        name = "install";
        script = ''
          export PYTHONPATH=${setuptools}/lib/python3.14/site-packages:${cython}/lib/python3.14/site-packages
          ${python3}/bin/python3 setup.py install --prefix="$out"
          PYTHONPATH="$out/${sitePackages}" ${python3}/bin/python3 -c \
            'from lxml import etree; assert etree.fromstring(b"<a/>").tag == "a"'
        '';
      }
    ];

    meta = {
      description = "Pythonic binding for libxml2 and libxslt";
      homepage = "https://lxml.de/";
      license = "BSD-3-Clause";
    };
  }
