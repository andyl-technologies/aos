##! python3-lxml — Python bindings for libxml2 and libxslt
{
  lib,
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
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      role = "public-package";
    };
    pname = "python3-lxml";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The selected element contains the text 42.";
        "files" = {
          "probe.py" = "import glob\nimport sys\n\nlocations = glob.glob(\"@out@/lib/python*/site-packages\")\nif len(locations) != 1:\n    raise RuntimeError(\"package does not expose one Python site-packages directory\")\nsys.path.insert(0, locations[0])\n\nfrom lxml import etree\nroot = etree.fromstring(b\"<root><answer>42</answer></root>\")\nassert root.findtext(\"answer\") == \"42\"\n\nprint(\"python3-lxml primary passed\")\n";
        };
        "input" = "An XML document containing an integer answer element.";
        "operation" = "Parse the bytes and select the element through lxml.etree.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "probe.py"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "python3-lxml primary passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "lxml raises XMLSyntaxError and produces no accepted tree.";
        "files" = {
          "probe.py" = "import glob\nimport sys\n\nlocations = glob.glob(\"@out@/lib/python*/site-packages\")\nif len(locations) != 1:\n    raise RuntimeError(\"package does not expose one Python site-packages directory\")\nsys.path.insert(0, locations[0])\n\nfrom lxml import etree\ntry:\n    etree.fromstring(b\"<open></closed>\")\nexcept etree.XMLSyntaxError:\n    pass\nelse:\n    raise RuntimeError(\"lxml accepted malformed XML\")\n\nprint(\"python3-lxml rejected invalid input\", file=sys.stderr)\nraise SystemExit(7)\n";
        };
        "input" = "An XML document with mismatched tags.";
        "operation" = "Parse the malformed document through lxml.etree.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "probe.py"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "python3-lxml rejected invalid input\n";
            };
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
    };

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
