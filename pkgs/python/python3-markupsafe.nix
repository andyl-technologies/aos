##! python3-markupsafe — Safe markup strings for Python
{
  lib,
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
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      role = "public-package";
    };
    pname = "python3-markupsafe";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "MarkupSafe emits the exact entity-escaped representation.";
        "files" = {
          "probe.py" = "import glob\nimport sys\n\nlocations = glob.glob(\"@out@/lib/python*/site-packages\")\nif len(locations) != 1:\n    raise RuntimeError(\"package does not expose one site-packages directory\")\nsys.path.insert(0, locations[0])\n\nfrom markupsafe import escape\nassert str(escape(\"<answer>42 & more</answer>\")) == \"&lt;answer&gt;42 &amp; more&lt;/answer&gt;\"\n\nprint(\"python3-markupsafe primary passed\")\n";
        };
        "input" = "HTML markup containing an element and ampersand.";
        "operation" = "Escape the text through markupsafe.escape.";
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
              "exact" = "python3-markupsafe primary passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "MarkupSafe rejects the conversion with ValueError.";
        "files" = {
          "probe.py" = "import glob\nimport sys\n\nlocations = glob.glob(\"@out@/lib/python*/site-packages\")\nif len(locations) != 1:\n    raise RuntimeError(\"package does not expose one site-packages directory\")\nsys.path.insert(0, locations[0])\n\nfrom markupsafe import Markup\ntry:\n    Markup(\"{value!z}\").format(value=\"answer\")\nexcept ValueError:\n    pass\nelse:\n    raise RuntimeError(\"MarkupSafe accepted an invalid conversion\")\n\nprint(\"python3-markupsafe rejected invalid input\", file=sys.stderr)\nraise SystemExit(7)\n";
        };
        "input" = "A safe-format template containing an unsupported conversion specifier.";
        "operation" = "Format the malformed template through Markup.format.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "probe.py"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "python3-markupsafe rejected invalid input\n";
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
