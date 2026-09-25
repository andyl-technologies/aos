##! python3-mako — Mako template language for Python
{
  lib,
  mkDerivation,
  fetchurl,
  python3,
  python3-markupsafe,
  stdenv,
}: let
  version = "1.3.10";
  sitePackages = "lib/python3.14/site-packages";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      role = "public-package";
    };
    pname = "python3-mako";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The rendered output is the exact string answer=42.";
        "files" = {
          "probe.py" = "import glob\nimport sys\n\nlocations = glob.glob(\"@out@/lib/python*/site-packages\")\nif len(locations) != 1:\n    raise RuntimeError(\"package does not expose one Python site-packages directory\")\nsys.path.insert(0, locations[0])\n\nfrom mako.template import Template\nassert Template(\"answer=\${left + right}\").render(left=19, right=23) == \"answer=42\"\n\nprint(\"python3-mako primary passed\")\n";
        };
        "input" = "A template adding two supplied integer values.";
        "operation" = "Compile and render the template through Mako.";
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
              "exact" = "python3-mako primary passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Mako raises its template SyntaxException.";
        "files" = {
          "probe.py" = "import glob\nimport sys\n\nlocations = glob.glob(\"@out@/lib/python*/site-packages\")\nif len(locations) != 1:\n    raise RuntimeError(\"package does not expose one Python site-packages directory\")\nsys.path.insert(0, locations[0])\n\nfrom mako import exceptions\nfrom mako.template import Template\ntry:\n    Template(\"answer=\${unclosed\")\nexcept exceptions.SyntaxException:\n    pass\nelse:\n    raise RuntimeError(\"Mako accepted malformed template syntax\")\n\nprint(\"python3-mako rejected invalid input\", file=sys.stderr)\nraise SystemExit(7)\n";
        };
        "input" = "A template expression with an unclosed delimiter.";
        "operation" = "Compile the malformed template through Mako.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "probe.py"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "python3-mako rejected invalid input\n";
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
      urls = ["https://github.com/sqlalchemy/mako/archive/refs/tags/rel_1_3_10.tar.gz"];
      hash = "sha256-6PEzSQRhHVyzV7Y5Z5D9Q3WsIa2QH0MU0iLV1XWJebk=";
    };

    buildDeps = [];
    runtimeDeps = [python3 python3-markupsafe];
    propagatedDeps = [python3 python3-markupsafe];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd mako-rel_1_3_10
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out/${sitePackages}" "$out/bin"
          cp -R mako "$out/${sitePackages}/"
          cat > "$out/bin/mako-render" <<'PY'
          #!${python3}/bin/python3
          import sys
          sys.path.insert(0, "${builtins.placeholder "out"}/${sitePackages}")
          sys.path.insert(0, "${python3-markupsafe}/${sitePackages}")
          from mako.cmd import cmdline
          cmdline()
          PY
          chmod 0755 "$out/bin/mako-render"
          ${
            if stdenv.isCross
            then ""
            else ''
              # This import check requires a native Python interpreter.
              PYTHONPATH="$out/${sitePackages}:${python3-markupsafe}/${sitePackages}" \
                ${python3}/bin/python3 -c \
                'from mako.template import Template; assert Template("hello ''${name}").render(name="world") == "hello world"'
            ''
          }
        '';
      }
    ];

    meta = {
      description = "Fast template language for Python";
      homepage = "https://www.makotemplates.org/";
      license = "MIT";
    };
  }
