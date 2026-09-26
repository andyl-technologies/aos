##! python3-pygments — Syntax highlighting library for Python
{
  lib,
  mkDerivation,
  fetchurl,
  python3,
}: let
  version = "2.20.0";
  sitePackages = "lib/python3.14/site-packages";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      role = "public-package";
    };
    pname = "python3-pygments";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The tokens include the name answer and integer literal 42.";
        "files" = {
          "probe.py" = "import glob\nimport sys\n\nlocations = glob.glob(\"@out@/lib/python*/site-packages\")\nif len(locations) != 1:\n    raise RuntimeError(\"package does not expose one Python site-packages directory\")\nsys.path.insert(0, locations[0])\n\nfrom pygments import lex\nfrom pygments.lexers import PythonLexer\nfrom pygments.token import Name, Number\ntokens = list(lex(\"answer = 42\\n\", PythonLexer()))\nassert (Name, \"answer\") in tokens\nassert (Number.Integer, \"42\") in tokens\n\nprint(\"python3-pygments primary passed\")\n";
        };
        "input" = "A Python assignment token stream.";
        "operation" = "Lex the source with Pygments' Python lexer.";
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
              "exact" = "python3-pygments primary passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Pygments rejects the alias by raising ClassNotFound.";
        "files" = {
          "probe.py" = "import glob\nimport sys\n\nlocations = glob.glob(\"@out@/lib/python*/site-packages\")\nif len(locations) != 1:\n    raise RuntimeError(\"package does not expose one Python site-packages directory\")\nsys.path.insert(0, locations[0])\n\nfrom pygments.lexers import get_lexer_by_name\nfrom pygments.util import ClassNotFound\ntry:\n    get_lexer_by_name(\"qualification-lexer-does-not-exist\")\nexcept ClassNotFound:\n    pass\nelse:\n    raise RuntimeError(\"Pygments accepted an unknown lexer\")\n\nprint(\"python3-pygments rejected invalid input\", file=sys.stderr)\nraise SystemExit(7)\n";
        };
        "input" = "A lexer alias that is not registered.";
        "operation" = "Resolve the unknown alias through get_lexer_by_name.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "probe.py"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "python3-pygments rejected invalid input\n";
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
      urls = ["https://files.pythonhosted.org/packages/source/p/pygments/pygments-${version}.tar.gz"];
      hash = "sha256-Z1fNA3aAU/+Z8wOcGjbWwKoLJjQ4/KsXUgswowOoK18=";
    };

    buildDeps = [];
    runtimeDeps = [python3];
    propagatedDeps = [python3];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd pygments-${version}
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out/${sitePackages}" "$out/bin"
          cp -R pygments "$out/${sitePackages}/"
          cat > "$out/bin/pygmentize" <<'PY'
          #!${python3}/bin/python3
          import sys
          sys.path.insert(0, "${builtins.placeholder "out"}/${sitePackages}")
          from pygments.cmdline import main
          raise SystemExit(main(sys.argv))
          PY
          chmod 0755 "$out/bin/pygmentize"
          "$out/bin/pygmentize" -V
        '';
      }
    ];

    meta = {
      description = "Generic syntax highlighter written in Python";
      homepage = "https://pygments.org/";
      license = "BSD-2-Clause";
      mainProgram = "pygmentize";
    };
  }
