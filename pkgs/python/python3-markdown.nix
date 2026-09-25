##! python3-markdown — Markdown parser for Python
{
  lib,
  mkDerivation,
  fetchurl,
  python3,
  buildPackages,
  stdenv,
}: let
  version = "3.10.2";
  sitePackages = "lib/python3.14/site-packages";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      role = "public-package";
    };
    pname = "python3-markdown";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The renderer emits the expected h1 and emphasis elements.";
        "files" = {
          "probe.py" = "import glob\nimport sys\n\nlocations = glob.glob(\"@out@/lib/python*/site-packages\")\nif len(locations) != 1:\n    raise RuntimeError(\"package does not expose one Python site-packages directory\")\nsys.path.insert(0, locations[0])\n\nimport markdown\nassert markdown.markdown(\"# Result\\n\\n*42*\") == \"<h1>Result</h1>\\n<p><em>42</em></p>\"\n\nprint(\"python3-markdown primary passed\")\n";
        };
        "input" = "A Markdown heading and emphasized answer.";
        "operation" = "Render the source through markdown.markdown.";
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
              "exact" = "python3-markdown primary passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Markdown rejects configuration by raising ModuleNotFoundError.";
        "files" = {
          "probe.py" = "import glob\nimport sys\n\nlocations = glob.glob(\"@out@/lib/python*/site-packages\")\nif len(locations) != 1:\n    raise RuntimeError(\"package does not expose one Python site-packages directory\")\nsys.path.insert(0, locations[0])\n\nimport markdown\ntry:\n    markdown.markdown(\"text\", extensions=[\"qualification_extension_does_not_exist\"])\nexcept ModuleNotFoundError:\n    pass\nelse:\n    raise RuntimeError(\"Markdown accepted a missing extension\")\n\nprint(\"python3-markdown rejected invalid input\", file=sys.stderr)\nraise SystemExit(7)\n";
        };
        "input" = "An extension module name that cannot be imported.";
        "operation" = "Configure the renderer with the nonexistent extension.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "probe.py"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "python3-markdown rejected invalid input\n";
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
      urls = ["https://github.com/Python-Markdown/markdown/archive/refs/tags/${version}.tar.gz"];
      hash = "sha256-n0y1JAlIOVg/2vdIDl2puf6SxFvIxYKGFV4tFLdNTx4=";
    };

    buildDeps = [buildPackages.python3 buildPackages.setuptools];
    runtimeDeps = [python3];
    propagatedDeps = [python3];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd markdown-${version}
        '';
      }
      {
        name = "build";
        script = ''
          # Build through the declared backend so extension entry points and
          # distribution metadata remain synchronized with upstream.
          PYTHONPATH=${buildPackages.setuptools}/${sitePackages} \
            ${buildPackages.python3}/bin/python3 -c \
              'from setuptools.build_meta import build_wheel; build_wheel("dist")'
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out/${sitePackages}" "$out/bin"
          ${buildPackages.python3}/bin/python3 - <<'PY'
          import os
          from pathlib import Path
          from zipfile import ZipFile

          wheel, = Path("dist").glob("*.whl")
          with ZipFile(wheel) as archive:
              archive.extractall(Path(os.environ["out"]) / "${sitePackages}")
          PY
          cat > "$out/bin/markdown_py" <<'PY'
          #!${python3}/bin/python3
          import sys
          sys.path.insert(0, "${builtins.placeholder "out"}/${sitePackages}")
          from markdown.__main__ import run
          run()
          PY
          chmod 0755 "$out/bin/markdown_py"
          ${
            if stdenv.isCross
            then ""
            else ''
              # These import checks execute the installed interpreter on native builds.
              PYTHONPATH="$out/${sitePackages}" ${python3}/bin/python3 -c \
                'import markdown; assert markdown.markdown("# Title") == "<h1>Title</h1>"'
              # Short extension names resolve through installed entry-point metadata.
              PYTHONPATH="$out/${sitePackages}" ${python3}/bin/python3 - <<'PY'
              import importlib.metadata
              import markdown

              extensions = importlib.metadata.entry_points(group="markdown.extensions")
              assert {"codehilite", "fenced_code", "toc", "tables"} <= {entry.name for entry in extensions}
              for entry in extensions:
                  entry.load()
              rendered = markdown.markdown("# Title\n\n```python\nprint(1)\n```", extensions=["codehilite", "fenced_code", "toc"])
              assert '<h1 id="title">Title</h1>' in rendered
              assert "print(1)" in rendered
              PY
            ''
          }
        '';
      }
    ];

    meta = {
      description = "Python implementation of the Markdown markup language";
      homepage = "https://python-markdown.github.io/";
      license = "BSD-3-Clause";
      mainProgram = "markdown_py";
    };
  }
