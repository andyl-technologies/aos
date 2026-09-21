##! python3-markdown — Markdown parser for Python
{
  mkDerivation,
  fetchurl,
  python3,
  buildPackages,
}: let
  version = "3.10.2";
  sitePackages = "lib/python3.14/site-packages";
in
  mkDerivation {
    pname = "python3-markdown";
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
