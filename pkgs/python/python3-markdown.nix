##! python3-markdown — Markdown parser for Python
{
  mkDerivation,
  fetchurl,
  python3,
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

    buildDeps = [];
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
        name = "install";
        script = ''
          mkdir -p "$out/${sitePackages}" "$out/bin"
          cp -R markdown "$out/${sitePackages}/"
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
