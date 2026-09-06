##! python3-mako — Mako template language for Python
{
  mkDerivation,
  fetchurl,
  python3,
  python3-markupsafe,
}: let
  version = "1.3.10";
  sitePackages = "lib/python3.14/site-packages";
in
  mkDerivation {
    pname = "python3-mako";
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
          PYTHONPATH="$out/${sitePackages}:${python3-markupsafe}/${sitePackages}" \
            ${python3}/bin/python3 -c \
            'from mako.template import Template; assert Template("hello ''${name}").render(name="world") == "hello world"'
        '';
      }
    ];

    meta = {
      description = "Fast template language for Python";
      homepage = "https://www.makotemplates.org/";
      license = "MIT";
    };
  }
