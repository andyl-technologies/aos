##! python3-pygments — Syntax highlighting library for Python
{
  mkDerivation,
  fetchurl,
  python3,
}: let
  version = "2.20.0";
  sitePackages = "lib/python3.14/site-packages";
in
  mkDerivation {
    pname = "python3-pygments";
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
