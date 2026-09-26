##! python3-pygdbmi — GDB machine-interface parser for Python
{
  mkDerivation,
  fetchurl,
  python3,
}: let
  version = "0.11.0.0";
  sitePackages = "lib/python3.14/site-packages";
in
  mkDerivation {
    pname = "python3-pygdbmi";
    inherit version;

    src = fetchurl {
      urls = [
        "https://files.pythonhosted.org/packages/source/p/pygdbmi/pygdbmi-${version}.tar.gz"
      ];
      hash = "sha256-eihr4vzyVlDZ9m4RrcRulyzweKRmhkpwDNRHOa0mH7A=";
    };

    buildDeps = [];
    runtimeDeps = [python3];
    propagatedDeps = [python3];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd pygdbmi-${version}
        '';
      }
      {
        name = "install";
        script = ''
          site="$out/${sitePackages}"
          mkdir -p "$site/pygdbmi-${version}.dist-info"
          cp -R pygdbmi "$site/"
          cp LICENSE "$site/pygdbmi-${version}.dist-info/"
          cat > "$site/pygdbmi-${version}.dist-info/METADATA" <<'EOF'
          Metadata-Version: 2.1
          Name: pygdbmi
          Version: ${version}
          License: MIT
          EOF
          printf 'pygdbmi\n' > "$site/pygdbmi-${version}.dist-info/top_level.txt"

          PYTHONPATH="$site" ${python3}/bin/python3 - <<'PYTHON'
          import importlib.metadata
          import pygdbmi.gdbcontroller

          assert importlib.metadata.version("pygdbmi") == "${version}"
          PYTHON
        '';
      }
    ];

    meta = {
      description = "GDB machine-interface parser for Python";
      homepage = "https://github.com/cs01/pygdbmi";
      license = "MIT";
    };
  }
