##! pip — Python package installer
{
  mkDerivation,
  fetchurl,
  python3,
}: let
  version = "26.2.1";
in
  mkDerivation {
    pname = "pip";
    inherit version;

    src = fetchurl {
      urls = [
        "https://files.pythonhosted.org/packages/source/p/pip/pip-${version}.tar.gz"
      ];
      hash = "sha256-9q1mfomh/ngEbI8TIyskcgD1JY14KPP3iD1mCHjggT8=";
    };

    buildDeps = [python3];
    runtimeDeps = [python3];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd pip-${version}
        '';
      }
      {
        name = "install";
        script = ''
          site=$out/lib/python3.14/site-packages
          mkdir -p "$site" "$out/bin"
          cp -r src/pip "$site/"

          metadata="$site/pip-${version}.dist-info"
          mkdir -p "$metadata"
          cat > "$metadata/METADATA" <<'EOF'
          Metadata-Version: 2.4
          Name: pip
          Version: ${version}
          Requires-Python: >=3.10
          EOF
          cat > "$metadata/entry_points.txt" <<'EOF'
          [console_scripts]
          pip = pip._internal.cli.main:main
          pip3 = pip._internal.cli.main:main
          EOF
          touch "$metadata/INSTALLER"
          cp LICENSE.txt "$metadata/"

          cat > "$out/bin/pip" <<'EOF'
          #!${python3}/bin/python3
          from pip._internal.cli.main import main

          raise SystemExit(main())
          EOF
          chmod +x "$out/bin/pip"
          ln -s pip "$out/bin/pip3"
          ln -s pip "$out/bin/pip3.14"
        '';
      }
      {
        name = "check";
        script = ''
          PYTHONPATH=$out/lib/python3.14/site-packages \
            "$out/bin/pip" --version | grep -F "pip ${version}"
        '';
      }
    ];

    meta = {
      description = "Python package installer";
      homepage = "https://pip.pypa.io/";
      license = "MIT";
    };
  }
