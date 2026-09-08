##! wheel — Python wheel archive utility
{
  mkDerivation,
  fetchurl,
  python3,
  packaging,
}: let
  version = "0.48.0";
in
  mkDerivation {
    pname = "wheel";
    inherit version;

    src = fetchurl {
      urls = [
        "https://files.pythonhosted.org/packages/source/w/wheel/wheel-${version}.tar.gz"
      ];
      hash = "sha256-lIAHZWAekXG/XVjQZuZAZihCvO3Lq5grLJB4eiyYcyI=";
    };

    buildDeps = [python3];
    runtimeDeps = [
      python3
      packaging
    ];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd wheel-${version}
        '';
      }
      {
        name = "install";
        script = ''
          site=$out/lib/python3.14/site-packages
          mkdir -p "$site" "$out/bin"
          cp -r src/wheel "$site/"

          metadata="$site/wheel-${version}.dist-info"
          mkdir -p "$metadata"
          cat > "$metadata/METADATA" <<'EOF'
          Metadata-Version: 2.4
          Name: wheel
          Version: ${version}
          Requires-Python: >=3.9
          Requires-Dist: packaging >=24.0
          EOF
          cat > "$metadata/entry_points.txt" <<'EOF'
          [console_scripts]
          wheel = wheel._commands:main

          [distutils.commands]
          bdist_wheel = wheel.bdist_wheel:bdist_wheel
          EOF
          touch "$metadata/INSTALLER"
          cp LICENSE.txt "$metadata/"

          cat > "$out/bin/wheel" <<'EOF'
          #!${python3}/bin/python3
          from wheel._commands import main

          raise SystemExit(main())
          EOF
          chmod +x "$out/bin/wheel"
        '';
      }
      {
        name = "check";
        script = ''
          PYTHONPATH=$out/lib/python3.14/site-packages:${packaging}/lib/python3.14/site-packages \
            "$out/bin/wheel" version | grep -F "wheel ${version}"
        '';
      }
    ];

    meta = {
      description = "Command-line tool for manipulating Python wheel archives";
      homepage = "https://wheel.readthedocs.io/";
      license = "MIT";
    };
  }
