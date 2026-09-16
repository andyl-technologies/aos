##! wheel — Python wheel archive utility
{
  lib,
  mkDerivation,
  fetchurl,
  python3,
  packaging,
}: let
  version = "0.48.0";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      role = "public-package";
    };
    pname = "wheel";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "WheelFile preserves the member bytes and emits the wheel RECORD metadata.";
        "files" = {
          "probe.py" = "import glob\nimport sys\n\nlocations = glob.glob(\"@out@/lib/python*/site-packages\")\nassert len(locations) == 1\nsys.path.insert(0, locations[0])\n\nfrom wheel.wheelfile import WheelFile\n\nwheel_path = \"answer-1.0-py3-none-any.whl\"\nwith WheelFile(wheel_path, \"w\") as archive:\n    archive.writestr(\"answer/__init__.py\", b\"VALUE = 42\\n\")\nwith WheelFile(wheel_path) as archive:\n    assert archive.read(\"answer/__init__.py\") == b\"VALUE = 42\\n\"\n    assert \"answer-1.0.dist-info/RECORD\" in archive.namelist()\nprint(\"wheel archive passed\")\n";
        };
        "input" = "A Python module payload written through WheelFile.";
        "operation" = "Create a wheel archive through the packaged API, reopen it, and read the module bytes.";
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
              "exact" = "wheel archive passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "WheelFile propagates BadZipFile for the invalid container.";
        "files" = {
          "broken-1.0-py3-none-any.whl" = "not a wheel archive\n";
          "probe.py" = "import glob\nimport sys\nimport zipfile\n\nlocations = glob.glob(\"@out@/lib/python*/site-packages\")\nassert len(locations) == 1\nsys.path.insert(0, locations[0])\n\nfrom wheel.wheelfile import WheelFile\n\ntry:\n    WheelFile(\"broken-1.0-py3-none-any.whl\")\nexcept zipfile.BadZipFile:\n    print(\"wheel rejected invalid archive\")\nelse:\n    raise RuntimeError(\"WheelFile accepted an invalid archive\")\n";
        };
        "input" = "A wheel-shaped filename containing plain text rather than a ZIP archive.";
        "operation" = "Open the malformed archive through WheelFile.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "probe.py"
            ];
            "exit_code" = 0;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "wheel rejected invalid archive\n";
            };
          }
        ];
      };
    };

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
