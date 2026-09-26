##! pip — Python package installer
{
  lib,
  mkDerivation,
  fetchurl,
  python3,
}: let
  version = "26.2.1";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      role = "public-package";
    };
    pname = "pip";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Pip prints the exact SHA-256 requirement fragment.";
        "files" = {
          "answer.txt" = "answer=42\n";
        };
        "input" = "A local file containing the bytes answer=42 followed by a newline.";
        "operation" = "Hash the file through pip hash.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/pip"
              "hash"
              "answer.txt"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "answer.txt:\n--hash=sha256:24cab0d01b67b184d0a737de3a5b5d47b8b69b36203273296d5ef763f7fdcf68\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Pip rejects the missing input with status 2.";
        "files" = {};
        "input" = "A pathname that does not exist.";
        "operation" = "Hash the missing file through pip hash.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/pip"
              "hash"
              "missing-qualification-file"
            ];
            "exit_code" = 2;
            "observes_rejection" = true;
          }
        ];
      };
    };

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
          import pathlib
          import sys

          # Console scripts must find their own immutable modules without an
          # activation profile or caller-provided PYTHONPATH.
          prefix = pathlib.Path(__file__).resolve().parent.parent
          sys.path.insert(0, str(prefix / "lib/python3.14/site-packages"))
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
          unset PYTHONPATH
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
