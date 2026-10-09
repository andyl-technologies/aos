##! SCons — Python-based software construction tool
{
  mkDerivation,
  fetchurl,
  bash,
  python3,
  setuptools,
  stdenv,
}: let
  version = "4.10.1";
  sitePackages = "lib/python3.14/site-packages";
in
  mkDerivation {
    platformSupport = {
      build = [
        {
          abi = ["gnu"];
          os = ["linux"];
        }
      ];
      host = [
        {
          abi = ["gnu"];
          cpu = [stdenv.buildPlatform.constraints.cpu];
          os = ["linux"];
        }
      ];
      target = [];
      role = "public-package";
    };

    pname = "scons";
    inherit version;
    src = fetchurl {
      urls = ["https://files.pythonhosted.org/packages/source/s/scons/scons-${version}.tar.gz"];
      hash = "sha256-mcDpSkKiwRgvpoWbC+aXlT2we6k27MmBeuDSGM7SCxU=";
    };

    buildDeps = [python3 setuptools];
    runtimeDeps = [python3 bash];
    PYTHONPATH = "${setuptools}/${sitePackages}";

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd scons-${version}
        '';
      }
      {
        name = "build";
        script = ''${python3}/bin/python3 setup.py build'';
      }
      {
        name = "install";
        script = ''
          ${python3}/bin/python3 setup.py install --prefix="$out"
          for program in scons sconsign scons-configure-cache; do
            mv "$out/bin/$program" "$out/bin/.$program-real"
            cat > "$out/bin/$program" <<EOF
          #!${bash}/bin/bash
          export PYTHONPATH="$out/${sitePackages}\''${PYTHONPATH:+:\$PYTHONPATH}"
          exec "$out/bin/.$program-real" "\$@"
          EOF
            chmod +x "$out/bin/$program"
          done
          mkdir -p "$out/share/licenses/scons"
          cp LICENSE "$out/share/licenses/scons/LICENSE"
        '';
      }
      {
        name = "check";
        script = ''
          PYTHONPATH="$out/${sitePackages}" "$out/bin/scons" --version
          mkdir package-check
          cd package-check
          cat > SConstruct <<'PY'
          env = Environment()
          env.Command('answer.txt', [], "${python3}/bin/python3 -c 'print(19 + 23)' > $TARGET")
          PY
          PYTHONPATH="$out/${sitePackages}" "$out/bin/scons" --no-site-dir -Q
          test "$(cat answer.txt)" = 42
        '';
      }
    ];

    meta = {
      description = "Python-based dependency-aware software construction tool";
      homepage = "https://scons.org/";
      license = "MIT";
      mainProgram = "scons";
    };
  }
