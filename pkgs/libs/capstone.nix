##! Capstone — Multi-architecture disassembly engine
{
  mkDerivation,
  fetchurl,
  gnumake,
  stdenv,
}: let
  version = "5.0.6";
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

    pname = "capstone";
    inherit version;
    src = fetchurl {
      urls = ["https://codeload.github.com/capstone-engine/capstone/tar.gz/refs/tags/${version}"];
      hash = "sha256-JA68g0xRquQcqSFdMZDMNy/RMrnFyKotXxnKDDJeKPk=";
    };

    buildDeps = [gnumake];
    runtimeDeps = [];
    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd capstone-${version}
        '';
      }
      {
        name = "build";
        script = ''make -j"$NIX_BUILD_CORES" SHELL="$CONFIG_SHELL" PREFIX="$out"'';
      }
      {
        name = "check";
        script = ''
          make -j"$NIX_BUILD_CORES" SHELL="$CONFIG_SHELL" PREFIX="$out" check
          # Upstream's check target prints FAILED but exits successfully.
          # Execute every built fixture directly so failures fail the package.
          export LD_LIBRARY_PATH="$PWD"
          test -x tests/test_basic
          for testExecutable in tests/test_*; do
            if test -x "$testExecutable"; then
              "$testExecutable" > /dev/null
            fi
          done
        '';
      }
      {
        name = "install";
        script = ''
          make SHELL="$CONFIG_SHELL" PREFIX="$out" install
          mkdir -p "$out/share/licenses/capstone"
          cp LICENSE.TXT "$out/share/licenses/capstone/LICENSE.TXT"
        '';
      }
    ];

    meta = {
      description = "Multi-architecture disassembly library and command-line tool";
      homepage = "https://www.capstone-engine.org/";
      license = "BSD-3-Clause";
      mainProgram = "cstool";
    };
  }
