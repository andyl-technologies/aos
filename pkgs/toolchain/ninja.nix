##! ninja — Small build system with a focus on speed
{
  mkDerivation,
  fetchurl,
  gnumake,
  bash,
  lib,
  stdenv,
}: let
  version = "1.13.2";
in
  mkDerivation {
    pname = "ninja";
    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/ninja-build/ninja/archive/v${version}/ninja-${version}.tar.gz"
      ];
      hash = "sha256-l01rL07u+iViXTTaPLNr3Ovn+85A9MFqwINf0cDLrhc=";
    };

    buildDeps = [gnumake];
    runtimeDeps = [bash];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd ninja-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          # Ninja's POSIX runner invokes this shell for every build command.
          # Pin it to the packaged interpreter available in the sandbox.
          sed -i 's|"/bin/sh"|"${bash}/bin/bash"|g' src/subprocess-posix.cc
          grep -F '"${bash}/bin/bash"' src/subprocess-posix.cc
        '';
      }
      {
        name = "build";
        script = ''
          # Remove bundled getopt (conflicts with glibc's C++ declarations)
          # and browse.cc (needs generated browse_py.h).
          # Linux provides getopt via <unistd.h>; browse is optional.
          rm -f src/getopt.h src/getopt.cc src/browse.cc

          # Bootstrap ninja without python by compiling POSIX sources directly.
          # Skip: Windows files, test files.
          srcs=""
          for f in src/*.cc; do
            case "$f" in
              *msvc*|*win32*|*includes_normalize-win32*) continue ;;
              *_test.cc|*_perftest.cc|*/test.cc) continue ;;
              *.in.cc) continue ;;
              */hash_collision_bench.cc) continue ;;
              *) srcs="$srcs $f" ;;
            esac
          done
          $CXX ''${CXXFLAGS:-} -Isrc -o ninja $srcs -lpthread
        '';
      }
      {
        name = "check";
        script = lib.optionalString (!stdenv.isCross) ''
          cat > "$TMPDIR/ninja-shell-check.ninja" <<'EOF'
          rule shell_check
            command = printf '%s' hermetic-shell > $out
          build ninja-shell-result: shell_check
          EOF
          ./ninja -f "$TMPDIR/ninja-shell-check.ninja"
          test "$(cat ninja-shell-result)" = hermetic-shell
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p $out/bin
          install -m 755 ninja $out/bin/ninja
        '';
      }
    ];

    meta = {
      description = "Small build system with a focus on speed";
      homepage = "https://ninja-build.org/";
      license = "Apache-2.0";
    };
  }
