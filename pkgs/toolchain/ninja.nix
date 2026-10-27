##! ninja — Small build system with a focus on speed
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  bash,
  patch,
  stdenv,
}: let
  version = "1.13.2";
  recipe = ./ninja.nix;
  shellPatch = ./ninja-aos-shell.patch;
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
          cpu = ["x86_64" "aarch64"];
          os = ["linux"];
        }
        {
          abi = ["darwin"];
          cpu = ["x86_64" "aarch64"];
          os = ["darwin"];
        }
      ];
      target = [
        {
          abi = ["gnu"];
          cpu = ["x86_64" "aarch64"];
          os = ["linux"];
        }
        {
          abi = ["darwin"];
          cpu = ["x86_64" "aarch64"];
          os = ["darwin"];
        }
      ];
      role = "public-package";
    };
    pname = "ninja";
    outputs = ["out" "source"];
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [
          {
            "path" = "answer.txt";
            "text" = "answer=42";
          }
        ];
        "expected" = "Ninja creates the exact declared output artifact.";
        "files" = {
          "build.ninja" = "rule answer\n  command = @bash@ -c \"printf answer=42 > $out\"\nbuild answer.txt: answer\ndefault answer.txt\n";
        };
        "input" = "A Ninja graph whose sole rule writes answer=42.";
        "operation" = "Execute the default edge through Ninja.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/ninja"
              "-f"
              "build.ninja"
            ];
            "exit_code" = 0;
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Ninja rejects the graph with status 1.";
        "files" = {
          "build.ninja" = "build answer.txt answer\n";
        };
        "input" = "A Ninja build edge missing the colon after its output.";
        "operation" = "Parse the malformed build graph through Ninja.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/ninja"
              "-f"
              "build.ninja"
            ];
            "exit_code" = 1;
            "observes_rejection" = true;
          }
        ];
      };
    };

    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/ninja-build/ninja/archive/v${version}/ninja-${version}.tar.gz"
      ];
      hash = "sha256-l01rL07u+iViXTTaPLNr3Ovn+85A9MFqwINf0cDLrhc=";
    };

    buildDeps = [gnumake bash patch];
    runtimeDeps = [bash];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar --no-same-owner -xf "$src"
          cd ninja-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          # Pin both sides of the source change; no fuzz or shell fallback is
          # permitted when an upstream launcher changes.
          printf '%s  %s\n' \
            a9a4ea4280ac4e9e3d275dc4458c30baf0c067c8cd51b3c6d2034fe6eab88fdc \
            src/subprocess-posix.cc | sha256sum --check --status
          ${patch}/bin/patch --batch --fuzz=0 -p1 < ${shellPatch}
          printf '%s  %s\n' \
            ad0a0bee985acbc592479b022b568ed51b98e48e0a087c431cfcca4a0256652d \
            src/subprocess-posix.cc | sha256sum --check --status

          # Retain every original file before the existing bootstrap exclusions.
          tar -czf ../ninja-patched-source.tar.gz .
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
          printf '%s\n' "$CXX" "''${CXXFLAGS:-}" \
            '-DAOS_NINJA_COMMAND_SHELL="${bash}/bin/bash"' \
            "$srcs" > ../ninja-build-inputs.txt
          $CXX ''${CXXFLAGS:-} \
            '-DAOS_NINJA_COMMAND_SHELL="${bash}/bin/bash"' \
            -Isrc -o ninja $srcs -lpthread
        '';
      }
      {
        name = "check";
        script = lib.optionalString (!stdenv.isCross) ''
          mkdir shell-check
          cat > shell-check/build.ninja <<'EOF'
          rule shell
            command = test -n "$$BASH_VERSION" && test "$$0" = sh && printf 'answer=42' > answer.txt; if test -e /proc/$$$$/exe; then readlink /proc/$$$$/exe > shell-path.txt; fi; :
          rule console_shell
            command = test -n "$$BASH_VERSION" && test "$$0" = sh && printf 'console=42' > console.txt; if test -e /proc/$$$$/exe; then readlink /proc/$$$$/exe > console-path.txt; fi; :
            pool = console
          build answer.txt: shell
          build console.txt: console_shell
          default answer.txt console.txt
          EOF
          SHELL=/aos-test-must-not-use-env-shell ./ninja -C shell-check -j1
          test "$(cat shell-check/answer.txt)" = answer=42
          test "$(cat shell-check/console.txt)" = console=42
          if test -e /proc/self/exe; then
            test "$(cat shell-check/shell-path.txt)" = '${bash}/bin/bash'
            test "$(cat shell-check/console-path.txt)" = '${bash}/bin/bash'
          fi

          # A failing command must still fail its build edge.
          cat > shell-check/failure.ninja <<'EOF'
          rule fail
            command = exit 33
          build rejected: fail
          EOF
          if ./ninja -C shell-check -f failure.ninja; then
            echo 'Ninja accepted a failing command' >&2
            exit 1
          else
            test "$?" = 33
          fi
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p $out/bin
          install -m 755 ninja $out/bin/ninja

          source_root="$source/share/ninja-source"
          mkdir -p "$source_root" "$out/share/ninja"
          cp "$src" "$source_root/ninja-${version}.tar.gz"
          cp ../ninja-patched-source.tar.gz ../ninja-build-inputs.txt COPYING \
            "$source_root/"
          cp ${recipe} "$source_root/ninja.nix"
          cp ${shellPatch} "$source_root/ninja-aos-shell.patch"
          ln -s "$source" "$out/share/ninja/source"
        '';
      }
    ];

    meta = {
      description = "Small build system with a focus on speed";
      homepage = "https://ninja-build.org/";
      license = "Apache-2.0";
    };
  }
