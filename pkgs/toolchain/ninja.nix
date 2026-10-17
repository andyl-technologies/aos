##! ninja — Small build system with a focus on speed
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  bash,
}: let
  version = "1.13.2";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      role = "public-package";
    };
    pname = "ninja";
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
          # Retain sh/POSIX invocation semantics without a host shell path.
          test "$(grep -F -c 'const char* spawned_args[] = { "/bin/sh", "-c", command.c_str(), NULL };' src/subprocess-posix.cc)" -eq 1
          test "$(grep -F -c 'err = posix_spawn(&pid_, "/bin/sh", &action, &attr,' src/subprocess-posix.cc)" -eq 1
          sed -i \
            -e 's|{ "/bin/sh", "-c", command.c_str(), NULL }|{ "sh", "-c", command.c_str(), NULL }|' \
            -e 's|posix_spawn(&pid_, "/bin/sh",|posix_spawn(\&pid_, "${bash}/bin/bash",|' \
            src/subprocess-posix.cc
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
        script = ''
          mkdir shell-dispatch-check
          cd shell-dispatch-check

          cat > build.ninja <<'EOF'
          rule posix_shell
            command = test "$$0" = sh && case ":$$SHELLOPTS:" in *:posix:*) ;; *) exit 1 ;; esac && printf '%s\n' 'hermetic shell dispatch' | tr 'a-z' 'A-Z' > "$out"
          build success: posix_shell
          default success
          EOF

          ../ninja -v
          test "$(cat success)" = 'HERMETIC SHELL DISPATCH'
          ../ninja -v > incremental.log
          grep -F 'ninja: no work to do.' incremental.log

          cat > failure.ninja <<'EOF'
          rule refused
            command = exit 7
          build refused: refused
          EOF

          if ../ninja -f failure.ninja > failure.log 2>&1; then
            cat failure.log
            exit 1
          fi
          grep -F 'FAILED: [code=7] refused' failure.log
          cd ..
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
