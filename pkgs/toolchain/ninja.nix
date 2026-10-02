##! ninja — Small build system with a focus on speed
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
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
    runtimeDeps = [];
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
          # No configure step — ninja is bootstrapped directly from C++ sources
          true
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
