##! abseil-cpp — Common C++ libraries used by Protocol Buffers
{
  lib,
  mkDerivation,
  mkGithubUpstream,
  cmake,
  gnumake,
  stdenv,
}: let
  upstream = mkGithubUpstream {
    unitId = "abseil-cpp";
    family = "abseil-cpp";
    stream = "release-train";
    owner = "pkgs/libs/abseil-cpp.nix";
    classification = "assisted";
    version = "20260817.0";
    upstreamId = "20260817.0";
    repository = "abseil/abseil-cpp";
    provider = "github-releases";
    versionScheme = "numeric";
    riskFloor = "high";
    source = {
      authority = "github.com";
      path = [
        "abseil"
        "abseil-cpp"
        "archive"
        "refs"
        "tags"
        {
          parts = [
            {
              componentField = {
                component = "main";
                field = "comparisonVersion";
              };
            }
            {literal = ".tar.gz";}
          ];
        }
      ];
      hash = "sha256-9+BRed85xFQ0ytQz9Xg4QLs3iO8yKXb5E4vGtys6EH0=";
    };
  };
  inherit (upstream) version;
in
  mkDerivation {
    pname = "abseil-cpp";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The public API returns the expected value and the consumer prints the fixed success line.";
        "files" = {
          "primary.cc" = "#include <iostream>\n#include \"absl/strings/numbers.h\"\n\nint main() {\n    int value = 0;\n    if (!absl::SimpleAtoi(\"42\", &value) || value != 42) {\n        return 2;\n    }\n    std::cout << \"abseil-cpp api passed\\n\";\n}\n";
        };
        "input" = "The decimal string 42.";
        "operation" = "Parse the string with absl::SimpleAtoi and verify the integer result.";
        "steps" = [
          {
            "argv" = [
              "@cxx@"
              "primary.cc"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-labsl_strings"
              "-labsl_base"
              "-o"
              "primary-consumer"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "";
            };
          }
          {
            "argv" = [
              "@work@/primary/primary-consumer"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "abseil-cpp api passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "The public API reports rejection and the consumer exits with the fixed rejection status and diagnostic.";
        "files" = {
          "bad-input.cc" = "#include <iostream>\n#include \"absl/strings/numbers.h\"\n\nint main() {\n    int value = 0;\n    if (absl::SimpleAtoi(\"42x\", &value)) {\n        return 2;\n    }\n    std::cerr << \"abseil-cpp rejected invalid input\\n\";\n    return 7;\n}\n";
        };
        "input" = "A decimal string with trailing alphabetic data.";
        "operation" = "Parse the malformed integer with absl::SimpleAtoi.";
        "steps" = [
          {
            "argv" = [
              "@cxx@"
              "bad-input.cc"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-labsl_strings"
              "-labsl_base"
              "-o"
              "bad-input-consumer"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "";
            };
          }
          {
            "argv" = [
              "@work@/bad-input/bad-input-consumer"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "abseil-cpp rejected invalid input\n";
            };
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
    };

    inherit version;

    src = upstream.components.main.sources.source;
    update = upstream.update;

    buildDeps = [
      cmake
      gnumake
    ];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script =
          if stdenv.isCross && stdenv.hostPlatform.isDarwin
          then ''
            tar xf $src
            cd abseil-cpp-${version}

            # Apple's multi-architecture -Xarch forwarding is only valid for
            # native universal builds. A single-architecture cross compiler
            # must select the flags from CMAKE_SYSTEM_PROCESSOR.
            sed -i \
              's/if(APPLE AND CMAKE_CXX_COMPILER_ID MATCHES \[\[Clang\]\])/if(APPLE AND CMAKE_CXX_COMPILER_ID MATCHES [[Clang]] AND NOT CMAKE_CROSSCOMPILING)/' \
              absl/copts/AbseilConfigureCopts.cmake
          ''
          else ''
            tar xf $src
            cd abseil-cpp-${version}
          '';
      }
      {
        name = "configure";
        script = ''
          mkdir build
          cd build
          cmake .. \
            $cmakeFlags \
            -DCMAKE_INSTALL_PREFIX=$out \
            -DCMAKE_INSTALL_LIBDIR=lib \
            -DCMAKE_BUILD_TYPE=Release \
            -DCMAKE_CXX_STANDARD=17 \
            -DBUILD_SHARED_LIBS=ON \
            -DABSL_ENABLE_INSTALL=ON \
            -DABSL_PROPAGATE_CXX_STD=ON \
            -DABSL_BUILD_TESTING=OFF
        '';
      }
      {
        name = "build";
        script = ''
          cmake --build . -j$NIX_BUILD_CORES
        '';
      }
      {
        name = "install";
        script = ''
          cmake --install .
        '';
      }
    ];

    meta = {
      description = "Abseil common C++ libraries";
      homepage = "https://abseil.io";
      license = "Apache-2.0";
    };
  }
