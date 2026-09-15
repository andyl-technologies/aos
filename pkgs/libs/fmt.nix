##! fmt — Modern C++ formatting library
{
  lib,
  mkDerivation,
  mkGithubUpstream,
  cmake,
  gnumake,
}: let
  upstream = mkGithubUpstream {
    unitId = "fmt-12";
    family = "fmt";
    stream = "12";
    owner = "pkgs/libs/fmt.nix";
    version = "12.2.0";
    upstreamId = "12.2.0";
    repository = "fmtlib/fmt";
    provider = "github-releases";
    major = 12;
    source = {
      authority = "github.com";
      path = [
        "fmtlib"
        "fmt"
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
      hash = "sha256-i4UrtapufYVk+egTlAVTld0dGTbTjf06F3kqAr69evA=";
    };
  };
  inherit (upstream) version;
in
  mkDerivation {
    pname = "fmt";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The public API returns the expected value and the consumer prints the fixed success line.";
        "files" = {
          "primary.cc" = "#include <iostream>\n#include <fmt/format.h>\n\nint main() {\n    if (fmt::format(\"answer={:04d}\", 42) != \"answer=0042\") {\n        return 2;\n    }\n    std::cout << \"fmt api passed\\n\";\n}\n";
        };
        "input" = "A format string with a zero-padded integer field.";
        "operation" = "Format an integer with fmt::format and compare the resulting string.";
        "steps" = [
          {
            "argv" = [
              "@cxx@"
              "primary.cc"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lfmt"
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
              "exact" = "fmt api passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "The public API reports rejection and the consumer exits with the fixed rejection status and diagnostic.";
        "files" = {
          "bad-input.cc" = "#include <iostream>\n#include <fmt/format.h>\n\nint main() {\n    try {\n        static_cast<void>(fmt::format(fmt::runtime(\"{\"), 42));\n        return 2;\n    } catch (const fmt::format_error &) {\n        std::cerr << \"fmt rejected invalid input\\n\";\n        return 7;\n    }\n}\n";
        };
        "input" = "A runtime format string with an unmatched opening brace.";
        "operation" = "Format a value through fmt::runtime and catch the format_error.";
        "steps" = [
          {
            "argv" = [
              "@cxx@"
              "bad-input.cc"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lfmt"
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
              "exact" = "fmt rejected invalid input\n";
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

    buildDeps = [cmake gnumake];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd fmt-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          cmake -S . -B build \
            $cmakeFlags \
            -DCMAKE_INSTALL_PREFIX=$out \
            -DCMAKE_INSTALL_LIBDIR=lib \
            -DCMAKE_BUILD_TYPE=Release \
            -DBUILD_SHARED_LIBS=ON \
            -DFMT_DOC=OFF \
            -DFMT_TEST=OFF
        '';
      }
      {
        name = "build";
        script = ''
          cmake --build build --parallel $NIX_BUILD_CORES
        '';
      }
      {
        name = "install";
        script = ''
          cmake --install build
        '';
      }
    ];

    meta = {
      description = "Modern formatting library for C++";
      homepage = "https://fmt.dev/";
      license = "MIT";
    };
  }
