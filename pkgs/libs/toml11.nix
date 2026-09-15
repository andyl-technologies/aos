##! toml11 — TOML for Modern C++ (header-only)
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  cmake,
  ninja,
}: let
  version = "4.4.0";
in
  mkDerivation {
    pname = "toml11";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The public API returns the expected value and the consumer prints the fixed success line.";
        "files" = {
          "primary.cc" = "#include <cstdint>\n#include <iostream>\n#include <sstream>\n#include <toml.hpp>\n\nint main() {\n    std::istringstream input(\"answer = 42\\n\");\n    const auto document = toml::parse(input, \"answer.toml\");\n    if (toml::find<std::int64_t>(document, \"answer\") != 42) {\n        return 2;\n    }\n    std::cout << \"toml11 api passed\\n\";\n}\n";
        };
        "input" = "A TOML document containing an integer answer.";
        "operation" = "Parse the document with toml11 and retrieve the typed integer.";
        "steps" = [
          {
            "argv" = [
              "@cxx@"
              "primary.cc"
              "-std=c++17"
              "-I@out@/include"
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
              "exact" = "toml11 api passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "The public API reports rejection and the consumer exits with the fixed rejection status and diagnostic.";
        "files" = {
          "bad-input.cc" = "#include <iostream>\n#include <sstream>\n#include <toml.hpp>\n\nint main() {\n    std::istringstream input(\"answer =\\n\");\n    try {\n        (void)toml::parse(input, \"invalid.toml\");\n    } catch (const toml::syntax_error&) {\n        std::cerr << \"toml11 rejected invalid input\\n\";\n        return 7;\n    }\n    return 2;\n}\n";
        };
        "input" = "A TOML integer assignment with no value.";
        "operation" = "Parse the malformed document with toml11.";
        "steps" = [
          {
            "argv" = [
              "@cxx@"
              "bad-input.cc"
              "-std=c++17"
              "-I@out@/include"
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
              "exact" = "toml11 rejected invalid input\n";
            };
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
    };

    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/ToruNiina/toml11/archive/refs/tags/v${version}.tar.gz"
      ];
      hash = "sha256-gVv+Z5KqEaE6EzuG5/D0Xtxdcet49ftmhsScf3krkEk=";
    };

    buildDeps = [
      gnumake
      cmake
      ninja
    ];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd toml11-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          cmake -S . -B build -G Ninja \
            $cmakeFlags \
            -DCMAKE_BUILD_TYPE=Release \
            -DCMAKE_INSTALL_PREFIX=$out \
            -DCMAKE_INSTALL_LIBDIR=lib \
            -Dtoml11_BUILD_TEST=OFF \
            -Dtoml11_BUILD_EXAMPLES=OFF
        '';
      }
      {
        name = "build";
        script = ''
          ninja -C build -j$NIX_BUILD_CORES
        '';
      }
      {
        name = "install";
        script = ''
          ninja -C build install
        '';
      }
    ];

    checks = {
      testing,
      self,
      pkgs,
    }: {
      compile = testing.mkCxxCompileCheck {
        pname = "lib-toml11";
        deps = [self];
        testSource = ''
          #include <toml.hpp>
          #include <iostream>
          #include <sstream>
          int main() {
            std::istringstream ss("[package]\nname = \"test\"\n");
            auto data = toml::parse(ss);
            auto name = toml::find<std::string>(data, "package", "name");
            if (name != "test") return 1;
            std::cout << "toml11: PASS" << std::endl;
            return 0;
          }
        '';
      };
    };

    meta = {
      description = "toml11 — TOML for Modern C++ (header-only)";
      homepage = "https://github.com/ToruNiina/toml11";
      license = "MIT";
    };
  }
