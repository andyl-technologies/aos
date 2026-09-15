##! nlohmann-json — JSON for Modern C++ (header-only)
{
  lib,
  mkDerivation,
  mkGithubUpstream,
  gnumake,
  cmake,
  ninja,
}: let
  upstream = mkGithubUpstream {
    unitId = "nlohmann-json-3";
    family = "nlohmann-json";
    stream = "3";
    owner = "pkgs/libs/nlohmann-json.nix";
    version = "3.12.0";
    upstreamId = "v3.12.0";
    repository = "nlohmann/json";
    provider = "github-releases";
    tagPrefix = "v";
    major = 3;
    source = {
      authority = "github.com";
      path = [
        "nlohmann"
        "json"
        "archive"
        "refs"
        "tags"
        {
          parts = [
            {literal = "v";}
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
      hash = "sha256-S5LrDAbRBoP3RHzpQGy5fNS0U74Y1yeTIPey8CXBAYc=";
    };
  };
  inherit (upstream) version;
in
  mkDerivation {
    pname = "nlohmann-json";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The answer field has integer value 42.";
        "files" = {
          "primary.cc" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"nlohmann-json primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"nlohmann-json rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <nlohmann/json.hpp>\nint main() {\n    auto document = nlohmann::json::parse(\"{\\\"answer\\\":42}\");\n    return document.at(\"answer\").get<int>() == 42 ? pass() : 2;\n}\n\n";
        };
        "input" = "A JSON object containing an integer answer.";
        "operation" = "Parse the document and read the value through nlohmann::json.";
        "steps" = [
          {
            "argv" = [
              "@cxx@"
              "primary.cc"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-o"
              "primary-check"
            ];
            "exit_code" = 0;
            "stdout" = {
              "exact" = "";
            };
          }
          {
            "argv" = [
              "@work@/primary/primary-check"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "nlohmann-json primary passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "The library returns its discarded sentinel.";
        "files" = {
          "bad-input.cc" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"nlohmann-json primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"nlohmann-json rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <nlohmann/json.hpp>\nint main() {\n    auto document = nlohmann::json::parse(\"{\\\"answer\\\":42,}\", nullptr, false);\n    if (!document.is_discarded()) return 2;\n    return reject();\n}\n\n";
        };
        "input" = "A JSON object with a trailing comma.";
        "operation" = "Parse the malformed document while disabling exceptions.";
        "steps" = [
          {
            "argv" = [
              "@cxx@"
              "bad-input.cc"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-o"
              "bad-input-check"
            ];
            "exit_code" = 0;
            "stdout" = {
              "exact" = "";
            };
          }
          {
            "argv" = [
              "@work@/bad-input/bad-input-check"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "nlohmann-json rejected invalid input\n";
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
          cd json-${version}
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
            -DJSON_BuildTests=OFF \
            -DJSON_MultipleHeaders=ON
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
          # pkgconfig file installed to share/pkgconfig — symlink to lib/pkgconfig
          mkdir -p $out/lib/pkgconfig
          ln -sf ../../share/pkgconfig/nlohmann_json.pc $out/lib/pkgconfig/nlohmann_json.pc
        '';
      }
    ];

    checks = {
      testing,
      self,
      pkgs,
    }: {
      compile = testing.mkCxxCompileCheck {
        pname = "lib-nlohmann-json";
        deps = [self];
        testSource = ''
          #include <nlohmann/json.hpp>
          #include <iostream>
          int main() {
            nlohmann::json j;
            j["key"] = 42;
            std::string s = j.dump();
            auto parsed = nlohmann::json::parse(s);
            if (parsed["key"] != 42) return 1;
            std::cout << "nlohmann-json: PASS" << std::endl;
            return 0;
          }
        '';
      };
    };

    meta = {
      description = "nlohmann-json — JSON for Modern C++ (header-only)";
      homepage = "https://github.com/nlohmann/json";
      license = "MIT";
    };
  }
