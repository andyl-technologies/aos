##! nlohmann-json — JSON for Modern C++ (header-only)
{
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
