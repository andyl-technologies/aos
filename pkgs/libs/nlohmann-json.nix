##! nlohmann-json — JSON for Modern C++ (header-only)
{
  mkDerivation,
  fetchurl,
  gnumake,
  cmake,
  ninja,
}: let
  version = "3.12.0";
in
  mkDerivation {
    pname = "nlohmann-json";
    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/nlohmann/json/archive/refs/tags/v${version}.tar.gz"
      ];
      hash = "sha256-S5LrDAbRBoP3RHzpQGy5fNS0U74Y1yeTIPey8CXBAYc=";
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
