##! toml11 — TOML for Modern C++ (header-only)
{
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
