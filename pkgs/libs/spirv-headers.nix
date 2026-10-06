##! SPIR-V public API headers and grammar registry
{
  mkDerivation,
  fetchurl,
  buildPackages,
  stdenv,
  lib,
}: let
  version = "1.4.321.0";
in
  mkDerivation {
    pname = "spirv-headers";
    inherit version;

    src = fetchurl {
      urls = ["https://github.com/KhronosGroup/SPIRV-Headers/archive/refs/tags/vulkan-sdk-${version}.tar.gz"];
      hash = "sha256-W76pJWY9TNK6sj761Th08nGCSKc9yvndId/4y0jmAvw=";
    };

    buildDeps = [buildPackages.cmake buildPackages.ninja buildPackages.python3 buildPackages.pkg-config];
    runtimeDeps = [];
    propagatedDeps = [];

    phases =
      [
        {
          name = "unpack";
          script = ''
            tar xf "$src"
            cd SPIRV-Headers-vulkan-sdk-${version}
          '';
        }
        {
          name = "configure";
          script = ''
            cmake -S . -B build -G Ninja $cmakeFlags \
              -DCMAKE_BUILD_TYPE=Release \
              -DCMAKE_INSTALL_PREFIX="$out" \
              -DCMAKE_INSTALL_LIBDIR=lib
          '';
        }
        {
          name = "build";
          script = ''
            ninja -C build -j"$NIX_BUILD_CORES"
          '';
        }
      ]
      ++ lib.optionals (!stdenv.isCross) [
        {
          name = "check";
          script = ''
            ctest --test-dir build --output-on-failure -j"$NIX_BUILD_CORES"
          '';
        }
      ]
      ++ [
        {
          name = "install";
          script = ''
            ninja -C build install
            mkdir -p "$out/share/licenses/spirv-headers"
            cp -R LICENSE* "$out/share/licenses/spirv-headers/"
          '';
        }
      ];

    meta = {
      description = "SPIR-V public API headers and grammar registry";
      homepage = "https://github.com/KhronosGroup/SPIRV-Headers";
      license = "Apache-2.0";
    };
  }
