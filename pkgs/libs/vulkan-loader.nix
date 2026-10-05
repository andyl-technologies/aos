##! Vulkan ICD loader with XCB, Xlib, Xrandr and Wayland WSI
{
  mkDerivation,
  fetchurl,
  buildPackages,
  stdenv,
  lib,
  vulkan-headers,
  libxcb,
  libx11,
  libxrandr,
  wayland,
}: let
  version = "1.4.321";
in
  mkDerivation {
    pname = "vulkan-loader";
    inherit version;

    src = fetchurl {
      urls = ["https://github.com/KhronosGroup/Vulkan-Loader/archive/refs/tags/v${version}.tar.gz"];
      hash = "sha256-AGafa7LbNcjfB/CxGMCb/g6//sqtfYBkekKe7ODjesM=";
    };

    buildDeps = [buildPackages.cmake buildPackages.ninja buildPackages.python3 buildPackages.pkg-config];
    runtimeDeps = [vulkan-headers libxcb libx11 libxrandr wayland];
    propagatedDeps = [vulkan-headers libxcb libx11 libxrandr wayland];

    phases =
      [
        {
          name = "unpack";
          script = ''
            tar xf "$src"
            cd Vulkan-Loader-${version}
          '';
        }
        {
          name = "configure";
          script = ''
            cmake -S . -B build -G Ninja $cmakeFlags \
              -DCMAKE_BUILD_TYPE=Release \
              -DCMAKE_INSTALL_PREFIX="$out" \
              -DCMAKE_INSTALL_LIBDIR=lib -DVulkanHeaders_DIR=${vulkan-headers}/share/cmake/VulkanHeaders
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
            mkdir -p "$out/share/licenses/vulkan-loader"
            cp -R LICENSE* "$out/share/licenses/vulkan-loader/"
          '';
        }
      ];

    meta = {
      description = "Vulkan ICD loader with XCB, Xlib, Xrandr and Wayland WSI";
      homepage = "https://github.com/KhronosGroup/Vulkan-Loader";
      license = "Apache-2.0";
    };
  }
