##! Vulkan public API headers and registry
{
  mkDerivation,
  fetchurl,
  cmake,
  ninja,
}: let
  version = "1.4.321";
in
  mkDerivation {
    pname = "vulkan-headers";
    inherit version;

    src = fetchurl {
      urls = ["https://github.com/KhronosGroup/Vulkan-Headers/archive/refs/tags/v${version}.tar.gz"];
      hash = "sha256-fBh0+Rhtnn1SReJ5zcyqd6Zu2PUocbQoYwrrdx3HYjw=";
    };

    buildDeps = [cmake ninja];
    runtimeDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd Vulkan-Headers-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          cmake -S . -B build -G Ninja $cmakeFlags \
            -DCMAKE_INSTALL_PREFIX="$out" -DCMAKE_INSTALL_LIBDIR=lib
        '';
      }
      {
        name = "install";
        script = ''
          ninja -C build install
          mkdir -p "$out/share/licenses/vulkan-headers"
          cp -R LICENSE* "$out/share/licenses/vulkan-headers/"
        '';
      }
    ];

    meta = {
      description = "Vulkan API headers and protocol registry";
      homepage = "https://github.com/KhronosGroup/Vulkan-Headers";
      license = "MIT OR Apache-2.0";
    };
  }
