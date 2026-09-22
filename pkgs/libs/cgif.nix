##! cgif — GIF encoding library used by libvips and Sharp.
{
  mkDerivation,
  fetchurl,
  buildPackages,
  stdenv,
}: let
  version = "0.5.3";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "cgif";
    inherit version;
    src = fetchurl {
      urls = ["https://github.com/dloebl/cgif/archive/refs/tags/v${version}.tar.gz"];
      hash = "sha256-3MdzHpdO5323XfJsmayk2V8Ryi0mfYcNQrzh4NHh518=";
    };

    buildDeps = [buildPackages.meson buildPackages.ninja buildPackages.python3];
    runtimeDeps = [];

    phases =
      [
        {
          name = "unpack";
          script = ''
            tar xf "$src"
            cd cgif-${version}
            # Meson runs this checksum helper during the native test suite.
            sed -i '1c#!${buildPackages.python3}/bin/python3' tests/scripts/sha256sum.py
          '';
        }
        {
          name = "configure";
          script = ''
            meson setup build $mesonFlags --prefix="$out" --libdir=lib --buildtype=release
          '';
        }
        {
          name = "build";
          script = ''
            # Ninja invokes Meson's Python helpers without its CLI wrapper.
            PYTHONPATH=${buildPackages.meson}/lib/python3/site-packages \
              ninja -C build -j"$NIX_BUILD_CORES"
          '';
        }
      ]
      ++ (
        if stdenv.isCross
        then []
        else [
          {
            name = "check";
            script = ''
              meson test -C build --print-errorlogs
            '';
          }
        ]
      )
      ++ [
        {
          name = "install";
          script = ''
            meson install -C build
            mkdir -p "$out/share/licenses/cgif"
            cp LICENSE "$out/share/licenses/cgif/"
          '';
        }
      ];

    checks = {
      testing,
      self,
      ...
    }: {
      link = testing.mkLinkCheck {
        pname = "lib-cgif";
        library = self;
        libs = ["-lcgif"];
        testSource = ''
          #include <cgif.h>

          int main(void) {
              uint8_t palette[] = {255, 0, 0};
              uint8_t pixel[] = {0};
              CGIF_Config config = {0};
              config.width = 1;
              config.height = 1;
              config.path = "/tmp/cgif-check.gif";
              config.pGlobalPalette = palette;
              config.numGlobalPaletteEntries = 1;

              CGIF *gif = cgif_newgif(&config);
              if (gif == NULL) return 1;
              CGIF_FrameConfig frame = {0};
              frame.pImageData = pixel;
              int result = cgif_addframe(gif, &frame);
              int closed = cgif_close(gif);
              return result != CGIF_OK || closed != CGIF_OK;
          }
        '';
      };
    };

    meta = {
      description = "GIF encoder with animation, transparency, and compression support";
      homepage = "https://github.com/dloebl/cgif";
      license = "MIT";
    };
  }
