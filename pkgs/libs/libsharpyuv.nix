##! libsharpyuv — Sharp RGB-to-YUV conversion for image codecs.
{
  mkDerivation,
  fetchurl,
  buildPackages,
  stdenv,
}: let
  sourceVersion = "1.6.0";
in
  mkDerivation {
    platformSupport = {
      build = [
        {
          abi = ["gnu"];
          os = ["linux"];
        }
      ];
      host = [
        {
          abi = ["gnu"];
          cpu = ["x86_64" "aarch64"];
          os = ["linux"];
        }
        {
          abi = ["darwin"];
          cpu = ["x86_64" "aarch64"];
          os = ["darwin"];
        }
      ];
      target = [];
      role = "public-package";
    };
    pname = "libsharpyuv";
    version = "0.4.2";
    src = fetchurl {
      urls = ["https://storage.googleapis.com/downloads.webmproject.org/releases/webp/libwebp-${sourceVersion}.tar.gz"];
      hash = "0r25ikisj6chsgn4fwxszx629kv476l2lk1dk08zsa86pw4p1az4";
    };

    buildDeps = [buildPackages.gnumake buildPackages.pkg-config];
    runtimeDeps = [];

    phases =
      [
        {
          name = "unpack";
          script = ''
            tar xf "$src"
            cd libwebp-${sourceVersion}
          '';
        }
        {
          name = "configure";
          script = ''
            $CONFIG_SHELL ./configure $configureFlags --prefix="$out" --enable-libsharpyuv
          '';
        }
        {
          name = "build";
          script = ''
            # SharpYUV has its own public library and install target in WebP's source tree.
            make -C sharpyuv -j"$NIX_BUILD_CORES" SHELL="$CONFIG_SHELL"
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
              cat > conversion-test.c <<'C'
              #include <stdint.h>
              #include <string.h>
              #include "sharpyuv/sharpyuv.h"
              #include "sharpyuv/sharpyuv_csp.h"

              int main(void) {
                  const SharpYuvConversionMatrix *matrix =
                      SharpYuvGetConversionMatrix(kSharpYuvMatrixRec601Full);
                  uint8_t rgb[16 * 16 * 3], y[16 * 16], u[8 * 8], v[8 * 8];

                  for (int value = 0; value <= 255; value += 255) {
                      memset(rgb, value, sizeof(rgb));
                      if (!SharpYuvConvert(rgb, rgb + 1, rgb + 2, 3, 16 * 3, 8,
                                           y, 16, u, 8, v, 8, 8, 16, 16, matrix)) {
                          return 1;
                      }

                      for (unsigned i = 0; i < sizeof(y); ++i) {
                          if (y[i] != value) return 2;
                      }
                      for (unsigned i = 0; i < sizeof(u); ++i) {
                          if (u[i] != 128 || v[i] != 128) return 3;
                      }
                  }
                  return 0;
              }
              C
              $CC conversion-test.c -I. -Lsharpyuv/.libs \
                -Wl,-rpath,"$PWD/sharpyuv/.libs" -lsharpyuv -o conversion-test
              ./conversion-test
            '';
          }
        ]
      )
      ++ [
        {
          name = "install";
          script = ''
            make -C sharpyuv install SHELL="$CONFIG_SHELL"
            mkdir -p "$out/share/licenses/libsharpyuv"
            cp COPYING PATENTS "$out/share/licenses/libsharpyuv/"
          '';
        }
      ];

    meta = {
      description = "Sharp RGB-to-YUV conversion library with SIMD acceleration";
      homepage = "https://developers.google.com/speed/webp";
      license = "BSD-3-Clause";
    };
  }
