##! libsharpyuv — Sharp RGB-to-YUV conversion for image codecs.
{
  lib,
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
    qualification.packageProbe = lib.qualification.commandProbe {
      primary = {
        input = "A four-by-four grayscale RGB gradient.";
        operation = "Convert it to full-range YUV through the installed SharpYUV library.";
        expected = "Luma preserves the gradient and chroma remains neutral.";
        files."gradient.c" = ''
          #include <sharpyuv/sharpyuv.h>
          #include <sharpyuv/sharpyuv_csp.h>
          #include <stdint.h>
          #include <stdio.h>

          int main(void) {
            const SharpYuvConversionMatrix *matrix =
              SharpYuvGetConversionMatrix(kSharpYuvMatrixRec601Full);
            uint8_t rgb[4 * 4 * 3], y[4 * 4], u[2 * 2], v[2 * 2];
            for (int pixel = 0; pixel < 16; pixel++) {
              uint8_t shade = (uint8_t)(pixel * 16);
              rgb[pixel * 3] = shade;
              rgb[pixel * 3 + 1] = shade;
              rgb[pixel * 3 + 2] = shade;
            }

            if (!SharpYuvConvert(rgb, rgb + 1, rgb + 2, 3, 4 * 3, 8,
                                 y, 4, u, 2, v, 2, 8, 4, 4, matrix)) return 1;
            for (int pixel = 0; pixel < 16; pixel++) {
              if (y[pixel] != pixel * 16) return 2;
            }
            for (int pixel = 0; pixel < 4; pixel++) {
              if (u[pixel] != 128 || v[pixel] != 128) return 3;
            }

            puts("libsharpyuv grayscale conversion passed");
          }
        '';
        artifacts = [];
        steps = [
          {
            argv = [
              "@cc@"
              "-std=c11"
              "-I@out@/include/webp"
              "gradient.c"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lsharpyuv"
              "-o"
              "gradient"
            ];
            exit_code = 0;
            stdout.exact = "";
          }
          {
            argv = ["./gradient"];
            exit_code = 0;
            stdout.exact = "libsharpyuv grayscale conversion passed\n";
            stderr.exact = "";
          }
        ];
      };
      badInput = {
        input = "An RGB image with zero width.";
        operation = "Attempt to convert it to YUV.";
        expected = "SharpYUV rejects the invalid image dimensions.";
        files."bad.c" = ''
          #include <sharpyuv/sharpyuv.h>
          #include <sharpyuv/sharpyuv_csp.h>
          #include <stdint.h>
          #include <stdio.h>

          int main(void) {
            const SharpYuvConversionMatrix *matrix =
              SharpYuvGetConversionMatrix(kSharpYuvMatrixRec601Full);
            uint8_t rgb[12] = {0}, y[4] = {0}, u[1] = {0}, v[1] = {0};
            if (SharpYuvConvert(rgb, rgb + 1, rgb + 2, 3, 6, 8,
                                y, 2, u, 1, v, 1, 8, 0, 2, matrix)) return 1;

            puts("libsharpyuv rejected zero-width image");
            return 7;
          }
        '';
        artifacts = [];
        steps = [
          {
            argv = [
              "@cc@"
              "-std=c11"
              "-I@out@/include/webp"
              "bad.c"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lsharpyuv"
              "-o"
              "bad"
            ];
            exit_code = 0;
            stdout.exact = "";
          }
          {
            argv = ["./bad"];
            exit_code = 7;
            observes_rejection = true;
            stdout.exact = "libsharpyuv rejected zero-width image\n";
            stderr.exact = "";
          }
        ];
      };
    };
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
