##! libimagequant — Palette quantization for image encoders.
{
  lib,
  mkDerivation,
  fetchurl,
  buildPackages,
  stdenv,
}: let
  version = "2.4.1";
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
    pname = "libimagequant";
    qualification.packageProbe = lib.qualification.commandProbe {
      primary = {
        input = "A two-by-two RGBA image with four distinct colors.";
        operation = "Quantize the image and map palette indexes back to colors.";
        expected = "Every mapped pixel exactly matches the original color.";
        files."palette.c" = ''
          #include <libimagequant.h>
          #include <stdio.h>

          int main(void) {
            unsigned char rgba[16] = {
              255, 0, 0, 255, 0, 255, 0, 255,
              0, 0, 255, 255, 255, 255, 255, 255
            };
            liq_attr *attr = liq_attr_create();
            if (!attr || liq_set_max_colors(attr, 4) != LIQ_OK) return 1;

            liq_image *image = liq_image_create_rgba(attr, rgba, 2, 2, 0);
            if (!image) return 2;
            liq_result *result = liq_quantize_image(attr, image);
            if (!result) return 3;

            const liq_palette *palette = liq_get_palette(result);
            unsigned char indexes[4];
            if (!palette || palette->count != 4 ||
                liq_write_remapped_image(result, image, indexes, sizeof(indexes)) != LIQ_OK)
              return 4;

            for (int pixel = 0; pixel < 4; pixel++) {
              liq_color color = palette->entries[indexes[pixel]];
              unsigned char channels[4] = {color.r, color.g, color.b, color.a};
              for (int channel = 0; channel < 4; channel++) {
                if (channels[channel] != rgba[pixel * 4 + channel]) return 5;
              }
            }

            liq_result_destroy(result);
            liq_image_destroy(image);
            liq_attr_destroy(attr);
            puts("libimagequant palette conversion passed");
          }
        '';
        artifacts = [];
        steps = [
          {
            argv = [
              "@cc@"
              "-std=c11"
              "-I@out@/include"
              "palette.c"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-limagequant"
              "-o"
              "palette"
            ];
            exit_code = 0;
            stdout.exact = "";
          }
          {
            argv = ["./palette"];
            exit_code = 0;
            stdout.exact = "libimagequant palette conversion passed\n";
            stderr.exact = "";
          }
        ];
      };
      badInput = {
        input = "An RGBA image with zero width.";
        operation = "Attempt to create it through the image API.";
        expected = "The image constructor rejects the invalid dimensions.";
        files."bad.c" = ''
          #include <libimagequant.h>
          #include <stdio.h>

          int main(void) {
            unsigned char rgba[4] = {255, 0, 0, 255};
            liq_attr *attr = liq_attr_create();
            if (!attr) return 1;
            liq_image *image = liq_image_create_rgba(attr, rgba, 0, 1, 0);
            if (image) return 2;

            liq_attr_destroy(attr);
            puts("libimagequant rejected zero-width image");
            return 7;
          }
        '';
        artifacts = [];
        steps = [
          {
            argv = [
              "@cc@"
              "-std=c11"
              "-I@out@/include"
              "bad.c"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-limagequant"
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
            stdout.exact = "libimagequant rejected zero-width image\n";
            stderr.exact = "";
          }
        ];
      };
    };
    inherit version;
    src = fetchurl {
      urls = ["https://github.com/lovell/libimagequant/archive/v${version}.tar.gz"];
      hash = "1ysdjvcylj0844qk2k2av11ppxfbrbix98shkmf9flhhgd5silj7";
    };

    buildDeps = [buildPackages.meson buildPackages.ninja buildPackages.python3];
    runtimeDeps = [];

    phases =
      [
        {
          name = "unpack";
          script = ''
            tar xf "$src"
            cd libimagequant-${version}
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
            mkdir -p "$out/share/licenses/libimagequant"
            cp COPYRIGHT "$out/share/licenses/libimagequant/"
          '';
        }
      ];

    meta = {
      description = "Palette quantization library used by image encoders";
      homepage = "https://github.com/lovell/libimagequant";
      license = "BSD-2-Clause";
    };
  }
