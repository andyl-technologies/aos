##! WebP codec libraries, independent of the image-conversion tools.
{
  mkDerivation,
  fetchurl,
  buildPackages,
  stdenv,
  lib,
}: let
  version = "1.6.0";
  probeSource = ''
    #include <stdint.h>
    #include <stdio.h>
    #include <string.h>
    #include <webp/decode.h>
    #include <webp/encode.h>

    int main(int argc, char **argv) {
        int width = 0;
        int height = 0;

        if (argc > 1 && strcmp(argv[1], "invalid") == 0) {
            const uint8_t malformed[] = {0, 1, 2, 3};
            uint8_t *decoded = WebPDecodeRGBA(malformed, sizeof(malformed), &width, &height);
            if (decoded != NULL) {
                WebPFree(decoded);
                return 1;
            }
            puts("libwebp rejected malformed image");
            return 0;
        }

        const uint8_t pixels[] = {255, 0, 0, 255};
        uint8_t *encoded = NULL;
        size_t size = WebPEncodeLosslessRGBA(pixels, 1, 1, 4, &encoded);
        if (size == 0) return 1;

        uint8_t *decoded = WebPDecodeRGBA(encoded, size, &width, &height);
        int failed = decoded == NULL || width != 1 || height != 1;
        if (!failed) failed = memcmp(pixels, decoded, sizeof(pixels)) != 0;
        WebPFree(decoded);
        WebPFree(encoded);
        if (failed) return 1;

        puts("libwebp roundtrip passed");
        return 0;
    }
  '';
  compileProbe = {
    argv = [
      "@cc@"
      "-I@out@/include"
      "-L@out@/lib"
      "-Wl,-rpath,@out@/lib"
      "@work@/probe.c"
      "-lwebp"
      "-o"
      "@work@/probe"
    ];
    exit_code = 0;
  };
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
    pname = "libwebp";
    qualification.packageProbe = lib.qualification.commandProbe {
      primary = {
        input = "A one-pixel RGBA image.";
        operation = "Compile against the installed WebP library and round-trip the image.";
        expected = "Lossless encoding and decoding preserve the pixel.";
        files."probe.c" = probeSource;
        artifacts = [];
        steps = [
          compileProbe
          {
            argv = ["@work@/probe"];
            exit_code = 0;
            stdout.exact = "libwebp roundtrip passed\n";
            stderr.exact = "";
          }
        ];
      };
      badInput = {
        input = "Four malformed bytes instead of a WebP image.";
        operation = "Decode the malformed image through the installed library.";
        expected = "The decoder returns no image.";
        files."probe.c" = probeSource;
        artifacts = [];
        steps = [
          compileProbe
          {
            argv = ["@work@/probe" "invalid"];
            exit_code = 0;
            observes_rejection = true;
            stdout.exact = "libwebp rejected malformed image\n";
            stderr.exact = "";
          }
        ];
      };
    };
    inherit version;
    src = fetchurl {
      urls = ["https://storage.googleapis.com/downloads.webmproject.org/releases/webp/libwebp-${version}.tar.gz"];
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
            cd libwebp-${version}
          '';
        }
        {
          name = "configure";
          script = ''
            $CONFIG_SHELL ./configure $configureFlags --prefix="$out" \
              --enable-libwebpdecoder --enable-libwebpmux --enable-libwebpdemux \
              --enable-libsharpyuv
          '';
        }
        {
          name = "build";
          script = ''
            # TIFF consumes the codec, while WebP's conversion tools consume TIFF.
            # Build the complete library targets separately to avoid that cycle.
            make -C sharpyuv -j"$NIX_BUILD_CORES" SHELL="$CONFIG_SHELL"
            make -C src -j"$NIX_BUILD_CORES" SHELL="$CONFIG_SHELL"
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
              cat > roundtrip.c <<'C'
              #include <stdint.h>
              #include <string.h>
              #include "src/webp/encode.h"
              #include "src/webp/decode.h"

              int main(void) {
                  const uint8_t pixels[] = {255, 0, 0, 255, 0, 255, 0, 128,
                                            0, 0, 255, 255, 23, 42, 79, 255};
                  uint8_t *encoded = NULL;
                  size_t size = WebPEncodeLosslessRGBA(pixels, 2, 2, 8, &encoded);
                  if (size == 0) return 1;

                  int width = 0, height = 0;
                  uint8_t *decoded = WebPDecodeRGBA(encoded, size, &width, &height);
                  int failed = decoded == NULL || width != 2 || height != 2;
                  if (!failed) failed = memcmp(pixels, decoded, sizeof(pixels)) != 0;
                  WebPFree(decoded);
                  WebPFree(encoded);
                  return failed;
              }
              C
              $CC roundtrip.c -I. -Lsrc/.libs -Wl,-rpath,"$PWD/src/.libs" \
                -lwebp -o roundtrip
              ./roundtrip
            '';
          }
        ]
      )
      ++ [
        {
          name = "install";
          script = ''
            make -C sharpyuv install SHELL="$CONFIG_SHELL"
            make -C src install SHELL="$CONFIG_SHELL"
            mkdir -p "$out/share/licenses/libwebp"
            cp COPYING PATENTS "$out/share/licenses/libwebp/"
          '';
        }
      ];

    meta = {
      description = "WebP encoder, decoder, animation mux and demux libraries";
      homepage = "https://developers.google.com/speed/webp";
      license = "BSD-3-Clause";
    };
  }
