##! Brotli — Generic-purpose lossless compression algorithm
{
  mkDerivation,
  fetchurl,
  gnumake,
  cmake,
  ninja,
  stdenv,
}: let
  version = "1.2.0";
in
  mkDerivation {
    pname = "brotli";
    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/google/brotli/archive/refs/tags/v${version}.tar.gz"
      ];
      hash = "sha256-gWyW6Ojxk7QBUdrX6P83sSIdAZ28ucNc0/rb/mR33+w=";
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
          cd brotli-${version}
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
            -DBUILD_SHARED_LIBS=ON \
            ${
            if stdenv.hostPlatform.isDarwin
            then "-DBROTLI_EMSCRIPTEN=OFF"
            else ""
          } \
            -DBROTLI_DISABLE_TESTS=ON
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

    meta = {
      description = "Brotli — generic-purpose lossless compression algorithm";
      homepage = "https://github.com/google/brotli";
      license = "MIT";
    };

    checks = {
      testing,
      self,
      pkgs,
    }: {
      link = testing.mkLinkCheck {
        pname = "lib-brotli";
        library = self;
        libs = [
          "-lbrotlienc"
          "-lbrotlicommon"
        ];
        testSource = ''
          #include <brotli/encode.h>
          #include <stdint.h>
          #include <stdio.h>
          int main() {
            uint32_t v = BrotliEncoderVersion();
            printf("brotli encoder version: %u.%u.%u\n", v >> 24, (v >> 12) & 0xfff, v & 0xfff);
            return 0;
          }
        '';
      };

      decode = testing.mkLinkCheck {
        pname = "lib-brotli-decode";
        library = self;
        libs = [
          "-lbrotlienc"
          "-lbrotlidec"
          "-lbrotlicommon"
        ];
        testSource = ''
          #include <brotli/encode.h>
          #include <brotli/decode.h>
          #include <string.h>
          #include <stdio.h>
          int main(void) {
              const char *input = "brotli round-trip test data for AOS";
              size_t input_size = strlen(input);
              size_t encoded_size = BrotliEncoderMaxCompressedSize(input_size);
              unsigned char encoded[4096];
              if (BrotliEncoderCompress(BROTLI_DEFAULT_QUALITY, BROTLI_DEFAULT_WINDOW,
                                        BROTLI_DEFAULT_MODE, input_size,
                                        (const unsigned char *)input,
                                        &encoded_size, encoded) != BROTLI_TRUE)
                  return 1;
              unsigned char decoded[4096];
              size_t decoded_size = sizeof(decoded);
              if (BrotliDecoderDecompress(encoded_size, encoded,
                                          &decoded_size, decoded)
                  != BROTLI_DECODER_RESULT_SUCCESS)
                  return 1;
              if (decoded_size != input_size || memcmp(decoded, input, input_size) != 0)
                  return 1;
              printf("brotli-decode round-trip: PASS\n");
              return 0;
          }
        '';
      };
    };
  }
