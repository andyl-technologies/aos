##! Zstandard — Fast real-time compression algorithm
{
  mkDerivation,
  fetchurl,
  make,
  zlib,
}: let
  version = "1.5.7";
in
  mkDerivation {
    pname = "zstd";
    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/facebook/zstd/releases/download/v${version}/zstd-${version}.tar.gz"
      ];
      hash = "sha256-6zPlH0mhXgI5UM14Jcp0pKK0Pbg1SCWsJPwbfuCeb6M=";
    };

    buildDeps = [make];
    runtimeDeps = [zlib];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd zstd-${version}
        '';
      }
      {
        name = "build";
        script = ''
          make PREFIX=$out -j$NIX_BUILD_CORES
        '';
      }
      {
        name = "install";
        script = ''
          make install PREFIX=$out
        '';
      }
    ];

    meta = {
      description = "Zstandard — fast real-time compression algorithm";
      homepage = "https://facebook.github.io/zstd/";
      license = "BSD-3-Clause";
    };

    checks = {
      testing,
      self,
      pkgs,
    }: {
      link = testing.mkLinkCheck {
        pname = "lib-zstd";
        library = self;
        libs = ["-lzstd"];
        testSource = ''
          #include <zstd.h>
          #include <stdio.h>
          int main() {
            printf("zstd version: %s\n", ZSTD_versionString());
            return 0;
          }
        '';
      };

      compress = testing.mkLinkCheck {
        pname = "lib-zstd-compress";
        library = self;
        libs = ["-lzstd"];
        testSource = ''
          #include <zstd.h>
          #include <string.h>
          #include <stdlib.h>
          #include <stdio.h>
          int main() {
            const char *src = "hello zstd compression test data";
            size_t srcSize = strlen(src);
            size_t dstCap = ZSTD_compressBound(srcSize);
            void *dst = malloc(dstCap);
            size_t cSize = ZSTD_compress(dst, dstCap, src, srcSize, 1);
            if (ZSTD_isError(cSize)) return 1;
            size_t origSize = ZSTD_getFrameContentSize(dst, cSize);
            char *result = malloc(origSize);
            size_t dSize = ZSTD_decompress(result, origSize, dst, cSize);
            if (ZSTD_isError(dSize)) return 1;
            if (memcmp(result, src, srcSize) != 0) return 1;
            free(dst);
            free(result);
            printf("zstd compress/decompress round-trip: PASS\n");
            return 0;
          }
        '';
      };

      cli-roundtrip = testing.mkVMTest {
        name = "lib-zstd-cli-roundtrip";
        rootfsDeps = [self];
        testScript = ''
          echo "zstd round-trip test data 1234567890" > /tmp/original.txt
          zstd /tmp/original.txt -o /tmp/compressed.zst
          zstd -d /tmp/compressed.zst -o /tmp/decompressed.txt
          ORIG=$(cat /tmp/original.txt)
          RESULT=$(cat /tmp/decompressed.txt)
          if [ "$ORIG" != "$RESULT" ]; then
            echo "==> ERROR: decompressed data does not match original" >&2
            exit 1
          fi
          echo "==> zstd CLI round-trip: PASS"
        '';
      };
    };
  }
