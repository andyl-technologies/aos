##! Zstandard — Fast real-time compression algorithm
{
  mkDerivation,
  mkGithubUpstream,
  gnumake,
  zlib,
  xz,
  lz4,
  stdenv,
}: let
  upstream = mkGithubUpstream {
    unitId = "zstd-1";
    family = "zstd";
    stream = "1";
    owner = "pkgs/compression/zstd.nix";
    version = "1.5.7";
    upstreamId = "v1.5.7";
    repository = "facebook/zstd";
    tagPrefix = "v";
    major = 1;
    source = {
      authority = "github.com";
      path = [
        "facebook"
        "zstd"
        "releases"
        "download"
        {
          parts = [
            {literal = "v";}
            {
              componentField = {
                component = "main";
                field = "comparisonVersion";
              };
            }
          ];
        }
        {
          parts = [
            {literal = "zstd-";}
            {
              componentField = {
                component = "main";
                field = "comparisonVersion";
              };
            }
            {literal = ".tar.gz";}
          ];
        }
      ];
      hash = "sha256-6zPlH0mhXgI5UM14Jcp0pKK0Pbg1SCWsJPwbfuCeb6M=";
    };
  };
  inherit (upstream) version;
in
  mkDerivation {
    pname = "zstd";
    inherit version;

    src = upstream.components.main.sources.source;
    update = upstream.update;

    buildDeps = [gnumake];
    # Keep the CLI's gzip, legacy lzma, and lz4 stream support enabled.
    runtimeDeps = [zlib xz lz4];
    propagatedDeps = [];

    # The build machine's uname remains Linux during a cross build. Tell the
    # upstream makefiles which target naming and install-name rules to use.
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
          make PREFIX=$out -j$NIX_BUILD_CORES ${
            if stdenv.hostPlatform.isDarwin
            then "TARGET_SYSTEM=Darwin UNAME_TARGET_SYSTEM=Darwin"
            else ""
          }
        '';
      }
      {
        name = "install";
        script = ''
          make install PREFIX=$out ${
            if stdenv.hostPlatform.isDarwin
            then "TARGET_SYSTEM=Darwin UNAME_TARGET_SYSTEM=Darwin"
            else ""
          }
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

      soname = testing.mkSONAMECheck {
        pkg = self;
        libs = ["libzstd.so"];
      };

      version-consistency = testing.mkVersionCheck {
        pkg = self;
        name = "zstd";
        headerCode = ''
          #include <zstd.h>
        '';
        runtimeCode = ''
          const char *header_ver = ZSTD_VERSION_STRING;
          const char *runtime_ver = ZSTD_versionString();
        '';
        libs = ["-lzstd"];
      };

      compression-interop = testing.mkVMTest {
        name = "cross-cutting-compression-interop";
        rootfsDeps = [
          pkgs.zlib
          self
        ];
        testScript = ''
          export C_INCLUDE_PATH="${pkgs.zlib}/include:${self}/include:$C_INCLUDE_PATH"
          export LIBRARY_PATH="${pkgs.zlib}/lib:${self}/lib:$LIBRARY_PATH"
          export LD_LIBRARY_PATH="${pkgs.zlib}/lib:${self}/lib:$LD_LIBRARY_PATH"

          cat > /tmp/compress_test.c << 'EOF'
          #include <zlib.h>
          #include <zstd.h>
          #include <string.h>
          #include <stdlib.h>
          #include <stdio.h>

          int main(void) {
              const char *original = "The quick brown fox jumps over the lazy dog. "
                                     "This is test data for compression interop.";
              size_t origLen = strlen(original);

              printf("==> Testing zstd round-trip\n");
              size_t zstdBound = ZSTD_compressBound(origLen);
              void *zstdComp = malloc(zstdBound);
              size_t zstdSize = ZSTD_compress(zstdComp, zstdBound, original, origLen, 1);
              if (ZSTD_isError(zstdSize)) {
                  fprintf(stderr, "zstd compress failed: %s\n", ZSTD_getErrorName(zstdSize));
                  return 1;
              }
              printf("    Compressed %zu -> %zu bytes with zstd\n", origLen, zstdSize);

              char *zstdDecomp = malloc(origLen + 1);
              size_t dSize = ZSTD_decompress(zstdDecomp, origLen, zstdComp, zstdSize);
              if (ZSTD_isError(dSize)) {
                  fprintf(stderr, "zstd decompress failed: %s\n", ZSTD_getErrorName(dSize));
                  return 1;
              }
              if (dSize != origLen || memcmp(zstdDecomp, original, origLen) != 0) {
                  fprintf(stderr, "zstd round-trip mismatch\n");
                  return 1;
              }
              printf("    zstd round-trip: OK\n");
              free(zstdComp);
              free(zstdDecomp);

              printf("==> Testing zlib round-trip\n");
              uLong zlibBound = compressBound((uLong)origLen);
              Bytef *zlibComp = malloc(zlibBound);
              uLong zlibSize = zlibBound;
              if (compress(zlibComp, &zlibSize, (const Bytef *)original, (uLong)origLen) != Z_OK) {
                  fprintf(stderr, "zlib compress failed\n");
                  return 1;
              }
              printf("    Compressed %zu -> %lu bytes with zlib\n", origLen, zlibSize);

              char *zlibDecomp = malloc(origLen + 1);
              uLong resLen = (uLong)origLen;
              if (uncompress((Bytef *)zlibDecomp, &resLen, zlibComp, zlibSize) != Z_OK) {
                  fprintf(stderr, "zlib uncompress failed\n");
                  return 1;
              }
              if (resLen != (uLong)origLen || memcmp(zlibDecomp, original, origLen) != 0) {
                  fprintf(stderr, "zlib round-trip mismatch\n");
                  return 1;
              }
              printf("    zlib round-trip: OK\n");
              free(zlibComp);
              free(zlibDecomp);

              printf("Compression interop: PASS\n");
              return 0;
          }
          EOF

          echo "==> Compiling compression interop test"
          gcc -o /tmp/compress_test /tmp/compress_test.c -lzstd -lz
          echo "==> Running compression interop test"
          /tmp/compress_test
        '';
      };
    };
  }
