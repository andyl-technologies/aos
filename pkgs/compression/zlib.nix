##! zlib — Lossless data compression library
{
  lib,
  mkDerivation,
  mkUpstream,
  gnumake,
  stdenv,
}: let
  upstream = mkUpstream {
    schema = "aos.package-update/v1";
    unitId = "zlib-1";
    family = "zlib";
    stream = "1";
    owner = "pkgs/compression/zlib.nix";
    classification = "automatic";

    package = {
      currentVersion = "1.3.2";
      versionProjection = {
        kind = "component-field";
        component = "main";
        field = "comparisonVersion";
      };
    };

    components.main = {
      current = {
        upstreamId = "v1.3.2";
        comparisonVersion = "1.3.2";
      };
      discovery = {
        primary = {
          provider = "github-releases";
          repository = "madler/zlib";
          tagPrefix = "v";
        };
        advisors.repology.project = "zlib";
      };
      releasePolicy = {
        strategy = "latest-in-series";
        versionScheme = "semver";
        series.major = 1;
        allowPrerelease = false;
        minimumAgeDays = 3;
      };
      sources.source = {
        fetcher = "fetchurl";
        urlTemplates = [
          {
            scheme = "https";
            authority = "zlib.net";
            path = [
              {
                parts = [
                  {literal = "zlib-";}
                  {
                    componentField = {
                      component = "main";
                      field = "comparisonVersion";
                    };
                  }
                  {literal = ".tar.xz";}
                ];
              }
            ];
          }
        ];
        hash = "sha256-16BlR4Ok2lKdG7eTt62cMxgCCvd2Z7yuNfldDkKnkvM=";
        hashMode = "flat";
        allowedRedirectHosts = ["zlib.net"];
      };
    };

    policy = {
      lifecycle = "supported";
      riskFloor = "normal";
    };
  };
  version = upstream.version;
in
  mkDerivation {
    pname = "zlib";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The recovered bytes equal the original bytes and the consumer prints the fixed success line.";
        "files" = {
          "round-trip.c" = "#include <stdio.h>\n#include <string.h>\n#include <zlib.h>\n\nint main(void) {\n    const char input[] = \"AOS package qualification\";\n    unsigned char compressed[128];\n    unsigned char recovered[sizeof(input)];\n    uLongf compressed_size = sizeof(compressed);\n    uLongf recovered_size = sizeof(recovered);\n\n    if (compress(compressed, &compressed_size,\n                 (const Bytef *)input, sizeof(input)) != Z_OK) {\n        return 2;\n    }\n    if (uncompress(recovered, &recovered_size,\n                   compressed, compressed_size) != Z_OK) {\n        return 3;\n    }\n    if (recovered_size != sizeof(input)\n        || memcmp(recovered, input, sizeof(input)) != 0) {\n        return 4;\n    }\n\n    return puts(\"zlib round trip passed\") == EOF;\n}\n";
        };
        "input" = "A fixed byte string to compress and recover through the public zlib API.";
        "operation" = "Compile and run a consumer that compresses and decompresses the input.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "round-trip.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lz"
              "-o"
              "zlib-round-trip"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "";
            };
          }
          {
            "argv" = [
              "@work@/primary/zlib-round-trip"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "zlib round trip passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "The public API returns Z_DATA_ERROR and the consumer exits with the fixed rejection status and diagnostic.";
        "files" = {
          "reject-invalid.c" = "#include <stdio.h>\n#include <zlib.h>\n\nint main(void) {\n    const unsigned char invalid[] = \"not a zlib stream\";\n    unsigned char output[128];\n    uLongf output_size = sizeof(output);\n    int result = uncompress(output, &output_size, invalid, sizeof(invalid));\n\n    if (result != Z_DATA_ERROR) {\n        return 2;\n    }\n\n    fputs(\"zlib rejected invalid stream\\n\", stderr);\n    return 7;\n}\n";
        };
        "input" = "A byte sequence that is not a zlib stream.";
        "operation" = "Compile and run a consumer that passes the invalid stream to uncompress.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "reject-invalid.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lz"
              "-o"
              "zlib-reject-invalid"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "";
            };
          }
          {
            "argv" = [
              "@work@/bad-input/zlib-reject-invalid"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "zlib rejected invalid stream\n";
            };
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
    };

    inherit version;

    src = upstream.components.main.sources.source;
    update = upstream.forPackage {member = "zlib";};

    buildDeps = [gnumake];
    runtimeDeps = [];
    propagatedDeps = [];

    # zlib's configure script understands a synthetic Darwin uname, but then
    # assumes Apple's /usr/bin/libtool creates static archives. Keep llvm-ar
    # and llvm-ranlib selected explicitly for the Linux-hosted cross build.
    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd zlib-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure --prefix=$out ${
            if stdenv.hostPlatform.isDarwin
            then "--uname=${stdenv.hostPlatform.config}"
            else ""
          }
        '';
      }
      {
        name = "build";
        script = ''
          make -j$NIX_BUILD_CORES ${
            if stdenv.hostPlatform.isDarwin
            then ''AR="$AR" ARFLAGS=rc RANLIB="$RANLIB"''
            else ""
          }
        '';
      }
      {
        name = "install";
        script = ''
          make install ${
            if stdenv.hostPlatform.isDarwin
            then ''AR="$AR" ARFLAGS=rc RANLIB="$RANLIB" LDCONFIG=:''
            else ""
          }
        '';
      }
    ];

    meta = {
      description = "zlib — lossless data compression library";
      homepage = "https://zlib.net";
      license = "Zlib";
    };

    checks = {
      testing,
      self,
      pkgs,
    }: {
      link = testing.mkLinkCheck {
        pname = "lib-zlib";
        library = self;
        libs = ["-lz"];
        testSource = ''
          #include <zlib.h>
          #include <stdio.h>
          int main() {
            printf("zlib version: %s\n", zlibVersion());
            return 0;
          }
        '';
      };

      compress = testing.mkLinkCheck {
        pname = "lib-zlib-compress";
        library = self;
        libs = ["-lz"];
        testSource = ''
          #include <zlib.h>
          #include <string.h>
          #include <stdio.h>
          int main() {
            const char *src = "hello zlib compression test data";
            uLong srcLen = strlen(src);
            uLong dstLen = compressBound(srcLen);
            Bytef dst[4096];
            if (compress(dst, &dstLen, (const Bytef *)src, srcLen) != Z_OK) return 1;
            char result[256];
            uLong resLen = sizeof(result);
            if (uncompress((Bytef *)result, &resLen, dst, dstLen) != Z_OK) return 1;
            if (memcmp(result, src, srcLen) != 0) return 1;
            printf("zlib compress/uncompress round-trip: PASS\n");
            return 0;
          }
        '';
      };

      header-version = testing.mkLinkCheck {
        pname = "lib-zlib-header-version";
        library = self;
        libs = ["-lz"];
        testSource = ''
          #include <zlib.h>
          #include <stdio.h>
          #include <string.h>
          int main(void) {
              const char *hdr = ZLIB_VERSION;
              const char *lib = zlibVersion();
              printf("header:  %s\n", hdr);
              printf("runtime: %s\n", lib);
              if (strcmp(hdr, lib) != 0) {
                  fprintf(stderr, "MISMATCH: header and runtime versions differ\n");
                  return 1;
              }
              printf("zlib-header-version: PASS\n");
              return 0;
          }
        '';
      };

      soname = testing.mkSONAMECheck {
        pkg = self;
        libs = ["libz.so"];
      };

      symbols = testing.mkSymbolCheck {
        pkg = self;
        libName = "libz.so";
        symbols = [
          "compress"
          "uncompress"
          "deflate"
          "inflate"
        ];
      };

      version-consistency = testing.mkVersionCheck {
        pkg = self;
        name = "zlib";
        headerCode = ''
          #include <zlib.h>
        '';
        runtimeCode = ''
          const char *header_ver = ZLIB_VERSION;
          const char *runtime_ver = zlibVersion();
        '';
        libs = ["-lz"];
      };

      consumers = testing.mkVMTest {
        name = "lib-zlib-consumers";
        rootfsDeps = [
          pkgs.curl
          pkgs.libarchive
          pkgs.elfutils
          self
        ];
        testScript = ''
          FAIL=0
          for bin in \
            ${pkgs.curl}/bin/curl; do
            echo "==> Checking $bin"
            OUTPUT=$(readelf -d "$bin" 2>&1) || true
            case "$OUTPUT" in
              *libz*)
                echo "    OK: links against zlib"
                ;;
              *)
                echo "    FAIL: no zlib linkage found" >&2
                FAIL=1
                ;;
            esac
          done
          for lib in \
            ${pkgs.libarchive}/lib/libarchive.so; do
            echo "==> Checking $lib"
            if [ ! -e "$lib" ]; then
              echo "    SKIP: $lib not found"
              continue
            fi
            OUTPUT=$(readelf -d "$lib" 2>&1) || true
            case "$OUTPUT" in
              *libz*)
                echo "    OK: links against zlib"
                ;;
              *)
                echo "    FAIL: no zlib linkage found" >&2
                FAIL=1
                ;;
            esac
          done
          if [ "$FAIL" -ne 0 ]; then
            echo "==> ERROR: some consumers missing zlib linkage" >&2
            exit 1
          fi
          echo "==> zlib-consumers: PASS"
        '';
      };
    };
  }
