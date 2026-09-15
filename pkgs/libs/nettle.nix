{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  m4,
  gmp,
  stdenv,
}: let
  version = "4.0";
in
  mkDerivation {
    pname = "nettle";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The digest matches the standard SHA-256 vector.";
        "files" = {
          "primary.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"nettle primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"nettle rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <string.h>\n#include <nettle/sha2.h>\nint main(void) {\n    static const unsigned char expected[32] = {0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad};\n    struct sha256_ctx context; unsigned char digest[32];\n    sha256_init(&context); sha256_update(&context, 3, (const uint8_t *)\"abc\"); sha256_digest(&context, digest);\n    return memcmp(digest, expected, sizeof(digest)) == 0 ? pass() : 2;\n}\n\n";
        };
        "input" = "The ASCII string abc for SHA-256 hashing.";
        "operation" = "Hash the bytes through Nettle's SHA-256 context API.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "primary.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lnettle"
              "-o"
              "primary-check"
            ];
            "exit_code" = 0;
            "stdout" = {
              "exact" = "";
            };
          }
          {
            "argv" = [
              "@work@/primary/primary-check"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "nettle primary passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Nettle returns false instead of producing decoded bytes.";
        "files" = {
          "bad-input.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"nettle primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"nettle rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <nettle/base64.h>\nint main(void) {\n    struct base64_decode_ctx context; uint8_t output[8]; size_t output_size = sizeof(output);\n    base64_decode_init(&context);\n    if (base64_decode_update(&context, &output_size, output, 1, (const uint8_t *)\"!\")) return 2;\n    return reject();\n}\n\n";
        };
        "input" = "A base64 input containing a character outside the alphabet.";
        "operation" = "Decode the malformed bytes through base64_decode_update.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "bad-input.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lnettle"
              "-o"
              "bad-input-check"
            ];
            "exit_code" = 0;
            "stdout" = {
              "exact" = "";
            };
          }
          {
            "argv" = [
              "@work@/bad-input/bad-input-check"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "nettle rejected invalid input\n";
            };
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
    };

    inherit version;

    src = fetchurl {
      urls = [
        "https://ftp.gnu.org/gnu/nettle/nettle-${version}.tar.gz"
        "https://mirrors.dotsrc.org/gnu/nettle/nettle-${version}.tar.gz"
      ];
      hash = "sha256-Ot28ANoBhGsjL7O8RTU46lRo2kMDPyG7NFyx6Qc/UJQ=";
    };

    buildDeps = [gnumake m4];
    runtimeDeps = [gmp];
    propagatedDeps = [gmp];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd nettle-${version}
        '';
      }
      {
        name = "configure";
        script =
          if stdenv.isCross && stdenv.hostPlatform.isDarwin
          then ''
            export CFLAGS="$CFLAGS \
              -ffile-prefix-map=$PWD=. \
              -fdebug-prefix-map=$PWD=."

            # Nettle compiles and executes hogweed's mini-gmp generator on
            # the build machine. Isolate that compiler from Darwin SDK and
            # architecture flags exported by the cross stdenv.
            native_cc="$BUILD_CC"
            mkdir -p .aos-build-tools
            cat > .aos-build-tools/cc-for-build <<EOF
            #!$CONFIG_SHELL
            unset AOS_HARDENING_ENABLE AOS_TARGET_ARCH AOS_TARGET_PLATFORM
            unset C_INCLUDE_PATH CPLUS_INCLUDE_PATH LIBRARY_PATH
            unset MACOSX_DEPLOYMENT_TARGET NIX_CFLAGS_COMPILE NIX_LDFLAGS SDKROOT
            exec "$native_cc" "\$@"
            EOF
            chmod +x .aos-build-tools/cc-for-build
            export CC_FOR_BUILD="$PWD/.aos-build-tools/cc-for-build"

            ./configure \
              $configureFlags \
              --prefix=$out \
              --libdir=$out/lib \
              --disable-static \
              --enable-shared \
              --disable-documentation
          ''
          else ''
            ./configure \
              $configureFlags \
              --prefix=$out \
              --libdir=$out/lib \
              --disable-static \
              --enable-shared \
              --disable-documentation
          '';
      }
      {
        name = "build";
        script = ''
          make -j$NIX_BUILD_CORES
        '';
      }
      {
        name = "install";
        script = ''
          make install
        '';
      }
    ];

    meta = {
      description = "Low-level cryptographic library (libnettle + libhogweed)";
      homepage = "https://www.lysator.liu.se/~nisse/nettle/";
      license = "LGPL-3.0-or-later";
    };
  }
