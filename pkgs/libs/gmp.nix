##! GMP — GNU Multiple Precision Arithmetic Library
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  m4,
  stdenv,
}: let
  version = "6.3.0";
in
  mkDerivation {
    pname = "gmp";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The public API returns the expected value and the consumer prints the fixed success line.";
        "files" = {
          "primary.c" = "#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n#include <gmp.h>\n\nint main(void) {\n    mpz_t left, right, sum;\n    mpz_inits(left, right, sum, NULL);\n    if (mpz_set_str(left, \"100000000000000000000\", 10) != 0\n        || mpz_set_str(right, \"23\", 10) != 0) {\n        return 2;\n    }\n    mpz_add(sum, left, right);\n    char *text = mpz_get_str(NULL, 10, sum);\n    int failed = text == NULL || strcmp(text, \"100000000000000000023\") != 0;\n    free(text);\n    mpz_clears(left, right, sum, NULL);\n    if (failed) {\n        return 3;\n    }\n    return puts(\"gmp api passed\") == EOF;\n}\n";
        };
        "input" = "Two integers larger than a native 64-bit value.";
        "operation" = "Parse and add the integers with GMP, then compare their decimal sum.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "primary.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lgmp"
              "-o"
              "primary-consumer"
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
              "@work@/primary/primary-consumer"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "gmp api passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "The public API reports rejection and the consumer exits with the fixed rejection status and diagnostic.";
        "files" = {
          "bad-input.c" = "#include <stdio.h>\n#include <gmp.h>\n\nint main(void) {\n    mpz_t value;\n    mpz_init(value);\n    int status = mpz_set_str(value, \"42x\", 10);\n    mpz_clear(value);\n    if (status == 0) {\n        return 2;\n    }\n    fputs(\"gmp rejected invalid input\\n\", stderr);\n    return 7;\n}\n";
        };
        "input" = "A supposed decimal integer containing an alphabetic character.";
        "operation" = "Parse the malformed integer with mpz_set_str.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "bad-input.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lgmp"
              "-o"
              "bad-input-consumer"
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
              "@work@/bad-input/bad-input-consumer"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "gmp rejected invalid input\n";
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
        "https://gmplib.org/download/gmp/gmp-${version}.tar.xz"
        "https://mirrors.kernel.org/gnu/gmp/gmp-${version}.tar.xz"
        "https://mirrors.kernel.org/gnu/gmp/gmp-${version}.tar.xz"
      ];
      hash = "sha256-o8K4AgG4nmhhb0rTC8Zq7kknw85Q4zkpyoGdXENTiJg=";
    };

    buildDeps = [
      gnumake
      m4
    ];
    runtimeDeps = [];
    propagatedDeps = [];
    disallowedReferences = [stdenv.cc];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd gmp-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ${
            if stdenv.isCross && stdenv.hostPlatform.isDarwin
            then ''
              # GMP compiles configure helpers for the build machine. Keep
              # the native compiler isolated from target-only SDK, linker,
              # and hardening flags exported by the cross stdenv.
              native_cc="$BUILD_CC"
              mkdir -p .aos-build-tools
              cat > .aos-build-tools/cc <<EOF
              #!$CONFIG_SHELL
              unset AOS_HARDENING_ENABLE AOS_TARGET_ARCH AOS_TARGET_PLATFORM
              unset C_INCLUDE_PATH
              unset CPLUS_INCLUDE_PATH LIBRARY_PATH MACOSX_DEPLOYMENT_TARGET
              unset NIX_CFLAGS_COMPILE NIX_LDFLAGS SDKROOT
              exec "$native_cc" "\$@"
              EOF
              chmod +x .aos-build-tools/cc
              export CC_FOR_BUILD="$PWD/.aos-build-tools/cc"
            ''
            else ""
          }

          ${
            if stdenv.hostPlatform.isDarwin
            then ''
              # Apple libtool's fallback partial link uses ld64 -r, which
              # ld64.lld does not implement. Its single-module form links
              # the same objects directly into the shared library.
              export lt_cv_apple_cc_single_mod=yes

              # Mach-O debug symbols retain compilation and object paths even
              # after stripping. Remap the sandbox prefix at compile time so
              # cached libraries contain no ephemeral /build references.
              export CXXFLAGS="''${CXXFLAGS:-} -ffile-prefix-map=$PWD=. -fdebug-prefix-map=$PWD=. -fdebug-compilation-dir=."
            ''
            else ""
          }

          ./configure \
            $configureFlags \
            --prefix=$out \
            --enable-shared \
            --disable-static \
            --enable-cxx \
            --with-pic \
            ${
            if stdenv.hostPlatform.isDarwin
            then ''CFLAGS="-std=c99 -ffile-prefix-map=$PWD=. -fdebug-prefix-map=$PWD=. -fdebug-compilation-dir=."''
            else "CFLAGS=-std=c99"
          }
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

          # GMP records the build compiler for diagnostic purposes. Keeping
          # its store path here would retain the complete compiler toolchain
          # in every runtime closure that uses libgmp.
          sed -i \
            -e 's|^#define __GMP_CC .*|#define __GMP_CC "cc"|' \
            -e 's|^#define __GMP_CFLAGS .*|#define __GMP_CFLAGS ""|' \
            "$out/include/gmp.h"
        '';
      }
    ];

    meta = {
      description = "GMP — GNU Multiple Precision Arithmetic Library";
      homepage = "https://gmplib.org/";
      license = "LGPL-3.0-or-later";
    };
  }
