##! libqcow — QEMU Copy-On-Write (QCOW) image file library
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  zlib,
  openssl,
  stdenv,
}: let
  version = "20240308";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "libqcow";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Libqcow reports its package version and returns a usable handle.";
        "files" = {
          "primary.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"libqcow primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"libqcow rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <string.h>\n#include <libqcow.h>\nint main(void) {\n    libqcow_file_t *file = NULL;\n    libqcow_error_t *error = NULL;\n    int status = libqcow_file_initialize(&file, &error);\n    int valid = status == 1 && file != NULL && error == NULL\n        && strcmp(libqcow_get_version(), \"20240308\") == 0;\n    libqcow_file_free(&file, NULL);\n    libqcow_error_free(&error);\n    return valid ? pass() : 2;\n}\n\n";
        };
        "input" = "A request for a new libqcow file handle.";
        "operation" = "Initialize and free the handle through the public API.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "primary.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lqcow"
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
              "exact" = "libqcow primary passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Libqcow returns -1 and supplies a structured error.";
        "files" = {
          "bad-input.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"libqcow primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"libqcow rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <libqcow.h>\nint main(void) {\n    libqcow_error_t *error = NULL;\n    int status = libqcow_set_codepage(999, &error);\n    int rejected = status == -1 && error != NULL;\n    libqcow_error_free(&error);\n    return rejected ? reject() : 2;\n}\n\n";
        };
        "input" = "Codepage number 999, which libqcow does not support.";
        "operation" = "Set the invalid codepage through libqcow_set_codepage.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "bad-input.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lqcow"
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
              "exact" = "libqcow rejected invalid input\n";
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
        "https://github.com/libyal/libqcow/releases/download/${version}/libqcow-alpha-${version}.tar.gz"
      ];
      hash = "sha256-94E7RvRtTWVoPyCvBz1zYvmSAs/bpzQhEmEWGAbXN7I=";
    };

    buildDeps = [
      gnumake
      pkg-config
    ];
    runtimeDeps = [
      zlib
      openssl
    ];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd libqcow-${version}
        '';
      }
      {
        name = "configure";
        script =
          if stdenv.isCross
          then ''
            # This capability is true for the same AOS OpenSSL in the
            # native build, but Autoconf otherwise tries to execute the
            # target probe binary while cross compiling.
            export ac_cv_openssl_xts_duplicate_keys=yes
            ./configure \
              $configureFlags \
              --prefix=$out \
              --enable-shared \
              --disable-static \
              --with-zlib=${zlib} \
              --with-openssl=${openssl} \
              --disable-python
          ''
          else ''
            ./configure \
              $configureFlags \
              --prefix=$out \
              --enable-shared \
              --disable-static \
              --with-zlib=${zlib} \
              --with-openssl=${openssl} \
              --disable-python
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

    checks = {
      testing,
      self,
      pkgs,
    }: {
      soname = testing.mkSONAMECheck {
        pkg = self;
        libs = ["libqcow.so"];
      };

      link = testing.mkLinkCheck {
        pname = "lib-libqcow";
        library = self;
        libs = ["-lqcow"];
        extraDeps = [
          pkgs.zlib
          pkgs.openssl
        ];
        testSource = ''
          #include <libqcow.h>
          #include <stdio.h>
          int main() {
            const char *version = libqcow_get_version();
            printf("libqcow version: %s\n", version);
            return 0;
          }
        '';
      };
    };

    meta = {
      description = "libqcow — QEMU Copy-On-Write image file library";
      homepage = "https://github.com/libyal/libqcow";
      license = "LGPL-3.0-or-later";
    };
  }
