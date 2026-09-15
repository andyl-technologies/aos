##! libselinux — SELinux userspace library
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  libsepol,
  pcre2,
}: let
  version = "3.11";
in
  mkDerivation {
    pname = "libselinux";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Libselinux returns the declared user, role, type, range, and canonical context.";
        "files" = {
          "primary.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"libselinux primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"libselinux rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <string.h>\n#include <selinux/context.h>\nint main(void) {\n    context_t context = context_new(\"system_u:system_r:init_t:s0\");\n    if (context == NULL) return 2;\n    int valid = strcmp(context_user_get(context), \"system_u\") == 0\n        && strcmp(context_role_get(context), \"system_r\") == 0\n        && strcmp(context_type_get(context), \"init_t\") == 0\n        && strcmp(context_range_get(context), \"s0\") == 0\n        && strcmp(context_str(context), \"system_u:system_r:init_t:s0\") == 0;\n    context_free(context);\n    return valid ? pass() : 3;\n}\n\n";
        };
        "input" = "The SELinux context system_u:system_r:init_t:s0.";
        "operation" = "Parse the context and inspect each component through the context API.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "primary.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lselinux"
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
              "exact" = "libselinux primary passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Libselinux rejects the context by returning null.";
        "files" = {
          "bad-input.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"libselinux primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"libselinux rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <selinux/context.h>\nint main(void) {\n    context_t context = context_new(\"missing-fields\");\n    if (context != NULL) {\n        context_free(context);\n        return 2;\n    }\n    return reject();\n}\n\n";
        };
        "input" = "A security context containing only one field.";
        "operation" = "Parse the incomplete context through context_new.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "bad-input.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lselinux"
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
              "exact" = "libselinux rejected invalid input\n";
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
        "https://github.com/SELinuxProject/selinux/releases/download/${version}/selinux-${version}.tar.gz"
      ];
      hash = "sha256-a21Hqw81/hwJvaDGKCHI2XoMvn9ulASzON973gGCxPQ=";
    };

    buildDeps = [
      gnumake
      pkg-config
    ];
    runtimeDeps = [
      libsepol
      pcre2
    ];
    propagatedDeps = [
      pcre2
      libsepol
    ];

    # SELinux userspace has unchecked memory-copy patterns that trip
    # _FORTIFY_SOURCE. Disabling fortify disables fortify3 too.
    hardeningDisable = ["fortify"];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd selinux-${version}/libselinux
        '';
      }
      {
        name = "build";
        script = ''
          make PREFIX=$out SHLIBDIR=$out/lib \
            CFLAGS="-I${libsepol}/include -I${pcre2}/include" \
            LDFLAGS="-L${libsepol}/lib -L${pcre2}/lib -lpcre2-8" \
            USE_PCRE2=y \
            -j$NIX_BUILD_CORES
        '';
      }
      {
        name = "install";
        script = ''
          make install PREFIX=$out SHLIBDIR=$out/lib
        '';
      }
    ];

    meta = {
      description = "libselinux — SELinux userspace runtime library";
      homepage = "https://github.com/SELinuxProject/selinux";
      license = "LGPL-2.1-or-later";
    };
  }
