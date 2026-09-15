##! libcap — POSIX capabilities library
{
  lib,
  mkDerivation,
  fetchurl,
  stdenv,
  gnumake,
  perl,
  linux-headers,
}: let
  version = "2.78";
in
  mkDerivation {
    pname = "libcap";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The rendered set contains cap_chown with effective and permitted flags.";
        "files" = {
          "primary.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"libcap primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"libcap rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <string.h>\n#include <sys/capability.h>\nint main(void) {\n    cap_t capabilities = cap_from_text(\"cap_chown=ep\");\n    if (capabilities == NULL) return 2;\n    char *text = cap_to_text(capabilities, NULL);\n    int ok = text != NULL && strstr(text, \"cap_chown\") != NULL && strstr(text, \"ep\") != NULL;\n    cap_free(text); cap_free(capabilities);\n    return ok ? pass() : 3;\n}\n\n";
        };
        "input" = "The textual capability set cap_chown=ep.";
        "operation" = "Parse the text and render the capability set back through libcap.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "primary.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lcap"
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
              "exact" = "libcap primary passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "libcap rejects the name by returning a null capability set.";
        "files" = {
          "bad-input.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"libcap primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"libcap rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <sys/capability.h>\nint main(void) {\n    cap_t capabilities = cap_from_text(\"cap_definitely_not_real=ep\");\n    if (capabilities != NULL) { cap_free(capabilities); return 2; }\n    return reject();\n}\n\n";
        };
        "input" = "A capability name that is not defined by Linux.";
        "operation" = "Parse the invalid name with cap_from_text.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "bad-input.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lcap"
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
              "exact" = "libcap rejected invalid input\n";
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
        "https://mirrors.edge.kernel.org/pub/linux/libs/security/linux-privs/libcap2/libcap-${version}.tar.xz"
        "https://mirrors.kernel.org/pub/linux/libs/security/linux-privs/libcap2/libcap-${version}.tar.xz"
      ];
      hash = "sha256-DWIeVi/ZMsz2e5Zg+wGORopoPXuCdUHfJ4EyKMmWuxE=";
    };

    buildDeps = [
      gnumake
      perl
      # Kernel UAPI headers are compile-time only; in runtimeDeps they would
      # ride into the closure of everything that links libcap (a dead RPATH,
      # since linux-headers ships no shared library).
      linux-headers
    ];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd libcap-${version}
        '';
      }
      {
        name = "build";
        script = ''
          # Fix shebangs: scripts reference /bin/bash which doesn't exist
          # in the Nix sandbox. Replace with $CONFIG_SHELL (bootstrap bash).
          for f in $(find . -name '*.sh' -o -name '*.pl'); do
            if [ -f "$f" ]; then
              sed -i "1s|#!/bin/bash|#!$CONFIG_SHELL|" "$f"
              sed -i "1s|#!/usr/bin/env bash|#!$CONFIG_SHELL|" "$f"
              sed -i "1s|#!/usr/bin/bash|#!$CONFIG_SHELL|" "$f"
            fi
          done

          build_cc=''${BUILD_CC:-$CC}

          make -j$NIX_BUILD_CORES \
            CC="$CC" \
            AR="$AR" \
            RANLIB="$RANLIB" \
            OBJCOPY="${stdenv.binutils}/bin/objcopy" \
            BUILD_CC="$build_cc" \
            prefix=$out \
            lib=lib \
            SHARED=yes \
            GOLANG=no \
            PAM_CAP=no \
            DYNAMIC=yes
        '';
      }
      {
        name = "install";
        script = ''
          build_cc=''${BUILD_CC:-$CC}

          make install \
            CC="$CC" \
            AR="$AR" \
            RANLIB="$RANLIB" \
            OBJCOPY="${stdenv.binutils}/bin/objcopy" \
            BUILD_CC="$build_cc" \
            prefix=$out \
            lib=lib \
            SHARED=yes \
            GOLANG=no \
            PAM_CAP=no \
            RAISE_SETFCAP=no \
            DYNAMIC=yes
        '';
      }
    ];

    checks = {
      testing,
      self,
      pkgs,
    }: {
      link = testing.mkLinkCheck {
        pname = "lib-libcap";
        library = self;
        libs = ["-lcap"];
        testSource = ''
          #include <sys/capability.h>
          #include <stdio.h>
          int main() {
            cap_t caps = cap_get_proc();
            if (caps) {
              cap_free(caps);
            }
            printf("libcap: PASS\n");
            return 0;
          }
        '';
      };
    };

    meta = {
      description = "libcap — POSIX capabilities library";
      homepage = "https://sites.google.com/site/fullaborern8/home";
      license = "BSD-3-Clause OR GPL-2.0-only";
    };
  }
