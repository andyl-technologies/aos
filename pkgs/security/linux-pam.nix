##! linux-pam — Pluggable Authentication Modules
{
  lib,
  mkDerivation,
  fetchurl,
  meson,
  ninja,
  pkg-config,
  flex,
  bison,
  gettext,
  python3,
  libxcrypt,
  audit,
}: let
  version = "1.7.1";
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
      ];
      target = [];
      role = "public-package";
    };
    pname = "linux-pam";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Linux-PAM preserves the exact environment value.";
        "files" = {
          "primary.c" = "#include <stdio.h>\n#include <string.h>\n#include <security/pam_appl.h>\n\nstatic int conversation(\n    int message_count,\n    const struct pam_message **messages,\n    struct pam_response **responses,\n    void *data\n) {\n    (void)message_count;\n    (void)messages;\n    (void)responses;\n    (void)data;\n    return PAM_CONV_ERR;\n}\n\nstatic int pass(void) {\n    return puts(\"linux-pam primary passed\") == EOF;\n}\n\nstatic int reject(void) {\n    fputs(\"linux-pam rejected invalid input\\n\", stderr);\n    return 7;\n}\n\nint main(void) {\n    struct pam_conv callback = {conversation, NULL};\n    pam_handle_t *handle = NULL;\n    int start_status = pam_start(\"qualification\", \"user\", &callback, &handle);\n    if (start_status != PAM_SUCCESS || handle == NULL) return 2;\n\n    int put_status = pam_putenv(handle, \"ANSWER=42\");\n    const char *value = pam_getenv(handle, \"ANSWER\");\n    int valid = put_status == PAM_SUCCESS\n        && value != NULL\n        && strcmp(value, \"42\") == 0;\n\n    pam_end(handle, PAM_SUCCESS);\n    return valid ? pass() : 3;\n}\n\n";
        };
        "input" = "A PAM transaction with the environment entry ANSWER=42.";
        "operation" = "Create the transaction, store the entry, and retrieve it through the application API.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "primary.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lpam"
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
              "exact" = "linux-pam primary passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Linux-PAM rejects the entry with PAM_BAD_ITEM.";
        "files" = {
          "bad-input.c" = "#include <stdio.h>\n#include <string.h>\n#include <security/pam_appl.h>\n\nstatic int conversation(\n    int message_count,\n    const struct pam_message **messages,\n    struct pam_response **responses,\n    void *data\n) {\n    (void)message_count;\n    (void)messages;\n    (void)responses;\n    (void)data;\n    return PAM_CONV_ERR;\n}\n\nstatic int pass(void) {\n    return puts(\"linux-pam primary passed\") == EOF;\n}\n\nstatic int reject(void) {\n    fputs(\"linux-pam rejected invalid input\\n\", stderr);\n    return 7;\n}\n\nint main(void) {\n    struct pam_conv callback = {conversation, NULL};\n    pam_handle_t *handle = NULL;\n    int start_status = pam_start(\"qualification\", \"user\", &callback, &handle);\n    if (start_status != PAM_SUCCESS || handle == NULL) return 2;\n\n    int status = pam_putenv(handle, \"=invalid\");\n    pam_end(handle, PAM_SUCCESS);\n    return status == PAM_BAD_ITEM ? reject() : 3;\n}\n\n";
        };
        "input" = "A PAM environment assignment whose variable name is empty.";
        "operation" = "Store the malformed assignment through pam_putenv.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "bad-input.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lpam"
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
              "exact" = "linux-pam rejected invalid input\n";
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
        "https://github.com/linux-pam/linux-pam/releases/download/v${version}/Linux-PAM-${version}.tar.xz"
        "https://github.com/linux-pam/linux-pam/archive/refs/tags/v${version}.tar.gz"
      ];
      hash = "sha256-IdvOxuAd1XjxR4nqyQJKGJQebycCoFz5GyjCMu6yarA=";
    };

    buildDeps = [
      meson
      ninja
      pkg-config
      flex
      bison
      gettext
      python3
    ];
    runtimeDeps = [
      libxcrypt
      audit
    ];
    propagatedDeps = [];

    abilities = ./_linux-pam;

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd Linux-PAM-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          # Meson needs to find its own Python modules (ninja invokes
          # python3 -m mesonbuild.mesonmain directly).
          nativeMesonRoot=$(dirname "$(dirname "$(command -v meson)")")
          export PYTHONPATH="$nativeMesonRoot/lib/python3/site-packages''${PYTHONPATH:+:$PYTHONPATH}"

          meson setup build \
            $mesonFlags \
            --prefix=$out \
            --sysconfdir=$out/etc \
            --buildtype=release \
            --libdir=lib \
            -Ddefault_library=both \
            -Ddocs=disabled \
            -Dexamples=false \
            -Dxtests=false \
            -Dnis=disabled \
            -Dselinux=disabled \
            -Delogind=disabled \
            -Dlogind=disabled \
            -Dopenssl=disabled \
            -Dpam_userdb=disabled \
            -Dpam_unix=enabled \
            -Daudit=enabled
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
      description = "Pluggable Authentication Modules for Linux";
      homepage = "https://github.com/linux-pam/linux-pam";
      license = "BSD-3-Clause";
    };
  }
