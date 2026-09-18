##! gpgme — High-level API for GnuPG operations
{
  lib,
  mkDerivation,
  stdenv,
  bash,
  fetchurl,
  gnumake,
  pkg-config,
  texinfo,
  gnupg,
  libassuan,
  libgpg-error,
  npth,
  glib,
}: let
  version = "2.2.0";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "gpgme";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The public API returns the expected value and the consumer prints the fixed success line.";
        "files" = {
          "primary.c" = "#include <stdio.h>\n#include <string.h>\n#include <gpgme.h>\n\nint main(void) {\n    const char source[] = \"qualification\";\n    char recovered[sizeof(source)] = {0};\n    gpgme_data_t data = NULL;\n    if (gpgme_data_new_from_mem(&data, source, sizeof(source) - 1, 1) != 0\n        || gpgme_data_seek(data, 0, SEEK_SET) != 0\n        || gpgme_data_read(data, recovered, sizeof(source) - 1) != sizeof(source) - 1\n        || memcmp(recovered, source, sizeof(source) - 1) != 0) {\n        if (data != NULL) gpgme_data_release(data);\n        return 2;\n    }\n    gpgme_data_release(data);\n    return puts(\"gpgme api passed\") == EOF;\n}\n";
        };
        "input" = "A fixed memory buffer exposed as GPGME data.";
        "operation" = "Create a data object, seek it, and read back the exact bytes.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "primary.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lgpgme"
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
              "exact" = "gpgme api passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "The API reports the rejected boundary and the consumer returns the fixed rejection status.";
        "files" = {
          "bad-input.c" = "#include <stdio.h>\n#include <gpgme.h>\n\nint main(void) {\n    gpgme_ctx_t context;\n    if (gpgme_new(&context) != 0) {\n        return 2;\n    }\n    gpgme_error_t status = gpgme_set_protocol(context, (gpgme_protocol_t)9999);\n    gpgme_release(context);\n    if (status == 0) {\n        return 3;\n    }\n    fputs(\"gpgme rejected invalid input\\n\", stderr);\n    return 7;\n}\n";
        };
        "input" = "A protocol identifier outside GPGME's public protocol enumeration.";
        "operation" = "Assign the invalid protocol to a new GPGME context.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "bad-input.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lgpgme"
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
              "exact" = "gpgme rejected invalid input\n";
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
        "https://gnupg.org/ftp/gcrypt/gpgme/gpgme-${version}.tar.bz2"
      ];
      hash = "sha256-cWDoDoTa/QDZVshIkcUzu3qxampU++FXSy86zwSWl3s=";
    };

    buildDeps = [gnumake pkg-config texinfo gnupg libgpg-error];
    runtimeDeps = [libassuan libgpg-error npth glib] ++ lib.optional (stdenv.isCross && stdenv.hostPlatform.isLinux) bash;
    propagatedDeps = [libassuan libgpg-error];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd gpgme-${version}
        '';
      }
      {
        name = "configure";
        script =
          lib.optionalString (stdenv.isCross && stdenv.hostPlatform.isLinux) ''
            # The native libgpg-error supplies yat2m, but its config helper would
            # select native libraries. Resolve target metadata with the build shell.
            mkdir -p .aos-build-tools
            cat > .aos-build-tools/gpgrt-config <<EOF
            #!$CONFIG_SHELL
            exec "$CONFIG_SHELL" ${libgpg-error}/bin/gpgrt-config "\$@"
            EOF
            chmod +x .aos-build-tools/gpgrt-config
            export GPGRT_CONFIG="$PWD/.aos-build-tools/gpgrt-config"
            export PKG_CONFIG_LIBDIR=
            export PKG_CONFIG_PATH="${libgpg-error}/lib/pkgconfig:${libassuan}/lib/pkgconfig''${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
          ''
          + ''
            ./configure \
              $configureFlags \
              --prefix="$out" \
              --enable-fixed-path=${gnupg}/bin \
              --with-libgpg-error-prefix=${libgpg-error} \
              --with-libassuan-prefix=${libassuan}
          '';
      }
      {
        name = "build";
        script = ''make -j"$NIX_BUILD_CORES"'';
      }
      {
        name = "check";
        script = ''make -j"$NIX_BUILD_CORES" check'';
      }
      {
        name = "install";
        script =
          ''make install''
          + lib.optionalString (stdenv.isCross && stdenv.hostPlatform.isLinux) ''

            # Public config helpers run on the target, including when invoked by
            # target Python during an emulated consumer build.
            sed -i '1s|^#!.*|#!${bash}/bin/bash|' "$out/bin/gpgme-config"
          '';
      }
    ];

    checks = {
      testing,
      self,
      ...
    }: {
      link = testing.mkLinkCheck {
        pname = "lib-gpgme";
        library = self;
        libs = ["-lgpgme"];
        testSource = ''
          #include <gpgme.h>

          int main(void) {
              return gpgme_check_version(NULL) == NULL;
          }
        '';
      };
      tool = testing.mkToolCheck {
        pname = "tool-gpgme";
        tool = self;
        command = "gpgme-tool --version";
      };
    };

    meta = {
      description = "High-level API for GnuPG operations";
      homepage = "https://gnupg.org/software/gpgme/";
      license = "LGPL-2.1-or-later AND GPL-3.0-or-later";
    };
  }
