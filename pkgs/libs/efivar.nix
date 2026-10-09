##! efivar — EFI variable and device-path libraries
{
  lib,
  mkDerivation,
  fetchurl,
  stdenv,
  buildPackages,
  gnumake,
  pkg-config,
  mandoc,
  popt,
}: let
  version = "39";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];}];
      target = [];
      role = "public-package";
    };
    pname = "efivar";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The API returns the expected value and the consumer prints the fixed success line.";
        "files" = {
          "primary.c" = "#include <stdio.h>\n#include <string.h>\n#include <efivar/efivar.h>\n\nint main(void) {\n    efi_guid_t parsed;\n    efi_guid_t expected = EFI_GLOBAL_GUID;\n    if (efi_str_to_guid(\"8be4df61-93ca-11d2-aa0d-00e098032b8c\", &parsed) < 0\n        || memcmp(&parsed, &expected, sizeof(parsed)) != 0) {\n        return 2;\n    }\n    return puts(\"efivar api passed\") == EOF;\n}\n";
        };
        "input" = "The canonical EFI global-variable GUID string.";
        "operation" = "Parse the string with efi_str_to_guid and compare it to EFI_GLOBAL_GUID.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "primary.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lefivar"
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
              "exact" = "efivar api passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "The API reports rejection and the consumer emits the fixed diagnostic and rejection status.";
        "files" = {
          "bad-input.c" = "#include <stdio.h>\n#include <efivar/efivar.h>\n\nint main(void) {\n    efi_guid_t parsed;\n    if (efi_str_to_guid(\"8be4df6z-93ca-11d2-aa0d-00e098032b8c\", &parsed) >= 0) {\n        return 2;\n    }\n    fputs(\"efivar rejected invalid input\\n\", stderr);\n    return 7;\n}\n";
        };
        "input" = "A GUID string containing a non-hexadecimal character.";
        "operation" = "Parse the malformed identifier with efi_str_to_guid.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "bad-input.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lefivar"
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
              "exact" = "efivar rejected invalid input\n";
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
        "https://github.com/rhboot/efivar/archive/refs/tags/${version}.tar.gz"
      ];
      hash = "sha256-ye3RXy7u6mMjLz5mmkjpkse+mv9X7iJnKsMfXsoWCaY=";
    };

    buildDeps = [gnumake pkg-config mandoc];
    runtimeDeps = [popt];
    propagatedDeps = [popt];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd efivar-${version}
        '';
      }
      {
        name = "build";
        script =
          lib.optionalString (stdenv.isCross && stdenv.hostPlatform.isLinux) ''
            # makeguids runs during the build. Keep its native compiler clear
            # of target include paths and link flags inherited from the stdenv.
            mkdir -p .aos-build-tools
            cat > .aos-build-tools/cc-for-build <<'EOF'
            #!${buildPackages.bash}/bin/bash
            native_hardening=
            for flag in $AOS_HARDENING_ENABLE; do
              case "$flag" in
                pacret) ;;
                *) native_hardening="$native_hardening $flag" ;;
              esac
            done
            export AOS_HARDENING_ENABLE="$native_hardening"
            unset AOS_TARGET_ARCH AOS_TARGET_PLATFORM
            unset C_INCLUDE_PATH CPLUS_INCLUDE_PATH LIBRARY_PATH
            unset NIX_CFLAGS_COMPILE NIX_LDFLAGS
            exec ${buildPackages.cc}/bin/cc "$@"
            EOF
            chmod +x .aos-build-tools/cc-for-build
            export HOSTCC="$PWD/.aos-build-tools/cc-for-build"
            export HOSTCCLD="$HOSTCC"
            # Build generators must not depend on the builder's CPU features.
            sed -i 's/HOST_MARCH=-march=native/HOST_MARCH=/' src/include/defaults.mk
          ''
          + ''
            make -j"$NIX_BUILD_CORES" \
              PREFIX="$out" \
              LIBDIR="$out/lib" \
              BINDIR="$out/bin" \
              INCLUDEDIR="$out/include" \
              PCDIR="$out/lib/pkgconfig" \
              MANDOC="${mandoc}/bin/mandoc" \
              ENABLE_DOCS=1
          '';
      }
      {
        name = "install";
        script = ''
          make install \
            PREFIX="$out" \
            LIBDIR="$out/lib" \
            BINDIR="$out/bin" \
            INCLUDEDIR="$out/include" \
            PCDIR="$out/lib/pkgconfig" \
            MANDIR="$out/share/man" \
            MANDOC="${mandoc}/bin/mandoc" \
            ENABLE_DOCS=1
        '';
      }
    ];

    checks = {
      testing,
      self,
      ...
    }: {
      link = testing.mkLinkCheck {
        pname = "lib-efivar";
        library = self;
        libs = ["-lefivar"];
        testSource = ''
          #include <efivar/efivar.h>

          int main(void) {
              efi_guid_t guid;
              return efi_str_to_guid("8be4df61-93ca-11d2-aa0d-00e098032b8c", &guid) < 0;
          }
        '';
      };
    };

    meta = {
      description = "EFI variable and device-path libraries";
      homepage = "https://github.com/rhboot/efivar";
      license = "LGPL-2.1-only";
    };
  }
