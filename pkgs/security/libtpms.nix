{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  autoconf,
  automake,
  libtool,
  m4,
  perl,
  openssl,
}: let
  version = "0.10.2";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "libtpms";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Libtpms exposes a nonzero version and accepts TPM 2.";
        "files" = {
          "primary.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"libtpms primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"libtpms rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <libtpms/tpm_library.h>\nint main(void) {\n    return TPMLIB_GetVersion() > 0\n        && TPMLIB_ChooseTPMVersion(TPMLIB_TPM_VERSION_2) == 0 ? pass() : 2;\n}\n\n";
        };
        "input" = "A request to select the TPM 2 implementation.";
        "operation" = "Query libtpms's version and select TPM 2 through TPMLIB_ChooseTPMVersion.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "primary.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-ltpms"
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
              "exact" = "libtpms primary passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Libtpms returns a nonzero parameter error.";
        "files" = {
          "bad-input.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"libtpms primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"libtpms rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <libtpms/tpm_library.h>\nint main(void) {\n    TPM_RESULT status = TPMLIB_ChooseTPMVersion((TPMLIB_TPMVersion)99);\n    return status != 0 ? reject() : 2;\n}\n\n";
        };
        "input" = "A TPM implementation selector outside the public enum.";
        "operation" = "Select the invalid implementation through TPMLIB_ChooseTPMVersion.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "bad-input.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-ltpms"
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
              "exact" = "libtpms rejected invalid input\n";
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
        "https://github.com/stefanberger/libtpms/archive/refs/tags/v${version}.tar.gz"
      ];
      hash = "sha256-7awDaA+KShxcHWCaEOP0HhoSnjj/UVjwyN6u3HGfsSc=";
    };

    # perl provides pod2man, which libtpms uses to build its man pages.
    buildDeps = [gnumake pkg-config autoconf automake libtool m4 perl];
    runtimeDeps = [openssl];
    propagatedDeps = [openssl];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd libtpms-${version}
        '';
      }
      {
        # GitHub archive ships no configure — autogen.sh regenerates it.
        # ACLOCAL_PATH must reach pkg.m4 (PKG_CHECK_MODULES) and libtool's
        # LT_INIT macros, else autoreconf fails. --with-tpm2 enables the
        # TPM 2.0 personality swtpm drives.
        name = "configure";
        script = ''
          nativePkgConfig=$(dirname "$(dirname "$(command -v pkg-config)")")
          nativeLibtool=$(dirname "$(dirname "$(command -v libtoolize)")")
          export ACLOCAL_PATH="$nativePkgConfig/share/aclocal:$nativeLibtool/share/aclocal''${ACLOCAL_PATH:+:$ACLOCAL_PATH}"
          NOCONFIGURE=1 ./autogen.sh
          ./configure \
            $configureFlags \
            --prefix=$out \
            --disable-static \
            --with-openssl \
            --with-tpm2
        '';
      }
      {
        # libtpms bakes -Werror into AM_CFLAGS; GCC 14's -Warray-bounds
        # fires on its intentional flexible bignum scratch arrays. CFLAGS
        # is appended after AM_CFLAGS, so -Wno-error demotes them.
        name = "build";
        script = ''
          make -j$NIX_BUILD_CORES CFLAGS="-O2 -g -Wno-error"
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
      description = "TPM emulation library (TPM 1.2 + TPM 2.0) used by swtpm";
      homepage = "https://github.com/stefanberger/libtpms";
      license = "BSD-3-Clause";
    };
  }
