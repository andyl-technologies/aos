##! ICU4C — Unicode and globalization support library
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  python3,
  buildPackages,
  stdenv,
}: let
  version = "78.3";
in
  mkDerivation {
    pname = "icu";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "ICU returns the two expected Unicode code units.";
        "files" = {
          "primary.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"icu primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"icu rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <unicode/ustring.h>\nint main(void) {\n    const char input[3] = {'b', (char)0xc3, (char)0xbc}; UChar output[8]; int32_t length = 0;\n    UErrorCode error = U_ZERO_ERROR;\n    u_strFromUTF8(output, 8, &length, input, sizeof(input), &error);\n    return U_SUCCESS(error) && length == 2 && output[0] == 0x62 && output[1] == 0xfc ? pass() : 2;\n}\n\n";
        };
        "input" = "The UTF-8 bytes for b followed by u-umlaut.";
        "operation" = "Convert the bytes into UTF-16 through ICU's u_strFromUTF8 API.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "primary.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-licuuc"
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
              "exact" = "icu primary passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "ICU returns U_INVALID_CHAR_FOUND.";
        "files" = {
          "bad-input.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"icu primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"icu rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <unicode/ustring.h>\nint main(void) {\n    const char input[1] = {(char)0x80}; UChar output[8]; int32_t length = 0;\n    UErrorCode error = U_ZERO_ERROR;\n    u_strFromUTF8(output, 8, &length, input, sizeof(input), &error);\n    if (error != U_INVALID_CHAR_FOUND) return 2;\n    return reject();\n}\n\n";
        };
        "input" = "A single continuation byte that cannot form a UTF-8 character.";
        "operation" = "Convert the malformed byte through u_strFromUTF8.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "bad-input.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-licuuc"
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
              "exact" = "icu rejected invalid input\n";
            };
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
    };

    inherit version;
    outputs = ["out" "cross"];

    src = fetchurl {
      urls = [
        "https://github.com/unicode-org/icu/releases/download/release-${version}/icu4c-${version}-sources.tgz"
      ];
      hash = "sha256-Oi56R2BLpwLzRYeDCOb+/sphLuiVz0pfIi55Vfq/4MA=";
    };

    buildDeps = [
      gnumake
      python3
    ];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script =
          if stdenv.hostPlatform.isDarwin && stdenv.isCross
          then ''
            tar xf $src
            cd icu/source

            # Modern public Darwin SDKs no longer install tzfile.h. ICU
            # ships the matching IANA header for its tzcode tools.
            sed -i \
              's|#include <tzfile.h>|#include "../tools/tzcode/tzfile.h"|' \
              common/putil.cpp

            # The debug utility exposes these values through ICU's public
            # system-parameter API. Publish reusable target compiler names,
            # not this build's Linux-hosted cross-wrapper store paths.
            sed -i \
              's|"-DU_CC=\\"@CC@\\"" "-DU_CXX=\\"@CXX@\\""|"-DU_CC=\\"cc\\"" "-DU_CXX=\\"c++\\""|' \
              tools/toolutil/Makefile.in
          ''
          else if stdenv.hostPlatform.isDarwin
          then ''
            tar xf $src
            cd icu/source

            # Modern public Darwin SDKs no longer install tzfile.h. ICU
            # ships the matching IANA header for its tzcode tools.
            sed -i \
              's|#include <tzfile.h>|#include "../tools/tzcode/tzfile.h"|' \
              common/putil.cpp
          ''
          else ''
            tar xf $src
            cd icu/source
          '';
      }
      {
        name = "configure";
        script =
          if stdenv.hostPlatform.isDarwin
          then ''
            # ICU otherwise records bare dylib basenames. Its rpath mode uses
            # the configured libdir as the install name, which keeps every
            # consumer resolvable directly from the immutable store output.
            ./configure \
              $configureFlags \
              ${
              if stdenv.isCross
              then "--with-cross-build=${buildPackages.icu.cross}/source"
              else ""
            } \
              --enable-rpath \
              --prefix=$out \
              --enable-shared \
              --enable-static
          ''
          else ''
            ./configure \
              $configureFlags \
              ${
              if stdenv.isCross
              then "--with-cross-build=${buildPackages.icu.cross}/source"
              else ""
            } \
              --prefix=$out \
              --enable-shared \
              --enable-static
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
        script =
          if stdenv.hostPlatform.isDarwin && stdenv.isCross
          then ''
            make install

            # ICU publishes the compiler utilities used to build it for
            # downstream data packaging. Defer them to the consuming Darwin
            # stdenv instead of retaining this Linux-hosted cross wrapper and
            # its native compiler closure.
            metadata_dir="$out/lib/icu/${version}"
            sed -i \
              's|${stdenv.cc}/bin/||g' \
              "$metadata_dir/Makefile.inc" \
              "$metadata_dir/pkgdata.inc"

            # The same downstream metadata also records the Linux build
            # shell and install utility. Consumers supply these build tools;
            # publishing their native store paths would retain an unrelated
            # Linux runtime in every target ICU closure.
            sed -i \
              -e 's|^SHELL = .*|SHELL = bash|' \
              -e 's|^INSTALL_CMD=.*|INSTALL_CMD=install -c|' \
              "$metadata_dir/Makefile.inc" \
              "$metadata_dir/pkgdata.inc"
            if grep -F '${stdenv.cc}' \
              "$metadata_dir/Makefile.inc" \
              "$metadata_dir/pkgdata.inc"; then
              echo "ICU target metadata retains the cross compiler" >&2
              exit 1
            fi
            if grep -E '/nix/store/[a-z0-9]+-(bash|coreutils)-' \
              "$metadata_dir/Makefile.inc" \
              "$metadata_dir/pkgdata.inc"; then
              echo "ICU target metadata retains native build utilities" >&2
              exit 1
            fi

            mkdir -p "$cross"
          ''
          else ''
            make install

            if [ -n "''${AOS_CROSS_COMPILING:-}" ]; then
              mkdir -p "$cross"
            else
              mkdir -p "$cross"
              cp -R . "$cross/source"
            fi
          '';
      }
    ];

    meta = {
      description = "ICU4C Unicode and globalization libraries";
      homepage = "https://icu.unicode.org/";
      license = "Unicode-3.0";
    };

    checks = {
      testing,
      self,
      ...
    }: {
      link = testing.mkLinkCheck {
        pname = "lib-icu";
        library = self;
        libs = ["-licuuc"];
        testSource = ''
          #include <unicode/uversion.h>
          int main(void) {
            UVersionInfo version;
            u_getVersion(version);
            return version[0] == 0;
          }
        '';
      };

      soname = testing.mkSONAMECheck {
        pkg = self;
        libs = ["libicuuc.so"];
      };
    };
  }
