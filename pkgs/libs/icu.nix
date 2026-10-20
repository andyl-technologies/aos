##! ICU4C — Unicode and globalization support library
{
  lib,
  mkDerivation,
  fetchgit,
  gnumake,
  python3,
  buildPackages,
  stdenv,
}: let
  version = "78.3";
  unpackSource = ''
    cp -a "$src/LICENSE" ./LICENSE
    cp -a "$src/icu4c" ./icu4c
    cp -a "$src/tools" ./tools
    chmod -R u+w icu4c tools
    cd icu4c/source

    test -f data/locales/root.txt
    if test -n "$(find . -type f \
        \( -name '*.dat' -o -name '*.icu' -o -name '*.res' \
        -o -name '*.class' -o -name '*.jar' -o -name '*.so' \
        -o -name '*.a' -o -name '*.o' \) -print -quit)"; then
      echo "ICU source checkout contains prebuilt data or executables" >&2
      exit 1
    fi
  '';
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
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

    # GNU strip rewrites static archive headers with live timestamps. ICU
    # already builds its archives deterministically, so retain them intact.
    dontStrip = true;

    src = fetchgit {
      url = "https://github.com/unicode-org/icu.git";
      ref = "release-${version}";
      rev = "21d1eb0f306e1141c10931e914dfc038c06121da";
      hash = "sha256-T/WzaAr/i8kOPtIhI/+XvmcLwIQFZegBipb4GlAIFdM=";
      name = "icu4c-${version}-source-and-data";

      git = buildPackages.git-minimal;
      caCertificates = buildPackages.ca-certificates;
      coreutils = buildPackages.coreutils;

      # ICU's release tarball contains a precompiled data library. Fetch
      # text sources and build tools without any compiled blobs instead.
      sparsePatterns = [
        "/LICENSE"
        "/icu4c/source/"
        "/icu4c/LICENSE"
        "/tools/unicode/c/genprops/"
        "/tools/unicode/c/genuca/"
        "!*.dat"
        "!*.icu"
        "!*.res"
        "!*.class"
        "!*.jar"
        "!*.so"
        "!*.a"
        "!*.o"
        "!*.dll"
        "!*.dylib"
        "!*.exe"
        "!*.bin"
      ];
    };

    buildDeps = [
      gnumake
      python3
      buildPackages.findutils
    ];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script =
          if stdenv.hostPlatform.isDarwin && stdenv.isCross
          then ''
            ${unpackSource}

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
            ${unpackSource}

            # Modern public Darwin SDKs no longer install tzfile.h. ICU
            # ships the matching IANA header for its tzcode tools.
            sed -i \
              's|#include <tzfile.h>|#include "../tools/tzcode/tzfile.h"|' \
              common/putil.cpp
          ''
          else ''
            ${unpackSource}
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

            # AOS GNU ar and ranlib default to live archive timestamps.
            # ICU's central make settings also feed pkgdata's data archive.
            grep -q '^ARFLAGS = .* r$' icudefs.mk
            grep -q '^RANLIB = ' icudefs.mk
            sed -i '/^ARFLAGS = /s/ r$/ rD/' icudefs.mk
            sed -i '/^RANLIB = /s/$/ -D/' icudefs.mk
          '';
      }
      {
        name = "generate-data";
        script =
          if stdenv.isCross
          then ''
            # Native ICU produced this data from the same pinned text tree.
            mkdir -p data/in
            cp -a ${buildPackages.icu.cross}/source/data/in/. data/in/
          ''
          else ''
            # ICU's default make expects property data from release binaries.
            # Build the upstream generators against source-built bootstrap
            # libraries, then regenerate their inputs from Unicode text.
            mkdir -p lib bin
            for component in stubdata common i18n io tools; do
              make -C "$component" -j"$NIX_BUILD_CORES"
            done

            # Generator executables link the just-built ICU libraries and
            # its empty bootstrap data library before packaged data exists.
            export LD_LIBRARY_PATH="$PWD/lib:$PWD/stubdata"

            tool_sources="$src/tools/unicode/c"
            mkdir -p data/in/coll generated-tools
            $CXX -std=c++17 -Icommon -Itools/toolutil \
              "$tool_sources/genprops/genprops.cpp" \
              "$tool_sources/genprops/pnamesbuilder.cpp" \
              "$tool_sources/genprops/corepropsbuilder.cpp" \
              "$tool_sources/genprops/bidipropsbuilder.cpp" \
              "$tool_sources/genprops/casepropsbuilder.cpp" \
              "$tool_sources/genprops/emojipropsbuilder.cpp" \
              "$tool_sources/genprops/layoutpropsbuilder.cpp" \
              "$tool_sources/genprops/namespropsbuilder.cpp" \
              -Llib -Lstubdata -Wl,-rpath,"$PWD/lib" \
              -licutu -licuuc -licudata \
              -o generated-tools/genprops
            $CXX -std=c++17 -Icommon -Ii18n -Itools/toolutil \
              "$tool_sources/genuca/genuca.cpp" \
              "$tool_sources/genuca/collationbasedatabuilder.cpp" \
              -Llib -Lstubdata -Wl,-rpath,"$PWD/lib" \
              -licutu -licui18n -licuuc -licudata \
              -o generated-tools/genuca

            norm2="$PWD/data/unidata/norm2"
            bin/gennorm2 -o common/norm2_nfc_data.h \
              -s "$norm2" nfc.txt --csource
            bin/gennorm2 -o data/in/nfc.nrm \
              -s "$norm2" nfc.txt
            bin/gennorm2 -o data/in/nfkc.nrm \
              -s "$norm2" nfc.txt nfkc.txt
            bin/gennorm2 -o data/in/nfkc_cf.nrm \
              -s "$norm2" nfc.txt nfkc.txt nfkc_cf.txt
            bin/gennorm2 -o data/in/nfkc_scf.nrm \
              -s "$norm2" nfc.txt nfkc.txt nfkc_scf.txt
            bin/gennorm2 -o data/in/uts46.nrm \
              -s "$norm2" nfc.txt uts46.txt

            generated-tools/genprops "$PWD/.."
            generated-tools/genuca \
              --hanOrder implicit "$PWD/.."
            generated-tools/genuca \
              --hanOrder radical-stroke "$PWD/.."
            generated-tools/genuca \
              --icu4x --hanOrder implicit "$PWD/.."
            generated-tools/genuca \
              --icu4x --hanOrder radical-stroke "$PWD/.."
            unset LD_LIBRARY_PATH
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
