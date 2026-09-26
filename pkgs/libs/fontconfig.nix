##! Fontconfig — font configuration and customization library
{
  lib,
  mkDerivation,
  fetchurl,
  stdenv,
  gnumake,
  autoconf,
  automake,
  libtool,
  gettext,
  gperf,
  pkg-config,
  python3,
  freetype,
  expat,
  zlib,
}: let
  version = "2.18.3";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "fontconfig";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The public API returns the expected value and the consumer prints the fixed success line.";
        "files" = {
          "primary.c" = "#include <stdio.h>\n#include <string.h>\n#include <fontconfig/fontconfig.h>\n\nint main(void) {\n    FcPattern *pattern = FcNameParse((const FcChar8 *)\"monospace:weight=200\");\n    FcChar8 *family = NULL;\n    if (pattern == NULL\n        || FcPatternGetString(pattern, FC_FAMILY, 0, &family) != FcResultMatch\n        || family == NULL || strcmp((const char *)family, \"monospace\") != 0) {\n        if (pattern != NULL) FcPatternDestroy(pattern);\n        return 2;\n    }\n    FcPatternDestroy(pattern);\n    return puts(\"fontconfig api passed\") == EOF;\n}\n";
        };
        "input" = "A font pattern containing a family and integer weight.";
        "operation" = "Parse the pattern with FcNameParse and retrieve its family field.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "primary.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lfontconfig"
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
              "exact" = "fontconfig api passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "The API reports the rejected boundary and the consumer returns the fixed rejection status.";
        "files" = {
          "bad-input.c" = "#include <stdio.h>\n#include <fontconfig/fontconfig.h>\n\nint main(void) {\n    FcPattern *pattern = FcNameParse((const FcChar8 *)\"monospace\");\n    FcChar8 *family = NULL;\n    if (pattern == NULL) {\n        return 2;\n    }\n    FcResult result = FcPatternGetString(pattern, FC_FAMILY, 1, &family);\n    FcPatternDestroy(pattern);\n    if (result != FcResultNoId) {\n        return 3;\n    }\n    fputs(\"fontconfig rejected invalid input\\n\", stderr);\n    return 7;\n}\n";
        };
        "input" = "A request for a second family value from a pattern containing only one.";
        "operation" = "Query the out-of-range value index with FcPatternGetString.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "bad-input.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lfontconfig"
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
              "exact" = "fontconfig rejected invalid input\n";
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
        "https://gitlab.freedesktop.org/fontconfig/fontconfig/-/archive/${version}/fontconfig-${version}.tar.gz"
      ];
      hash = "sha256-muAeHVOs3vVgEMVFHNNKpB0yWy+szYYGRI2PoBsklrM=";
    };

    buildDeps = [
      gnumake
      autoconf
      automake
      libtool
      gettext
      gperf
      pkg-config
      python3
    ];
    runtimeDeps = [
      freetype
      expat
      zlib
    ];
    # Consumers need these to resolve fontconfig.pc's Requires fields.
    propagatedDeps = [freetype expat];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd fontconfig-${version}
        '';
      }
      {
        name = "patch";
        script = ''
          export ACLOCAL_PATH="${libtool}/share/aclocal"
          NOCONFIGURE=1 $CONFIG_SHELL ./autogen.sh
        '';
      }
      {
        name = "build";
        script =
          lib.optionalString stdenv.isCross ''
            # The runtime-only configure probe has no cross fallback. AOS
            # target toolchains provide C99 va_copy for Linux and Darwin.
            export ac_cv_va_copy=C99
          ''
          + ''
            FREETYPE_CFLAGS="-I${freetype}/include/freetype2" \
            FREETYPE_LIBS="-L${freetype}/lib -lfreetype" \
            $CONFIG_SHELL ./configure \
              $configureFlags \
              --prefix=$out \
              --sysconfdir=$out/etc \
              --localstatedir=$out/var \
              --disable-docs
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

    meta = {
      description = "Fontconfig — font configuration and customization library";
      homepage = "https://www.freedesktop.org/wiki/Software/fontconfig/";
      license = "MIT";
    };
  }
