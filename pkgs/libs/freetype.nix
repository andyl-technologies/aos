##! FreeType — font rendering library
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  zlib,
  bash,
  stdenv,
  buildPackages,
}: let
  version = "2.14.3";
  isDarwinCross = stdenv.isCross && stdenv.hostPlatform.isDarwin;
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "freetype";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The API returns the expected value and the consumer prints the fixed success line.";
        "files" = {
          "primary.c" = "#include <stdio.h>\n#include <ft2build.h>\n#include FT_FREETYPE_H\n\nint main(void) {\n    FT_Library library;\n    FT_Int major = 0, minor = 0, patch = 0;\n    if (FT_Init_FreeType(&library) != 0) {\n        return 2;\n    }\n    FT_Library_Version(library, &major, &minor, &patch);\n    FT_Done_FreeType(library);\n    if (major < 2 || minor < 0 || patch < 0) {\n        return 3;\n    }\n    return puts(\"freetype api passed\") == EOF;\n}\n";
        };
        "input" = "A request to initialize FreeType and query its linked version.";
        "operation" = "Initialize a library handle and read the major, minor, and patch version.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "primary.c"
              "-I@out@/include/freetype2"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lfreetype"
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
              "exact" = "freetype api passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "The API reports rejection and the consumer emits the fixed diagnostic and rejection status.";
        "files" = {
          "bad-input.c" = "#include <stdio.h>\n#include <ft2build.h>\n#include FT_FREETYPE_H\n\nint main(void) {\n    const FT_Byte invalid[] = {'n', 'o', 'p', 'e'};\n    FT_Library library;\n    FT_Face face;\n    if (FT_Init_FreeType(&library) != 0) {\n        return 2;\n    }\n    FT_Error status = FT_New_Memory_Face(library, invalid, sizeof(invalid), 0, &face);\n    if (status == 0) {\n        FT_Done_Face(face);\n        FT_Done_FreeType(library);\n        return 3;\n    }\n    FT_Done_FreeType(library);\n    fputs(\"freetype rejected invalid input\\n\", stderr);\n    return 7;\n}\n";
        };
        "input" = "A four-byte buffer that is not a font file.";
        "operation" = "Create a memory face from the invalid bytes.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "bad-input.c"
              "-I@out@/include/freetype2"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lfreetype"
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
              "exact" = "freetype rejected invalid input\n";
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
        "https://download-mirror.savannah.gnu.org/releases/freetype/freetype-${version}.tar.xz"
      ];
      hash = "sha256-NrxPHMQTM1No7mVsQq/KZcWjmH6HaMwozxG6d154Wl8=";
    };

    buildDeps = [gnumake];
    runtimeDeps =
      [zlib]
      ++ (
        if stdenv.hostPlatform.isDarwin
        then [bash]
        else []
      );
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd freetype-${version}
        '';
      }
      {
        name = "build";
        script =
          if isDarwinCross
          then ''
            # FreeType builds apinames for the Linux build machine. Isolate
            # that compiler from the surrounding target SDK and arm64-only
            # PAC hardening before passing it through upstream's CC_BUILD.
            native_cc=${buildPackages.cc}/bin/cc
            mkdir -p .aos-build-tools
            cat > .aos-build-tools/cc-for-build <<EOF
            #!$CONFIG_SHELL
            native_hardening=
            for token in \$AOS_HARDENING_ENABLE; do
              case "\$token" in
                pacret) ;;
                *) native_hardening="\$native_hardening \$token" ;;
              esac
            done
            export AOS_HARDENING_ENABLE="\$native_hardening"
            unset AOS_TARGET_ARCH AOS_TARGET_PLATFORM
            unset C_INCLUDE_PATH CPLUS_INCLUDE_PATH LIBRARY_PATH
            unset MACOSX_DEPLOYMENT_TARGET NIX_CFLAGS_COMPILE NIX_LDFLAGS SDKROOT
            exec "$native_cc" "\$@"
            EOF
            chmod +x .aos-build-tools/cc-for-build

            CC_BUILD="$PWD/.aos-build-tools/cc-for-build" \
              $CONFIG_SHELL ./configure \
                $configureFlags \
                --prefix=$out \
                --enable-freetype-config \
                --with-zlib=yes \
                --without-bzip2 \
                --without-png \
                --without-harfbuzz \
                --without-brotli
            make -j$NIX_BUILD_CORES
          ''
          else ''
            $CONFIG_SHELL ./configure \
              $configureFlags \
              --prefix=$out \
              --enable-freetype-config \
              --with-zlib=yes \
              --without-bzip2 \
              --without-png \
              --without-harfbuzz \
              --without-brotli
            make -j$NIX_BUILD_CORES
          '';
      }
      {
        name = "install";
        script =
          if stdenv.hostPlatform.isDarwin
          then ''
            make install
            sed -i "1s|^#!.*|#!${bash}/bin/bash|" "$out/bin/freetype-config"
          ''
          else ''
            make install
          '';
      }
    ];

    meta = {
      description = "FreeType — font rendering library";
      homepage = "https://freetype.org";
      license = "FTL OR GPL-2.0-or-later";
    };
  }
