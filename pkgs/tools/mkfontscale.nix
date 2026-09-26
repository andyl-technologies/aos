##! X font index generator.
{
  lib,
  mkDerivation,
  fetchurl,
  buildPackages,
  stdenv,
  libfontenc,
  freetype,
  zlib,
  bzip2,
  xorgproto,
}: let
  version = "1.2.4";
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
        {
          abi = ["darwin"];
          cpu = ["x86_64" "aarch64"];
          os = ["darwin"];
        }
      ];
      target = [];
      role = "public-package";
    };
    pname = "mkfontscale";
    qualification.packageProbe = lib.qualification.commandProbe {
      primary = {
        input = "A one-glyph BDF font with an ISO-8859-11 XLFD name.";
        operation = "Generate its font directory index.";
        expected = "The generated index contains the font and its XLFD name.";
        files."fonts/tiny.bdf" = ''
          STARTFONT 2.1
          FONT -misc-aos-medium-r-normal--8-80-75-75-c-80-iso8859-11
          SIZE 8 75 75
          FONTBOUNDINGBOX 8 8 0 0
          STARTPROPERTIES 2
          FONT_ASCENT 8
          FONT_DESCENT 0
          ENDPROPERTIES
          CHARS 1
          STARTCHAR A
          ENCODING 65
          SWIDTH 500 0
          DWIDTH 8 0
          BBX 8 8 0 0
          BITMAP
          18
          24
          42
          7E
          42
          42
          42
          00
          ENDCHAR
          ENDFONT
        '';
        artifacts = [];
        steps = [
          {
            argv = ["@out@/bin/mkfontscale" "-b" "fonts"];
            exit_code = 0;
            stdout.exact = "";
            stderr.exact = "";
          }
          {
            argv = [
              "@python@"
              "-c"
              ''
                from pathlib import Path

                assert Path("fonts/fonts.dir").read_text() == (
                    "1\n"
                    "tiny.bdf -misc-aos-medium-r-normal--8-80-75-75-c-80-iso8859-11\n"
                )
                print("mkfontscale BDF indexing passed")
              ''
            ];
            exit_code = 0;
            stdout.exact = "mkfontscale BDF indexing passed\n";
            stderr.exact = "";
          }
        ];
      };
      badInput = {
        input = "Text without a BDF font header, named with a .bdf suffix.";
        operation = "Attempt to index the directory as fonts.";
        expected = "The invalid file is omitted from the index.";
        files."fonts/garbage.bdf" = "not a BDF font\n";
        artifacts = [];
        steps = [
          {
            argv = ["@out@/bin/mkfontscale" "-b" "fonts"];
            exit_code = 0;
            stdout.exact = "";
            stderr.exact = "";
          }
          {
            argv = [
              "@python@"
              "-c"
              ''
                from pathlib import Path

                assert Path("fonts/fonts.dir").read_text() == "0\n"
                print("mkfontscale omitted invalid font")
                raise SystemExit(7)
              ''
            ];
            exit_code = 7;
            observes_rejection = true;
            stdout.exact = "mkfontscale omitted invalid font\n";
            stderr.exact = "";
          }
        ];
      };
    };
    inherit version;
    src = fetchurl {
      urls = ["https://www.x.org/releases/individual/app/mkfontscale-${version}.tar.xz"];
      hash = "0phsn0fvbm0wd805znlqyawialrh1s2pir9fz7ihwv4vgahr4550";
    };
    buildDeps = [buildPackages.gnumake buildPackages.pkg-config];
    runtimeDeps = [libfontenc freetype zlib bzip2 xorgproto];
    phases =
      [
        {
          name = "unpack";
          script = ''
            tar xf "$src"
            cd mkfontscale-${version}
          '';
        }
        {
          name = "configure";
          script = ''
            $CONFIG_SHELL ./configure $configureFlags --prefix="$out"
          '';
        }
        {
          name = "build";
          script = ''
            make -j"$NIX_BUILD_CORES"
          '';
        }
      ]
      ++ (
        if stdenv.isCross
        then []
        else [
          {
            name = "check";
            script = ''
              make check
            '';
          }
        ]
      )
      ++ [
        {
          name = "install";
          script = ''
            make install
            mkdir -p "$out/share/licenses/mkfontscale"
            cp COPYING "$out/share/licenses/mkfontscale/"
          '';
        }
      ];
    meta = {
      description = "X font index generator";
      homepage = "https://www.x.org/";
      license = "MIT";
    };
  }
