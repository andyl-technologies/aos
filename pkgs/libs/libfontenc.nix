##! X font encoding library with the complete encoding database.
{
  lib,
  mkDerivation,
  fetchurl,
  buildPackages,
  stdenv,
  xorgproto,
  zlib,
  encodings,
}: let
  package = import ./_libfontenc.nix {
    inherit mkDerivation fetchurl buildPackages stdenv xorgproto zlib encodings;
  };
in
  package.overrideAttrs (_: {
    qualification.packageProbe = lib.qualification.commandProbe {
      primary = {
        input = "The installed ISO-8859-11 font encoding database.";
        operation = "Find the encoding and map its first Thai character to Unicode.";
        expected = "The encoding lookup maps byte A1 to Unicode U+0E01.";
        files."encoding.c" = ''
          #include <X11/fonts/fontenc.h>
          #include <stdio.h>
          #include <string.h>

          int main(void) {
            FontEncPtr encoding = FontEncFind("iso8859-11", NULL);
            if (!encoding || strcmp(encoding->name, "iso8859-11") != 0) return 1;
            FontMapPtr mapping = FontMapFind(encoding, FONT_ENCODING_UNICODE, 0, 0);
            if (!mapping || FontEncRecode(0xA1, mapping) != 0x0E01) return 2;

            puts("libfontenc Thai encoding lookup passed");
          }
        '';
        artifacts = [];
        steps = [
          {
            argv = [
              "@cc@"
              "-std=c11"
              "-I@out@/include"
              "encoding.c"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lfontenc"
              "-o"
              "encoding"
            ];
            exit_code = 0;
            stdout.exact = "";
          }
          {
            argv = ["./encoding"];
            exit_code = 0;
            stdout.exact = "libfontenc Thai encoding lookup passed\n";
            stderr.exact = "";
          }
        ];
      };
      badInput = {
        input = "A name absent from the font encoding database.";
        operation = "Look up the unknown encoding.";
        expected = "The library returns no encoding.";
        files."bad.c" = ''
          #include <X11/fonts/fontenc.h>
          #include <stdio.h>

          int main(void) {
            if (FontEncFind("not-an-encoding", NULL) != NULL) return 1;

            puts("libfontenc rejected unknown encoding");
            return 7;
          }
        '';
        artifacts = [];
        steps = [
          {
            argv = [
              "@cc@"
              "-std=c11"
              "-I@out@/include"
              "bad.c"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lfontenc"
              "-o"
              "bad"
            ];
            exit_code = 0;
            stdout.exact = "";
          }
          {
            argv = ["./bad"];
            exit_code = 7;
            observes_rejection = true;
            stdout.exact = "libfontenc rejected unknown encoding\n";
            stderr.exact = "";
          }
        ];
      };
    };
  })
