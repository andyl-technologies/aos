##! Expat — XML parsing library
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  stdenv,
}: let
  version = "2.8.4";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "expat";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The public API returns the expected value and the consumer prints the fixed success line.";
        "files" = {
          "primary.c" = "#include <stdio.h>\n#include <string.h>\n#include <expat.h>\n\nint main(void) {\n    const char document[] = \"<root><value>42</value></root>\";\n    XML_Parser parser = XML_ParserCreate(NULL);\n    if (parser == NULL || XML_Parse(parser, document, (int)strlen(document), XML_TRUE) != XML_STATUS_OK) {\n        XML_ParserFree(parser);\n        return 2;\n    }\n    XML_ParserFree(parser);\n    return puts(\"expat api passed\") == EOF;\n}\n";
        };
        "input" = "A well-formed XML document with nested elements.";
        "operation" = "Parse the complete document with XML_Parse.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "primary.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lexpat"
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
              "exact" = "expat api passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "The public API reports rejection and the consumer exits with the fixed rejection status and diagnostic.";
        "files" = {
          "bad-input.c" = "#include <stdio.h>\n#include <string.h>\n#include <expat.h>\n\nint main(void) {\n    const char document[] = \"<root><value>42</root>\";\n    XML_Parser parser = XML_ParserCreate(NULL);\n    if (parser == NULL) {\n        return 2;\n    }\n    enum XML_Status status = XML_Parse(parser, document, (int)strlen(document), XML_TRUE);\n    XML_ParserFree(parser);\n    if (status != XML_STATUS_ERROR) {\n        return 3;\n    }\n    fputs(\"expat rejected invalid input\\n\", stderr);\n    return 7;\n}\n";
        };
        "input" = "An XML document whose closing tag does not match its opening tag.";
        "operation" = "Parse the malformed complete document with XML_Parse.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "bad-input.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lexpat"
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
              "exact" = "expat rejected invalid input\n";
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
        "https://github.com/libexpat/libexpat/releases/download/R_${
          builtins.replaceStrings ["."] ["_"] version
        }/expat-${version}.tar.xz"
      ];
      hash = "sha256-ZWrhzI2jtOpRO7TiVPM+YkOTgITA7GI52oczdrCZhac=";
    };

    buildDeps = [gnumake];
    runtimeDeps = [];
    propagatedDeps = [];

    phases =
      [
        {
          name = "unpack";
          script = ''
            tar xf $src
            cd expat-${version}
          '';
        }
      ]
      ++ (
        if stdenv.isCross && stdenv.hostPlatform.isDarwin
        then [
          {
            name = "darwin-build-paths";
            script = ''
              export CFLAGS="$CFLAGS \
                -ffile-prefix-map=$PWD=. \
                -fdebug-prefix-map=$PWD=."
            '';
          }
        ]
        else []
      )
      ++ [
        {
          name = "configure";
          script = ''
            ./configure \
              $configureFlags \
              --prefix=$out \
              --disable-static \
              --enable-shared \
              --without-docbook
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
          script = ''
            make install
          '';
        }
      ];

    checks = {
      testing,
      self,
      pkgs,
    }: {
      link = testing.mkLinkCheck {
        pname = "lib-expat";
        library = self;
        libs = ["-lexpat"];
        testSource = ''
          #include <expat.h>
          #include <stdio.h>
          int main() {
            printf("expat version: %s\n", XML_ExpatVersion());
            return 0;
          }
        '';
      };
    };

    meta = {
      description = "Expat — XML parsing C library";
      homepage = "https://libexpat.github.io/";
      license = "MIT";
    };
  }
