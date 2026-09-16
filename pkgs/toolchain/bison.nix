##! GNU Bison — Parser generator
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  m4,
  bash,
  stdenv,
}: let
  version = "3.8.2";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "bison";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The generated parser accepts the input and prints its token count.";
        "files" = {
          "parser.y" = "%{\n#include <stdio.h>\nint count;\nint yylex(void) { int c = getchar(); return c == 'a' ? 'a' : 0; }\nvoid yyerror(const char *message) { (void)message; }\n%}\n%%\ninput: items { printf(\"parsed %d tokens\\n\", count); };\nitems: 'a' { count = 1; } | items 'a' { ++count; };\n%%\nint main(void) { return yyparse(); }\n";
        };
        "input" = "A grammar accepting a nonempty sequence of the token 'a'.";
        "operation" = "Generate a C parser, compile it, and parse a valid token sequence.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/bison"
              "-o"
              "parser.c"
              "parser.y"
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
              "@cc@"
              "parser.c"
              "-o"
              "parser"
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
              "@work@/primary/parser"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdin" = "aaa";
            "stdout" = {
              "exact" = "parsed 3 tokens\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Bison rejects the grammar with status 1.";
        "files" = {
          "invalid.y" = "%token\n%%\ninput: ;\n%%\n";
        };
        "input" = "A grammar with a token declaration missing its identifier.";
        "operation" = "Ask Bison to generate a parser from the malformed grammar.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/bison"
              "-o"
              "invalid.c"
              "invalid.y"
            ];
            "exit_code" = 1;
            "observes_rejection" = true;
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
        "https://gnu.mirror.constant.com/bison/bison-${version}.tar.xz"
        "https://mirrors.kernel.org/gnu/bison/bison-${version}.tar.xz"
        "https://mirrors.kernel.org/gnu/bison/bison-${version}.tar.xz"
      ];
      hash = "sha256-m7oCFMz38QecXVkhAEUie89hlRmEDr+oDNOEnP9aW/I=";
    };

    buildDeps = [
      gnumake
      m4
    ];
    runtimeDeps =
      if stdenv.hostPlatform.isDarwin
      then [bash]
      else [];
    propagatedDeps = [m4];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd bison-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            $configureFlags \
            --prefix=$out \
            --disable-nls
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
          if stdenv.hostPlatform.isDarwin
          then ''
            make install
            sed -i "1s|^#!.*|#!${bash}/bin/bash|" "$out/bin/yacc"
          ''
          else ''
            make install
          '';
      }
    ];

    meta = {
      description = "GNU Bison — general-purpose parser generator";
      homepage = "https://www.gnu.org/software/bison/";
      license = "GPL-3.0-or-later";
    };
  }
