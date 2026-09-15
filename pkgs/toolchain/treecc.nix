##! TreeCC - Aspect-oriented tree compiler generator
{
  lib,
  mkDerivation,
  fetchurl,
  bash,
  gnumake,
  buildPackages,
  stdenv,
}: let
  version = "0.3.10";
in
  mkDerivation {
    pname = "treecc";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "TreeCC's generated node constructor stores the supplied integer and the consumer prints 42.";
        "files" = {
          "main.c" = "#include <stdio.h>\n#include <stdlib.h>\n#include \"generated.h\"\n\nchar *yycurrfilename(void) {\n    return \"nodes.tc\";\n}\n\nlong yycurrlinenum(void) {\n    return 1;\n}\n\nvoid yynodefailed(void) {\n    abort();\n}\n\nint main(void) {\n    expression *value = number_create(42);\n    if (value == NULL) {\n        return 2;\n    }\n    printf(\"%d\\n\", ((number *)value)->value);\n    yynodeclear();\n    return 0;\n}\n";
          "nodes.tc" = "%{\n#include \"generated.h\"\n%}\n\n%node expression %abstract %typedef\n%node number expression =\n{\n    int value;\n}\n";
        };
        "input" = "A TreeCC definition containing an abstract expression node and a concrete number node.";
        "operation" = "Generate C source and a header, compile them with a small consumer, and execute it.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/treecc"
              "-o"
              "generated.c"
              "-h"
              "generated.h"
              "nodes.tc"
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
              "generated.c"
              "main.c"
              "-o"
              "consumer"
            ];
            "exit_code" = 0;
          }
          {
            "argv" = [
              "@work@/primary/consumer"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "42\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "TreeCC rejects the unknown directive with a failure status.";
        "files" = {
          "invalid.tc" = "%qualification-unknown\n";
        };
        "input" = "A TreeCC source containing an unknown directive.";
        "operation" = "Attempt to generate C output from the malformed source.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/treecc"
              "-o"
              "invalid.c"
              "-h"
              "invalid.h"
              "invalid.tc"
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
        "https://ftp.gnu.org/old-gnu/dotgnu/pnet/treecc-${version}.tar.gz"
      ];
      hash = "sha256-Xp0gppOODG/t/tDKvH6emEAk5IgbdI0Hbox18a627+c=";
    };

    buildDeps =
      [bash gnumake]
      ++ (
        if stdenv.isCross
        then [buildPackages.automake buildPackages.treecc]
        else []
      );
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd treecc-${version}
          test "$(head -n 1 tests/run_tests)" = '#!/bin/sh'
          sed -i "1c #!$CONFIG_SHELL" tests/run_tests
        '';
      }
      {
        name = "configure";
        script =
          (
            if stdenv.isCross
            then ''
              # The bundled config.sub predates AArch64. Refresh it from the
              # current AOS-built canonical helper before cross configuration.
              cp ${buildPackages.automake}/share/automake-*/config.sub config.sub
            ''
            else ""
          )
          + ''
            "$CONFIG_SHELL" ./configure $configureFlags --prefix=$out
            ${
              if stdenv.isCross
              then ''sed -i "s|\$(top_builddir)/treecc|${buildPackages.treecc}/bin/treecc|g" examples/Makefile''
              else ""
            }
          '';
      }
      {
        name = "build";
        script = ''
          make SHELL="$CONFIG_SHELL" -j$NIX_BUILD_CORES
        '';
      }
      {
        name = "check";
        script = ''
          ${
            if stdenv.isCross
            then ''echo "skipping target execution tests while cross-compiling for $AOS_TARGET_PLATFORM"''
            else ''make SHELL="$CONFIG_SHELL" -j$NIX_BUILD_CORES check''
          }
        '';
      }
      {
        name = "install";
        script = ''
          make SHELL="$CONFIG_SHELL" install
          test -x "$out/bin/treecc"

          sourceDir=$PWD
          cd "$TMPDIR"
          ${
            if stdenv.isCross
            then "${buildPackages.treecc}/bin/treecc"
            else ''"$out/bin/treecc"''
          } \
            -o expr_c.c \
            -h expr_c.h \
            "$sourceDir/examples/expr_c.tc"
          test -s expr_c.c
          test -s expr_c.h
          cc -I. -c expr_c.c -o expr_c.o
          test -s expr_c.o
          cd "$sourceDir"

          forbidden_shebangs=$(find "$out" -type f -exec grep -I -n -E \
            '^#![[:space:]]*((/bin|/usr/bin|/usr/local/bin)/((ba|da|k|z)?sh)|(/bin|/usr/bin|/usr/local/bin)/env[[:space:]]+(-S[[:space:]]+)?((ba|da|k|z)?sh))([[:space:]]|$)' \
            {} + 2>/dev/null || true)
          if test -n "$forbidden_shebangs"; then
            printf '%s\n' "$forbidden_shebangs" >&2
            echo "forbidden host shell shebang found in treecc output" >&2
            exit 1
          fi

          placeholder_refs=$(find "$out" -type f \
            -exec grep -a -H -n -F '/nix/store/eeee' {} + \
            2>/dev/null || true)
          if test -n "$placeholder_refs"; then
            printf '%s\n' "$placeholder_refs" >&2
            echo "placeholder store reference found in treecc output" >&2
            exit 1
          fi

          dangling_links=$(find "$out" -type l -exec test ! -e {} \; -print)
          if test -n "$dangling_links"; then
            printf '%s\n' "$dangling_links" >&2
            echo "dangling symlink found in treecc output" >&2
            exit 1
          fi
        '';
      }
    ];

    meta = {
      description = "Aspect-oriented tree compiler generator";
      homepage = "https://www.gnu.org/projects/dotgnu/pnet.html";
      license = "GPL-2.0-or-later";
    };
  }
