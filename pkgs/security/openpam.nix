##! OpenPAM -- portable Pluggable Authentication Modules implementation
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  stdenv,
}: let
  version = "20250531";
in
  mkDerivation {
    pname = "openpam";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "OpenPAM returns the three logical arguments without the comment.";
        "files" = {
          "primary.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"openpam primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"openpam rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <stdlib.h>\n#include <string.h>\n#include <security/pam_appl.h>\n#include <security/openpam.h>\nint main(void) {\n    FILE *input = tmpfile();\n    if (input == NULL) return 2;\n    fputs(\"alpha 'two words' beta # ignored\\n\", input);\n    rewind(input);\n    int line = 0, count = 0;\n    char **words = openpam_readlinev(input, &line, &count);\n    int valid = words != NULL && line == 1 && count == 3\n        && strcmp(words[0], \"alpha\") == 0\n        && strcmp(words[1], \"two words\") == 0\n        && strcmp(words[2], \"beta\") == 0;\n    if (words != NULL) {\n        for (int index = 0; index < count; ++index) free(words[index]);\n        free(words);\n    }\n    fclose(input);\n    return valid ? pass() : 3;\n}\n\n";
        };
        "input" = "A PAM configuration line containing a quoted two-word argument and a comment.";
        "operation" = "Tokenize the line through openpam_readlinev.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "primary.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lpam"
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
              "exact" = "openpam primary passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "OpenPAM rejects the line by returning null and no arguments.";
        "files" = {
          "bad-input.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"openpam primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"openpam rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <stdlib.h>\n#include <security/pam_appl.h>\n#include <security/openpam.h>\nint main(void) {\n    FILE *input = tmpfile();\n    if (input == NULL) return 2;\n    fputs(\"alpha 'unterminated\\n\", input);\n    rewind(input);\n    int line = 0, count = 0;\n    char **words = openpam_readlinev(input, &line, &count);\n    fclose(input);\n    if (words != NULL) {\n        for (int index = 0; index < count; ++index) free(words[index]);\n        free(words);\n        return 3;\n    }\n    return line == 1 && count == 0 ? reject() : 4;\n}\n\n";
        };
        "input" = "A PAM configuration line with an unterminated quoted argument.";
        "operation" = "Tokenize the malformed line through openpam_readlinev.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "bad-input.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lpam"
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
              "exact" = "openpam rejected invalid input\n";
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
        "https://downloads.sourceforge.net/project/openpam/openpam/Zingiber/openpam-${version}.tar.gz"
      ];
      hash = "sha256-wesvNpiwElgg2Y3b5WmqbUeNeWuLQlkLEa4A8+cgFZU=";
    };

    buildDeps = [
      gnumake
      pkg-config
    ];
    runtimeDeps = [];
    propagatedDeps = [];

    phases =
      [
        {
          name = "unpack";
          script = ''
            tar xf $src
            cd openpam-${version}

            # The release configures OPENPAM_MODULES_DIR, while the runtime
            # lookup checks the older OPENPAM_MODULES_DIRECTORY spelling.
            # Keep the installed modules in the hermetic package closure.
            sed -i 's/OPENPAM_MODULES_DIRECTORY/OPENPAM_MODULES_DIR/g' \
              lib/libpam/openpam_constants.c
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
              --with-localbase=$out \
              --with-modules-dir=$out/lib/security
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

    meta = {
      description = "Portable Pluggable Authentication Modules implementation";
      homepage = "https://openpam.org/";
      license = "BSD-3-Clause";
    };
  }
