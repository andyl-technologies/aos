##! libedit — NetBSD command-line editing library
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  ncurses,
}: let
  version = "20260512-3.1";
in
  mkDerivation {
    pname = "libedit";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The tokenizer returns three arguments and preserves the quoted space.";
        "files" = {
          "primary.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"libedit primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"libedit rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <string.h>\n#include <histedit.h>\nint main(void) {\n    Tokenizer *tokenizer = tok_init(NULL); int count = 0; const char **words = NULL;\n    if (tokenizer == NULL) return 2;\n    int status = tok_str(tokenizer, \"run 'answer 42' now\", &count, &words);\n    int ok = status == 0 && count == 3 && strcmp(words[1], \"answer 42\") == 0;\n    tok_end(tokenizer);\n    return ok ? pass() : 3;\n}\n\n";
        };
        "input" = "A command line containing a quoted two-word argument.";
        "operation" = "Tokenize the line through libedit's tok_str interface.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "primary.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-ledit"
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
              "exact" = "libedit primary passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "libedit returns its unmatched-quote status.";
        "files" = {
          "bad-input.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"libedit primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"libedit rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <histedit.h>\nint main(void) {\n    Tokenizer *tokenizer = tok_init(NULL); int count = 0; const char **words = NULL;\n    if (tokenizer == NULL) return 2;\n    int status = tok_str(tokenizer, \"run 'unterminated\", &count, &words);\n    tok_end(tokenizer);\n    if (status == 0) return 3;\n    return reject();\n}\n\n";
        };
        "input" = "A command line containing an unterminated single quote.";
        "operation" = "Tokenize the malformed line through tok_str.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "bad-input.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-ledit"
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
              "exact" = "libedit rejected invalid input\n";
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
      urls = ["https://thrysoee.dk/editline/libedit-${version}.tar.gz"];
      hash = "sha256-Qy1efqiwEW3Tny7Ke8EdDu13+qa3fqUmrOiZB8I+pKA=";
    };

    buildDeps = [gnumake];
    runtimeDeps = [ncurses];
    propagatedDeps = [ncurses];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd libedit-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure $configureFlags \
            --prefix="$out" \
            --enable-widec
        '';
      }
      {
        name = "build";
        script = ''make -j"$NIX_BUILD_CORES"'';
      }
      {
        name = "check";
        script = ''make check'';
      }
      {
        name = "install";
        script = ''make install'';
      }
    ];

    checks = {
      testing,
      self,
      ...
    }: {
      link = testing.mkLinkCheck {
        pname = "libedit";
        library = self;
        libs = ["-ledit" "-lncursesw"];
        testSource = ''
          #include <histedit.h>

          int main(void) {
              History *history = history_init();
              if (history == NULL) return 1;
              history_end(history);
              return 0;
          }
        '';
      };
    };

    meta = {
      description = "Port of the NetBSD command-line editor library";
      homepage = "https://thrysoee.dk/editline/";
      license = "BSD-3-Clause";
    };
  }
