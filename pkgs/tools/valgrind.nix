##! valgrind — Dynamic analysis and profiling tools
{
  lib,
  mkDerivation,
  fetchurl,
  autoconf,
  automake,
  libtool,
  gnumake,
  perl,
  gdb,
}: let
  version = "3.27.1";
in
  mkDerivation {
    pname = "valgrind";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Memcheck accepts the valid memory lifecycle and the program prints 42.";
        "files" = {
          "valid.c" = "#include <stdio.h>\n#include <stdlib.h>\n\nint main(void) {\n    int *answer = malloc(sizeof(*answer));\n    if (answer == NULL) {\n        return 2;\n    }\n    *answer = 42;\n    printf(\"%d\\n\", *answer);\n    free(answer);\n    return 0;\n}\n";
        };
        "input" = "A C program that allocates, reads, and frees one integer.";
        "operation" = "Compile the program and execute it under Valgrind Memcheck.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "valid.c"
              "-o"
              "valid"
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
              "@out@/bin/valgrind"
              "--quiet"
              "--error-exitcode=99"
              "@work@/primary/valid"
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
        "expected" = "Memcheck detects the definite leak and returns the configured rejection status.";
        "files" = {
          "leak.c" = "#include <stdlib.h>\n\nint main(void) {\n    unsigned char *volatile allocation = malloc(42);\n    if (allocation == NULL) {\n        return 2;\n    }\n    *allocation = 42;\n    allocation = NULL;\n    return 0;\n}\n";
        };
        "input" = "A C program that loses its only reference to allocated memory.";
        "operation" = "Run the leaking program under Memcheck with definite leaks promoted to errors.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "leak.c"
              "-o"
              "leak"
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
              "@out@/bin/valgrind"
              "--quiet"
              "--leak-check=full"
              "--errors-for-leak-kinds=definite"
              "--error-exitcode=7"
              "@work@/bad-input/leak"
            ];
            "exit_code" = 7;
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
      urls = ["https://sourceware.org/pub/valgrind/valgrind-${version}.tar.bz2"];
      hash = "sha256-XViRUuuAccAv6rjOarcZ5DGh+8PisXAPVDJjKouSZNw=";
    };

    buildDeps = [autoconf automake libtool gnumake perl];
    runtimeDeps = [perl gdb];
    propagatedDeps = [];
    hardeningDisable = ["stackprotector"];

    configureFlags = "--enable-only64bit --with-mpicc=no";

    checks = {
      testing,
      self,
      ...
    }: {
      tool = testing.mkToolCheck {
        pname = "tool-valgrind";
        tool = self;
        command = "valgrind --version";
      };
    };

    meta = {
      description = "Dynamic analysis and profiling tool suite";
      homepage = "https://valgrind.org/";
      license = "GPL-2.0-or-later";
      mainProgram = "valgrind";
    };
  }
