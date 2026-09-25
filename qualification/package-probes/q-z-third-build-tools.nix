##! Exercises additional Q-through-Z build and dynamic-analysis tools.
{testing}: {
  valgrind = testing.mkQualificationPackageProbe {
    name = "valgrind";
    spec = {
      schema_version = "aos.release.package-probe/v1";
      package = "valgrind";
      primary = {
        input = "A C program that allocates, reads, and frees one integer.";
        operation = "Compile the program and execute it under Valgrind Memcheck.";
        expected = "Memcheck accepts the valid memory lifecycle and the program prints 42.";
        files."valid.c" = ''
          #include <stdio.h>
          #include <stdlib.h>

          int main(void) {
              int *answer = malloc(sizeof(*answer));
              if (answer == NULL) {
                  return 2;
              }
              *answer = 42;
              printf("%d\n", *answer);
              free(answer);
              return 0;
          }
        '';
        steps = [
          {
            argv = ["@cc@" "valid.c" "-o" "valid"];
            exit_code = 0;
            stdout.exact = "";
            stderr.exact = "";
          }
          {
            argv = ["@out@/bin/valgrind" "--quiet" "--error-exitcode=99" "@work@/primary/valid"];
            exit_code = 0;
            stdout.exact = "42\n";
            stderr.exact = "";
          }
        ];
        artifacts = [];
      };
      bad_input = {
        input = "A C program that loses its only reference to allocated memory.";
        operation = "Run the leaking program under Memcheck with definite leaks promoted to errors.";
        expected = "Memcheck detects the definite leak and returns the configured rejection status.";
        files."leak.c" = ''
          #include <stdlib.h>

          int main(void) {
              unsigned char *volatile allocation = malloc(42);
              if (allocation == NULL) {
                  return 2;
              }
              *allocation = 42;
              allocation = NULL;
              return 0;
          }
        '';
        steps = [
          {
            argv = ["@cc@" "leak.c" "-o" "leak"];
            exit_code = 0;
            stdout.exact = "";
            stderr.exact = "";
          }
          {
            argv = [
              "@out@/bin/valgrind"
              "--quiet"
              "--leak-check=full"
              "--errors-for-leak-kinds=definite"
              "--error-exitcode=7"
              "@work@/bad-input/leak"
            ];
            exit_code = 7;
            stdout.exact = "";
            observes_rejection = true;
          }
        ];
        artifacts = [];
      };
    };
  };

  treecc = testing.mkQualificationPackageProbe {
    name = "treecc";
    spec = {
      schema_version = "aos.release.package-probe/v1";
      package = "treecc";
      primary = {
        input = "A TreeCC definition containing an abstract expression node and a concrete number node.";
        operation = "Generate C source and a header, compile them with a small consumer, and execute it.";
        expected = "TreeCC's generated node constructor stores the supplied integer and the consumer prints 42.";
        files = {
          "nodes.tc" = ''
            %{
            #include "generated.h"
            %}

            %node expression %abstract %typedef
            %node number expression =
            {
                int value;
            }
          '';
          "main.c" = ''
            #include <stdio.h>
            #include <stdlib.h>
            #include "generated.h"

            char *yycurrfilename(void) {
                return "nodes.tc";
            }

            long yycurrlinenum(void) {
                return 1;
            }

            void yynodefailed(void) {
                abort();
            }

            int main(void) {
                expression *value = number_create(42);
                if (value == NULL) {
                    return 2;
                }
                printf("%d\n", ((number *)value)->value);
                yynodeclear();
                return 0;
            }
          '';
        };
        steps = [
          {
            argv = ["@out@/bin/treecc" "-o" "generated.c" "-h" "generated.h" "nodes.tc"];
            exit_code = 0;
            stdout.exact = "";
            stderr.exact = "";
          }
          {
            argv = ["@cc@" "generated.c" "main.c" "-o" "consumer"];
            exit_code = 0;
          }
          {
            argv = ["@work@/primary/consumer"];
            exit_code = 0;
            stdout.exact = "42\n";
            stderr.exact = "";
          }
        ];
        artifacts = [];
      };
      bad_input = {
        input = "A TreeCC source containing an unknown directive.";
        operation = "Attempt to generate C output from the malformed source.";
        expected = "TreeCC rejects the unknown directive with a failure status.";
        files."invalid.tc" = "%qualification-unknown\n";
        steps = [
          {
            argv = ["@out@/bin/treecc" "-o" "invalid.c" "-h" "invalid.h" "invalid.tc"];
            exit_code = 1;
            stdout.exact = "";
            observes_rejection = true;
          }
        ];
        artifacts = [];
      };
    };
  };
}
