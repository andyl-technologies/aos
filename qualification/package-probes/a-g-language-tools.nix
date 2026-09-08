##! Exercises A-G compilers and source generators by running generated programs.
{testing}: let
  mkCCompilerProbe = {
    package,
    executable,
  }:
    testing.mkQualificationPackageProbe {
      name = package;
      spec = {
        schema_version = "aos.release.package-probe/v1";
        inherit package;
        primary = {
          input = "A C program that computes and prints an integer result.";
          operation = "Compile the program with ${executable}, then execute the generated binary.";
          expected = "The compiler succeeds and the binary prints the fixed result.";
          files."valid.c" = ''
            #include <stdio.h>

            int main(void) {
                int values[] = {19, 23};
                return printf("compiler result: %d\n", values[0] + values[1]) < 0;
            }
          '';
          steps = [
            {
              argv = ["@out@/bin/${executable}" "valid.c" "-o" "compiled-program"];
              exit_code = 0;
              stdout.exact = "";
              stderr.exact = "";
            }
            {
              argv = ["@work@/primary/compiled-program"];
              exit_code = 0;
              stdout.exact = "compiler result: 42\n";
              stderr.exact = "";
            }
          ];
          artifacts = [];
        };
        bad_input = {
          input = "A C translation unit with an incomplete initializer.";
          operation = "Ask ${executable} to compile the malformed source.";
          expected = "The compiler rejects the syntax error with status 1.";
          files."invalid.c" = "int main(void) { int answer = ; return answer; }\n";
          steps = [
            {
              argv = ["@out@/bin/${executable}" "invalid.c" "-o" "invalid-program"];
              exit_code = 1;
              stdout.exact = "";
              observes_rejection = true;
            }
          ];
          artifacts = [];
        };
      };
    };

  mkGoProbe = package:
    testing.mkQualificationPackageProbe {
      name = package;
      spec = {
        schema_version = "aos.release.package-probe/v1";
        inherit package;
        primary = {
          input = "A Go program that sorts three strings.";
          operation = "Compile and run the program with the packaged Go toolchain.";
          expected = "The program prints the strings in lexical order.";
          files."main.go" = ''
            package main

            import (
                "fmt"
                "sort"
            )

            func main() {
                values := []string{"gamma", "alpha", "beta"}
                sort.Strings(values)
                fmt.Println(values)
            }
          '';
          steps = [
            {
              argv = ["@out@/bin/go" "run" "@work@/primary/main.go"];
              exit_code = 0;
              stdout.exact = "[alpha beta gamma]\n";
              stderr.exact = "";
              timeout_seconds = 120;
            }
          ];
          artifacts = [];
        };
        bad_input = {
          input = "A Go program with a missing expression in a declaration.";
          operation = "Compile the malformed program with the packaged Go toolchain.";
          expected = "The Go parser rejects the source with status 1.";
          files."invalid.go" = "package main\nfunc main() { value := ; _ = value }\n";
          steps = [
            {
              argv = ["@out@/bin/go" "run" "@work@/bad-input/invalid.go"];
              exit_code = 1;
              stdout.exact = "";
              observes_rejection = true;
              timeout_seconds = 120;
            }
          ];
          artifacts = [];
        };
      };
    };
in {
  bison = testing.mkQualificationPackageProbe {
    name = "bison";
    spec = {
      schema_version = "aos.release.package-probe/v1";
      package = "bison";
      primary = {
        input = "A grammar accepting a nonempty sequence of the token 'a'.";
        operation = "Generate a C parser, compile it, and parse a valid token sequence.";
        expected = "The generated parser accepts the input and prints its token count.";
        files."parser.y" = ''
          %{
          #include <stdio.h>
          int count;
          int yylex(void) { int c = getchar(); return c == 'a' ? 'a' : 0; }
          void yyerror(const char *message) { (void)message; }
          %}
          %%
          input: items { printf("parsed %d tokens\n", count); };
          items: 'a' { count = 1; } | items 'a' { ++count; };
          %%
          int main(void) { return yyparse(); }
        '';
        steps = [
          {
            argv = ["@out@/bin/bison" "-o" "parser.c" "parser.y"];
            exit_code = 0;
            stdout.exact = "";
            stderr.exact = "";
          }
          {
            argv = ["@cc@" "parser.c" "-o" "parser"];
            exit_code = 0;
            stdout.exact = "";
            stderr.exact = "";
          }
          {
            argv = ["@work@/primary/parser"];
            stdin = "aaa";
            exit_code = 0;
            stdout.exact = "parsed 3 tokens\n";
            stderr.exact = "";
          }
        ];
        artifacts = [];
      };
      bad_input = {
        input = "A grammar with a token declaration missing its identifier.";
        operation = "Ask Bison to generate a parser from the malformed grammar.";
        expected = "Bison rejects the grammar with status 1.";
        files."invalid.y" = "%token\n%%\ninput: ;\n%%\n";
        steps = [
          {
            argv = ["@out@/bin/bison" "-o" "invalid.c" "invalid.y"];
            exit_code = 1;
            stdout.exact = "";
            observes_rejection = true;
          }
        ];
        artifacts = [];
      };
    };
  };

  cc = mkCCompilerProbe {
    package = "cc";
    executable = "cc";
  };

  dtc = testing.mkQualificationPackageProbe {
    name = "dtc";
    spec = {
      schema_version = "aos.release.package-probe/v1";
      package = "dtc";
      primary = {
        input = "A device tree containing a 32-bit answer property.";
        operation = "Compile the source tree to a blob, then read the property with fdtget.";
        expected = "The compiled blob reports the exact decimal property value.";
        files."tree.dts" = ''
          /dts-v1/;
          / {
            compatible = "aos,qualification";
            probe {
              answer = <42>;
            };
          };
        '';
        steps = [
          {
            argv = ["@out@/bin/dtc" "-I" "dts" "-O" "dtb" "-o" "tree.dtb" "tree.dts"];
            exit_code = 0;
            stdout.exact = "";
            stderr.exact = "";
          }
          {
            argv = ["@out@/bin/fdtget" "-t" "u" "tree.dtb" "/probe" "answer"];
            exit_code = 0;
            stdout.exact = "42\n";
            stderr.exact = "";
          }
        ];
        artifacts = [];
      };
      bad_input = {
        input = "A device tree source with an unterminated node.";
        operation = "Compile the malformed device tree source.";
        expected = "Dtc rejects the syntax error with status 1.";
        files."invalid.dts" = "/dts-v1/;\n/ { node { value = <1>; };\n";
        steps = [
          {
            argv = ["@out@/bin/dtc" "-I" "dts" "-O" "dtb" "-o" "invalid.dtb" "invalid.dts"];
            exit_code = 1;
            stdout.exact = "";
            observes_rejection = true;
          }
        ];
        artifacts = [];
      };
    };
  };

  flex = testing.mkQualificationPackageProbe {
    name = "flex";
    spec = {
      schema_version = "aos.release.package-probe/v1";
      package = "flex";
      primary = {
        input = "A scanner recognizing decimal integers and words.";
        operation = "Generate and compile the scanner, then tokenize a fixed input.";
        expected = "The scanner emits the expected token classes and values.";
        files."scanner.l" = ''
          %option noyywrap
          %{
          #include <stdio.h>
          %}
          %%
          [0-9]+       { printf("integer:%s\n", yytext); }
          [[:alpha:]]+ { printf("word:%s\n", yytext); }
          [[:space:]]+ ;
          .            { return 2; }
          %%
          int main(void) { return yylex(); }
        '';
        steps = [
          {
            argv = ["@out@/bin/flex" "-o" "scanner.c" "scanner.l"];
            exit_code = 0;
            stdout.exact = "";
            stderr.exact = "";
          }
          {
            argv = ["@cc@" "scanner.c" "-o" "scanner"];
            exit_code = 0;
            stdout.exact = "";
            stderr.exact = "";
          }
          {
            argv = ["@work@/primary/scanner"];
            stdin = "alpha 42\n";
            exit_code = 0;
            stdout.exact = "word:alpha\ninteger:42\n";
            stderr.exact = "";
          }
        ];
        artifacts = [];
      };
      bad_input = {
        input = "A scanner specification with an unterminated character class.";
        operation = "Ask Flex to generate a scanner from the malformed rule.";
        expected = "Flex rejects the malformed rule with status 1.";
        files."invalid.l" = "%option noyywrap\n%%\n[abc { return 0; }\n%%\n";
        steps = [
          {
            argv = ["@out@/bin/flex" "-o" "invalid.c" "invalid.l"];
            exit_code = 1;
            stdout.exact = "";
            observes_rejection = true;
          }
        ];
        artifacts = [];
      };
    };
  };

  gcc = mkCCompilerProbe {
    package = "gcc";
    executable = "gcc";
  };

  gccUnwrapped = mkCCompilerProbe {
    package = "gccUnwrapped";
    executable = "gcc";
  };

  go = mkGoProbe "go";
  go-1_17 = mkGoProbe "go-1_17";
  go-1_20 = mkGoProbe "go-1_20";
  go-1_22 = mkGoProbe "go-1_22";
  go-1_24 = mkGoProbe "go-1_24";
  go-1_4 = mkGoProbe "go-1_4";
}
