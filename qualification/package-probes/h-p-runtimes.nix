##! Exercises H-through-P compilers, runtimes, and language modules.
{testing}: let
  mkRuntimeProbe = {
    package,
    executable,
    primaryFiles,
    primarySteps,
    badFiles,
    badSteps,
    primaryInput,
    primaryOperation,
    primaryExpected,
    badInput,
    badOperation,
    badExpected,
  }:
    testing.mkQualificationPackageProbe {
      name = package;
      spec = {
        schema_version = "aos.release.package-probe/v1";
        inherit package;
        primary = {
          input = primaryInput;
          operation = primaryOperation;
          expected = primaryExpected;
          files = primaryFiles;
          steps = map (step: step // {argv = [("@out@/bin/" + executable)] ++ step.argv;}) primarySteps;
          artifacts = [];
        };
        bad_input = {
          input = badInput;
          operation = badOperation;
          expected = badExpected;
          files = badFiles;
          steps = map (step: step // {argv = [("@out@/bin/" + executable)] ++ step.argv;}) badSteps;
          artifacts = [];
        };
      };
    };

  mkPython = package:
    mkRuntimeProbe {
      inherit package;
      executable = "python3";
      primaryInput = "A Python program that computes the sum of 19 and 23.";
      primaryOperation = "Compile and execute the program with the packaged interpreter.";
      primaryExpected = "The interpreter prints the exact integer result 42.";
      primaryFiles."answer.py" = ''
        print(19 + 23)
      '';
      primarySteps = [
        {
          argv = ["answer.py"];
          exit_code = 0;
          stdout.exact = "42\n";
          stderr.exact = "";
        }
      ];
      badInput = "A Python source file with an incomplete function definition.";
      badOperation = "Compile the malformed source with the packaged interpreter.";
      badExpected = "The interpreter exits with its syntax-error status.";
      badFiles."invalid.py" = ''
        def incomplete(
      '';
      badSteps = [
        {
          argv = ["-m" "py_compile" "invalid.py"];
          exit_code = 1;
          observes_rejection = true;
        }
      ];
    };

  mkOpenJdk = package:
    testing.mkQualificationPackageProbe {
      name = package;
      spec = {
        schema_version = "aos.release.package-probe/v1";
        inherit package;
        primary = {
          input = "A Java class that prints the sum of 19 and 23.";
          operation = "Compile the class with javac and execute it with java.";
          expected = "The packaged toolchain produces runnable bytecode that prints 42.";
          files."Answer.java" = ''
            public final class Answer {
                public static void main(String[] arguments) {
                    System.out.println(19 + 23);
                }
            }
          '';
          steps = [
            {
              argv = ["@out@/bin/javac" "Answer.java"];
              exit_code = 0;
              stdout.exact = "";
              stderr.exact = "";
            }
            {
              argv = ["@out@/bin/java" "-cp" "." "Answer"];
              exit_code = 0;
              stdout.exact = "42\n";
              stderr.exact = "";
            }
          ];
          artifacts = [];
        };
        bad_input = {
          input = "A Java class whose return statement has no expression.";
          operation = "Compile the malformed class with javac.";
          expected = "javac rejects the source with its compilation-failure status.";
          files."Invalid.java" = ''
            public final class Invalid {
                public static int answer() { return; }
            }
          '';
          steps = [
            {
              argv = ["@out@/bin/javac" "Invalid.java"];
              exit_code = 1;
              observes_rejection = true;
            }
          ];
          artifacts = [];
        };
      };
    };

  mkLlvm = package:
    mkRuntimeProbe {
      inherit package;
      executable = "llvm-as";
      primaryInput = "A well-formed LLVM IR module whose main function returns zero.";
      primaryOperation = "Assemble the textual module into LLVM bitcode.";
      primaryExpected = "llvm-as accepts the typed IR and writes the bitcode output.";
      primaryFiles."answer.ll" = ''
        define i32 @main() {
          ret i32 0
        }
      '';
      primarySteps = [
        {
          argv = ["answer.ll" "-o" "answer.bc"];
          exit_code = 0;
          stdout.exact = "";
          stderr.exact = "";
        }
      ];
      badInput = "LLVM IR whose i32 function returns an i8 value.";
      badOperation = "Assemble the ill-typed textual module.";
      badExpected = "llvm-as rejects the type mismatch with its parse-failure status.";
      badFiles."invalid.ll" = ''
        define i32 @main() {
          ret i8 0
        }
      '';
      badSteps = [
        {
          argv = ["invalid.ll" "-o" "invalid.bc"];
          exit_code = 1;
          observes_rejection = true;
        }
      ];
    };
in
  {
    lua = mkRuntimeProbe {
      package = "lua";
      executable = "lua";
      primaryInput = "A Lua expression that adds 19 and 23.";
      primaryOperation = "Evaluate the expression with the packaged Lua interpreter.";
      primaryExpected = "Lua prints the exact integer result 42.";
      primaryFiles = {};
      primarySteps = [
        {
          argv = ["-e" "print(19 + 23)"];
          exit_code = 0;
          stdout.exact = "42\n";
          stderr.exact = "";
        }
      ];
      badInput = "A Lua function declaration with an unclosed parameter list.";
      badOperation = "Parse the malformed expression with the packaged interpreter.";
      badExpected = "Lua exits with its syntax-error status.";
      badFiles = {};
      badSteps = [
        {
          argv = ["-e" "function broken("];
          exit_code = 1;
          observes_rejection = true;
        }
      ];
    };

    python3 = mkPython "python3";
    "python3-3_12" = mkPython "python3-3_12";

    llvm = mkLlvm "llvm";
    "llvm-17" = mkLlvm "llvm-17";
    "llvm-18" = mkLlvm "llvm-18";
    "llvm-19" = mkLlvm "llvm-19";
    "llvm-20" = mkLlvm "llvm-20";
    "llvm-21" = mkLlvm "llvm-21";
    "llvm-22" = mkLlvm "llvm-22";

    openjdk = mkOpenJdk "openjdk";
    "openjdk-7" = mkOpenJdk "openjdk-7";
    "openjdk-8" = mkOpenJdk "openjdk-8";
    "openjdk-9" = mkOpenJdk "openjdk-9";
    "openjdk-10" = mkOpenJdk "openjdk-10";
    "openjdk-11" = mkOpenJdk "openjdk-11";
    "openjdk-12" = mkOpenJdk "openjdk-12";
    "openjdk-13" = mkOpenJdk "openjdk-13";
    "openjdk-14" = mkOpenJdk "openjdk-14";
    "openjdk-15" = mkOpenJdk "openjdk-15";
    "openjdk-16" = mkOpenJdk "openjdk-16";
    "openjdk-17" = mkOpenJdk "openjdk-17";
    "openjdk-18" = mkOpenJdk "openjdk-18";
    "openjdk-19" = mkOpenJdk "openjdk-19";
    "openjdk-20" = mkOpenJdk "openjdk-20";
    "openjdk-21" = mkOpenJdk "openjdk-21";
    "openjdk-22" = mkOpenJdk "openjdk-22";
    "openjdk-23" = mkOpenJdk "openjdk-23";
    "openjdk-24" = mkOpenJdk "openjdk-24";
  }
  // builtins.listToAttrs (
    map (
      definition: {
        name = definition.package;
        value = mkRuntimeProbe definition;
      }
    ) [
      {
        package = "nodejs";
        executable = "node";
        primaryInput = "A JavaScript expression that adds 19 and 23.";
        primaryOperation = "Evaluate the expression with the packaged Node.js runtime.";
        primaryExpected = "Node.js prints the exact integer result 42.";
        primaryFiles = {};
        primarySteps = [
          {
            argv = ["-e" "console.log(19 + 23)"];
            exit_code = 0;
            stdout.exact = "42\n";
            stderr.exact = "";
          }
        ];
        badInput = "A JavaScript function declaration with an unclosed parameter list.";
        badOperation = "Parse the malformed program with the packaged runtime.";
        badExpected = "Node.js exits with its syntax-error status.";
        badFiles."invalid.js" = "function broken(\n";
        badSteps = [
          {
            argv = ["--check" "invalid.js"];
            exit_code = 1;
            observes_rejection = true;
          }
        ];
      }
      {
        package = "perl";
        executable = "perl";
        primaryInput = "A Perl expression that adds 19 and 23.";
        primaryOperation = "Evaluate the expression with the packaged Perl interpreter.";
        primaryExpected = "Perl prints the exact integer result 42.";
        primaryFiles = {};
        primarySteps = [
          {
            argv = ["-e" "print 19 + 23, qq{\\n}"];
            exit_code = 0;
            stdout.exact = "42\n";
            stderr.exact = "";
          }
        ];
        badInput = "A Perl expression with an unclosed parenthesis.";
        badOperation = "Compile the malformed expression without executing it.";
        badExpected = "Perl exits with its syntax-error status.";
        badFiles = {};
        badSteps = [
          {
            argv = ["-c" "-e" "print ("];
            exit_code = 255;
            observes_rejection = true;
          }
        ];
      }
    ]
  )
