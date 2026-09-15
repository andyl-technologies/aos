##! Exercises A-G command-line packages with concrete data transformations.
{testing}: let
  mkCommandProbe = {
    package,
    executable,
    primary,
    badInput,
  }:
    testing.mkQualificationPackageProbe {
      name = package;
      spec = {
        schema_version = "aos.release.package-probe/v1";
        inherit package;
        primary = {
          inherit (primary) input operation expected;
          files = primary.files or {};
          steps = [
            ({
                argv = ["@out@/bin/${executable}"] ++ primary.arguments;
                exit_code = 0;
              }
              // (
                if primary ? stdin
                then {inherit (primary) stdin;}
                else {}
              )
              // (
                if primary ? stdout
                then {stdout.exact = primary.stdout;}
                else {}
              )
              // (
                if primary ? stderr
                then {stderr.exact = primary.stderr;}
                else {}
              ))
          ];
          artifacts = primary.artifacts or [];
        };
        bad_input = {
          inherit (badInput) input operation expected;
          files = badInput.files or {};
          steps = [
            ({
                argv = ["@out@/bin/${executable}"] ++ badInput.arguments;
                exit_code = badInput.exitCode;
                observes_rejection = true;
              }
              // (
                if badInput ? stdin
                then {inherit (badInput) stdin;}
                else {}
              )
              // (
                if badInput ? stdout
                then {stdout.exact = badInput.stdout;}
                else {}
              )
              // (
                if badInput ? stderr
                then {stderr.exact = badInput.stderr;}
                else {}
              ))
          ];
          artifacts = badInput.artifacts or [];
        };
      };
    };

  mkCompressionProbe = {
    package,
    executable,
    compressArguments ? [],
    decompressArguments ? ["-d" "-c"],
    badExitCode ? 1,
  }:
    testing.mkQualificationPackageProbe {
      name = package;
      spec = {
        schema_version = "aos.release.package-probe/v1";
        inherit package;
        primary = {
          input = "A fixed text payload.";
          operation = "Compress the payload, then decompress the resulting stream through ${executable}.";
          expected = "The decompressed bytes exactly reproduce the original payload.";
          files."payload.txt" = "AOS qualification payload\n";
          steps = [
            {
              argv = ["@out@/bin/${executable}"] ++ compressArguments ++ ["@work@/primary/payload.txt"];
              exit_code = 0;
              stdout.exact = "";
              stderr.exact = "";
            }
            {
              argv =
                ["@out@/bin/${executable}"]
                ++ decompressArguments
                ++ [
                  "@work@/primary/payload.txt.${
                    if package == "bzip2"
                    then "bz2"
                    else if package == "brotli"
                    then "br"
                    else "gz"
                  }"
                ];
              exit_code = 0;
              stdout.exact = "AOS qualification payload\n";
              stderr.exact = "";
            }
          ];
          artifacts = [];
        };
        bad_input = {
          input = "A regular text file that is not a ${package} stream.";
          operation = "Ask ${executable} to decompress the invalid stream.";
          expected = "The decoder rejects the malformed stream with a failure status.";
          files."invalid.${
            if package == "bzip2"
            then "bz2"
            else if package == "brotli"
            then "br"
            else "gz"
          }" = "not a compressed stream\n";
          steps = [
            {
              argv =
                ["@out@/bin/${executable}"]
                ++ decompressArguments
                ++ [
                  "@work@/bad-input/invalid.${
                    if package == "bzip2"
                    then "bz2"
                    else if package == "brotli"
                    then "br"
                    else "gz"
                  }"
                ];
              exit_code = badExitCode;
              observes_rejection = true;
            }
          ];
          artifacts = [];
        };
      };
    };
in {
  alejandra = mkCommandProbe {
    package = "alejandra";
    executable = "alejandra";
    primary = {
      input = "An unformatted Nix attribute set.";
      operation = "Format the Nix expression in place.";
      expected = "Alejandra accepts the expression and writes its canonical layout.";
      files."expression.nix" = "{a=1;b=[2 3];}\n";
      arguments = ["@work@/primary/expression.nix"];
      stdout = "";
      stderr = "";
      artifacts = [
        {
          path = "expression.nix";
          text = ''
            {
              a = 1;
              b = [2 3];
            }
          '';
        }
      ];
    };
    badInput = {
      input = "A Nix expression with an unterminated list.";
      operation = "Attempt to format the malformed expression.";
      expected = "Alejandra rejects the syntax error.";
      files."invalid.nix" = "{ value = [ 1 2; }\n";
      arguments = ["@work@/bad-input/invalid.nix"];
      exitCode = 1;
    };
  };

  bash = mkCommandProbe {
    package = "bash";
    executable = "bash";
    primary = {
      input = "A shell program using an indexed array and arithmetic expansion.";
      operation = "Evaluate the program with Bash.";
      expected = "Bash prints the selected array value and computed integer.";
      arguments = ["-c" ''values=(alpha beta); printf "%s:%d\n" "''${values[1]}" "$((6 * 7))"''];
      stdout = "beta:42\n";
      stderr = "";
    };
    badInput = {
      input = "A shell program with an unterminated conditional expression.";
      operation = "Ask Bash to parse the malformed program.";
      expected = "Bash reports a syntax failure with status 2.";
      arguments = ["-n" "-c" "if true; then echo broken"];
      exitCode = 2;
      stdout = "";
    };
  };

  bc = mkCommandProbe {
    package = "bc";
    executable = "bc";
    primary = {
      input = "An arithmetic expression combining exponentiation and addition.";
      operation = "Evaluate the expression with bc.";
      expected = "The calculator emits the exact integer result.";
      arguments = ["-q"];
      stdin = "2^5 + 10\n";
      stdout = "42\n";
      stderr = "";
    };
    badInput = {
      input = "A command-line option that bc does not define.";
      operation = "Invoke bc with the invalid option.";
      expected = "Bc rejects the option with status 1.";
      arguments = ["--definitely-invalid-option"];
      exitCode = 1;
    };
  };

  bat = mkCommandProbe {
    package = "bat";
    executable = "bat";
    primary = {
      input = "A two-line text file.";
      operation = "Render the file with decorations, paging, and color disabled.";
      expected = "Bat preserves the exact file bytes.";
      files."sample.txt" = "alpha\nbeta\n";
      arguments = ["--plain" "--color=never" "--paging=never" "@work@/primary/sample.txt"];
      stdout = "alpha\nbeta\n";
      stderr = "";
    };
    badInput = {
      input = "A path that does not exist.";
      operation = "Ask bat to render the missing file.";
      expected = "Bat rejects the missing input with status 1.";
      arguments = ["--plain" "--color=never" "--paging=never" "@work@/bad-input/missing.txt"];
      exitCode = 1;
      stdout = "";
    };
  };

  binutils = mkCommandProbe {
    package = "binutils";
    executable = "strings";
    primary = {
      input = "Data containing printable runs above and below a five-byte threshold.";
      operation = "Extract printable runs of at least five bytes with GNU strings.";
      expected = "Strings emits exactly the two qualifying runs.";
      files."sample.bin" = "alpha\nxy\nbravo\n";
      arguments = ["--bytes=5" "@work@/primary/sample.bin"];
      stdout = "alpha\nbravo\n";
      stderr = "";
    };
    badInput = {
      input = "A minimum string length of zero, outside the accepted positive range.";
      operation = "Invoke strings with the invalid length bound.";
      expected = "Strings rejects the bound with status 1.";
      files."sample.bin" = "alpha\n";
      arguments = ["--bytes=0" "@work@/bad-input/sample.bin"];
      exitCode = 1;
      stdout = "";
    };
  };

  brotli = mkCompressionProbe {
    package = "brotli";
    executable = "brotli";
  };

  bzip2 = mkCompressionProbe {
    package = "bzip2";
    executable = "bzip2";
    badExitCode = 2;
  };

  cmake = mkCommandProbe {
    package = "cmake";
    executable = "cmake";
    primary = {
      input = "A CMake script performing integer arithmetic and a conditional.";
      operation = "Execute the script in CMake script mode.";
      expected = "CMake evaluates the language constructs and emits the fixed result.";
      files."valid.cmake" = ''
        math(EXPR answer "6 * 7")
        if(NOT answer EQUAL 42)
          message(FATAL_ERROR "wrong answer")
        endif()
        message("cmake result: ''${answer}")
      '';
      arguments = ["-P" "@work@/primary/valid.cmake"];
      stdout = "";
      stderr = "cmake result: 42\n";
    };
    badInput = {
      input = "A CMake script calling an unknown command.";
      operation = "Execute the invalid script in CMake script mode.";
      expected = "CMake rejects the unknown command with status 1.";
      files."invalid.cmake" = "not_a_cmake_command()\n";
      arguments = ["-P" "@work@/bad-input/invalid.cmake"];
      exitCode = 1;
      stdout = "";
    };
  };

  coreutils = mkCommandProbe {
    package = "coreutils";
    executable = "printf";
    primary = {
      input = "A string and integer for a padded format conversion.";
      operation = "Format the values with GNU printf.";
      expected = "Printf emits the exact padded record.";
      arguments = ["%s:%03d\\n" "qualified" "7"];
      stdout = "qualified:007\n";
      stderr = "";
    };
    badInput = {
      input = "A character that is not a valid integer operand.";
      operation = "Apply an integer conversion to the invalid operand.";
      expected = "GNU printf diagnoses the invalid number and returns status 1.";
      arguments = ["%d\\n" "x"];
      exitCode = 1;
      stdout = "0\n";
    };
  };

  curl = mkCommandProbe {
    package = "curl";
    executable = "curl";
    primary = {
      input = "A local file URL containing a fixed payload.";
      operation = "Transfer the URL through curl's file protocol.";
      expected = "Curl writes the exact resource body.";
      files."resource.txt" = "curl local transfer passed\n";
      arguments = ["--silent" "--show-error" "file://@work@/primary/resource.txt"];
      stdout = "curl local transfer passed\n";
      stderr = "";
    };
    badInput = {
      input = "A URL with a malformed IPv6 host literal.";
      operation = "Ask curl to parse the malformed URL.";
      expected = "Curl rejects the URL with its URL-format status.";
      arguments = ["--silent" "--show-error" "http://[invalid/"];
      exitCode = 3;
      stdout = "";
    };
  };

  diffutils = mkCommandProbe {
    package = "diffutils";
    executable = "cmp";
    primary = {
      input = "Two files with identical bytes.";
      operation = "Compare the files byte for byte.";
      expected = "Cmp confirms equality with a silent success.";
      files = {
        "left.txt" = "same bytes\n";
        "right.txt" = "same bytes\n";
      };
      arguments = ["@work@/primary/left.txt" "@work@/primary/right.txt"];
      stdout = "";
      stderr = "";
    };
    badInput = {
      input = "Two files differing in one byte.";
      operation = "Compare the unequal files in silent mode.";
      expected = "Cmp reports inequality through status 1.";
      files = {
        "left.txt" = "alpha\n";
        "right.txt" = "alpHa\n";
      };
      arguments = ["--silent" "@work@/bad-input/left.txt" "@work@/bad-input/right.txt"];
      exitCode = 1;
      stdout = "";
      stderr = "";
    };
  };

  findutils = mkCommandProbe {
    package = "findutils";
    executable = "find";
    primary = {
      input = "A directory containing one matching and one nonmatching file.";
      operation = "Select regular files with the .txt suffix and print only their base name.";
      expected = "Find emits only the matching file name.";
      files = {
        "tree/answer.txt" = "42\n";
        "tree/ignored.log" = "no\n";
      };
      arguments = ["@work@/primary/tree" "-type" "f" "-name" "*.txt" "-printf" "%f\\n"];
      stdout = "answer.txt\n";
      stderr = "";
    };
    badInput = {
      input = "A directory path that does not exist.";
      operation = "Traverse the missing path.";
      expected = "Find rejects the missing traversal root with status 1.";
      arguments = ["@work@/bad-input/missing"];
      exitCode = 1;
      stdout = "";
    };
  };

  fish = mkCommandProbe {
    package = "fish";
    executable = "fish";
    primary = {
      input = "A Fish program splitting a colon-delimited string.";
      operation = "Evaluate the program and select the second field.";
      expected = "Fish prints the selected field.";
      arguments = ["-c" "string split : alpha:beta:gamma | string match beta"];
      stdout = "beta\n";
      stderr = "";
    };
    badInput = {
      input = "A Fish program with an unterminated command substitution.";
      operation = "Parse the malformed Fish program without executing it.";
      expected = "Fish rejects the syntax error with status 127.";
      arguments = ["-n" "-c" "echo (string upper broken"];
      exitCode = 127;
      stdout = "";
    };
  };

  file = mkCommandProbe {
    package = "file";
    executable = "file";
    primary = {
      input = "A newline-terminated ASCII text file.";
      operation = "Classify the file's contents without printing its path.";
      expected = "File identifies the payload as ASCII text.";
      files."sample.txt" = "AOS text\n";
      arguments = ["--brief" "@work@/primary/sample.txt"];
      stdout = "ASCII text\n";
      stderr = "";
    };
    badInput = {
      input = "A malformed magic database rule and a byte to classify.";
      operation = "Classify the byte using only the malformed magic database.";
      expected = "File rejects the invalid magic rule with status 1.";
      files = {
        "invalid.magic" = "this is not a magic rule\n";
        "sample.bin" = "x";
      };
      arguments = ["--brief" "-m" "@work@/bad-input/invalid.magic" "@work@/bad-input/sample.bin"];
      exitCode = 1;
      stdout = "";
    };
  };

  gawk = mkCommandProbe {
    package = "gawk";
    executable = "awk";
    primary = {
      input = "Two colon-delimited records.";
      operation = "Sum the numeric second fields with awk.";
      expected = "Awk emits the exact aggregate.";
      arguments = ["-F:" "{ total += $2 } END { print total }"];
      stdin = "alpha:19\nbeta:23\n";
      stdout = "42\n";
      stderr = "";
    };
    badInput = {
      input = "An awk program with an unterminated action.";
      operation = "Parse the malformed awk program.";
      expected = "Awk rejects the syntax error with status 1.";
      arguments = ["{ print $1"];
      exitCode = 1;
      stdout = "";
    };
  };

  git = mkCommandProbe {
    package = "git";
    executable = "git";
    primary = {
      input = "A fixed byte sequence to encode as a Git blob object.";
      operation = "Compute the blob object identifier with git hash-object.";
      expected = "Git emits the exact SHA-1 object identifier.";
      arguments = ["hash-object" "--stdin"];
      stdin = "qualification object\n";
      stdout = "157adbdcc19d3c521d96614eb0e7af902f2bdfb4\n";
      stderr = "";
    };
    badInput = {
      input = "A path that does not exist.";
      operation = "Hash the missing path as a Git object.";
      expected = "Git rejects the missing input with status 128.";
      arguments = ["hash-object" "@work@/bad-input/missing"];
      exitCode = 128;
      stdout = "";
    };
  };

  git-2_42 = mkCommandProbe {
    package = "git-2_42";
    executable = "git";
    primary = {
      input = "A fixed byte sequence to encode as a Git blob object.";
      operation = "Compute the blob object identifier with Git 2.42 hash-object.";
      expected = "Git emits the exact SHA-1 object identifier.";
      arguments = ["hash-object" "--stdin"];
      stdin = "qualification object\n";
      stdout = "157adbdcc19d3c521d96614eb0e7af902f2bdfb4\n";
      stderr = "";
    };
    badInput = {
      input = "A path that does not exist.";
      operation = "Hash the missing path as a Git object.";
      expected = "Git rejects the missing input with status 128.";
      arguments = ["hash-object" "@work@/bad-input/missing"];
      exitCode = 128;
      stdout = "";
    };
  };

  git-minimal = mkCommandProbe {
    package = "git-minimal";
    executable = "git";
    primary = {
      input = "A fixed byte sequence to encode as a Git blob object.";
      operation = "Compute the blob object identifier with minimal Git's hash-object command.";
      expected = "Git emits the exact SHA-1 object identifier.";
      arguments = ["hash-object" "--stdin"];
      stdin = "qualification object\n";
      stdout = "157adbdcc19d3c521d96614eb0e7af902f2bdfb4\n";
      stderr = "";
    };
    badInput = {
      input = "A path that does not exist.";
      operation = "Hash the missing path as a Git object.";
      expected = "Git rejects the missing input with status 128.";
      arguments = ["hash-object" "@work@/bad-input/missing"];
      exitCode = 128;
      stdout = "";
    };
  };

  gnumake = mkCommandProbe {
    package = "gnumake";
    executable = "make";
    primary = {
      input = "A makefile deriving an output file from an input variable.";
      operation = "Build the declared target with GNU Make.";
      expected = "Make runs the recipe and creates the exact output artifact.";
      files.Makefile = ''
               value = 42
               result.txt:
        printf 'make result: %s\n' '$(value)' > result.txt
      '';
      arguments = ["--no-print-directory" "result.txt"];
      stdout = "printf 'make result: %s\\n' '42' > result.txt\n";
      stderr = "";
      artifacts = [
        {
          path = "result.txt";
          text = "make result: 42\n";
        }
      ];
    };
    badInput = {
      input = "A requested target with no rule in an otherwise valid makefile.";
      operation = "Ask GNU Make to build the undefined target.";
      expected = "Make rejects the target with status 2.";
      files.Makefile = "all:\n\t@:\n";
      arguments = ["--no-print-directory" "missing-target"];
      exitCode = 2;
      stdout = "";
    };
  };

  grep = mkCommandProbe {
    package = "grep";
    executable = "grep";
    primary = {
      input = "Three records, two of which end in a decimal digit.";
      operation = "Select records matching an extended regular expression.";
      expected = "Grep emits exactly the two matching records.";
      arguments = ["-E" "^[a-z]+[0-9]$"];
      stdin = "alpha1\nbeta\ngamma3\n";
      stdout = "alpha1\ngamma3\n";
      stderr = "";
    };
    badInput = {
      input = "An extended regular expression with an unterminated group.";
      operation = "Compile the invalid regular expression.";
      expected = "Grep rejects the expression with status 2.";
      arguments = ["-E" "("];
      stdin = "anything\n";
      exitCode = 2;
      stdout = "";
    };
  };

  guile = mkCommandProbe {
    package = "guile";
    executable = "guile";
    primary = {
      input = "A Scheme expression mapping and summing a list.";
      operation = "Evaluate the expression with Guile.";
      expected = "Guile prints the computed value.";
      arguments = ["-c" "(display (apply + (map (lambda (x) (* x x)) '(1 2 3 4)))) (newline)"];
      stdout = "30\n";
      stderr = "";
    };
    badInput = {
      input = "A Scheme expression with an unterminated list.";
      operation = "Parse the malformed expression.";
      expected = "Guile rejects the syntax error with status 1.";
      arguments = ["-c" "(display (+ 1 2)"];
      exitCode = 1;
      stdout = "";
    };
  };

  gzip = mkCompressionProbe {
    package = "gzip";
    executable = "gzip";
  };
}
