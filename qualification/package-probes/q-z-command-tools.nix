##! Exercises Q-through-Z command packages through deterministic transformations.
{testing}: let
  mkToolProbe = {
    package,
    executable,
    primaryInput,
    primaryOperation,
    primaryExpected,
    primaryFiles ? {},
    primarySteps,
    primaryArtifacts ? [],
    badInput,
    badOperation,
    badExpected,
    badFiles ? {},
    badSteps,
    badArtifacts ? [],
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
          steps = map (step: step // {argv = ["@out@/bin/${executable}"] ++ step.argv;}) primarySteps;
          artifacts = primaryArtifacts;
        };
        bad_input = {
          input = badInput;
          operation = badOperation;
          expected = badExpected;
          files = badFiles;
          steps = map (step: step // {argv = ["@out@/bin/${executable}"] ++ step.argv;}) badSteps;
          artifacts = badArtifacts;
        };
      };
    };

  mkQemuImageProbe = package:
    mkToolProbe {
      inherit package;
      executable = "qemu-img";
      primaryInput = "Two raw disk-image byte streams with identical contents.";
      primaryOperation = "Compare the images byte for byte through qemu-img's raw-image reader.";
      primaryExpected = "qemu-img reports the two images as identical.";
      primaryFiles = {
        "left.raw" = "AOS raw image payload\n";
        "right.raw" = "AOS raw image payload\n";
      };
      primarySteps = [
        {
          argv = ["compare" "-f" "raw" "-F" "raw" "left.raw" "right.raw"];
          exit_code = 0;
          stdout.exact = "Images are identical.\n";
          stderr.exact = "";
        }
      ];
      badInput = "Two raw disk-image byte streams that differ in one value.";
      badOperation = "Compare the mismatched images through qemu-img.";
      badExpected = "qemu-img identifies the content mismatch and returns its comparison status.";
      badFiles = {
        "left.raw" = "answer=41\n";
        "right.raw" = "answer=42\n";
      };
      badSteps = [
        {
          argv = ["compare" "-f" "raw" "-F" "raw" "left.raw" "right.raw"];
          exit_code = 1;
          observes_rejection = true;
        }
      ];
    };

  mkCompressionProbe = {
    package,
    executable,
    compressedSuffix,
  }:
    testing.mkQualificationPackageProbe {
      name = package;
      spec = {
        schema_version = "aos.release.package-probe/v1";
        inherit package;
        primary = {
          input = "A fixed text payload.";
          operation = "Compress the payload, then decode the resulting ${package} stream.";
          expected = "The decoded bytes exactly reproduce the original payload.";
          files."payload.txt" = "AOS qualification payload\n";
          steps = [
            {
              argv = ["@out@/bin/${executable}" "-q" "payload.txt"];
              exit_code = 0;
              stdout.exact = "";
              stderr.exact = "";
            }
            {
              argv = ["@out@/bin/${executable}" "-q" "-d" "-c" "payload.txt.${compressedSuffix}"];
              exit_code = 0;
              stdout.exact = "AOS qualification payload\n";
              stderr.exact = "";
            }
          ];
          artifacts = [];
        };
        bad_input = {
          input = "A plain-text file carrying a ${package} filename suffix.";
          operation = "Attempt to decode the malformed compressed stream.";
          expected = "The decoder rejects bytes outside the ${package} format.";
          files."invalid.${compressedSuffix}" = "not a compressed stream\n";
          steps = [
            {
              argv = ["@out@/bin/${executable}" "-q" "-d" "-c" "invalid.${compressedSuffix}"];
              exit_code = 1;
              observes_rejection = true;
            }
          ];
          artifacts = [];
        };
      };
    };
in {
  qemu = mkQemuImageProbe "qemu";
  "qemu-crucible" = mkQemuImageProbe "qemu-crucible";
  "qemu-crucible-reference" = mkQemuImageProbe "qemu-crucible-reference";
  "qemu-img" = mkQemuImageProbe "qemu-img";

  ripgrep = mkToolProbe {
    package = "ripgrep";
    executable = "rg";
    primaryInput = "Two lines containing one anchored answer assignment.";
    primaryOperation = "Search the file with an anchored regular expression and line numbers.";
    primaryExpected = "Ripgrep emits only the matching line and its line number.";
    primaryFiles."values.txt" = "answer=41\nanswer=42\n";
    primarySteps = [
      {
        argv = ["--line-number" "^answer=42$" "values.txt"];
        exit_code = 0;
        stdout.exact = "2:answer=42\n";
        stderr.exact = "";
      }
    ];
    badInput = "A text file containing no requested answer.";
    badOperation = "Search for an absent anchored value.";
    badExpected = "Ripgrep reports no match with status 1 and no output.";
    badFiles."values.txt" = "answer=41\n";
    badSteps = [
      {
        argv = ["^answer=42$" "values.txt"];
        exit_code = 1;
        stdout.exact = "";
        stderr.exact = "";
        observes_rejection = true;
      }
    ];
  };

  "remove-references-to" = mkToolProbe {
    package = "remove-references-to";
    executable = "remove-references-to";
    primaryInput = "A text file containing the hash portion of a syntactically valid Nix store path.";
    primaryOperation = "Scrub that store reference in place.";
    primaryExpected = "The selected store hash is replaced with the fixed non-reference marker.";
    primaryFiles."reference.txt" = "dependency=/nix/store/0123456789abcdfghijklmnpqrsvwxyz-target\n";
    primarySteps = [
      {
        argv = ["-t" "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-target" "reference.txt"];
        exit_code = 0;
        stdout.exact = "";
        stderr.exact = "";
      }
    ];
    primaryArtifacts = [
      {
        path = "reference.txt";
        text = "dependency=/nix/store/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee-target\n";
      }
    ];
    badInput = "A target argument outside the Nix store path grammar.";
    badOperation = "Attempt to select the malformed target for reference removal.";
    badExpected = "The tool rejects the target before changing the input file.";
    badFiles."reference.txt" = "answer=42\n";
    badSteps = [
      {
        argv = ["-t" "not-a-store-path" "reference.txt"];
        exit_code = 1;
        stdout.exact = "";
        stderr.exact = "remove-references-to: -t argument must be a Nix store path, got: not-a-store-path\n";
        observes_rejection = true;
      }
    ];
    badArtifacts = [
      {
        path = "reference.txt";
        text = "answer=42\n";
      }
    ];
  };

  rsync = mkToolProbe {
    package = "rsync";
    executable = "rsync";
    primaryInput = "A source file with a fixed payload.";
    primaryOperation = "Copy the file locally through rsync's transfer engine.";
    primaryExpected = "The destination contains the source bytes exactly.";
    primaryFiles."source.txt" = "answer=42\n";
    primarySteps = [
      {
        argv = ["--quiet" "source.txt" "destination.txt"];
        exit_code = 0;
        stdout.exact = "";
        stderr.exact = "";
      }
    ];
    primaryArtifacts = [
      {
        path = "destination.txt";
        text = "answer=42\n";
      }
    ];
    badInput = "A source path that does not exist.";
    badOperation = "Attempt a local transfer from the missing source.";
    badExpected = "Rsync rejects the missing source with its partial-transfer status.";
    badSteps = [
      {
        argv = ["--quiet" "missing.txt" "destination.txt"];
        exit_code = 23;
        observes_rejection = true;
      }
    ];
  };

  sed = mkToolProbe {
    package = "sed";
    executable = "sed";
    primaryInput = "A line containing the decimal value 41.";
    primaryOperation = "Replace the value with 42 using a basic regular expression.";
    primaryExpected = "Sed writes the transformed line exactly.";
    primarySteps = [
      {
        argv = ["s/41/42/"];
        stdin = "answer=41\n";
        exit_code = 0;
        stdout.exact = "answer=42\n";
        stderr.exact = "";
      }
    ];
    badInput = "A substitution expression with an unterminated regular expression.";
    badOperation = "Parse the malformed expression.";
    badExpected = "Sed rejects the expression with its script-error status.";
    badSteps = [
      {
        argv = ["s/[unterminated/42/"];
        exit_code = 1;
        stdout.exact = "";
        observes_rejection = true;
      }
    ];
  };

  socat = mkToolProbe {
    package = "socat";
    executable = "socat";
    primaryInput = "A fixed byte stream on standard input.";
    primaryOperation = "Relay the stream between Socat's standard-input and standard-output addresses.";
    primaryExpected = "Socat preserves the payload exactly.";
    primarySteps = [
      {
        argv = ["-u" "STDIN" "STDOUT"];
        stdin = "answer=42\n";
        exit_code = 0;
        stdout.exact = "answer=42\n";
        stderr.exact = "";
      }
    ];
    badInput = "An address type that Socat does not implement.";
    badOperation = "Open the unknown address.";
    badExpected = "Socat rejects the address before starting a relay.";
    badSteps = [
      {
        argv = ["-u" "QUALIFICATION-NOT-AN-ADDRESS" "STDOUT"];
        exit_code = 1;
        stdout.exact = "";
        observes_rejection = true;
      }
    ];
  };

  sqlite = mkToolProbe {
    package = "sqlite";
    executable = "sqlite3";
    primaryInput = "SQL that inserts two integers and computes their sum.";
    primaryOperation = "Execute the statements in an in-memory SQLite database.";
    primaryExpected = "SQLite evaluates the query and prints 42.";
    primarySteps = [
      {
        argv = [":memory:"];
        stdin = "CREATE TABLE values_(value INTEGER); INSERT INTO values_ VALUES (19), (23); SELECT sum(value) FROM values_;\n";
        exit_code = 0;
        stdout.exact = "42\n";
        stderr.exact = "";
      }
    ];
    badInput = "A SELECT statement with an incomplete expression.";
    badOperation = "Parse the malformed SQL.";
    badExpected = "SQLite rejects the syntax error with status 1.";
    badSteps = [
      {
        argv = [":memory:"];
        stdin = "SELECT 19 +;\n";
        exit_code = 1;
        stdout.exact = "";
        observes_rejection = true;
      }
    ];
  };

  systemd = mkToolProbe {
    package = "systemd";
    executable = "systemd-escape";
    primaryInput = "An absolute filesystem path.";
    primaryOperation = "Escape the path as a systemd unit-name component.";
    primaryExpected = "systemd-escape emits the canonical escaped path.";
    primarySteps = [
      {
        argv = ["--path" "/var/lib/aos"];
        exit_code = 0;
        stdout.exact = "var-lib-aos\n";
        stderr.exact = "";
      }
    ];
    badInput = "A relative path, which is outside --path's accepted input domain.";
    badOperation = "Attempt to escape the relative value as an absolute path.";
    badExpected = "systemd-escape rejects the relative path.";
    badSteps = [
      {
        argv = ["--path" "relative/path"];
        exit_code = 1;
        stdout.exact = "";
        observes_rejection = true;
      }
    ];
  };

  tar = testing.mkQualificationPackageProbe {
    name = "tar";
    spec = {
      schema_version = "aos.release.package-probe/v1";
      package = "tar";
      primary = {
        input = "A text file stored in a new tar archive.";
        operation = "Create the archive, then stream the member back through tar.";
        expected = "The extracted member bytes exactly match the input.";
        files."payload.txt" = "answer=42\n";
        steps = [
          {
            argv = ["@out@/bin/tar" "-cf" "payload.tar" "payload.txt"];
            exit_code = 0;
            stdout.exact = "";
            stderr.exact = "";
          }
          {
            argv = ["@out@/bin/tar" "-xOf" "payload.tar" "payload.txt"];
            exit_code = 0;
            stdout.exact = "answer=42\n";
            stderr.exact = "";
          }
        ];
        artifacts = [];
      };
      bad_input = {
        input = "Text bytes that do not form a tar archive.";
        operation = "Attempt to list the malformed archive.";
        expected = "Tar rejects the invalid archive with status 2.";
        files."invalid.tar" = "not a tar archive\n";
        steps = [
          {
            argv = ["@out@/bin/tar" "-tf" "invalid.tar"];
            exit_code = 2;
            observes_rejection = true;
          }
        ];
        artifacts = [];
      };
    };
  };

  texinfo = mkToolProbe {
    package = "texinfo";
    executable = "makeinfo";
    primaryInput = "A minimal Texinfo document containing emphasized text.";
    primaryOperation = "Render the document as plain text.";
    primaryExpected = "Makeinfo emits the expected heading and emphasized value.";
    primaryFiles."answer.texi" = "@node Top\n@top Answer\nThe answer is @emph{42}.\n";
    primarySteps = [
      {
        argv = ["--plaintext" "answer.texi"];
        exit_code = 0;
        stdout.exact = "Answer\n******\n\nThe answer is _42_.\n";
        stderr.exact = "";
      }
    ];
    badInput = "A Texinfo document containing an unknown command.";
    badOperation = "Render the malformed document.";
    badExpected = "Makeinfo rejects the undefined command.";
    badFiles."invalid.texi" = "@node Top\n@top Invalid\n@qualificationUnknown{value}\n";
    badSteps = [
      {
        argv = ["--plaintext" "invalid.texi"];
        exit_code = 1;
        observes_rejection = true;
      }
    ];
  };

  vim = mkToolProbe {
    package = "vim";
    executable = "vim";
    primaryInput = "A text file containing the decimal value 41.";
    primaryOperation = "Run a noninteractive Vim substitution and save the buffer.";
    primaryExpected = "Vim writes the transformed value 42 to the file.";
    primaryFiles."answer.txt" = "answer=41\n";
    primarySteps = [
      {
        argv = ["-Nu" "NONE" "-n" "-es" "-c" "%s/41/42/" "-c" "wq" "answer.txt"];
        exit_code = 0;
        stdout.exact = "";
        stderr.exact = "";
      }
    ];
    primaryArtifacts = [
      {
        path = "answer.txt";
        text = "answer=42\n";
      }
    ];
    badInput = "An Ex command name that Vim does not define.";
    badOperation = "Execute the unknown command in noninteractive mode.";
    badExpected = "Vim rejects the command with a failure status.";
    badSteps = [
      {
        argv = ["-Nu" "NONE" "-n" "-es" "-c" "QualificationUnknownCommand" "-c" "quit"];
        exit_code = 1;
        stdout.exact = "";
        stderr.exact = "";
        observes_rejection = true;
      }
    ];
  };

  which = mkToolProbe {
    package = "which";
    executable = "which";
    primaryInput = "The absolute path of the packaged which executable.";
    primaryOperation = "Resolve the already-absolute executable name.";
    primaryExpected = "Which returns the same executable path exactly.";
    primarySteps = [
      {
        argv = ["@out@/bin/which"];
        exit_code = 0;
        stderr.exact = "";
      }
    ];
    badInput = "A command name absent from the qualification profile.";
    badOperation = "Search for the nonexistent command.";
    badExpected = "Which reports the failed lookup with status 1.";
    badSteps = [
      {
        argv = ["qualification-command-does-not-exist"];
        exit_code = 1;
        stdout.exact = "";
        observes_rejection = true;
      }
    ];
  };

  xz = mkCompressionProbe {
    package = "xz";
    executable = "xz";
    compressedSuffix = "xz";
  };

  zstd = mkCompressionProbe {
    package = "zstd";
    executable = "zstd";
    compressedSuffix = "zst";
  };
}
