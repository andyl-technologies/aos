##! Exercises H-through-P command packages through deterministic transformations.
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
          steps = map (step: step // {argv = [("@out@/bin/" + executable)] ++ step.argv;}) primarySteps;
          artifacts = primaryArtifacts;
        };
        bad_input = {
          input = badInput;
          operation = badOperation;
          expected = badExpected;
          files = badFiles;
          steps = map (step: step // {argv = [("@out@/bin/" + executable)] ++ step.argv;}) badSteps;
          artifacts = badArtifacts;
        };
      };
    };
in {
  jq = mkToolProbe {
    package = "jq";
    executable = "jq";
    primaryInput = "A JSON object whose answer member is 41.";
    primaryOperation = "Parse the document and increment its answer with a jq filter.";
    primaryExpected = "jq emits the canonical integer result 42.";
    primarySteps = [
      {
        argv = [".answer + 1"];
        stdin = "{\"answer\":41}\n";
        exit_code = 0;
        stdout.exact = "42\n";
        stderr.exact = "";
      }
    ];
    badInput = "A truncated JSON object.";
    badOperation = "Parse the malformed document with the identity filter.";
    badExpected = "jq exits with its invalid-JSON status.";
    badSteps = [
      {
        argv = ["."];
        stdin = "{\"answer\":";
        exit_code = 5;
        observes_rejection = true;
      }
    ];
  };

  less = mkToolProbe {
    package = "less";
    executable = "less";
    primaryInput = "A short line supplied on standard input in noninteractive mode.";
    primaryOperation = "Page the stream without terminal initialization or screen clearing.";
    primaryExpected = "less copies the line to standard output unchanged.";
    primarySteps = [
      {
        argv = ["-F" "-X"];
        stdin = "answer=42\n";
        exit_code = 0;
        stdout.exact = "answer=42\n";
        stderr.exact = "";
      }
    ];
    badInput = "An option name outside less's command-line grammar.";
    badOperation = "Invoke less with the unknown option.";
    badExpected = "less rejects the option with a non-success status.";
    badSteps = [
      {
        argv = ["--definitely-not-a-less-option"];
        exit_code = 0;
        stdout.exact = "";
        stderr.exact = "There is no definitely-not-a-less-option option (\"less --help\" for help)\n";
        observes_rejection = true;
      }
    ];
  };

  m4 = mkToolProbe {
    package = "m4";
    executable = "m4";
    primaryInput = "An m4 macro definition and invocation.";
    primaryOperation = "Expand the macro through the packaged processor.";
    primaryExpected = "m4 emits the macro's exact value 42.";
    primarySteps = [
      {
        argv = [];
        stdin = "define(`ANSWER', `42')dnl\nANSWER\n";
        exit_code = 0;
        stdout.exact = "42\n";
        stderr.exact = "";
      }
    ];
    badInput = "An include directive for a file that is absent.";
    badOperation = "Process the missing include with fatal warnings enabled.";
    badExpected = "m4 rejects the unresolved include with a non-success status.";
    badSteps = [
      {
        argv = ["--fatal-warnings"];
        stdin = "include(`missing-qualification-file')\n";
        exit_code = 1;
        observes_rejection = true;
      }
    ];
  };

  patch = mkToolProbe {
    package = "patch";
    executable = "patch";
    primaryInput = "A one-line file and a unified diff changing 41 to 42.";
    primaryOperation = "Apply the diff to the named file.";
    primaryExpected = "patch succeeds and the resulting file contains answer=42.";
    primaryFiles = {
      "answer.txt" = "answer=41\n";
      "answer.patch" = ''
        --- answer.txt
        +++ answer.txt
        @@ -1 +1 @@
        -answer=41
        +answer=42
      '';
    };
    primarySteps = [
      {
        argv = ["answer.txt" "answer.patch"];
        exit_code = 0;
      }
    ];
    primaryArtifacts = [
      {
        path = "answer.txt";
        text = "answer=42\n";
      }
    ];
    badInput = "Text that is not a patch in any supported format.";
    badOperation = "Attempt to apply the malformed patch stream.";
    badExpected = "patch exits with its malformed-input status.";
    badSteps = [
      {
        argv = [];
        stdin = "this is not a patch\n";
        exit_code = 2;
        observes_rejection = true;
      }
    ];
  };

  pv = mkToolProbe {
    package = "pv";
    executable = "pv";
    primaryInput = "A fixed byte stream and a disabled progress display.";
    primaryOperation = "Copy the stream through pv's data path.";
    primaryExpected = "pv preserves every input byte on standard output.";
    primarySteps = [
      {
        argv = ["--quiet"];
        stdin = "answer=42\n";
        exit_code = 0;
        stdout.exact = "answer=42\n";
        stderr.exact = "";
      }
    ];
    badInput = "A numeric rate limit containing non-numeric text.";
    badOperation = "Parse the invalid rate-limit argument.";
    badExpected = "pv rejects the malformed numeric value with a non-success status.";
    badSteps = [
      {
        argv = ["--rate-limit" "not-a-number"];
        exit_code = 64;
        observes_rejection = true;
      }
    ];
  };

  protobuf = mkToolProbe {
    package = "protobuf";
    executable = "protoc";
    primaryInput = "A proto3 schema declaring one message with an int32 field.";
    primaryOperation = "Compile the schema into a descriptor set with protoc.";
    primaryExpected = "protoc validates the declaration and writes its descriptor output.";
    primaryFiles."answer.proto" = ''
      syntax = "proto3";
      package qualification;
      message Answer { int32 value = 1; }
    '';
    primarySteps = [
      {
        argv = ["--descriptor_set_out=answer.pb" "answer.proto"];
        exit_code = 0;
        stdout.exact = "";
        stderr.exact = "";
      }
    ];
    badInput = "A protobuf field declaration with no numeric tag.";
    badOperation = "Compile the malformed schema with protoc.";
    badExpected = "protoc rejects the schema with its parse-failure status.";
    badFiles."invalid.proto" = ''
      syntax = "proto3";
      message Invalid { int32 value = ; }
    '';
    badSteps = [
      {
        argv = ["--descriptor_set_out=invalid.pb" "invalid.proto"];
        exit_code = 1;
        observes_rejection = true;
      }
    ];
  };

  lzip = mkToolProbe {
    package = "lzip";
    executable = "lzip";
    primaryInput = "A fixed text file compressed into an lzip member.";
    primaryOperation = "Compress the file and decode the member back to standard output.";
    primaryExpected = "The decompressed bytes exactly equal the original text.";
    primaryFiles."answer.txt" = "answer=42\n";
    primarySteps = [
      {
        argv = ["-k" "answer.txt"];
        exit_code = 0;
        stdout.exact = "";
        stderr.exact = "";
      }
      {
        argv = ["-d" "-c" "answer.txt.lz"];
        exit_code = 0;
        stdout.exact = "answer=42\n";
        stderr.exact = "";
      }
    ];
    badInput = "A byte sequence that is not an lzip member.";
    badOperation = "Attempt to decompress the malformed member.";
    badExpected = "lzip reports corrupt input with its data-error status.";
    badFiles."invalid.lz" = "not an lzip member\n";
    badSteps = [
      {
        argv = ["-d" "-c" "invalid.lz"];
        exit_code = 2;
        observes_rejection = true;
      }
    ];
  };

  nasm = mkToolProbe {
    package = "nasm";
    executable = "nasm";
    primaryInput = "A flat-binary assembly source declaring the bytes answer=42.";
    primaryOperation = "Assemble the source into a raw binary.";
    primaryExpected = "NASM emits the exact declared byte sequence.";
    primaryFiles."answer.asm" = ''
      bits 64
      db "answer=42", 10
    '';
    primarySteps = [
      {
        argv = ["-f" "bin" "answer.asm" "-o" "answer.bin"];
        exit_code = 0;
        stdout.exact = "";
        stderr.exact = "";
      }
    ];
    primaryArtifacts = [
      {
        path = "answer.bin";
        text = "answer=42\n";
      }
    ];
    badInput = "An assembly source with an operand but no instruction mnemonic.";
    badOperation = "Assemble the malformed source as a flat binary.";
    badExpected = "NASM rejects the source with its assembly-error status.";
    badFiles."invalid.asm" = "bits 64\nrax, rbx\n";
    badSteps = [
      {
        argv = ["-f" "bin" "invalid.asm" "-o" "invalid.bin"];
        exit_code = 1;
        observes_rejection = true;
      }
    ];
  };

  nix = mkToolProbe {
    package = "nix";
    executable = "nix-instantiate";
    primaryInput = "A pure Nix arithmetic expression adding 19 and 23.";
    primaryOperation = "Evaluate the expression through nix-instantiate.";
    primaryExpected = "The evaluator prints the integer value 42.";
    primarySteps = [
      {
        argv = ["--eval" "--expr" "19 + 23"];
        exit_code = 0;
        stdout.exact = "42\n";
        stderr.exact = "";
      }
    ];
    badInput = "A Nix let expression with no value after the equals sign.";
    badOperation = "Parse and evaluate the malformed expression.";
    badExpected = "The evaluator exits with its syntax-error status.";
    badSteps = [
      {
        argv = ["--eval" "--expr" "let answer = ; in answer"];
        exit_code = 1;
        observes_rejection = true;
      }
    ];
  };

  pigz = mkToolProbe {
    package = "pigz";
    executable = "pigz";
    primaryInput = "A fixed text file compressed as a deterministic gzip stream.";
    primaryOperation = "Compress the file without name metadata and decode it back.";
    primaryExpected = "The decompressed bytes exactly equal the original text.";
    primaryFiles."answer.txt" = "answer=42\n";
    primarySteps = [
      {
        argv = ["-n" "-k" "answer.txt"];
        exit_code = 0;
        stdout.exact = "";
        stderr.exact = "";
      }
      {
        argv = ["-d" "-c" "answer.txt.gz"];
        exit_code = 0;
        stdout.exact = "answer=42\n";
        stderr.exact = "";
      }
    ];
    badInput = "A file carrying the gzip suffix but no gzip header.";
    badOperation = "Attempt to decompress the malformed stream.";
    badExpected = "pigz reports corrupt input with a non-success status.";
    badFiles."invalid.gz" = "not a gzip stream\n";
    badSteps = [
      {
        argv = ["-d" "-c" "invalid.gz"];
        exit_code = 1;
        observes_rejection = true;
      }
    ];
  };

  patchelf = testing.mkQualificationPackageProbe {
    name = "patchelf";
    spec = {
      schema_version = "aos.release.package-probe/v1";
      package = "patchelf";
      primary = {
        input = "A linked ELF executable and the requested runtime search path /qualification.";
        operation = "Set the executable's RPATH and query it back through patchelf.";
        expected = "patchelf reports the exact newly stored RPATH.";
        files."sample.c" = "int main(void) { return 0; }\n";
        steps = [
          {
            argv = ["@cc@" "sample.c" "-o" "sample"];
            exit_code = 0;
            stdout.exact = "";
          }
          {
            argv = ["@out@/bin/patchelf" "--set-rpath" "/qualification" "sample"];
            exit_code = 0;
            stdout.exact = "";
            stderr.exact = "";
          }
          {
            argv = ["@out@/bin/patchelf" "--print-rpath" "sample"];
            exit_code = 0;
            stdout.exact = "/qualification\n";
            stderr.exact = "";
          }
        ];
        artifacts = [];
      };
      bad_input = {
        input = "A plain-text file with no ELF header.";
        operation = "Attempt to read its RPATH through patchelf.";
        expected = "patchelf rejects the non-ELF input with a non-success status.";
        files."not-elf" = "this is not an ELF object\n";
        steps = [
          {
            argv = ["@out@/bin/patchelf" "--print-rpath" "not-elf"];
            exit_code = 1;
            observes_rejection = true;
          }
        ];
        artifacts = [];
      };
    };
  };

  mtools = testing.mkQualificationPackageProbe {
    name = "mtools";
    spec = {
      schema_version = "aos.release.package-probe/v1";
      package = "mtools";
      primary = {
        input = "A blank 1.44 MiB disk image and a text file containing answer=42.";
        operation = "Format the image as FAT, copy the file into it, and read the file back through mtools.";
        expected = "The FAT image preserves the file's exact contents.";
        files."answer.txt" = "answer=42\n";
        steps = [
          {
            argv = ["@python@" "-c" "open('disk.img', 'wb').truncate(1474560)"];
            exit_code = 0;
            stdout.exact = "";
            stderr.exact = "";
          }
          {
            argv = ["@out@/bin/mformat" "-i" "disk.img" "-f" "1440" "::"];
            exit_code = 0;
            stdout.exact = "";
            stderr.exact = "";
          }
          {
            argv = ["@out@/bin/mcopy" "-i" "disk.img" "answer.txt" "::ANSWER.TXT"];
            exit_code = 0;
            stdout.exact = "";
            stderr.exact = "";
          }
          {
            argv = ["@out@/bin/mtype" "-i" "disk.img" "::ANSWER.TXT"];
            exit_code = 0;
            stdout.exact = "answer=42\n";
            stderr.exact = "";
          }
        ];
        artifacts = [];
      };
      bad_input = {
        input = "A floppy-size argument containing non-numeric text.";
        operation = "Parse the malformed geometry through mformat.";
        expected = "mformat rejects the malformed numeric size with a non-success status.";
        files = {};
        steps = [
          {
            argv = ["@out@/bin/mformat" "-f" "not-a-number" "::"];
            exit_code = 1;
            observes_rejection = true;
          }
        ];
        artifacts = [];
      };
    };
  };
}
