##! Exercises additional H-through-P command packages with local data transformations.
{testing}: let
  mkCommandProbe = {
    package,
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
          steps = primarySteps;
          artifacts = primaryArtifacts;
        };
        bad_input = {
          input = badInput;
          operation = badOperation;
          expected = badExpected;
          files = badFiles;
          steps = badSteps;
          artifacts = badArtifacts;
        };
      };
    };
in {
  just = mkCommandProbe {
    package = "just";
    primaryInput = "A justfile defining the variable answer as 42.";
    primaryOperation = "Evaluate the named variable through just's recipe parser.";
    primaryExpected = "just emits the exact variable value 42.";
    primaryFiles.justfile = ''
      answer := "42"
    '';
    primarySteps = [
      {
        argv = ["@out@/bin/just" "--evaluate" "answer"];
        exit_code = 0;
        stdout.exact = "42";
        stderr.exact = "";
      }
    ];
    badInput = "A justfile assignment with no value expression.";
    badOperation = "Parse and evaluate the malformed justfile.";
    badExpected = "just rejects the file with its parse-error status.";
    badFiles.justfile = ''
      answer :=
    '';
    badSteps = [
      {
        argv = ["@out@/bin/just" "--evaluate" "answer"];
        exit_code = 1;
        observes_rejection = true;
      }
    ];
  };

  kbd = mkCommandProbe {
    package = "kbd";
    primaryInput = "A minimal Linux console keymap binding keycode 1 to Escape.";
    primaryOperation = "Parse the keymap and translate it into C tables with loadkeys.";
    primaryExpected = "loadkeys accepts the mapping and emits its compiled table representation.";
    primaryFiles."answer.map" = ''
      keymaps 0
      keycode 1 = Escape
    '';
    primarySteps = [
      {
        argv = ["@out@/bin/loadkeys" "-m" "answer.map"];
        exit_code = 0;
      }
    ];
    badInput = "A keymap declaration whose keycode is not numeric.";
    badOperation = "Parse the malformed mapping through loadkeys.";
    badExpected = "loadkeys rejects the invalid keycode with a non-success status.";
    badFiles."invalid.map" = ''
      keymaps 0
      keycode not-a-number = Escape
    '';
    badSteps = [
      {
        argv = ["@out@/bin/loadkeys" "-m" "invalid.map"];
        exit_code = 1;
        observes_rejection = true;
      }
    ];
  };

  libxslt = mkCommandProbe {
    package = "libxslt";
    primaryInput = "An XML answer element and an XSLT stylesheet selecting its text.";
    primaryOperation = "Transform the document into plain text through xsltproc.";
    primaryExpected = "The output artifact contains the exact selected value 42.";
    primaryFiles = {
      "input.xml" = "<root><answer>42</answer></root>\n";
      "transform.xsl" = ''
        <xsl:stylesheet version="1.0"
          xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
          <xsl:output method="text"/>
          <xsl:template match="/"><xsl:value-of select="root/answer"/><xsl:text>&#10;</xsl:text></xsl:template>
        </xsl:stylesheet>
      '';
    };
    primarySteps = [
      {
        argv = ["@out@/bin/xsltproc" "-o" "answer.txt" "transform.xsl" "input.xml"];
        exit_code = 0;
        stdout.exact = "";
        stderr.exact = "";
      }
    ];
    primaryArtifacts = [
      {
        path = "answer.txt";
        text = "42\n";
      }
    ];
    badInput = "An XSLT stylesheet with an unclosed template element.";
    badOperation = "Parse and apply the malformed stylesheet through xsltproc.";
    badExpected = "xsltproc exits with its stylesheet parse-error status.";
    badFiles = {
      "input.xml" = "<root/>\n";
      "invalid.xsl" = ''
        <xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
          <xsl:template match="/">
        </xsl:stylesheet>
      '';
    };
    badSteps = [
      {
        argv = ["@out@/bin/xsltproc" "invalid.xsl" "input.xml"];
        exit_code = 4;
        observes_rejection = true;
      }
    ];
  };

  moreutils = mkCommandProbe {
    package = "moreutils";
    primaryInput = "A fixed byte stream and an output pathname.";
    primaryOperation = "Consume the stream into the file through sponge.";
    primaryExpected = "sponge writes the exact input after reaching end of stream.";
    primarySteps = [
      {
        argv = ["@out@/bin/sponge" "answer.txt"];
        stdin = "answer=42\n";
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
    badInput = "An output pathname beneath a directory that does not exist.";
    badOperation = "Attempt to write the stream through sponge.";
    badExpected = "sponge rejects the inaccessible destination with a non-success status.";
    badSteps = [
      {
        argv = ["@out@/bin/sponge" "missing-directory/answer.txt"];
        stdin = "answer=42\n";
        exit_code = 1;
        observes_rejection = true;
      }
    ];
  };

  "nuke-references" = mkCommandProbe {
    package = "nuke-references";
    primaryInput = "Text containing one syntactically valid Nix store reference.";
    primaryOperation = "Rewrite the store hash through nuke-refs.";
    primaryExpected = "The hash is replaced by 32 e characters while surrounding bytes remain unchanged.";
    primaryFiles."reference.txt" = "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-package/data\n";
    primarySteps = [
      {
        argv = ["@out@/bin/nuke-refs" "reference.txt"];
        exit_code = 0;
        stdout.exact = "";
        stderr.exact = "";
      }
    ];
    primaryArtifacts = [
      {
        path = "reference.txt";
        text = "/nix/store/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee-package/data\n";
      }
    ];
    badInput = "An exclusion value that is not a complete Nix store path.";
    badOperation = "Parse the malformed exclusion through nuke-refs.";
    badExpected = "nuke-refs rejects the exclusion with status 1.";
    badFiles."reference.txt" = "unchanged\n";
    badSteps = [
      {
        argv = ["@out@/bin/nuke-refs" "-e" "not-a-store-path" "reference.txt"];
        exit_code = 1;
        stdout.exact = "";
        stderr.exact = "nuke-refs: -e needs a store path\n";
        observes_rejection = true;
      }
    ];
  };

  openssh = mkCommandProbe {
    package = "openssh";
    primaryInput = "A request for a passphrase-protected Ed25519 private key in the probe workspace.";
    primaryOperation = "Generate the key and derive its public key through ssh-keygen.";
    primaryExpected = "Both key generation and private-key parsing succeed.";
    primarySteps = [
      {
        argv = ["@out@/bin/ssh-keygen" "-q" "-t" "ed25519" "-N" "qualification-passphrase" "-f" "qualification-key"];
        exit_code = 0;
        stdout.exact = "";
        stderr.exact = "";
      }
      {
        argv = ["@out@/bin/ssh-keygen" "-y" "-P" "qualification-passphrase" "-f" "qualification-key"];
        exit_code = 0;
      }
    ];
    badInput = "A text file that is not an OpenSSH private key.";
    badOperation = "Attempt to derive a public key from the malformed file.";
    badExpected = "ssh-keygen rejects the file with its key-load failure status.";
    badFiles.invalid = "not an OpenSSH private key\n";
    badSteps = [
      {
        argv = ["@out@/bin/ssh-keygen" "-y" "-f" "invalid"];
        exit_code = 255;
        observes_rejection = true;
      }
    ];
  };

  parted = mkCommandProbe {
    package = "parted";
    primaryInput = "A blank four-MiB disk image and a one-MiB partition extent.";
    primaryOperation = "Create a GPT label and partition through GNU Parted's script interface.";
    primaryExpected = "Parted accepts the image geometry and writes the partition table.";
    primarySteps = [
      {
        argv = ["@python@" "-c" "open('disk.img', 'wb').truncate(4 * 1024 * 1024)"];
        exit_code = 0;
        stdout.exact = "";
        stderr.exact = "";
      }
      {
        argv = ["@out@/sbin/parted" "-s" "disk.img" "mklabel" "gpt" "mkpart" "primary" "1MiB" "2MiB"];
        exit_code = 0;
      }
      {
        argv = ["@out@/sbin/parted" "-s" "disk.img" "unit" "s" "print"];
        exit_code = 0;
      }
    ];
    badInput = "A partition-table label name unsupported by GNU Parted.";
    badOperation = "Attempt to create the unknown label on a local image.";
    badExpected = "Parted rejects the label with a non-success status.";
    badSteps = [
      {
        argv = ["@python@" "-c" "open('disk.img', 'wb').truncate(4 * 1024 * 1024)"];
        exit_code = 0;
        stdout.exact = "";
        stderr.exact = "";
      }
      {
        argv = ["@out@/sbin/parted" "-s" "disk.img" "mklabel" "qualification-label-does-not-exist"];
        exit_code = 1;
        observes_rejection = true;
      }
    ];
  };

  "pkg-config" = mkCommandProbe {
    package = "pkg-config";
    primaryInput = "A complete pkg-config metadata document.";
    primaryOperation = "Validate its variables and required package fields through pkg-config.";
    primaryExpected = "pkg-config accepts the metadata without diagnostics.";
    primaryFiles."qualification.pc" = ''
      prefix=/qualification
      Name: qualification
      Description: qualification metadata
      Version: 1.0
      Libs: -L''${prefix}/lib -lqualification
      Cflags: -I''${prefix}/include
    '';
    primarySteps = [
      {
        argv = ["@out@/bin/pkg-config" "--validate" "qualification.pc"];
        exit_code = 0;
        stdout.exact = "";
        stderr.exact = "";
      }
    ];
    badInput = "A metadata document whose Name field lacks its required colon.";
    badOperation = "Validate the malformed document through pkg-config.";
    badExpected = "pkg-config rejects the document with status 1.";
    badFiles."invalid.pc" = ''
      Name qualification
      Version: 1.0
    '';
    badSteps = [
      {
        argv = ["@out@/bin/pkg-config" "--validate" "invalid.pc"];
        exit_code = 1;
        observes_rejection = true;
      }
    ];
  };

  pnpm = mkCommandProbe {
    package = "pnpm";
    primaryInput = "A local package manifest naming the qualification package.";
    primaryOperation = "Read the name through pnpm's package-metadata command.";
    primaryExpected = "pnpm prints the exact manifest name.";
    primaryFiles."package.json" = ''
      {"name":"qualification","version":"1.0.0"}
    '';
    primarySteps = [
      {
        argv = ["@out@/bin/pnpm" "pkg" "get" "name"];
        exit_code = 0;
        stdout.exact = "qualification\n";
        stderr.exact = "";
      }
    ];
    badInput = "A package manifest containing malformed JSON.";
    badOperation = "Read metadata from the malformed manifest through pnpm.";
    badExpected = "pnpm rejects the manifest with its parse-error status.";
    badFiles."package.json" = "{bad\n";
    badSteps = [
      {
        argv = ["@out@/bin/pnpm" "pkg" "get" "name"];
        exit_code = 1;
        observes_rejection = true;
      }
    ];
  };

  "protobuf-c" = mkCommandProbe {
    package = "protobuf-c";
    primaryInput = "A proto3 schema declaring one message with an int32 field.";
    primaryOperation = "Compile the schema into C source and header output through protoc-c.";
    primaryExpected = "protoc-c validates the declaration and generates both outputs.";
    primaryFiles."answer.proto" = ''
      syntax = "proto3";
      package qualification;
      message Answer { int32 value = 1; }
    '';
    primarySteps = [
      {
        argv = ["@out@/bin/protoc-c" "--c_out=." "answer.proto"];
        exit_code = 0;
        stdout.exact = "";
      }
    ];
    badInput = "A protobuf field declaration with no numeric tag.";
    badOperation = "Compile the malformed schema through protoc-c.";
    badExpected = "protoc-c rejects the schema with its parse-error status.";
    badFiles."invalid.proto" = ''
      syntax = "proto3";
      message Invalid { int32 value = ; }
    '';
    badSteps = [
      {
        argv = ["@out@/bin/protoc-c" "--c_out=." "invalid.proto"];
        exit_code = 1;
        observes_rejection = true;
      }
    ];
  };

  pyrefly = mkCommandProbe {
    package = "pyrefly";
    primaryInput = "A Python module assigning an integer to an int annotation.";
    primaryOperation = "Type-check the module with Pyrefly's bundled typeshed.";
    primaryExpected = "Pyrefly accepts the consistent assignment.";
    primaryFiles = {
      "pyrefly.toml" = ''
        python-version = "3.14"
        skip-interpreter-query = true
        project-includes = ["answer.py"]
      '';
      "answer.py" = "answer: int = 42\n";
    };
    primarySteps = [
      {
        argv = ["@out@/bin/pyrefly" "check"];
        exit_code = 0;
      }
    ];
    badInput = "A Python module assigning a string to an int annotation.";
    badOperation = "Type-check the inconsistent assignment through Pyrefly.";
    badExpected = "Pyrefly reports a type error and exits with status 1.";
    badFiles = {
      "pyrefly.toml" = ''
        python-version = "3.14"
        skip-interpreter-query = true
        project-includes = ["invalid.py"]
      '';
      "invalid.py" = ''
        answer: int = "forty-two"
      '';
    };
    badSteps = [
      {
        argv = ["@out@/bin/pyrefly" "check"];
        exit_code = 1;
        observes_rejection = true;
      }
    ];
  };
}
