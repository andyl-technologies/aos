##! Exercises a fifth H-through-P command slice with local deterministic inputs.
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
  nmap = mkCommandProbe {
    package = "nmap";
    primaryInput = "The text answer=42 sent over a local Unix-domain socket.";
    primaryOperation = "Listen and connect through Ncat, then capture the transferred bytes.";
    primaryExpected = "Ncat transports the exact input through the local socket.";
    primarySteps = [
      {
        argv = [
          "@bash@"
          "-c"
          ''
            set -eu
            "@out@/bin/ncat" -l -U channel.sock > received.txt &
            listener=$!
            for attempt in 1 2 3 4 5 6 7 8 9 10; do
              test -S channel.sock && break
              read -r -t 0.05 ignored || true
            done
            printf 'answer=42\n' | "@out@/bin/ncat" -U channel.sock
            wait "$listener"
          ''
        ];
        exit_code = 0;
        stdout.exact = "";
        stderr.exact = "";
      }
    ];
    primaryArtifacts = [
      {
        path = "received.txt";
        text = "answer=42\n";
      }
    ];
    badInput = "A request to listen and perform zero-I/O scanning simultaneously.";
    badOperation = "Parse the conflicting flags through Ncat.";
    badExpected = "Ncat rejects the incompatible modes with status 2.";
    badSteps = [
      {
        argv = ["@out@/bin/ncat" "-l" "-z"];
        exit_code = 2;
        stdout.exact = "";
        stderr.exact = "Ncat: Services designed for LISTENING can't be used with -z QUITTING.\n";
        observes_rejection = true;
      }
    ];
  };

  policycoreutils = mkCommandProbe {
    package = "policycoreutils";
    primaryInput = "The SELinux context system_u:system_r:init_t:s0.";
    primaryOperation = "Extract its user component through secon.";
    primaryExpected = "Secon prints system_u exactly.";
    primarySteps = [
      {
        argv = ["@out@/bin/secon" "-u" "system_u:system_r:init_t:s0"];
        exit_code = 0;
        stdout.exact = "system_u\n";
        stderr.exact = "";
      }
    ];
    badInput = "A security context containing only one field.";
    badOperation = "Extract its user through secon.";
    badExpected = "Secon rejects the malformed context with status 1.";
    badSteps = [
      {
        argv = ["@out@/bin/secon" "-u" "missing-fields"];
        exit_code = 1;
        stdout.exact = "";
        stderr.exact = "secon: Couldn't create context from: missing-fields\n";
        observes_rejection = true;
      }
    ];
  };
}
