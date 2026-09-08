##! Exercises a third H-through-P command slice with local deterministic inputs.
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
  kubectl = mkCommandProbe {
    package = "kubectl";
    primaryInput = "A ConfigMap named qualification with the literal answer=42.";
    primaryOperation = "Construct the object locally through kubectl's client-side dry run.";
    primaryExpected = "Kubectl prints the created ConfigMap resource name without contacting a cluster.";
    primarySteps = [
      {
        argv = ["@out@/bin/kubectl" "create" "configmap" "qualification" "--from-literal=answer=42" "--dry-run=client" "-o" "name"];
        exit_code = 0;
        stdout.exact = "configmap/qualification\n";
        stderr.exact = "";
      }
    ];
    badInput = "Two literal values with the same ConfigMap key.";
    badOperation = "Construct the conflicting object through kubectl's client-side dry run.";
    badExpected = "Kubectl rejects the duplicate data key with status 1.";
    badSteps = [
      {
        argv = ["@out@/bin/kubectl" "create" "configmap" "qualification" "--from-literal=answer=42" "--from-literal=answer=43" "--dry-run=client" "-o" "name"];
        exit_code = 1;
        stdout.exact = "";
        observes_rejection = true;
      }
    ];
  };

  mariadb = mkCommandProbe {
    package = "mariadb";
    primaryInput = "A client option group declaring a user and TCP port.";
    primaryOperation = "Read the group through my_print_defaults.";
    primaryExpected = "MariaDB prints the two normalized command-line options in declaration order.";
    primaryFiles."my.cnf" = ''
      [client]
      user=qualification
      port=4242
    '';
    primarySteps = [
      {
        argv = ["@out@/bin/my_print_defaults" "--defaults-file=@work@/primary/my.cnf" "client"];
        exit_code = 0;
        stdout.exact = "--user=qualification\n--port=4242\n";
        stderr.exact = "";
      }
    ];
    badInput = "An option file with an unterminated client group header.";
    badOperation = "Read the malformed option file through my_print_defaults.";
    badExpected = "MariaDB rejects the group syntax with status 2.";
    badFiles."my.cnf" = "[client\nuser=qualification\n";
    badSteps = [
      {
        argv = ["@out@/bin/my_print_defaults" "--defaults-file=@work@/bad-input/my.cnf" "client"];
        exit_code = 2;
        stdout.exact = "";
        observes_rejection = true;
      }
    ];
  };

  minisign = mkCommandProbe {
    package = "minisign";
    primaryInput = "The text answer=42 and a newly generated unencrypted signing key.";
    primaryOperation = "Generate a key, sign the file, and verify its detached signature.";
    primaryExpected = "Minisign accepts the signature made by the corresponding public key.";
    primaryFiles."answer.txt" = "answer=42\n";
    primarySteps = [
      {
        argv = ["@out@/bin/minisign" "-G" "-W" "-p" "qualification.pub" "-s" "qualification.key"];
        exit_code = 0;
      }
      {
        argv = ["@out@/bin/minisign" "-S" "-s" "qualification.key" "-m" "answer.txt" "-x" "answer.minisig" "-t" "qualification"];
        exit_code = 0;
        stdout.exact = "";
        stderr.exact = "";
      }
      {
        argv = ["@out@/bin/minisign" "-V" "-q" "-p" "qualification.pub" "-m" "answer.txt" "-x" "answer.minisig"];
        exit_code = 0;
        stdout.exact = "";
        stderr.exact = "";
      }
    ];
    badInput = "A signed answer file and a second file whose contents were changed.";
    badOperation = "Verify the original signature against the changed file.";
    badExpected = "Minisign rejects the signature mismatch with status 1.";
    badFiles = {
      "answer.txt" = "answer=42\n";
      "changed.txt" = "answer=43\n";
    };
    badSteps = [
      {
        argv = ["@out@/bin/minisign" "-G" "-W" "-p" "qualification.pub" "-s" "qualification.key"];
        exit_code = 0;
      }
      {
        argv = ["@out@/bin/minisign" "-S" "-s" "qualification.key" "-m" "answer.txt" "-x" "answer.minisig" "-t" "qualification"];
        exit_code = 0;
        stdout.exact = "";
        stderr.exact = "";
      }
      {
        argv = ["@out@/bin/minisign" "-V" "-q" "-p" "qualification.pub" "-m" "changed.txt" "-x" "answer.minisig"];
        exit_code = 1;
        stdout.exact = "";
        observes_rejection = true;
      }
    ];
  };

  ncurses = mkCommandProbe {
    package = "ncurses";
    primaryInput = "A terminfo source declaring a 42-column qualification terminal.";
    primaryOperation = "Compile the source with tic and reconstruct it with infocmp.";
    primaryExpected = "Ncurses emits a database entry whose reconstructed capabilities match the source.";
    primaryFiles."qualification.info" = "qualification|Qualification terminal,cols#42,lines#24,\n";
    primarySteps = [
      {
        argv = ["@out@/bin/tic" "-x" "-o" "db" "qualification.info"];
        exit_code = 0;
        stdout.exact = "";
        stderr.exact = "";
      }
      {
        argv = ["@out@/bin/infocmp" "-A" "db" "qualification"];
        exit_code = 0;
        stdout.exact = "#\tReconstructed via infocmp from file: db/./q/qualification\nqualification|Qualification terminal,\n\tcols#42, lines#24,\n";
        stderr.exact = "";
      }
    ];
    badInput = "A lookup for a terminal absent from an empty custom terminfo database.";
    badOperation = "Resolve the missing entry through infocmp.";
    badExpected = "Infocmp rejects the absent terminal with status 1.";
    badFiles."empty/.keep" = "empty\n";
    badSteps = [
      {
        argv = ["@out@/bin/infocmp" "-A" "empty" "qualification-missing"];
        exit_code = 1;
        stdout.exact = "";
        observes_rejection = true;
      }
    ];
  };

  postgresql = mkCommandProbe {
    package = "postgresql";
    primaryInput = "An empty directory for a UTF-8 PostgreSQL cluster using trust authentication.";
    primaryOperation = "Initialize the cluster locally through initdb without locale discovery.";
    primaryExpected = "PostgreSQL creates a version 18 data directory.";
    primarySteps = [
      {
        argv = ["@out@/bin/initdb" "--no-locale" "--encoding=UTF8" "--auth=trust" "-D" "@work@/primary/database"];
        exit_code = 0;
      }
    ];
    primaryArtifacts = [
      {
        path = "database/PG_VERSION";
        text = "18\n";
      }
    ];
    badInput = "A cluster request naming an unsupported local authentication method.";
    badOperation = "Initialize the cluster through initdb with the invalid authentication method.";
    badExpected = "PostgreSQL rejects the authentication method with status 1.";
    badSteps = [
      {
        argv = ["@out@/bin/initdb" "--no-locale" "--auth=qualification-invalid" "-D" "@work@/bad-input/database"];
        exit_code = 1;
        stdout.exact = "";
        observes_rejection = true;
      }
    ];
  };
}
