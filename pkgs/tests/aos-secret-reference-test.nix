{
  lib,
  mkDerivation,
  writeTextFile,
  bash,
  coreutils,
}: let
  consumer = writeTextFile {
    name = "aos-secret-reference-test-consumer";
    executable = true;
    destination = "/bin/aos-secret-reference-test-consumer";
    text = ''
      #!${bash}/bin/bash
      set -euo pipefail

      credential=$1
      state_dir=$2
      ${coreutils}/bin/mkdir -p "$state_dir"
      attempts=0
      if [ -s "$state_dir/attempt-count" ]; then
        attempts=$(${coreutils}/bin/cat "$state_dir/attempt-count")
      fi
      attempts=$((attempts + 1))
      ${coreutils}/bin/printf '%s\n' "$attempts" > "$state_dir/attempt-count"
      test -s "$credential"
      count=0
      if [ -s "$state_dir/start-count" ]; then
        count=$(${coreutils}/bin/cat "$state_dir/start-count")
      fi
      count=$((count + 1))
      ${coreutils}/bin/printf '%s\n' "$count" > "$state_dir/start-count"
      ${coreutils}/bin/cat "$credential" > "$state_dir/observed"
      ${coreutils}/bin/stat -c '%a' "$credential" > "$state_dir/delivery-mode"
    '';
  };
in
  mkDerivation {
    pname = "aos-secret-reference-test";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The consumer is valid Bash and references the declared join-token credential and state files.";
        "files" = {};
        "input" = "The installed secret-reference consumer script.";
        "operation" = "Parse the script and inspect its credential and state contracts.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import pathlib, subprocess\nscript = pathlib.Path(\"@out@/bin/aos-secret-reference-test-consumer\").resolve()\nresult = subprocess.run([\"@bash@\", \"-n\", script], capture_output=True)\nsource = script.read_text()\nassert result.returncode == 0 and \"CREDENTIALS_DIRECTORY/join-token\" in source\nassert \"attempt-count\" in source and \"delivery-mode\" in source\nprint(\"aos-secret-reference-test data passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "aos-secret-reference-test data passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "The package contains only the consumer and rejects an embedded credential.";
        "files" = {};
        "input" = "A request for a credential embedded in the immutable package output.";
        "operation" = "Resolve the forbidden packaged secret payload.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import pathlib, sys\nif pathlib.Path(\"@out@/share/credentials/join-token\").exists():\n    raise SystemExit(2)\nsys.stderr.write(\"aos-secret-reference-test rejected invalid input\\n\")\nraise SystemExit(7)\n"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "aos-secret-reference-test rejected invalid input\n";
            };
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
    };

    version = "0";
    src = null;

    runtimeDeps = [consumer bash coreutils];

    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/bin"
          ln -s ${consumer}/bin/aos-secret-reference-test-consumer \
            "$out/bin/aos-secret-reference-test-consumer"
        '';
      }
    ];

    abilities = ./_aos-secret-reference-test/module.nix;

    meta = {
      description = "Fleet fixture for secretRef activation";
      license = "Apache-2.0";
    };
  }
