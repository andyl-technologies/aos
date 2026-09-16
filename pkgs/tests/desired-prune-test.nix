{
  lib,
  mkDerivation,
  writeShellScriptBin,
}: let
  start = writeShellScriptBin "desired-prune-test-start" ''
    set -eu

    state_dir=$1
    mkdir -p "$state_dir"
    printf pruned > "$state_dir/started"
  '';
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];}];
      target = [];
      role = "build-input";
    };
    pname = "desired-prune-test";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The package contains its exact desired-prune-test marker.";
        "files" = {};
        "input" = "The desired-pruning test package payload.";
        "operation" = "Read the installed package identity bytes.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import pathlib\nassert pathlib.Path(\"@out@/share/desired-prune-test/payload.txt\").read_bytes() == b\"desired-prune-test\"\nprint(\"desired-prune-test data passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "desired-prune-test data passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "The immutable package rejects the absent runtime-state path.";
        "files" = {};
        "input" = "A request for mutable service state inside the immutable package output.";
        "operation" = "Resolve the nonexistent state marker beneath the package output.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import pathlib, sys\nif pathlib.Path(\"@out@/var/lib/aos-pkg-desired-prune-test/started\").exists():\n    raise SystemExit(2)\nsys.stderr.write(\"desired-prune-test rejected invalid input\\n\")\nraise SystemExit(7)\n"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "desired-prune-test rejected invalid input\n";
            };
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
    };

    version = "1.0.0";
    src = null;

    runtimeDeps = [start];

    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/share/desired-prune-test"
          printf desired-prune-test > "$out/share/desired-prune-test/payload.txt"
          mkdir -p "$out/bin"
          ln -s ${start}/bin/desired-prune-test-start "$out/bin/desired-prune-test-start"
        '';
      }
    ];

    abilities = ./_desired-prune-test;

    meta = {
      description = "AOS desired package prune sequencing test payload";
      license = "Apache-2.0";
    };
  }
