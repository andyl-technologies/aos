{
  lib,
  mkDerivation,
  writeShellScriptBin,
}: let
  start = writeShellScriptBin "desired-config-test-start" ''
    set -eu

    config=$1
    state_dir=$2
    . "$config"
    test "$TOKEN" = desired-token
    mkdir -p "$state_dir"
    printf '%s\n' "$TOKEN" > "$state_dir/started"
  '';
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];}];
      target = [];
      role = "build-input";
    };
    pname = "desired-config-test";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The package contains its exact desired-config-test marker.";
        "files" = {};
        "input" = "The desired-configuration test package payload.";
        "operation" = "Read the installed package identity bytes.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import pathlib\nassert pathlib.Path(\"@out@/share/desired-config-test/payload.txt\").read_bytes() == b\"desired-config-test\"\nprint(\"desired-config-test data passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "desired-config-test data passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "The immutable package rejects the absent host-generated configuration.";
        "files" = {};
        "input" = "A request for an undeclared generated configuration file in the immutable package.";
        "operation" = "Resolve that path beneath the package output.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import pathlib, sys\nif pathlib.Path(\"@out@/etc/aos/packages/desired-config-test/config.env\").exists():\n    raise SystemExit(2)\nsys.stderr.write(\"desired-config-test rejected invalid input\\n\")\nraise SystemExit(7)\n"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "desired-config-test rejected invalid input\n";
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
          mkdir -p "$out/share/desired-config-test"
          printf desired-config-test > "$out/share/desired-config-test/payload.txt"
          mkdir -p "$out/bin"
          ln -s ${start}/bin/desired-config-test-start "$out/bin/desired-config-test-start"
        '';
      }
    ];

    abilities = ./_desired-config-test/module.nix;

    meta = {
      description = "AOS desired package config sequencing test payload";
      license = "Apache-2.0";
    };
  }
