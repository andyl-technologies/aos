{
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
    pname = "desired-prune-test";
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

    abilities = ./_desired-prune-test/module.nix;

    meta = {
      description = "AOS desired package prune sequencing test payload";
      license = "Apache-2.0";
    };
  }
