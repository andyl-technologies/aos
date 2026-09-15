{
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
    pname = "desired-config-test";
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
