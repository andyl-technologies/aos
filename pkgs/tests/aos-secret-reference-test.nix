{
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
