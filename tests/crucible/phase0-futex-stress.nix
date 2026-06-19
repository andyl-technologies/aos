{pkgs}: let
  iterations = "2000000";
  jitterWorkers = "2";
  source = builtins.readFile ./phase0-futex-stress.c;
in
  pkgs.mkDerivation {
    pname = "crucible-phase0-futex-stress";
    version = "0";
    src = null;

    inherit source;
    passAsFile = ["source"];

    buildDeps = [
      pkgs.coreutils
    ];

    ITERATIONS = iterations;
    JITTER_WORKERS = jitterWorkers;

    phases = [
      {
        name = "build";
        script = ''
          cp "$sourcePath" phase0-futex-stress.c
          cc -std=c11 -O2 -Wall -Wextra phase0-futex-stress.c -o phase0-futex-stress
        '';
      }
      {
        name = "run";
        script = ''
          mkdir -p "$out"
          timeout 120 ./phase0-futex-stress "$ITERATIONS" "$JITTER_WORKERS" > "$out/result"
          cp phase0-futex-stress.c "$out/source.c"
        '';
      }
    ];

    meta = {
      description = "Crucible Phase 0 cross-process futex stress spike";
    };
  }
