{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase6.basicBlockCoverage",
  taskIds ? ["T-ADV-10" "T-PLUG-15" "T-PERF-15"],
  openTaskIds ? [],
  dependencies ? [],
}: let
  inherit (import ./_test-gate.nix {inherit pkgs lib;}) mkCrucibleTestGate;
in
  mkCrucibleTestGate {
    pname = "crucible-phase6-basic-block-coverage";
    buildDeps = [pkgs.coreutils pkgs.grep pkgs.sed] ++ dependencies;
    phases = [
      {
        name = "run-current-coverage-contracts";
        script = ''
          set -eu
          crucible-cargo test \
            -p crucible \
            --test gate_basic_block_coverage -- --test-threads=1
          crucible-cargo test \
            -p crucible-qemu \
            mapped_quantum::coverage_tests --lib -- --test-threads=1
          crucible-cargo test \
            -p crucible-qemu-plugin \
            coverage --lib -- --test-threads=1
        '';
      }
      {
        name = "write-result";
        script = ''
          mkdir -p "$out"
          cat > "$out/result" <<'RESULT'
          PASS
          check=${attrPath}
          tasks=${builtins.concatStringsSep "," taskIds}
          open_tasks=${builtins.concatStringsSep "," openTaskIds}
          gate=gate:basic-block-coverage
          transport=aggregate-shmem-coverage
          restore_generation_acknowledged=true
          coverage_opt_in=true
          canonical_fingerprint_effect=none
          RESULT
        '';
      }
    ];
  }
