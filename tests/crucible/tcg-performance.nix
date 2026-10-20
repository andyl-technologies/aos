{
  pkgs,
  qemuPackage ? pkgs.qemu-crucible,
}: let
  fixtures = import ./tcg-performance-fixtures.nix {
    inherit pkgs qemuPackage;
  };
in
  pkgs.mkDerivation {
    pname = "crucible-tcg-performance-determinism";
    version = "0";
    src = null;

    buildDeps = [pkgs.coreutils pkgs.python3 fixtures qemuPackage];

    phases = [
      {
        name = "check-exact-cold-and-restored-tcg-state";
        script = ''
          set -eu
          mkdir -p "$out/evidence"

          ${pkgs.python3}/bin/python3 ${./tcg-performance.py} \
            --qemu packaged=${qemuPackage}/bin/qemu-system-x86_64 \
            --fixtures ${fixtures} \
            --output "$out/evidence" \
            --repetitions 2 \
            --stop 2400000 \
            --checkpoint 1200000 > "$out/samples.jsonl"

          cat > "$out/result" <<'RESULT'
          PASS
          check=checks.crucible.phase2.tcgPerformanceDeterminism
          exact_stop_icount=true
          exact_logical_tick=true
          independent_50ps_tick_oracle=true
          independent_register_ram_arithmetic_oracle=true
          cold_repeats_identical=true
          restored_repeats_identical=true
          cold_restored_registers_identical=true
          cold_restored_ram_digest_identical=true
          timings_retained_without_portable_threshold=true
          RESULT
        '';
      }
    ];
  }
