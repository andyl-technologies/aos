# Keeps the production Sim FIFO barriers while exercising ordinary common
# events. Host arbitration is bounded; native inertness qualification is separate.
{pkgs}: let
  patchDir = ../../pkgs/emulation/qemu-patches;
  atomicPatch = import (patchDir + "/_atomic-patch.nix");
in
  pkgs.mkDerivation {
    pname = "crucible-phase1-qemu-rr-sim-barriers";
    version = "0";
    src = pkgs.qemu-crucible.src;

    buildDeps = [
      pkgs.coreutils
      pkgs.glib
      pkgs.glib.dev
      pkgs.grep
      pkgs.patch
      pkgs.python3
      pkgs.tar
      pkgs.xz
    ];

    phases = [
      {
        name = "unpack-and-apply-atomic-patch";
        script = ''
          set -eu
          tar -xf "$src"
          cd qemu-${atomicPatch.qemuVersion}
          patch --batch --forward --fuzz=0 -p1 -i "${patchDir}/${atomicPatch.file}"
        '';
      }
      {
        name = "run-production-rr-sim-barriers";
        script = ''
          set -eu
          export CC=cc
          export CFLAGS="-std=gnu11 -O2 -Wall -Wextra -Werror -Wmissing-prototypes -Wstrict-prototypes -Wredundant-decls -I$PWD -I$PWD/include -I${pkgs.glib.dev}/include/glib-2.0 -I${pkgs.glib.dev}/lib/glib-2.0/include"
          export LDFLAGS="-L${pkgs.glib.dev}/lib -Wl,-rpath,${pkgs.glib}/lib -lglib-2.0"

          mkdir -p "$out"
          ${pkgs.python3}/bin/python3 tests/unit/test-crucible-rr-sim-barriers.py \
            --output-dir "$out/proof" > "$out/production-proof.result"
          cat "$out/production-proof.result"
          grep -q '^PASS healthy ordinary 8->3 cycles per CPU' "$out/production-proof.result"

          # Reject only compiled assertion failures, preserving causal evidence
          # for the mode guard, common processing and Sim ordering obligations.
          for negative in wrong-mode skipped-common missing-pre-drain \
            missing-fixed-point missing-owner-restoration; do
            if ${pkgs.python3}/bin/python3 tests/unit/test-crucible-rr-sim-barriers.py \
              --output-dir "$out/negative-$negative" \
              --negative-control "$negative" > "$out/negative-$negative.log" 2>&1; then
              echo "negative RR barrier control $negative unexpectedly passed" >&2
              exit 1
            fi
            grep -q '^Compiled production-body RR Sim barrier fixture' "$out/negative-$negative.log"
            grep -Ei -q 'assertion.*failed|assertion failed' "$out/negative-$negative.log"
          done

          cat > "$out/result" <<'RESULT'
          PASS
          check=checks.crucible.phase1.qemuRrSimBarriers
          sim_global_fifo_fixed_point_precedes_first_stopped_acknowledgement=true
          sim_callback_stop_and_fifo_owner_order_preserved=true
          ordinary_common_stop_before_work_and_extra_common_passes_retained=true
          ordinary_healthy_empty_work_mutex_cycles_reduced_from_eight_to_three=true
          actual_queue_common_pause_resume_kick_and_wait_bodies_exercised=true
          five_compiled_causal_negative_controls_rejected=true
          bounded_arbitration_without_concurrent_producers_or_guest_execution=true
          native_boot_run_migration_qmp_acceptance_is_separate=true
          RESULT
        '';
      }
    ];
  }
