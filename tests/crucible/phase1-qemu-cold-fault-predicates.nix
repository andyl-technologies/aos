# Exercises the production memory and clock predicates, rule index transitions,
# and restore guards. The package repeats the proof with its configured compiler.
{pkgs}: let
  patchDir = ../../pkgs/emulation/qemu-patches;
  atomicPatch = import (patchDir + "/_atomic-patch.nix");
in
  pkgs.mkDerivation {
    pname = "crucible-phase1-qemu-cold-fault-predicates";
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
        name = "run-production-cold-fault-predicates";
        script = ''
          set -eu
          export CC=cc
          export CFLAGS="-std=gnu11 -O2 -Wall -Wextra -Werror -Wmissing-prototypes -I$PWD -I$PWD/include -I${pkgs.glib.dev}/include/glib-2.0 -I${pkgs.glib.dev}/lib/glib-2.0/include"
          export LDFLAGS="-L${pkgs.glib.dev}/lib -Wl,-rpath,${pkgs.glib}/lib -lglib-2.0"

          mkdir -p "$out"
          ${pkgs.python3}/bin/python3 tests/unit/test-crucible-cold-fault-predicates.py \
            --output-dir "$out/proof" > "$out/production-proof.result"
          cat "$out/production-proof.result"
          grep -q '^PASS production cold fault predicates:' "$out/production-proof.result"

          # Restoring either old operand order must compile and then expose an
          # accelerator identity read on an otherwise inactive fault path.
          for control in memory-order clock-order; do
            if ${pkgs.python3}/bin/python3 tests/unit/test-crucible-cold-fault-predicates.py \
              --output-dir "$out/negative-$control" \
              --negative-control "$control" > "$out/negative-$control.log" 2>&1; then
              echo "negative cold predicate control unexpectedly passed: $control" >&2
              exit 1
            fi
            grep -q '^Compiled production cold fault predicates fixture' "$out/negative-$control.log"
            grep -q 'assertion failed.*accel_reads' "$out/negative-$control.log"
          done

          cat > "$out/result" <<'RESULT'
          PASS
          check=checks.crucible.phase1.qemuColdFaultPredicates
          legal_initialized_mode_memory_and_clock_truth_tables_preserved=true
          production_rule_index_install_remove_and_restore_masks_exercised=true
          healthy_callbacks_skip_accelerator_identity_reads=true
          active_clock_projection_rebase_and_restore_guards_preserved=true
          causal_old_operand_order_controls_rejected=true
          bounded_provider_fixture_without_guest_execution=true
          RESULT
        '';
      }
    ];
  }
