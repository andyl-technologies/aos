# Exercises accelerator publication and hot mode predicates with production
# bodies. The package repeats the proof with its configured compiler.
{pkgs}: let
  patchDir = ../../pkgs/emulation/qemu-patches;
  atomicPatch = import (patchDir + "/_atomic-patch.nix");
in
  pkgs.mkDerivation {
    pname = "crucible-phase1-qemu-accel-classification";
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
        name = "run-production-accel-classification";
        script = ''
          set -eu
          export CC=cc
          export CFLAGS="-std=gnu11 -O2 -Wall -Wextra -Werror -Wmissing-prototypes -I$PWD -I$PWD/include -I${pkgs.glib.dev}/include/glib-2.0 -I${pkgs.glib.dev}/lib/glib-2.0/include"
          export LDFLAGS="-L${pkgs.glib.dev}/lib -Wl,-rpath,${pkgs.glib}/lib -lglib-2.0"

          mkdir -p "$out"
          ${pkgs.python3}/bin/python3 tests/unit/test-crucible-accel-classification.py \
            --output-dir "$out/proof" > "$out/production-proof.result"
          cat "$out/production-proof.result"
          grep -q '^PASS production accel classification:' "$out/production-proof.result"

          # Each mutation must compile and then fail a lifecycle or hot-path
          # assertion. A parser error or missing provider is not a causal proof.
          for negative in publication-order callback-order shared-classification \
            stale-retry superclass-match repeated-name-query predicate-order; do
            if ${pkgs.python3}/bin/python3 tests/unit/test-crucible-accel-classification.py \
              --output-dir "$out/negative-$negative" \
              --negative-control "$negative" > "$out/negative-$negative.log" 2>&1; then
              echo "negative accelerator control $negative unexpectedly passed" >&2
              exit 1
            fi
            grep -q '^Compiled production accel classification fixture' "$out/negative-$negative.log"
            grep -Ei -q 'assertion.*failed|assertion failed' "$out/negative-$negative.log"
          done

          cat > "$out/result" <<'RESULT'
          PASS
          check=checks.crucible.phase1.qemuAccelClassification
          instance_classification_precedes_publication_and_init_callbacks=true
          exact_names_failed_initialization_and_retry_preserved=true
          absent_machine_and_accelerator_return_false=true
          audited_reset_restore_identity_and_real_fork_continuity=true
          hot_mode_predicates_avoid_repeated_class_and_name_queries=true
          icount_short_circuit_and_timer_side_effect_order_preserved=true
          seven_compiled_causal_negative_controls_rejected=true
          bounded_provider_fixture_without_guest_execution=true
          RESULT
        '';
      }
    ];
  }
