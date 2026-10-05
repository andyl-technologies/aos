# Exercises production fault, mutex-owner, and snapshot-query fast paths without
# a complete emulator build. The package runs the same proofs with its configured
# compiler flags to keep this check aligned with the shipped implementation.
{pkgs}: let
  patchDir = ../../pkgs/emulation/qemu-patches;
  atomicPatch = import (patchDir + "/_atomic-patch.nix");
in
  pkgs.mkDerivation {
    pname = "crucible-phase1-qemu-tcg-fast-paths";
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
        name = "run-production-tcg-fast-paths";
        script = ''
          set -eu
          export CC=cc
          export CFLAGS="-std=gnu11 -O2 -Wall -Wextra -Werror -I$PWD/include -I${pkgs.glib.dev}/include/glib-2.0 -I${pkgs.glib.dev}/lib/glib-2.0/include"
          export LDFLAGS="-L${pkgs.glib.dev}/lib -Wl,-rpath,${pkgs.glib}/lib -lglib-2.0"

          mkdir -p "$out"
          ${pkgs.python3}/bin/python3 tests/unit/test-crucible-tcg-fast-paths.py \
            --output-dir "$out/proof" > "$out/production-proof.result"
          cat "$out/production-proof.result"
          grep -q '^PASS production TCG fast paths:' "$out/production-proof.result"

          # Each regression must fail at its behavioral assertion when its
          # production fast path or restore publication is removed.
          for negative in queue completion restore; do
            if ${pkgs.python3}/bin/python3 tests/unit/test-crucible-tcg-fast-paths.py \
              --output-dir "$out/negative-$negative" \
              --negative-control "$negative" > "$out/negative-$negative.log" 2>&1; then
              echo "negative control unexpectedly passed: $negative" >&2
              exit 1
            fi
            grep -q 'assertion failed' "$out/negative-$negative.log"
          done

          ${pkgs.python3}/bin/python3 tests/unit/test-crucible-mutex-owner-cache.py \
            --output-dir "$out/mutex-owner-proof" > "$out/mutex-owner-proof.result"
          cat "$out/mutex-owner-proof.result"
          grep -q '^PASS production mutex owner cache:' "$out/mutex-owner-proof.result"

          for negative in cache atfork native; do
            if ${pkgs.python3}/bin/python3 tests/unit/test-crucible-mutex-owner-cache.py \
              --output-dir "$out/negative-mutex-$negative" \
              --negative-control "$negative" > "$out/negative-mutex-$negative.log" 2>&1; then
              echo "negative mutex-owner control unexpectedly passed: $negative" >&2
              exit 1
            fi
            grep -q 'assertion failed' "$out/negative-mutex-$negative.log"
          done

          ${pkgs.python3}/bin/python3 tests/unit/test-crucible-snapshot-fast-path.py \
            --output-dir "$out/snapshot-proof" > "$out/snapshot-proof.result"
          cat "$out/snapshot-proof.result"
          grep -q '^PASS production snapshot fast path:' "$out/snapshot-proof.result"

          if ${pkgs.python3}/bin/python3 tests/unit/test-crucible-snapshot-fast-path.py \
            --output-dir "$out/negative-snapshot-order" \
            --negative-control order > "$out/negative-snapshot-order.log" 2>&1; then
            echo "negative snapshot control unexpectedly passed: order" >&2
            exit 1
          fi
          grep -q 'assertion failed' "$out/negative-snapshot-order.log"

          cat > "$out/result" <<'RESULT'
          PASS
          check=checks.crucible.phase1.qemuTcgFastPaths
          production_bodies_exercised=true
          empty_fault_queue_avoids_mutex_and_clock_reads=true
          active_fault_and_restore_behavior_preserved=true
          inactive_instruction_completion_avoids_icount_reads=true
          causal_negative_controls_rejected=true
          cached_mutex_owner_matches_real_thread_and_fork_ids=true
          atfork_callback_order_and_native_child_refresh_preserved=true
          cold_snapshot_query_avoids_accelerator_lookup=true
          active_snapshot_restore_cursor_and_tb_shape_preserved=true
          RESULT
        '';
      }
    ];
  }
