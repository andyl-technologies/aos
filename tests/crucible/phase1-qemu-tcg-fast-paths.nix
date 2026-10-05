# Executes the patched production fault-query and completion bodies without a
# complete emulator build. The package also runs this proof with its configured
# compiler flags, keeping the fast check and shipped implementation aligned.
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

          cat > "$out/result" <<'RESULT'
          PASS
          check=checks.crucible.phase1.qemuTcgFastPaths
          production_bodies_exercised=true
          empty_fault_queue_avoids_mutex_and_clock_reads=true
          active_fault_and_restore_behavior_preserved=true
          inactive_instruction_completion_avoids_icount_reads=true
          causal_negative_controls_rejected=true
          RESULT
        '';
      }
    ];
  }
