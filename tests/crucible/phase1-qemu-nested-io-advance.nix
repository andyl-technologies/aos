# Exercises the production advance completion when it runs nested inside a
# guest access blocked in synchronous device I/O. The full package repeats the
# positive proof with its configured compiler.
{pkgs}: let
  patchDir = ../../pkgs/emulation/qemu-patches;
  atomicPatch = import (patchDir + "/_atomic-patch.nix");
in
  pkgs.mkDerivation {
    pname = "crucible-phase1-qemu-nested-io-advance";
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
        name = "run-production-nested-io-advance";
        script = ''
          set -eu
          # The extracted-body fixtures keep QEMU's own warning policy, which
          # leaves unused stub parameters to the configured build.
          export CC=cc
          export CFLAGS="-std=gnu11 -D_GNU_SOURCE -O2 -Wall -Werror -Wno-unused-parameter -Wno-sign-compare -Wmissing-prototypes -I$PWD -I$PWD/include -I${pkgs.glib.dev}/include/glib-2.0 -I${pkgs.glib.dev}/lib/glib-2.0/include"
          export LDFLAGS="-L${pkgs.glib.dev}/lib -Wl,-rpath,${pkgs.glib}/lib -lglib-2.0"

          mkdir -p "$out"
          ${pkgs.python3}/bin/python3 tests/unit/test-crucible-control-deferred.py \
            --output-dir "$out/proof" --case nested-io > "$out/production-proof.result"
          cat "$out/production-proof.result"
          grep -q '^PASS production control:' "$out/production-proof.result"

          # Leaving the nested completion to the outer RR idle settlement must
          # reproduce the stall: the waiter's next advance is refused -EBUSY.
          if ${pkgs.python3}/bin/python3 tests/unit/test-crucible-control-deferred.py \
            --output-dir "$out/negative-nested-settle" --case nested-io \
            --negative-control nested-settle > "$out/negative-nested-settle.log" 2>&1; then
            echo "negative nested-settle control unexpectedly passed" >&2
            exit 1
          fi
          grep -q 'assertion failed (nested_retry_status == 0): (-16 == 0)' \
            "$out/negative-nested-settle.log"

          cat > "$out/result" <<'RESULT'
          PASS
          check=checks.crucible.phase1.qemuNestedIoAdvance
          production_advance_completion_and_enqueue_bodies_exercised=true
          nested_completion_releases_barrier_before_waiters=true
          second_advance_in_one_blocked_access_accepted=true
          no_idle_wake_published_from_executing_rr_thread=true
          outer_settlement_negative_reproduces_ebusy=true
          RESULT
        '';
      }
    ];
  }
