# Exercises the production completion wake, final prepark scan, and outer idle
# settlement. The full package repeats this proof with its configured compiler.
{pkgs}: let
  patchDir = ../../pkgs/emulation/qemu-patches;
  atomicPatch = import (patchDir + "/_atomic-patch.nix");
in
  pkgs.mkDerivation {
    pname = "crucible-phase1-qemu-settle-prepark";
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
        name = "run-production-settle-prepark";
        script = ''
          set -eu
          export CC=cc
          export CFLAGS="-std=gnu11 -O2 -Wall -Wextra -Werror -Wmissing-prototypes -I$PWD -I$PWD/include -I${pkgs.glib.dev}/include/glib-2.0 -I${pkgs.glib.dev}/lib/glib-2.0/include"
          export LDFLAGS="-L${pkgs.glib.dev}/lib -Wl,-rpath,${pkgs.glib}/lib -lglib-2.0"

          mkdir -p "$out"
          ${pkgs.python3}/bin/python3 tests/unit/test-crucible-settle-prepark.py \
            --output-dir "$out/proof" > "$out/production-proof.result"
          cat "$out/production-proof.result"
          grep -q '^PASS production settle prepark:' "$out/production-proof.result"

          # Removing the durable scan must reproduce a consumed wake followed
          # by a park while SETTLE_READY still belongs to the outer idle loop.
          if ${pkgs.python3}/bin/python3 tests/unit/test-crucible-settle-prepark.py \
            --output-dir "$out/negative-settle-scan" \
            --negative-control settle-scan > "$out/negative-settle-scan.log" 2>&1; then
            echo "negative settle-prepark control unexpectedly passed" >&2
            exit 1
          fi
          grep -q 'assertion failed.*blocked' "$out/negative-settle-scan.log"

          cat > "$out/result" <<'RESULT'
          PASS
          check=checks.crucible.phase1.qemuSettlePrepark
          production_completion_prepark_and_event_bodies_exercised=true
          consumed_completion_wake_cannot_hide_durable_settle_state=true
          settlement_remains_exactly_once_at_outer_idle=true
          armed_nonready_waits_and_replay_bql_restoration_preserved=true
          causal_lost_park_negative_rejected=true
          bounded_provider_fixture_without_guest_execution=true
          RESULT
        '';
      }
    ];
  }
