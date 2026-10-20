# Runs the production RR Sim stop decisions against bounded scheduler ceilings
# (RFC-0010 SCHED-12): a ceiling bounds the clock, only exact events move it
# across a partial instruction, and a stalled node settles without moving.
# Clocks, timers, fault deadlines and plugin callbacks are bounded providers.
{pkgs}: let
  patchDir = ../../pkgs/emulation/qemu-patches;
  atomicPatch = import (patchDir + "/_atomic-patch.nix");
  negatives = ["credit-ceiling" "stalled-ceiling-jump"];
in
  pkgs.mkDerivation {
    pname = "crucible-phase1-qemu-rr-bound-ceiling";
    version = "0";
    src = pkgs.qemu-crucible.src;

    buildDeps = [
      pkgs.coreutils
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
        name = "run-production-rr-bound-ceiling";
        script = ''
          set -eu
          export CC=cc
          export CFLAGS="-O2 -Wall -Wextra -Werror -Wmissing-prototypes -Wstrict-prototypes -Wredundant-decls"
          export LDFLAGS=

          mkdir -p "$out"
          ${pkgs.python3}/bin/python3 tests/unit/test-crucible-rr-bound-ceiling.py \
            --output-dir "$out/proof" > "$out/production-proof.result"
          cat "$out/production-proof.result"
          grep -Fxq 'PASS production bounded ceilings: 10 cases' "$out/production-proof.result"

          # Each negative restores one pre-fix ceiling credit and must fail a
          # compiled assertion, not the build.
          for negative in ${builtins.concatStringsSep " " negatives}; do
            if ${pkgs.python3}/bin/python3 tests/unit/test-crucible-rr-bound-ceiling.py \
              --output-dir "$out/negative-$negative" \
              --negative-control "$negative" > "$out/negative-$negative.log" 2>&1; then
              echo "negative bounded-ceiling control $negative unexpectedly passed" >&2
              exit 1
            fi
            grep -q '^Compiled production-body RR bounded-ceiling fixture' "$out/negative-$negative.log"
            grep -Ei -q 'assertion.*failed|assertion failed' "$out/negative-$negative.log"
          done

          cat > "$out/result" <<'RESULT'
          PASS
          check=checks.crucible.phase1.qemuRrBoundCeiling
          bare_ceiling_keeps_the_last_retirement_and_settles=true
          timer_and_plugin_exact_events_are_the_only_gap_targets=true
          exact_event_ceiling_is_reached=true
          legacy_plugin_keeps_its_exact_ceiling=true
          stalled_node_settles_without_moving=true
          two_compiled_causal_negative_controls_rejected=true
          guest_execution_host_scheduler_and_migration_are_separate=true
          RESULT
        '';
      }
    ];
  }
