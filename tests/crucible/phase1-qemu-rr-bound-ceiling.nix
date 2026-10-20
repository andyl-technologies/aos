# Runs the production RR Sim stop decisions against bounded scheduler ceilings
# (RFC-0010 SCHED-12): a ceiling bounds the clock, only exact events move it
# across a partial instruction, and a stalled node settles without moving. A
# sim node without the plugin settlement bridge is refused, never credited.
# Clocks, timers, fault deadlines and plugin callbacks are bounded providers.
#
# The same check runs the production timer/icount version gate: streams older
# than version 6 may carry credited bias and must be refused.
{pkgs}: let
  patchDir = ../../pkgs/emulation/qemu-patches;
  atomicPatch = import (patchDir + "/_atomic-patch.nix");
  negatives = [
    "credit-ceiling"
    "stalled-ceiling-jump"
    "legacy-ceiling-fallback"
    "launch-without-bridge"
    "plain-settled-fallback"
  ];
  versionNegatives = ["accept-version-5" "unchecked-minimum-version"];
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
          grep -Fxq 'PASS production bounded ceilings: 13 cases' "$out/production-proof.result"
          # A ceiling less than one retirement ahead settles with a zero budget.
          grep -Fxq 'PASS zero-budget gaps of 1 and 49 settle at 2000000' "$out/production-proof.result"
          grep -Fxq 'PASS a timer in a one-tick gap is reached, then settles' "$out/production-proof.result"

          # Each negative restores one pre-fix ceiling credit or fallback and
          # must fail a compiled assertion, not the build.
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

          ${pkgs.python3}/bin/python3 tests/unit/test-crucible-icount-vmstate-version.py \
            --output-dir "$out/version-proof" > "$out/version-proof.result"
          cat "$out/version-proof.result"
          grep -Fxq 'PASS production timer/icount version gate: 4 cases' "$out/version-proof.result"

          # Each version negative accepts a version 5 stream and must fail a
          # compiled assertion, not the build.
          for negative in ${builtins.concatStringsSep " " versionNegatives}; do
            if ${pkgs.python3}/bin/python3 tests/unit/test-crucible-icount-vmstate-version.py \
              --output-dir "$out/version-negative-$negative" \
              --negative-control "$negative" > "$out/version-negative-$negative.log" 2>&1; then
              echo "negative timer/icount version control $negative unexpectedly passed" >&2
              exit 1
            fi
            grep -q '^Compiled production-body timer/icount version fixture' \
              "$out/version-negative-$negative.log"
            grep -Ei -q 'assertion.*failed|assertion failed' "$out/version-negative-$negative.log"
          done

          cat > "$out/result" <<'RESULT'
          PASS
          check=checks.crucible.phase1.qemuRrBoundCeiling
          bare_ceiling_keeps_the_last_retirement_and_settles=true
          timer_and_plugin_exact_events_are_the_only_gap_targets=true
          exact_event_ceiling_is_reached=true
          sim_dispatch_without_settlement_bridge_is_refused=true
          stalled_node_settles_without_moving=true
          timer_icount_version_5_is_refused=true
          five_compiled_causal_negative_controls_rejected=true
          two_compiled_version_negative_controls_rejected=true
          guest_execution_host_scheduler_and_migration_are_separate=true
          RESULT
        '';
      }
    ];
  }
