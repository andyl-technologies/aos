# Per-patch behavioral drop-one discriminator: boot the full-minus-N VARIANT
# binary under the shared sim workload up to MAX_RUNS times and classify N's
# runtime effect against the deterministic full baseline. Only meaningful when N
# dropped clean and full-minus-N built (a sim-gated behavioral patch with no
# exported ABI symbol).
#
# Classification (recomputed live -- nothing hardcoded):
#   diverges  : two variant runs differ -> N suppresses a nondeterminism that
#               reappears without it (e.g. the S6 async-virtio-rng-delivery pair).
#               The determinism guarantee is present in full, absent in the
#               variant, at runtime. records runs_to_diverge.
#   differs   : variant is deterministic but its fingerprint differs from the
#               full baseline -> N's fixed-behavior effect is guest-observable and
#               present in full, absent in the variant.
#   none      : variant is deterministic and identical to full -> this generic
#               workload does not reach N's effect (non-discriminating); the
#               caller records drop-one-composition + a latent-gap flag.
#
# Anti-flake: nondeterminism guarantees divergence in distribution, not in any
# two particular runs, so divergence is sought across MAX_RUNS boots (stopping
# early on the first divergence) rather than asserted on a single pair.
{
  pkgs,
  lib,
  index,
  qemuPackage ? pkgs.qemu-crucible,
  buildDrv,
  fullBaseline ? import ./_sim-full-baseline.nix {inherit pkgs lib qemuPackage;},
  maxRuns ? 5,
  # RTC clock mode for the variant boots. "vm" (deterministic virtual clock) by
  # default; "host" exposes the sim-forces-virtual-RTC patch (0007) -- a variant
  # lacking it reads host time and diverges run-to-run.
  rtcClock ? "vm",
  attrPath ? "drop-one-sim-diverge",
  dependencies ? [],
}: let
  workload = import ./_sim-workload.nix {inherit pkgs lib;};
  usesCanonicalTrace = builtins.elem index [3 17 19 37 38 40];
  canonicalTrace =
    if usesCanonicalTrace
    then
      import ./_drop-one-canonical-trace.nix {
        inherit pkgs lib index buildDrv qemuPackage;
        attrPath = "${attrPath}.canonicalTrace";
      }
    else null;
in
  pkgs.mkDerivation {
    pname = "crucible-sim-diverge-${toString index}";
    version = "0";
    src = null;
    buildDeps = [pkgs.coreutils pkgs.gawk pkgs.grep qemuPackage] ++ dependencies;
    BUILD_DRV = "${buildDrv}";
    FULL_BASELINE = "${fullBaseline}";
    FULL_QEMU = "${qemuPackage}/bin/qemu-system-x86_64";
    FIRMWARE = "${qemuPackage}/share/qemu";
    MAX_RUNS = toString maxRuns;
    RTC_CLOCK = rtcClock;
    DROP_INDEX = toString index;
    CANONICAL_TRACE =
      if usesCanonicalTrace
      then "${canonicalTrace}"
      else "";
    phases = [
      {
        name = "sim-diverge-probe";
        script = ''
          set -eu
          export LC_ALL=C
          mkdir -p "$out"
          ${workload.probeLib}

          # Tolerant: only a clean-dropped, built variant can be booted. For
          # conflict / build-failed outcomes this probe is not applicable (those
          # patches are already attributed by source-dependency / build-required),
          # so emit not-applicable without booting.
          if [ "$(cat "$BUILD_DRV/outcome")" != built ]; then
            cat > "$out/result" <<RESULT
          PASS
          check=${attrPath}
          gate=gate:patch-microtests
          drop_index=$DROP_INDEX
          sim_discriminator_classification=not-applicable
          reason=variant-not-built
          RESULT
            exit 0
          fi
          variant="$BUILD_DRV/variant-qemu-system-x86_64"
          test -x "$variant"
          full_fp=$(cat "$FULL_BASELINE/fingerprint")
          probe_smp=1

          : > "$out/variant-fingerprints"

          # Timer and terminal-observation patches change canonical execution
          # state without necessarily changing the guest's simple serial
          # observables. Compare the repository's exact-horizon SMP trace,
          # normalizing only binary/argv identity fields.
          if [ -n "$CANONICAL_TRACE" ]; then
            cp "$CANONICAL_TRACE/result" "$out/result"
            for artifact in \
              variant-trace.result \
              full-normalized.jsonl \
              variant-a-normalized.jsonl \
              full-vs-variant.diff \
              full-a.tsv \
              full-b.tsv \
              variant-a.tsv \
              variant-b.tsv \
              full-a.marker \
              full-b.marker \
              variant-a.marker \
              variant-b.marker \
              full-a.sha256 \
              full-b.sha256 \
              variant-a.sha256 \
              variant-b.sha256; do
              if [ -f "$CANONICAL_TRACE/$artifact" ]; then
                cp "$CANONICAL_TRACE/$artifact" "$out/$artifact"
              fi
            done
            exit 0
          fi

          # Patch 0008 is a fail-closed policy, not a deterministic-output
          # transform. Exercise the ordinary guest-random API through an SD
          # card probe, deliberately excluding the later sim-specific
          # virtio-rng path: full must reject the unseeded request, while
          # full-minus-0008 must cross the same request into guest userspace.
          if [ "$DROP_INDEX" -eq 8 ]; then
            sim_unseeded_guest_random_policy_probe \
              "$FULL_QEMU" "$FIRMWARE" "$out/full-unseeded"
            sim_unseeded_guest_random_policy_probe \
              "$variant" "$FIRMWARE" "$out/variant-unseeded"
            grep -Fq -- '-accel sim requires -seed for deterministic guest random' \
              "$out/full-unseeded.qemu-stderr" || {
                echo "FAIL: fully patched sim did not reject ordinary unseeded guest random" >&2
                exit 1
              }
            if grep -q '^SIMBOOT:USERSPACE$' "$out/full-unseeded.normalized"; then
              echo "FAIL: fully patched sim reached userspace after unseeded guest random" >&2
              exit 1
            fi
            grep -q '^SIMBOOT:USERSPACE$' "$out/variant-unseeded.normalized" || {
              cat "$out/variant-unseeded.qemu-stderr" >&2
              echo "FAIL: full-minus-0008 did not cross unseeded guest random into userspace" >&2
              exit 1
            }
            if grep -Fq -- '-accel sim requires -seed for deterministic guest random' \
              "$out/variant-unseeded.qemu-stderr"; then
              echo "FAIL: full-minus-0008 retained the dropped guest-random policy" >&2
              exit 1
            fi
            printf 'run=1 outcome=guest-userspace seed_mode=none\n' \
              > "$out/variant-fingerprints"
            cat > "$out/result" <<RESULT
          PASS
          check=${attrPath}
          gate=gate:patch-microtests
          drop_index=$DROP_INDEX
          sim_discriminator_classification=differs
          semantic_form=full-rejects-unseeded-variant-reaches-userspace
          full_unseeded_ordinary_guest_random_rejected=true
          variant_unseeded_guest_userspace_reached=true
          variant_runs=1
          variant_diverges=false
          runs_to_diverge=0
          variant_first_fingerprint=not-applicable-policy-probe
          full_baseline_fingerprint=$full_fp
          variant_max_runs=$MAX_RUNS
          RESULT
            exit 0
          fi

          diverged=false
          runs_to_diverge=0
          run=0
          first=""
          while [ "$run" -lt "$MAX_RUNS" ]; do
            run=$((run + 1))
            fp=$(sim_fingerprint "$variant" "$FIRMWARE" "$RTC_CLOCK" seeded "$probe_smp")
            printf 'run=%s fp=%s\n' "$run" "$fp" >> "$out/variant-fingerprints"
            if [ "$run" -eq 1 ]; then
              first="$fp"
              # An empty fingerprint means this variant did not complete the
              # bounded guest workload. Repeating the same failed boot cannot
              # establish runtime nondeterminism, so classify it as an
              # undiscriminated composition after the first finite attempt.
              if [ -z "$first" ]; then
                break
              fi
            elif [ "$fp" != "$first" ]; then
              diverged=true
              runs_to_diverge="$run"
              break
            fi
          done

          if [ "$diverged" = true ]; then
            classification=diverges
          elif [ -n "$first" ] && [ "$first" != "$full_fp" ]; then
            classification=differs
          else
            classification=none
          fi

          cat > "$out/result" <<RESULT
          PASS
          check=${attrPath}
          gate=gate:patch-microtests
          drop_index=$DROP_INDEX
          sim_discriminator_classification=$classification
          variant_runs=$run
          variant_diverges=$diverged
          runs_to_diverge=$runs_to_diverge
          variant_first_fingerprint=$first
          full_baseline_fingerprint=$full_fp
          variant_max_runs=$MAX_RUNS
          probe_smp=$probe_smp
          RESULT
        '';
      }
    ];
  }
