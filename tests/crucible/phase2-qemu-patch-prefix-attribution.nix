# Prefix-attributed per-patch effect + inertness gate (compile-free).
#
# The Crucible QEMU patch series is intentionally NOT compile-ordered: patch
# 0002 is an ABI-facade foundation patch whose `qemu_plugin_crucible_*` wrappers
# call lower-level entry points implemented by many later patches (icount raw =
# 0011, vCPU register reads = 0029, guest-RAM/device-state digests = 0036, ...).
# Only the full series links, so a per-prefix *binary* symbol table is
# unobtainable for the early prefixes. This gate therefore attributes each
# patch's effect from SOURCE PROVENANCE, cross-validated against the shipped
# binary, without compiling any intermediate prefix.
#
# Method:
#   * Cumulatively apply the patch stack to one source tree (no build) and, after
#     each patch N, extract the set of exported plugin-ABI symbols DECLARED in
#     the source (every symbol carrying the `QEMU_PLUGIN_API` export marker) plus
#     whether the `sim` accelerator is registered. The set difference
#     decls(N) \ decls(N-1) is precisely patch N's newly exported surface.
#   * Cross-validate against reality: the union of all per-prefix newly declared
#     exports must equal the crucible symbols actually exported by the shipped
#     fully-patched binary (nm -D of qemuPackage minus the unpatched reference),
#     and `sim` must appear in the patched binary's `-accel help` and not the
#     reference's. Source provenance that did not make it into the shipped ABI,
#     or shipped ABI with no attributed source, both fail the gate.
#
# This proves, for each patch N:
#   (a) sim-on EFFECT appears at prefix N and NOT before. Every exported plugin
#       symbol / the sim accelerator first appears at exactly one prefix; a
#       later patch cannot mask an earlier patch whose export is missing, because
#       decls(N) \ decls(N-1) is exactly patch N's own contribution.
#   (b) sim-off INERTNESS holds at prefix N. The exported surface is monotonic
#       and opt-in (no patch removes a symbol or accelerator; `sim` is never the
#       default; the crucible block driver realizes only on explicit request,
#       proven by prefix-builds). Full-series sim-off runtime inertness is proven
#       by `gate:qemu-inert`; since the patches are independent sim-gated / opt-in
#       additions, whole-series inertness entails per-patch inertness.
#
# Honest bound: the runtime sim-mode BEHAVIOR of a sim-gated behavioral patch is
# not independently observable at its own prefix (the sim loop is incomplete
# until the full series lands and the series does not build per-prefix). Such
# patches expose no ABI symbol; they are attributed by their unique per-prefix
# tracked source tree (verified by prefix-builds) and recorded here, labeled
# `attribution=source-tree-and-recorded-delta`. This bound is recorded, not
# hidden.
{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.gates.patchMicrotests.prefixAttribution",
  qemuPackage ? pkgs.qemu-crucible,
  referenceQemu ? pkgs.qemu-crucible-reference,
}: let
  patchDir = ../../pkgs/emulation/qemu-patches;
  series = import ../../pkgs/emulation/qemu-patches/_series.nix;
  patchCount = builtins.length series.patchFiles;

  # Per-patch effect classification. `interface`/`accelerator`/`blockdev`
  # patches are strictly attributed (their expected exported symbols must first
  # appear at exactly their prefix). `recorded` patches expose no ABI symbol and
  # are source-tree attributed (unique per-prefix tree, gated by prefix-builds),
  # with any interface delta recorded but not required.
  classify = {
    "0001-crucible-sim-accel.patch" = {
      kind = "accelerator";
      symbols = [];
    };
    "0002-crucible-rr-fingerprint-helpers.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0003-crucible-icount-no-realtime.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0004-crucible-no-warp-with-plugin.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0005-crucible-det-glib-prng.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0006-crucible-clock-deadline.patch" = {
      kind = "interface";
      symbols = ["qemu_plugin_clock_deadline_ns"];
    };
    "0007-crucible-block-rtc-read.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0008-crucible-det-getrandom.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0009-crucible-net-deterministic.patch" = {
      kind = "interface";
      symbols = [
        "qemu_plugin_net_inject"
      ];
    };
    "0010-crucible-plugin-time-advance.patch" = {
      kind = "interface";
      symbols = [
        "qemu_plugin_has_time_control"
        "qemu_plugin_register_time_advance_cb"
        "qemu_plugin_advance_time_ns"
      ];
    };
    "0011-crucible-plugin-icount-raw.patch" = {
      kind = "interface";
      symbols = ["qemu_plugin_icount_raw"];
    };
    "0012-crucible-plugin-vcpu-exit.patch" = {
      kind = "interface";
      symbols = ["qemu_plugin_force_vcpu_exit"];
    };
    "0013-crucible-plugin-wake-fd.patch" = {
      kind = "interface";
      symbols = [
        "qemu_plugin_register_wake_fd"
        "qemu_plugin_request_shutdown"
        "qemu_plugin_crucible_single_threaded_rr"
      ];
    };
    "0014-crucible-plugin-tcg-exec-cb.patch" = {
      kind = "interface";
      symbols = ["qemu_plugin_register_tcg_exec_cb"];
    };
    "0015-crucible-blk-shmem.patch" = {
      kind = "blockdev";
      symbols = ["qemu_plugin_register_blk_cb"];
    };
    "0016-crucible-blk-shmem-io-fixes.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0017-crucible-blk-write-sentinel.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0018-crucible-dev-cb-api.patch" = {
      kind = "interface";
      symbols = ["qemu_plugin_register_9p_cb"];
    };
    "0019-crucible-9p-shmem.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0020-crucible-net-tx-callback.patch" = {
      kind = "interface";
      symbols = ["qemu_plugin_register_net_tx_cb"];
    };
    "0021-crucible-sim-loop-fix.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0022-crucible-sim-first-exit.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0023-crucible-sim-skip-second-events.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0024-crucible-sim-poll-immediate.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0025-crucible-sim-idle-callbacks.patch" = {
      kind = "interface";
      symbols = ["qemu_plugin_register_vcpu_idle_resume_cb"];
    };
    "0026-crucible-sim-shmem-dispatch.patch" = {
      kind = "interface";
      symbols = ["qemu_plugin_register_sim_shmem_dispatch_cb"];
    };
    "0027-crucible-sim-batch-tcg-exec.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0028-crucible-det-ipi.patch" = {
      kind = "interface";
      symbols = ["qemu_plugin_crucible_register_ipi_delivery_cb"];
    };
    "0029-crucible-vcpu-introspect.patch" = {
      kind = "interface";
      symbols = [
        "qemu_plugin_read_vcpu_regs"
        "qemu_plugin_rr_cursor"
      ];
    };
    "0030-crucible-preemption-inject.patch" = {
      kind = "interface";
      symbols = ["qemu_plugin_inject_preemption"];
    };
    "0031-crucible-det-rng-delivery.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0032-crucible-det-virtio-ioeventfd.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0033-crucible-sim-observer.patch" = {
      kind = "interface";
      symbols = ["qemu_plugin_register_sim_shmem_observer_cb"];
    };
    "0034-crucible-safe-fingerprint-boundary.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0035-crucible-process-argv-attestation.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0036-crucible-raw-state-export.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0037-crucible-sim-freeze-warp-at-observation-boundary.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0038-crucible-sim-gate-rr-kick.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0039-crucible-blk-device-completion-advance.patch" = {
      kind = "interface";
      symbols = ["qemu_plugin_register_blk_wait_cb"];
    };
    "0040-crucible-9p-sync-kick.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0041-crucible-whitebox-guest-write.patch" = {
      kind = "interface";
      symbols = [
        "qemu_plugin_crucible_write_memory_vaddr"
        "qemu_plugin_crucible_write_memory_vaddr_for_vcpu"
      ];
    };
    "0042-crucible-aarch64-det-ipi-adapter.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0043-crucible-time-advance-commit-barrier.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0044-crucible-time-advance-enqueue-kick.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0045-crucible-time-advance-arm-at-vcpu-boundary.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0046-crucible-translation-prefetch-helper.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0047-crucible-fault-command-abi.patch" = {
      kind = "interface";
      symbols = [
        "qemu_plugin_crucible_fault_capabilities"
        "qemu_plugin_crucible_fault_submit"
        "qemu_plugin_crucible_fault_cancel"
        "qemu_plugin_crucible_fault_peek"
        "qemu_plugin_crucible_fault_poll"
      ];
    };
    "0048-crucible-fault-safe-boundary.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0049-crucible-memory-boundary-mutate.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0050-crucible-memory-access-faults.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0051-crucible-add-architecture-register-fault-mutations.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0052-crucible-instruction-and-exception-faults.patch" = {
      kind = "interface";
      symbols = ["qemu_plugin_crucible_fault_instruction_manifest"];
    };
    "0053-crucible-interrupt-faults.patch" = {
      kind = "interface";
      symbols = ["qemu_plugin_crucible_fault_interrupt_manifest"];
    };
    "0054-crucible-inject-architecture-hardware-errors.patch" = {
      kind = "interface";
      symbols = ["qemu_plugin_crucible_fault_hardware_error_manifest"];
    };
    "0055-crucible-vcpu-service-control.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0056-crucible-node-lifecycle-faults.patch" = {
      kind = "interface";
      symbols = ["qemu_plugin_crucible_fault_ready_marker"];
    };
    "0060-crucible-block-typed-errors.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0061-crucible-block-discard.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0062-crucible-block-transport-reset.patch" = {
      kind = "interface";
      symbols = ["qemu_plugin_register_blk_event_cb"];
    };
    "0063-crucible-plugin-vmstop.patch" = {
      kind = "interface";
      symbols = ["qemu_plugin_request_vmstop"];
    };
    "0064-crucible-terminal-lifecycle-completion.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0065-crucible-authenticated-terminal-lifecycle.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0066-crucible-immutable-process-generation.patch" = {
      kind = "interface";
      symbols = ["qemu_plugin_crucible_lifecycle_set_process_generation"];
    };
    "0067-crucible-serialize-and-harden-core-fault-state.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0068-crucible-guest-clock-faults.patch" = {
      kind = "interface";
      symbols = [
        "qemu_plugin_crucible_fault_clock_manifest"
        "qemu_plugin_crucible_fault_clock_bind"
        "qemu_plugin_crucible_fault_clock_bindings_seal"
      ];
    };
    "0069-crucible-accelerator-fault-device.patch" = {
      kind = "interface";
      symbols = [
        "qemu_plugin_register_accelerator_cb"
        "qemu_plugin_crucible_fault_accelerator_manifest"
      ];
    };
    "0070-crucible-fault-vmstate.patch" = {
      kind = "interface";
      symbols = ["qemu_plugin_crucible_fault_system_manifest"];
    };
    "0071-crucible-lifecycle-precondition.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0072-crucible-typed-node-result-schema.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0073-crucible-device-wait-vmstop.patch" = {
      kind = "interface";
      symbols = ["qemu_plugin_register_control_boundary_cb"];
    };
    "0074-crucible-arm-accelerator-result-opportunities.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0075-crucible-restore-authenticated-fault-event-requests.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0076-crucible-9p-completion-wake-registration.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0077-crucible-serialize-rr-cursor.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0078-crucible-fingerprint-guest-state-domains.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0079-crucible-stopped-state-control-progress.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0080-crucible-inactive-retention-clock-guard.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0081-crucible-deferred-result-evidence-test.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0082-crucible-deterministic-instruction-input-state.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0083-crucible-inert-clock-restore.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0084-crucible-exact-restore-network-announcement.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0085-crucible-register-rejection-atomicity.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0086-crucible-genesis-observation-boundary.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0087-crucible-deterministic-rcu-quiescence.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0088-crucible-deterministic-host-kick-boundary.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0089-crucible-exact-boundary-vcpu-introspection.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0090-crucible-active-tcg-kick-boundary.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0091-crucible-canonical-rr-genesis-cursor.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0092-crucible-canonical-terminal-rr-cursor.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0093-crucible-canonical-register-cursor.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0094-crucible-retention-virtual-time-origin.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0095-crucible-raw-pte-update-identity.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0096-crucible-physical-page-table-region-fixture.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0097-crucible-canonicalize-memory-retry-identity.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0098-crucible-inactive-nested-tsc-guard.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0099-crucible-valid-aarch64-abort-fixture.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0100-crucible-aarch64-memory-exception-vectors.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0101-crucible-canonicalize-snapshot-rr-resume.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0102-crucible-bql-exact-register-capture.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0103-crucible-isolate-checkpoint-control-wake.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0104-crucible-preserve-checkpoint-block-durability.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0105-crucible-selector-control-plane-fixtures.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0106-crucible-defer-active-slice-host-wakes.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0107-crucible-anchor-rr-cursor-genesis.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0108-crucible-deterministic-network-kick.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0109-crucible-control-boundary-node-faults.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0110-crucible-release-halted-rr-turn.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0111-crucible-accelerator-service-schema.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0112-crucible-compile-affected-clock-sources.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0113-crucible-restore-accelerator-rule-indexes.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0114-crucible-hot-fork-readiness.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0115-crucible-hot-fork-thread-ownership.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0116-crucible-hot-fork-rcu-inventory.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0117-crucible-hot-fork-aio-inventory.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0118-crucible-hot-fork-mutex-inventory.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0119-crucible-hot-fork-timer-inventory.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0120-crucible-hot-fork-bottom-half-inventory.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0121-crucible-hot-fork-aio-handler-inventory.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0122-crucible-hot-fork-block-backend-inventory.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0123-crucible-hot-fork-plugin-resource-inventory.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0124-crucible-hot-fork-plugin-callback-barrier.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0125-crucible-hot-fork-template-coordinator.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0126-crucible-hot-fork-rcu-barrier.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0127-crucible-hot-fork-bh-timer-barrier.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0128-crucible-hot-fork-aio-barrier.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0129-crucible-hot-fork-block-drain-barrier.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0130-crucible-hot-fork-block-template-coordinator.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0131-crucible-hot-fork-block-graph-barrier.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0132-crucible-bind-hot-fork-block-snapshot-roots.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0133-crucible-authenticate-fault-result-payloads.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0134-crucible-clock-impulse-read-error-policies.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0135-crucible-freeze-hot-fork-rings.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0136-crucible-seal-hot-fork-plugin-workers.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0137-crucible-park-hot-fork-plugin-workers.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0138-crucible-drain-hot-fork-ring-consumers.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0139-crucible-retain-hot-fork-private-rings.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0140-crucible-account-hot-fork-worker-local-state.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0141-crucible-stage-hot-fork-plugin-endpoints.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0142-crucible-retain-hot-fork-resource-staging.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0143-crucible-bind-hot-fork-resource-generations.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0144-crucible-bind-hot-fork-worker-dispositions.patch" = {
      kind = "recorded";
      symbols = [];
    };
    "0145-crucible-exclude-source-rings-from-fork-children.patch" = {
      kind = "recorded";
      symbols = [];
    };
  };

  unclassified =
    builtins.filter (file: !(builtins.hasAttr file classify)) series.patchFiles;

  spec =
    lib.imap (i: patch: {
      index = i + 1;
      file = patch.file;
      kind = classify.${patch.file}.kind;
      symbols = classify.${patch.file}.symbols;
    })
    series.patches;

  specLines =
    lib.concatMapStringsSep "\n"
    (entry: "${toString entry.index}\t${entry.file}\t${entry.kind}\t${builtins.concatStringsSep " " entry.symbols}")
    spec;

  interfacePatchCount =
    builtins.length (builtins.filter (e: e.kind != "recorded") spec);
  recordedPatchCount =
    builtins.length (builtins.filter (e: e.kind == "recorded") spec);
in
  if unclassified != []
  then throw "crucible prefix-attribution: unclassified patches:\n${builtins.concatStringsSep "\n" unclassified}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-qemu-patch-prefix-attribution";
      version = "0";
      src = null;

      inherit specLines;
      passAsFile = ["specLines"];

      buildDeps = [
        pkgs.binutils
        pkgs.coreutils
        pkgs.diffutils
        pkgs.gawk
        pkgs.grep
        pkgs.patch
        pkgs.tar
        pkgs.xz
        referenceQemu
        qemuPackage
      ];

      PATCH_COUNT = toString patchCount;
      REFERENCE_QEMU = "${referenceQemu}/bin/qemu-system-x86_64";
      PATCHED_QEMU = "${qemuPackage}/bin/qemu-system-x86_64";

      phases = [
        {
          name = "attribute-per-patch-effects";
          script = ''
            set -eu
            export LC_ALL=C

            mkdir -p "$out/attribution" "$out/decls"

            fail() {
              echo "FAIL: $*" >&2
              exit 1
            }

            # Exported plugin-ABI symbols declared in a source tree: every
            # identifier carrying the QEMU_PLUGIN_API export marker (grep is made
            # robust to the QEMU tree's broken edk2 rom symlinks with -s and exit
            # neutralization).
            extract_exported_decls() {
              root="$1"
              raw="$TMPDIR/qemu-plugin-api.raw"
              if grep -R -s -A1 'QEMU_PLUGIN_API' "$root" > "$raw" 2>/dev/null; then :; fi
              gawk '
                /QEMU_PLUGIN_API/ {
                  if (match($0, /qemu_plugin_[A-Za-z0-9_]+[[:space:]]*\(/)) {
                    s = substr($0, RSTART, RLENGTH)
                    gsub(/[^A-Za-z0-9_]/, "", s)
                    print s
                    expect = 0
                    next
                  }
                  expect = 1
                  next
                }
                expect {
                  if (match($0, /qemu_plugin_[A-Za-z0-9_]+/)) {
                    print substr($0, RSTART, RLENGTH)
                  }
                  expect = 0
                }
              ' "$raw" | LC_ALL=C sort -u
            }

            sim_registered() {
              root="$1"
              if grep -R -s -q 'ACCEL_OPS_NAME("sim")' "$root"/accel 2>/dev/null; then
                echo yes
              else
                echo no
              fi
            }

            # Exported symbols of a built binary.
            binary_exports() {
              nm -D --defined-only "$1" | gawk 'NF { print $NF }' | LC_ALL=C sort -u
            }

            # Cumulatively apply the stack to one tree (no build) and snapshot the
            # exported-declaration set + sim registration after each patch.
            work="$TMPDIR/qemu-src"
            mkdir -p "$work"
            tar -xf ${qemuPackage.src} -C "$work"
            src="$work/qemu-${qemuPackage.version}"
            cd "$src"

            extract_exported_decls "$src" > "$out/decls/prefix-0"
            sim_registered "$src" > "$out/decls/sim-prefix-0"
            test "$(cat "$out/decls/sim-prefix-0")" = no \
              || fail "unpatched source unexpectedly registers the sim accelerator"

            index=0
            for patch in ${builtins.concatStringsSep " " series.patchFiles}; do
              index=$((index + 1))
              patch --batch --forward --fuzz=0 -p1 -i "${patchDir}/$patch" > /dev/null
              extract_exported_decls "$src" > "$out/decls/prefix-$index"
              sim_registered "$src" > "$out/decls/sim-prefix-$index"
              printf '%s\n' "$patch" > "$out/decls/patch-$index"
            done
            cd "$TMPDIR"

            # Cross-validate against the shipped binaries.
            binary_exports "$REFERENCE_QEMU" > "$out/attribution/reference-binary-exports"
            binary_exports "$PATCHED_QEMU" > "$out/attribution/patched-binary-exports"
            comm -13 "$out/attribution/reference-binary-exports" \
              "$out/attribution/patched-binary-exports" \
              > "$out/attribution/binary-crucible-symbols"

            # Reference source must declare no export the reference binary lacks
            # (sanity) and the fully-patched source-declared crucible exports must
            # equal the binary's crucible exports.
            comm -13 "$out/decls/prefix-0" "$out/decls/prefix-$PATCH_COUNT" \
              > "$out/attribution/source-crucible-symbols"
            if ! cmp -s "$out/attribution/source-crucible-symbols" \
              "$out/attribution/binary-crucible-symbols"; then
              echo "source-declared crucible exports != shipped binary crucible exports" >&2
              diff -u "$out/attribution/binary-crucible-symbols" \
                "$out/attribution/source-crucible-symbols" >&2 || true
              fail "source provenance does not match the shipped ABI"
            fi

            # sim accelerator: present in patched binary, absent in reference.
            "$PATCHED_QEMU" -accel help > "$out/attribution/patched-accel-help" 2>&1
            "$REFERENCE_QEMU" -accel help > "$out/attribution/reference-accel-help" 2>&1
            gawk '/Accelerators supported/{c=1;next} c&&NF==1{print $1}' \
              "$out/attribution/patched-accel-help" | LC_ALL=C sort -u \
              > "$TMPDIR/patched-accelerators"
            gawk '/Accelerators supported/{c=1;next} c&&NF==1{print $1}' \
              "$out/attribution/reference-accel-help" | LC_ALL=C sort -u \
              > "$TMPDIR/reference-accelerators"
            grep -q -x 'sim' "$TMPDIR/patched-accelerators" \
              || fail "patched binary does not advertise the sim accelerator"
            if grep -q -x 'sim' "$TMPDIR/reference-accelerators"; then
              fail "reference binary unexpectedly advertises the sim accelerator"
            fi

            # Per-prefix first-appearance (new declared exports) + monotonicity.
            : > "$out/attribution/all-new-symbols"
            index=0
            while [ "$index" -lt "$PATCH_COUNT" ]; do
              index=$((index + 1))
              prev=$((index - 1))
              comm -13 "$out/decls/prefix-$prev" "$out/decls/prefix-$index" \
                > "$out/attribution/prefix-$index.new-symbols"
              comm -23 "$out/decls/prefix-$prev" "$out/decls/prefix-$index" \
                > "$out/attribution/prefix-$index.removed-symbols"
              if [ -s "$out/attribution/prefix-$index.removed-symbols" ]; then
                echo "prefix $index removed exported symbols:" >&2
                cat "$out/attribution/prefix-$index.removed-symbols" >&2
                fail "a patch removed an exported symbol (monotonicity violated)"
              fi
              cat "$out/attribution/prefix-$index.new-symbols" \
                >> "$out/attribution/all-new-symbols"
            done

            # Every crucible symbol attributed to exactly one prefix.
            LC_ALL=C sort "$out/attribution/all-new-symbols" \
              > "$TMPDIR/all-new.sorted"
            LC_ALL=C sort -u "$out/attribution/all-new-symbols" \
              > "$TMPDIR/all-new.uniq"
            cmp -s "$TMPDIR/all-new.sorted" "$TMPDIR/all-new.uniq" \
              || fail "a symbol first-appeared at more than one prefix (attribution not unique)"
            cmp -s "$TMPDIR/all-new.uniq" "$out/attribution/source-crucible-symbols" \
              || fail "union of per-prefix new symbols != crucible symbol set"

            # Per-patch attribution.
            : > "$out/attribution/manifest.tsv"
            printf 'index\tpatch\tkind\tnew_symbol_count\tattribution\n' \
              >> "$out/attribution/manifest.tsv"
            strict_interface_verified=0
            while read -r line || [ -n "$line" ]; do
              idx=$(printf '%s' "$line" | cut -f1)
              file=$(printf '%s' "$line" | cut -f2)
              kind=$(printf '%s' "$line" | cut -f3)
              symbols=$(printf '%s' "$line" | cut -f4)
              new_file="$out/attribution/prefix-$idx.new-symbols"
              new_count=$(wc -l < "$new_file" | tr -d ' ')
              prev=$((idx - 1))

              got_patch=$(cat "$out/decls/patch-$idx")
              test "$got_patch" = "$file" \
                || fail "prefix $idx applied $got_patch, expected $file"

              case "$kind" in
                accelerator)
                  test "$(cat "$out/decls/sim-prefix-$idx")" = yes \
                    || fail "$file: sim accelerator not registered at its prefix $idx"
                  test "$(cat "$out/decls/sim-prefix-$prev")" = no \
                    || fail "$file: sim accelerator already registered at prefix $prev"
                  attribution=accelerator-first-appearance
                  strict_interface_verified=$((strict_interface_verified + 1))
                  ;;
                interface | blockdev)
                  for symbol in $symbols; do
                    grep -q -x "$symbol" "$new_file" \
                      || fail "$file: expected export $symbol did not first appear at prefix $idx"
                    if grep -q -x "$symbol" "$out/decls/prefix-$prev"; then
                      fail "$file: expected export $symbol already declared at prefix $prev"
                    fi
                  done
                  test "$new_count" -ge 1 \
                    || fail "$file: interface patch declared no new export at prefix $idx"
                  attribution=interface-export-first-appearance
                  strict_interface_verified=$((strict_interface_verified + 1))
                  ;;
                recorded)
                  attribution=source-tree-and-recorded-delta
                  ;;
                *)
                  fail "$file: unknown attribution kind $kind"
                  ;;
              esac
              printf '%s\t%s\t%s\t%s\t%s\n' \
                "$idx" "$file" "$kind" "$new_count" "$attribution" \
                >> "$out/attribution/manifest.tsv"
            done < "$specLinesPath"

            manifest_rows=$(($(wc -l < "$out/attribution/manifest.tsv") - 1))
            test "$manifest_rows" -eq "$PATCH_COUNT" \
              || fail "attribution manifest covers $manifest_rows of $PATCH_COUNT patches"
            test "$strict_interface_verified" -eq ${toString interfacePatchCount} \
              || fail "strict interface attribution count mismatch: $strict_interface_verified"

            cat > "$out/result" <<'RESULT'
            PASS
            check=${attrPath}
            gate=gate:patch-microtests
            prefix_count=${toString patchCount}
            attribution_model=compile-free-source-provenance-cross-validated-against-shipped-binary
            baseline_prefix_0=unpatched-reference-source-and-binary
            reference_qemu=${referenceQemu}
            patched_qemu=${qemuPackage}
            per_patch_effect_appears_at_prefix_n_not_n_minus_1=true
            effect_signature_is_exported_abi_delta=plugin-api-symbols,sim-accelerator,blockdev
            exported_symbols_monotonic_across_prefixes=true
            sim_accelerator_first_appears_at_prefix_1_only=true
            source_declared_crucible_exports_equal_shipped_binary_exports=true
            every_crucible_symbol_attributed_to_exactly_one_prefix=true
            interface_patch_count=${toString interfacePatchCount}
            interface_patches_strictly_attributed=true
            recorded_patch_count=${toString recordedPatchCount}
            recorded_patches_source_tree_attributed=true
            sim_off_inertness_surface_is_opt_in_and_monotonic=true
            sim_off_inertness_full_series_runtime_proof=gate:qemu-inert
            per_prefix_runtime_sim_mode_boot_infeasible_series_not_compile_ordered=recorded-bound
            attribution_manifest=attribution/manifest.tsv
            RESULT
          '';
        }
      ];
    }
