//! Shared roster, filesystem, and assertion primitives for the
//! `gate_patch_microtests` support modules.
//!
//! `EXPECTED_PATCHES` is the authoritative carried-QEMU-patch roster; it must
//! stay byte-for-byte in sync with the `.patch` files under
//! `pkgs/emulation/qemu-patches/` (enforced by
//! `assert_covers_carried_qemu_patch_series`).

use std::collections::BTreeSet;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

/// The carried QEMU patch series, in application order.
///
/// Every `.patch` file under `pkgs/emulation/qemu-patches/` must appear here,
/// and every entry here must exist on disk; the aggregate microtest gate fails
/// closed on either mismatch.
pub(super) const EXPECTED_PATCHES: &[&str] = &[
    "0001-crucible-sim-accel.patch",
    "0002-crucible-rr-fingerprint-helpers.patch",
    "0003-crucible-icount-no-realtime.patch",
    "0004-crucible-no-warp-with-plugin.patch",
    "0005-crucible-det-glib-prng.patch",
    "0006-crucible-clock-deadline.patch",
    "0007-crucible-block-rtc-read.patch",
    "0008-crucible-det-getrandom.patch",
    "0009-crucible-net-deterministic.patch",
    "0010-crucible-plugin-time-advance.patch",
    "0011-crucible-plugin-icount-raw.patch",
    "0012-crucible-plugin-vcpu-exit.patch",
    "0013-crucible-plugin-wake-fd.patch",
    "0014-crucible-plugin-tcg-exec-cb.patch",
    "0015-crucible-blk-shmem.patch",
    "0016-crucible-blk-shmem-io-fixes.patch",
    "0017-crucible-blk-write-sentinel.patch",
    "0018-crucible-dev-cb-api.patch",
    "0019-crucible-9p-shmem.patch",
    "0020-crucible-net-tx-callback.patch",
    "0021-crucible-sim-loop-fix.patch",
    "0022-crucible-sim-first-exit.patch",
    "0023-crucible-sim-skip-second-events.patch",
    "0024-crucible-sim-poll-immediate.patch",
    "0025-crucible-sim-idle-callbacks.patch",
    "0026-crucible-sim-shmem-dispatch.patch",
    "0027-crucible-sim-batch-tcg-exec.patch",
    "0028-crucible-det-ipi.patch",
    "0029-crucible-vcpu-introspect.patch",
    "0030-crucible-preemption-inject.patch",
    "0031-crucible-det-rng-delivery.patch",
    "0032-crucible-det-virtio-ioeventfd.patch",
    "0033-crucible-sim-observer.patch",
    "0034-crucible-safe-fingerprint-boundary.patch",
    "0035-crucible-process-argv-attestation.patch",
    "0036-crucible-raw-state-export.patch",
    "0037-crucible-sim-freeze-warp-at-observation-boundary.patch",
    "0038-crucible-sim-gate-rr-kick.patch",
    "0039-crucible-blk-device-completion-advance.patch",
    "0040-crucible-9p-sync-kick.patch",
    "0041-crucible-whitebox-guest-write.patch",
    "0042-crucible-aarch64-det-ipi-adapter.patch",
    "0043-crucible-time-advance-commit-barrier.patch",
    "0044-crucible-time-advance-enqueue-kick.patch",
    "0045-crucible-time-advance-arm-at-vcpu-boundary.patch",
    "0046-crucible-translation-prefetch-helper.patch",
    "0047-crucible-fault-command-abi.patch",
    "0048-crucible-fault-safe-boundary.patch",
    "0049-crucible-memory-boundary-mutate.patch",
    "0050-crucible-memory-access-faults.patch",
    "0051-crucible-add-architecture-register-fault-mutations.patch",
    "0052-crucible-instruction-and-exception-faults.patch",
    "0053-crucible-interrupt-faults.patch",
    "0054-crucible-inject-architecture-hardware-errors.patch",
    "0055-crucible-vcpu-service-control.patch",
    "0056-crucible-node-lifecycle-faults.patch",
    "0060-crucible-block-typed-errors.patch",
    "0061-crucible-block-discard.patch",
    "0062-crucible-block-transport-reset.patch",
    "0063-crucible-plugin-vmstop.patch",
    "0064-crucible-terminal-lifecycle-completion.patch",
    "0065-crucible-authenticated-terminal-lifecycle.patch",
    "0066-crucible-immutable-process-generation.patch",
    "0067-crucible-serialize-and-harden-core-fault-state.patch",
    "0068-crucible-guest-clock-faults.patch",
    "0069-crucible-accelerator-fault-device.patch",
    "0070-crucible-fault-vmstate.patch",
    "0071-crucible-lifecycle-precondition.patch",
    "0072-crucible-typed-node-result-schema.patch",
    "0073-crucible-device-wait-vmstop.patch",
    "0074-crucible-arm-accelerator-result-opportunities.patch",
    "0075-crucible-restore-authenticated-fault-event-requests.patch",
    "0076-crucible-9p-completion-wake-registration.patch",
    "0077-crucible-serialize-rr-cursor.patch",
    "0078-crucible-fingerprint-guest-state-domains.patch",
    "0079-crucible-stopped-state-control-progress.patch",
    "0080-crucible-inactive-retention-clock-guard.patch",
    "0081-crucible-deferred-result-evidence-test.patch",
    "0082-crucible-deterministic-instruction-input-state.patch",
    "0083-crucible-inert-clock-restore.patch",
    "0084-crucible-exact-restore-network-announcement.patch",
    "0085-crucible-register-rejection-atomicity.patch",
    "0086-crucible-genesis-observation-boundary.patch",
    "0087-crucible-deterministic-rcu-quiescence.patch",
    "0088-crucible-deterministic-host-kick-boundary.patch",
    "0089-crucible-exact-boundary-vcpu-introspection.patch",
    "0090-crucible-active-tcg-kick-boundary.patch",
    "0091-crucible-canonical-rr-genesis-cursor.patch",
    "0092-crucible-canonical-terminal-rr-cursor.patch",
    "0093-crucible-canonical-register-cursor.patch",
    "0094-crucible-retention-virtual-time-origin.patch",
    "0095-crucible-raw-pte-update-identity.patch",
    "0096-crucible-physical-page-table-region-fixture.patch",
    "0097-crucible-canonicalize-memory-retry-identity.patch",
    "0098-crucible-inactive-nested-tsc-guard.patch",
    "0099-crucible-valid-aarch64-abort-fixture.patch",
    "0100-crucible-aarch64-memory-exception-vectors.patch",
    "0101-crucible-canonicalize-snapshot-rr-resume.patch",
    "0102-crucible-bql-exact-register-capture.patch",
    "0103-crucible-isolate-checkpoint-control-wake.patch",
    "0104-crucible-preserve-checkpoint-block-durability.patch",
    "0105-crucible-selector-control-plane-fixtures.patch",
    "0106-crucible-defer-active-slice-host-wakes.patch",
    "0107-crucible-anchor-rr-cursor-genesis.patch",
    "0108-crucible-deterministic-network-kick.patch",
    "0109-crucible-control-boundary-node-faults.patch",
    "0110-crucible-release-halted-rr-turn.patch",
    "0111-crucible-accelerator-service-schema.patch",
    "0112-crucible-compile-affected-clock-sources.patch",
    "0113-crucible-restore-accelerator-rule-indexes.patch",
    "0114-crucible-hot-fork-readiness.patch",
    "0115-crucible-hot-fork-thread-ownership.patch",
    "0116-crucible-hot-fork-rcu-inventory.patch",
    "0117-crucible-hot-fork-aio-inventory.patch",
    "0118-crucible-hot-fork-mutex-inventory.patch",
    "0119-crucible-hot-fork-timer-inventory.patch",
    "0120-crucible-hot-fork-bottom-half-inventory.patch",
    "0121-crucible-hot-fork-aio-handler-inventory.patch",
    "0122-crucible-hot-fork-block-backend-inventory.patch",
    "0123-crucible-hot-fork-plugin-resource-inventory.patch",
    "0124-crucible-hot-fork-plugin-callback-barrier.patch",
    "0125-crucible-hot-fork-template-coordinator.patch",
    "0126-crucible-hot-fork-rcu-barrier.patch",
    "0127-crucible-hot-fork-bh-timer-barrier.patch",
    "0128-crucible-hot-fork-aio-barrier.patch",
    "0129-crucible-hot-fork-block-drain-barrier.patch",
    "0130-crucible-hot-fork-block-template-coordinator.patch",
    "0131-crucible-hot-fork-block-graph-barrier.patch",
    "0132-crucible-bind-hot-fork-block-snapshot-roots.patch",
    "0133-crucible-authenticate-fault-result-payloads.patch",
    "0134-crucible-clock-impulse-read-error-policies.patch",
    "0135-crucible-freeze-hot-fork-rings.patch",
    "0136-crucible-seal-hot-fork-plugin-workers.patch",
    "0137-crucible-park-hot-fork-plugin-workers.patch",
    "0138-crucible-drain-hot-fork-ring-consumers.patch",
    "0139-crucible-retain-hot-fork-private-rings.patch",
    "0140-crucible-account-hot-fork-worker-local-state.patch",
    "0141-crucible-stage-hot-fork-plugin-endpoints.patch",
    "0142-crucible-retain-hot-fork-resource-staging.patch",
    "0143-crucible-bind-hot-fork-resource-generations.patch",
    "0144-crucible-bind-hot-fork-worker-dispositions.patch",
    "0145-crucible-exclude-source-rings-from-fork-children.patch",
    "0146-crucible-register-hot-fork-child-runtime.patch",
    "0147-crucible-bind-hot-fork-child-process-generation.patch",
    "0148-crucible-expose-hot-fork-child-runtime-state.patch",
    "0149-crucible-bind-hot-fork-endpoint-replacement-slots.patch",
    "0150-crucible-add-fork-child-endpoint-replacement-primitive.patch",
    "0151-crucible-authenticate-immediate-hot-fork-children.patch",
    "0152-crucible-acknowledge-frozen-hot-fork-plugin-rings.patch",
    "0153-crucible-close-inherited-child-descriptor-tables.patch",
    "0154-crucible-close-fork-child-descriptor-admission.patch",
    "0155-crucible-verify-fork-child-mapping-dispositions.patch",
    "0156-crucible-authenticate-fork-child-shared-mapping-backings.patch",
    "0157-crucible-compose-fork-child-resource-disposition.patch",
    "0158-crucible-bind-hot-fork-source-mappings.patch",
    "0159-crucible-bind-child-runtime-source-mappings.patch",
    "0160-crucible-compose-registered-fork-child-runtime.patch",
    "0161-crucible-bind-retained-plugin-child-plan.patch",
    "0162-crucible-bind-plugin-child-resource-tables.patch",
    "0163-crucible-compose-child-resource-contributions.patch",
    "0164-crucible-consume-sealed-child-resource-plans.patch",
    "0165-crucible-compose-child-descriptor-replacements.patch",
    "0166-crucible-bind-branch-private-child-diagnostics.patch",
    "0167-crucible-retain-branch-private-child-qmp.patch",
    "0168-crucible-bind-child-qmp-reinitializer.patch",
    "0169-crucible-compose-child-qmp-reinitializer.patch",
    "0170-crucible-report-complete-child-qmp-disposition.patch",
    "0171-crucible-preserve-child-qmp-query-basis.patch",
    "0172-crucible-inventory-qmp-monitor-state.patch",
    "0173-crucible-bind-supported-child-qmp-profile.patch",
    "0174-crucible-bind-child-monitor-ownership-basis.patch",
    "0175-crucible-bind-child-monitor-chardev-disposition.patch",
    "0176-crucible-bind-child-monitor-socket-resources.patch",
    "0177-crucible-hold-reconstructed-child-monitor-socket.patch",
    "0178-crucible-reset-reconstructed-child-qmp-protocol.patch",
    "0179-crucible-rebuild-reconstructed-child-qmp-dispatcher.patch",
    "0180-crucible-reconstruct-child-monitor-iothread.patch",
];

/// Collects the `.patch` file names carried under `path`, validating each
/// against [`EXPECTED_PATCHES`].
///
/// # Errors
///
/// Returns an error if `path` cannot be read as a directory.
///
/// # Panics
///
/// Panics if a carried `.patch` file is absent from [`EXPECTED_PATCHES`], so a
/// newly added patch that skips the roster fails the gate loudly.
pub(super) fn patch_files(path: &Path) -> Result<BTreeSet<&'static str>, Box<dyn Error>> {
    let mut patches = BTreeSet::new();
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.ends_with(".patch") {
            let patch = EXPECTED_PATCHES
                .iter()
                .copied()
                .find(|expected| *expected == name);
            if let Some(patch) = patch {
                patches.insert(patch);
            } else {
                panic!("unexpected carried QEMU patch `{name}`");
            }
        }
    }
    Ok(patches)
}

/// Asserts `haystack` contains `needle`, panicking with the missing needle on
/// failure.
///
/// # Panics
///
/// Panics if `needle` is not a substring of `haystack`.
pub(super) fn assert_contains(haystack: &str, needle: &str) {
    assert!(
        haystack.contains(needle),
        "expected to find `{needle}` in checked source"
    );
}

/// Unwraps an extraction from checked source, panicking with `context` when
/// the extraction found nothing (the workspace denies `expect_used`, so test
/// support code funnels fallible extractions through this assertion instead).
///
/// # Panics
///
/// Panics with `context` when `value` is `None`.
pub(super) fn required<T>(value: Option<T>, context: &str) -> T {
    match value {
        Some(inner) => inner,
        None => panic!("{context}"),
    }
}

/// Locates the workspace root by walking upward until the crate manifest and
/// the crucible test tree are both present.
///
/// # Errors
///
/// Returns an error if the current directory cannot be read or no ancestor
/// contains both `crates/Cargo.toml` and `tests/crucible/default.nix`.
pub(super) fn workspace_root() -> Result<PathBuf, Box<dyn Error>> {
    let mut current = std::env::current_dir()?;
    loop {
        if current.join("crates/Cargo.toml").is_file()
            && current.join("tests/crucible/default.nix").is_file()
        {
            return Ok(current);
        }
        if !current.pop() {
            return Err("could not locate workspace root".into());
        }
    }
}
