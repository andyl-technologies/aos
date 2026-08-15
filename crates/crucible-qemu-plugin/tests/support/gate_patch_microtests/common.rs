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
