//! Per-patch evidence table and the assertion that every carried patch's
//! microtest fixture publishes the required evidence tokens.

use std::error::Error;
use std::fs;

use super::common::{assert_contains, workspace_root};

/// Asserts each carried patch's microtest nix fixture (and C fixture, when
/// present) publishes the required evidence tokens.
///
/// # Errors
///
/// Returns an error if any checked fixture file cannot be read.
pub(super) fn assert_per_patch_evidence() -> Result<(), Box<dyn Error>> {
    let root = workspace_root()?;
    let per_patch_checks = [
        (
            "tests/crucible/phase1-sim-accel.nix",
            "",
            "0001-crucible-sim-accel.patch",
        ),
        (
            "tests/crucible/phase1-rr-fingerprint-helpers.nix",
            "tests/crucible/phase1-rr-fingerprint-helpers.c",
            "0002-crucible-rr-fingerprint-helpers.patch",
        ),
        (
            "tests/crucible/phase1-icount-no-realtime.nix",
            "tests/crucible/phase1-icount-no-realtime.c",
            "0003-crucible-icount-no-realtime.patch",
        ),
        (
            "tests/crucible/phase1-no-warp-with-plugin.nix",
            "tests/crucible/phase1-no-warp-with-plugin.c",
            "0004-crucible-no-warp-with-plugin.patch",
        ),
        (
            "tests/crucible/phase1-qemu-deterministic-entropy.nix",
            "tests/crucible/phase1-qemu-deterministic-entropy.c",
            "0005-crucible-det-glib-prng.patch",
        ),
        (
            "tests/crucible/phase1-clock-deadline.nix",
            "tests/crucible/phase1-clock-deadline.c",
            "0006-crucible-clock-deadline.patch",
        ),
        (
            "tests/crucible/phase1-block-rtc-read.nix",
            "tests/crucible/phase1-block-rtc-read.c",
            "0007-crucible-block-rtc-read.patch",
        ),
        (
            "tests/crucible/phase1-qemu-deterministic-getrandom.nix",
            "tests/crucible/phase1-qemu-deterministic-entropy.c",
            "0008-crucible-det-getrandom.patch",
        ),
        (
            "tests/crucible/phase1-qemu-net-deterministic.nix",
            "tests/crucible/phase1-qemu-net-deterministic.c",
            "0009-crucible-net-deterministic.patch",
        ),
        (
            "tests/crucible/phase1-plugin-time-advance.nix",
            "tests/crucible/phase1-plugin-time-advance.c",
            "0010-crucible-plugin-time-advance.patch",
        ),
        (
            "tests/crucible/phase1-plugin-time-advance.nix",
            "tests/crucible/phase1-plugin-time-advance.c",
            "0043-crucible-time-advance-commit-barrier.patch",
        ),
        (
            "tests/crucible/phase1-plugin-time-advance.nix",
            "tests/crucible/phase1-plugin-time-advance.c",
            "0044-crucible-time-advance-enqueue-kick.patch",
        ),
        (
            "tests/crucible/phase1-plugin-time-advance.nix",
            "tests/crucible/phase1-plugin-time-advance.c",
            "0045-crucible-time-advance-arm-at-vcpu-boundary.patch",
        ),
        (
            "tests/crucible/phase7-translation-prefetch-neutrality.nix",
            "",
            "0046-crucible-translation-prefetch-helper.patch",
        ),
        (
            "tests/crucible/phase1-plugin-runtime-apis.nix",
            "tests/crucible/phase1-plugin-runtime-apis.c",
            "0011-crucible-plugin-icount-raw.patch",
        ),
        (
            "tests/crucible/phase1-plugin-runtime-apis.nix",
            "tests/crucible/phase1-plugin-runtime-apis.c",
            "0012-crucible-plugin-vcpu-exit.patch",
        ),
        (
            "tests/crucible/phase1-plugin-runtime-apis.nix",
            "tests/crucible/phase1-plugin-runtime-apis.c",
            "0013-crucible-plugin-wake-fd.patch",
        ),
        (
            "tests/crucible/phase1-plugin-runtime-apis.nix",
            "tests/crucible/phase1-plugin-runtime-apis.c",
            "0014-crucible-plugin-tcg-exec-cb.patch",
        ),
        (
            "tests/crucible/phase1-plugin-runtime-apis.nix",
            "tests/crucible/phase1-plugin-runtime-apis.c",
            "0063-crucible-plugin-vmstop.patch",
        ),
        (
            "tests/crucible/phase1-qemu-block-shmem.nix",
            "tests/crucible/phase1-qemu-block-shmem.c",
            "0015-crucible-blk-shmem.patch",
        ),
        (
            "tests/crucible/phase1-qemu-block-shmem.nix",
            "tests/crucible/phase1-qemu-block-shmem.c",
            "0016-crucible-blk-shmem-io-fixes.patch",
        ),
        (
            "tests/crucible/phase1-qemu-block-shmem.nix",
            "tests/crucible/phase1-qemu-block-shmem.c",
            "0017-crucible-blk-write-sentinel.patch",
        ),
        (
            "tests/crucible/phase1-qemu-9p-shmem.nix",
            "tests/crucible/phase1-qemu-9p-shmem.c",
            "0018-crucible-dev-cb-api.patch",
        ),
        (
            "tests/crucible/phase1-qemu-9p-shmem.nix",
            "tests/crucible/phase1-qemu-9p-shmem.c",
            "0019-crucible-9p-shmem.patch",
        ),
        (
            "tests/crucible/phase1-qemu-net-tx-callback.nix",
            "tests/crucible/phase1-qemu-net-tx-callback.c",
            "0020-crucible-net-tx-callback.patch",
        ),
        (
            "tests/crucible/phase1-qemu-sim-correctness.nix",
            "tests/crucible/phase1-qemu-sim-correctness.c",
            "0021-crucible-sim-loop-fix.patch",
        ),
        (
            "tests/crucible/phase1-qemu-sim-correctness.nix",
            "tests/crucible/phase1-qemu-sim-correctness.c",
            "0022-crucible-sim-first-exit.patch",
        ),
        (
            "tests/crucible/phase1-qemu-sim-correctness.nix",
            "tests/crucible/phase1-qemu-sim-correctness.c",
            "0023-crucible-sim-skip-second-events.patch",
        ),
        (
            "tests/crucible/phase1-qemu-sim-correctness.nix",
            "tests/crucible/phase1-qemu-sim-correctness.c",
            "0024-crucible-sim-poll-immediate.patch",
        ),
        (
            "tests/crucible/phase1-qemu-sim-correctness.nix",
            "tests/crucible/phase1-qemu-sim-correctness.c",
            "0025-crucible-sim-idle-callbacks.patch",
        ),
        (
            "tests/crucible/phase1-qemu-sim-correctness.nix",
            "tests/crucible/phase1-qemu-sim-correctness.c",
            "0026-crucible-sim-shmem-dispatch.patch",
        ),
        (
            "tests/crucible/phase1-qemu-sim-batch-tcg-exec.nix",
            "tests/crucible/phase1-qemu-sim-batch-tcg-exec.c",
            "0027-crucible-sim-batch-tcg-exec.patch",
        ),
        (
            "tests/crucible/phase2-qemu-det-ipi.nix",
            "",
            "0028-crucible-det-ipi.patch",
        ),
        (
            "tests/crucible/phase2-qemu-vcpu-introspect.nix",
            "tests/crucible/phase2-qemu-vcpu-introspect.c",
            "0029-crucible-vcpu-introspect.patch",
        ),
        (
            "tests/crucible/phase1-qemu-det-rng-delivery.nix",
            "",
            "0031-crucible-det-rng-delivery.patch",
        ),
        (
            "tests/crucible/phase1-qemu-det-virtio-ioeventfd.nix",
            "",
            "0032-crucible-det-virtio-ioeventfd.patch",
        ),
    ];

    for (nix_path, c_path, patch) in per_patch_checks {
        let nix_source = fs::read_to_string(root.join(nix_path))?;

        assert_contains(&nix_source, "gate=gate:patch-microtests");
        if nix_path == "tests/crucible/phase1-plugin-runtime-apis.nix" {
            assert_contains(&nix_source, "patch=${patchName}");
            assert_contains(&nix_source, patch);
            assert_contains(&nix_source, "tcg_exec_callback_after_icount_context=true");
        } else if matches!(
            nix_path,
            "tests/crucible/phase1-qemu-block-shmem.nix"
                | "tests/crucible/phase1-qemu-9p-shmem.nix"
                | "tests/crucible/phase1-qemu-net-tx-callback.nix"
        ) {
            assert_contains(&nix_source, "patch=${patchName}");
            assert_contains(&nix_source, patch);
        } else if nix_path == "tests/crucible/phase1-qemu-sim-correctness.nix" {
            assert_contains(&nix_source, "patch=${patchName}");
            assert_contains(&nix_source, patch);
            assert_contains(&nix_source, "sim_correctness_fixture_exercised=true");
            assert_contains(&nix_source, "sim_block_wake_coqueue_microtest=true");
            assert_contains(&nix_source, "sim_block_wake_failure_fails_waiter=true");
            assert_contains(&nix_source, "sim_block_main_loop_reentry_absent=true");
            assert_contains(&nix_source, "sim_idle_callbacks_missed_wake_microtest=true");
            assert_contains(
                &nix_source,
                "sim_idle_advance_completion_barrier_microtest=true",
            );
            assert_contains(&nix_source, "sim_idle_advance_rearms_while_halted=true");
            assert_contains(&nix_source, "sim_shmem_dispatch_ceiling_microtest=true");
            assert_contains(&nix_source, "sim_shmem_budget_clamp_microtest=true");
        } else if nix_path == "tests/crucible/phase1-qemu-sim-batch-tcg-exec.nix" {
            assert_contains(&nix_source, "patch=${patchName}");
            assert_contains(&nix_source, patch);
            assert_contains(
                &nix_source,
                "sim_batch_tcg_exec_single_vcpu_fixed_limit=true",
            );
            assert_contains(&nix_source, "sim_batch_tcg_exec_multivcpu_limit_guard=true");
            assert_contains(
                &nix_source,
                "sim_batch_tcg_exec_on_off_icount_trace_identical=true",
            );
            assert_contains(
                &nix_source,
                "sim_batch_tcg_exec_halted_returns_to_rr_handoff=true",
            );
            assert_contains(
                &nix_source,
                "sim_batch_tcg_exec_breaks_on_debug_atomic=true",
            );
            assert_contains(&nix_source, "sim_batch_tcg_exec_timer_between_slots=true");
            assert_contains(&nix_source, "sim_batch_tcg_exec_shmem_ceiling_guard=true");
        } else if nix_path == "tests/crucible/phase2-qemu-det-ipi.nix" {
            assert_contains(&nix_source, "patch=${patchName}");
            assert_contains(&nix_source, patch);
            assert_contains(
                &nix_source,
                "deterministic_ipi_rr_handoff=queued-drain-before-next-vcpu",
            );
            assert_contains(&nix_source, "deterministic_ipi_fixed_mode_trace=true");
            assert_contains(&nix_source, "deterministic_ipi_init_mode_trace=true");
            assert_contains(&nix_source, "deterministic_ipi_sipi_mode_trace=true");
            assert_contains(
                &nix_source,
                "deterministic_ipi_delivery_icount_trace_match=true",
            );
            assert_contains(&nix_source, "deterministic_ipi_source_target_distinct=true");
        } else if nix_path == "tests/crucible/phase2-qemu-vcpu-introspect.nix" {
            assert_contains(&nix_source, "patch=${patchName}");
            assert_contains(&nix_source, patch);
            assert_contains(
                &nix_source,
                "formal_register_export=qemu_plugin_read_vcpu_regs",
            );
            assert_contains(&nix_source, "formal_cursor_export=qemu_plugin_rr_cursor");
            assert_contains(&nix_source, "arbitrary_vcpu_register_read=true");
            assert_contains(&nix_source, "register_read_side_effect_free=true");
            assert_contains(&nix_source, "register_short_buffer_fails_closed=true");
            assert_contains(&nix_source, "register_size_mismatch_rejected=true");
            assert_contains(&nix_source, "rr_cursor_boundary_rejected=true");
            assert_contains(
                &nix_source,
                "rr_cursor_out_of_range_current_vcpu_rejected=true",
            );
        } else {
            assert_contains(&nix_source, &format!("patch={patch}"));
        }
        assert_contains(&nix_source, "patched_fixture_exercised=true");
        assert_contains(&nix_source, "stock_negative_control");
        assert_contains(&nix_source, "qemuPackage ?");
        assert_contains(&nix_source, "qemu_package=${qemuPackage}");
        assert_contains(&nix_source, "qemu_package_version=${qemuPackage.version}");
        assert_contains(&nix_source, "patch --batch --fuzz=0 -p1");
        if !c_path.is_empty() {
            let c_source = fs::read_to_string(root.join(c_path))?;
            assert_contains(&c_source, "stock_negative_control");
        }
    }

    Ok(())
}
