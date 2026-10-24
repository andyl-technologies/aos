//! Shared-service metadata costs for the unchanged full RAM traversal.
//!
//! Every pass checks all page bytes and EOF through the actual physical Graph
//! edge. Counters describe work, not permission, wall-time parity or a native
//! process envelope. The existing complete 512 MiB lifecycle test is separate.

use super::*;

pub(super) fn assert_repack_read_costs(bytes: u64) {
    let directory = tempfile::tempdir().unwrap();
    let (fixture, shared) = shared_metadata::fixture(directory.path());
    let pages = bytes / 4096;
    let root = capture_pages(&fixture, pages);
    shared.reclaim();
    let baseline = fixture.quota.0.usage().unwrap();

    assert_restored(&fixture, &root, pages, "cost_before_repack");
    let before = crate::content_store::packed_read_costs();
    assert_restored(&fixture, &root, pages, "cost_before_repack_warm");
    let before_warm = crate::content_store::packed_read_costs();
    let before_retained = assert_reclaimed(&fixture, &shared, baseline);

    let repack = fixture.admin.packed_repack();
    let plan = repack[0]
        .plan_repack_with_boundary(&fixture.original, &mut || Ok(()))
        .unwrap();
    let report = repack[0]
        .apply_repack_with_boundary(&fixture.original, &plan, &mut || Ok(()))
        .unwrap();
    assert_eq!(report.before().logical_objects(), 3 * pages);
    assert_eq!(report.after().logical_objects(), 3 * pages);
    let before_packs = report.before().packs();
    let after_packs = report.after().packs();
    drop((report, plan, repack));
    shared.reclaim();
    assert_eq!(fixture.quota.0.usage().unwrap(), baseline);

    assert_restored(&fixture, &root, pages, "cost_after_repack");
    let after = crate::content_store::packed_read_costs();
    assert_restored(&fixture, &root, pages, "cost_after_repack_warm");
    let after_warm = crate::content_store::packed_read_costs();
    let after_retained = assert_reclaimed(&fixture, &shared, baseline);

    assert_eq!(before.lookups, 3 * pages - 1);
    for measured in [before, before_warm, after, after_warm] {
        assert_eq!(measured.lookups, before.lookups);
        assert!(measured.authenticated_manifests <= measured.pack_switches);
    }
    assert!(before.authenticated_manifests > 0);
    assert!(after.authenticated_manifests > 0);
    // crucible-lint: allow direct-diagnostic -- actual same-root work, not permissions or performance parity.
    eprintln!(
        "packed_shared_repack_dfs_costs bytes={bytes} pages={pages} metadata_limit={} baseline_bytes={} before_packs={before_packs} after_packs={after_packs} before_retained_bytes={before_retained} after_retained_bytes={after_retained} before={before:?} before_warm={before_warm:?} after={after:?} after_warm={after_warm:?}",
        64 << 20,
        baseline.1,
    );
}

fn assert_reclaimed(
    fixture: &Fixture,
    shared: &shared_metadata::SharedQuota,
    baseline: (u64, u64),
) -> u64 {
    let retained = fixture.quota.0.usage().unwrap();
    assert_eq!(retained.0, baseline.0, "cached metadata retains no pack FD");
    assert!(retained.1 > baseline.1);
    assert_eq!(shared.reclaim(), retained.1 - baseline.1);
    assert_eq!(fixture.quota.0.usage().unwrap(), baseline);
    retained.1 - baseline.1
}
