//! Canonical sender and complete-lifecycle fixtures sharing physical metadata.
//!
//! The finite portable bank models the authored metadata subset. It issues no
//! kernel quota, native Source or process envelope; real archive/Graph/EOF
//! behavior and cache resource lifetime execute unchanged against actual files.

use super::*;
use crate::content_store::{PackedManifestCache, PackedManifestRead};
use crate::owned_decode::ResourceLoan;
use crucible_qemu_protocol::ram_transfer::{
    RamTransferControl, RamTransferLimits, RamTransferMessage, RamTransferNodeCoordinate,
};

const METADATA_BYTES: u64 = 64 << 20;

pub(super) struct SharedQuota {
    cache: PackedManifestCache<ResourceLoan>,
    quota: Arc<FixtureRamQuota>,
    maximum_bytes: u64,
}

impl StorePhysicalQuotaGuard for SharedQuota {
    fn decoded_metadata_limit(&self) -> Result<u64, StoreError> {
        Ok(self.maximum_bytes)
    }

    fn verify(&self) -> Result<(), StoreError> {
        self.quota.verify()
    }

    fn reserve_resources(&self, fds: u64, bytes: u64) -> Result<ResourceLoan, StoreError> {
        self.reclaim_shortfall(bytes)?;
        self.quota.reserve_resources(fds, bytes)
    }

    fn read_packed_manifest(&self, request: &mut PackedManifestRead<'_>) -> Result<(), StoreError> {
        request.retain_in(&self.cache, |bytes, check| {
            check()?;
            let charged = bytes
                .checked_add(
                    crate::content_store::test_resources::FixtureResourceBudget::loan_control_bytes(
                    ),
                )
                .ok_or(StoreError::Quota)?;
            self.reclaim_shortfall(charged)?;
            check()?;
            self.quota.0.reserve_with_control(bytes)
        })
    }
}

pub(super) fn fixture(root: &Path) -> (Fixture, Arc<SharedQuota>) {
    let quota = Arc::new(FixtureRamQuota(
        crate::content_store::test_resources::FixtureResourceBudget::new(128, METADATA_BYTES),
    ));
    fixture_with_quota(root, quota, METADATA_BYTES)
}

/// Uses the complete lifecycle's unchanged descriptor and resident bank.
pub(super) fn volume_fixture(root: &Path) -> (Fixture, Arc<SharedQuota>) {
    let quota = Fixture::new_quota();
    let maximum_bytes = quota.decoded_metadata_limit().unwrap();
    fixture_with_quota(root, quota, maximum_bytes)
}

fn fixture_with_quota(
    root: &Path,
    quota: Arc<FixtureRamQuota>,
    maximum_bytes: u64,
) -> (Fixture, Arc<SharedQuota>) {
    let shared = Arc::new(SharedQuota {
        cache: PackedManifestCache::new(
            maximum_bytes,
            crate::content_store::test_resources::FixtureResourceBudget::loan_control_bytes(),
        ),
        quota,
        maximum_bytes,
    });
    let fixture = shared.reopen_fixture(root);
    (fixture, shared)
}

impl SharedQuota {
    /// Reopens the Graph using this SAME cache owner and finite bank.
    pub(super) fn reopen_fixture(self: &Arc<Self>, root: &Path) -> Fixture {
        Fixture::with_guard(
            root,
            self.quota.clone(),
            self.clone(),
            BTreeSet::from([
                ObjectKind::RamExtent,
                ObjectKind::RamTree,
                ObjectKind::ExactManifest,
                ObjectKind::Trace,
            ]),
        )
    }

    pub(super) fn assert_reclaimed(&self) {
        let before = self.quota.0.usage().unwrap();
        let reclaimed = self.reclaim();
        let after = self.quota.0.usage().unwrap();
        assert!(reclaimed > 0, "the lifecycle retained shared metadata");
        assert_eq!(after.0, before.0, "metadata owns no pack descriptors");
        assert_eq!(before.1 - after.1, reclaimed);
        assert_eq!(self.reclaim(), 0, "physical refund occurs only once");
        assert_eq!(self.quota.0.usage().unwrap(), after);
    }

    fn reclaim_shortfall(&self, requested: u64) -> Result<(), StoreError> {
        let used = self.quota.0.usage()?.1;
        let shortfall = used
            .checked_add(requested)
            .ok_or(StoreError::Quota)?
            .saturating_sub(self.maximum_bytes);
        if shortfall != 0 {
            // The real finite bank is rechecked by the following reservation.
            // No lock is held during physical cache destruction, and pending
            // fills retain their loans through that destruction.
            self.cache.reclaim(shortfall)?.ok_or(StoreError::Quota)?;
        }
        Ok(())
    }

    pub(super) fn reclaim(&self) -> u64 {
        self.cache.reclaim(u64::MAX).unwrap().unwrap()
    }
}

#[test]
fn two_real_archive_senders_share_one_pool_through_the_physical_graph_edge() {
    let directory = tempfile::tempdir().unwrap();
    let (fixture, shared) = fixture(directory.path());
    let root = capture_pages(&fixture, 8);
    let repack = fixture.admin.packed_repack();
    let plan = repack[0]
        .plan_repack_with_boundary(&fixture.original, &mut || Ok(()))
        .unwrap();
    repack[0]
        .apply_repack_with_boundary(&fixture.original, &plan, &mut || Ok(()))
        .unwrap();
    shared.cache.reclaim(u64::MAX).unwrap();
    let original = fixture_original(&fixture.store);
    let baseline = fixture.quota.0.usage().unwrap();
    crate::content_store::reset_packed_read_costs();
    let world = ContentId::for_bytes(ObjectKind::ExactManifest, 6, b"shared sender original");
    let limits = RamTransferLimits {
        objects: 100,
        bytes: 1 << 20,
        chunk_bytes: 64 << 10,
    };
    let mut first = RamTransferSender::new(
        fixture.store.clone(),
        root.clone(),
        [41; 32],
        world,
        "shared-destination",
        1,
        limits,
        &fixture.original,
    )
    .unwrap();
    let mut second = RamTransferSender::new(
        fixture.store.clone(),
        root.clone(),
        [42; 32],
        world,
        "shared-destination",
        1,
        limits,
        &original,
    )
    .unwrap();
    for (sender, operation) in [(&mut first, [41; 32]), (&mut second, [42; 32])] {
        drop(
            sender
                .respond(
                    RamTransferMessage {
                        operation,
                        control: RamTransferControl::WantNode {
                            coordinate: RamTransferNodeCoordinate::Root,
                            object: root.object_id().to_string(),
                        },
                    },
                    &mut || Ok(()),
                )
                .unwrap(),
        );
        drop(
            sender
                .respond(
                    RamTransferMessage {
                        operation,
                        control: RamTransferControl::WantNode {
                            coordinate: RamTransferNodeCoordinate::Catalog {
                                region_id: "main".into(),
                                first_page: 0,
                                height: root.regions[0].height,
                            },
                            object: root.regions[0].id.to_string(),
                        },
                    },
                    &mut || Ok(()),
                )
                .unwrap(),
        );
    }
    assert_eq!(
        crate::content_store::packed_read_costs().authenticated_manifests,
        1,
        "both real senders authenticate the same repacked manifest once"
    );
    assert_eq!(fixture.quota.0.usage().unwrap().0, baseline.0);
    drop((first, second));
    let retained = fixture.quota.0.usage().unwrap();
    assert!(
        retained.1 > baseline.1,
        "the service owns valid metadata beyond one sender"
    );
    assert_eq!(
        shared.cache.reclaim(u64::MAX).unwrap(),
        Some(retained.1 - baseline.1)
    );
    assert_eq!(fixture.quota.0.usage().unwrap(), baseline);
}

#[test]
fn ordinary_decode_reclaims_rows_before_admission_in_the_same_finite_bank() {
    let directory = tempfile::tempdir().unwrap();
    let (fixture, shared) = fixture(directory.path());
    let root = capture_pages(&fixture, 8);
    shared.reclaim();
    let baseline = fixture.quota.0.usage().unwrap();
    assert_restored(&fixture, &root, 8, "reclaim_initial_read");
    let retained = fixture.quota.0.usage().unwrap();
    assert!(retained.1 > baseline.1);
    assert_eq!(retained.0, baseline.0);

    let held = shared
        .reserve_resources(0, METADATA_BYTES - baseline.1)
        .unwrap();
    assert_eq!(fixture.quota.0.usage().unwrap().1, METADATA_BYTES);
    assert_eq!(shared.reclaim(), 0, "rows physically closed before grant");
    drop(held);
    assert_eq!(fixture.quota.0.usage().unwrap(), baseline);

    assert_restored(&fixture, &root, 8, "reclaim_fresh_read");
    assert!(crate::content_store::packed_read_costs().authenticated_manifests > 0);
    let retained = fixture.quota.0.usage().unwrap();
    assert_eq!(shared.reclaim(), retained.1 - baseline.1);
    assert_eq!(fixture.quota.0.usage().unwrap(), baseline);
}
