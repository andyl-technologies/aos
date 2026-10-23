//! Real lazy-page paths through Graph, physical quota and Packed metadata reuse.
//!
//! These controls use the unchanged finite component bank and actual disk
//! contents. They supply no process envelope, native authority or parity claim.

use super::*;

#[test]
fn lazy_page_path_reuses_shared_manifest_and_closes_active_pins_before_response() {
    let directory = tempfile::tempdir().unwrap();
    let (fixture, shared) = shared_metadata::fixture(directory.path());
    let root = capture_pages(&fixture, 8);
    shared.reclaim();
    let baseline = fixture.quota.0.usage().unwrap();

    for (index, cold) in [(3, true), (6, false)] {
        crate::content_store::reset_packed_read_costs();
        let response = fixture
            .store
            .read_page_with_proof(&root, "main", index, &fixture.original, &mut || Ok(()))
            .unwrap();

        let mut expected = [0u8; 4096];
        fill_page(index, &mut expected);
        assert_eq!(response.bytes(), expected);
        response
            .proof()
            .verify(response.bytes(), root.record(), root.logical_digest())
            .unwrap();
        let costs = crate::content_store::packed_read_costs();
        assert_eq!(costs.lookups, 5, "four catalogs and the selected page only");
        assert_eq!(costs.pack_switches, 1);
        assert_eq!(costs.authenticated_manifests, u64::from(cold));
        assert_eq!(fixture.quota.0.usage().unwrap().0, baseline.0);
        drop(response);
    }

    let retained = fixture.quota.0.usage().unwrap();
    assert!(retained.1 > baseline.1);
    assert_eq!(shared.reclaim(), retained.1 - baseline.1);
    assert_eq!(fixture.quota.0.usage().unwrap(), baseline);
}

#[test]
fn lazy_page_path_refuses_graph_excluded_page_before_its_lookup() {
    let directory = tempfile::tempdir().unwrap();
    let (fixture, shared) = shared_metadata::fixture(directory.path());
    let root = capture_pages(&fixture, 8);
    shared.reclaim();
    let restricted = Fixture::with_guard(
        directory.path(),
        fixture.quota.clone(),
        shared.clone(),
        BTreeSet::from([
            ObjectKind::RamTree,
            ObjectKind::ExactManifest,
            ObjectKind::Trace,
        ]),
    );
    let baseline = fixture.quota.0.usage().unwrap();
    crate::content_store::reset_packed_read_costs();

    let error = restricted
        .store
        .read_page_with_proof(&root, "main", 3, &restricted.original, &mut || Ok(()))
        .unwrap_err();

    assert_eq!(crate::content_store::packed_read_costs().lookups, 4);
    assert_eq!(fixture.quota.0.usage().unwrap().0, baseline.0);
    drop(error);
    shared.reclaim();
    assert_eq!(fixture.quota.0.usage().unwrap(), baseline);
}

#[test]
fn lazy_page_path_authenticates_actual_page_after_shared_manifest_reuse() {
    use std::os::unix::fs::FileExt;

    let directory = tempfile::tempdir().unwrap();
    let (fixture, shared) = shared_metadata::fixture(directory.path());
    let root = capture_pages(&fixture, 8);
    shared.reclaim();
    let baseline = fixture.quota.0.usage().unwrap();
    drop(
        fixture
            .store
            .read_page_with_proof(&root, "main", 3, &fixture.original, &mut || Ok(()))
            .unwrap(),
    );
    let mut expected = [0u8; 4096];
    fill_page(6, &mut expected);
    let (path, offset) = std::fs::read_dir(directory.path().join("objects/packs"))
        .unwrap()
        .find_map(|entry| {
            let path = entry.unwrap().path();
            let bytes = std::fs::read(&path).unwrap();
            bytes
                .windows(expected.len())
                .position(|bytes| bytes == expected)
                .map(|offset| (path, offset as u64))
        })
        .expect("the selected real page exists in a physical pack");
    let file = std::fs::OpenOptions::new().write(true).open(path).unwrap();
    file.write_all_at(&[expected[0] ^ 1], offset).unwrap();
    drop(file);
    crate::content_store::reset_packed_read_costs();

    let error = fixture
        .store
        .read_page_with_proof(&root, "main", 6, &fixture.original, &mut || Ok(()))
        .unwrap_err();

    assert!(crate::content_store::packed_read_costs().lookups > 0);
    assert_eq!(fixture.quota.0.usage().unwrap().0, baseline.0);
    drop(error);
    shared.reclaim();
    assert_eq!(fixture.quota.0.usage().unwrap(), baseline);
}

#[test]
fn lazy_page_path_final_boundary_refuses_after_all_actual_pins_close() {
    let directory = tempfile::tempdir().unwrap();
    let (fixture, shared) = shared_metadata::fixture(directory.path());
    let root = capture_pages(&fixture, 8);
    shared.reclaim();
    let baseline = fixture.quota.0.usage().unwrap();
    crate::content_store::reset_packed_read_costs();
    let mut reached = false;

    let error = fixture
        .store
        .read_page_with_proof(&root, "main", 3, &fixture.original, &mut || {
            if crate::content_store::packed_read_costs().lookups == 5
                && fixture.quota.0.usage().unwrap().0 == baseline.0
            {
                reached = true;
                return Err(RamStoreError::Canceled);
            }
            Ok(())
        })
        .unwrap_err();

    assert!(
        reached,
        "the same final boundary follows physical pin closure"
    );
    assert!(matches!(
        &error,
        RamStoreError::Store(StoreError::RamReadBoundary { .. })
    ));
    assert_eq!(fixture.quota.0.usage().unwrap().0, baseline.0);
    drop(error);
    shared.reclaim();
    assert_eq!(fixture.quota.0.usage().unwrap(), baseline);
}

struct ClosingPhysical {
    shared: Arc<shared_metadata::SharedQuota>,
    closed: std::sync::atomic::AtomicBool,
    observed: std::sync::atomic::AtomicBool,
}

impl StorePhysicalQuotaGuard for ClosingPhysical {
    fn verify(&self) -> Result<(), StoreError> {
        use std::sync::atomic::Ordering;

        if self.closed.load(Ordering::SeqCst) {
            self.observed.store(true, Ordering::SeqCst);
            return Err(StoreError::Unauthorized);
        }
        self.shared.verify()
    }

    fn decoded_metadata_limit(&self) -> Result<u64, StoreError> {
        self.shared.decoded_metadata_limit()
    }

    fn reserve_resources(
        &self,
        fds: u64,
        bytes: u64,
    ) -> Result<crate::owned_decode::ResourceLoan, StoreError> {
        self.shared.reserve_resources(fds, bytes)
    }

    fn read_packed_manifest(
        &self,
        request: &mut crate::content_store::PackedManifestRead<'_>,
    ) -> Result<(), StoreError> {
        self.shared.read_packed_manifest(request)
    }
}

#[test]
fn lazy_page_path_final_physical_refusal_keeps_the_page_unaccepted() {
    use std::sync::atomic::{AtomicBool, Ordering};

    let directory = tempfile::tempdir().unwrap();
    let (fixture, shared) = shared_metadata::fixture(directory.path());
    let root = capture_pages(&fixture, 8);
    shared.reclaim();
    let physical = Arc::new(ClosingPhysical {
        shared: shared.clone(),
        closed: AtomicBool::new(false),
        observed: AtomicBool::new(false),
    });
    let selected = Fixture::with_guard(
        directory.path(),
        fixture.quota.clone(),
        physical.clone(),
        BTreeSet::from([
            ObjectKind::RamTree,
            ObjectKind::RamExtent,
            ObjectKind::ExactManifest,
            ObjectKind::Trace,
        ]),
    );
    let baseline = fixture.quota.0.usage().unwrap();
    crate::content_store::reset_packed_read_costs();

    let error = selected
        .store
        .read_page_with_proof(&root, "main", 3, &selected.original, &mut || {
            if crate::content_store::packed_read_costs().lookups == 5
                && fixture.quota.0.usage().unwrap().0 == baseline.0
            {
                physical.closed.store(true, Ordering::SeqCst);
            }
            Ok(())
        })
        .unwrap_err();

    assert!(physical.closed.load(Ordering::SeqCst));
    assert!(physical.observed.load(Ordering::SeqCst));
    assert_eq!(crate::content_store::packed_read_costs().lookups, 5);
    assert_eq!(fixture.quota.0.usage().unwrap().0, baseline.0);
    drop(error);
    shared.reclaim();
    assert_eq!(fixture.quota.0.usage().unwrap(), baseline);
}
