//! Root-retention callbacks cannot authorize a revoked publication caller.
//!
//! The real directory backend and retention owner finish their work before the
//! callback irreversibly revokes the same finite caller. Durable objects can
//! remain present; their possession does not authorize a successful return.

use super::*;

struct RevokingRootRetention<'a> {
    retention: &'a Retention,
    caller: Arc<ObservedQuota>,
    issued: Mutex<Option<ContentId>>,
}

impl RamRetention for RevokingRootRetention<'_> {
    fn retain_object(&self, id: ContentId) -> Result<(), RamStoreError> {
        self.retention.retain_object(id)
    }

    fn retain_root(&self, id: ContentId) -> Result<Arc<dyn RamRootLease>, RamStoreError> {
        let lease = self.retention.retain_root(id)?;
        let mut issued = self.issued.lock().unwrap();
        assert!(issued.replace(id).is_none(), "root receipt cannot repeat");
        self.caller.revoked.store(true, Ordering::SeqCst);
        Ok(lease)
    }
}

fn contains_original_revocation(error: &(dyn Error + 'static)) -> bool {
    let mut source = Some(error);
    while let Some(current) = source {
        if current.is::<RevokedOriginalAuthority>() {
            return true;
        }
        source = current.source();
    }
    false
}

fn publication_refuses_after_root_retention(update: bool) {
    let directory = tempfile::tempdir().unwrap();
    let backend_quota = ObservedQuota::with_limit(32 << 20);
    let store = directory_store(directory.path(), &backend_quota);
    let retention = Retention::default();
    let topology = Topology::new(
        vec![RegionDescriptor::new("main", RegionClass::MutableMain, 17).unwrap()],
        Limits::default(),
    )
    .unwrap();
    let predecessor = store
        .capture(
            topology.clone(),
            Scope::Exact,
            &mut patterned,
            &retention,
            &fixture_original(&store),
            &mut || Ok(()),
        )
        .unwrap();
    let caller_quota = ObservedQuota::with_limit(32 << 20);
    let original = DecodeBudget::for_store(caller_quota.clone()).unwrap();
    original
        .charge_bytes(crate::ram::maximum_ram_root_decoding_bytes().unwrap())
        .unwrap();
    let admitted = caller_quota.used();
    let revoking = RevokingRootRetention {
        retention: &retention,
        caller: caller_quota.clone(),
        issued: Mutex::new(None),
    };

    let result = if update {
        store.update(
            &predecessor,
            [RamPageChange {
                region_id: "main".into(),
                page_index: 0,
                bytes: vec![43; 17],
            }],
            &revoking,
            &original,
            &mut || Ok(()),
        )
    } else {
        store.capture(
            topology,
            Scope::Exact,
            &mut patterned,
            &revoking,
            &original,
            &mut || Ok(()),
        )
    };

    assert!(caller_quota.revoked.load(Ordering::SeqCst));
    let issued = revoking.issued.lock().unwrap().unwrap();
    assert!(retention.objects.lock().unwrap().contains(&issued));
    let backend_original = fixture_original(&store);
    let stored = store
        .backend
        .read_with_boundary(&backend_original, issued, None, &mut || Ok(()))
        .unwrap()
        .read_all_with_boundary(&backend_original, 8192, &mut || Ok(()))
        .unwrap();
    assert!(issued.authenticates(&stored));
    drop(stored);
    drop(backend_original);

    let error = result.unwrap_err();
    assert!(contains_original_revocation(&error));
    assert!(matches!(
        &error,
        RamStoreError::Store(StoreError::DecodeAdmission { .. })
    ));
    assert_eq!(caller_quota.used(), admitted);
    drop(original);
    assert_eq!(caller_quota.used(), admitted);
    drop(error);
    assert_eq!(caller_quota.used(), 0);
}

#[test]
fn capture_refuses_original_revocation_during_root_retention() {
    publication_refuses_after_root_retention(false);
}

#[test]
fn update_refuses_original_revocation_during_root_retention() {
    publication_refuses_after_root_retention(true);
}

fn transfer_refuses_after_root_retention(revoke_source: bool) {
    let source_directory = tempfile::tempdir().unwrap();
    let destination_directory = tempfile::tempdir().unwrap();
    let source_backend_quota = ObservedQuota::with_limit(32 << 20);
    let destination_backend_quota = ObservedQuota::with_limit(32 << 20);
    let source_store = directory_store(source_directory.path(), &source_backend_quota);
    let destination_store =
        directory_store(destination_directory.path(), &destination_backend_quota);
    let source_retention = Retention::default();
    let destination_retention = Retention::default();
    let topology = Topology::new(
        vec![RegionDescriptor::new("main", RegionClass::MutableMain, 17).unwrap()],
        Limits::default(),
    )
    .unwrap();
    let root = source_store
        .capture(
            topology,
            Scope::Exact,
            &mut patterned,
            &source_retention,
            &fixture_original(&source_store),
            &mut || Ok(()),
        )
        .unwrap();
    let source_quota = ObservedQuota::with_limit(32 << 20);
    let destination_quota = ObservedQuota::with_limit(32 << 20);
    let source_original = DecodeBudget::for_store(source_quota.clone()).unwrap();
    let destination_original = DecodeBudget::for_store(destination_quota.clone()).unwrap();
    for original in [&source_original, &destination_original] {
        original
            .charge_bytes(crate::ram::maximum_ram_root_decoding_bytes().unwrap())
            .unwrap();
    }
    let source_admitted = source_quota.used();
    let destination_admitted = destination_quota.used();
    let (revoked_quota, live_quota, retained) = if revoke_source {
        (&source_quota, &destination_quota, source_admitted)
    } else {
        (&destination_quota, &source_quota, destination_admitted)
    };
    let revoking = RevokingRootRetention {
        retention: &destination_retention,
        caller: revoked_quota.clone(),
        issued: Mutex::new(None),
    };

    let result = source_store.transfer_to(
        &root,
        &destination_store,
        &revoking,
        &source_original,
        &destination_original,
        &mut || Ok(()),
    );

    assert!(revoked_quota.revoked.load(Ordering::SeqCst));
    assert!(!live_quota.revoked.load(Ordering::SeqCst));
    let issued = revoking.issued.lock().unwrap().unwrap();
    assert_eq!(issued, root.object_id());
    assert!(
        destination_retention
            .objects
            .lock()
            .unwrap()
            .contains(&issued)
    );
    let backend_original = fixture_original(&destination_store);
    let stored = destination_store
        .backend
        .read_with_boundary(&backend_original, issued, None, &mut || Ok(()))
        .unwrap()
        .read_all_with_boundary(&backend_original, 8192, &mut || Ok(()))
        .unwrap();
    assert!(issued.authenticates(&stored));
    drop(stored);
    drop(backend_original);

    let error = result.unwrap_err();
    assert!(contains_original_revocation(&error));
    assert!(matches!(
        &error,
        RamStoreError::Store(StoreError::DecodeAdmission { .. })
    ));
    assert_eq!(source_quota.used(), source_admitted);
    assert_eq!(destination_quota.used(), destination_admitted);
    drop(source_original);
    drop(destination_original);
    assert_eq!(revoked_quota.used(), retained);
    assert_eq!(live_quota.used(), 0);
    drop(error);
    assert_eq!(source_quota.used(), 0);
    assert_eq!(destination_quota.used(), 0);
}

#[test]
fn transfer_refuses_source_revocation_during_destination_root_retention() {
    transfer_refuses_after_root_retention(true);
}

#[test]
fn transfer_refuses_destination_revocation_during_root_retention() {
    transfer_refuses_after_root_retention(false);
}
