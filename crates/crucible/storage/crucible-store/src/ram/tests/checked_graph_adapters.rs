//! Actual RAM capture and owning page reads through checked graph adapters.

use super::*;
use crate::content_store::{DirectoryBlobBackend, MetricsStore, RoutedStore};
use std::collections::BTreeMap;

#[test]
fn checked_graph_adapters_capture_and_reopen_actual_ram_on_directory_and_sqlite() {
    for directory_backend in [true, false] {
        let directory = tempfile::tempdir().unwrap();
        let quota = Arc::new(FixtureRamQuota(
            crate::content_store::test_resources::FixtureResourceBudget::new(128, 256 << 20),
        ));
        let original = crate::owned_decode::DecodeBudget::for_store(quota.clone()).unwrap();
        let child = if directory_backend {
            DirectoryBlobBackend::new_with_physical_quota(
                "adapters",
                directory.path(),
                quota.clone(),
            )
            .unwrap()
        } else {
            SqliteBlobBackend::open_with_physical_quota(
                "adapters",
                directory.path(),
                quota.clone(),
                8 * 1024 * 1024,
                Arc::new(FixtureCatalogSupervisor(quota.clone())),
                &crate::content_store::fixture_sqlite_heap()
                    .expect("authored SQLite fixture process"),
            )
            .unwrap()
        };
        let (metrics, state) = MetricsStore::new("metrics", child);
        let metrics: Arc<dyn ImmutableBlobBackend> = Arc::new(metrics);
        let routed = RoutedStore::new(
            "routed",
            BTreeMap::from([
                (ObjectKind::RamExtent, metrics.clone()),
                (ObjectKind::RamTree, metrics.clone()),
                (ObjectKind::ExactManifest, metrics),
            ]),
        )
        .unwrap();
        assert!(Arc::ptr_eq(
            &routed.metadata_resources().unwrap(),
            &(quota.clone() as Arc<dyn crate::content_store::StorePhysicalQuotaGuard>),
        ));
        let store = RamStore::new(
            Arc::new(routed),
            DurabilityRequirement::new(1, false).unwrap(),
            RamStoreLimits::default(),
        )
        .unwrap();
        let retention = Retention::default();
        let captured = store
            .capture(
                topology(4096),
                Scope::Exact,
                &mut patterned,
                &retention,
                &original.child().unwrap(),
                &mut || Ok(()),
            )
            .unwrap();
        let root = store
            .open_with_metadata_resources(
                retention.retain_root(captured.object_id()).unwrap(),
                &original.child().unwrap(),
                &mut || Ok(()),
            )
            .unwrap();
        store
            .verify(&root, &original.child().unwrap(), &mut || Ok(()))
            .unwrap();
        let page = store
            .read_page_with_proof(&root, "main", 0, &original.child().unwrap(), &mut || Ok(()))
            .unwrap();
        assert_eq!(page.bytes().len(), 4096);
        assert!(state.snapshot().put_calls > 0);
        assert!(state.snapshot().read_calls > 0);
        assert_eq!(state.snapshot().read_stream_bytes, 0);
        drop(captured);
        drop(root);
        drop(store);
        drop(original);
        assert!(quota.0.usage().unwrap().1 > 0);
        assert_eq!(
            page.proof().page_digest(),
            crucible_ram::PageDigest::hash(page.bytes()).unwrap()
        );
        drop(page);
        assert_eq!(quota.0.usage().unwrap(), (0, 0));
    }
}
