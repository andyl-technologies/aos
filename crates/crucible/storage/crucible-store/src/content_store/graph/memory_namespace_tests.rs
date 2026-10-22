//! Fixed Memory namespace admission before graph construction effects.
//!
//! The finite model grant exercises graph ownership and refusal ordering.
//! Fixture/backend/registry controls remain outside production funding proof.

use std::path::Path;
use std::sync::Mutex;

use super::*;
use crate::content_store::test_resources::FixtureResourceBudget;
use crate::owned_decode::ResourceLoan;

struct NamespaceAccount {
    resources: FixtureResourceBudget,
    requested: Mutex<Vec<u64>>,
}

struct NamespaceBinder(Arc<NamespaceAccount>);

impl StorePhysicalQuotaBinder for NamespaceBinder {
    fn reserve_memory_namespace(&self, bytes: u64) -> Result<ResourceLoan, StoreError> {
        self.0.requested.lock().unwrap().push(bytes);
        self.0.resources.reserve(0, bytes)
    }

    fn verify_memory_namespace(&self) -> Result<(), StoreError> {
        Ok(())
    }

    fn bind(
        &self,
        _root: &Path,
        _project_id: u32,
        _maximum_physical_bytes: u64,
        _maximum_inodes: u64,
    ) -> Result<Arc<dyn StorePhysicalQuotaGuard>, StoreError> {
        Err(StoreError::Unsupported {
            capability: "model-memory-disk-binding",
        })
    }
}

fn node(name: &str) -> StoreNodeId {
    StoreNodeId::new(name).unwrap()
}

fn memory_config(max_objects: u64) -> StoreGraphConfig {
    let memory = node("memory");
    StoreGraphConfig {
        root: memory.clone(),
        gc_mark_root: None,
        admitted_kinds: BTreeSet::from([ObjectKind::Trace]),
        nodes: BTreeMap::from([(
            memory,
            StoreNodeSpec::Memory {
                max_logical_bytes: 0,
                max_objects,
            },
        )]),
    }
}

fn build(
    config: StoreGraphConfig,
    original: Option<&StorePhysicalQuotaBinderHandle>,
) -> Result<(StoreGraph, StoreGraphAdmin), StoreError> {
    StoreGraph::build_with_admin_and_all_capabilities(
        config,
        &StoreGraphKeyring::new(),
        &StoreGraphNamespaceAuthorizers::new(),
        &StoreGraphObjectProfilers::new(),
        &StoreGraphPhysicalQuotaBinders::new(),
        &StoreGraphS3Clients::new(),
        original,
    )
}

#[test]
fn ordinary_graph_has_a_unique_empty_object_ceiling_and_refuses_checked_ram() {
    let (graph, admin) = build(memory_config(1), None).unwrap();
    let empty = BlobHandle::from_bytes(Vec::new());
    let first = ContentId::for_bytes(ObjectKind::Trace, 1, &[]);
    let second = ContentId::for_bytes(ObjectKind::Trace, 2, &[]);

    graph.put_if_absent(first, &empty).unwrap();
    graph.put_if_absent(first, &empty).unwrap();
    assert!(matches!(
        graph.put_if_absent(second, &empty),
        Err(StoreError::Quota)
    ));
    assert!(graph.contains(first).unwrap());
    assert!(!graph.contains(second).unwrap());
    assert!(matches!(
        graph.checked_publication_metadata(ObjectKind::Trace),
        Err(StoreError::Unsupported {
            capability: "checked-memory-namespace"
        })
    ));
    assert_eq!(admin.physical_count(), 1);
}

#[test]
fn all_memory_namespaces_admit_before_any_disk_constructor() {
    let account = Arc::new(NamespaceAccount {
        resources: FixtureResourceBudget::new(0, 4096),
        requested: Mutex::new(Vec::new()),
    });
    let original = StorePhysicalQuotaBinderHandle::new(NamespaceBinder(account.clone()));
    let temporary = tempfile::TempDir::new().unwrap();
    let disk_path = temporary.path().join("must-remain-absent");
    let root = node("root");
    let disk = node("disk");
    let first = node("memory-a");
    let second = node("memory-b");
    let config = StoreGraphConfig {
        root: root.clone(),
        gc_mark_root: None,
        admitted_kinds: BTreeSet::from([ObjectKind::Trace]),
        nodes: BTreeMap::from([
            (
                root,
                StoreNodeSpec::WriteThrough {
                    children: vec![disk.clone(), first.clone(), second.clone()],
                },
            ),
            (
                disk,
                StoreNodeSpec::Packed {
                    root: disk_path.clone(),
                    target_pack_bytes: 4096,
                },
            ),
            (
                first,
                StoreNodeSpec::Memory {
                    max_logical_bytes: 0,
                    max_objects: 1,
                },
            ),
            (
                second,
                StoreNodeSpec::Memory {
                    max_logical_bytes: 0,
                    max_objects: 64,
                },
            ),
        ]),
    };

    assert!(matches!(
        build(config, Some(&original)),
        Err(StoreError::Quota)
    ));
    assert_eq!(*account.requested.lock().unwrap(), [544, 8544]);
    assert_eq!(account.resources.usage().unwrap(), (0, 0));
    assert!(!disk_path.exists());
}

#[test]
fn namespace_credit_survives_graph_until_the_last_admin_owner_closes() {
    let account = Arc::new(NamespaceAccount {
        resources: FixtureResourceBudget::new(0, 4096),
        requested: Mutex::new(Vec::new()),
    });
    let original = StorePhysicalQuotaBinderHandle::new(NamespaceBinder(account.clone()));
    let (graph, admin) = build(memory_config(1), Some(&original)).unwrap();
    let first = ContentId::for_bytes(ObjectKind::Trace, 1, &[]);
    graph
        .put_if_absent(first, &BlobHandle::from_bytes(Vec::new()))
        .unwrap();

    assert!(
        graph
            .checked_publication_metadata(ObjectKind::Trace)
            .is_ok()
    );
    assert_eq!(account.resources.usage().unwrap(), (0, 544));
    drop(graph);
    assert_eq!(account.resources.usage().unwrap(), (0, 544));
    drop(admin);
    assert_eq!(account.resources.usage().unwrap(), (0, 0));
}

#[test]
fn invalid_object_capacity_refuses_before_the_original_grant() {
    let account = Arc::new(NamespaceAccount {
        resources: FixtureResourceBudget::new(0, 4096),
        requested: Mutex::new(Vec::new()),
    });
    let original = StorePhysicalQuotaBinderHandle::new(NamespaceBinder(account.clone()));

    for maximum in [0, u64::MAX] {
        assert!(matches!(
            build(memory_config(maximum), Some(&original)),
            Err(StoreError::Quota)
        ));
    }
    assert!(account.requested.lock().unwrap().is_empty());
    assert_eq!(account.resources.usage().unwrap(), (0, 0));
}
