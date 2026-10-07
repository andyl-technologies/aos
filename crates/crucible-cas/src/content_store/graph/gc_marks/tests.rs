//! GC-only graph admission, origin custody and data-route separation tests.
//!
//! The finite component binder below owns real directory handles and metadata
//! loans. Kernel project-quota proof remains the deployed CLI maintenance test.

use super::*;
use crate::content_store::test_resources::FixtureResourceBudget;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use tempfile::TempDir;

fn node(name: &str) -> StoreNodeId {
    StoreNodeId::new(name).unwrap_or_else(|error| panic!("node fixture: {error}"))
}

fn configuration(root: &Path) -> StoreGraphConfig {
    StoreGraphConfig {
        root: node("data"),
        gc_mark_root: Some(node("marks")),
        admitted_kinds: BTreeSet::from([ObjectKind::Trace]),
        nodes: BTreeMap::from([
            (
                node("data"),
                StoreNodeSpec::Memory {
                    max_logical_bytes: 4096,
                },
            ),
            (
                node("marks"),
                StoreNodeSpec::PhysicalQuota {
                    child: node("mark-directory"),
                    policy: StorePhysicalQuotaPolicyId::new("fixture/marks")
                        .unwrap_or_else(|error| panic!("policy fixture: {error}")),
                    project_id: 70,
                    maximum_physical_bytes: 1 << 20,
                    maximum_inodes: 128,
                },
            ),
            (
                node("mark-directory"),
                StoreNodeSpec::Directory {
                    root: root.to_owned(),
                },
            ),
        ]),
    }
}

struct MarkGuard {
    root: PathBuf,
    allowed: AtomicBool,
    resources: FixtureResourceBudget,
}

impl StorePhysicalQuotaGuard for MarkGuard {
    fn verify(&self) -> Result<(), StoreError> {
        if self.allowed.load(Ordering::SeqCst) {
            Ok(())
        } else {
            Err(StoreError::Quota)
        }
    }

    fn reserve_resources(
        &self,
        descriptors: u64,
        bytes: u64,
    ) -> Result<crate::owned_decode::ResourceLoan, StoreError> {
        self.verify()?;
        self.resources.reserve(descriptors, bytes)
    }

    fn gc_mark_backend(
        self: Arc<Self>,
        scope: &str,
    ) -> Result<Arc<dyn ImmutableBlobBackend>, StoreError> {
        self.verify()?;
        if scope != "component-cut" {
            return Err(StoreError::Unauthorized);
        }
        let backend = DirectoryBlobBackend::new_with_physical_quota(
            "component-gc-marks",
            self.root.join("component-cut"),
            self,
        )?;
        Ok(backend)
    }
}

struct MarkBinder {
    guard: Arc<MarkGuard>,
    calls: AtomicUsize,
}

impl StorePhysicalQuotaBinder for MarkBinder {
    fn bind(
        &self,
        root: &Path,
        project: u32,
        bytes: u64,
        inodes: u64,
    ) -> Result<Arc<dyn StorePhysicalQuotaGuard>, StoreError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if root != self.guard.root || (project, bytes, inodes) != (70, 1 << 20, 128) {
            return Err(StoreError::Unauthorized);
        }
        self.guard.verify()?;
        Ok(self.guard.clone())
    }
}

fn build(
    config: StoreGraphConfig,
    binder: Arc<MarkBinder>,
) -> Result<(StoreGraph, StoreGraphAdmin), StoreError> {
    let mut quotas = StoreGraphPhysicalQuotaBinders::new();
    quotas.insert(StorePhysicalQuotaPolicyId::new("fixture/marks")?, binder)?;
    StoreGraph::build_with_admin_and_all_capabilities(
        config,
        &StoreGraphKeyring::new(),
        &StoreGraphNamespaceAuthorizers::new(),
        &StoreGraphObjectProfilers::new(),
        &quotas,
        &StoreGraphS3Clients::new(),
    )
}

fn binder(root: &Path, allowed: bool) -> Arc<MarkBinder> {
    Arc::new(MarkBinder {
        guard: Arc::new(MarkGuard {
            root: root.to_owned(),
            allowed: AtomicBool::new(allowed),
            resources: FixtureResourceBudget::new(128, 1 << 20),
        }),
        calls: AtomicUsize::new(0),
    })
}

#[test]
fn gc_only_root_is_charged_described_and_keeps_reader_origin_without_data_routing()
-> Result<(), StoreError> {
    let temporary = TempDir::new().unwrap_or_else(|error| panic!("mark fixture: {error}"));
    let root = temporary.path().join("marks");
    let binder = binder(&root, true);
    let weak = Arc::downgrade(&binder.guard);
    let (graph, admin) = build(configuration(&root), binder.clone())?;
    assert_eq!(binder.calls.load(Ordering::SeqCst), 1);
    assert_eq!(admin.gc_mark_root_id(), Some(&node("marks")));
    assert_eq!(admin.physical_count(), 1);
    assert_eq!(admin.physical()[0].node(), &node("data"));
    assert_eq!(graph.describe().len(), 3);
    assert!(binder.guard.resources.usage()?.1 > 0);
    assert!(
        admin
            .gc_mark_backend("mark-directory", "component-cut")
            .is_err()
    );

    let marks = admin.gc_mark_backend("marks", "component-cut")?;
    let bytes = b"actual durable component mark";
    let id = ContentId::for_bytes(ObjectKind::Trace, 1, bytes);
    marks.put_if_absent(id, &BlobHandle::from_bytes(bytes.to_vec()))?;
    assert!(root.is_dir());
    assert!(
        std::fs::metadata(&root)
            .map_err(|source| StoreError::Io {
                operation: "GC mark fixture census",
                path: root.clone(),
                source,
            })?
            .blocks()
            > 0
    );
    assert!(!graph.contains(id)?);
    let handle = marks.read(id, None)?;
    let mut reader = handle.open()?;
    assert!(binder.guard.resources.usage()?.0 > 0);
    drop(handle);
    drop(marks);
    drop(admin);
    drop(graph);
    drop(binder);
    assert!(
        weak.upgrade().is_some(),
        "actual reader retains original quota and account"
    );
    let mut actual = Vec::new();
    reader
        .read_to_end(&mut actual)
        .map_err(|source| StoreError::StreamIo {
            operation: "GC mark fixture read",
            source,
        })?;
    assert_eq!(actual, bytes);
    drop(reader);
    assert!(
        weak.upgrade().is_none(),
        "last physical borrower releases original owner"
    );
    Ok(())
}

#[test]
fn ordinary_description_retains_only_original_credit_after_gc_authority_closes()
-> Result<(), StoreError> {
    let temporary = TempDir::new().unwrap_or_else(|error| panic!("description fixture: {error}"));
    let root = temporary.path().join("marks");
    let binder = binder(&root, true);
    let (graph, admin) = build(configuration(&root), binder.clone())?;
    let before = binder.guard.resources.usage()?.1;
    drop(admin);
    let description_only = binder.guard.resources.usage()?.1;
    assert!(description_only > 0 && description_only < before);
    assert_eq!(graph.describe().len(), 3);
    drop(graph);
    assert_eq!(binder.guard.resources.usage()?, (0, 0));
    Ok(())
}

#[test]
fn refusal_precedes_directory_effects_and_no_gc_root_is_inferred() -> Result<(), StoreError> {
    let temporary = TempDir::new().unwrap_or_else(|error| panic!("mark refusal: {error}"));
    let root = temporary.path().join("marks");
    let binder = binder(&root, false);
    assert!(matches!(
        build(configuration(&root), binder.clone()),
        Err(StoreError::Quota)
    ));
    assert_eq!(binder.calls.load(Ordering::SeqCst), 1);
    assert!(!root.exists());

    let mut absent = configuration(&root);
    absent.gc_mark_root = None;
    assert!(matches!(
        StoreGraph::build(absent),
        Err(StoreError::InvalidGraph {
            violation: GraphViolation::UnreachableNode,
            ..
        })
    ));
    Ok(())
}

#[test]
fn gc_root_identity_and_invalid_roles_remain_distinct() -> Result<(), StoreError> {
    let temporary = TempDir::new().unwrap_or_else(|error| panic!("mark identity: {error}"));
    let root = temporary.path().join("marks");
    let configured = configuration(&root);
    let configured_id = StoreGraphConfigurationId::for_config(&configured)?;
    let mut absent = configured.clone();
    absent.gc_mark_root = None;
    assert_ne!(
        configured_id,
        StoreGraphConfigurationId::for_config(&absent)?
    );

    for selected in ["data", "mark-directory", "missing"] {
        let mut invalid = configured.clone();
        invalid.gc_mark_root = Some(node(selected));
        assert!(StoreGraph::build(invalid).is_err());
    }
    let mut aliased = configured.clone();
    aliased.nodes.insert(
        node("data"),
        StoreNodeSpec::Directory { root: root.clone() },
    );
    assert!(matches!(
        StoreGraph::build(aliased),
        Err(StoreError::InvalidGraph {
            violation: GraphViolation::OverlappingAdministrativePath,
            ..
        })
    ));
    let mut parent = configured.clone();
    parent.nodes.insert(
        node("data"),
        StoreNodeSpec::Directory {
            root: root.join("nested"),
        },
    );
    assert!(StoreGraph::build(parent).is_err());
    let mut dotdot = configured.clone();
    dotdot.nodes.insert(
        node("data"),
        StoreNodeSpec::Directory {
            root: root.join("../other"),
        },
    );
    assert!(StoreGraph::build(dotdot).is_err());
    let mut cycle = configured.clone();
    cycle.nodes.insert(
        node("data"),
        StoreNodeSpec::Verified {
            child: node("data"),
        },
    );
    assert!(matches!(
        StoreGraph::build(cycle),
        Err(StoreError::InvalidGraph {
            violation: GraphViolation::Cycle,
            ..
        })
    ));
    Ok(())
}
