//! Original and physical refusal through the actual Graph-to-Packed inventory.
//!
//! Real body, EOF and final-visitor cuts retain first causes and close paid
//! buffers and descriptors before accepting the complete canonical walk.

use super::*;
use crate::content_store::test_resources::FixtureResourceBudget;
use crate::content_store::{BlobHandle, ObjectKind, PackedBlobBackend, StorePhysicalQuotaGuard};
use crate::owned_decode::{DecodeBudget, ResourceLoan};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

struct Account(Arc<FixtureResourceBudget>);

impl StorePhysicalQuotaGuard for Account {
    fn verify(&self) -> Result<(), StoreError> {
        Ok(())
    }

    fn decoded_metadata_limit(&self) -> Result<u64, StoreError> {
        Ok(4 << 20)
    }

    fn reserve_resources(&self, descriptors: u64, bytes: u64) -> Result<ResourceLoan, StoreError> {
        self.0.reserve(descriptors, bytes)
    }
}

struct Physical {
    account: Arc<FixtureResourceBudget>,
    closed: AtomicBool,
    refusal_fds: AtomicU64,
}

impl StorePhysicalQuotaGuard for Physical {
    fn verify(&self) -> Result<(), StoreError> {
        if self.closed.load(Ordering::SeqCst) {
            self.refusal_fds
                .store(self.account.usage()?.0, Ordering::SeqCst);
            Err(StoreError::Unauthorized)
        } else {
            Ok(())
        }
    }

    fn decoded_metadata_limit(&self) -> Result<u64, StoreError> {
        Ok(4 << 20)
    }

    fn reserve_resources(&self, descriptors: u64, bytes: u64) -> Result<ResourceLoan, StoreError> {
        self.account.reserve(descriptors, bytes)
    }
}

#[test]
fn original_physical_guard_refuses_body_after_successful_cached_lookup() {
    let directory = tempfile::tempdir().unwrap();
    let backend = PackedBlobBackend::open("physical-cut", directory.path(), 64 << 10).unwrap();
    let bytes = b"authenticated source; intentionally not a canonical envelope";
    let id = crate::content_store::ContentId::for_bytes(ObjectKind::RamExtent, 1, bytes);
    backend
        .put_if_absent(id, &BlobHandle::from_bytes(bytes.to_vec()))
        .unwrap();
    let bank = Arc::new(FixtureResourceBudget::new(8, 4 << 20));
    let original = DecodeBudget::for_store(Arc::new(Account(bank.clone()))).unwrap();
    let physical = Physical {
        account: bank.clone(),
        closed: AtomicBool::new(false),
        refusal_fds: AtomicU64::new(u64::MAX),
    };
    let check = PhysicalReadCheck {
        guard: &physical,
        checked_backend: &backend,
        previous: None,
    };
    let baseline = bank.usage().unwrap();

    let error = {
        let view = crate::content_store::PackedReadView::begin(&backend, &original, &mut || Ok(()))
            .unwrap();
        let mut reader = view.reader(&backend, &original, &mut || Ok(())).unwrap();
        let mut boundary = || Ok(());
        let mut work = Work::new(
            super::super::RamStoreLimits::default(),
            &original,
            &mut boundary,
        )
        .unwrap();
        let mut source =
            |caller: &DecodeBudget,
             requested,
             boundary: &mut dyn FnMut() -> Result<(), StoreError>| {
                let handle = reader.lookup(&backend, caller, requested, boundary)?;
                physical.closed.store(true, Ordering::SeqCst);
                Ok(handle)
            };
        let mut verify = |caller: &DecodeBudget| verify_physical(caller, Some(&check));
        super::super::codec::read_envelope_using(id, &mut work, false, &mut source, &mut verify)
            .err()
            .unwrap()
    };
    // Without the body check, the actual invalid canonical bytes would be
    // decoded instead. The retained physical refusal precedes those bytes.
    assert!(
        matches!(error, RamStoreError::Store(StoreError::Unauthorized)),
        "{error:?}"
    );
    assert_eq!(bank.usage().unwrap(), baseline);
}

// This observation wrapper returns the underlying authenticated bytes unchanged.
// The existing outer handle must reject expiry before accepting that final EOF.
struct ExpireAtEof {
    source: BlobHandle,
    supervisor: crucible_linux_resource::host_supervision::HostOperationSupervisor,
    observed: Arc<AtomicBool>,
}

impl crate::content_store::BlobSource for ExpireAtEof {
    fn checked_read_access(&self) -> crate::content_store::CheckedReadAccess {
        crate::content_store::CheckedReadAccess::Whole
    }

    fn logical_length(&self) -> u64 {
        self.source.logical_length()
    }

    fn open(&self) -> Result<Box<dyn std::io::Read + Send>, StoreError> {
        self.source.open()
    }

    fn read_all_with_boundary(
        &self,
        caller: &DecodeBudget,
        maximum: u64,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<crate::content_store::OwnedBlobBytes, StoreError> {
        let bytes = self
            .source
            .read_all_with_boundary(caller, maximum, boundary)?;
        self.supervisor
            .amend_outer_cap(0, Some(std::time::Duration::from_nanos(1)))
            .map_err(|source| StoreError::Supervision {
                source: Box::new(source),
            })?;
        self.observed.store(true, Ordering::SeqCst);
        Ok(bytes)
    }
}

#[test]
fn original_expiry_at_authenticated_eof_refuses_bytes_and_keeps_committed_root() {
    use crucible_linux_resource::host_supervision::{
        HOST_OPERATION_CLASS_COUNT, HostOperationBudget, HostOperationBudgets, HostOperationClass,
        HostOperationSupervisor, HostSupervisionError,
    };
    use std::time::Duration;

    let directory = tempfile::tempdir().unwrap();
    let backend = PackedBlobBackend::open("eof-cut", directory.path(), 64 << 10).unwrap();
    let envelope = crate::content_envelope::ContentEnvelope::new(
        super::super::codec::TREE_SCHEMA,
        1,
        std::collections::BTreeSet::new(),
        vec![0; 45],
    )
    .unwrap();
    let bytes = envelope.canonical_bytes();
    let id = crate::content_store::ContentId::for_bytes(ObjectKind::RamTree, 1, &bytes);
    backend
        .put_if_absent(id, &BlobHandle::from_bytes(bytes))
        .unwrap();
    let committed = std::fs::read(directory.path().join(".packed-admin/index-v1")).unwrap();
    let bank = Arc::new(FixtureResourceBudget::new(8, 4 << 20));
    let original = DecodeBudget::for_store(Arc::new(Account(bank.clone()))).unwrap();
    let baseline = bank.usage().unwrap();
    let supervisor = HostOperationSupervisor::new(
        HostOperationBudgets {
            classes: [HostOperationBudget::finite(Duration::from_secs(300));
                HOST_OPERATION_CLASS_COUNT],
        },
        Some(Duration::from_secs(300)),
    )
    .unwrap();
    let operation = supervisor.begin(HostOperationClass::Transfer).unwrap();
    let operation_id = operation.status().unwrap().operation_id;
    let eof = Arc::new(AtomicBool::new(false));

    {
        let source_credit = original
            .reserve_scratch_bytes(BlobHandle::source_allocation_bytes::<ExpireAtEof>())
            .unwrap();
        let view = crate::content_store::PackedReadView::begin(&backend, &original, &mut || Ok(()))
            .unwrap();
        let mut reader = view.reader(&backend, &original, &mut || Ok(())).unwrap();
        let mut boundary = || {
            operation.wait_slice().map(|_| ()).map_err(|source| {
                RamStoreError::Store(StoreError::Supervision {
                    source: Box::new(source),
                })
            })
        };
        let mut work = Work::new(
            super::super::RamStoreLimits::default(),
            &original,
            &mut boundary,
        )
        .unwrap();
        let error = {
            let mut source =
                |caller: &DecodeBudget,
                 requested,
                 boundary: &mut dyn FnMut() -> Result<(), StoreError>| {
                    let handle = reader.lookup(&backend, caller, requested, boundary)?;
                    let observed = ExpireAtEof {
                        source: handle.clone(),
                        supervisor: supervisor.clone(),
                        observed: eof.clone(),
                    };
                    Ok(handle.with_observed_source(observed))
                };
            super::super::codec::read_envelope_using(id, &mut work, true, &mut source, &mut |_| {
                Ok(())
            })
            .err()
            .unwrap()
        };
        assert!(
            eof.load(Ordering::SeqCst),
            "the real source reached authenticated EOF"
        );
        let RamStoreError::Store(StoreError::RamReadBoundary { source: cause }) = &error else {
            panic!("{error:?}")
        };
        assert!(
            matches!(cause.first_boundary(), Some(RamStoreError::Store(StoreError::Supervision { source }))
            if matches!(source.downcast_ref::<HostSupervisionError>(), Some(HostSupervisionError::DeadlineExpired { operation_id: actual, class: HostOperationClass::Transfer }) if *actual == operation_id)),
            "{error:?}"
        );
        // Preserve the existing partial accounting at a failed checked read;
        // no decoded owner or inventory candidate was accepted.
        assert_eq!(work.visits, 1);
        assert_eq!(work.io_bytes, envelope.canonical_bytes().len() as u64);
        drop(error);
        drop(work);
        drop(reader);
        drop(view);
        drop(source_credit);
    }
    assert_eq!(
        std::fs::read(directory.path().join(".packed-admin/index-v1")).unwrap(),
        committed
    );
    assert_eq!(bank.usage().unwrap(), baseline);
}

struct Binder(Arc<Physical>);

impl crate::content_store::StorePhysicalQuotaBinder for Binder {
    fn bind(
        &self,
        _root: &std::path::Path,
        _project: u32,
        _bytes: u64,
        _inodes: u64,
    ) -> Result<Arc<dyn StorePhysicalQuotaGuard>, StoreError> {
        Ok(self.0.clone())
    }
}

fn graph_at(
    root: &std::path::Path,
    physical: Arc<Physical>,
    admitted: std::collections::BTreeSet<ObjectKind>,
) -> crate::content_store::StoreGraph {
    use crate::content_store::{
        StoreGraph, StoreGraphConfig, StoreGraphKeyring, StoreGraphNamespaceAuthorizers,
        StoreGraphObjectProfilers, StoreGraphPhysicalQuotaBinders, StoreGraphS3Clients,
        StoreNodeId, StoreNodeSpec, StorePhysicalQuotaBinderHandle, StorePhysicalQuotaPolicyId,
    };
    let parent = StoreNodeId::new("physical").unwrap();
    let child = StoreNodeId::new("packed").unwrap();
    let policy = StorePhysicalQuotaPolicyId::new("model/read-view").unwrap();
    let mut binders = StoreGraphPhysicalQuotaBinders::new();
    binders
        .insert(
            policy.clone(),
            StorePhysicalQuotaBinderHandle::new(Binder(physical)),
        )
        .unwrap();
    StoreGraph::build_with_admin_and_all_capabilities(
        StoreGraphConfig {
            gc_mark_root: None,
            root: parent.clone(),
            admitted_kinds: admitted,
            nodes: std::collections::BTreeMap::from([
                (
                    parent,
                    StoreNodeSpec::PhysicalQuota {
                        child: child.clone(),
                        policy,
                        project_id: 47,
                        maximum_physical_bytes: 4 << 30,
                        maximum_inodes: 1 << 20,
                    },
                ),
                (
                    child,
                    StoreNodeSpec::Packed {
                        root: root.join("objects"),
                        target_pack_bytes: 64 << 10,
                    },
                ),
            ]),
        },
        &StoreGraphKeyring::new(),
        &StoreGraphNamespaceAuthorizers::new(),
        &StoreGraphObjectProfilers::new(),
        &binders,
        &StoreGraphS3Clients::new(),
        None,
    )
    .unwrap()
    .0
}

struct Retention;
struct Lease(crate::content_store::ContentId);

impl super::super::RamRootLease for Lease {
    fn root(&self) -> crate::content_store::ContentId {
        self.0
    }
}

impl super::super::RamRetention for Retention {
    fn retain_object(&self, _id: crate::content_store::ContentId) -> Result<(), RamStoreError> {
        Ok(())
    }

    fn retain_root(
        &self,
        id: crate::content_store::ContentId,
    ) -> Result<Arc<dyn super::super::RamRootLease>, RamStoreError> {
        Ok(Arc::new(Lease(id)))
    }
}

struct GraphFixture {
    directory: tempfile::TempDir,
    bank: Arc<FixtureResourceBudget>,
    physical: Arc<Physical>,
    original: DecodeBudget,
    store: super::super::RamStore,
    root: super::super::LeasedRamRoot,
    refs: Arc<dyn crate::content_store::RefStoreAdmin>,
}

impl GraphFixture {
    fn new() -> Self {
        use crate::content_store::{DirectoryRefBackend, DurabilityRequirement};
        use crucible_ram::{Limits, RegionClass, RegionDescriptor, Scope, Topology};
        let directory = tempfile::tempdir().unwrap();
        let bank = Arc::new(FixtureResourceBudget::new(128, 256 << 20));
        let physical = Arc::new(Physical {
            account: bank.clone(),
            closed: AtomicBool::new(false),
            refusal_fds: AtomicU64::new(u64::MAX),
        });
        let original = DecodeBudget::for_store(Arc::new(Account(bank.clone()))).unwrap();
        let graph = graph_at(
            directory.path(),
            physical.clone(),
            std::collections::BTreeSet::from([
                ObjectKind::ExactManifest,
                ObjectKind::RamTree,
                ObjectKind::RamExtent,
            ]),
        );
        let store = super::super::RamStore::new(
            Arc::new(graph),
            DurabilityRequirement::new(1, false).unwrap(),
            super::super::RamStoreLimits::default(),
        )
        .unwrap();
        let topology = Topology::new(
            vec![RegionDescriptor::new("main", RegionClass::MutableMain, 4096).unwrap()],
            Limits::default(),
        )
        .unwrap();
        let root = store
            .capture(
                topology,
                Scope::Exact,
                &mut |_, _, bytes| {
                    bytes.fill(7);
                    Ok(())
                },
                &Retention,
                &original.child().unwrap(),
                &mut || Ok(()),
            )
            .unwrap();
        let (_, refs) = DirectoryRefBackend::new_with_physical_quota_and_admin(
            directory.path().join("refs"),
            physical.clone(),
        )
        .unwrap();
        Self {
            directory,
            bank,
            physical,
            original,
            store,
            root,
            refs,
        }
    }

    fn index_bytes(&self) -> Vec<u8> {
        std::fs::read(self.directory.path().join("objects/.packed-admin/index-v1")).unwrap()
    }
}

#[test]
fn actual_graph_final_root_visitor_closes_physical_before_inventory_acceptance() {
    let fixture = GraphFixture::new();
    let fence = fixture.refs.acquire_ref_inventory_fence().unwrap();
    let baseline = fixture.bank.usage().unwrap();
    let committed = fixture.index_bytes();
    let root = fixture.root.object_id();
    let mut positions = [None; 3];
    let mut visited = 0;
    let error = fixture
        .store
        .visit_inventory_graph(
            root,
            fence.as_ref(),
            &fixture.original,
            &mut || Ok(()),
            &mut |id| {
                positions[visited] = Some(id);
                visited += 1;
                if id == root {
                    fixture.physical.closed.store(true, Ordering::SeqCst);
                }
                Ok(())
            },
        )
        .unwrap_err();
    let RamStoreError::Store(stored) = &error else {
        panic!("{error:?}")
    };
    assert!(
        matches!(stored.original_failure(), StoreError::Unauthorized),
        "{error:?}"
    );
    assert_eq!(positions[2], Some(root));
    assert_eq!(visited, 3);
    assert_eq!(
        fixture.physical.refusal_fds.load(Ordering::SeqCst),
        baseline.0,
        "actual view descriptors physically closed before the final refusal"
    );
    drop(error);
    assert_eq!(fixture.index_bytes(), committed);
    assert_eq!(fixture.bank.usage().unwrap().0, baseline.0);
}

#[test]
fn actual_graph_final_root_visitor_expires_same_original_before_inventory_acceptance() {
    use crucible_linux_resource::host_supervision::{
        HOST_OPERATION_CLASS_COUNT, HostOperationBudget, HostOperationBudgets, HostOperationClass,
        HostOperationSupervisor, HostSupervisionError,
    };
    use std::time::Duration;
    let fixture = GraphFixture::new();
    let fence = fixture.refs.acquire_ref_inventory_fence().unwrap();
    let committed = fixture.index_bytes();
    let baseline = fixture.bank.usage().unwrap();
    let supervisor = HostOperationSupervisor::new(
        HostOperationBudgets {
            classes: [HostOperationBudget::finite(Duration::from_secs(300));
                HOST_OPERATION_CLASS_COUNT],
        },
        Some(Duration::from_secs(300)),
    )
    .unwrap();
    let operation = supervisor.begin(HostOperationClass::Transfer).unwrap();
    let expected = operation.status().unwrap().operation_id;
    let root = fixture.root.object_id();
    let mut visited = 0;
    let error = fixture
        .store
        .visit_inventory_graph(
            root,
            fence.as_ref(),
            &fixture.original,
            &mut || {
                operation.wait_slice().map(|_| ()).map_err(|source| {
                    RamStoreError::Store(StoreError::Supervision {
                        source: Box::new(source),
                    })
                })
            },
            &mut |id| {
                visited += 1;
                if id == root {
                    supervisor
                        .amend_outer_cap(0, Some(Duration::from_nanos(1)))
                        .unwrap();
                }
                Ok(())
            },
        )
        .unwrap_err();
    let RamStoreError::Store(stored) = &error else {
        panic!("{error:?}")
    };
    assert!(
        matches!(stored.original_failure(), StoreError::Supervision { source }
        if matches!(source.downcast_ref::<HostSupervisionError>(), Some(HostSupervisionError::DeadlineExpired { operation_id, class: HostOperationClass::Transfer }) if *operation_id == expected)),
        "{error:?}"
    );
    assert_eq!(visited, 3);
    assert_eq!(fixture.index_bytes(), committed);
    assert_eq!(fixture.bank.usage().unwrap().0, baseline.0);
}

#[test]
fn actual_graph_forbidden_page_kind_refuses_selected_child_without_mutating_root() {
    let mut fixture = GraphFixture::new();
    let root = fixture.root.object_id();
    let committed = fixture.index_bytes();
    // Reopen the actual persisted graph with a narrower admitted-kind contract.
    // The canonical root/tree remain valid; the selected page is forbidden.
    drop(fixture.store);
    let graph = graph_at(
        fixture.directory.path(),
        fixture.physical.clone(),
        std::collections::BTreeSet::from([ObjectKind::ExactManifest, ObjectKind::RamTree]),
    );
    fixture.store = super::super::RamStore::new(
        Arc::new(graph),
        crate::content_store::DurabilityRequirement::new(1, false).unwrap(),
        super::super::RamStoreLimits::default(),
    )
    .unwrap();
    let fence = fixture.refs.acquire_ref_inventory_fence().unwrap();
    let baseline = fixture.bank.usage().unwrap();
    let mut visited = 0;
    let error = fixture
        .store
        .visit_inventory_graph(
            root,
            fence.as_ref(),
            &fixture.original,
            &mut || Ok(()),
            &mut |_| {
                visited += 1;
                Ok(())
            },
        )
        .unwrap_err();
    let RamStoreError::Store(stored) = &error else {
        panic!("{error:?}")
    };
    assert!(
        matches!(
            stored.original_failure(),
            StoreError::InvalidGraph {
                violation: crate::content_store::GraphViolation::RouteCoverage,
                ..
            }
        ),
        "{error:?}"
    );
    assert_eq!(visited, 0);
    assert_eq!(fixture.index_bytes(), committed);
    assert_eq!(fixture.bank.usage().unwrap().0, baseline.0);
}

#[test]
fn actual_graph_keeps_one_bounded_pack_view_through_canonical_inventory() {
    let fixture = GraphFixture::new();
    let fence = fixture.refs.acquire_ref_inventory_fence().unwrap();
    let baseline = fixture.bank.usage().unwrap();
    let committed = fixture.index_bytes();
    let mut positions = [None; 3];
    let mut visited = 0;

    fixture
        .store
        .visit_inventory_graph(
            fixture.root.object_id(),
            fence.as_ref(),
            &fixture.original,
            &mut || Ok(()),
            &mut |id| {
                positions[visited] = Some(id);
                visited += 1;
                // This actual three-object root is inline, so the view holds two
                // exclusion locks and one cached pack FD, with no arena FD.
                assert_eq!(fixture.bank.usage().unwrap().0, baseline.0 + 3);
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(visited, 3);
    assert_eq!(positions[2], Some(fixture.root.object_id()));
    assert_eq!(fixture.bank.usage().unwrap(), baseline);
    assert_eq!(fixture.index_bytes(), committed);
}
