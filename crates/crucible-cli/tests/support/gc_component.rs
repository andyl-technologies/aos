//! Original finite resource authority for ordinary offline GC fixtures.
//!
//! The graph, mark directory and decoder share this component account. It
//! models Rust metadata and descriptors, never an installed filesystem quota.
//! Disposable kernel runs continue to use the deployed quota binder instead.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use crucible_cas::content_store::{
    ContentId, DirectoryBlobBackend, DirectoryRefBackend, ImmutableBlobBackend, ObjectKind,
    StoreError, StoreGraph, StoreGraphConfig, StoreGraphKeyring, StoreGraphNamespaceAuthorizers,
    StoreGraphObjectProfilers, StoreGraphOriginalResources, StoreGraphPhysicalQuotaBinders,
    StoreGraphS3Clients, StoreNodeId, StoreNodeSpec, StorePhysicalQuotaBinder,
    StorePhysicalQuotaBinderHandle, StorePhysicalQuotaGuard, StorePhysicalQuotaPolicyId,
};
use crucible_cas::owned_decode::ResourceLoan;
use crucible_daemon::CampaignLocalRepositoryStore;
use crucible_linux_resource::host_services::{HostServiceAllocator, HostServiceLease};

const COMPONENT_DESCRIPTORS: u64 = 256;
const COMPONENT_METADATA_BYTES: u64 = 67_108_864;
const COMPONENT_PROJECT: u32 = 1;
const PHYSICAL_BYTES: u64 = 2_147_483_648;
const PHYSICAL_INODES: u64 = 1_048_576;

/// Retains one original component account across planning and journal reopens.
///
/// Only the private synchronous CLI runner consumes constructed stores; all
/// graph, mark and decode borrowers close before this parent fixture closes.
pub(super) struct ComponentGcStore {
    guard: Arc<ComponentGuard>,
    refs: PathBuf,
    structural_bytes: u64,
    // External parent custody also covers the final raw guard control free.
    _structure: HostServiceLease,
}

impl ComponentGcStore {
    /// Admits fixture storage before constructing its retained guard and paths.
    ///
    /// # Errors
    /// Refuses invalid finite resource geometry or exhausted component capacity.
    pub(super) fn new(root: &Path, refs: &Path) -> Result<Self, StoreError> {
        let resources =
            HostServiceAllocator::new(1, COMPONENT_DESCRIPTORS, COMPONENT_METADATA_BYTES)
                .map_err(|_| StoreError::Quota)?;
        let structural_bytes = ResourceLoan::allocation_bytes::<ComponentGuard>()
            .checked_add(HostServiceLease::metadata_bytes())
            .and_then(|bytes| bytes.checked_add(root.as_os_str().len() as u64))
            .and_then(|bytes| bytes.checked_add(refs.as_os_str().len() as u64))
            .ok_or(StoreError::Quota)?;
        let structure = resources
            .reserve_resources(0, 0, structural_bytes)
            .map_err(|_| StoreError::Quota)?;

        Ok(Self {
            guard: Arc::new(ComponentGuard {
                root: root.to_owned(),
                closed: AtomicBool::new(false),
                resources,
            }),
            refs: refs.to_owned(),
            structural_bytes,
            _structure: structure,
        })
    }

    /// Builds the physical graph and its exact separately retained administration.
    ///
    /// # Errors
    /// Preserves finite guard, graph and repository admission refusals.
    pub(super) fn store(&self) -> Result<CampaignLocalRepositoryStore, ComponentStoreError> {
        self.guard.verify()?;
        // These small authored config inputs overlap graph admission. Their
        // portable purpose is separate from the graph's own retained loans.
        let _configuration = self.guard.reserve_resources(
            0,
            65_536_u64
                .checked_add(self.guard.root.as_os_str().len() as u64)
                .ok_or(StoreError::Quota)?,
        )?;
        let policy = StorePhysicalQuotaPolicyId::new("component/gc")?;
        let primary = StoreNodeId::new("primary")?;
        let directory = StoreNodeId::new("raw-primary")?;
        let binder = ComponentBinder {
            guard: self.guard.clone(),
        };
        let mut binders = StoreGraphPhysicalQuotaBinders::new();
        binders.insert(policy.clone(), StorePhysicalQuotaBinderHandle::new(binder))?;

        let (graph, admin) = StoreGraph::build_with_admin_and_all_capabilities(
            StoreGraphConfig {
                root: primary.clone(),
                gc_mark_root: None,
                admitted_kinds: BTreeSet::from([
                    ObjectKind::CampaignFact,
                    ObjectKind::CampaignSnapshot,
                    ObjectKind::MerkleNode,
                    ObjectKind::Scenario,
                    ObjectKind::Configuration,
                    ObjectKind::Policy,
                    ObjectKind::ExactManifest,
                    ObjectKind::RamExtent,
                    ObjectKind::DiskExtent,
                    ObjectKind::DeviceState,
                    ObjectKind::Observation,
                    ObjectKind::Finding,
                    ObjectKind::Projection,
                    ObjectKind::Trace,
                ]),
                nodes: BTreeMap::from([
                    (
                        primary,
                        StoreNodeSpec::PhysicalQuota {
                            child: directory.clone(),
                            policy,
                            project_id: COMPONENT_PROJECT,
                            maximum_physical_bytes: PHYSICAL_BYTES,
                            maximum_inodes: PHYSICAL_INODES,
                        },
                    ),
                    (
                        directory,
                        StoreNodeSpec::Directory {
                            root: self.guard.root.clone(),
                        },
                    ),
                ]),
            },
            &StoreGraphKeyring::new(),
            &StoreGraphNamespaceAuthorizers::new(),
            &StoreGraphObjectProfilers::new(),
            &binders,
            &StoreGraphS3Clients::new(),
            StoreGraphOriginalResources::default(),
        )?;
        let refs = Arc::new(DirectoryRefBackend::new(self.refs.clone()));
        CampaignLocalRepositoryStore::new_with_maintenance(Arc::new(graph), refs, admin)
            .map_err(ComponentStoreError::Repository)
    }

    /// Closes the fixture authority without resetting its original counters.
    pub(super) fn close(&self) {
        self.guard.closed.store(true, Ordering::Release);
    }

    /// Checks that every synchronous graph, mark and decoder borrower closed.
    pub(super) fn assert_idle(&self) {
        assert_eq!(
            Arc::strong_count(&self.guard),
            1,
            "original guard borrowers"
        );
        let remaining = COMPONENT_METADATA_BYTES - self.structural_bytes;
        let available = self
            .guard
            .resources
            .reserve_resources(0, COMPONENT_DESCRIPTORS, remaining)
            .expect("all transient credits returned to the original component account");
        drop(available);
    }
}

/// Preserves the actual component admission cause without a second heap owner.
#[derive(Debug)]
pub(super) enum ComponentStoreError {
    Store(StoreError),
    Repository(crucible_daemon::CampaignLocalServiceError),
}

impl From<StoreError> for ComponentStoreError {
    fn from(error: StoreError) -> Self {
        Self::Store(error)
    }
}

impl std::fmt::Display for ComponentStoreError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Store(error) => error.fmt(formatter),
            Self::Repository(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for ComponentStoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Store(error) => Some(error),
            Self::Repository(error) => Some(error),
        }
    }
}

struct ComponentGuard {
    root: PathBuf,
    closed: AtomicBool,
    resources: HostServiceAllocator,
}

impl StorePhysicalQuotaGuard for ComponentGuard {
    fn decoded_metadata_limit(&self) -> Result<u64, StoreError> {
        self.verify()?;
        Ok(COMPONENT_METADATA_BYTES)
    }

    fn reserve_resources(&self, descriptors: u64, bytes: u64) -> Result<ResourceLoan, StoreError> {
        self.verify()?;
        let charged = bytes
            .checked_add(HostServiceLease::metadata_bytes())
            .and_then(|bytes| {
                bytes.checked_add(ResourceLoan::allocation_bytes::<HostServiceLease>())
            })
            .ok_or(StoreError::Quota)?;
        let lease = self
            .resources
            .reserve_resources(0, descriptors, charged)
            .map_err(|source| {
                eprintln!(
                    "component GC original refusal: descriptors={descriptors}, requested_bytes={bytes}, charged_bytes={charged}, ceiling={COMPONENT_METADATA_BYTES}, source={source:?}"
                );
                StoreError::Quota
            })?;
        self.verify()?;
        Ok(ResourceLoan::new(lease))
    }

    fn verify(&self) -> Result<(), StoreError> {
        if self.closed.load(Ordering::Acquire) {
            return Err(StoreError::Quota);
        }
        self.resources.verify_live().map_err(|_| StoreError::Quota)
    }

    fn gc_mark_backend(
        self: Arc<Self>,
        scope: &str,
    ) -> Result<Arc<dyn ImmutableBlobBackend>, StoreError> {
        if scope.is_empty() || scope.len() > 256 || scope.chars().any(char::is_control) {
            return Err(StoreError::InvalidComposition {
                reason: "component GC scope is empty, unbounded or contains control characters",
            });
        }
        self.verify()?;
        let _path = self.reserve_resources(
            0,
            (self.root.as_os_str().len() as u64)
                .checked_add(128)
                .and_then(|bytes| bytes.checked_mul(4))
                .ok_or(StoreError::Quota)?,
        )?;
        let id = ContentId::for_bytes(ObjectKind::Trace, 1, scope.as_bytes());
        let directory = id.with_encoded_text(|encoded| {
            let name =
                std::str::from_utf8(encoded).map_err(|_| StoreError::InvalidComposition {
                    reason: "component GC mark identity is not canonical ASCII",
                })?;
            Ok::<_, StoreError>(
                self.root
                    .join(DirectoryBlobBackend::GC_MARK_DIRECTORY)
                    .join(name),
            )
        })?;
        let _descriptor = self.reserve_resources(1, 0)?;
        self.verify()?;
        std::fs::create_dir_all(&directory).map_err(|source| StoreError::Io {
            operation: "create component GC mark directory",
            path: directory.clone(),
            source,
        })?;
        DirectoryBlobBackend::new_with_physical_quota("component-gc-marks", directory, self)
    }
}

struct ComponentBinder {
    guard: Arc<ComponentGuard>,
}

impl StorePhysicalQuotaBinder for ComponentBinder {
    fn bind(
        &self,
        root: &Path,
        project: u32,
        bytes: u64,
        inodes: u64,
    ) -> Result<Arc<dyn StorePhysicalQuotaGuard>, StoreError> {
        if root != self.guard.root
            || (project, bytes, inodes) != (COMPONENT_PROJECT, PHYSICAL_BYTES, PHYSICAL_INODES)
        {
            return Err(StoreError::Unauthorized);
        }
        self.guard.verify()?;
        Ok(self.guard.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn component_binder_rejects_a_different_root_before_directory_effects() {
        let root = tempfile::tempdir().expect("component GC root");
        let objects = root.path().join("objects");
        let fixture = ComponentGcStore::new(&objects, &root.path().join("refs"))
            .expect("finite component original");
        let binder = ComponentBinder {
            guard: fixture.guard.clone(),
        };

        assert!(matches!(
            binder.bind(
                root.path(),
                COMPONENT_PROJECT,
                PHYSICAL_BYTES,
                PHYSICAL_INODES
            ),
            Err(StoreError::Unauthorized)
        ));
        assert!(!objects.exists());
        for (project, bytes, inodes) in [
            (COMPONENT_PROJECT + 1, PHYSICAL_BYTES, PHYSICAL_INODES),
            (COMPONENT_PROJECT, PHYSICAL_BYTES + 1, PHYSICAL_INODES),
            (COMPONENT_PROJECT, PHYSICAL_BYTES, PHYSICAL_INODES + 1),
        ] {
            assert!(matches!(
                binder.bind(&objects, project, bytes, inodes),
                Err(StoreError::Unauthorized)
            ));
            assert!(!objects.exists());
        }
        drop(binder);
        fixture.assert_idle();
    }

    #[test]
    fn component_marks_and_decoder_keep_the_same_original_guard_until_close() {
        let root = tempfile::tempdir().expect("component GC root");
        let fixture = ComponentGcStore::new(root.path(), &root.path().join("refs"))
            .expect("finite component original");
        let marks = fixture
            .guard
            .clone()
            .gc_mark_backend("same-journal")
            .expect("same-guard mark namespace");
        let resources = marks.metadata_resources().expect("mark metadata origin");
        let original = crucible_cas::owned_decode::DecodeBudget::for_store(resources.clone())
            .expect("same-guard original decode account");
        let expected: Arc<dyn StorePhysicalQuotaGuard> = fixture.guard.clone();

        assert!(Arc::ptr_eq(&resources, &expected));
        let loan = original
            .reserve_scratch_bytes(1024)
            .expect("original retained loan");
        drop(expected);
        drop(resources);
        drop(marks);
        assert!(Arc::strong_count(&fixture.guard) > 1);
        drop(original);
        assert!(Arc::strong_count(&fixture.guard) > 1);
        drop(loan);
        fixture.assert_idle();
    }

    #[test]
    fn component_marks_stay_outside_objects_and_unknown_roots_still_refuse() {
        use crucible_cas::content_store::BlobStoreAdmin;

        let directory = tempfile::tempdir().expect("component GC root");
        let objects = directory.path().join("objects");
        let fixture = ComponentGcStore::new(&objects, &directory.path().join("refs"))
            .expect("finite component original");
        let marks = fixture
            .guard
            .clone()
            .gc_mark_backend("inventory-separation")
            .expect("same-guard administrative marks");
        // The flock/state or flock/ReadDir pair needs two descriptor credits.
        // The raw inventory fixture has explicit external custody, separate
        // from its original mark backend's internally retained storage loans.
        let inventory_credit = fixture
            .guard
            .reserve_resources(2, 65_536 + 8 * objects.as_os_str().len() as u64)
            .expect("bounded component inventory purpose");
        let backend = DirectoryBlobBackend::new("primary", &objects);
        let mut fence = backend
            .acquire_inventory_fence()
            .expect("actual Directory inventory fence");
        let mut visited = 0;
        fence
            .visit_inventory(&mut |_| {
                visited += 1;
                Ok(())
            })
            .expect("marks are administration, not objects");
        assert_eq!(visited, 0);
        drop(fence);

        std::fs::create_dir(objects.join(".unexpected-root"))
            .expect("unknown root negative control");
        let mut fence = backend
            .acquire_inventory_fence()
            .expect("same actual inventory fence");
        assert!(matches!(
            fence.visit_inventory(&mut |_| Ok(())),
            Err(StoreError::InvalidComposition {
                reason: "inventory contains an unknown root directory"
            })
        ));
        drop(fence);
        drop(backend);
        drop(inventory_credit);
        drop(marks);
        fixture.assert_idle();
    }

    #[test]
    fn component_gc_reservation_geometry_uses_the_compiled_public_types() {
        use crucible_cas::content_store::BlobInventoryRecord;
        use crucible_daemon::{CampaignGcBlobInventoryBasis, CampaignGcCandidate};

        eprintln!(
            "component GC geometry: ContentId={}, CampaignGcCandidate={}, CampaignGcBlobInventoryBasis={}, BlobInventoryRecord={}, usize={}, ResourceLoan={}, HostServiceLease={}, HostServiceLeaseControl={}",
            std::mem::size_of::<ContentId>(),
            std::mem::size_of::<CampaignGcCandidate>(),
            std::mem::size_of::<CampaignGcBlobInventoryBasis>(),
            std::mem::size_of::<BlobInventoryRecord>(),
            std::mem::size_of::<usize>(),
            std::mem::size_of::<ResourceLoan>(),
            std::mem::size_of::<HostServiceLease>(),
            HostServiceLease::metadata_bytes(),
        );
        assert_eq!(COMPONENT_METADATA_BYTES, 67_108_864);
    }
}
