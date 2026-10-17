//! Same-original finite Directory authority for archive and GC integration.
//!
//! This component account covers portable metadata and descriptors, not an
//! installed filesystem quota or a native execution entitlement.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use crucible_campaign::{CampaignRamAdmission, CampaignRepository};
use crucible_cas::content_store::{
    DirectoryBlobBackend, DirectoryRefBackend, ImmutableBlobBackend, MutableRefBackend, ObjectKind,
    RefStoreAdmin, StoreError, StoreGraph, StoreGraphAdmin, StoreGraphConfig, StoreGraphKeyring,
    StoreGraphNamespaceAuthorizers, StoreGraphObjectProfilers, StoreGraphOriginalResources,
    StoreGraphPhysicalQuotaBinders, StoreGraphS3Clients, StoreNodeId, StoreNodeSpec,
    StorePhysicalQuotaBinder, StorePhysicalQuotaBinderHandle, StorePhysicalQuotaGuard,
    StorePhysicalQuotaPolicyId,
};
use crucible_cas::owned_decode::{DecodeBudget, ResourceLoan};
use crucible_linux_resource::host_services::{HostServiceAllocator, HostServiceLease};

const DESCRIPTORS: u64 = 256;
const METADATA_BYTES: u64 = 64 * 1024 * 1024;
const PROJECT: u32 = 1;
const PHYSICAL_BYTES: u64 = 2_147_483_648;
const INODES: u64 = 1_048_576;

/// Holds the original account after all graph, ref and decoder borrowers close.
pub(super) struct OriginalNamespace {
    guard: Arc<NamespaceGuard>,
    structural_bytes: u64,
    _structure: HostServiceLease,
}

impl OriginalNamespace {
    pub(super) fn new(root: &Path) -> Self {
        let resources = HostServiceAllocator::new(1, DESCRIPTORS, METADATA_BYTES)
            .expect("original finite namespace");
        let structural_bytes = ResourceLoan::allocation_bytes::<NamespaceGuard>()
            + HostServiceLease::metadata_bytes()
            + root.as_os_str().len() as u64;
        let structure = resources
            .reserve_resources(0, 0, structural_bytes)
            .expect("guard and path before construction");

        Self {
            guard: Arc::new(NamespaceGuard {
                root: root.to_owned(),
                resources,
                closed: AtomicBool::new(false),
            }),
            structural_bytes,
            _structure: structure,
        }
    }

    pub(super) fn open(&self, refs_root: &Path) -> RepositoryNamespace {
        self.open_with_original(refs_root, None)
    }

    pub(super) fn reopen(&self, refs_root: &Path, original: &DecodeBudget) -> RepositoryNamespace {
        self.open_with_original(refs_root, Some(original.clone()))
    }

    fn open_with_original(
        &self,
        refs_root: &Path,
        saved: Option<DecodeBudget>,
    ) -> RepositoryNamespace {
        let configuration = self
            .guard
            .reserve_resources(0, 65_536 + 4 * self.guard.root.as_os_str().len() as u64)
            .expect("finite graph configuration before allocation");
        let policy =
            StorePhysicalQuotaPolicyId::new("catalog-gc-component").expect("quota policy identity");
        let primary = StoreNodeId::new("primary").expect("primary identity");
        let directory = StoreNodeId::new("directory").expect("directory identity");
        let mut binders = StoreGraphPhysicalQuotaBinders::new();
        binders
            .insert(
                policy.clone(),
                StorePhysicalQuotaBinderHandle::new(NamespaceBinder(self.guard.clone())),
            )
            .expect("same original binder");
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
                    ObjectKind::RamTree,
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
                            project_id: PROJECT,
                            maximum_physical_bytes: PHYSICAL_BYTES,
                            maximum_inodes: INODES,
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
        )
        .expect("real guarded Directory graph and maintenance");
        let graph = Arc::new(graph);
        let (refs, refs_admin) =
            DirectoryRefBackend::new_with_physical_quota_and_admin(refs_root, self.guard.clone())
                .expect("same original guarded ref namespace");
        let original = saved.unwrap_or_else(|| {
            DecodeBudget::for_store(self.guard.clone()).expect("same original namespace decoding")
        });
        let repository = CampaignRepository::new(
            graph.clone(),
            refs.clone(),
            CampaignRamAdmission::Available(original.clone()),
        );

        RepositoryNamespace {
            repository,
            graph,
            admin,
            refs,
            refs_admin,
            original,
            _configuration: configuration,
        }
    }

    pub(super) fn assert_idle(&self) {
        assert_eq!(
            Arc::strong_count(&self.guard),
            1,
            "all namespace borrowers closed"
        );
        let available = self
            .guard
            .resources
            .reserve_resources(0, DESCRIPTORS, METADATA_BYTES - self.structural_bytes)
            .expect("all transient credits returned to the same original");
        drop(available);
    }
}

pub(super) struct RepositoryNamespace {
    pub(super) repository: CampaignRepository,
    pub(super) graph: Arc<StoreGraph>,
    pub(super) admin: StoreGraphAdmin,
    pub(super) refs: Arc<dyn MutableRefBackend>,
    pub(super) refs_admin: Arc<dyn RefStoreAdmin>,
    pub(super) original: DecodeBudget,
    // External construction custody outlives every graph and ref alias here.
    _configuration: ResourceLoan,
}

struct NamespaceGuard {
    root: PathBuf,
    resources: HostServiceAllocator,
    closed: AtomicBool,
}

impl StorePhysicalQuotaGuard for NamespaceGuard {
    fn decoded_metadata_limit(&self) -> Result<u64, StoreError> {
        self.verify()?;
        Ok(METADATA_BYTES)
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
            .map_err(|_| StoreError::Quota)?;
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
                reason: "invalid component GC mark scope",
            });
        }
        let _path = self.reserve_resources(0, 4 * (self.root.as_os_str().len() as u64 + 128))?;
        let directory = self
            .root
            .join(DirectoryBlobBackend::GC_MARK_DIRECTORY)
            .join(blake3::hash(scope.as_bytes()).to_hex().as_str());
        let _descriptor = self.reserve_resources(1, 0)?;
        self.verify()?;
        std::fs::create_dir_all(&directory).map_err(|source| StoreError::Io {
            operation: "create catalog integration mark directory",
            path: directory.clone(),
            source,
        })?;
        DirectoryBlobBackend::new_with_physical_quota("catalog-gc-marks", directory, self)
    }
}

struct NamespaceBinder(Arc<NamespaceGuard>);

impl StorePhysicalQuotaBinder for NamespaceBinder {
    fn bind(
        &self,
        root: &Path,
        project: u32,
        bytes: u64,
        inodes: u64,
    ) -> Result<Arc<dyn StorePhysicalQuotaGuard>, StoreError> {
        if root != self.0.root || (project, bytes, inodes) != (PROJECT, PHYSICAL_BYTES, INODES) {
            return Err(StoreError::Unauthorized);
        }
        self.0.verify()?;
        Ok(self.0.clone())
    }
}
