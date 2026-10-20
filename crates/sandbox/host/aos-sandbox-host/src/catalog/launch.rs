//! Resolves a launch catalog under the original authenticated Host loan.
//!
//! The native recipes are shared with ordinary catalog resolution. This owner
//! keeps partial acquisition and all independent posts together; catalog bytes,
//! handles and native observations alone never admit a launch or an export.

use std::error::Error;
use std::mem::size_of;
use std::os::fd::OwnedFd;
use std::path::Path;

use aos_sandbox_guest_protocol::guest_root_publication::GuestRootPublicationProofV1;
use aos_sandbox_model::{ObjectDigest, ResourceDimension as D, ResourceVector};
use aos_sandbox_linux::path::BeneathRegularFileReadOriginalV2;
use aos_sandbox_linux::pidfd::NamespaceFd;
use aos_sandbox_protocol::host_catalog_snapshot::HostCatalogSnapshotError;
use aos_sandbox_protocol::{ValidatedAssignmentFence, ValidatedRuntimePlan};

use super::pins::{CatalogPinOriginalV2, cause, closed, positive};
use super::{
    AttachmentAnchorCatalogEntry, CatalogIdentityAllocation, FileHostCatalog, HostCatalogSnapshot,
    MAXIMUM_HOST_CATALOG_BYTES, NetworkCatalogEntry, WorkspaceCatalogEntry,
};
use crate::live_agent::HostGuestPackageBindingCredentialOriginalV2;
use crate::plan::{
    CatalogPinConstructionFailureV2, HostLaunchCatalogReceivingV2, ResolvedAttachmentAnchor,
    ResolvedIdentityAllocation, ResolvedLaunchResources, ResolvedNetwork, ResolvedWorkspace,
};
use crate::{HostError, Result};

/// Retains one real catalog resolution and its original failed native prefixes.
///
/// Construction is inert. Every native entry and buffer/model growth requires
/// the same private-construction authenticated Launch borrower. Successful
/// resolution supplies resource custody; separate authenticated Storage export
/// and the existing Host launch admission remain mandatory.
pub struct HostLaunchCatalogOriginalV2 {
    fixed_geometry: Option<Result<ResourceVector>>,
    fixed_funding: Option<Result<()>>,
    export: crate::storage_root_export::HostRootMountExportOriginalV2,
    root_before: NamedCatalogRootOriginalV2,
    root_after: NamedCatalogRootOriginalV2,
    file: BeneathRegularFileReadOriginalV2,
    capture: Option<aos_sandbox_linux::Result<()>>,
    extent: Option<Result<usize>>,
    model_geometry: Option<Result<ResourceVector>>,
    model_funding: Option<Result<()>>,
    read: Option<aos_sandbox_linux::Result<()>>,
    snapshot: Option<std::result::Result<HostCatalogSnapshot, HostCatalogSnapshotError>>,
    package: HostGuestPackageBindingCredentialOriginalV2,
    package_capture: Option<Result<()>>,
    package_binding: Option<Result<ObjectDigest>>,
    pins: [CatalogPinOriginalV2; 3],
    construction: ConstructedCatalogOriginalV2,
    handles: Option<([u8; 32], [u8; 32], [u8; 32])>,
    returned: Option<Result<ResolvedLaunchResources>>,
    file_post: Option<aos_sandbox_linux::Result<()>>,
    package_post: Option<Result<()>>,
    pin_posts: [CatalogPinOriginalV2; 3],
    posts: Option<Result<()>>,
    final_current: Option<Result<()>>,
    entered: bool,
    first_primary: Option<PrimaryFailureV2>,
    closed: Option<HostError>,
}

impl HostLaunchCatalogOriginalV2 {
    /// Creates empty destinations without allocating catalog bytes or doing IO.
    #[must_use]
    pub fn new() -> Self {
        Self {
            fixed_geometry: None,
            fixed_funding: None,
            export: crate::storage_root_export::HostRootMountExportOriginalV2::new(),
            root_before: NamedCatalogRootOriginalV2::default(),
            root_after: NamedCatalogRootOriginalV2::default(),
            file: BeneathRegularFileReadOriginalV2::new(),
            capture: None,
            extent: None,
            model_geometry: None,
            model_funding: None,
            read: None,
            snapshot: None,
            package: HostGuestPackageBindingCredentialOriginalV2::new(),
            package_capture: None,
            package_binding: None,
            pins: std::array::from_fn(|_| CatalogPinOriginalV2::new()),
            construction: ConstructedCatalogOriginalV2::default(),
            handles: None,
            returned: None,
            file_post: None,
            package_post: None,
            pin_posts: std::array::from_fn(|_| CatalogPinOriginalV2::new()),
            posts: None,
            final_current: None,
            entered: false,
            first_primary: None,
            closed: None,
        }
    }

    pub(super) fn resolve_once(
        &mut self,
        catalog: &FileHostCatalog,
        fence: &ValidatedAssignmentFence,
        plan: &ValidatedRuntimePlan,
        receiving: &mut HostLaunchCatalogReceivingV2<'_, '_>,
    ) -> Result<ResolvedLaunchResources> {
        if self.entered {
            if self.failure().is_none() {
                self.closed = Some(closed());
            }
            return Err(closed());
        }
        self.entered = true;
        self.handles = Some((
            *plan.workspace_handle(),
            *plan.network_handle(),
            *plan.attachment_anchor_handle(),
        ));
        self.returned = Some(catalog.resolve_catalog_recipe_v2(
            fence,
            plan,
            &mut CatalogResolutionDispositionV2::Launch {
                receiving,
                original: self,
            },
        ));
        self.first_primary = self.select_primary_failure();
        self.finish_posts(catalog);
        self.final_current = Some(receiving.require_current_v2());
        if self.closed.is_some()
            || !matches!(self.returned, Some(Ok(_)))
            || !matches!(self.posts, Some(Ok(())))
            || !matches!(self.final_current, Some(Ok(())))
        {
            return Err(closed());
        }
        match self.returned.take() {
            Some(Ok(resources)) => Ok(resources),
            _ => std::process::abort(),
        }
    }

    pub(super) fn export_root_mount_once_v2(
        &mut self,
        root: &aos_sandbox_linux::cgroup::CgroupV2Root,
        workspace: &ResolvedWorkspace,
        receiving: &mut HostLaunchCatalogReceivingV2<'_, '_>,
    ) -> Result<aos_sandbox_linux::mount::DetachedMount> {
        if self.failure().is_some() || !self.entered || !matches!(self.posts, Some(Ok(())))
            || !matches!(self.final_current, Some(Ok(()))) || self.returned.is_some() {
            return Err(closed());
        }
        self.export.export_launch_once(root, workspace, receiving)
    }

    /// Bounds temporary descriptors after the complete catalog/export handoff.
    ///
    /// # Errors
    /// Refuses incomplete or failed resolution, export, or independent posts.
    pub(crate) fn completed_temporary_files_v2(&self) -> Result<u64> {
        if !self.entered || self.failure().is_some() || self.returned.is_some()
            || !matches!(self.posts, Some(Ok(())))
            || !matches!(self.final_current, Some(Ok(())))
        {
            return Err(closed());
        }
        let catalog = positive(&self.fixed_geometry)?.get(D::OpenFiles)
            .checked_sub(3).ok_or(HostError::ResourceExhausted)?;
        // Workspace, network and attachment pins moved into PreparedLaunch.
        // Their three live descriptors remain charged after this owner drops.
        catalog.checked_add(self.export.completed_temporary_files_v2()?)
            .ok_or(HostError::ResourceExhausted)
    }

    fn fixed_demand() -> Result<ResourceVector> {
        let (file_bytes, file_fds) =
            BeneathRegularFileReadOriginalV2::fixed_receiving_demand_v2(super::CATALOG_FILE.len())
                .ok_or(HostError::ResourceExhausted)?;
        // Three named primary pins and three independent posts coexist. Network
        // owns its catalog pin and fixed current-namespace comparison each time.
        let pin_bytes = size_of::<CatalogPinOriginalV2>()
            .checked_mul(12)
            .and_then(|bytes| bytes.checked_add(6 * 8 * 4097))
            .and_then(|bytes| bytes.checked_add(16 * 1024))
            .ok_or(HostError::ResourceExhausted)?;
        let bytes = file_bytes
            .checked_add(pin_bytes)
            .and_then(|bytes| bytes.checked_add(4 * size_of::<NamedCatalogRootOriginalV2>()))
            .ok_or(HostError::ResourceExhausted)?;
        ResourceVector::ZERO
            .with(
                D::MemoryBytes,
                u64::try_from(bytes).map_err(|_| HostError::ResourceExhausted)?,
            )
            .with(
                D::OpenFiles,
                u64::try_from(file_fds + 10).map_err(|_| HostError::ResourceExhausted)?,
            )
            .with(D::MetadataEntries, 4)
            .checked_add(
                HostGuestPackageBindingCredentialOriginalV2::receiving_demand_v2()
                    .ok_or(HostError::ResourceExhausted)?,
            )
            .map_err(|_| HostError::ResourceExhausted)
    }

    fn model_demand(bytes: usize) -> Result<ResourceVector> {
        // A malformed JSON prefix can grow vectors before semantic validation.
        // Price their largest concrete row, growth overlap, nested strings and
        // arrays, canonical re-encoding, and the held read buffer from byte size.
        // This is a conservative receiving bound, not measured heap residency.
        let memory = aos_sandbox_protocol::host_catalog_snapshot::
            host_catalog_canonical_decode_receiving_bytes_v2(bytes)
            .ok_or(HostError::ResourceExhausted)?;
        let rows = bytes.checked_mul(4).ok_or(HostError::ResourceExhausted)?;
        Ok(ResourceVector::ZERO
            .with(
                D::MemoryBytes,
                u64::try_from(memory).map_err(|_| HostError::ResourceExhausted)?,
            )
            .with(
                D::MetadataEntries,
                u64::try_from(rows).map_err(|_| HostError::ResourceExhausted)?,
            ))
    }

    fn read_snapshot(
        &mut self,
        catalog: &FileHostCatalog,
        receiving: &mut HostLaunchCatalogReceivingV2<'_, '_>,
    ) -> Result<HostCatalogSnapshot> {
        self.fixed_geometry = Some(Self::fixed_demand());
        self.fixed_funding =
            Some(receiving.admit_additional_demand_v2(*positive(&self.fixed_geometry)?));
        positive(&self.fixed_funding)?;
        self.root_before.observe_once(&catalog.root)?;
        self.capture = Some(
            self.file
                .capture_once_v2(&catalog.root, Path::new(super::CATALOG_FILE)),
        );
        positive(&self.capture)?;
        self.extent = Some(
            self.file
                .captured_bytes_v2()
                .filter(|bytes| *bytes != 0 && *bytes <= MAXIMUM_HOST_CATALOG_BYTES)
                .ok_or_else(closed),
        );
        let extent = *positive(&self.extent)?;
        self.model_geometry = Some(Self::model_demand(extent));
        self.model_funding =
            Some(receiving.admit_additional_demand_v2(*positive(&self.model_geometry)?));
        positive(&self.model_funding)?;
        self.read = Some(self.file.read_once_v2(extent));
        positive(&self.read)?;
        self.snapshot = Some(HostCatalogSnapshot::decode_canonical(
            self.file.bytes_v2().ok_or_else(closed)?,
        ));
        positive(&self.snapshot)?;
        match self.snapshot.take() {
            Some(Ok(snapshot)) => Ok(snapshot),
            _ => std::process::abort(),
        }
    }

    fn finish_posts(&mut self, catalog: &FileHostCatalog) {
        // Do not let a body, funding or earlier native refusal suppress any
        // already-paid independent post whose primary acquisition was entered.
        if self.capture.is_some() {
            self.file_post = Some(
                self.file
                    .finish_once_v2(&catalog.root, Path::new(super::CATALOG_FILE)),
            );
        }
        if self.package_capture.is_some() {
            self.package_post = Some(self.package.finish_once_v2());
        }
        if let (Some(Ok(snapshot)), Some((workspace, network, anchor))) =
            (&self.snapshot, self.handles)
        {
            if self.pins[0].entered() {
                if let Ok(index) = snapshot
                    .workspaces()
                    .binary_search_by_key(&workspace, |entry| *entry.handle())
                {
                    let entry = &snapshot.workspaces()[index];
                    let _owed = self.pin_posts[0].workspace_once(
                        entry.root_directory(),
                        entry.device(),
                        entry.inode(),
                    );
                }
            }
            if self.pins[1].entered() {
                if let Ok(index) = snapshot
                    .networks()
                    .binary_search_by_key(&network, |entry| *entry.handle())
                {
                    let entry = &snapshot.networks()[index];
                    let _owed = self.pin_posts[1].network_once(
                        entry.namespace_path(),
                        entry.device(),
                        entry.inode(),
                    );
                }
            }
            if self.pins[2].entered() {
                if let Ok(index) = snapshot
                    .attachment_anchors()
                    .binary_search_by_key(&anchor, |entry| *entry.handle())
                {
                    let entry = &snapshot.attachment_anchors()[index];
                    let _owed = self.pin_posts[2].anchor_once(
                        entry.directory(),
                        entry.device(),
                        entry.inode(),
                        entry.mount_id(),
                    );
                }
            }
        }
        if self.root_before.entered {
            let _owed = self.root_after.observe_once(&catalog.root);
        }
        self.posts = Some((|| {
            if self.root_before.entered {
                self.root_after.require_complete()?;
            }
            if self.capture.is_some() {
                positive(&self.file_post)?;
            }
            if self.package_capture.is_some() {
                positive(&self.package_post)?;
            }
            for (primary, post) in self.pins.iter().zip(&self.pin_posts) {
                if primary.entered() {
                    post.require_complete()?;
                }
            }
            Ok(())
        })());
    }

    fn select_primary_failure(&self) -> Option<PrimaryFailureV2> {
        if cause(&self.fixed_geometry).is_some() {
            Some(PrimaryFailureV2::FixedGeometry)
        } else if cause(&self.fixed_funding).is_some() {
            Some(PrimaryFailureV2::FixedFunding)
        } else if self.root_before.failure().is_some() {
            Some(PrimaryFailureV2::RootBefore)
        } else if cause(&self.capture).is_some() {
            Some(PrimaryFailureV2::Capture)
        } else if cause(&self.extent).is_some() {
            Some(PrimaryFailureV2::Extent)
        } else if cause(&self.model_geometry).is_some() {
            Some(PrimaryFailureV2::ModelGeometry)
        } else if cause(&self.model_funding).is_some() {
            Some(PrimaryFailureV2::ModelFunding)
        } else if cause(&self.read).is_some() {
            Some(PrimaryFailureV2::Read)
        } else if cause(&self.snapshot).is_some() {
            Some(PrimaryFailureV2::Snapshot)
        } else if self.package.failure().is_some() {
            Some(PrimaryFailureV2::Package)
        } else if cause(&self.package_binding).is_some() {
            Some(PrimaryFailureV2::PackageBinding)
        } else if let Some(index) = self.pins.iter().position(|pin| pin.failure().is_some()) {
            Some(PrimaryFailureV2::Pin(index))
        } else if self.construction.failure().is_some() {
            Some(PrimaryFailureV2::Construction)
        } else if cause(&self.returned).is_some() {
            Some(PrimaryFailureV2::Returned)
        } else {
            None
        }
    }

    fn primary_failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.first_primary? {
            PrimaryFailureV2::FixedGeometry => cause(&self.fixed_geometry),
            PrimaryFailureV2::FixedFunding => cause(&self.fixed_funding),
            PrimaryFailureV2::RootBefore => self.root_before.failure(),
            PrimaryFailureV2::Capture => self.file.failure().map(|cause| cause as &(dyn Error + 'static)).or_else(|| cause(&self.capture)),
            PrimaryFailureV2::Extent => cause(&self.extent),
            PrimaryFailureV2::ModelGeometry => cause(&self.model_geometry),
            PrimaryFailureV2::ModelFunding => cause(&self.model_funding),
            PrimaryFailureV2::Read => self.file.failure().map(|cause| cause as &(dyn Error + 'static)).or_else(|| cause(&self.read)),
            PrimaryFailureV2::Snapshot => cause(&self.snapshot),
            PrimaryFailureV2::Package => self.package.failure(),
            PrimaryFailureV2::PackageBinding => cause(&self.package_binding),
            PrimaryFailureV2::Pin(index) => self.pins.get(index)?.failure(),
            PrimaryFailureV2::Construction => self.construction.failure(),
            PrimaryFailureV2::Returned => cause(&self.returned),
        }
    }

    /// Borrows the earliest retained native, decoding or receiving failure.
    ///
    /// The primary origin is latched before any independent post is entered,
    /// so a later native post cannot mask an earlier body failure. This performs
    /// no IO and creates no currentness or completion token.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.primary_failure()
            .or_else(|| self.root_after.failure())
            .or_else(|| self.file.failure().map(|cause| cause as &(dyn Error + 'static)))
            .or_else(|| self.package.failure())
            .or_else(|| {
                self.pin_posts
                    .iter()
                    .find_map(CatalogPinOriginalV2::failure)
            })
            .or_else(|| cause(&self.posts))
            .or_else(|| cause(&self.final_current))
            .or_else(|| self.export.failure())
            .or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }
}

#[derive(Clone, Copy)]
enum PrimaryFailureV2 {
    FixedGeometry,
    FixedFunding,
    RootBefore,
    Capture,
    Extent,
    ModelGeometry,
    ModelFunding,
    Read,
    Snapshot,
    Package,
    PackageBinding,
    Pin(usize),
    Construction,
    Returned,
}

pub(super) enum CatalogResolutionDispositionV2<'visit, 'catalog, 'original> {
    Ordinary,
    Launch {
        receiving: &'visit mut HostLaunchCatalogReceivingV2<'catalog, 'original>,
        original: &'visit mut HostLaunchCatalogOriginalV2,
    },
}

impl CatalogResolutionDispositionV2<'_, '_, '_> {
    pub(super) fn snapshot(&mut self, catalog: &FileHostCatalog) -> Result<HostCatalogSnapshot> {
        match self {
            Self::Ordinary => catalog.snapshot(),
            Self::Launch {
                receiving,
                original,
            } => original.read_snapshot(catalog, receiving),
        }
    }

    pub(super) fn retain_snapshot(&mut self, snapshot: HostCatalogSnapshot) {
        if let Self::Launch { original, .. } = self {
            original.snapshot = Some(Ok(snapshot));
        }
    }

    pub(super) fn package_binding(&mut self) -> Result<ObjectDigest> {
        match self {
            Self::Ordinary => super::protected_guest_package_binding(),
            Self::Launch { original, .. } => {
                original.package_capture = Some(original.package.capture_once_v2());
                positive(&original.package_capture)?;
                original.package_binding = Some(super::decode_guest_package_binding(
                    original.package.bytes_v2()?,
                ));
                positive(&original.package_binding).copied()
            }
        }
    }

    pub(super) fn workspace(&mut self, entry: &WorkspaceCatalogEntry) -> Result<Option<OwnedFd>> {
        match self {
            Self::Ordinary => {
                super::verify_workspace_pin(entry.root_directory(), entry.device(), entry.inode())
                    .map(Some)
            }
            Self::Launch { original, .. } => {
                original.pins[0].workspace_once(
                    entry.root_directory(),
                    entry.device(),
                    entry.inode(),
                )?;
                Ok(None)
            }
        }
    }

    pub(super) fn network(&mut self, entry: &NetworkCatalogEntry) -> Result<Option<NamespaceFd>> {
        match self {
            Self::Ordinary => {
                super::verify_network_pin(entry.namespace_path(), entry.device(), entry.inode())
                    .map(Some)
            }
            Self::Launch { original, .. } => {
                original.pins[1].network_once(
                    entry.namespace_path(),
                    entry.device(),
                    entry.inode(),
                )?;
                Ok(None)
            }
        }
    }

    pub(super) fn anchor(
        &mut self,
        entry: &AttachmentAnchorCatalogEntry,
    ) -> Result<Option<OwnedFd>> {
        match self {
            Self::Ordinary => super::verify_attachment_anchor_pin(
                entry.directory(),
                entry.device(),
                entry.inode(),
                entry.mount_id(),
            )
            .map(Some),
            Self::Launch { original, .. } => {
                original.pins[2].anchor_once(
                    entry.directory(),
                    entry.device(),
                    entry.inode(),
                    entry.mount_id(),
                )?;
                Ok(None)
            }
        }
    }

    pub(super) fn construct_resources(
        &mut self,
        workspace: &WorkspaceCatalogEntry,
        network: &NetworkCatalogEntry,
        anchor: &AttachmentAnchorCatalogEntry,
        proof: GuestRootPublicationProofV1,
        workspace_pin: Option<OwnedFd>,
        network_pin: Option<NamespaceFd>,
        anchor_pin: Option<OwnedFd>,
    ) -> Result<ResolvedLaunchResources> {
        let mut ordinary = ConstructedCatalogOriginalV2::default();
        let (destination, workspace_pin, network_pin, anchor_pin) = match self {
            Self::Ordinary => (&mut ordinary, workspace_pin, network_pin, anchor_pin),
            Self::Launch { original, .. } => (
                &mut original.construction,
                original.pins[0].take_raw(),
                original.pins[1].take_namespace(),
                original.pins[2].take_raw(),
            ),
        };
        // Park all three originals before the first constructor can fail.
        destination.pending_workspace = workspace_pin;
        destination.pending_network = network_pin;
        destination.pending_anchor = anchor_pin;
        let result = destination.construct(workspace, network, anchor, proof);
        match self {
            Self::Ordinary if result.is_err() => Err(ordinary.into_ordinary_error()),
            _ => result,
        }
    }
}

#[derive(Default)]
struct ConstructedCatalogOriginalV2 {
    pending_workspace: Option<OwnedFd>,
    pending_network: Option<NamespaceFd>,
    pending_anchor: Option<OwnedFd>,
    anchor: Option<
        std::result::Result<ResolvedAttachmentAnchor, CatalogPinConstructionFailureV2<OwnedFd>>,
    >,
    workspace:
        Option<std::result::Result<ResolvedWorkspace, CatalogPinConstructionFailureV2<OwnedFd>>>,
    network:
        Option<std::result::Result<ResolvedNetwork, CatalogPinConstructionFailureV2<NamespaceFd>>>,
}

impl ConstructedCatalogOriginalV2 {
    fn construct(
        &mut self,
        workspace: &WorkspaceCatalogEntry,
        network: &NetworkCatalogEntry,
        anchor: &AttachmentAnchorCatalogEntry,
        proof: GuestRootPublicationProofV1,
    ) -> Result<ResolvedLaunchResources> {
        self.anchor = Some(ResolvedAttachmentAnchor::from_pinned_retaining_v2(
            anchor.directory().to_owned(),
            anchor.device(),
            anchor.inode(),
            anchor.mount_id(),
            self.pending_anchor.take().ok_or_else(closed)?,
        ));
        if !self.anchor.as_ref().is_some_and(|value| value.is_ok()) {
            return Err(closed());
        }
        self.workspace = Some(ResolvedWorkspace::from_pinned_retaining_v2(
            workspace.root_directory().to_owned(),
            workspace.device(),
            workspace.inode(),
            self.pending_workspace.take().ok_or_else(closed)?,
        ));
        if !self.workspace.as_ref().is_some_and(|value| value.is_ok()) {
            return Err(closed());
        }
        self.network = Some(ResolvedNetwork::from_pinned_retaining_v2(
            network.namespace_path().to_owned(),
            network.device(),
            network.inode(),
            self.pending_network.take().ok_or_else(closed)?,
        ));
        if !self.network.as_ref().is_some_and(|value| value.is_ok()) {
            return Err(closed());
        }
        let (Some(Ok(attachment_anchor)), Some(Ok(resolved_workspace)), Some(Ok(resolved_network))) = (
            self.anchor.take(),
            self.workspace.take(),
            self.network.take(),
        ) else {
            std::process::abort()
        };
        Ok(ResolvedLaunchResources {
            workspace: resolved_workspace.with_guest_root_publication(proof),
            network: resolved_network,
            identity: ResolvedIdentityAllocation {
                range_start: workspace.identity().range_start(),
                range_size: workspace.identity().range_size(),
                catalog_generation: workspace.identity().catalog_generation(),
            },
            attachment_anchor,
        })
    }

    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.anchor
            .as_ref()
            .and_then(|value| value.as_ref().err())
            .map(CatalogPinConstructionFailureV2::failure)
            .or_else(|| {
                self.workspace
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(CatalogPinConstructionFailureV2::failure)
            })
            .or_else(|| {
                self.network
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(CatalogPinConstructionFailureV2::failure)
            })
    }

    fn into_ordinary_error(mut self) -> HostError {
        if let Some(Err(failure)) = self.anchor.take() {
            return failure.into_ordinary_error();
        }
        if let Some(Err(failure)) = self.workspace.take() {
            return failure.into_ordinary_error();
        }
        if let Some(Err(failure)) = self.network.take() {
            return failure.into_ordinary_error();
        }
        closed()
    }
}

/// Holds independent held-root and fixed-name observations before interpreting
/// either result. The fixed name is selected by installed Hostd, never an input.
#[derive(Default)]
pub(super) struct NamedCatalogRootOriginalV2 {
    opening: Option<rustix::io::Result<OwnedFd>>,
    named_stat: Option<rustix::io::Result<rustix::fs::Stat>>,
    held_stat: Option<rustix::io::Result<rustix::fs::Stat>>,
    comparison: Option<Result<()>>,
    entered: bool,
}

impl NamedCatalogRootOriginalV2 {
    pub(super) fn observe_once(&mut self, held: &aos_sandbox_linux::path::BeneathRoot) -> Result<()> {
        if self.entered {
            return Err(closed());
        }
        self.entered = true;
        self.opening = Some(super::open_catalog_root_descriptor(Path::new(
            "/run/aos/sandbox-host",
        )));
        if let Some(Ok(fd)) = &self.opening {
            self.named_stat = Some(rustix::fs::fstat(fd));
        }
        // An independent held-descriptor observation is owed even after a
        // failed named open or fstat; preserve both original native errors.
        self.held_stat = Some(rustix::fs::fstat(held.as_fd()));
        self.comparison = Some((|| {
            positive(&self.opening)?;
            let named = positive(&self.named_stat)?;
            let held = positive(&self.held_stat)?;
            super::require_catalog_root_protection(named)?;
            super::require_catalog_root_protection(held)?;
            if named.st_dev != held.st_dev || named.st_ino != held.st_ino {
                return Err(HostError::Catalog("catalog root name changed".to_owned()));
            }
            Ok(())
        })());
        self.require_complete()
    }

    pub(super) fn require_complete(&self) -> Result<()> {
        positive(&self.comparison).copied()
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        cause(&self.opening)
            .or_else(|| cause(&self.named_stat))
            .or_else(|| cause(&self.held_stat))
            .or_else(|| cause(&self.comparison))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unentered_catalog_original_is_inert() {
        let original = HostLaunchCatalogOriginalV2::new();
        assert!(original.failure().is_none());
        assert!(!original.root_before.entered);
        assert!(!original.root_after.entered);
        assert!(original.snapshot.is_none());
        assert!(original.returned.is_none());
    }

    #[test]
    fn primary_body_failure_precedes_independent_post_failure() {
        let mut original = HostLaunchCatalogOriginalV2::new();
        original.returned = Some(Err(HostError::Catalog("primary body".to_owned())));
        original.first_primary = original.select_primary_failure();
        original.root_after.opening = Some(Err(rustix::io::Errno::ACCESS));
        assert_eq!(
            original.failure().unwrap().to_string(),
            "host catalog rejected launch: primary body"
        );
    }
}
