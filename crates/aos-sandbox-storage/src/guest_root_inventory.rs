//! Protected Storage projection of physically published guest workspace roots.
//!
//! The source inventory has already been authenticated by the Storage runtime
//! and each row's root pin revalidated. This module adds only physical
//! publication evidence. It never treats a workspace marker as authority:
//! the expected proof is rebuilt from the current catalog row and a fixed
//! deployment-pinned AOS package template, then the complete tree is measured.

use std::fs::{self, OpenOptions};
use std::io::Read as _;
use std::os::fd::AsFd as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::{Component, Path, PathBuf};

use aos_proto::aos::sandbox::local::v1::InventoryStorageResourcesResponse;
use aos_sandbox_guest_root_realization::guest_root_label::verify_copied_guest_executable_labels_fd_v1;
use aos_sandbox_guest_root_realization::guest_root_marker::{
    GuestRootMarkerReadOriginalV1, read_guest_root_marker_v1,
};
use aos_sandbox_agent::guest_root_publication::{
    CONCRETE_GUEST_FEATURE_MASK_V1, GuestRootPublicationProofV1,
};
use aos_sandbox_guest_root_tree::guest_root_tree::{GuestRootTemplateComparisonDataV2, compare_guest_root_template_observed_v2};
use crate::{StorageAdmissionCoordinator, StorageBrokerError};
use aos_sandbox_protocol::{
    MAXIMUM_RESPONSE_BYTES, ValidatedStorageWorkspace, decode_storage_resource_inventory_response,
};
use buffa::Message as _;
use rustix::fs::{Mode, OFlags, open};

mod publication_readback;
mod label_receiving;
pub(crate) use label_receiving::GuestRootLabelReceivingV2;
pub(crate) use publication_readback::GuestRootTargetReadbackOriginalV2;

const PACKAGE_BINDING_FILE: &str = "package-binding";
const ROOT_TREE_DIGEST_FILE: &str = "root-tree-digest";
const ROOT_DIRECTORY: &str = "root";
const MARKER_FILE: &str = "etc/aos/sandbox-guest-root/publication-v1";
const O_NOFOLLOW: i32 = 0o400_000;
const O_CLOEXEC: i32 = 0o2_000_000;

/// Holds one exact, root-protected AOS package template selected by deployment.
#[derive(Clone, Debug)]
pub struct ProtectedGuestRootTemplateV1 {
    root: PathBuf,
    package_binding: [u8; 32],
    root_tree_digest: [u8; 32],
    comparison_census: GuestRootTemplateComparisonDataV2,
}

impl ProtectedGuestRootTemplateV1 {
    /// Opens and measures one fixed derivation output, not a request path.
    ///
    /// # Errors
    ///
    /// Returns [`GuestRootInventoryErrorV1`] if the output, binding file,
    /// ownership, mode, or complete template tree is not exact and protected.
    pub fn open(package_path: &Path) -> Result<Self, GuestRootInventoryErrorV1> {
        Self::open_for(package_path, None)
    }

    fn open_for(
        package_path: &Path,
        receiving: Option<&mut aos_sandbox::StorageGuestRootTemplateReceivingLoanV1<'_, '_>>,
    ) -> Result<Self, GuestRootInventoryErrorV1> {
        if !package_path.starts_with("/nix/store")
            || package_path == Path::new("/nix/store")
            || package_path
                .components()
                .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
        {
            return Err(GuestRootInventoryErrorV1::InvalidTemplate);
        }
        for ancestor in package_path
            .ancestors()
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
        {
            verify_protected_directory(ancestor)?;
        }
        let root = package_path.join(ROOT_DIRECTORY);
        verify_protected_directory(&root)?;

        let package_binding = read_protected_digest(&package_path.join(PACKAGE_BINDING_FILE))?;
        let expected_tree_digest =
            read_protected_digest(&package_path.join(ROOT_TREE_DIGEST_FILE))?;

        let comparison_census = match receiving {
            Some(receiving) => {
                receiving.measure_once_v1().map_err(|_| GuestRootInventoryErrorV1::Receiving)?;
                receiving.comparison_census_data_v2().map_err(|_| GuestRootInventoryErrorV1::Receiving)?
            }
            None => compare_guest_root_template_observed_v2(&root, &root)
                .map_err(|_| GuestRootInventoryErrorV1::InvalidTemplate)?,
        };
        let root_tree_digest = comparison_census.digest_v2();
        if root_tree_digest != expected_tree_digest {
            return Err(GuestRootInventoryErrorV1::InvalidTemplate);
        }
        Ok(Self {
            root,
            package_binding,
            root_tree_digest, comparison_census,
        })
    }

    /// Returns the independently pinned package-closure commitment.
    #[must_use]
    pub const fn package_binding(&self) -> &[u8; 32] {
        &self.package_binding
    }

    /// Returns the physically measured complete template tree commitment.
    #[must_use]
    pub const fn root_tree_digest(&self) -> &[u8; 32] {
        &self.root_tree_digest
    }

    /// Returns the protected template root used only by the fixed publisher.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    pub(crate) fn comparison_receiving_demand_v2(&self, workspace: &Path)
        -> Option<aos_sandbox_core::ResourceVector>
    {
        use std::os::unix::ffi::OsStrExt as _;
        self.comparison_census.receiving_demand_v2(self.root.as_os_str().as_bytes().len(),
            workspace.as_os_str().as_bytes().len())
    }

    pub(crate) fn expected_proof(
        &self,
        workspace: &ValidatedStorageWorkspace,
    ) -> GuestRootPublicationProofV1 {
        GuestRootPublicationProofV1 {
            sandbox: *workspace.fence().sandbox_id(),
            incarnation: *workspace.fence().incarnation_id(),
            assignment_epoch: workspace.fence().assignment_epoch(),
            assignment_digest: *workspace.fence().assignment_digest(),
            creation_operation: *workspace.creation_operation_id(),
            workspace_handle: *workspace.workspace_handle(),
            dataset_guid: workspace.dataset_guid(),
            root_image_digest: *workspace.root_image().digest().as_bytes(),
            package_binding: self.package_binding,
            root_tree_digest: self.root_tree_digest,
            feature_mask: CONCRETE_GUEST_FEATURE_MASK_V1,
        }
    }
}

/// Retains one actual protected-template load and its independent receiving post.
///
/// Construction is inert. The selected entry joins the real captured argv9 and
/// pays fixed path/digest work before the first filesystem observation. The
/// existing parser and exact template algorithm remain shared with ordinary
/// callers. The attempt keeps the whole actual upper Result on every refusal.
pub struct ProtectedGuestRootTemplateOpenV1 {
    demand: Option<Result<
        aos_sandbox_core::ResourceVector,
        aos_sandbox_core::AccountingError,
    >>,
    borrowing: Option<Result<(), aos_sandbox::StorageReceivingClosedV1>>,
    loaded: Option<Result<ProtectedGuestRootTemplateV1, GuestRootInventoryErrorV1>>,
    post: Option<Result<(), aos_sandbox::StorageReceivingClosedV1>>,
    entered: bool,
    taken: bool,
}

impl ProtectedGuestRootTemplateOpenV1 {
    /// Creates an inert template owner before any fallible load.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            demand: None,
            borrowing: None,
            loaded: None,
            post: None,
            entered: false,
            taken: false,
        }
    }

    /// Loads under the actual same-original argv9 receiving interval once.
    ///
    /// # Errors
    ///
    /// Keeps actual accounting, parse, native/tree and post causes on their
    /// original owners. The returned marker cannot replace those whole Results.
    pub fn open_receiving_once_v1(
        &mut self,
        receiving: &mut aos_sandbox::StoragePrepareReceivingLoanV1<'_>,
        package: &Path,
    ) -> Result<(), GuestRootInventoryErrorV1> {
        if self.entered {
            return Err(GuestRootInventoryErrorV1::Receiving);
        }
        self.entered = true;
        self.demand = Some(Self::fixed_demand(package));
        let demand = self.demand.as_ref().and_then(|result| result.as_ref().ok())
            .copied().ok_or(GuestRootInventoryErrorV1::Receiving)?;
        let mut guard = match receiving.borrow_guest_root_template_once_v1(package, demand) {
            Ok(guard) => {
                self.borrowing = Some(Ok(()));
                guard
            }
            Err(cause) => {
                self.borrowing = Some(Err(cause));
                return Err(GuestRootInventoryErrorV1::Receiving);
            }
        };
        self.loaded = Some(ProtectedGuestRootTemplateV1::open_for(package, Some(&mut guard)));
        // The actual earlier upper parse/expected-digest Result is parked
        // before the independent same-original post, including on rejection.
        self.post = Some(guard.finish_once_v1());
        if matches!(self.loaded, Some(Ok(_))) && matches!(self.post, Some(Ok(()))) {
            Ok(())
        } else {
            Err(GuestRootInventoryErrorV1::Receiving)
        }
    }

    /// Retains the existing nonresource protected-template load once.
    ///
    /// This preserves its existing scope and supplies no receiving authority.
    ///
    /// # Errors
    ///
    /// Keeps the whole original parser/physical Result rather than dropping it.
    pub fn open_legacy_once_v1(&mut self, package: &Path) -> Result<(), GuestRootInventoryErrorV1> {
        if self.entered {
            return Err(GuestRootInventoryErrorV1::Receiving);
        }
        self.entered = true;
        self.loaded = Some(ProtectedGuestRootTemplateV1::open(package));
        if matches!(self.loaded, Some(Ok(_))) {
            Ok(())
        } else {
            Err(GuestRootInventoryErrorV1::Receiving)
        }
    }

    /// Borrows the actually observed positive template before its final transfer.
    #[must_use]
    pub fn template(&self) -> Option<&ProtectedGuestRootTemplateV1> {
        if self.taken || (self.borrowing.is_some() && !matches!(self.post, Some(Ok(())))) {
            return None;
        }
        self.loaded.as_ref().and_then(|result| result.as_ref().ok())
    }

    /// Moves the actual template only after its complete positive load/posts.
    #[must_use]
    pub fn take_template_once_v1(&mut self) -> Option<ProtectedGuestRootTemplateV1> {
        if self.taken || !matches!(self.loaded, Some(Ok(_)))
            || (self.borrowing.is_some() && !matches!(self.post, Some(Ok(()))))
        {
            return None;
        }
        let Some(Ok(template)) = self.loaded.take() else {
            return None;
        };
        self.taken = true;
        Some(template)
    }

    /// Borrows an actual upper cause; Native keeps its independent original cause.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.demand.as_ref().and_then(|result| result.as_ref().err())
            .map(|cause| cause as &dyn std::error::Error)
            .or_else(|| self.borrowing.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &dyn std::error::Error))
            .or_else(|| self.loaded.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &dyn std::error::Error))
            .or_else(|| self.post.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &dyn std::error::Error))
    }

    fn fixed_demand(
        package: &Path,
    ) -> Result<aos_sandbox_core::ResourceVector, aos_sandbox_core::AccountingError> {
        use aos_sandbox_core::{AccountingError, ResourceDimension as D, ResourceVector};
        use std::os::unix::ffi::OsStrExt as _;
        let invalid = || AccountingError::ArithmeticOverflow { dimension: D::MemoryBytes };
        let paths = package.as_os_str().as_bytes().len().checked_mul(16).ok_or_else(invalid)?;
        let ancestors = package.ancestors().count().checked_mul(4 * std::mem::size_of::<&Path>())
            .ok_or_else(invalid)?;
        let bytes = paths.checked_add(ancestors)
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Self>() + 64 * 1024))
            .ok_or_else(invalid)?;
        // Both 65-byte digest reads are sequential. This also covers the actual
        // retained template path, root join, ancestor Vec growth and bounded
        // path/error/native scratch before the reached scanner's own demand.
        Ok(ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(bytes).map_err(|_| invalid())?)
            .with(D::OpenFiles, 2)
            .with(D::MetadataEntries, 16))
    }
}

impl Default for ProtectedGuestRootTemplateOpenV1 {
    fn default() -> Self {
        Self::new()
    }
}

/// Adds exact physical AOSGRP01 proof to current authenticated inventory rows.
///
/// Missing marker means the workspace is not launch-ready. A present but
/// malformed, stale, or physically mismatched marker rejects the entire
/// snapshot; it cannot be silently treated as absence.
///
/// # Errors
///
/// Returns [`GuestRootInventoryErrorV1`] if input inventory is invalid, a
/// present marker or tree does not match, or the bounded output is invalid.
pub fn attach_guest_root_publication_readback_v1(
    inventory_bytes: &[u8],
    template: &ProtectedGuestRootTemplateV1,
) -> Result<Vec<u8>, GuestRootInventoryErrorV1> {
    attach_guest_root_publication_readback_inner_v1(inventory_bytes, template, None, None, None)
}

/// The actual selected frame owns these native rows through its independent posts.
#[derive(Default)]
pub(crate) struct GuestRootInventoryReadbackOriginalV1 {
    rows: Vec<PublicationReadbackRowV1>,
    allocation: Option<Result<(), std::collections::TryReserveError>>,
    first: Option<usize>,
    entered: bool,
    complete_projection_prepaid: bool,
}

#[derive(Default)]
struct PublicationReadbackRowV1 {
    before: Option<std::io::Result<fs::Metadata>>,
    marker_presence: Option<std::io::Result<fs::Metadata>>,
    marker: GuestRootMarkerReadOriginalV1,
    marker_result: Option<Result<(), aos_sandbox_guest_root_realization::guest_root_marker::GuestRootMarkerErrorV1>>,
    retain_complete_projection: bool,
    label_invoice: label_receiving::GuestRootLabelInvoiceOriginalV2,
    current_publication: Option<Result<Option<aos_sandbox_protocol::semantics::storage_guest_root::StorageGuestRootCurrentPublicationDataV2>, StorageBrokerError>>,
    root: Option<Result<std::os::fd::OwnedFd, rustix::io::Errno>>,
    labels: Option<Result<(), aos_sandbox_guest_root_realization::guest_root_label::GuestRootLabelErrorV1>>,
    after: Option<std::io::Result<fs::Metadata>>,
    first: Option<ReadbackNativeFailureV1>,
}

#[derive(Clone, Copy)]
enum ReadbackNativeFailureV1 {
    Before,
    Presence,
    Marker,
    Root,
    Labels,
    After,
    CurrentPublication,
}

impl GuestRootInventoryReadbackOriginalV1 {
    pub(crate) fn mark_complete_projection_prepaid_v2(&mut self) {
        self.complete_projection_prepaid = true;
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        fn error<T, E: std::error::Error + 'static>(value: &Option<Result<T, E>>)
            -> Option<&(dyn std::error::Error + 'static)>
        {
            value.as_ref()?.as_ref().err().map(|cause| cause as _)
        }
        if let Some(cause) = error(&self.allocation) {
            return Some(cause);
        }
        let row = self.rows.get(self.first?)?;
        match row.first? {
            ReadbackNativeFailureV1::Before => error(&row.before),
            ReadbackNativeFailureV1::Presence => error(&row.marker_presence),
            ReadbackNativeFailureV1::Marker => {
                if row.marker.retained_projection_admission_refused_v2() {
                    row.label_invoice.failure_v2().or_else(|| row.marker.failure())
                } else { row.marker.failure().or_else(|| error(&row.marker_result)) }
            },
            ReadbackNativeFailureV1::Root => error(&row.root),
            ReadbackNativeFailureV1::Labels => error(&row.labels),
            ReadbackNativeFailureV1::After => error(&row.after),
            ReadbackNativeFailureV1::CurrentPublication => error(&row.current_publication),
        }
    }
}

pub(crate) fn marker_readback_retained_demand_v1(workspaces: u64)
    -> Result<aos_sandbox_core::ResourceVector, aos_sandbox_core::AccountingError>
{
    use crate::receiving_demand::{add, count, multiply};
    use aos_sandbox_core::{AccountingError, ResourceDimension as D, ResourceVector};
    // Three actual moved marker/root descriptors remain per reached workspace.
    // The already-paid source geometry covers the inventory namespace/models;
    // these native destinations add no invented scalar metadata-entry fees.
    let row = add(multiply(count(std::mem::size_of::<PublicationReadbackRowV1>())?, 3)?,
        8 * 4096 + 4 * 512)?;
    let bytes = add(multiply(workspaces, row)?,
        3 * count(std::mem::size_of::<GuestRootInventoryReadbackOriginalV1>())?)?;
    let files = workspaces.checked_mul(3).ok_or(AccountingError::ArithmeticOverflow {
        dimension: D::OpenFiles,
    })?;
    Ok(ResourceVector::ZERO.with(D::MemoryBytes, bytes).with(D::OpenFiles, files))
}

pub(crate) fn attach_guest_root_publication_readback_retaining_v1(
    inventory_bytes: &[u8],
    template: &ProtectedGuestRootTemplateV1,
    original: &mut GuestRootInventoryReadbackOriginalV1,
) -> Result<Vec<u8>, GuestRootInventoryErrorV1> {
    attach_guest_root_publication_readback_inner_v1(inventory_bytes, template, Some(original), None, None)
}

/// Uses the completed native readback and exact protected State relation.
pub(crate) fn attach_guest_root_publication_readback_current_v2(
    inventory_bytes: &[u8],
    template: &ProtectedGuestRootTemplateV1,
    original: &mut GuestRootInventoryReadbackOriginalV1,
    coordinator: &StorageAdmissionCoordinator,
    labels: &mut GuestRootLabelReceivingV2<'_, '_, '_>,
) -> Result<Vec<u8>, GuestRootInventoryErrorV1> {
    if !original.complete_projection_prepaid {
        return Err(GuestRootInventoryErrorV1::Receiving);
    }
    attach_guest_root_publication_readback_inner_v1(inventory_bytes, template, Some(original), Some(coordinator), Some(labels))
}

/// Prices the sole complete label/tree engine for canonical workspace roots.
pub(crate) fn additional_complete_marker_readback_demand_v2(
    workspaces: u64,
    template: &ProtectedGuestRootTemplateV1,
) -> Result<aos_sandbox_core::ResourceVector, aos_sandbox_core::AccountingError> {
    use aos_sandbox_core::{AccountingError, ResourceDimension as D, ResourceVector};
    use aos_sandbox_guest_root_realization::guest_root_label::GuestRootLabelReadOriginalV1;
    use crate::receiving_demand::{add, count, multiply};
    use std::os::unix::ffi::OsStrExt as _;
    let overflow = |dimension| AccountingError::ArithmeticOverflow { dimension };
    let labels = GuestRootLabelReadOriginalV1::fixed_receiving_footprint_v1()
        .ok_or_else(|| overflow(D::MemoryBytes))?;
    // The sole Inventory validator derives this exact path from its fixed
    // prefix and 32-byte handle; no caller-controlled pathname enters it.
    let root_length = crate::workspace_pin::WORKSPACE_PIN_ROOT.len() + 1 + 64;
    let tree = template.comparison_census.receiving_demand_v2(
        template.root.as_os_str().as_bytes().len(), root_length,
    ).ok_or_else(|| overflow(D::MemoryBytes))?;
    let one = tree.checked_add(ResourceVector::ZERO
        .with(D::MemoryBytes, add(count(labels.memory_bytes)?, 3 * 304)?)
        .with(D::OpenFiles, count(labels.open_files)?)
        .with(D::MetadataEntries, count(labels.metadata_entries)?))?;
    let mut total = ResourceVector::ZERO;
    for dimension in [D::MemoryBytes, D::OpenFiles, D::MetadataEntries] {
        total = total.with(dimension, multiply(workspaces, one.get(dimension))?);
    }
    // The original Inventory retention supplier already owns each fixed
    // marker/root row. Only the added whole label/tree/current-binding planes
    // are charged here; no fixed descriptor or parser fields become metadata.
    Ok(total)
}

fn attach_guest_root_publication_readback_inner_v1(
    inventory_bytes: &[u8],
    template: &ProtectedGuestRootTemplateV1,
    mut original: Option<&mut GuestRootInventoryReadbackOriginalV1>,
    coordinator: Option<&StorageAdmissionCoordinator>,
    mut labels: Option<&mut GuestRootLabelReceivingV2<'_, '_, '_>>,
) -> Result<Vec<u8>, GuestRootInventoryErrorV1> {
    let inventory =
        decode_storage_resource_inventory_response(inventory_bytes, MAXIMUM_RESPONSE_BYTES)
            .map_err(|_| GuestRootInventoryErrorV1::InvalidInventory)?;
    let mut response = InventoryStorageResourcesResponse::decode_from_slice(inventory_bytes)
        .map_err(|_| GuestRootInventoryErrorV1::InvalidInventory)?;
    if response.workspaces.len() != inventory.workspaces().len() {
        return Err(GuestRootInventoryErrorV1::InvalidInventory);
    }

    if let Some(original) = original.as_deref_mut() {
        if original.entered {
            return Err(GuestRootInventoryErrorV1::Receiving);
        }
        original.entered = true;
        original.allocation = Some(original.rows.try_reserve_exact(inventory.workspaces().len()));
        if !matches!(original.allocation, Some(Ok(()))) {
            return Err(GuestRootInventoryErrorV1::Receiving);
        }
    }

    for (record, workspace) in response.workspaces.iter_mut().zip(inventory.workspaces()) {
        if !record.guest_root_publication_proof.is_empty()
            || !record.current_guest_root_publication_v2.is_empty() {
            return Err(GuestRootInventoryErrorV1::InvalidInventory);
        }
        let root = Path::new(workspace.root_directory());
        let expected = template.expected_proof(workspace);
        let mut row = original.as_deref_mut().map(|original| {
            let index = original.rows.len();
            let mut row = PublicationReadbackRowV1::default();
            row.retain_complete_projection = original.complete_projection_prepaid;
            original.rows.push(row);
            original.first = Some(index);
            &mut original.rows[index]
        });
        let (present, _ordinary_root) = read_publication_row_v1(
            root, workspace, template, expected, row.as_deref_mut(), labels.as_deref_mut(),
        )?;
        if !present {
            if let Some(original) = original.as_deref_mut() {
                original.first = None;
            }
            continue;
        }
        if let Some(original) = original.as_deref_mut() {
            original.first = None;
        }
        record.guest_root_publication_proof = expected
            .encode()
            .map_err(|_| GuestRootInventoryErrorV1::InvalidPublication)?
            .to_vec();
        if let Some(coordinator) = coordinator {
            let Some(original) = original.as_deref_mut() else {
                return Err(GuestRootInventoryErrorV1::Receiving);
            };
            let index = original.rows.len().checked_sub(1)
                .ok_or(GuestRootInventoryErrorV1::Receiving)?;
            original.first = Some(index);
            let row = &mut original.rows[index];
            row.first = Some(ReadbackNativeFailureV1::CurrentPublication);
            row.current_publication = Some(coordinator.completed_guest_root_publication_v2(workspace, expected));
            match row.current_publication.as_ref() {
                Some(Ok(Some(current))) => record.current_guest_root_publication_v2 = current.encode_v2().to_vec(),
                Some(Ok(None)) => {}
                _ => return Err(GuestRootInventoryErrorV1::InvalidPublication),
            }
            row.first = None;
            original.first = None;
        }
    }

    let encoded = response.encode_to_vec();
    decode_storage_resource_inventory_response(&encoded, MAXIMUM_RESPONSE_BYTES)
        .map_err(|_| GuestRootInventoryErrorV1::InvalidInventory)?;
    Ok(encoded)
}

fn read_publication_row_v1(
    root: &Path,
    workspace: &ValidatedStorageWorkspace,
    template: &ProtectedGuestRootTemplateV1,
    expected: GuestRootPublicationProofV1,
    mut original: Option<&mut PublicationReadbackRowV1>,
    labels: Option<&mut GuestRootLabelReceivingV2<'_, '_, '_>>,
) -> Result<(bool, Option<std::os::fd::OwnedFd>), GuestRootInventoryErrorV1> {
    if let Some(original) = original.as_deref_mut() {
        original.first = Some(ReadbackNativeFailureV1::Before);
        original.before = Some(fs::symlink_metadata(root));
        let Some(Ok(metadata)) = original.before.as_ref() else {
            return Err(GuestRootInventoryErrorV1::InvalidPublication);
        };
        verify_workspace_metadata(metadata, workspace)?;
    } else {
        verify_workspace_root(root, workspace)?;
    }
    let marker = root.join(MARKER_FILE);
    if let Some(original) = original.as_deref_mut() {
        original.first = Some(ReadbackNativeFailureV1::Presence);
        original.marker_presence = Some(fs::symlink_metadata(marker));
        match original.marker_presence.as_ref() {
            Some(Err(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                original.first = None;
                return Ok((false, None));
            }
            Some(Ok(_)) => {}
            _ => return Err(GuestRootInventoryErrorV1::InvalidPublication),
        }
    } else {
        match fs::symlink_metadata(marker) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok((false, None)),
            Err(error) => return Err(error.into()),
            Ok(_) => {}
        }
    }
    if let Some(original) = original.as_deref_mut() {
        original.first = Some(ReadbackNativeFailureV1::Marker);
        original.marker_result = Some(if original.retain_complete_projection {
            let receiving = labels.ok_or(GuestRootInventoryErrorV1::Receiving)?;
            let invoice = &mut original.label_invoice;
            original.marker.read_receiving_projection_once_v2(template.root(), root, expected,
                &mut |shape| invoice.admit_v2(shape, receiving))
        } else {
            original.marker.read_once_v1(template.root(), root, expected)
        });
        if !matches!(original.marker_result, Some(Ok(()))) {
            return Err(GuestRootInventoryErrorV1::InvalidPublication);
        }
    } else {
        read_guest_root_marker_v1(template.root(), root, expected)
            .map_err(|_| GuestRootInventoryErrorV1::InvalidPublication)?;
    }

    let opened = open(root,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty());
    if let Some(original) = original.as_deref_mut() {
        original.first = Some(ReadbackNativeFailureV1::Root);
        original.root = Some(opened);
        let Some(Ok(root_fd)) = original.root.as_ref() else {
            return Err(GuestRootInventoryErrorV1::InvalidPublication);
        };
        original.first = Some(ReadbackNativeFailureV1::Labels);
        original.labels = Some(if original.retain_complete_projection {
            if original.marker.retained_projection_completed_v2() { Ok(()) }
            else { return Err(GuestRootInventoryErrorV1::InvalidPublication); }
        } else {
            verify_copied_guest_executable_labels_fd_v1(root_fd.as_fd())
        });
        if !matches!(original.labels, Some(Ok(()))) {
            return Err(GuestRootInventoryErrorV1::InvalidPublication);
        }
        original.first = Some(ReadbackNativeFailureV1::After);
        original.after = Some(fs::symlink_metadata(root));
        let Some(Ok(metadata)) = original.after.as_ref() else {
            return Err(GuestRootInventoryErrorV1::InvalidPublication);
        };
        verify_workspace_metadata(metadata, workspace)?;
        original.first = None;
    } else {
        let root_fd = opened.map_err(|_| GuestRootInventoryErrorV1::InvalidPublication)?;
        verify_copied_guest_executable_labels_fd_v1(root_fd.as_fd())
            .map_err(|_| GuestRootInventoryErrorV1::InvalidPublication)?;
        verify_workspace_root(root, workspace)?;
        // Keep the ordinary descriptor at its old loop boundary, through the
        // caller's proof encoding. Selected retains the same FD on its row.
        return Ok((true, Some(root_fd)));
    }
    Ok((true, None))
}

fn verify_workspace_root(
    root: &Path,
    workspace: &ValidatedStorageWorkspace,
) -> Result<(), GuestRootInventoryErrorV1> {
    let metadata = fs::symlink_metadata(root)?;
    verify_workspace_metadata(&metadata, workspace)
}

fn verify_workspace_metadata(
    metadata: &fs::Metadata,
    workspace: &ValidatedStorageWorkspace,
) -> Result<(), GuestRootInventoryErrorV1> {
    if !metadata.is_dir()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
        || metadata.dev() != workspace.root_device()
        || metadata.ino() != workspace.root_inode()
    {
        return Err(GuestRootInventoryErrorV1::InvalidPublication);
    }
    Ok(())
}

fn verify_protected_directory(path: &Path) -> Result<(), GuestRootInventoryErrorV1> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err(GuestRootInventoryErrorV1::InvalidTemplate);
    }
    Ok(())
}

fn read_protected_digest(path: &Path) -> Result<[u8; 32], GuestRootInventoryErrorV1> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err(GuestRootInventoryErrorV1::InvalidTemplate);
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW | O_CLOEXEC)
        .open(path)?;
    if file.metadata()?.ino() != metadata.ino() {
        return Err(GuestRootInventoryErrorV1::InvalidTemplate);
    }
    let mut encoded = Vec::new();
    file.take(66).read_to_end(&mut encoded)?;
    if encoded.len() != 65 || encoded[64] != b'\n' {
        return Err(GuestRootInventoryErrorV1::InvalidTemplate);
    }
    let mut digest = [0_u8; 32];
    for (index, pair) in encoded[..64].chunks_exact(2).enumerate() {
        digest[index] = (hex_digit(pair[0])? << 4) | hex_digit(pair[1])?;
    }
    if digest == [0; 32] {
        return Err(GuestRootInventoryErrorV1::InvalidTemplate);
    }
    Ok(digest)
}

fn hex_digit(byte: u8) -> Result<u8, GuestRootInventoryErrorV1> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(GuestRootInventoryErrorV1::InvalidTemplate),
    }
}

/// Reports rejection at the protected template/inventory readback boundary.
#[derive(Debug, thiserror::Error)]
pub enum GuestRootInventoryErrorV1 {
    /// The actual paid original or its retained template observation is closed.
    #[error("protected guest root template receiving interval is closed")]
    Receiving,
    /// The pinned template, its package binding, or its ownership is invalid.
    #[error("protected guest root template is invalid")]
    InvalidTemplate,
    /// The authenticated workspace inventory is invalid or already annotated.
    #[error("guest root inventory input or output is invalid")]
    InvalidInventory,
    /// A present publication marker or complete workspace tree is invalid.
    #[error("guest root physical publication is invalid")]
    InvalidPublication,
    /// A protected template or workspace filesystem operation failed.
    #[error("guest root physical readback failed: {0}")]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retained_marker_files_are_priced_by_actual_workspace_count() {
        use aos_sandbox_core::ResourceDimension as D;
        let zero = marker_readback_retained_demand_v1(0).unwrap();
        let two = marker_readback_retained_demand_v1(2).unwrap();

        assert_eq!(zero.get(D::OpenFiles), 0);
        assert_eq!(two.get(D::OpenFiles), 6);
        assert!(two.get(D::MemoryBytes) > zero.get(D::MemoryBytes));
        assert_eq!(two.get(D::MetadataEntries), 0);
        assert!(marker_readback_retained_demand_v1(u64::MAX).is_err());
    }

    #[test]
    fn template_source_must_be_a_protected_store_output() {
        for path in [
            "/tmp/guest-template",
            "/nix/store",
            "/nix/store/../guest-template",
            "relative/guest-template",
        ] {
            assert!(matches!(
                ProtectedGuestRootTemplateV1::open(Path::new(path)),
                Err(GuestRootInventoryErrorV1::InvalidTemplate)
            ));
        }
    }

    #[test]
    fn package_binding_rejects_noncanonical_hex() {
        assert_eq!(hex_digit(b'a').ok(), Some(10));
        assert_eq!(hex_digit(b'9').ok(), Some(9));
        assert!(hex_digit(b'A').is_err());
        assert!(hex_digit(b'g').is_err());
    }
}
