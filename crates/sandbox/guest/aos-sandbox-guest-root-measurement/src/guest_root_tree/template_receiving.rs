//! Reached dominant receiving obligations for the existing template algorithm.
//!
//! This is portable accounting DATA around the same physical comparison. The
//! actual upper owner supplies independent path/currentness/protection custody;
//! no numeric ledger or helper here can create a genuine service receiver.

use std::fs::Metadata;
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Path, PathBuf};

use aos_sandbox_model::component_receiving::ComponentServiceReceivingLedgerV1;
use aos_sandbox_model::{ResourceDimension as D, ResourceVector};

use super::{
    GuestRootTreeErrorV1, MAXIMUM_ENTRIES, MAXIMUM_PATH_BYTES,
    TreeHashState, GuestRootTemplateComparisonDataV2, compare_guest_root_tree_observed_v2,
};

/// Compares a protected template while charging its reached dominant shapes.
///
/// This shares the ordinary digest and traversal. The supplied ledger is only
/// accounting DATA; it does not establish protected roots, a receiving original
/// or permission to allocate. A privileged caller must borrow its SAME real
/// original's ledger and retain that original through the complete observation.
///
/// Names, pending row carriers and joined paths are charged before growth. The
/// unchanged global entry/path/file limits and the caller's actual service
/// cgroup back allocator metadata and native implementation overhead.
///
/// # Errors
///
/// Returns ordinary physical comparison errors, allocation failure or a closed
/// accounting interval. The first exact accounting cause stays on `receiving`.
pub fn compare_guest_root_template_receiving_v1(
    template: &Path,
    workspace: &Path,
    receiving: &mut ComponentServiceReceivingLedgerV1,
) -> Result<[u8; 32], GuestRootTreeErrorV1> {
    compare_guest_root_template_receiving_observed_v2(template, workspace, receiving)
        .map(|observed| observed.digest_v2())
}

/// Captures shape DATA during the same actual paid comparison, with no rescan.
///
/// # Errors
/// Returns the same tree, native, allocation or retained-ledger refusal.
pub fn compare_guest_root_template_receiving_observed_v2(
    template: &Path, workspace: &Path, receiving: &mut ComponentServiceReceivingLedgerV1,
) -> Result<GuestRootTemplateComparisonDataV2, GuestRootTreeErrorV1> {
    // One streaming hash buffer; one directory iterator/name scratch; two
    // symlink target buffers; fixed native/error scratch. Descriptor-relative
    // complete-root capture is a separate algorithm and is not substituted.
    let mut traversal = TemplateTraversalV1 {
        scheduled_entries: 0,
        receiving: Some(receiving),
    };
    traversal.reserve_shape(
        ResourceVector::ZERO
            .with(D::MemoryBytes, 3 * 64 * 1024 + 3 * MAXIMUM_PATH_BYTES as u64)
            .with(D::OpenFiles, 2)
            .with(D::MetadataEntries, 8),
    )?;

    compare_guest_root_tree_observed_v2(template, workspace, true, traversal)
}

pub(super) struct TemplateTraversalV1<'receiving> {
    pub(super) scheduled_entries: usize,
    pub(super) receiving: Option<&'receiving mut ComponentServiceReceivingLedgerV1>,
}

impl TemplateTraversalV1<'_> {
    pub(super) fn legacy() -> Self {
        Self {
            scheduled_entries: 0,
            receiving: None,
        }
    }

    fn reserve_shape(&mut self, shape: ResourceVector) -> Result<(), GuestRootTreeErrorV1> {
        let Some(receiving) = self.receiving.as_deref_mut() else {
            return Ok(());
        };
        receiving.reserve(shape).map_err(|_| GuestRootTreeErrorV1::Receiving)?;
        Ok(())
    }

    // Includes pending parent names, so recursion cannot bypass the global cap
    // by collecting names that have not yet reached the hashing loop.
    pub(super) fn schedule_name(
        &mut self,
        source: &Path,
        destination: &Path,
        relative: &Path,
        name: &std::ffi::OsStr,
    ) -> Result<(), GuestRootTreeErrorV1> {
        let next = self.scheduled_entries
            .checked_add(1)
            .filter(|count| *count <= MAXIMUM_ENTRIES)
            .ok_or(GuestRootTreeErrorV1::InvalidTree)?;
        if self.receiving.is_some() {
            let name_bytes = name.as_bytes().len();
            let joined_length = |parent: &Path| {
                parent.as_os_str().as_bytes().len()
                    .checked_add(usize::from(!parent.as_os_str().is_empty()))
                    .and_then(|bytes| bytes.checked_add(name_bytes))
                    .ok_or(GuestRootTreeErrorV1::InvalidTree)
            };
            let relative_bytes = joined_length(relative)?;
            // Four reached name cells cover Vec's minimum/geometric growth,
            // old+new reallocation buffers and sort scratch. Each observed name
            // is temporarily covered by the fixed single-name scratch BEFORE
            // this charge; it is retained only after successful admission.
            let cells = 4 * std::mem::size_of::<std::ffi::OsString>()
                + 4 * (2 * std::mem::size_of::<Metadata>()
                    + 3 * std::mem::size_of::<PathBuf>()
                    + std::mem::size_of::<TreeHashState>());
            let paths = joined_length(source)?
                .checked_add(joined_length(destination)?)
                .and_then(|bytes| bytes.checked_add(relative_bytes))
                .and_then(|bytes| bytes.checked_mul(4))
                .and_then(|bytes| bytes.checked_add(2 * name_bytes))
                .and_then(|bytes| bytes.checked_add(cells))
                .ok_or(GuestRootTreeErrorV1::InvalidTree)?;
            let bytes = u64::try_from(paths).map_err(|_| GuestRootTreeErrorV1::InvalidTree)?;
            self.reserve_shape(
                ResourceVector::ZERO
                    .with(D::MemoryBytes, bytes)
                    .with(D::MetadataEntries, 1),
            )?;
        }
        self.scheduled_entries = next;
        Ok(())
    }
}
