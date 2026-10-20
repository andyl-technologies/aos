//! Retains the one method31 target's complete post-worker physical readback.
//!
//! This uses the ordinary marker/template/label/root-identity engine once. The
//! genuine State31 caller pays fixed readback custody before entry and each
//! reached label/native prefix before growth. An expected proof or inventory
//! row alone cannot create payment or completion.

use super::*;
use aos_sandbox_core::{AccountingError, ResourceDimension as D, ResourceVector};
use aos_sandbox_guest_root_realization::guest_root_label::GuestRootLabelReadOriginalV1;

#[derive(Clone, Copy)]
enum Failure { Binding, Native, Missing }

pub(crate) struct GuestRootTargetReadbackOriginalV2 {
    row: PublicationReadbackRowV1,
    binding: Option<Result<(), GuestRootInventoryErrorV1>>,
    native: Option<Result<(bool, Option<std::os::fd::OwnedFd>), GuestRootInventoryErrorV1>>,
    expected: Option<GuestRootPublicationProofV1>,
    resource_digest: Option<[u8; 32]>,
    first: Option<Failure>,
    entered: bool,
    completed: bool,
}

impl GuestRootTargetReadbackOriginalV2 {
    pub(crate) fn new() -> Self {
        Self { row: PublicationReadbackRowV1::default(), binding: None, native: None,
            expected: None, resource_digest: None, first: None, entered: false, completed: false }
    }

    pub(crate) fn receiving_demand_v2(template: &ProtectedGuestRootTemplateV1, workspace: &ValidatedStorageWorkspace)
        -> Result<ResourceVector, AccountingError>
    {
        let invalid = || AccountingError::ArithmeticOverflow { dimension: D::MemoryBytes };
        let labels = GuestRootLabelReadOriginalV1::fixed_receiving_footprint_v1()
            .ok_or_else(invalid)?;
        let tree = template.comparison_receiving_demand_v2(Path::new(workspace.root_directory())).ok_or_else(invalid)?;
        let memory = 3usize.checked_mul(std::mem::size_of::<Self>())
            .and_then(|bytes| bytes.checked_add(8 * 4096 + 4 * 512))
            .and_then(|bytes| bytes.checked_add(labels.memory_bytes)).ok_or_else(invalid)?;
        let files = labels.open_files.checked_add(3).ok_or_else(invalid)?;
        // The recursive projection's namespace supplier includes its actual
        // fixed paths and rejected-next name. Control fields add bytes only.
        tree.checked_add(ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(memory).map_err(|_| invalid())?)
            .with(D::OpenFiles, u64::try_from(files).map_err(|_| invalid())?)
            .with(D::MetadataEntries, u64::try_from(labels.metadata_entries).map_err(|_| invalid())?))
    }

    pub(crate) fn observe_once_v2(
        &mut self, template: &ProtectedGuestRootTemplateV1, workspace: &ValidatedStorageWorkspace,
        pending: &crate::state::GuestRootStateRecordOriginalV2,
        worker: GuestRootPublicationProofV1,
        state: &aos_sandbox::Journal,
        receiving: &mut crate::state::encoding::StateEncodingLoanV1<'_, '_>,
    ) -> Result<(), GuestRootInventoryErrorV1> {
        if self.entered {
            self.completed = false;
            if !self.binding.as_ref().is_some_and(Result::is_err) {
                self.binding = Some(Err(GuestRootInventoryErrorV1::InvalidPublication));
            }
            self.first.get_or_insert(Failure::Binding);
            return Err(GuestRootInventoryErrorV1::Receiving);
        }
        self.entered = true;
        self.binding = Some((|| {
            let attempt = pending.attempt_v2().ok_or(GuestRootInventoryErrorV1::InvalidPublication)?;
            let expected = template.expected_proof(workspace);
            if worker != expected || attempt.expected_proof != expected
                || attempt.root_device != workspace.root_device() || attempt.root_inode != workspace.root_inode()
            { return Err(GuestRootInventoryErrorV1::InvalidPublication); }
            attempt.current_publication.require_creation_data_v2(
                workspace.fence().broker_assignment().map_err(|_| GuestRootInventoryErrorV1::InvalidPublication)?,
                expected, workspace.resource_digest(),
            ).map_err(|_| GuestRootInventoryErrorV1::InvalidPublication)?;
            self.expected = Some(expected);
            self.resource_digest = Some(*workspace.resource_digest());
            Ok(())
        })());
        if !matches!(self.binding, Some(Ok(()))) {
            self.first = Some(Failure::Binding);
            return Err(GuestRootInventoryErrorV1::Receiving);
        }
        let expected = self.expected.ok_or(GuestRootInventoryErrorV1::InvalidPublication)?;
        self.row.retain_complete_projection = true;
        let mut labels = GuestRootLabelReceivingV2::state_v2(state, receiving);
        self.native = Some(read_publication_row_v1(Path::new(workspace.root_directory()), workspace,
            template, expected, Some(&mut self.row), Some(&mut labels)));
        match self.native.as_ref() {
            Some(Ok((true, None))) => { self.completed = true; Ok(()) }
            Some(Ok(_)) => { self.first = Some(Failure::Missing); Err(GuestRootInventoryErrorV1::InvalidPublication) }
            _ => { self.first = Some(Failure::Native); Err(GuestRootInventoryErrorV1::Receiving) }
        }
    }

    pub(crate) fn requires_pending_v2(&self, pending: &crate::state::GuestRootStateRecordOriginalV2) -> bool {
        let Some(attempt) = pending.attempt_v2() else { return false; };
        self.completed && self.first.is_none() && self.expected == Some(attempt.expected_proof)
            && self.resource_digest.as_ref() == Some(attempt.current_publication.creation_resource_digest_v2())
            && self.row.marker.retained_projection_completed_v2()
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        fn error<T, E: std::error::Error + 'static>(slot: &Option<Result<T, E>>)
            -> Option<&(dyn std::error::Error + 'static)>
        { slot.as_ref()?.as_ref().err().map(|cause| cause as _) }
        match self.first? {
            Failure::Binding => error(&self.binding),
            Failure::Native => match self.row.first {
                Some(ReadbackNativeFailureV1::Before) => error(&self.row.before),
                Some(ReadbackNativeFailureV1::Presence) => error(&self.row.marker_presence),
                Some(ReadbackNativeFailureV1::Marker) => {
                    if self.row.marker.retained_projection_admission_refused_v2() {
                        self.row.label_invoice.failure_v2().or_else(|| self.row.marker.failure())
                    } else { self.row.marker.failure().or_else(|| error(&self.row.marker_result)) }
                },
                Some(ReadbackNativeFailureV1::Root) => error(&self.row.root),
                Some(ReadbackNativeFailureV1::Labels) => error(&self.row.labels),
                Some(ReadbackNativeFailureV1::After) => error(&self.row.after),
                Some(ReadbackNativeFailureV1::CurrentPublication) => error(&self.row.current_publication),
                None => error(&self.native),
            },
            Failure::Missing => Some(&GuestRootInventoryErrorV1::InvalidPublication),
        }
    }
}
