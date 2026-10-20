//! Reached raw Inventory and semantic collection destinations.
//!
//! The same validator owns both ordinary and retained paths. These fields are
//! DATA, not authenticated inventory or a receiving/funding original.

use super::*;
use crate::capture::DescriptorCaptureV1;

#[derive(Default)]
pub(crate) struct InventoryResponseCaptureV1 {
    pub(super) message: InventoryStorageResourcesResponse,
    pub(super) decode: Option<Result<(), buffa::DecodeError>>,
    pub(super) workspaces: WorkspaceCollectionCaptureV1,
    pub(super) completed_workspaces: Vec<ValidatedStorageWorkspace>,
    pub(super) lifecycle: LifecycleCaptureV1,
    pub(super) repairs: Vec<ValidatedStorageOperatorRepairCommitV1>,
    result: Option<Result<(ValidatedStorageInventory, InventoryStorageResourcesResponse), ProtocolValidationError>>,
    entered: bool,
}

impl InventoryResponseCaptureV1 {
    pub(crate) fn decode_once(&mut self, bytes: &[u8], maximum: u32) -> Result<(), ProtocolValidationError> {
        if self.entered {
            return Err(ProtocolValidationError::InvalidField("repeated Inventory capture"));
        }
        self.entered = true;
        let result = super::decode_inventory_response_engine(bytes, maximum, Some(self));
        let returned = result.as_ref().map(|_| ()).map_err(Clone::clone);
        self.result = Some(result);
        returned
    }

    pub(crate) fn value(&self) -> Option<&(ValidatedStorageInventory, InventoryStorageResourcesResponse)> {
        self.result.as_ref()?.as_ref().ok()
    }

    // Moves only a successful passive model. A refusal keeps its exact Result
    // in the original capture, including all previously reached decoder fields.
    pub(crate) fn take_value_data_v2(&mut self)
        -> Option<(ValidatedStorageInventory, InventoryStorageResourcesResponse)> {
        match self.result.take() {
            Some(Ok(value)) => Some(value),
            retained => { self.result = retained; None }
        }
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.decode.as_ref().and_then(|value| value.as_ref().err())
            .map(|cause| cause as &(dyn std::error::Error + 'static))
            .or_else(|| self.workspaces.row.descriptor.failure())
            .or_else(|| self.result.as_ref().and_then(|value| value.as_ref().err())
                .map(|cause| cause as &(dyn std::error::Error + 'static)))
    }
}

#[derive(Default)]
pub(super) struct WorkspaceCollectionCaptureV1 {
    pub(super) workspaces: Vec<ValidatedStorageWorkspace>,
    pub(super) physical: BTreeSet<(u64, u64)>,
    pub(super) datasets: BTreeSet<u64>,
    pub(super) ranges: Vec<(u32, u32)>,
    pub(super) current: Option<ValidatedStorageWorkspace>,
    pub(super) row: WorkspaceRowCaptureV1,
}

#[derive(Default)]
pub(super) struct WorkspaceRowCaptureV1 {
    pub(super) fence: Option<ValidatedAssignmentFence>,
    pub(super) root_image: Option<ObjectDescriptor>,
    pub(super) descriptor: DescriptorCaptureV1,
    pub(super) proof: Option<GuestRootPublicationProofV1>,
    pub(super) current_publication: Option<crate::semantics::storage_guest_root::StorageGuestRootCurrentPublicationDataV2>,
}

#[derive(Default)]
pub(super) struct LifecycleCaptureV1 {
    pub(super) checkpoint_requests: BTreeSet<[u8; 16]>,
}

// The ordinary path retains its borrowed-key representation and disposal. The
// selected index owns fixed validated bytes so no self-references are stored.
pub(super) enum CheckpointRequestsV1<'destination, 'wire> {
    Local(BTreeSet<&'wire Vec<u8>>),
    Retained(&'destination mut BTreeSet<[u8; 16]>),
}

impl<'destination, 'wire> CheckpointRequestsV1<'destination, 'wire> {
    pub(super) fn new(destination: Option<&'destination mut LifecycleCaptureV1>) -> Self {
        match destination {
            Some(destination) => Self::Retained(&mut destination.checkpoint_requests),
            None => Self::Local(BTreeSet::new()),
        }
    }

    pub(super) fn insert(&mut self, bytes: &'wire Vec<u8>) -> Result<bool, ProtocolValidationError> {
        match self {
            Self::Local(index) => Ok(index.insert(bytes)),
            Self::Retained(index) => Ok(index.insert(exact_nonzero::<16>(
                bytes, "storage atomic checkpoint request",
            )?)),
        }
    }
}
