//! Quotes the real Root4 fixed owner before its first constructor.

use super::super::super::{
    initial_geometry, initial_ready_controls,
    preopen_geometry::ProtectedJournalPreopenReplayExtentV1,
};
use super::*;
use aos_sandbox_broker::receiving::RootSelectedControllerSubjectSampleV1;
use aos_sandbox_broker::receiving::RootSubjectReadinessV1;
use aos_sandbox_model::ResourceDimension as D;
use std::mem::size_of;

impl RootSignedBoundOriginalV1 {
    pub(in crate::native::root_current) fn fixed_demand_v1(
        held: &ProtectedJournalPreopenReplayExtentV1,
        supplement: ResourceVector,
        admitted: &RootUseAdmittedOriginalV1,
    ) -> Result<ResourceVector, NativeError> {
        let invalid = NativeError::geometry;
        let receipt = admitted.completed_receipt_v1().map_err(|_| invalid())?;
        let extent=super::super::super::preopen_geometry::protected_authority_preopen_replay_extent_for_prefix_v1(
            held.limits_v1(),receipt.after_end).map_err(NativeError::Mechanical)?;
        let chunk = aos_sandbox_protocol::domain_ledger::create_q04_history::CLAIM_CHUNK_BYTES;
        let diagnostic = size_of::<(&Self, Option<&(dyn Error + 'static)>)>()
            .checked_mul(2)
            .ok_or_else(invalid)?;
        let owner = size_of::<Self>()
            .checked_mul(2)
            .and_then(|bytes| bytes.checked_add(chunk))
            .and_then(|bytes| bytes.checked_add(FRAME_HEADER_BYTES * 2 + 48))
            .and_then(|bytes| bytes.checked_add(diagnostic))
            .and_then(|bytes| bytes.checked_add(Self::construction_control_bytes_v1()?))
            .ok_or_else(invalid)?;
        let base = initial_geometry::continuation_append_demand_v1(
            &extent,
            supplement,
            SIGNED_BOUND_BODY_BYTES_V1,
            FRAME_BYTES + FRAME_HEADER_BYTES + 48,
            owner,
        )?;
        let subject: Result<ResourceVector, NativeError> = aos_sandbox_broker::root_subject_receiving_demand_v1! {
            sample:RootSelectedControllerSubjectSampleV1,readiness:RootSubjectReadinessV1,error:NativeError::geometry(),
        };
        let post = initial_geometry::history_post_demand_v1()?;
        // Unlike Root2/Root3 these controls are created AFTER this fixed fee.
        // Their twelve identities therefore belong here, not incoming forecast.
        let cells=crate::native::journal::names::RootPolicyNameObservationOriginalV1::retained_control_cells_v1()
            .checked_mul(12).ok_or_else(invalid)?;
        let clock = initial_ready_controls::clock_demand_v1()?;
        base.checked_add(subject?)
            .and_then(|v| v.checked_add(clock))
            .map_err(|_| invalid())?
            .checked_add(post)
            .and_then(|v| v.checked_add(post))
            .and_then(|v| v.checked_add(ResourceVector::ZERO.with(D::MetadataEntries, cells)))
            .map_err(|_| invalid())
    }
}

impl RootSignedBoundOriginalV1 {
    pub(in crate::native::root_current) fn construction_control_bytes_v1() -> Option<usize> {
        use super::super::signed_input::RootSignedInputOriginalV1;
        let nested = size_of::<RootSignedReceivedOriginalV1>()
            .checked_mul(2)?
            .checked_add(size_of::<RootInitialStageOriginalV1>().checked_mul(4)?)?
            .checked_add(size_of::<RootInitialOpenPostsOriginalV1>().checked_mul(8)?)?
            .checked_add(
                size_of::<RootCurrentHistoryPairV1<SIGNED_BOUND_RECORD_BYTES_V1>>()
                    .checked_mul(2)?,
            )?
            .checked_add(size_of::<RootSignedVerificationV1>().checked_mul(2)?)?
            .checked_add(size_of::<SliceDeadlineStreamIoV1>().checked_mul(2)?)?;
        // The pair constructs its own crossing owner before returning. Its
        // constructor and return are distinct from the resident Pair headers.
        let crossing = size_of::<super::super::super::initial_open::RootInitialOpenCrossingOriginalV1>()
            .checked_mul(2)?;
        // Four names in that crossing and four in each of the four Posts:
        // 4 + (2 received bookends + append post + send post) * 4 = 20.
        // The canonical supplier excludes the resident field already in Self.
        let names = crate::native::journal::names::RootPolicyNameObservationOriginalV1::
            fixed_carrier_demand_v1()?
            .get(D::MemoryBytes)
            .checked_mul(20)?;
        let names = usize::try_from(names).ok()?;
        nested.checked_add(crossing)?
            .checked_add(names)?
            .checked_add(RootSignedInputOriginalV1::receiving_construction_bytes_v1()?)
    }
}
