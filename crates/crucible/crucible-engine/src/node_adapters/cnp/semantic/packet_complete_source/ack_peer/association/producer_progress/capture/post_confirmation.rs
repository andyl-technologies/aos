//! Retains the actual fourth SDK reply, decoded graph and administrative bridge.
//!
//! The Source attempt owns this slot before confirmation can allocate or write.
//! A failed decode keeps its raw/current graph attempt in this same owner. The
//! later Source Journal is intentionally absent from these native checks.

#[path = "post_confirmation/capacities.rs"]
mod capacities;

use super::{
    bridge::CaptureAdminBridge, confirmation::CaptureConfirmationOwners,
    sdk_effect::CaptureSdkOwners,
};
use crate::{
    node_adapters::cnp::PacketCompleteSemanticSource,
    node_admission::{OriginalRestoredCaptureClaim, OriginalRestoredCaptureSigningInputs},
    node_contract::RuntimeError,
};
use crucible_node_format::{ContentRef, Id};
use crucible_node_transport::{
    client::{
        CnpController, OriginalCanonicalBlobAckEmitter,
        OriginalRestoredSettledCaptureConstructionData,
    },
    protocol_snapshot::restored_settled17::{
        RestoredSettledNative17CaptureOutputPlan, RestoredSettledNative17DecodeAttempt,
        ValidatedRestoredSettledNative17CaptureOutputs,
    },
    reference_packet::{
        control::PacketNative5UnderlyingRecord,
        service::{
            complete_restore::{
                PacketNativeRestoredRecord,
                settled_recapture::PacketRestoredSettledCaptureOutputLimits,
            },
            native_startup::PacketRestoredSettledNativeOutputValidationStorageData,
        },
    },
};

#[derive(Clone, Copy, Eq, PartialEq)]
enum Stage {
    Retained,
    Confirming,
    Decoding,
    Bridging,
    Complete,
}

/// Owns each distinct post-Capture stage through success or refusal.
///
/// The attempt and validated output are separate slots. The defining native
/// reader moves a completed attempt once; an unfinished attempt never leaves
/// this owner merely because a later validation returned an error.
pub(super) struct CapturePostConfirmationOwners {
    stage: Stage,
    confirmation: CaptureConfirmationOwners,
    native_attempt: Option<RestoredSettledNative17DecodeAttempt>,
    native_output: Option<ValidatedRestoredSettledNative17CaptureOutputs>,
    bridge: Option<CaptureAdminBridge>,
}

impl CapturePostConfirmationOwners {
    pub(super) fn new_data() -> Self {
        Self {
            stage: Stage::Retained,
            confirmation: CaptureConfirmationOwners::new_data(),
            native_attempt: None,
            native_output: None,
            bridge: None,
        }
    }

    /// Completes the real retained SDK transaction before issuing a local bridge.
    ///
    /// The caller keeps its genuine SourceRead armed throughout. Independent
    /// Source decoder credit must precede this call; native-process reserves
    /// cannot fund the second process's raw and typed decoding owners.
    pub(super) fn complete_data(
        &mut self,
        captured: &CaptureSdkOwners,
        source: &PacketCompleteSemanticSource,
        controller: &mut CnpController,
        emitter: &OriginalCanonicalBlobAckEmitter,
        inputs: &OriginalRestoredCaptureSigningInputs<'_>,
        claim: &OriginalRestoredCaptureClaim<'_>,
        confirmation_id: Id,
        sdk: &OriginalRestoredSettledCaptureConstructionData,
        limits: &PacketRestoredSettledCaptureOutputLimits,
        validation: &PacketRestoredSettledNativeOutputValidationStorageData,
        record: &PacketNativeRestoredRecord,
        underlying: &PacketNative5UnderlyingRecord,
        measurement: &ContentRef,
        key: &[u8; 32],
        recheck_read: &mut dyn FnMut() -> Result<(), RuntimeError>,
    ) -> Result<(), RuntimeError> {
        if self.stage != Stage::Retained {
            return Err(RuntimeError::OutstandingObligations);
        }
        // Spend before the first fallible precondition. Retrying a refused
        // confirmation must not assign another original or renew its cut.
        self.stage = Stage::Confirming;
        captured.captured_data()?;
        claim.authenticate_inputs_data(inputs)?;
        inputs.authenticate_current_data()?;
        claim.authenticate_current_data(source, controller as *const _)?;
        recheck_read()?;

        {
            let mut marker = controller
                .original_restored_settled_capture_marker_data(emitter)
                .map_err(|_| RuntimeError::InvalidReceipt)?;
            self.confirmation.publish_data(
                &mut marker,
                emitter,
                confirmation_id,
                sdk,
                recheck_read,
            )?;
        }

        claim.authenticate_current_data(source, controller as *const _)?;
        recheck_read()?;
        self.stage = Stage::Decoding;

        let completed = controller
            .original_completed_restored_settled_capture_data(emitter)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        // All four bodies come from the actual completed loan, whose constructor
        // checks the same literal journal pairs and unchanged final frontier.
        let plan = RestoredSettledNative17CaptureOutputPlan::validate_data(&completed, limits)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        plan.validate_retained_outputs_into(
            &mut self.native_attempt,
            &mut self.native_output,
            validation,
        )
        .map_err(|_| RuntimeError::InvalidReceipt)?;
        let native = self
            .native_output
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        native
            .authenticate_current_checkpoint_data(record, underlying, measurement)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        recheck_read()?;
        self.stage = Stage::Bridging;

        CaptureAdminBridge::retain_into(
            source,
            controller,
            inputs,
            claim,
            &completed,
            native,
            captured.signatures_data(),
            sdk.maximum_frame_bytes_data(),
            record,
            underlying,
            measurement,
            key,
            &mut self.bridge,
            recheck_read,
        )?;
        // A partial bridge is retained even when this final current fence fails.
        claim.authenticate_current_data(source, controller as *const _)?;
        recheck_read()?;
        inputs.authenticate_current_data()?;
        self.stage = Stage::Complete;
        Ok(())
    }

    pub(super) fn current_bridge_data(&self) -> Result<&CaptureAdminBridge, RuntimeError> {
        if self.stage != Stage::Complete {
            return Err(RuntimeError::OutstandingObligations);
        }
        self.bridge.as_ref().ok_or(RuntimeError::OwnerUnavailable)
    }

    /// Counts every initialized owner independently, including refused partials.
    pub(super) fn retained_storage_data(&self, maximum: usize) -> Result<usize, RuntimeError> {
        let Self {
            stage: _,
            confirmation,
            native_attempt,
            native_output,
            bridge,
        } = self;
        let mut requested = confirmation.retained_storage_data(maximum)?;
        if let Some(attempt) = native_attempt {
            requested = add(
                requested,
                attempt
                    .retained_requested_storage_data(maximum)
                    .map_err(|_| RuntimeError::ResourceLimit)?,
                maximum,
            )?;
        }
        if let Some(output) = native_output {
            requested = add(
                requested,
                output
                    .retained_requested_storage_data(maximum)
                    .map_err(|_| RuntimeError::ResourceLimit)?,
                maximum,
            )?;
        }
        if let Some(bridge) = bridge {
            requested = add(requested, bridge.retained_storage_data(maximum)?, maximum)?;
        }
        Ok(requested)
    }

    pub(super) fn counter_scratch_data() -> usize {
        use std::mem::size_of;
        size_of::<Self>()
            + size_of::<Option<Self>>()
            + size_of::<&Self>()
            + size_of::<&mut Self>()
            + size_of::<Stage>()
            + size_of::<&CaptureSdkOwners>()
            + size_of::<Option<RestoredSettledNative17DecodeAttempt>>()
            + size_of::<Option<ValidatedRestoredSettledNative17CaptureOutputs>>()
            + size_of::<Option<CaptureAdminBridge>>()
            + size_of::<Result<&CaptureAdminBridge, RuntimeError>>()
            + size_of::<Result<(), RuntimeError>>()
            + size_of::<Result<usize, RuntimeError>>()
            + size_of::<Option<usize>>()
            + size_of::<&PacketCompleteSemanticSource>()
            + size_of::<&mut CnpController>()
            + size_of::<&OriginalCanonicalBlobAckEmitter>()
            + size_of::<&OriginalRestoredCaptureClaim<'static>>()
            + size_of::<&OriginalRestoredCaptureSigningInputs<'static>>()
            + size_of::<&OriginalRestoredSettledCaptureConstructionData>()
            + size_of::<&PacketRestoredSettledCaptureOutputLimits>()
            + size_of::<&PacketRestoredSettledNativeOutputValidationStorageData>()
            + size_of::<&PacketNativeRestoredRecord>()
            + size_of::<&PacketNative5UnderlyingRecord>()
            + size_of::<&ContentRef>()
            + size_of::<&[u8; 32]>()
            + size_of::<&mut dyn FnMut() -> Result<(), RuntimeError>>()
            + size_of::<
                crucible_node_transport::client::OriginalCompletedRestoredSettledCaptureData<
                    'static,
                >,
            >()
            + size_of::<RestoredSettledNative17CaptureOutputPlan<'static>>()
            + size_of::<
                Result<
                    RestoredSettledNative17CaptureOutputPlan<'static>,
                    crucible_node_transport::ProviderError,
                >,
            >()
            + CaptureConfirmationOwners::counter_scratch_data()
            + CaptureAdminBridge::counter_scratch_data()
    }
}

fn add(left: usize, right: usize, maximum: usize) -> Result<usize, RuntimeError> {
    left.checked_add(right)
        .filter(|requested| *requested <= maximum)
        .ok_or(RuntimeError::ResourceLimit)
}

impl CapturePostConfirmationOwners {
    /// Borrows the actual fully validated outputs after the Bridge completed.
    pub(super) fn current_native_outputs17_data(
        &self,
    ) -> Result<&ValidatedRestoredSettledNative17CaptureOutputs, RuntimeError> {
        self.current_bridge_data()?;
        self.native_output
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)
    }
}
