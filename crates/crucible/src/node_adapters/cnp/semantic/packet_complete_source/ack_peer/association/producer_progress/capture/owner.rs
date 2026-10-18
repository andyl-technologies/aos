//! Owns the one real Source-side Capture transaction through every failed phase.
//!
//! The enclosing registered Source installs this inline owner before any SDK
//! or decoded graph argument is allocated. The genuine Window quote funds all
//! argument construction separately; this owner never creates a ticket or row.

use super::{
    bridge::CaptureAdminBridge, post_confirmation::CapturePostConfirmationOwners,
    prefix::CapturePrefixOwners, sdk_effect::CaptureSdkOwners,
};
use crate::{
    node_adapters::cnp::PacketCompleteSemanticSource,
    node_admission::{OriginalRestoredCaptureClaim, OriginalRestoredCaptureSigningInputs},
    node_contract::RuntimeError,
};
use crucible_node_contract::{ContentRef, Id, U64};
use crucible_node_provider::{
    client::{
        CnpController, OriginalCanonicalBlobAckEmitter,
        OriginalRestoredSettledCaptureConstructionData,
    },
    reference_packet::{
        control::PacketNative5UnderlyingRecord,
        service::{
            PacketNative5SourceLaunch,
            complete_restore::{
                PacketNativeRestoredRecord,
                settled_recapture::PacketRestoredSettledCaptureOutputLimits,
            },
            native_startup::{
                PacketRestoredSettledCaptureUploadGeometryData,
                PacketRestoredSettledNativeOutputValidationStorageData,
            },
        },
    },
};

#[derive(Clone, Copy, Eq, PartialEq)]
enum Stage {
    Unused,
    Preparing,
    Prepared,
    Capturing,
    Confirming,
    Complete,
}

pub(in crate::node_adapters::cnp::semantic::packet_complete_source::ack_peer::association) struct CaptureOnceOwner
{
    stage: Stage,
    pub(super) construction: super::effect::CaptureConstructionOwners,
    prefix: CapturePrefixOwners,
    pub(super) materialization: std::cell::RefCell<super::effect::CaptureMaterializationOwner>,
    transport: Option<CaptureSdkOwners>,
    post_confirmation: CapturePostConfirmationOwners,
}

impl CaptureOnceOwner {
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source::ack_peer::association) fn new_data()
    -> Self {
        Self {
            stage: Stage::Unused,
            construction: super::effect::CaptureConstructionOwners::empty(),
            prefix: CapturePrefixOwners::new_data(),
            materialization: std::cell::RefCell::new(
                super::effect::CaptureMaterializationOwner::empty(),
            ),
            transport: None,
            post_confirmation: CapturePostConfirmationOwners::new_data(),
        }
    }

    /// Retains the actual pre-upload current history and coordinator body.
    ///
    /// The distinct genuine claim and full construction row precede this
    /// allocation. The borrowed logical view must come from the same current
    /// Source, Node and SDK owners; no historical decoded view is substituted.
    pub(super) fn prepare_prefix_data<History: serde::Serialize + ?Sized>(
        &mut self,
        source: &PacketCompleteSemanticSource,
        controller: *const CnpController,
        claim: &OriginalRestoredCaptureClaim<'_>,
        history: &History,
        maximum_checkpoint: usize,
        maximum_prefix: usize,
        recheck_read: &mut dyn FnMut() -> Result<(), RuntimeError>,
    ) -> Result<(), RuntimeError> {
        if self.stage != Stage::Unused {
            return Err(RuntimeError::OutstandingObligations);
        }
        self.stage = Stage::Preparing;
        self.prefix.encode_data(
            source,
            controller,
            claim,
            history,
            maximum_checkpoint,
            maximum_prefix,
            recheck_read,
        )?;
        self.stage = Stage::Prepared;
        Ok(())
    }

    pub(super) fn prefix_payload_data(&self) -> Result<(&ContentRef, &[u8]), RuntimeError> {
        if self.stage != Stage::Prepared {
            return Err(RuntimeError::OutstandingObligations);
        }
        self.prefix.payload_data()
    }

    /// Lends the original uploaded prefix only after actual Capture completion.
    ///
    /// # Errors
    /// Refuses an earlier phase, absent prefix custody or changed full bytes.
    pub(super) fn completed_prefix_payload17_data(
        &self,
    ) -> Result<(&ContentRef, &[u8]), RuntimeError> {
        if self.stage != Stage::Complete {
            return Err(RuntimeError::OutstandingObligations);
        }
        self.prefix.payload_data()
    }

    /// Runs one admitted Capture and preserves its independent Source originals.
    ///
    /// The caller holds its real SourceRead across this entire action, including
    /// every upload, the fourth response, and both final current fences. This
    /// private entry accepts the nonconstructible live claim rather than stored
    /// coordinate or quote DATA. A refusal cannot reset the Source once owner.
    pub(super) fn run_data(
        &mut self,
        transport: CaptureSdkOwners,
        source: &PacketCompleteSemanticSource,
        controller: &mut CnpController,
        emitter: &OriginalCanonicalBlobAckEmitter,
        inputs: &OriginalRestoredCaptureSigningInputs<'_>,
        claim: &OriginalRestoredCaptureClaim<'_>,
        launch: &PacketNative5SourceLaunch,
        canonical_launch5: &[u8],
        confirmation_id: Id,
        sdk: &OriginalRestoredSettledCaptureConstructionData,
        geometry: &PacketRestoredSettledCaptureUploadGeometryData,
        limits: &PacketRestoredSettledCaptureOutputLimits,
        validation: &PacketRestoredSettledNativeOutputValidationStorageData,
        record: &PacketNativeRestoredRecord,
        underlying: &PacketNative5UnderlyingRecord,
        measurement: &ContentRef,
        checkpoint_frontier: U64,
        key: &[u8; 32],
        recheck_read: &mut dyn FnMut() -> Result<(), RuntimeError>,
    ) -> Result<(), RuntimeError> {
        if self.stage != Stage::Prepared || self.transport.is_some() {
            return Err(RuntimeError::OutstandingObligations);
        }
        // Retain before validation or transport assignment. Even a failed
        // initial current fence keeps every independently constructed argument.
        self.transport = Some(transport);
        self.stage = Stage::Capturing;
        claim.authenticate_inputs_data(inputs)?;
        inputs.authenticate_current_data()?;
        let actual_limits = source.original_completed_restored_settled_startup_data()?;
        if &actual_limits.output_limits != limits {
            return Err(RuntimeError::ForeignAuthority);
        }
        source.with_original_completed_restored_settled_startup_data(|native| {
            let expected = native
                .source_output_validation_data()
                .map_err(|_| RuntimeError::ResourceLimit)?;
            if &expected != validation {
                return Err(RuntimeError::ForeignAuthority);
            }
            Ok(())
        })?;
        let prefix = self.prefix.payload_data()?;
        let transport = self
            .transport
            .as_mut()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        transport.authenticate_prefix_payload_data(prefix)?;
        let request = transport.request_data();
        if &request.current_record != measurement
            || request.current_model != record.native_receipt.native_record
            || request.history_next_sequence != checkpoint_frontier
        {
            return Err(RuntimeError::InvalidReceipt);
        }
        transport.capture_data(
            source,
            controller,
            emitter,
            claim,
            launch,
            canonical_launch5,
            sdk,
            geometry,
            key,
            recheck_read,
        )?;
        self.stage = Stage::Confirming;
        self.post_confirmation.complete_data(
            transport,
            source,
            controller,
            emitter,
            inputs,
            claim,
            confirmation_id,
            sdk,
            limits,
            validation,
            record,
            underlying,
            measurement,
            key,
            recheck_read,
        )?;
        self.stage = Stage::Complete;
        Ok(())
    }

    pub(in crate::node_adapters::cnp::semantic::packet_complete_source::ack_peer::association) fn is_used_data(
        &self,
    ) -> bool {
        self.stage != Stage::Unused
            || self.transport.is_some()
            || self.construction.is_started_data()
    }

    pub(super) fn current_bridge_data(&self) -> Result<&CaptureAdminBridge, RuntimeError> {
        if self.stage != Stage::Complete {
            return Err(RuntimeError::OutstandingObligations);
        }
        self.post_confirmation.current_bridge_data()
    }

    pub(in crate::node_adapters::cnp::semantic::packet_complete_source::ack_peer::association) fn retained_storage_data(
        &self,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        let Self {
            stage: _,
            construction,
            prefix,
            materialization,
            transport,
            post_confirmation,
        } = self;
        let materialization = materialization
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let copies = materialization.retained_storage_data(maximum)?;
        let prefix = prefix.retained_storage_data(maximum)?;
        let post = post_confirmation.retained_storage_data(maximum)?;
        let transport = transport
            .as_ref()
            .map_or(Ok(0), |owner| owner.retained_storage_data(maximum))?;
        post.checked_add(construction.retained_storage_data(maximum)?)
            .and_then(|bytes| bytes.checked_add(prefix))
            .and_then(|bytes| bytes.checked_add(transport))
            .and_then(|bytes| bytes.checked_add(copies))
            .filter(|requested| *requested <= maximum)
            .ok_or(RuntimeError::ResourceLimit)
    }

    pub(super) fn counter_scratch_data() -> usize {
        use std::mem::size_of;
        Self::housekeeping_counter_scratch_data()
            + size_of::<Self>()
            + size_of::<&Self>()
            + size_of::<&mut Self>()
            + size_of::<Stage>()
            + size_of::<Option<CaptureSdkOwners>>()
            + size_of::<Option<&CaptureSdkOwners>>()
            + size_of::<Option<&mut CaptureSdkOwners>>()
            + size_of::<Result<&CaptureAdminBridge, RuntimeError>>()
            + size_of::<Result<usize, RuntimeError>>()
            + size_of::<Result<(), RuntimeError>>()
            + size_of::<Option<usize>>()
            + size_of::<&PacketCompleteSemanticSource>()
            + size_of::<&mut CnpController>()
            + size_of::<&OriginalCanonicalBlobAckEmitter>()
            + size_of::<&OriginalRestoredCaptureClaim<'static>>()
            + size_of::<&OriginalRestoredCaptureSigningInputs<'static>>()
            + size_of::<&PacketNative5SourceLaunch>()
            + size_of::<&[u8]>()
            + size_of::<Id>()
            + size_of::<&OriginalRestoredSettledCaptureConstructionData>()
            + size_of::<&PacketRestoredSettledCaptureUploadGeometryData>()
            + size_of::<&PacketRestoredSettledCaptureOutputLimits>()
            + size_of::<&PacketRestoredSettledNativeOutputValidationStorageData>()
            + size_of::<&PacketNativeRestoredRecord>()
            + size_of::<&PacketNative5UnderlyingRecord>()
            + size_of::<&ContentRef>()
            + size_of::<(&ContentRef, &[u8])>()
            + size_of::<&[u8; 32]>()
            + size_of::<&mut dyn FnMut() -> Result<(), RuntimeError>>()
            + super::effect::CaptureMaterializationOwner::counter_scratch_data()
            + CapturePrefixOwners::counter_scratch_data()
            + CaptureSdkOwners::counter_scratch_data()
            + CapturePostConfirmationOwners::counter_scratch_data()
    }
}

#[path = "owner/ledger.rs"]
mod ledger;
pub(in crate::node_adapters::cnp::semantic::packet_complete_source) use ledger::{
    CapturePreEncoderCut, CapturePrefixEncoder,
};

#[path = "owner/effect.rs"]
mod effect;
