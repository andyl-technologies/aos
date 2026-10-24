//! Lends actual completed Capture custody before dynamic work is admitted.
//!
//! Only private completed live owners are accepted. Their genuine once path
//! already authenticated the immutable schema definitions. Rechecking the same
//! installed actor/codec/negotiation and retained journal requires no schema
//! factory, canonical copy, digest String or historical DTO conversion.

use super::*;
use crate::reference_packet::{
    control::PacketControlSelection,
    service::{
        complete_restore::settled_recapture::{
            PACKET_RESTORED_SETTLED_INPUT_REACTIVE_FEATURE,
            PACKET_RESTORED_SETTLED_RECAPTURE_FEATURE,
        },
        restored_input_reactive17, restored_settled_capture, restored_settled_confirmation,
    },
};

const FEATURES: [&str; 6] = [
    PACKET_RESTORED_SETTLED_RECAPTURE_FEATURE,
    PACKET_RESTORED_SETTLED_INPUT_REACTIVE_FEATURE,
    restored_input_reactive17::RESTORED_INPUT_REACTIVE17_FEATURE,
    restored_settled_capture::RESTORED_SETTLED_CAPTURE_FEATURE,
    restored_settled_capture::upload::RESTORED_SETTLED_CAPTURE_UPLOAD_FEATURE,
    restored_settled_confirmation::PACKET_RESTORED_SETTLED_AFTER_CONFIRMATION_FEATURE,
];

impl CnpController {
    /// Borrows actual completed Capture custody using fixed scratch only.
    ///
    /// The Source must hold its private completed Capture bridge. Any caller
    /// asserting native checkpoint currency must also hold and recheck its
    /// genuine same-Source read/claim. This is a correspondence loan, not a
    /// decoder or a means to issue a new Capture, restore, native action or
    /// allocation permission.
    /// The ordinary full current lender remains the admitted validation path.
    ///
    /// # Errors
    /// Refuses another actor/emitter/immutable codec, revoked negotiation,
    /// missing or incomplete actual once owners, changed journal/typed receipt,
    /// unavailable or changed retained content, or an advanced SDK frontier.
    pub fn original_completed_restored_settled_capture_precredit_data(
        &self,
        emitter: &OriginalCanonicalBlobAckEmitter,
    ) -> Result<OriginalCompletedRestoredSettledCaptureData<'_>, ProviderError> {
        self.authenticate_completed_capture17_cached_selection_data(emitter)?;
        let capture = self
            .original_restored_settled_capture
            .as_ref()
            .ok_or_else(refused)?;
        let confirmation = capture.confirmation.as_ref().ok_or_else(refused)?;
        if capture.stage != Stage::Complete
            || confirmation.stage != ConfirmationStage::Complete
            || capture.prefix_frontier != Some(capture.request.history_next_sequence)
        {
            return Err(refused());
        }
        let frontier = confirmation.frontier.ok_or_else(refused)?;
        if frontier != self.session.fresh_restore_query_sequence()? {
            return Err(refused());
        }
        let capture_original = capture.original.as_ref().ok_or_else(refused)?;
        let capture_terminal = capture.terminal.as_ref().ok_or_else(refused)?;
        let confirmation_original = confirmation.original.as_ref().ok_or_else(refused)?;
        let confirmation_terminal = confirmation.terminal.as_ref().ok_or_else(refused)?;
        authenticate_pair(
            self,
            &capture.request_id,
            capture_original,
            capture_terminal,
        )?;
        authenticate_pair(
            self,
            &confirmation.request_id,
            confirmation_original,
            confirmation_terminal,
        )?;

        let capture_body = capture.decoded.as_deref().ok_or_else(refused)?;
        let confirmation_body = confirmation.decoded.as_deref().ok_or_else(refused)?;
        let Some(MethodResult::Capture(result)) = &capture_body.result else {
            return Err(refused());
        };
        let Some(MethodResult::Poll(poll)) = &confirmation_body.result else {
            return Err(refused());
        };
        let receipt = confirmation.receipt.as_ref().ok_or_else(refused)?;
        if !matches!(
            &capture_body.shape,
            crate::bodies::ResponseShape::Completed {
                operation_state: crate::bodies::OperationState::Completed,
                ..
            }
        ) || !matches!(
            &confirmation_body.shape,
            crate::bodies::ResponseShape::Completed {
                operation_state: crate::bodies::OperationState::Completed,
                ..
            }
        ) || result.owner_state_refs.len() != 1
            || receipt.capture != confirmation.request
            || receipt.capture.capture_request_id != capture.request_id
            || receipt.capture.capture_operation_id != capture.operation_id
            || receipt.capture.native_snapshot_ref != result.capture_manifest
            || receipt.capture.native_control_ref != result.owner_state_refs[0]
            || receipt.capture.native_anchor_ref != result.unchanged_cut_receipt
            || poll.operation_id != capture.operation_id
            || !poll.observations.is_empty()
            || poll.next_observation_sequence != U64::new(0)
            || poll.outcome.0.as_ref() != Some(&capture_terminal.body)
        {
            return Err(refused());
        }
        self.custody
            .content()
            .original_completed_capture17_body_precredit_data(&receipt.native_after_ref)?;
        emitter.authenticate_original(self)?;
        if frontier != self.session.fresh_restore_query_sequence()? {
            return Err(refused());
        }
        Ok(OriginalCompletedRestoredSettledCaptureData {
            controller: self,
            capture,
            confirmation,
            frontier,
            capture_original,
            capture_terminal,
            capture_body,
            confirmation_original,
            confirmation_terminal,
            confirmation_body,
            receipt,
        })
    }

    // This fixed check authenticates original parents, negotiated features and
    // the actual completed first Observe. Callers independently distinguish an
    // absent, partial or completed Capture owner. It does not authenticate supplied
    // schemas: genuine Source declaration/action admission keeps those full checks.
    pub(in crate::client::controller::settled_capture) fn authenticate_completed_capture17_cached_selection_data(
        &self,
        emitter: &OriginalCanonicalBlobAckEmitter,
    ) -> Result<(), ProviderError> {
        emitter.authenticate_original(self)?;
        self.protocol_owner.ensure_current()?;
        if self.fenced {
            return Err(refused());
        }
        let selection = self.session.fresh_restore_query_selection()?;
        let authority = self.authority();
        if selection.realization.bindings.is_empty() {
            return Err(refused());
        }
        for expected in FEATURES {
            for features in [
                selection.provider.extensions_supported.as_slice(),
                authority.selected_features().as_slice(),
            ] {
                let mut found = false;
                for feature in features {
                    if feature.as_str() == expected {
                        if found {
                            return Err(refused());
                        }
                        found = true;
                    }
                }
                if !found {
                    return Err(refused());
                }
            }
            if !authority.envelope_extensions().contains(expected) {
                return Err(refused());
            }
        }
        authority.ensure_live()?;

        let first = self.original_completed_installed_restoration_observation(emitter)?;
        let id = first.original().request_id.0.as_ref().ok_or_else(refused)?;
        authenticate_pair(self, id, first.original(), first.response())
    }

    /// Reports fixed scratch for the allocation-free completed Capture loan.
    ///
    /// The caller separately funds callback work and retains every existing
    /// Source/SDK owner. This getter supplies no transferable admission credit.
    pub fn original_completed_restored_settled_capture_precredit_counter_scratch_data() -> usize {
        super::counter_scratch_data()
            + crate::client::ClientContent::original_completed_capture17_body_precredit_counter_scratch_data()
            + size_of::<&PacketControlSelection>()
            + size_of::<Result<&PacketControlSelection, ProviderError>>()
            + size_of::<&crate::handshake::ConnectionAuthority>()
            + size_of::<&OriginalCanonicalBlobAckEmitter>()
            + size_of::<&crate::handshake::RegistrationRead>()
            + size_of::<crate::handshake::RegistrationRead>()
            + size_of::<Result<crate::handshake::RegistrationRead, ProviderError>>()
            + size_of::<std::sync::MutexGuard<'static, ()>>()
            + size_of::<std::sync::TryLockResult<std::sync::MutexGuard<'static, ()>>>()
            + size_of::<std::sync::TryLockError<std::sync::MutexGuard<'static, ()>>>()
            + size_of::<std::sync::atomic::Ordering>()
            + size_of::<crate::handshake::Limits>()
            + size_of::<&crate::protocol_snapshot::ProtocolCaptureOwner>()
            + size_of::<&std::rc::Rc<crate::connection::Native5CodecOwner>>()
            + size_of::<std::rc::Rc<dyn crate::connection::BodySchemaVerifier>>()
            + size_of::<std::thread::Thread>()
            + size_of::<std::thread::ThreadId>()
            + size_of::<u32>()
            + size_of::<Option<crate::reference_packet::service::ack_emitter::PacketNative5AckEmitterSelection>>()
            + size_of::<Result<Option<crate::reference_packet::service::ack_emitter::PacketNative5AckEmitterSelection>, ProviderError>>()
            + size_of::<crate::client::CompletedOriginalInstalledRestorationObservation<'static>>()
            + size_of::<Result<crate::client::CompletedOriginalInstalledRestorationObservation<'static>, ProviderError>>()
            + size_of::<[&str; 6]>()
            + size_of::<std::array::IntoIter<&str, 6>>()
            + size_of::<[&[Id]; 2]>()
            + size_of::<std::array::IntoIter<&[Id], 2>>()
            + size_of::<std::slice::Iter<'static, Id>>()
            + size_of::<&[Id]>()
            + size_of::<&Id>()
            + size_of::<Option<&Id>>()
            + size_of::<Result<&Id, ProviderError>>()
            + size_of::<&str>()
            + size_of::<bool>() * 2
            + size_of::<Result<(), ProviderError>>() * 3
    }
}
