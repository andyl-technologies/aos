//! Original controller confirmation calls with explicit fourth-object custody.
//!
//! The selected Poll extends the same retained Capture history. This helper
//! checks original request identity and canonical terminal-body correspondence;
//! the source journal separately authenticates literal bytes and all ACKs. Its
//! returned receipt is data and cannot create a settlement or fresh association.

use super::*;
use crate::reference_packet::service::confirmation::{
    PACKET_NATIVE_AFTER_CONFIRMATION_EXTENSION, PacketNative5ConfirmationSelection,
    PacketNativeAfterConfirmationReceipt, PacketNativeAfterConfirmationRequest,
};

impl CnpController {
    /// Confirms a fourth body only through this same retained original Capture.
    ///
    /// The additional receipt is read from the actual response extension and its
    /// full hash-verified after bytes must already be present from provider Blob
    /// transfers acknowledged before that response. The ordinary body-only
    /// content scanner is not treated as extension-content evidence.
    ///
    /// The source separately admits the complete lifetime journals, raw suffix,
    /// typed receipt, baseline decoding and canonical terminal-hash temporaries.
    /// This method authenticates correspondence only; source tickets, literal
    /// archive verification and target authority remain independent requirements.
    ///
    /// # Errors
    /// Refuses an uninstalled selection, reused confirmation ID, foreign or
    /// incomplete original Capture, changed request/terminal/reference context,
    /// wrong Poll outcome, missing fourth bytes or uncertain transport.
    pub fn call_original_native_after_confirmation(
        &mut self,
        request_id: Id,
        capture_owner: Id,
        context: PacketNativeAfterConfirmationRequest,
    ) -> Result<(ResponseBody, PacketNativeAfterConfirmationReceipt), ProviderError> {
        self.authenticate_native5_source_codec()?;
        if self.original_native5_confirmation_selection()?
            != Some(PacketNative5ConfirmationSelection::AfterProtocolPoll5)
        {
            return Err(ProviderError::Correlation(
                "original confirmation selection absent",
            ));
        }
        count_serialized(&context, self.maximum_frame()?)?;
        context.validate_data()?;
        if self
            .custody
            .originals_by_origin(RequestOrigin::Controller)
            .any(|original| original.request.request_id.0.as_ref() == Some(&request_id))
        {
            return Err(ProviderError::Conflict(
                "confirmation already has original custody",
            ));
        }
        self.validate_original_confirmation_context(&capture_owner, &context)?;

        let mut extensions = Extensions::new();
        extensions.insert(
            PACKET_NATIVE_AFTER_CONFIRMATION_EXTENSION.into(),
            serde_json::to_value(&context).map_err(crucible_node_format::ContractError::from)?,
        );
        let response = self.call_scoped(
            request_id.clone(),
            CallScope {
                operation_id: Some(context.capture_operation_id.clone()),
                method: Method::Poll,
                owner_scoped: true,
                capture_owner: Some(capture_owner.clone()),
            },
            PollRequest {
                after_observation_sequence: U64::new(0),
                extensions: Extensions::new(),
            },
            extensions,
        )?;
        self.authenticate_native5_source_codec()?;
        self.validate_original_confirmation_context(&capture_owner, &context)?;

        let original = self
            .custody
            .originals_by_origin(RequestOrigin::Controller)
            .find(|original| original.request.request_id.0.as_ref() == Some(&request_id))
            .ok_or(ProviderError::Correlation(
                "confirmation original journal absent",
            ))?;
        let reply = original
            .response
            .as_ref()
            .ok_or(ProviderError::Correlation("confirmation response unknown"))?;
        let original_view =
            crate::connection::ConfirmationProjection::from_envelope(&original.request)?;
        let reply_view = crate::connection::ConfirmationProjection::from_envelope(reply)?;
        if original_view.capture != reply_view.capture || reply_view.after.is_none() {
            return Err(ProviderError::Correlation(
                "confirmation receipt changed original context",
            ));
        }
        let capture = self
            .custody
            .originals_by_origin(RequestOrigin::Controller)
            .find(|original| {
                original.request.request_id.0.as_ref() == Some(&context.capture_request_id)
            })
            .and_then(|original| original.response.as_ref())
            .ok_or(ProviderError::Correlation(
                "confirmation original Capture terminal absent",
            ))?;
        let Some(MethodResult::Poll(poll)) = &response.result else {
            return Err(ProviderError::Correlation(
                "confirmation Poll result absent",
            ));
        };
        if poll.operation_id != context.capture_operation_id
            || !poll.observations.is_empty()
            || poll.next_observation_sequence.get() != 0
            || poll.outcome.0.as_ref() != Some(&capture.body)
        {
            return Err(ProviderError::Correlation(
                "confirmation changed actual Capture terminal outcome",
            ));
        }
        let value = reply
            .extensions
            .get(PACKET_NATIVE_AFTER_CONFIRMATION_EXTENSION)
            .ok_or(ProviderError::Correlation(
                "confirmation receipt extension absent",
            ))?;
        // Borrowed Value deserialization owns the bounded typed strings once;
        // no cloned intermediate JSON tree or second wire parser is introduced.
        let receipt: PacketNativeAfterConfirmationReceipt = serde::Deserialize::deserialize(value)
            .map_err(crucible_node_format::ContractError::from)?;
        if receipt.capture != context {
            return Err(ProviderError::Correlation(
                "confirmation typed receipt changed actual request",
            ));
        }
        self.custody.content().get(&receipt.native_after_ref)?;
        self.authenticate_native5_source_codec()?;
        Ok((response, receipt))
    }

    fn validate_original_confirmation_context(
        &self,
        capture_owner: &Id,
        context: &PacketNativeAfterConfirmationRequest,
    ) -> Result<(), ProviderError> {
        let original = self
            .custody
            .originals_by_origin(RequestOrigin::Controller)
            .find(|original| {
                original.request.request_id.0.as_ref() == Some(&context.capture_request_id)
            })
            .ok_or(ProviderError::Correlation(
                "confirmation original Capture missing",
            ))?;
        let terminal = original
            .response
            .as_ref()
            .ok_or(ProviderError::Correlation(
                "confirmation Capture response unknown",
            ))?;
        if original.request.method != Method::Begin
            || original.request.body.get("kind").and_then(Value::as_str) != Some("capture")
            || original.request.capture_owner_id.0.as_ref() != Some(capture_owner)
            || original.request.node_id.0.as_ref() != Some(&self.route.node)
            || original.request.execution_owner_id.0.is_some()
            || original.request.operation_id.0.as_ref() != Some(&context.capture_operation_id)
            || original.identity != context.capture_request_hash
            || terminal.sequence != context.capture_terminal_sequence
            || terminal.body.get("status").and_then(Value::as_str) != Some("completed")
            || terminal.body.get("operation_state").and_then(Value::as_str) != Some("completed")
        {
            return Err(ProviderError::Correlation(
                "confirmation differs from retained Capture scope",
            ));
        }
        let result = terminal
            .body
            .get("result")
            .and_then(Value::as_object)
            .ok_or(ProviderError::Correlation(
                "confirmation Capture result absent",
            ))?;
        let owners = result
            .get("owner_state_refs")
            .and_then(Value::as_array)
            .ok_or(ProviderError::Correlation(
                "confirmation Capture owner refs absent",
            ))?;
        if terminal.body.len() != 4
            || result.len() != 3
            || owners.len() != 1
            || !terminal
                .body
                .get("extensions")
                .and_then(Value::as_object)
                .is_some_and(|values| values.is_empty())
            || !same_reference(result.get("capture_manifest"), &context.native_snapshot_ref)
            || !same_reference(owners.first(), &context.native_control_ref)
            || !same_reference(
                result.get("unchanged_cut_receipt"),
                &context.native_anchor_ref,
            )
        {
            return Err(ProviderError::Correlation(
                "confirmation changed original Capture object tuple",
            ));
        }
        original.request.matches_response(terminal)?;
        let value =
            serde_json::to_value(terminal).map_err(crucible_node_format::ContractError::from)?;
        let canonical_terminal = canonical::canonical_json(&value)?;
        if canonical::hash(
            "source-owned.packet-native-capture-terminal/5",
            &canonical_terminal,
        )? != context.capture_terminal_hash
        {
            return Err(ProviderError::Correlation(
                "confirmation canonical terminal bytes changed",
            ));
        }
        // Literal encoding/current actor is authenticated by the signed source
        // journal. This necessary canonical-byte comparison does not infer it.
        Ok(())
    }
}

fn same_reference(value: Option<&Value>, reference: &ContentRef) -> bool {
    let Some(value) = value.and_then(Value::as_object) else {
        return false;
    };
    let Some(hash) = value.get("hash").and_then(Value::as_object) else {
        return false;
    };
    value.len() == 3
        && hash.len() == 3
        && hash.get("algorithm").and_then(Value::as_str) == Some(reference.hash.algorithm.as_str())
        && hash.get("domain").and_then(Value::as_str) == Some(reference.hash.domain.as_str())
        && hash.get("digest").and_then(Value::as_str) == Some(reference.hash.digest.as_str())
        && value
            .get("length")
            .and_then(Value::as_str)
            .and_then(|text| text.parse::<u64>().ok())
            == Some(reference.length.get())
        && value.get("media_type").and_then(Value::as_str) == Some(reference.media_type.as_str())
}
