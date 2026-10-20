//! Borrows correlation, admission and sticky response facts at the settled cut.

use super::{BorrowedAdmission17Lineage, BorrowedAuthority17Lineage, bytes::*};
use crate::ProviderError;
use crate::protocol_snapshot::{
    native_wholegraph17::BorrowedNativeCurrentGraph17Plan,
    owned11::typed::{Fields, invalid, plain_string},
};

#[derive(Clone, Copy)]
pub(crate) struct BorrowedCorrelationLedger17<'a> {
    pub(crate) session: &'a [u8],
    pub(crate) incarnation: &'a [u8],
    pub(crate) next_received: u64,
    pub(crate) next_sent: u64,
    pub(crate) maximum_requests: usize,
    pub(crate) pending: &'a [u8],
    pub(crate) received_requests: &'a [u8],
    pub(crate) writing_responses: &'a [u8],
    pub(crate) extensions: &'a [u8],
    pub(crate) failed: bool,
    pub(crate) continuation_installed: bool,
}

impl<'a> BorrowedCorrelationLedger17<'a> {
    fn read(
        input: &'a [u8],
        authority: BorrowedAuthority17Lineage<'a>,
        current: Option<&[u8]>,
    ) -> Result<Self, ProviderError> {
        let mut fields = Fields::array(input)?;
        if plain_string(next(&mut fields)?)? != "source-private.correlations/6" {
            return Err(invalid());
        }
        let session = next(&mut fields)?;
        let incarnation = next(&mut fields)?;
        let next_received = quoted(next(&mut fields)?)?;
        let next_sent = quoted(next(&mut fields)?)?;
        let maximum_requests = quantity(next(&mut fields)?)?;
        let pending = next(&mut fields)?;
        let received_requests = next(&mut fields)?;
        let writing_responses = next(&mut fields)?;
        let extensions = next(&mut fields)?;
        let failed = boolean(next(&mut fields)?)?;
        let continuation_installed = boolean(next(&mut fields)?)?;
        fields.finish()?;
        if failed
            || session != authority.session
            || incarnation != authority.incarnation
            || !(1..=256).contains(&maximum_requests)
            || next_received < 2
            || next_sent < 2
        {
            return Err(invalid());
        }
        require_empty_map(pending)?;
        require_empty_map(writing_responses)?;
        let mut received = Fields::object(received_requests)?;
        match current {
            None => {
                if received.pair()?.is_some() {
                    return Err(invalid());
                }
            }
            Some(current) => {
                let (key, original) = received.pair()?.ok_or_else(invalid)?;
                if field(original, "request_id")? != key
                    || field(original, "message")? != b"\"request\""
                    || field(original, "session_id")? != session
                    || field(original, "incarnation_id")? != incarnation
                    || quoted(field(original, "sequence")?)?.checked_add(1) != Some(next_received)
                    || original != current
                    || received.pair()?.is_some()
                {
                    return Err(invalid());
                }
            }
        }
        received.finish()?;
        Ok(Self {
            session,
            incarnation,
            next_received,
            next_sent,
            maximum_requests,
            pending,
            received_requests,
            writing_responses,
            extensions,
            failed,
            continuation_installed,
        })
    }
}

fn require_empty_map(input: &[u8]) -> Result<(), ProviderError> {
    let mut fields = Fields::object(input)?;
    if fields.pair()?.is_some() {
        return Err(invalid());
    }
    fields.finish()
}

#[derive(Clone, Copy)]
pub(crate) struct BorrowedCompletedResponse17<'a> {
    pub(crate) encoded: &'a [u8],
    pub(crate) original: &'a [u8],
    pub(crate) canonical: Bytes17<'a>,
    pub(crate) literal_slot: usize,
    pub(crate) request_sequence: u64,
    pub(crate) completed_proof: Option<&'a [u8]>,
}

fn completed_response<'a>(
    input: &'a [u8],
    frames: Frames17<'a>,
    authority: BorrowedAuthority17Lineage<'a>,
) -> Result<BorrowedCompletedResponse17<'a>, ProviderError> {
    let original = field(input, "original")?;
    let canonical = Bytes17::compact(field(input, "canonical")?)?;
    let literal_slot = quantity(field(input, "literal_slot")?)?;
    let request_sequence = quoted(field(input, "request_sequence")?)?;
    let proof = field(input, "completed_proof")?;
    if plain_string(field(input, "phase")?)? != "complete"
        || !boolean(field(input, "original_cut_matches_deadline")?)?
        || field(original, "session_id")? != authority.session
        || field(original, "incarnation_id")? != authority.incarnation
    {
        return Err(invalid());
    }
    canonical.canonical(original)?;
    let frame = frames.frame(literal_slot)?;
    if frame.incoming || !frame.complete || frame.transferred != frame.bytes.len() {
        return Err(invalid());
    }
    frame
        .bytes
        .range(4, frame.bytes.len().checked_sub(4).ok_or_else(invalid)?)?
        .equal(canonical)?;
    if proof != b"null" {
        let prefix = quantity(field(proof, "prefix_slots")?)?;
        if frames.held_prefix_digest(prefix)? != digest(field(proof, "prefix_digest")?)? {
            return Err(invalid());
        }
    }
    Ok(BorrowedCompletedResponse17 {
        encoded: input,
        original,
        canonical,
        literal_slot,
        request_sequence,
        completed_proof: (proof != b"null").then_some(proof),
    })
}

/// Borrows exact future-affecting logical facts without cloning the old heap.
#[derive(Clone, Copy)]
pub(crate) struct BorrowedNativeConnection17LogicalData<'a> {
    pub(crate) authority: BorrowedAuthority17Lineage<'a>,
    pub(crate) correlations: BorrowedCorrelationLedger17<'a>,
    pub(crate) restore_inputs: Option<BorrowedAdmission17Lineage<'a>>,
    pub(crate) complete_restoration: Option<BorrowedAdmission17Lineage<'a>>,
    pub(crate) canonical_ack_admission: Option<BorrowedAdmission17Lineage<'a>>,
    pub(crate) restore_responses: [Option<BorrowedCompletedResponse17<'a>>; 2],
    pub(crate) packet_schema: bool,
    pub(crate) connected_packet_schema: bool,
    pub(crate) fenced: bool,
    pub(crate) frames: Frames17<'a>,
}

/// Checks borrowed lineage and the genuinely selected correlation cut.
///
/// # Errors
/// Refuses unresolved correlations/responses, failed transport/registration,
/// mismatched admission literals or a different selected Capture/Poll phase.
pub(crate) fn borrow_native17_connection_logical_data<'a>(
    plan: &BorrowedNativeCurrentGraph17Plan<'a, '_>,
) -> Result<BorrowedNativeConnection17LogicalData<'a>, ProviderError> {
    let roots = plan.root_spans_data();
    let input = roots.connection_data();
    let authority = BorrowedAuthority17Lineage::read(field(input, "authority")?)?;
    authority.require_live_history()?;
    authority.authenticate_registrar(roots.registrar_data())?;
    let current = authenticated_current_original(plan)?;
    let correlations =
        BorrowedCorrelationLedger17::read(field(input, "correlations")?, authority, current)?;
    let frames = Frames17::read(roots.frames_data())?;
    frames.require_complete()?;
    let coordinator = field(field(roots.codec_data(), "data")?, "coordinator")?;
    authenticate_content(
        item(coordinator, 0)?,
        Bytes17::compact(item(coordinator, 2)?)?,
    )?;
    if let Some(current) = current {
        frames.authenticate_incoming(current)?;
    }
    let reader = field(input, "reader")?;
    if boolean(field(reader, "failed")?)? {
        return Err(invalid());
    }
    let last = field(reader, "last_original_slot")?;
    if last != b"null" {
        frames.frame(quantity(last)?)?;
    }
    let restore_inputs = optional_token(field(input, "restore_inputs")?, authority, frames, true)?;
    let complete_restoration = optional_token(
        field(input, "complete_restoration")?,
        authority,
        frames,
        true,
    )?;
    let canonical_ack_admission = optional_token(
        field(input, "canonical_ack_admission")?,
        authority,
        frames,
        false,
    )?;
    let boot = plan.boot_lineage_data();
    if let Some(token) = canonical_ack_admission {
        token.authenticate_original(boot.ack_original.raw_data(), frames)?;
    }
    if let Some(token) = restore_inputs {
        token.authenticate_original(
            boot.prepare
                .as_ref()
                .ok_or_else(invalid)?
                .original
                .raw_data(),
            frames,
        )?;
    }
    if let Some(token) = complete_restoration {
        token.authenticate_original(
            boot.commit
                .as_ref()
                .ok_or_else(invalid)?
                .original
                .raw_data(),
            frames,
        )?;
    }
    let mut responses = Fields::array(field(input, "restore_responses")?)?;
    let mut restore_responses = [None, None];
    for response in &mut restore_responses {
        let raw = next(&mut responses)?;
        if raw != b"null" {
            *response = Some(completed_response(raw, frames, authority)?);
        }
    }
    responses.finish()?;
    let packet_schema = boolean(field(input, "packet_schema")?)?;
    let connected_packet_schema = boolean(field(input, "connected_packet_schema")?)?;
    let fenced = boolean(field(input, "fenced")?)?;
    if fenced {
        return Err(invalid());
    }
    let groups = plan.connection_groups_data();
    if groups.actor != plan.actor_group_data()
        || groups.frames != plan.frame_group_data()
        || groups.policy != plan.policy_group_data()
    {
        return Err(invalid());
    }
    Ok(BorrowedNativeConnection17LogicalData {
        authority,
        correlations,
        restore_inputs,
        complete_restoration,
        canonical_ack_admission,
        restore_responses,
        packet_schema,
        connected_packet_schema,
        fenced,
        frames,
    })
}

fn optional_token<'a>(
    input: &'a [u8],
    authority: BorrowedAuthority17Lineage<'a>,
    frames: Frames17<'a>,
    wrapper: bool,
) -> Result<Option<BorrowedAdmission17Lineage<'a>>, ProviderError> {
    if input == b"null" {
        return Ok(None);
    }
    Ok(Some(BorrowedAdmission17Lineage::read(
        if wrapper {
            field(input, "token")?
        } else {
            input
        },
        authority,
        frames,
    )?))
}

/// Binds the sole correlation to the actual typed active-recorder occurrence.
/// The earlier Capture artifact is independent from a current Poll confirmation.
fn authenticated_current_original<'a>(
    plan: &BorrowedNativeCurrentGraph17Plan<'a, '_>,
) -> Result<Option<&'a [u8]>, ProviderError> {
    use crate::protocol_snapshot::restored_settled17::current_actions::CurrentCaptureStage17;
    let Some(original) = plan.current_action_original_data() else {
        return Ok(None);
    };
    let phase = plan.current_capture_phase17_data().ok_or_else(invalid)?;
    if !matches!(phase.stage, CurrentCaptureStage17::Typed) || phase.original.raw_data() != original
    {
        return Err(invalid());
    }
    authenticate_current_phase(
        original,
        phase.body,
        phase.capture.raw_data(),
        phase.capture_context.raw_data(),
        phase.confirmation.raw_data(),
    )?;
    Ok(Some(original))
}

fn authenticate_current_phase(
    original: &[u8],
    body: &[u8],
    capture: &[u8],
    capture_context: &[u8],
    confirmation: &[u8],
) -> Result<(), ProviderError> {
    use crate::reference_packet::service::{
        restored_settled_capture::RESTORED_SETTLED_CAPTURE_FEATURE,
        restored_settled_confirmation::PACKET_RESTORED_SETTLED_AFTER_CONFIRMATION_FEATURE,
    };
    let typed_body = field(body, "data")?;
    if canonical_digest(typed_body)? != canonical_digest(field(original, "body")?)? {
        return Err(invalid());
    }
    let feature = match plain_string(field(body, "kind")?)? {
        "capture" => {
            if field(original, "method")? != b"\"begin\""
                || field(typed_body, "kind")? != b"\"capture\""
                || capture == b"null"
                || capture_context == b"null"
                || confirmation != b"null"
            {
                return Err(invalid());
            }
            let request = field(capture, "request")?;
            if canonical_digest(field(capture_context, "request")?)? != canonical_digest(request)?
                || field(original, "capture_owner_id")? != field(request, "capture_owner")?
                || field(original, "operation_id")? != field(request, "capture_operation")?
                || field(original, "node_id")?
                    != field(field(field(request, "scope")?, "target")?, "node")?
            {
                return Err(invalid());
            }
            (RESTORED_SETTLED_CAPTURE_FEATURE, capture)
        }
        "confirmation" => {
            require_empty_map(field(typed_body, "extensions")?)?;
            if field(original, "method")? != b"\"poll\""
                || confirmation == b"null"
                || capture != b"null"
                || capture_context != b"null"
                || field(original, "operation_id")? != field(confirmation, "capture_operation_id")?
                || quoted(field(typed_body, "after_observation_sequence")?)? != 0
            {
                return Err(invalid());
            }
            (
                PACKET_RESTORED_SETTLED_AFTER_CONFIRMATION_FEATURE,
                confirmation,
            )
        }
        _ => return Err(invalid()),
    };
    let mut extensions = Fields::object(field(original, "extensions")?)?;
    let (key, value) = extensions.pair()?.ok_or_else(invalid)?;
    if plain_string(key)? != feature.0
        || canonical_digest(value)? != canonical_digest(feature.1)?
        || extensions.pair()?.is_some()
    {
        return Err(invalid());
    }
    extensions.finish()
}

#[cfg(test)]
mod current_cut_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn current_poll_is_not_confused_with_the_prior_capture() -> Result<(), ProviderError> {
        use crate::reference_packet::service::restored_settled_confirmation::PACKET_RESTORED_SETTLED_AFTER_CONFIRMATION_FEATURE;
        let confirmation = json!({"capture_operation_id":"capture-operation"});
        let body = json!({"after_observation_sequence":"0","extensions":{}});
        let original = json!({
            "method":"poll", "operation_id":"capture-operation", "body":body,
            "extensions":{PACKET_RESTORED_SETTLED_AFTER_CONFIRMATION_FEATURE:confirmation}
        });
        let typed = json!({"kind":"confirmation","data":body});
        let encoded = |value: &serde_json::Value| serde_json::to_vec(value).map_err(|_| invalid());
        let original_bytes = encoded(&original)?;
        let typed = encoded(&typed)?;
        let confirmation = encoded(&confirmation)?;
        authenticate_current_phase(&original_bytes, &typed, b"null", b"null", &confirmation)?;

        let mut wrong_operation = original.clone();
        wrong_operation["operation_id"] = json!("another-operation");
        assert!(
            authenticate_current_phase(
                &encoded(&wrong_operation)?,
                &typed,
                b"null",
                b"null",
                &confirmation
            )
            .is_err()
        );
        let mut wrong_method = original;
        wrong_method["method"] = json!("begin");
        assert!(
            authenticate_current_phase(
                &encoded(&wrong_method)?,
                &typed,
                b"null",
                b"null",
                &confirmation
            )
            .is_err()
        );
        assert!(
            authenticate_current_phase(&original_bytes, &typed, br#"{}"#, b"null", &confirmation)
                .is_err()
        );
        Ok(())
    }
}
