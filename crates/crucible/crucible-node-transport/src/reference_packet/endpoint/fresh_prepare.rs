//! Binds the next Prepare to the actual completed Fresh publication.
//!
//! The short-lived header borrows real endpoint custody and its published
//! ExchangeRecord. It holds no Connection borrow, new permission or portable
//! completion DTO. The same raw reader checks it before typed Begin allocation.

use super::fresh_restore::NativeFreshRestoreAttempt;
use super::*;
use crate::reference_packet::service::ack_emitter::OriginalNativeReportStartupAllocation;
use crate::reference_packet::service::fresh_restore_allocation::*;
use base64::Engine as _;

pub(crate) struct OriginalNativeFreshPrepareHeader<'a> {
    startup: &'a OriginalNativeReportStartupAllocation,
    query: &'a Envelope,
    assigned_query: &'a [u8; 32],
    response: &'a [u8; 32],
    reference: &'a ContentRef,
    record: &'a ExchangeRecord,
}

impl NativeFreshRestoreAttempt {
    pub(super) fn borrow_completed_prepare_header<'a, S: ProviderStream>(
        &'a self,
        connection: &Connection<S>,
        record: &'a ExchangeRecord,
        record_index: usize,
    ) -> Result<OriginalNativeFreshPrepareHeader<'a>, ProviderError> {
        self.authenticate_current(connection)?;
        self.startup
            .authenticate_complete_native_baseline(connection)?;
        let (reference, response, actual_index) = self.publication.completed_parts_data()?;
        if record_index != actual_index {
            return Err(refused());
        }
        let frame = self.input.frame.as_ref().ok_or_else(refused)?;
        let commitments = self.input.commitments.as_ref().ok_or_else(refused)?;
        let header = OriginalNativeFreshPrepareHeader {
            startup: &self.startup,
            query: &frame.envelope,
            assigned_query: &commitments[2],
            response,
            reference,
            record,
        };
        header.authenticate_current(connection)?;
        Ok(header)
    }
}

impl<S: ProviderStream> PacketEndpoint<S> {
    pub(super) fn requires_original_fresh_prepare(&self) -> Result<bool, ProviderError> {
        self.ensure_complete_origin()?;
        let Some(owner) = self.fresh_restore_attempt.as_ref() else {
            return Ok(false);
        };
        if self.restore_protocol_attempted {
            // Later traffic enters its existing verified input/Commit route;
            // no query-selection Boolean authorizes that separate operation.
            return Ok(false);
        }
        let Some(Transport::Connected(connection)) = self.transport.as_ref() else {
            return Err(refused());
        };
        let attempt = owner.try_borrow().map_err(|_| refused())?;
        attempt.authenticate_current(connection)?;
        if attempt.prepare_input.is_some() {
            return Err(refused());
        }
        let index = self.records.len().checked_sub(1).ok_or_else(refused)?;
        attempt.borrow_completed_prepare_header(connection, &self.records[index], index)?;
        let token = connection.original_native_owned11_admission()?;
        let view = self
            .native
            .borrow_original_fresh_report_data(&token.policy)?;
        if view.selection_data().admission.as_str().is_empty() {
            return Err(refused());
        }
        Ok(true)
    }

    pub(super) fn receive_original_fresh_prepare(&mut self) -> Result<bool, ProviderError> {
        self.ensure_complete_origin()?;
        let Some(Transport::Connected(connection)) = self.transport.as_mut() else {
            return Err(refused());
        };
        let mut guard = self
            .fresh_restore_attempt
            .as_ref()
            .ok_or_else(refused)?
            .try_borrow_mut()
            .map_err(|_| refused())?;
        let attempt = &mut *guard;
        attempt.authenticate_current(connection)?;
        if attempt.prepare_input.is_some() {
            return Err(refused());
        }
        let index = self.records.len().checked_sub(1).ok_or_else(refused)?;
        let record = &self.records[index];
        let NativeFreshRestoreAttempt {
            startup,
            prepare,
            input,
            publication,
            ..
        } = attempt;
        let (reference, response, actual_index) = publication.completed_parts_data()?;
        if actual_index != index {
            return Err(refused());
        }
        let frame = input.frame.as_ref().ok_or_else(refused)?;
        let commitments = input.commitments.as_ref().ok_or_else(refused)?;
        let completed = OriginalNativeFreshPrepareHeader {
            startup,
            query: &frame.envelope,
            assigned_query: &commitments[2],
            response,
            reference,
            record,
        };
        completed.authenticate_current(connection)?;
        let frame = connection.receive_original_native_prepare_after_fresh(prepare, &completed)?;
        let Some(frame) = frame else {
            return Ok(false);
        };
        // The actual attempt was borrowed before the read. There is no origin,
        // lookup, borrow or fallible call between producing this owning frame
        // and moving it into the same retained slot. Prior occupancy was
        // rejected before reading; no earlier frame can be replaced here.
        attempt.prepare_input = Some(frame);
        attempt.authenticate_current(connection)?;
        attempt.prepare.authenticate_active(connection)?;
        Ok(true)
    }
}

impl OriginalNativeFreshPrepareHeader<'_> {
    pub(crate) const fn counter_scratch_data() -> usize {
        std::mem::size_of::<OriginalNativeFreshPrepareHeader<'static>>()
            + std::mem::size_of::<crate::connection::OriginalSentFrameView<'static>>()
            + std::mem::size_of::<[u8; 43]>()
            + std::mem::size_of::<[(&str, &[u8; 32]); 2]>()
            + std::mem::size_of::<blake3::Hasher>()
            + std::mem::size_of::<Rc<std::cell::RefCell<NativeFreshRestoreAttempt>>>()
            + std::mem::size_of::<std::cell::Ref<'static, NativeFreshRestoreAttempt>>()
            + std::mem::size_of::<std::cell::RefMut<'static, NativeFreshRestoreAttempt>>()
            + 12 * std::mem::size_of::<usize>()
    }

    pub(crate) fn authenticate_current<S: ProviderStream>(
        &self,
        connection: &Connection<S>,
    ) -> Result<(), ProviderError> {
        self.startup
            .authenticate_complete_native_baseline(connection)?;
        self.startup
            .authenticate_query_header_data(connection, self.query)?;
        if self.record.sent() != self.record.originals().len()
            || self.record.acknowledgements().len().checked_add(1) != Some(self.record.sent())
        {
            return Err(refused());
        }
        {
            let terminal = self.record.original_sent_frame(connection, 0)?;
            self.query.matches_response(terminal.original())?;
            if PacketNativeFreshRestoreOriginalRole::QueryResponse
                .verified_canonical_body_digest(terminal.canonical_body())
                != *self.response
            {
                return Err(refused());
            }
        }
        let last = self.record.sent().checked_sub(1).ok_or_else(refused)?;
        {
            let sent = self.record.original_sent_frame(connection, last)?;
            let acknowledgement = self.record.acknowledgements().last().ok_or_else(refused)?;
            sent.original()
                .matches_response(&acknowledgement.envelope)?;
            if !matches!(&acknowledgement.body, ReceivedBody::Response(response)
                if matches!(response.shape, ResponseShape::Completed { .. }))
            {
                return Err(refused());
            }
        }
        self.startup.authenticate_current(connection)
    }

    pub(crate) fn authenticate_header<S: ProviderStream>(
        &self,
        connection: &Connection<S>,
        original: &Envelope,
    ) -> Result<(), ProviderError> {
        self.authenticate_current(connection)?;
        let previous = self.record.acknowledgements().last().ok_or_else(refused)?;
        if previous.envelope.sequence.get().checked_add(1) != Some(original.sequence.get()) {
            return Err(refused());
        }
        authenticate_binding_data(
            original
                .extensions
                .get(PACKET_FRESH_RESTORE_ALLOCATION_PREPARE_BINDING)
                .ok_or_else(refused)?,
            self.assigned_query,
            self.response,
            self.reference,
        )?;
        self.authenticate_current(connection)
    }
}

// Compares borrowed, closed syntax only. NativeCurrent/Header authentication and
// the Source-signed complete Prepare original remain independent conjunctions.
fn authenticate_binding_data(
    value: &serde_json::Value,
    assigned_query: &[u8; 32],
    response: &[u8; 32],
    reference: &ContentRef,
) -> Result<(), ProviderError> {
    let value = value
        .as_object()
        .filter(|value| value.len() == 4)
        .ok_or_else(refused)?;
    if value.get("schema").and_then(serde_json::Value::as_str)
        != Some(PACKET_FRESH_RESTORE_ALLOCATION_PREPARE_BINDING)
    {
        return Err(refused());
    }
    for (name, expected) in [
        ("assigned_query", assigned_query),
        ("completed_query_response", response),
    ] {
        authenticate_digest(value.get(name).ok_or_else(refused)?, expected)?;
    }
    if !reference_matches(value.get("allocation").ok_or_else(refused)?, reference) {
        return Err(refused());
    }
    Ok(())
}

fn authenticate_digest(
    value: &serde_json::Value,
    expected: &[u8; 32],
) -> Result<(), ProviderError> {
    let mut encoded = [0u8; 43];
    let count = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode_slice(expected, &mut encoded)
        .map_err(|_| refused())?;
    if count != encoded.len() || value.as_str().map(str::as_bytes) != Some(encoded.as_slice()) {
        return Err(refused());
    }
    Ok(())
}

fn reference_matches(value: &serde_json::Value, reference: &ContentRef) -> bool {
    let Some(value) = value.as_object().filter(|value| value.len() == 3) else {
        return false;
    };
    let Some(hash) = value
        .get("hash")
        .and_then(serde_json::Value::as_object)
        .filter(|value| value.len() == 3)
    else {
        return false;
    };
    value
        .get("length")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|text| {
            !text.is_empty()
                && text.len() <= 20
                && (text == "0" || !text.starts_with('0'))
                && text.bytes().all(|byte| byte.is_ascii_digit())
                && text.parse::<u64>() == Ok(reference.length.get())
        })
        && value.get("media_type").and_then(serde_json::Value::as_str)
            == Some(reference.media_type.as_str())
        && hash.get("algorithm").and_then(serde_json::Value::as_str)
            == Some(reference.hash.algorithm.as_str())
        && hash.get("domain").and_then(serde_json::Value::as_str)
            == Some(reference.hash.domain.as_str())
        && hash.get("digest").and_then(serde_json::Value::as_str)
            == Some(reference.hash.digest.as_str())
}

fn refused() -> ProviderError {
    ProviderError::Correlation("native completed Fresh Prepare association differs")
}

impl PacketEndpoint<crate::client::DeadlineStream> {
    pub(super) fn original_fresh_endpoint_retained_facts_data(
        &self,
        policy: &Rc<super::super::Native5Policy>,
    ) -> Result<crate::retained_metadata::RetainedProtocolMetadataFacts, ProviderError> {
        self.ensure_complete_origin()?;
        if !self.held
            || !self.restore_protocol_attempted
            || self.capture.is_some()
            || self.pending_capture.is_some()
            || self.after_confirmation.is_some()
        {
            return Err(refused());
        }
        let Some(Transport::Connected(connection)) = self.transport.as_ref() else {
            return Err(refused());
        };
        let token = connection.original_native_owned11_admission()?;
        if !Rc::ptr_eq(&token.policy, policy) {
            return Err(refused());
        }
        let owner = self.fresh_restore_attempt.as_ref().ok_or_else(refused)?;
        let attempt = owner.try_borrow().map_err(|_| refused())?;
        attempt.authenticate_current(connection)?;
        attempt.prepare.authenticate_active(connection)?;
        let index = self.records.len().checked_sub(1).ok_or_else(refused)?;
        let header =
            attempt.borrow_completed_prepare_header(connection, &self.records[index], index)?;
        let input = attempt.prepare_input.as_ref().ok_or_else(refused)?;
        header.authenticate_header(connection, &input.envelope)?;
        let mut roots = crate::retained_metadata::NativeCaptureMetadataRoots::new();
        let mut observer = crate::retained_metadata::MetadataObserver::new();
        observer.vector::<ExchangeRecord>(self.records.capacity())?;
        for record in &self.records {
            record.observe_unique_capture_metadata(connection, &mut roots, &mut observer)?;
        }
        observer.vector::<OperationContentPin>(self.pins.capacity())?;
        for pin in &self.pins {
            pin.observe_unique_capture_metadata(&self.uploads, &mut roots, &mut observer)?;
        }
        if roots.observe_shared(
            &mut observer,
            crate::retained_metadata::aliases::MetadataSharedKind::NativePolicy,
            policy.as_ref(),
        )? {
            policy.observe_unique_capture_metadata(&mut roots, &mut observer)?;
        }
        if !roots.observe_shared(
            &mut observer,
            crate::retained_metadata::aliases::MetadataSharedKind::NativeFreshReportAttempt,
            owner.as_ref(),
        )? {
            return Err(refused());
        }
        attempt
            .startup
            .observe_unique_capture_metadata(connection, &mut roots, &mut observer)?;
        attempt
            .prepare
            .observe_unique_startup_metadata(connection, &mut roots, &mut observer)?;
        attempt.input.observe_retained_metadata(&mut observer)?;
        attempt
            .publication
            .observe_retained_metadata(&mut observer)?;
        // The saved census consists exclusively of fixed scalar facts and two
        // Copy bank descriptors; its full inline layout belongs to the Rc cell.
        observer.observe(&attempt.current.is_some())?;
        observer.observe(&input.envelope)?;
        let ReceivedBody::Request(body) = &input.body else {
            return Err(refused());
        };
        observer.boxed_value(body.as_ref())?;
        let RequestBody::Begin(begin) = body.as_ref() else {
            return Err(refused());
        };
        let BeginRequest {
            kind,
            binding_hash,
            owner_generation,
            activation_id,
            world_generation,
            arguments,
            extensions,
        } = begin;
        if *kind != BeginKind::PrepareRestore {
            return Err(refused());
        }
        observer.observe(&(*kind == BeginKind::PrepareRestore))?;
        observer.observe(binding_hash)?;
        observer.observe(owner_generation)?;
        observer.observe(activation_id)?;
        observer.observe(world_generation)?;
        observer.observe(arguments)?;
        observer.observe(extensions)?;
        roots.finish()?;
        attempt.authenticate_current(connection)?;
        Ok(observer.finish())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crucible_node_format::{Bytes, canonical};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn binding(reference: &ContentRef) -> PacketNativeFreshRestoreAllocationPrepareBinding {
        PacketNativeFreshRestoreAllocationPrepareBinding {
            schema: PACKET_FRESH_RESTORE_ALLOCATION_PREPARE_BINDING.into(),
            assigned_query: Bytes::new(vec![17; 32]),
            completed_query_response: Bytes::new(vec![29; 32]),
            allocation: reference.clone(),
        }
    }

    #[test]
    fn completed_prepare_binding_matches_actual_typed_serializer_and_each_commitment() -> TestResult
    {
        let reference =
            canonical::content_ref(b"original-report", PACKET_FRESH_RESTORE_ALLOCATION_MEDIA)?;
        let value = serde_json::to_value(binding(&reference))?;
        authenticate_binding_data(&value, &[17; 32], &[29; 32], &reference)?;

        let different_reference =
            canonical::content_ref(b"changed-report", PACKET_FRESH_RESTORE_ALLOCATION_MEDIA)?;
        assert!(authenticate_binding_data(&value, &[18; 32], &[29; 32], &reference).is_err());
        assert!(authenticate_binding_data(&value, &[17; 32], &[30; 32], &reference).is_err());
        assert!(
            authenticate_binding_data(&value, &[17; 32], &[29; 32], &different_reference).is_err()
        );
        Ok(())
    }

    #[test]
    fn completed_prepare_binding_refuses_each_full_reference_field_and_extra_syntax() -> TestResult
    {
        let reference =
            canonical::content_ref(b"original-report", PACKET_FRESH_RESTORE_ALLOCATION_MEDIA)?;
        let value = serde_json::to_value(binding(&reference))?;
        for pointer in [
            "/allocation/length",
            "/allocation/media_type",
            "/allocation/hash/algorithm",
            "/allocation/hash/domain",
            "/allocation/hash/digest",
            "/assigned_query",
            "/completed_query_response",
            "/schema",
        ] {
            let mut changed = value.clone();
            *changed
                .pointer_mut(pointer)
                .ok_or("actual typed binding field absent")? =
                serde_json::Value::String("changed".into());
            assert!(
                authenticate_binding_data(&changed, &[17; 32], &[29; 32], &reference).is_err(),
                "{pointer}"
            );
        }

        for pointer in ["", "/allocation", "/allocation/hash"] {
            let mut changed = value.clone();
            changed
                .pointer_mut(pointer)
                .and_then(serde_json::Value::as_object_mut)
                .ok_or("actual typed binding object absent")?
                .insert("extra".into(), serde_json::Value::Null);
            assert!(
                authenticate_binding_data(&changed, &[17; 32], &[29; 32], &reference).is_err(),
                "{pointer}"
            );
        }
        Ok(())
    }

    #[test]
    fn completed_prepare_binding_refuses_noncanonical_quoted_lengths() -> TestResult {
        let reference =
            canonical::content_ref(b"original-report", PACKET_FRESH_RESTORE_ALLOCATION_MEDIA)?;
        let value = serde_json::to_value(binding(&reference))?;
        for length in [
            serde_json::json!("015"),
            serde_json::json!("+15"),
            serde_json::json!(15),
            serde_json::json!("18446744073709551616"),
            serde_json::json!(""),
        ] {
            let mut changed = value.clone();
            changed["allocation"]["length"] = length;
            assert!(authenticate_binding_data(&changed, &[17; 32], &[29; 32], &reference).is_err());
        }
        Ok(())
    }
}
