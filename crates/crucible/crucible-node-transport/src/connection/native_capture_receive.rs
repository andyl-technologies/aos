//! Restricts the selected post-Observe read before allocating a typed request.
//!
//! Requested storage below is a conservative grammar/layout bound. It is not
//! actual capacity, allocator peak or permission to read a larger frame. The
//! existing negotiated raw ceiling, original literal bank and correlation rules
//! remain in force. Stack and allocator-internal overhead are separate terms.

use super::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::mem::{align_of, size_of};

/// Separates the future read/validation work from already reserved literal data.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct NativeCaptureFutureReceiveQuote {
    pub(crate) maximum_frame_body_bytes: usize,
    pub(crate) raw_read_requested_bytes: usize,
    pub(crate) raw_dom_requested_bytes: usize,
    pub(crate) typed_validation_requested_bytes: usize,
    pub(crate) correlation_requested_bytes: usize,
    pub(crate) current_incident_copy_requested_bytes: usize,
    /// Is a required subextent of the existing descriptor bank, not a new bank.
    pub(crate) original_descriptor_required_bytes: usize,
    /// Is a required subextent of the existing literal bank, not a new bank.
    pub(crate) original_literal_required_bytes: usize,
    pub(crate) maximum_requested_bytes: usize,
}

impl NativeCaptureFutureReceiveQuote {
    pub(super) fn observe_metadata(
        &self,
        observer: &mut crate::retained_metadata::MetadataObserver,
    ) -> Result<(), ProviderError> {
        let Self {
            maximum_frame_body_bytes,
            raw_read_requested_bytes,
            raw_dom_requested_bytes,
            typed_validation_requested_bytes,
            correlation_requested_bytes,
            current_incident_copy_requested_bytes,
            original_descriptor_required_bytes,
            original_literal_required_bytes,
            maximum_requested_bytes,
        } = self;
        observer.observe(&[
            *maximum_frame_body_bytes,
            *raw_read_requested_bytes,
            *raw_dom_requested_bytes,
            *typed_validation_requested_bytes,
            *correlation_requested_bytes,
            *current_incident_copy_requested_bytes,
            *original_descriptor_required_bytes,
            *original_literal_required_bytes,
            *maximum_requested_bytes,
        ])
    }

    /// Charges the real current guard copies made by one containment handoff.
    pub(super) fn with_original_guard_data(
        mut self,
        guard: &CorrelationGuard,
    ) -> Result<Self, ProviderError> {
        let mut observer = crate::retained_metadata::MetadataObserver::new();
        guard.observe_owned_metadata(&mut observer)?;
        let facts = observer.finish();
        let current_backing = sum(&[
            facts.string_capacity_bytes,
            facts.vector_capacity_bytes,
            facts.boxed_value_bytes,
            facts.shared_value_bytes,
            super::restore_input_quote::tree_storage(
                facts.tree_containers,
                facts.tree_entries,
                facts.maximum_tree_key_value_bytes,
                facts.maximum_tree_entry_alignment.max(1),
            )?,
        ])?;
        let outgoing = guard.pending_requests().count();
        let incoming = guard.incoming_requests().count();
        // The extra future Capture payload is already in the typed DOM budget.
        // Incident collection needs its actual extra inline Envelope slot too.
        let incident_slots = add(
            add(multiply(2, outgoing)?, multiply(2, add(incoming, 1)?)?)?,
            8,
        )?;
        self.current_incident_copy_requested_bytes = add(
            current_backing,
            add(
                multiply(incident_slots, size_of::<Envelope>())?,
                size_of::<ConnectionIncident>(),
            )?,
        )?;
        self.maximum_requested_bytes = add(
            self.maximum_requested_bytes,
            self.current_incident_copy_requested_bytes,
        )?;
        Ok(self)
    }

    pub(super) fn from_negotiated_frame(bytes: usize) -> Result<Self, ProviderError> {
        if bytes == 0 || bytes > 16_777_216 {
            return Err(credit());
        }
        // Every object entry consumes at least four input bytes ("":0), and
        // every array element at least two including its comma or delimiters.
        // Fresh empty parser trees/arrays do not allocate a retained root/bank.
        let entries = bytes / 4;
        let elements = bytes / 2;
        let nonempty_arrays = bytes / 3;
        let array_capacity = add(multiply(2, elements)?, multiply(4, nonempty_arrays)?)?;
        let dom_tree = super::restore_input_quote::tree_storage(
            entries,
            entries,
            size_of::<String>() + size_of::<Value>(),
            align_of::<String>().max(align_of::<Value>()),
        )?;
        let dom = sum(&[
            bytes,
            multiply(array_capacity, size_of::<Value>())?,
            dom_tree,
            size_of::<Value>(),
        ])?;
        // The canonical parser's per-string serde scratch grows geometrically;
        // its returned String owns at most the original token's decoded bytes.
        let raw_dom_requested_bytes = add(dom, byte_growth(bytes)?)?;

        // The only numeric leaf admitted before body decode is the actual
        // Position phase at body.arguments.cut.phase. Phase/version decoding
        // accepts only integral 0..=3 (including JCS-equivalent float tokens),
        // whose canonical output is one byte. All other leaves retain the
        // string-only restriction, so six output bytes per input byte still
        // bounds the complete canonical bank. bodies::object keeps that bank
        // alive while validating Capture arguments. The two known ryu-js132
        // buffers used by numeric canonicalization and version normalization
        // are included separately; compiler/recursive frames remain excluded.
        let canonical_bytes = multiply(6, bytes)?;
        let canonical_banks = multiply(3, byte_growth(canonical_bytes)?)?;
        let sort_keys = multiply(
            add(multiply(2, bytes)?, multiply(4, entries)?)?,
            size_of::<u16>(),
        )?;
        let sort_tree = super::restore_input_quote::tree_storage(
            entries,
            entries,
            size_of::<Vec<u16>>() + size_of::<(&str, &Value)>(),
            align_of::<Vec<u16>>().max(align_of::<(&str, &Value)>()),
        )?;
        // Four whole-DOM budgets cover the original Envelope, retained typed
        // Begin arguments, each temporary clone during nested body validation,
        // and the correlated Envelope copy. The participant Vec is an additional
        // typed owner, and sorted-ID validation temporarily clones two IDs.
        let typed_validation_requested_bytes = sum(&[
            multiply(4, dom)?,
            canonical_banks,
            sort_keys,
            sort_tree,
            multiply(elements, size_of::<Id>())?,
            bytes,
            2 * 128,
            size_of::<RequestBody>(),
            size_of::<crate::bodies::CaptureArguments>(),
            size_of::<ReceivedFrame>(),
            2 * 132,
        ])?;
        let correlation_requested_bytes = add(
            super::restore_input_quote::tree_storage(
                1,
                1,
                size_of::<Id>() + size_of::<Envelope>(),
                align_of::<Id>().max(align_of::<Envelope>()),
            )?,
            128,
        )?;
        let maximum_requested_bytes = sum(&[
            bytes,
            raw_dom_requested_bytes,
            typed_validation_requested_bytes,
            correlation_requested_bytes,
        ])?;
        Ok(Self {
            maximum_frame_body_bytes: bytes,
            raw_read_requested_bytes: bytes,
            raw_dom_requested_bytes,
            typed_validation_requested_bytes,
            correlation_requested_bytes,
            current_incident_copy_requested_bytes: 0,
            original_descriptor_required_bytes:
                crate::transport::original_frames::original_frame_slot_layout(),
            original_literal_required_bytes: add(bytes, 4)?,
            maximum_requested_bytes,
        })
    }
}

impl Connection<crate::client::DeadlineStream> {
    /// Reads only the selected next Capture under the existing negotiated limit.
    ///
    /// The completed Observe owner authenticates the same original actor, codec,
    /// bank and service before reading. Its old operational cut is not renewed
    /// or reused. Native semantic currency and the Source's actual Core ticket
    /// remain separate caller checks. Service guards are dropped before any
    /// read or containment callback can occur.
    pub(crate) fn receive_original_native_capture_after_quote(
        &mut self,
        quote: &super::native_capture_quote::NativeCaptureSdkCompletedQuote,
        blobs: &crate::blob::BlobReceiver,
        context: &crate::reference_packet::service::OriginalNativeCaptureContext<'_>,
    ) -> Result<Option<ReceivedFrame>, ProviderError> {
        quote.authenticate_same_target_data(self, blobs, context)?;
        if quote
            .sdk_data()
            .future_capture_receive
            .maximum_frame_body_bytes
            != allowance(self.authority.limits().frame_bytes.get())?
        {
            return Err(credit());
        }
        self.ensure_no_pending_native_restore_response()?;
        self.check_authority()?;
        let result = self.receive_inner_with_capture_filter(None, true);
        match &result {
            Ok(None) => self.contain(ConnectionFailure::Read),
            Err(_) => self.contain(ConnectionFailure::Protocol),
            _ => {}
        }
        result
    }
}

/// Admits only the real numeric Position phase at its exact Capture path.
///
/// This is a pre-typed scalar restriction, not a complete body/schema check.
/// Other numbers refuse even if their key is named phase. Missing or otherwise
/// malformed fixed fields remain the normal typed validator's responsibility.
pub(super) fn authenticate_capture_scalar_grammar(
    envelope: &Envelope,
) -> Result<(), ProviderError> {
    fn nonnumeric(value: &Value) -> bool {
        match value {
            Value::Number(_) => false,
            Value::Array(values) => values.iter().all(nonnumeric),
            Value::Object(values) => values.values().all(nonnumeric),
            Value::Null | Value::Bool(_) | Value::String(_) => true,
        }
    }

    fn phase(value: &Value) -> bool {
        // Reject out-of-range or nonnumeric inputs before the real phase
        // decoder, so its error formatter cannot allocate at this guard. The
        // remaining values are exactly its IEEE-754 integral 0..=3 grammar.
        value
            .as_f64()
            .is_some_and(|number| [0.0, 1.0, 2.0, 3.0].contains(&number))
            && crucible_node_format::Phase::deserialize(value).is_ok()
    }

    fn cut(value: &Value) -> bool {
        let Value::Object(fields) = value else {
            return nonnumeric(value);
        };
        fields.iter().all(|(key, value)| {
            if key == "phase" {
                phase(value)
            } else {
                nonnumeric(value)
            }
        })
    }

    fn arguments(value: &Value) -> bool {
        let Value::Object(fields) = value else {
            return nonnumeric(value);
        };
        fields.iter().all(|(key, value)| {
            if key == "cut" {
                cut(value)
            } else {
                nonnumeric(value)
            }
        })
    }

    let valid = envelope.body.iter().all(|(key, value)| {
        if key == "arguments" {
            arguments(value)
        } else {
            nonnumeric(value)
        }
    });
    if !valid {
        return Err(ProviderError::Frame(
            "native Capture numeric scalar grammar",
        ));
    }
    Ok(())
}

fn byte_growth(bytes: usize) -> Result<usize, ProviderError> {
    add(multiply(2, bytes)?, 8)
}

fn add(left: usize, right: usize) -> Result<usize, ProviderError> {
    left.checked_add(right).ok_or_else(credit)
}

fn multiply(left: usize, right: usize) -> Result<usize, ProviderError> {
    left.checked_mul(right).ok_or_else(credit)
}

fn sum(terms: &[usize]) -> Result<usize, ProviderError> {
    terms.iter().try_fold(0, |total, term| add(total, *term))
}

fn credit() -> ProviderError {
    ProviderError::ResourceExhausted("native Capture future receive requested storage")
}

// crucible-lint: allow panic-shortcut -- checked data fixture assertions are the intended test signals.
#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "bounded parser backing and numeric grammar are asserted from real data fixtures"
)]
mod tests {
    use super::*;
    use crate::retained_metadata::MetadataObserver;

    #[test]
    fn raw_parser_actual_backing_stays_within_named_grammar_bound() {
        for input in [
            br#"{"a":[0,0,0,0,0,0,0,0,0],"b":[{},[],{"":"\u0000\u1234"}]}"#.as_slice(),
            br#"[[[[["escaped\\string\nvalue",1e100,true,null]]]]]"#.as_slice(),
            br#"{"a":{},"b":{},"c":{},"d":[],"e":[]}"#.as_slice(),
        ] {
            let quote =
                NativeCaptureFutureReceiveQuote::from_negotiated_frame(input.len()).unwrap();
            let value = canonical::parse_json(input, input.len()).unwrap();
            let mut observer = MetadataObserver::new();
            observer.observe(&value).unwrap();
            let facts = observer.finish();
            let actual = facts.string_capacity_bytes
                + facts.vector_capacity_bytes
                + super::super::restore_input_quote::tree_storage(
                    facts.tree_containers,
                    facts.tree_entries,
                    facts.maximum_tree_key_value_bytes,
                    facts.maximum_tree_entry_alignment.max(1),
                )
                .unwrap();

            // The production bound omits fresh EMPTY roots because these do not
            // allocate; the generic observer deliberately includes empty roots.
            // Observe actual parser payload storage separately for this check.
            fn empty_objects(value: &Value) -> usize {
                match value {
                    Value::Object(values) => {
                        usize::from(values.is_empty())
                            + values.values().map(empty_objects).sum::<usize>()
                    }
                    Value::Array(values) => values.iter().map(empty_objects).sum(),
                    _ => 0,
                }
            }
            let empty_root_slack = super::super::restore_input_quote::tree_storage(
                empty_objects(&value),
                0,
                size_of::<String>() + size_of::<Value>(),
                align_of::<String>().max(align_of::<Value>()),
            )
            .unwrap();
            assert!(actual.saturating_sub(empty_root_slack) <= quote.raw_dom_requested_bytes);
        }
    }

    #[test]
    fn future_receive_sum_excludes_existing_literal_and_descriptor_banks() {
        let quote = NativeCaptureFutureReceiveQuote::from_negotiated_frame(65_536).unwrap();
        assert_eq!(
            quote.maximum_requested_bytes,
            quote.raw_read_requested_bytes
                + quote.raw_dom_requested_bytes
                + quote.typed_validation_requested_bytes
                + quote.correlation_requested_bytes
                + quote.current_incident_copy_requested_bytes
        );
        assert_eq!(quote.original_literal_required_bytes, 65_540);
        assert_eq!(
            quote.original_descriptor_required_bytes,
            crate::transport::original_frames::original_frame_slot_layout()
        );
        assert!(NativeCaptureFutureReceiveQuote::from_negotiated_frame(0).is_err());
        assert!(NativeCaptureFutureReceiveQuote::from_negotiated_frame(16_777_217).is_err());
        assert!(multiply(usize::MAX, 2).is_err());
    }
}

// crucible-lint: allow panic-shortcut -- checked data fixture assertions are the intended test signals.
#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "closed Envelope test data exercises pre-typed scalar rejection"
)]
mod scalar_tests {
    use super::*;

    #[test]
    fn capture_numeric_scalar_rejection_precedes_typed_body_decode() {
        let mut envelope: Envelope = serde_json::from_value(serde_json::json!({
            "protocol":"CNP/1", "message":"request", "session_id":"session",
            "incarnation_id":"incarnation", "node_id":"node", "execution_owner_id":null,
            "capture_owner_id":"capture-owner", "request_id":"capture-request", "operation_id":"capture-operation",
            "sequence":"1", "method":"begin", "body":{"kind":"capture", "arguments":{"nested":["1",null,true]}},
            "extensions":{}
        })).unwrap();
        authenticate_capture_scalar_grammar(&envelope).unwrap();
        envelope.body.insert(
            "arguments".to_owned(),
            serde_json::json!({"nested":["1",{"counter":1}]}),
        );
        assert!(authenticate_capture_scalar_grammar(&envelope).is_err());
        envelope.body.insert(
            "arguments".to_owned(),
            serde_json::json!({"nested":["1",{"counter":"1"}]}),
        );
        authenticate_capture_scalar_grammar(&envelope).unwrap();
    }
}

#[cfg(test)]
mod phase_tests {
    use super::*;
    use crucible_node_format::{Extensions, Phase, Position, Tick, U64};
    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn capture() -> Result<Envelope, Box<dyn std::error::Error>> {
        let arguments = crate::bodies::CaptureArguments {
            capture_id: Id::new("capture")?,
            participant_ids: vec![Id::new("participant")?],
            cut_id: Id::new("cut")?,
            cut: Position::new(Tick::new(7), U64::new(2), Phase::BoundaryControl),
            event_ordinal: U64::new(0),
            ordering_profile: "superdense-v1".to_owned(),
            preservation_contract: Id::new("preservation")?,
        };
        let begin = crate::bodies::BeginRequest {
            kind: crate::bodies::BeginKind::Capture,
            binding_hash: canonical::hash("cnp.owner-binding.v1", b"actual phase fixture")?,
            owner_generation: U64::new(1),
            activation_id: crate::envelope::Nullable(Some(Id::new("activation")?)),
            world_generation: U64::new(1),
            arguments: serde_json::from_value(serde_json::to_value(arguments)?)?,
            extensions: Extensions::new(),
        };
        let mut envelope = crate::envelope::tests::request();
        envelope.method = Method::Begin;
        envelope.body = serde_json::from_value(serde_json::to_value(begin)?)?;
        Ok(envelope)
    }

    #[test]
    fn actual_capture_arguments_accept_only_the_exact_phase_path_and_real_version_forms()
    -> TestResult {
        let mut envelope = capture()?;
        authenticate_capture_scalar_grammar(&envelope)?;
        crate::bodies::decode_request(Method::Begin, &envelope.body)?;
        for token in ["0", "1", "2", "3", "1.0", "1e0", "-0.0"] {
            let value: Value = serde_json::from_str(token)?;
            Phase::deserialize(&value)?;
            envelope
                .body
                .get_mut("arguments")
                .ok_or("arguments absent")?
                .get_mut("cut")
                .ok_or("cut absent")?["phase"] = value;
            authenticate_capture_scalar_grammar(&envelope)?;
            crate::bodies::decode_request(Method::Begin, &envelope.body)?;
        }
        for token in ["4", "-1", "0.5", "1e100", "\"1\"", "true", "null"] {
            let value: Value = serde_json::from_str(token)?;
            assert!(Phase::deserialize(&value).is_err());
            envelope
                .body
                .get_mut("arguments")
                .ok_or("arguments absent")?
                .get_mut("cut")
                .ok_or("cut absent")?["phase"] = value;
            assert!(authenticate_capture_scalar_grammar(&envelope).is_err());
        }
        Ok(())
    }

    #[test]
    fn numeric_phase_cannot_be_moved_to_another_body_path() -> TestResult {
        for change in 0..3 {
            let mut envelope = capture()?;
            match change {
                0 => {
                    envelope
                        .body
                        .insert("owner_generation".into(), serde_json::json!(1));
                }
                1 => {
                    envelope.body.insert("phase".into(), serde_json::json!(1));
                }
                _ => {
                    envelope
                        .body
                        .get_mut("arguments")
                        .ok_or("arguments absent")?["extra"] =
                        serde_json::json!({"cut":{"phase":1}});
                }
            }
            assert!(authenticate_capture_scalar_grammar(&envelope).is_err());
        }
        Ok(())
    }
}
