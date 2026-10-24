//! Rebuilds typed historical envelopes from borrowed fields and capacity rows.
//!
//! The closed field order matches the actual Envelope serde writer. Bodies and
//! extensions use the same captured Value/Number serialization, preserving float
//! variants rather than canonicalizing their numeric spelling. This parser
//! issues historical data only; it cannot authenticate a source, cut or actor.
//!
//! ```text
//! {"protocol":...,"message":...,"session_id":...,"incarnation_id":...,
//!  "node_id":...,"execution_owner_id":...,"capture_owner_id":...,
//!  "request_id":...,"operation_id":...,"sequence":...,"method":...,
//!  "body":{...},"extensions":{...}}
//! ```

use super::json_value::{HistoricalJsonLimits, ValidatedHistoricalJson};
use crate::retained_metadata::records::{MetadataRecordKind, MetadataRecordRows};
use crate::{
    ProviderError,
    envelope::{Envelope, MessageKind, Method, Nullable},
};
use crucible_node_format::{Id, U64};

/// Borrows a complete checked envelope and its exact metadata-row prefix.
pub struct ValidatedHistoricalEnvelope<'input, 'records> {
    protocol: HistoricalString<'input>,
    message: MessageKind,
    ids: [Option<HistoricalString<'input>>; 7],
    sequence: U64,
    method: Method,
    body: ValidatedHistoricalJson<'input, 'records>,
    extensions: ValidatedHistoricalJson<'input, 'records>,
    remaining: MetadataRecordRows<'records>,
}

impl<'input, 'records> ValidatedHistoricalEnvelope<'input, 'records> {
    /// Checks complete fixed fields and all body/extension capacity rows.
    ///
    /// Full borrowed grammar and row validation precedes any final String,
    /// identifier or JSON owner construction. The caller separately validates
    /// the complete whole-protocol roster and its aggregate backing allowances.
    ///
    /// # Errors
    /// Refuses unknown or reordered fields, invalid IDs/counters/methods,
    /// capacity disagreement, malformed JSON or excess data limits.
    pub fn validate(
        input: &'input [u8],
        mut records: MetadataRecordRows<'records>,
        limits: HistoricalJsonLimits,
    ) -> Result<Self, ProviderError> {
        if input.len() > limits.maximum_input_bytes {
            return Err(invalid());
        }
        let mut cursor = Cursor { input, position: 0 };
        cursor.literal(b"{\"protocol\":")?;
        let protocol = HistoricalString::capture(cursor.string()?, &mut records)?;
        if protocol.text != "CNP/1" {
            return Err(invalid());
        }
        cursor.field(b"message")?;
        let message = match cursor.string()? {
            "request" => MessageKind::Request,
            "response" => MessageKind::Response,
            "event" => MessageKind::Event,
            _ => return Err(invalid()),
        };
        let mut ids = [None; 7];
        for (slot, name) in ids.iter_mut().zip([
            b"session_id".as_slice(),
            b"incarnation_id",
            b"node_id",
            b"execution_owner_id",
            b"capture_owner_id",
            b"request_id",
            b"operation_id",
        ]) {
            cursor.field(name)?;
            if cursor.take(b"null") {
                continue;
            }
            let text = cursor.string()?;
            if text.is_empty()
                || text.len() > 128
                || !text.as_bytes()[0].is_ascii_alphanumeric()
                || !text
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"._:/-".contains(&byte))
            {
                return Err(invalid());
            }
            *slot = Some(HistoricalString::capture(text, &mut records)?);
        }
        cursor.field(b"sequence")?;
        let sequence = cursor.string()?;
        if sequence.is_empty() || (sequence.len() > 1 && sequence.starts_with('0')) {
            return Err(invalid());
        }
        let mut counter = 0u64;
        for digit in sequence.bytes() {
            if !digit.is_ascii_digit() {
                return Err(invalid());
            }
            counter = counter
                .checked_mul(10)
                .and_then(|value| value.checked_add(u64::from(digit - b'0')))
                .ok_or_else(invalid)?;
        }
        cursor.field(b"method")?;
        let method = method(cursor.string()?)?;
        cursor.field(b"body")?;
        let body_bytes = cursor.object_span()?;
        let body = ValidatedHistoricalJson::validate(body_bytes, records, limits)?;
        cursor.field(b"extensions")?;
        let extension_bytes = cursor.object_span()?;
        let extensions =
            ValidatedHistoricalJson::validate(extension_bytes, body.remaining_records(), limits)?;
        cursor.literal(b"}")?;
        if cursor.position != input.len() {
            return Err(invalid());
        }
        let remaining = extensions.remaining_records();
        Ok(Self {
            protocol,
            message,
            ids,
            sequence: U64::new(counter),
            method,
            body,
            extensions,
            remaining,
        })
    }

    pub(crate) fn authenticate_historical_admit_reply(
        &self,
        response: &Self,
    ) -> Result<(), ProviderError> {
        if self.message != MessageKind::Request
            || self.method != Method::Admit
            || response.message != MessageKind::Response
            || response.method != self.method
            || self
                .ids
                .iter()
                .zip(response.ids.iter())
                .any(|(left, right)| left.map(|field| field.text) != right.map(|field| field.text))
        {
            return Err(invalid());
        }
        Ok(())
    }

    pub(crate) fn authenticate_historical_restore_reply(
        &self,
        response: &Self,
    ) -> Result<(), ProviderError> {
        if self.message != MessageKind::Request
            || self.method != Method::Begin
            || response.message != MessageKind::Response
            || response.method != self.method
            || self
                .ids
                .iter()
                .zip(response.ids.iter())
                .any(|(left, right)| left.map(|field| field.text) != right.map(|field| field.text))
        {
            return Err(invalid());
        }
        Ok(())
    }

    /// Borrows the next typed field's rows without copying the roster.
    pub fn remaining_records(&self) -> MetadataRecordRows<'records> {
        self.remaining.clone()
    }

    /// Reconstructs final typed Envelope data with the recorded String capacities.
    ///
    /// No serde DTO parser or intermediate whole-envelope DOM is used. Root
    /// extensions are built directly into the final contract BTreeMap; physical
    /// tree allocation geometry remains a separate whole-owner prerequisite.
    ///
    /// # Errors
    /// Refuses exact-capacity reservation failure or an inconsistent validated
    /// layout. Input bytes and capacity rows remain immutably borrowed.
    pub fn reconstruct(&self) -> Result<Envelope, ProviderError> {
        let protocol = self.protocol.reconstruct()?;
        let mut ids: [Option<Id>; 7] = std::array::from_fn(|_| None);
        for (target, original) in ids.iter_mut().zip(self.ids) {
            if let Some(original) = original {
                *target = Some(Id::new(original.reconstruct()?)?);
            }
        }
        let serde_json::Value::Object(body) = self.body.reconstruct()? else {
            return Err(invalid());
        };
        let extensions = self.extensions.reconstruct_extensions()?;
        let [
            session_id,
            incarnation_id,
            node_id,
            execution_owner_id,
            capture_owner_id,
            request_id,
            operation_id,
        ] = ids;
        Ok(Envelope {
            protocol,
            message: self.message,
            session_id: Nullable(session_id),
            incarnation_id: Nullable(incarnation_id),
            node_id: Nullable(node_id),
            execution_owner_id: Nullable(execution_owner_id),
            capture_owner_id: Nullable(capture_owner_id),
            request_id: Nullable(request_id),
            operation_id: Nullable(operation_id),
            sequence: self.sequence,
            method: self.method,
            body,
            extensions,
        })
    }
}

#[derive(Clone, Copy)]
struct HistoricalString<'a> {
    text: &'a str,
    capacity: usize,
}

impl<'a> HistoricalString<'a> {
    fn capture(text: &'a str, records: &mut MetadataRecordRows<'_>) -> Result<Self, ProviderError> {
        let row = records.next().ok_or_else(invalid)??;
        if row.kind != MetadataRecordKind::String
            || row.element_bytes != 1
            || row.extent < text.len()
        {
            return Err(invalid());
        }
        Ok(Self {
            text,
            capacity: row.extent,
        })
    }

    fn reconstruct(self) -> Result<String, ProviderError> {
        let mut text = String::new();
        text.try_reserve_exact(self.capacity)
            .map_err(|_| ProviderError::ResourceExhausted("historical envelope String"))?;
        if text.capacity() != self.capacity {
            return Err(invalid());
        }
        text.push_str(self.text);
        Ok(text)
    }
}

fn method(text: &str) -> Result<Method, ProviderError> {
    Ok(match text {
        "hello" => Method::Hello,
        "discover" => Method::Discover,
        "realize" => Method::Realize,
        "admit" => Method::Admit,
        "activate" => Method::Activate,
        "input" => Method::Input,
        "observe" => Method::Observe,
        "begin" => Method::Begin,
        "poll" => Method::Poll,
        "cancel" => Method::Cancel,
        "quantum_close" => Method::QuantumClose,
        "world_activate" => Method::WorldActivate,
        "abort" => Method::Abort,
        "retire" => Method::Retire,
        "blob_begin" => Method::BlobBegin,
        "blob_chunk" => Method::BlobChunk,
        "blob_finish" => Method::BlobFinish,
        "release" => Method::Release,
        "operation_update" => Method::OperationUpdate,
        "observation_ready" => Method::ObservationReady,
        "provider_fault" => Method::ProviderFault,
        _ => return Err(invalid()),
    })
}

struct Cursor<'a> {
    input: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, literal: &[u8]) -> bool {
        if self.input[self.position..].starts_with(literal) {
            self.position += literal.len();
            true
        } else {
            false
        }
    }

    fn literal(&mut self, literal: &[u8]) -> Result<(), ProviderError> {
        if self.take(literal) {
            Ok(())
        } else {
            Err(invalid())
        }
    }

    fn field(&mut self, name: &[u8]) -> Result<(), ProviderError> {
        self.literal(b",\"")?;
        self.literal(name)?;
        self.literal(b"\":")
    }

    fn string(&mut self) -> Result<&'a str, ProviderError> {
        self.literal(b"\"")?;
        let start = self.position;
        while let Some(byte) = self.input.get(self.position).copied() {
            if byte == b'"' {
                let value = std::str::from_utf8(&self.input[start..self.position])
                    .map_err(|_| invalid())?;
                self.position += 1;
                return Ok(value);
            }
            if byte < 32 || byte == b'\\' {
                return Err(invalid());
            }
            self.position += 1;
        }
        Err(invalid())
    }

    fn object_span(&mut self) -> Result<&'a [u8], ProviderError> {
        let start = self.position;
        self.literal(b"{")?;
        let mut closings = [0u8; 64];
        closings[0] = b'}';
        let mut depth = 1usize;
        let mut string = false;
        let mut escaped = false;
        while let Some(byte) = self.input.get(self.position).copied() {
            self.position += 1;
            if string {
                if escaped {
                    escaped = false;
                } else if byte == b'\\' {
                    escaped = true;
                } else if byte == b'"' {
                    string = false;
                }
                continue;
            }
            match byte {
                b'"' => string = true,
                b'{' | b'[' => {
                    if depth == closings.len() {
                        return Err(invalid());
                    }
                    closings[depth] = if byte == b'{' { b'}' } else { b']' };
                    depth += 1;
                }
                b'}' | b']' => {
                    if closings[depth - 1] != byte {
                        return Err(invalid());
                    }
                    depth -= 1;
                    if depth == 0 {
                        return Ok(&self.input[start..self.position]);
                    }
                }
                _ => {}
            }
        }
        Err(invalid())
    }
}

fn invalid() -> ProviderError {
    ProviderError::Frame("historical typed Envelope grammar or capacity rows")
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "typed historical owners retain exact original capacities and subtype"
)]
mod tests {
    use super::*;
    use crate::retained_metadata::{
        MetadataObserver,
        records::{MetadataRecordBank, ValidatedMetadataRecords},
    };

    fn limits() -> HistoricalJsonLimits {
        HistoricalJsonLimits {
            maximum_input_bytes: 65536,
            maximum_nodes: 4096,
            maximum_depth: 64,
            maximum_owned_backing_bytes: 65536,
            maximum_tree_entries: 256,
        }
    }

    #[test]
    fn actual_typed_envelope_restores_both_maps_and_float_subtype() {
        let mut original = crate::envelope::tests::request();
        let mut protocol = String::with_capacity(73);
        protocol.push_str("CNP/1");
        original.protocol = protocol;
        let mut text = String::with_capacity(59);
        text.push_str("escaped \" \\ café");
        original
            .body
            .insert("historical".into(), serde_json::Value::String(text));
        original.body.insert(
            "float".into(),
            serde_json::Value::Number(serde_json::Number::from_f64(1.0).unwrap()),
        );
        let mut extension_key = String::with_capacity(67);
        extension_key.push_str("original-extension");
        let mut children = Vec::with_capacity(9);
        children.push(serde_json::Value::String(String::with_capacity(37)));
        original
            .extensions
            .insert(extension_key, serde_json::Value::Array(children));
        let mut bank = MetadataRecordBank::reserve(256).unwrap();
        let mut observer = MetadataObserver::recording(&mut bank);
        observer.observe(&original).unwrap();
        let facts = observer.finish();
        assert_eq!(facts.capacity_records, bank.rows().len());
        let encoded = serde_json::to_vec(&original).unwrap();
        let rows = serde_json::to_vec(&bank).unwrap();
        let records = ValidatedMetadataRecords::validate(&rows, 256, 65536).unwrap();
        let plan =
            ValidatedHistoricalEnvelope::validate(&encoded, records.rows(), limits()).unwrap();
        assert!(plan.remaining_records().next().is_none());
        let restored = plan.reconstruct().unwrap();

        assert_eq!(restored, original);
        assert_eq!(restored.protocol.capacity(), 73);
        assert!(restored.body["float"].as_number().unwrap().is_f64());
        assert_eq!(
            restored.body["historical"].as_str().unwrap(),
            original.body["historical"].as_str().unwrap()
        );
        let key = restored.extensions.keys().next().unwrap();
        assert_eq!(key.capacity(), 67);
        let values = restored.extensions[key].as_array().unwrap();
        assert_eq!(values.capacity(), 9);
        let serde_json::Value::String(empty) = &values[0] else {
            panic!("original empty String lost");
        };
        assert_eq!(empty.capacity(), 37);
        assert_eq!(serde_json::to_vec(&restored).unwrap(), encoded);
    }
}

/// Names fixed controls of borrowed Envelope validation, excluding reconstruction.
pub(crate) fn borrowed_validation_counter_scratch_data() -> usize {
    use std::mem::size_of;

    size_of::<ValidatedHistoricalEnvelope<'static, 'static>>()
        + size_of::<Result<ValidatedHistoricalEnvelope<'static, 'static>, ProviderError>>()
        + size_of::<Cursor<'static>>()
        + size_of::<HistoricalString<'static>>()
        + size_of::<Result<HistoricalString<'static>, ProviderError>>()
        + size_of::<[Option<HistoricalString<'static>>; 7]>()
        + size_of::<
            std::iter::Zip<
                std::slice::IterMut<'static, Option<HistoricalString<'static>>>,
                std::array::IntoIter<&'static [u8], 7>,
            >,
        >()
        + size_of::<
            Option<(
                &'static mut Option<HistoricalString<'static>>,
                &'static [u8],
            )>,
        >()
        + size_of::<MessageKind>()
        + size_of::<Method>()
        + size_of::<U64>()
        + size_of::<u64>()
        + size_of::<ValidatedHistoricalJson<'static, 'static>>() * 2
        + size_of::<Result<ValidatedHistoricalJson<'static, 'static>, ProviderError>>()
        + size_of::<MetadataRecordRows<'static>>()
        + size_of::<HistoricalJsonLimits>()
        + size_of::<&'static str>() * 2
        + size_of::<Option<u8>>()
        + size_of::<std::str::Bytes<'static>>()
        + size_of::<Result<(), ProviderError>>()
        + super::json_value::borrowed_validation_counter_scratch_data()
}
