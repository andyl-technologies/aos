//! Checks historical typed envelopes against their exact canonical literal bodies.
//!
//! Borrowed field scans compare final admitted owners without creating a second
//! envelope DOM or encoded buffer. Object lookup has an explicit work bound;
//! canonical object keys retain their required UTF-16 order.

use super::typed::{Fields, invalid};
use crate::{ProviderError, envelope::Envelope};
use serde::Serialize;
use serde_json::Value;
use std::io::Write;

const MAXIMUM_COMPARISON_WORK: usize = 64 * 1024 * 1024;

/// Names the explicit borrowed comparison views and scalar writer workspace.
///
/// The closed walker permits at most64 nested values. Each level is charged
/// conservatively for both container alternatives and scalar comparison views;
/// the byte span scanner and numeric formatter work are also charged at every
/// level even though those particular work buffers are sequential. This is
/// requested explicit Rust data, not a compiler-frame or allocator claim.
pub(crate) const fn envelope_comparison_scratch_data() -> usize {
    64 * (std::mem::size_of::<Fields<'static>>()
        + std::mem::size_of::<serde_json::map::Iter<'static>>()
        + std::mem::size_of::<std::slice::Iter<'static, Value>>()
        + std::mem::size_of::<ComparisonSink<'static>>()
        + std::mem::size_of::<[u8;128]>()
        // Pinned ryu-js1.0.3 Buffer; only Number leaves enter canonical writing.
        + std::mem::size_of::<[u8;132]>()
        + std::mem::size_of::<(&'static [u8], &'static Value, Option<&'static str>)>()
        + 4 * std::mem::size_of::<usize>())
}

// Names only the explicit borrowed parser/writer layouts used by envelope().
// Recursive compiler frames and caller-owned raw/typed banks remain separate.
pub(crate) fn envelope_counter_scratch_data() -> usize {
    std::mem::size_of::<Fields<'static>>() * 2
        + std::mem::size_of::<ComparisonSink<'static>>()
        + std::mem::size_of::<serde_json::Serializer<&mut ComparisonSink<'static>>>()
        + std::mem::size_of::<usize>()
        + 20
}

/// Names the fixed scanner/writer layouts and one decimal formatter bank.
///
/// Closed proof ACKs contain string/U64 leaves; each scalar formatter finishes
/// before the next one. Recursive/compiler frames and allocator residency are
/// separate obligations, not inferred by this requested-layout data getter.
pub(crate) const fn closed_envelope_comparison_scratch_data() -> usize {
    std::mem::size_of::<Fields<'static>>()
        + std::mem::size_of::<ComparisonSink<'static>>()
        + std::mem::size_of::<serde_json::Serializer<&mut ComparisonSink<'static>>>()
        + std::mem::size_of::<[u8; 128]>()
        + std::mem::size_of::<usize>()
        + 20
}

pub(crate) fn envelope(original: &Envelope, bytes: &[u8]) -> Result<(), ProviderError> {
    let mut fields = Fields::object(bytes)?;
    let mut work = MAXIMUM_COMPARISON_WORK;
    object(fields.named("body")?, original.body.iter(), 0, &mut work)?;
    scalar(
        fields.named("capture_owner_id")?,
        &original.capture_owner_id,
    )?;
    scalar(
        fields.named("execution_owner_id")?,
        &original.execution_owner_id,
    )?;
    object(
        fields.named("extensions")?,
        original.extensions.iter(),
        0,
        &mut work,
    )?;
    scalar(fields.named("incarnation_id")?, &original.incarnation_id)?;
    scalar(fields.named("message")?, &original.message)?;
    scalar(fields.named("method")?, &original.method)?;
    scalar(fields.named("node_id")?, &original.node_id)?;
    scalar(fields.named("operation_id")?, &original.operation_id)?;
    scalar(fields.named("protocol")?, &original.protocol)?;
    scalar(fields.named("request_id")?, &original.request_id)?;
    // The sequence has the closed U64 string grammar. Comparing its checked
    // digits avoids the U64 serializer's temporary String during cold walks.
    if super::typed::unsigned(super::typed::plain_string(fields.named("sequence")?)?.as_bytes())?
        != original.sequence.get()
    {
        return Err(invalid());
    }
    scalar(fields.named("session_id")?, &original.session_id)?;
    fields.finish()
}

/// Compares a complete portable reference through its actual canonical fields.
pub(crate) fn content_reference(
    original: &crucible_node_format::ContentRef,
    bytes: &[u8],
) -> Result<(), ProviderError> {
    let mut fields = Fields::object(bytes)?;
    let mut hash = Fields::object(fields.named("hash")?)?;
    scalar(hash.named("algorithm")?, &original.hash.algorithm)?;
    scalar(hash.named("digest")?, &original.hash.digest)?;
    scalar(hash.named("domain")?, &original.hash.domain)?;
    hash.finish()?;
    scalar(fields.named("length")?, &original.length)?;
    scalar(fields.named("media_type")?, &original.media_type)?;
    fields.finish()
}

/// Compares a complete retained Value without constructing another DOM or buffer.
pub(crate) fn json_value(original: &Value, bytes: &[u8]) -> Result<(), ProviderError> {
    let mut work = MAXIMUM_COMPARISON_WORK;
    value(bytes, original, 0, &mut work)
}

fn object<'a>(
    bytes: &[u8],
    values: impl Clone + Iterator<Item = (&'a String, &'a Value)>,
    depth: usize,
    work: &mut usize,
) -> Result<(), ProviderError> {
    if depth >= 64 {
        return Err(invalid());
    }
    charge(work, bytes.len())?;
    let mut fields = Fields::object(bytes)?;
    let mut previous: Option<&str> = None;
    let mut count = 0usize;
    while let Some((key, body)) = fields.pair()? {
        let mut found = None;
        for (candidate, value) in values.clone() {
            charge(work, key.len().saturating_add(candidate.len()))?;
            if serialized_equal(key, candidate)? {
                found = Some((candidate, value));
                break;
            }
        }
        let (key, body_value) = found.ok_or_else(invalid)?;
        if previous.is_some_and(|one| one.encode_utf16().cmp(key.encode_utf16()).is_ge()) {
            return Err(invalid());
        }
        previous = Some(key);
        value(body, body_value, depth + 1, work)?;
        count = count.checked_add(1).ok_or_else(invalid)?;
    }
    fields.finish()?;
    if count != values.count() {
        return Err(invalid());
    }
    Ok(())
}

fn value(
    bytes: &[u8],
    original: &Value,
    depth: usize,
    work: &mut usize,
) -> Result<(), ProviderError> {
    charge(work, bytes.len())?;
    match original {
        Value::Object(values) => object(bytes, values.iter(), depth, work),
        Value::Array(values) => {
            if depth >= 64 {
                return Err(invalid());
            }
            let mut fields = Fields::array(bytes)?;
            for original in values {
                value(
                    fields.next()?.ok_or_else(invalid)?,
                    original,
                    depth + 1,
                    work,
                )?;
            }
            fields.finish()
        }
        Value::Number(_) => {
            // Only this Number leaf reaches the canonical writer: no map/key
            // sorting or String scratch is constructed by that algorithm.
            let mut sink = ComparisonSink::new(bytes);
            crucible_node_format::canonical::canonical_json_to_writer(original, &mut sink)?;
            sink.finish()
        }
        _ => scalar(bytes, original),
    }
}

fn charge(work: &mut usize, extent: usize) -> Result<(), ProviderError> {
    *work = work
        .checked_sub(extent)
        .ok_or(ProviderError::ResourceExhausted(
            "historical canonical correspondence work",
        ))?;
    Ok(())
}

pub(super) fn scalar(bytes: &[u8], original: &impl Serialize) -> Result<(), ProviderError> {
    if !serialized_equal(bytes, original)? {
        return Err(invalid());
    }
    Ok(())
}

fn serialized_equal(bytes: &[u8], original: &impl Serialize) -> Result<bool, ProviderError> {
    let mut sink = ComparisonSink::new(bytes);
    serde_json::to_writer(&mut sink, original).map_err(|_| invalid())?;
    Ok(sink.position == bytes.len() && sink.equal)
}

struct ComparisonSink<'a> {
    bytes: &'a [u8],
    position: usize,
    equal: bool,
}

impl<'a> ComparisonSink<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            position: 0,
            equal: true,
        }
    }

    fn finish(self) -> Result<(), ProviderError> {
        if !self.equal || self.position != self.bytes.len() {
            return Err(invalid());
        }
        Ok(())
    }
}

impl Write for ComparisonSink<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let Some(end) = self.position.checked_add(bytes.len()) else {
            self.equal = false;
            return Err(std::io::ErrorKind::InvalidData.into());
        };
        self.equal &= self.bytes.get(self.position..end) == Some(bytes);
        self.position = end;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "historical literal correspondence assertions"
)]
mod tests {
    use super::*;
    use crate::envelope::{MessageKind, Method, Nullable};
    use crucible_node_format::{Extensions, Id, U64, canonical};

    fn original() -> Envelope {
        Envelope {
            protocol: "CNP/1".into(),
            message: MessageKind::Request,
            session_id: Nullable(Some(Id::new("session").unwrap())),
            incarnation_id: Nullable(Some(Id::new("incarnation").unwrap())),
            node_id: Nullable(Some(Id::new("node").unwrap())),
            execution_owner_id: Nullable(Some(Id::new("owner").unwrap())),
            capture_owner_id: Nullable(None),
            request_id: Nullable(Some(Id::new("request").unwrap())),
            operation_id: Nullable(None),
            sequence: U64::new(2),
            method: Method::Admit,
            body: serde_json::json!({"float":1.0,"negative_zero":-0.0,"large":u64::MAX,
                "nested":{"\u{10000}":"quoted\"value","\u{e000}":[null,true]}})
            .as_object()
            .unwrap()
            .clone(),
            extensions: Extensions::new(),
        }
    }

    #[test]
    fn actual_canonical_writer_matches_full_typed_values_without_a_second_dom() {
        let expected = original();
        let bytes = canonical::canonical_json(&serde_json::to_value(&expected).unwrap()).unwrap();
        envelope(&expected, &bytes).unwrap();
        let mut changed = expected.clone();
        changed.body.insert("float".into(), serde_json::json!(2.0));
        assert!(envelope(&changed, &bytes).is_err());
        changed = expected.clone();
        changed.sequence = U64::new(3);
        assert!(envelope(&changed, &bytes).is_err());
    }

    #[test]
    fn envelope_sequence_retains_canonical_u64_grammar_without_temporary_encoding() {
        let mut expected = original();
        expected.sequence = U64::new(u64::MAX);
        let bytes = canonical::canonical_json(&serde_json::to_value(&expected).unwrap()).unwrap();

        envelope(&expected, &bytes).unwrap();
        let text = std::str::from_utf8(&bytes).unwrap();
        let changed = text.replace(
            "\"sequence\":\"18446744073709551615\"",
            "\"sequence\":\"018446744073709551615\"",
        );
        assert_ne!(changed, text);
        assert!(envelope(&expected, changed.as_bytes()).is_err());
    }

    #[test]
    fn reordered_or_duplicate_fields_and_extra_values_refuse() {
        let expected = original();
        let noncanonical = serde_json::to_vec(&expected).unwrap();
        assert!(envelope(&expected, &noncanonical).is_err());
        let mut bytes =
            canonical::canonical_json(&serde_json::to_value(&expected).unwrap()).unwrap();
        bytes.push(b' ');
        assert!(envelope(&expected, &bytes).is_err());
        let mut work = 0;
        assert!(value(b"null", &Value::Null, 0, &mut work).is_err());
    }
}

/// Reads only the closed message discriminator before selecting the first reply.
pub(super) fn is_response(bytes: &[u8]) -> Result<bool, ProviderError> {
    let mut fields = Fields::object(bytes)?;
    fields.named("body")?;
    fields.named("capture_owner_id")?;
    fields.named("execution_owner_id")?;
    fields.named("extensions")?;
    fields.named("incarnation_id")?;
    Ok(fields.named("message")? == b"\"response\"")
}

pub(crate) fn realize_request(
    original: &crate::bodies::RealizeRequest,
    bytes: &[u8],
) -> Result<(), ProviderError> {
    let crate::bodies::RealizeRequest {
        realization_id,
        configuration,
        requested_node_ids,
        resource_limits,
        extensions,
    } = original;
    let mut body = Fields::object(bytes)?;
    content_reference(configuration, body.named("configuration")?)?;
    let mut work = MAXIMUM_COMPARISON_WORK;
    object(body.named("extensions")?, extensions.iter(), 0, &mut work)?;
    scalar(body.named("realization_id")?, realization_id)?;
    scalar(body.named("requested_node_ids")?, requested_node_ids)?;
    let mut limits = Fields::object(body.named("resource_limits")?)?;
    let crucible_node_format::ResourceLimits {
        cpu_budget_ns,
        memory_bytes,
        writable_bytes,
        processes,
        descriptors,
        pending_events,
        content_bytes,
        maximum_operations,
        extensions,
    } = resource_limits;
    scalar(limits.named("content_bytes")?, content_bytes)?;
    scalar(limits.named("cpu_budget_ns")?, cpu_budget_ns)?;
    scalar(limits.named("descriptors")?, descriptors)?;
    object(limits.named("extensions")?, extensions.iter(), 0, &mut work)?;
    scalar(limits.named("maximum_operations")?, maximum_operations)?;
    scalar(limits.named("memory_bytes")?, memory_bytes)?;
    scalar(limits.named("pending_events")?, pending_events)?;
    scalar(limits.named("processes")?, processes)?;
    scalar(limits.named("writable_bytes")?, writable_bytes)?;
    limits.finish()?;
    body.finish()
}
