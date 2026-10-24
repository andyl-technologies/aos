//! Joins an already owned SDK terminal to its exact retained native occurrence.
//!
//! The only native input is the private once-owned graph DATA. Comparisons stream
//! against its actual compact sent slot; no old frame bank, DOM, alias scratch or
//! terminal cache is reconstructed merely to perform this join.

use super::*;
use crate::envelope::Envelope;
use crate::protocol_snapshot::native_wholegraph17::NativeCurrentGraph17Data;
use serde::Serialize;
use serde_json::Value;
use std::io::Write;

/// Matches the complete SDK terminal to one actual native outgoing occurrence.
///
/// The historical verifier separately binds `original` to its signed Boot loan.
/// This function checks full CNP response scope, terminal canonical bytes, actual
/// sent progress and mirror-safe slot identity. It grants no live permission.
///
/// # Errors
/// Refuses incomplete DATA, another original/terminal scope, incomplete send,
/// changed body/extensions or differing native occurrences for one terminal.
pub(crate) fn authenticate_native17_retained_terminal_data(
    data: &NativeCurrentGraph17Data,
    original: &Envelope,
    terminal: &Envelope,
) -> Result<(), ProviderError> {
    data.validate_data()?;
    original.matches_response(terminal)?;
    if terminal.body.get("status").and_then(Value::as_str) != Some("completed") {
        return Err(invalid());
    }
    let roots = data.raw_root_spans_data()?;
    let frames = Frames17::read(roots.frames_data())?;
    let endpoint = roots.endpoint_data();
    let records = field(endpoint, "records")?;
    let mut found = None;
    for record_index in 0..count(records)? {
        let record = item(records, record_index)?;
        let originals = field(record, "originals")?;
        let slots = field(record, "original_slots")?;
        let sent = quantity(field(record, "sent")?)?;
        if sent > count(slots)? || count(slots)? > count(originals)? {
            return Err(invalid());
        }
        for original_index in 0..sent {
            let candidate = item(originals, original_index)?;
            if !same_terminal_header(candidate, terminal)? {
                continue;
            }
            let literal_slot = quantity(item(slots, original_index)?)?;
            authenticate_literal(candidate, terminal, literal_slot, frames)?;
            retain_terminal(
                &mut found,
                BorrowedTerminal17 {
                    encoded: candidate,
                    location: BorrowedTerminal17Location::Record {
                        record: record_index,
                        original: original_index,
                    },
                    literal_slot,
                },
            )?;
        }
    }
    let responses = field(roots.connection_data(), "restore_responses")?;
    for slot in 0..2 {
        let response = item(responses, slot)?;
        if response == b"null" {
            continue;
        }
        let candidate = field(response, "original")?;
        if !same_terminal_header(candidate, terminal)? {
            continue;
        }
        if field(response, "phase")? != b"\"complete\"" {
            return Err(invalid());
        }
        let literal_slot = quantity(field(response, "literal_slot")?)?;
        authenticate_literal(candidate, terminal, literal_slot, frames)?;
        retain_terminal(
            &mut found,
            BorrowedTerminal17 {
                encoded: candidate,
                location: BorrowedTerminal17Location::Assigned { slot },
                literal_slot,
            },
        )?;
    }
    found.ok_or_else(invalid)?;
    Ok(())
}

fn authenticate_literal(
    source: &[u8],
    terminal: &Envelope,
    slot: usize,
    frames: Frames17<'_>,
) -> Result<(), ProviderError> {
    let frame = frames.frame(slot)?;
    if frame.incoming || !frame.complete || frame.transferred != frame.bytes.len() {
        return Err(invalid());
    }
    let body = frame
        .bytes
        .range(4, frame.bytes.len().checked_sub(4).ok_or_else(invalid)?)?;
    body.canonical(source)?;
    let mut sink = ExactBytes17::new(body)?;
    write_envelope(terminal, &mut sink)?;
    sink.finish()
}

fn same_terminal_header(source: &[u8], terminal: &Envelope) -> Result<bool, ProviderError> {
    if field(source, "message")? != b"\"response\""
        || field(field(source, "body")?, "status")? != b"\"completed\""
        || quoted(field(source, "sequence")?)? != terminal.sequence.get()
    {
        return Ok(false);
    }
    Ok(
        equal_scalar(field(source, "protocol")?, &terminal.protocol)?
            && equal_scalar(field(source, "message")?, &terminal.message)?
            && equal_scalar(field(source, "method")?, &terminal.method)?
            && equal_scalar(field(source, "session_id")?, &terminal.session_id)?
            && equal_scalar(field(source, "incarnation_id")?, &terminal.incarnation_id)?
            && equal_scalar(field(source, "node_id")?, &terminal.node_id)?
            && equal_scalar(
                field(source, "execution_owner_id")?,
                &terminal.execution_owner_id,
            )?
            && equal_scalar(
                field(source, "capture_owner_id")?,
                &terminal.capture_owner_id,
            )?
            && equal_scalar(field(source, "request_id")?, &terminal.request_id)?
            && equal_scalar(field(source, "operation_id")?, &terminal.operation_id)?,
    )
}

fn equal_scalar(source: &[u8], value: &impl Serialize) -> Result<bool, ProviderError> {
    struct ScalarSink<'a> {
        expected: &'a [u8],
        position: usize,
        equal: bool,
    }
    impl Write for ScalarSink<'_> {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            let end = self
                .position
                .checked_add(bytes.len())
                .ok_or(std::io::ErrorKind::InvalidData)?;
            self.equal &= self.expected.get(self.position..end) == Some(bytes);
            self.position = end;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut sink = ScalarSink {
        expected: source,
        position: 0,
        equal: true,
    };
    serde_json::to_writer(&mut sink, value).map_err(|_| invalid())?;
    Ok(sink.equal && sink.position == source.len())
}

fn write_envelope(original: &Envelope, output: &mut impl Write) -> Result<(), ProviderError> {
    let mut work = 64usize * 1024 * 1024;
    output.write_all(b"{\"body\":")?;
    write_object(original.body.iter(), output, 1, &mut work)?;
    output.write_all(b",\"capture_owner_id\":")?;
    serde_json::to_writer(&mut *output, &original.capture_owner_id).map_err(|_| invalid())?;
    output.write_all(b",\"execution_owner_id\":")?;
    serde_json::to_writer(&mut *output, &original.execution_owner_id).map_err(|_| invalid())?;
    output.write_all(b",\"extensions\":")?;
    write_object(original.extensions.iter(), output, 1, &mut work)?;
    output.write_all(b",\"incarnation_id\":")?;
    serde_json::to_writer(&mut *output, &original.incarnation_id).map_err(|_| invalid())?;
    output.write_all(b",\"message\":")?;
    serde_json::to_writer(&mut *output, &original.message).map_err(|_| invalid())?;
    output.write_all(b",\"method\":")?;
    serde_json::to_writer(&mut *output, &original.method).map_err(|_| invalid())?;
    output.write_all(b",\"node_id\":")?;
    serde_json::to_writer(&mut *output, &original.node_id).map_err(|_| invalid())?;
    output.write_all(b",\"operation_id\":")?;
    serde_json::to_writer(&mut *output, &original.operation_id).map_err(|_| invalid())?;
    output.write_all(b",\"protocol\":")?;
    serde_json::to_writer(&mut *output, &original.protocol).map_err(|_| invalid())?;
    output.write_all(b",\"request_id\":")?;
    serde_json::to_writer(&mut *output, &original.request_id).map_err(|_| invalid())?;
    // U64's ordinary serializer creates a temporary String. Its fixed decimal
    // display writes directly into this existing comparison sink instead.
    write!(
        output,
        ",\"sequence\":\"{}\",\"session_id\":",
        original.sequence.get()
    )?;
    serde_json::to_writer(&mut *output, &original.session_id).map_err(|_| invalid())?;
    output.write_all(b"}")?;
    Ok(())
}

fn charge(work: &mut usize, amount: usize) -> Result<(), ProviderError> {
    *work = work
        .checked_sub(amount)
        .ok_or(ProviderError::ResourceExhausted(
            "native17 retained terminal comparison work",
        ))?;
    Ok(())
}

fn write_object<'a>(
    values: impl Clone + Iterator<Item = (&'a String, &'a Value)>,
    output: &mut impl Write,
    depth: usize,
    work: &mut usize,
) -> Result<(), ProviderError> {
    if depth >= 64 {
        return Err(invalid());
    }
    output.write_all(b"{")?;
    let mut previous: Option<&str> = None;
    let mut emitted = 0usize;
    loop {
        let mut selected: Option<(&str, &Value)> = None;
        let mut total = 0usize;
        for (key, value) in values.clone() {
            charge(work, key.len().checked_add(1).ok_or_else(invalid)?)?;
            total = total.checked_add(1).ok_or_else(invalid)?;
            if previous
                .is_some_and(|previous| key.encode_utf16().cmp(previous.encode_utf16()).is_le())
            {
                continue;
            }
            if selected
                .is_none_or(|(prior, _)| key.encode_utf16().cmp(prior.encode_utf16()).is_lt())
            {
                selected = Some((key, value));
            }
        }
        let Some((key, value)) = selected else {
            if total != emitted {
                return Err(invalid());
            }
            break;
        };
        if emitted != 0 {
            output.write_all(b",")?;
        }
        serde_json::to_writer(&mut *output, key).map_err(|_| invalid())?;
        output.write_all(b":")?;
        write_value(value, output, depth + 1, work)?;
        emitted += 1;
        previous = Some(key);
    }
    output.write_all(b"}")?;
    Ok(())
}

fn write_value(
    value: &Value,
    output: &mut impl Write,
    depth: usize,
    work: &mut usize,
) -> Result<(), ProviderError> {
    charge(work, 1)?;
    match value {
        Value::Object(values) => write_object(values.iter(), output, depth, work),
        Value::Array(values) => {
            if depth >= 64 || values.len() > 65536 {
                return Err(invalid());
            }
            output.write_all(b"[")?;
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.write_all(b",")?;
                }
                write_value(value, output, depth + 1, work)?;
            }
            output.write_all(b"]")?;
            Ok(())
        }
        Value::Number(_) => {
            crucible_node_format::canonical::canonical_json_to_writer(value, output)?;
            Ok(())
        }
        _ => {
            serde_json::to_writer(&mut *output, value).map_err(|_| invalid())?;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crucible_node_format::canonical;
    use serde_json::json;

    #[test]
    fn sdk_envelope_comparison_streams_full_jcs_without_u64_string_scratch()
    -> Result<(), ProviderError> {
        let value = json!({
            "protocol":"CNP/1", "message":"response", "session_id":"session",
            "incarnation_id":"incarnation", "node_id":null, "execution_owner_id":null,
            "capture_owner_id":null, "request_id":"request", "operation_id":null,
            "sequence":"18446744073709551615", "method":"admit",
            "body":{"status":"completed", "number":1.0, "zero":-0.0,
                "nested":{"\u{10000}":"quoted\"value", "\u{e000}":[null,true]}},
            "extensions":{}
        });
        let original: Envelope = serde_json::from_value(value.clone()).map_err(|_| invalid())?;
        let expected = canonical::canonical_json(&value)?;
        let mut sink = ExactBytes17::new(Bytes17::Slice(&expected))?;
        write_envelope(&original, &mut sink)?;
        sink.finish()?;
        let mut changed = original;
        changed.sequence = crucible_node_format::U64::new(3);
        let mut sink = ExactBytes17::new(Bytes17::Slice(&expected))?;
        assert!(write_envelope(&changed, &mut sink).is_err());
        Ok(())
    }
}
