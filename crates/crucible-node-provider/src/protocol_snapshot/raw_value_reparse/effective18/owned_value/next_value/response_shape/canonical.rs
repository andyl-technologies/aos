//! Checks first-stage body and actual second-stage ErrorRecord details.
//!
//! Counts exact JCS byte extent without an output bank or UTF-16 sort ownership.
//! Ordering changes neither byte extent nor acceptance; diagnostics are static
//! DATA markers. The existing canonical64/array/finite-number checks all precede
//! the existing16MiB check. Body checks precede every ResponseShape Value cut.

use super::*;
use crucible_node_contract::{MAX_ARRAY_ELEMENTS, canonical};
use std::io::Write;

mod reader;
use reader::{Array, Kind, Node, Object};

enum Frame<'a> {
    Array(Array<'a>),
    Object(Object<'a>),
}

fn string_extent_data(value: &str) -> Result<usize, ProviderError> {
    let mut bytes = 2;
    for character in value.chars() {
        bytes = add(
            bytes,
            match character {
                '"' | '\\' | '\u{08}' | '\u{0c}' | '\n' | '\r' | '\t' => 2,
                '\u{00}'..='\u{1f}' => 6,
                character => character.len_utf8(),
            },
        )?;
    }
    Ok(bytes)
}

struct NumberExtent {
    bytes: usize,
}

impl Write for NumberExtent {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.bytes = self
            .bytes
            .checked_add(bytes.len())
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::Other))?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn number_extent_data(value: &Number) -> Result<usize, ProviderError> {
    if !value.as_f64().is_some_and(f64::is_finite) {
        return Err(invalid());
    }
    let mut output = NumberExtent { bytes: 0 };
    // The locked ordinary Number is scalar, with no arbitrary_precision backing.
    // This sole ordinary Value wrapper has depth0 and no recursive child. Its
    // finite Ryu write cannot overflow a zero-seeded usize or fail this sink.
    canonical::canonical_json_to_writer(&Value::Number(value.clone()), &mut output)
        .map_err(|_| invalid())?;
    Ok(output.bytes)
}

fn node_extent_data(root: Node<'_>) -> Result<usize, ProviderError> {
    let mut frames: [Option<Frame<'_>>; 64] = std::array::from_fn(|_| None);
    let mut length = 0;
    let mut pending = Some(root);
    let mut bytes = 0;
    while let Some(value) = pending.take() {
        match value.kind_data()? {
            Kind::Null => bytes = add(bytes, 4)?,
            Kind::Bool(value) => bytes = add(bytes, if value { 4 } else { 5 })?,
            Kind::String(value) => bytes = add(bytes, string_extent_data(value)?)?,
            Kind::Number(value) => bytes = add(bytes, number_extent_data(value)?)?,
            Kind::Array(values) => {
                // The structural body/details map is container1. Refuse container65
                // before installing another frame; this is the existing check.
                if length >= 63 {
                    return Err(invalid());
                }
                let count = values.take(MAX_ARRAY_ELEMENTS + 1).count();
                if count > MAX_ARRAY_ELEMENTS {
                    return Err(invalid());
                }
                bytes = add(bytes, add(2, count.saturating_sub(1))?)?;
                let Kind::Array(values) = value.kind_data()? else {
                    return Err(invalid());
                };
                frames[length] = Some(Frame::Array(values));
                length += 1;
            }
            Kind::Object(values) => {
                if length >= 63 {
                    return Err(invalid());
                }
                let mut count = 0;
                for (key, _) in values {
                    count = add(count, 1)?;
                    bytes = add(bytes, add(string_extent_data(key)?, 1)?)?;
                }
                bytes = add(bytes, add(2, count.saturating_sub(1))?)?;
                let Kind::Object(values) = value.kind_data()? else {
                    return Err(invalid());
                };
                frames[length] = Some(Frame::Object(values));
                length += 1;
            }
        }
        while length != 0 {
            let last = length - 1;
            let next = match frames[last].as_mut().ok_or_else(invalid)? {
                Frame::Array(values) => values.next(),
                Frame::Object(values) => values.next().map(|(_, value)| value),
            };
            if let Some(value) = next {
                pending = Some(value);
                break;
            }
            frames[last] = None;
            length = last;
        }
    }
    Ok(bytes)
}

pub(super) fn body_extent_data(
    raw: &RetainedFrame,
    envelope: &NativeImport18EnvelopeFieldsAttemptData<'_>,
) -> Result<usize, ProviderError> {
    let body = envelope.body_data(raw)?;
    let mut bytes = add(2, body.len().saturating_sub(1))?;
    for (member, (key, input)) in body.iter().enumerate() {
        bytes = add(bytes, add(string_extent_data(key)?, 1)?)?;
        let value = envelope.completed_cut_data(raw, EnvelopeField18Data::Body, member, input)?;
        let input =
            NativeImport18NextValueInputData::selected_data(raw, value.boundary_data(), value)?;
        bytes = add(bytes, node_extent_data(Node::First(input.selected))?)?;
    }
    if bytes > 16_777_216 {
        return Err(invalid());
    }
    Ok(bytes)
}

pub(in super::super::super) fn transient_data() -> Result<usize, ProviderError> {
    sum(&[
        size_of::<Value>() * 2,
        size_of::<Number>(),
        size_of::<NumberExtent>(),
    ])
}

pub(super) fn counter_scratch_data() -> usize {
    size_of::<[Option<Frame<'static>>; 64]>()
        + size_of::<Frame<'static>>()
        + size_of::<Option<Frame<'static>>>()
        + size_of::<Option<&mut Frame<'static>>>()
        + size_of::<&mut Frame<'static>>()
        + size_of::<SourceView<'static>>()
        + size_of::<Option<SourceView<'static>>>()
        + size_of::<SourceKind<'static>>()
        + size_of::<Result<SourceKind<'static>, ProviderError>>()
        + size_of::<SourceArray<'static>>()
        + size_of::<SourceObject<'static>>()
        + size_of::<std::iter::Take<SourceArray<'static>>>()
        + size_of::<std::str::Chars<'static>>()
        + size_of::<char>() * 2
        + size_of::<Option<char>>()
        + size_of::<NumberExtent>()
        + size_of::<&mut NumberExtent>()
        + size_of::<Value>()
        + size_of::<Number>()
        + size_of::<&Number>()
        + size_of::<Result<(), crucible_node_contract::ContractError>>()
        + size_of::<std::io::Result<usize>>()
        + size_of::<std::io::Result<()>>()
        + size_of::<std::io::Error>()
        + size_of::<serde_json::map::Iter<'static>>()
        + size_of::<std::iter::Enumerate<serde_json::map::Iter<'static>>>()
        + size_of::<(&String, &Value)>()
        + size_of::<Option<(&str, SourceView<'static>)>>()
        + size_of::<NativeImport18OwnedValuePassViewData<'static>>()
        + size_of::<NativeImport18NextValueInputData<'static>>()
        + size_of::<Result<NativeImport18NextValueInputData<'static>, ProviderError>>()
        + size_of::<&str>() * 2
        + size_of::<Result<usize, ProviderError>>() * 3
        + size_of::<usize>() * 8
        + reader::counter_data()
        + size_of::<Node<'static>>()
        + size_of::<Option<Node<'static>>>()
        + size_of::<Kind<'static>>()
        + size_of::<Result<Kind<'static>, ProviderError>>()
        + size_of::<Array<'static>>()
        + size_of::<Object<'static>>()
        + size_of::<std::iter::Take<Array<'static>>>()
        + size_of::<Option<(&str, Node<'static>)>>()
        + size_of::<(&str, Node<'static>)>()
        + canonical::canonical_number_counter_scratch_bytes_data()
}

pub(in super::super::super) fn owned_body_extent_data(
    envelope: &NativeImport18OwningEnvelopeAttemptData,
) -> Result<usize, ProviderError> {
    let body = envelope.body_data()?;
    let mut bytes = add(2, body.len().saturating_sub(1))?;
    for (member, (key, _)) in body.iter().enumerate() {
        bytes = add(bytes, add(string_extent_data(key)?, 1)?)?;
        let first = envelope.cut_first_data(EnvelopeField18Data::Body, member)?;
        let input = NativeImport18NextValueInputData::owning_root_data(first)?;
        bytes = add(bytes, node_extent_data(Node::First(input.selected))?)?;
    }
    if bytes > 16_777_216 {
        return Err(invalid());
    }
    Ok(bytes)
}

pub(in super::super::super) fn owned_counter_scratch_data() -> usize {
    counter_scratch_data()
        // This actual reader owns Loans/Physical/FirstSource and its resolution
        // controls; FIRST's separate projection roster cannot supply them.
        + super::super::input::counter_scratch_data()
        + size_of::<&NativeImport18OwningEnvelopeAttemptData>() * 2
        + size_of::<&NativeImport18OwningFirstAttemptData>()
        + size_of::<Result<&NativeImport18OwningFirstAttemptData, ProviderError>>()
        + size_of::<Result<&serde_json::Map<String, Value>, ProviderError>>()
        + size_of::<(usize, (&String, &Value))>()
        + size_of::<Option<(usize, (&String, &Value))>>()
}

// This actual ErrorRecord validator observes only the existing second-pass
// details map. Result/Extensions are separate defining consumers, not a mode.
pub(super) fn owned_error_details_extent_data(
    source: &super::owning::NativeImport18OwningResponseAttemptData,
) -> Result<usize, ProviderError> {
    if source.shape_header_data()?.status != super::schedule::Status::Error {
        return Err(invalid());
    }
    let mut bytes = 2;
    let mut index = 0;
    let mut member = 0;
    while let Some((location, key, value)) = source.completed_cut_data(index)? {
        index = add(index, 1)?;
        let NativeImport18ResponseValueCutLocationData::ErrorDetail(ordinal) = location else {
            continue;
        };
        if ordinal != member {
            return Err(invalid());
        }
        if member != 0 {
            bytes = add(bytes, 1)?;
        }
        member = add(member, 1)?;
        bytes = add(bytes, add(string_extent_data(key)?, 1)?)?;
        bytes = add(bytes, node_extent_data(Node::Next(value))?)?;
    }
    if bytes > 16_777_216 {
        return Err(invalid());
    }
    Ok(bytes)
}

pub(super) fn error_details_counter_data() -> usize {
    type Cut<'a> = (
        NativeImport18ResponseValueCutLocationData,
        &'a str,
        NativeImport18NextValuePassViewData<'a>,
    );
    counter_scratch_data()
        + super::super::view::counter_scratch_data()
        + super::super::input::counter_scratch_data()
        + super::owning::NativeImport18OwningResponseAttemptData::take_requested_storage_data().2
        + super::owning::NativeImport18OwningResponseAttemptData::shape_header_counter_data()
        + size_of::<&super::owning::NativeImport18OwningResponseAttemptData>() * 2
        + size_of::<Cut<'static>>()
        + size_of::<Option<Cut<'static>>>()
        + size_of::<Result<Option<Cut<'static>>, ProviderError>>()
        + size_of::<super::shape_validate::HeaderInput<'static>>()
        + size_of::<Result<super::shape_validate::HeaderInput<'static>, ProviderError>>()
        + size_of::<NativeImport18ResponseValueCutLocationData>()
        + size_of::<NativeImport18NextValuePassViewData<'static>>()
        + size_of::<Node<'static>>()
        + size_of::<Result<usize, ProviderError>>() * 3
        + size_of::<&str>()
        + size_of::<usize>() * 6
}
