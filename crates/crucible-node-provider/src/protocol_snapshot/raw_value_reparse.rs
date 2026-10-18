//! Quotes nested serde JSON RawValue reparses from actual borrowed inputs.
//!
//! Ordinary owned Value deserialization can interpret the reserved RawValue
//! key when serde_json's raw_value feature is unified. Its String is parsed
//! again by from_str, with a fresh default recursion allowance. This companion
//! prices that extra work in either feature configuration; it changes no
//! accepted input, decoder, Source family or native permission.

use super::owned11::{
    json_value::{
        borrowed_json_string_comparison_counter_scratch_data, borrowed_json_string_matches_data,
    },
    typed::Fields,
};
use crate::ProviderError;
use crate::retained_metadata::serialization_storage::{
    original_json_value_storage_extent_counter_scratch_data,
    original_json_value_storage_extent_data,
};
use serde_json::{Map, Value};
use std::mem::size_of;

mod geometry;

const RAW_VALUE_KEY: &str = "$serde_json::private::RawValue";
// Raw Control callers already use canonical::parse_json's depth64 profile.
const RAW_OUTER_DEPTH: usize = 64;
// The owned-Value overload supports the ordinary from_str default profile.
// Its caller must independently establish that its supplied subtree fits this
// profile: owned Value::Deserializer itself has no depth limiter.
const TYPED_OUTER_DEPTH: usize = 128;

/// Contains separately derived extra reparse demand, never constructor credit.
///
/// A caller independently admits scanner S before this quote, then adds the
/// returned axes before its unchanged decoder. Its baseline parser/typed/model/
/// canonical/failure rows and original owner remain mandatory. No reserved key
/// means zero extra axes; the scanner and baseline decoder remain separately
/// funded. Reserved non-String values pay error-only demand, not parser layers.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct JsonValueReparseConstructionData {
    retained: usize,
    transient: usize,
    scratch: usize,
    markers: usize,
    layers: usize,
    values: usize,
    members: usize,
    strings: usize,
}

impl JsonValueReparseConstructionData {
    /// Returns extra retained, transient and fixed requested-layout axes.
    pub const fn requested_storage_data(&self) -> (usize, usize, usize) {
        (self.retained, self.transient, self.scratch)
    }

    /// Returns the number of actual reserved keys with String values.
    pub const fn detected_strings_data(&self) -> usize {
        self.markers
    }

    /// Returns the sum of independently bounded nested parser layers.
    pub const fn maximum_parser_layers_data(&self) -> usize {
        self.layers
    }

    /// Returns additional potential Value/key nodes, object members and text bytes.
    ///
    /// Surrounding typed/model/canonical consumers must independently apply
    /// their defining constructor populations to these expanded DATA if needed.
    pub const fn expanded_json_extents_data(&self) -> (usize, usize, usize) {
        (self.values, self.members, self.strings)
    }

    fn add_string_data(
        &mut self,
        actual_extent: usize,
        maximum: usize,
    ) -> Result<(), ProviderError> {
        // Empty text still invokes a parser and can construct a failure. One
        // byte is the minimum possible JSON value, not an invented input owner.
        let extent = actual_extent.max(1);
        let layers = geometry::maximum_layers_data(extent)?;
        let value = original_json_value_storage_extent_data(extent)?;
        let parser = geometry::parser_storage_data(extent)?;
        self.markers = add(self.markers, 1)?;
        self.layers = add(self.layers, layers)?;
        self.values = add(self.values, mul(layers, value.maximum_value_nodes)?)?;
        self.members = add(self.members, mul(layers, value.maximum_object_members)?)?;
        self.strings = add(
            self.strings,
            mul(layers, value.maximum_decoded_string_bytes)?,
        )?;
        self.retained = add(
            self.retained,
            mul(
                layers,
                add(
                    value.value_dom_requested_bytes,
                    geometry::retained_error_storage_data(extent)?,
                )?,
            )?,
        )?;
        self.transient = add(
            self.transient,
            mul(layers, add(value.value_dom_requested_bytes, parser.0)?)?,
        )?;
        self.scratch = add(self.scratch, mul(layers, parser.1)?)?;
        self.check(maximum)
    }

    fn add_wrong_type_data(&mut self, maximum: usize) -> Result<(), ProviderError> {
        let (retained, transient, scratch) = geometry::wrong_type_storage_data()?;
        self.retained = add(self.retained, retained)?;
        self.transient = add(self.transient, transient)?;
        self.scratch = add(self.scratch, scratch)?;
        self.check(maximum)
    }

    fn check(&self, maximum: usize) -> Result<(), ProviderError> {
        if add(add(self.retained, self.transient)?, self.scratch)? > maximum {
            return Err(exhausted());
        }
        Ok(())
    }
}

/// Quotes extra Value reparses from an actual borrowed ordinary JSON Map.
///
/// No Serialize, DOM, clone, callback or parser is invoked. The caller admits
/// value_scanner_counter_scratch_data separately BEFORE this walk. All matching
/// String entries are counted, including nonfirst keys that may later refuse.
///
/// # Errors
/// Refuses nesting beyond the supported default-parser profile of 128,
/// arithmetic overflow or extra axes above maximum. The actual caller must
/// establish this profile for its borrowed Value; this quote does not impose
/// a new decoder grammar or certify an arbitrary manually constructed tree.
pub fn quote_map_data(
    input: &Map<String, Value>,
    maximum: usize,
) -> Result<JsonValueReparseConstructionData, ProviderError> {
    let mut result = JsonValueReparseConstructionData::default();
    walk_typed(Some(TypedFrame::Object(input.iter())), &mut result, maximum)?;
    Ok(result)
}

/// Quotes the same extra demand from an actual borrowed Value root.
///
/// # Errors
/// Refuses the same depth, arithmetic and maximum violations as quote_map_data.
pub fn quote_value_data(
    input: &Value,
    maximum: usize,
) -> Result<JsonValueReparseConstructionData, ProviderError> {
    let mut result = JsonValueReparseConstructionData::default();
    walk_typed(TypedFrame::from_value(input), &mut result, maximum)?;
    Ok(result)
}

/// Quotes extra reparses from an actual borrowed compact/canonical JSON body.
///
/// This borrowed structural walk does not dequote or parse the detected String.
/// Its complete literal length safely bounds the inner decoded text. Escaped
/// object keys use the defining UTF-8/escape/surrogate comparator. String values
/// containing similar text are never interpreted as object keys. Outside-string
/// whitespace is unsupported here; the actual caller supplies canonical bytes.
/// This does not itself certify canonical bytes or a source-owned body.
///
/// # Errors
/// Refuses unsupported framing, depth beyond 64, invalid key strings, overflow
/// or extra axes above maximum. Original bytes are borrowed and never changed.
pub fn quote_raw_json_data(
    input: &[u8],
    maximum: usize,
) -> Result<JsonValueReparseConstructionData, ProviderError> {
    compact_framing(input)?;
    let mut result = JsonValueReparseConstructionData::default();
    walk_raw(input, &mut result, maximum)?;
    Ok(result)
}

/// Names the actual fixed-stack Map/Value quote controls before the first walk.
pub fn value_scanner_counter_scratch_data() -> usize {
    geometry::quote_counter_scratch_data()
        + size_of::<[Option<TypedFrame<'static>>; TYPED_OUTER_DEPTH]>()
        + 2 * size_of::<Option<TypedFrame<'static>>>()
        + size_of::<&Value>()
        + size_of::<&Map<String, Value>>()
        + size_of::<Option<&Value>>()
        + size_of::<Option<(&String, &Value)>>()
        + size_of::<Result<Option<&Value>, ProviderError>>()
        + size_of::<usize>() * 3
        + size_of::<Result<(), ProviderError>>()
}

/// Names the fixed raw-key frame stack and one active borrowed Fields walk.
pub fn raw_scanner_counter_scratch_data() -> usize {
    geometry::quote_counter_scratch_data()
        + size_of::<[Option<RawFrame<'static>>; RAW_OUTER_DEPTH]>()
        + size_of::<Option<RawFrame<'static>>>()
        + size_of::<Result<Option<RawFrame<'static>>, ProviderError>>()
        + Fields::counter_scratch_data()
        + size_of::<&[u8]>() * 3
        + size_of::<Option<(&[u8], &[u8])>>()
        + size_of::<Option<&u8>>()
        + size_of::<Result<Option<&[u8]>, ProviderError>>()
        + size_of::<usize>() * 3
        + size_of::<Result<(), ProviderError>>()
        + borrowed_json_string_comparison_counter_scratch_data()
        + size_of::<std::slice::Iter<'static, u8>>()
        + size_of::<bool>() * 2
}

enum TypedFrame<'a> {
    Object(serde_json::map::Iter<'a>),
    Array(std::slice::Iter<'a, Value>),
}

impl<'a> TypedFrame<'a> {
    fn from_value(input: &'a Value) -> Option<Self> {
        match input {
            Value::Object(values) => Some(Self::Object(values.iter())),
            Value::Array(values) => Some(Self::Array(values.iter())),
            _ => None,
        }
    }

    fn next_data(
        &mut self,
        out: &mut JsonValueReparseConstructionData,
        maximum: usize,
    ) -> Result<Option<&'a Value>, ProviderError> {
        match self {
            Self::Object(values) => {
                let Some((key, item)) = values.next() else {
                    return Ok(None);
                };
                if key == RAW_VALUE_KEY {
                    match item {
                        Value::String(text) => out.add_string_data(text.len(), maximum)?,
                        _ => out.add_wrong_type_data(maximum)?,
                    }
                }
                Ok(Some(item))
            }
            Self::Array(values) => Ok(values.next()),
        }
    }
}

fn walk_typed(
    root: Option<TypedFrame<'_>>,
    out: &mut JsonValueReparseConstructionData,
    maximum: usize,
) -> Result<(), ProviderError> {
    let Some(root) = root else {
        return Ok(());
    };
    let mut frames: [Option<TypedFrame<'_>>; TYPED_OUTER_DEPTH] =
        [const { None }; TYPED_OUTER_DEPTH];
    frames[0] = Some(root);
    let mut length = 1usize;

    while length != 0 {
        let next = frames[length - 1]
            .as_mut()
            .ok_or_else(exhausted)?
            .next_data(out, maximum)?;
        let Some(next) = next else {
            frames[length - 1] = None;
            length -= 1;
            continue;
        };
        if let Some(child) = TypedFrame::from_value(next) {
            if length == TYPED_OUTER_DEPTH {
                return Err(exhausted());
            }
            frames[length] = Some(child);
            length += 1;
        }
    }
    Ok(())
}

enum RawFrame<'a> {
    Object(Fields<'a>),
    Array(Fields<'a>),
}

impl<'a> RawFrame<'a> {
    fn from_bytes(input: &'a [u8]) -> Result<Option<Self>, ProviderError> {
        match input.first() {
            Some(b'{') => Ok(Some(Self::Object(Fields::object(input)?))),
            Some(b'[') => Ok(Some(Self::Array(Fields::array(input)?))),
            _ => Ok(None),
        }
    }

    fn next_data(
        &mut self,
        out: &mut JsonValueReparseConstructionData,
        maximum: usize,
    ) -> Result<Option<&'a [u8]>, ProviderError> {
        match self {
            Self::Object(fields) => {
                let Some((key, item)) = fields.pair()? else {
                    return Ok(None);
                };
                if borrowed_json_string_matches_data(key, RAW_VALUE_KEY)? {
                    if item.first() == Some(&b'"') {
                        // The defining comparator validates the complete token
                        // before comparison, without allocating decoded text.
                        borrowed_json_string_matches_data(item, "")?;
                        out.add_string_data(item.len(), maximum)?;
                    } else {
                        out.add_wrong_type_data(maximum)?;
                    }
                }
                Ok(Some(item))
            }
            Self::Array(fields) => fields.next(),
        }
    }

    fn finish(self) -> Result<(), ProviderError> {
        match self {
            Self::Object(mut fields) | Self::Array(mut fields) => fields.finish(),
        }
    }
}

fn walk_raw(
    input: &[u8],
    out: &mut JsonValueReparseConstructionData,
    maximum: usize,
) -> Result<(), ProviderError> {
    let Some(root) = RawFrame::from_bytes(input)? else {
        return Ok(());
    };
    let mut frames: [Option<RawFrame<'_>>; RAW_OUTER_DEPTH] = [const { None }; RAW_OUTER_DEPTH];
    frames[0] = Some(root);
    let mut length = 1usize;

    while length != 0 {
        let next = frames[length - 1]
            .as_mut()
            .ok_or_else(exhausted)?
            .next_data(out, maximum)?;
        let Some(next) = next else {
            frames[length - 1].take().ok_or_else(exhausted)?.finish()?;
            length -= 1;
            continue;
        };
        if let Some(child) = RawFrame::from_bytes(next)? {
            if length == RAW_OUTER_DEPTH {
                return Err(exhausted());
            }
            frames[length] = Some(child);
            length += 1;
        }
    }
    Ok(())
}

fn compact_framing(input: &[u8]) -> Result<(), ProviderError> {
    if input.is_empty() {
        return Err(exhausted());
    }
    let mut string = false;
    let mut escaped = false;
    for byte in input {
        if string {
            if escaped {
                escaped = false;
            } else if *byte == b'\\' {
                escaped = true;
            } else if *byte == b'"' {
                string = false;
            }
        } else if *byte == b'"' {
            string = true;
        } else if byte.is_ascii_whitespace() {
            return Err(exhausted());
        }
    }
    if string || escaped {
        return Err(exhausted());
    }
    Ok(())
}

fn add(a: usize, b: usize) -> Result<usize, ProviderError> {
    a.checked_add(b).ok_or_else(exhausted)
}
fn mul(a: usize, b: usize) -> Result<usize, ProviderError> {
    a.checked_mul(b).ok_or_else(exhausted)
}
fn exhausted() -> ProviderError {
    ProviderError::ResourceExhausted("owned JSON Value reparse construction")
}

#[cfg(test)]
mod tests;
