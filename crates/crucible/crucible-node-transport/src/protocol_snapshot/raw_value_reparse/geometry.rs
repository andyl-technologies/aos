//! Derives additional raw-JSON Value parser owners from actual string extents.
//!
//! The pinned serde_json1.0.150 from_str constructor starts at depth128 and does
//! not call disable_recursion_limit, even when unbounded_depth is unified.
//! Nested RawValue reparses reset that allowance; each string layer is priced
//! independently. Ordinary outer DTO/canonical/model work is not credited here.

use super::*;
use std::mem::align_of;

const PARSER_DEPTH: usize = 128;

pub(super) fn maximum_layers_data(extent: usize) -> Result<usize, ProviderError> {
    // A chain of k reparses contains quotes around k-1 inner reserved-object
    // String values. Each previous JSON-string layer escapes every quote and
    // backslash again. At least one such byte has 2^(k-1) encoded descendants;
    // hence k <= floor(log2(extent))+1. Large unescaped payloads need not shrink
    // geometrically, so EACH layer still pays the complete actual extent.
    let logarithm = extent.checked_ilog2().ok_or_else(exhausted)?;
    add(usize::try_from(logarithm).map_err(|_| exhausted())?, 1)
}

// alloc::raw_vec::min_non_zero_cap for u8 in the pinned AOS Rust toolchain.
const BYTE_BANK_MINIMUM: usize = 8;

/// Sums requested byte-bank growth, rather than importing spare capacity.
fn byte_bank_growth_data(extent: usize, banks: usize) -> Result<usize, ProviderError> {
    // grow_amortized requests max(2*old_capacity, required, 8). Requests at
    // least double; their sum is less than twice the last request, whose
    // capacity is at most max(2*initialized_length, 8). Each independent empty
    // bank therefore needs at most 4*length + 2*8 requested bytes. Summing the
    // actual per-level length budget keeps fragmented parser banks explicit.
    add(mul(4, extent)?, mul(2 * BYTE_BANK_MINIMUM, banks)?)
}

pub(super) fn parser_storage_data(extent: usize) -> Result<(usize, usize), ProviderError> {
    let values = original_json_value_storage_extent_data(extent)?;

    // value_dom_requested_bytes already includes every ordinary returned
    // Value String, array and map. These are DIFFERENT owners: each RawValue
    // seed keeps its source Box<str> live while the next from_str runs. A text
    // seed copies at most its decoded bytes with str::to_owned; into_boxed_str
    // may request that same length once more when shrinking. Owned Value seeds
    // instead move their String; charging both requests remains conservative.
    let raw_source_copy = extent;
    let raw_box_shrink = extent;

    // Each reset parser has one scratch Vec<u8>, shared by its string tokens.
    // read::parse_str_bytes clears/reuses this Vec; decoded bytes cannot exceed
    // source bytes. At one reparse level disjoint source strings sum to at most
    // extent, and parser count is bounded by lexical value occurrences. This
    // charges its independent minimum and cumulative reallocation requests.
    // For fragmented nested parses the parent text also contains a full
    // reserved-key object and quoted String per fragment. Removing that framing
    // saves more bytes than joining the fragments as one JSON array needs, so
    // the whole-level lexical extent bounds their combined nodes/strings and
    // independent parser count. The first level has just its one root parser.
    let parser_scratch = byte_bank_growth_data(extent, values.maximum_value_nodes)?;
    let error = error_storage_data(extent)?;
    let transient = add(
        add(raw_source_copy, raw_box_shrink)?,
        add(parser_scratch, error)?,
    )?;
    Ok((transient, parser_counter_scratch_data()))
}

pub(super) fn retained_error_storage_data(extent: usize) -> Result<usize, ProviderError> {
    add(error_header_data()?, error_text_length_data(extent)?)
}

/// Covers a reserved non-String key's refusal without claiming a nested parse.
pub(super) fn wrong_type_storage_data() -> Result<(usize, usize, usize), ProviderError> {
    // Non-String JSON values print only null/bool/integer/finite-float or the
    // fixed sequence/map classification. No rejected object's keys/payloads
    // are formatted. The named numeric widths below cover every such scalar.
    Ok((
        retained_error_storage_data(0)?,
        error_storage_data(0)?,
        error_counter_scratch_data(),
    ))
}

fn parser_counter_scratch_data() -> usize {
    type Parser = serde_json::Deserializer<serde_json::de::StrRead<'static>>;
    type MapIterator = <Map<String, Value> as IntoIterator>::IntoIter;
    // Both actual text SeqAccess/MapAccess contain &mut Deserializer and bool.
    let access = pair_layout::<&mut Parser, bool>();
    // Owned Value::Deserializer can coexist when a Value visitor invokes the
    // nested text parser. Its concrete private map/sequence states are retained.
    let owned_map = pair_layout::<MapIterator, Option<Value>>();
    let owned_sequence = field_layout::<std::vec::IntoIter<Value>>();
    let owned_enum = pair_layout::<String, Option<Value>>();
    let owned_variant = field_layout::<Option<Value>>();
    // Pinned value/de.rs KeyClass={Map(String),Number,RawValue}. Reserve a
    // full usize discriminant with field/tail alignment; niches may reduce
    // the actual layout but cannot increase this explicit tagged union bound.
    let key_alignment = align_of::<String>().max(align_of::<usize>());
    let key_class = tagged_layout_data(size_of::<String>(), key_alignment);
    let optional_key_class = tagged_layout_data(key_class, key_alignment);
    let key_result =
        tagged_layout_data(key_class.max(size_of::<serde_json::Error>()), key_alignment);
    let optional_key_result = tagged_layout_data(
        optional_key_class.max(size_of::<serde_json::Error>()),
        key_alignment,
    );

    // Pinned de.rs ParserNumber={F64(f64),U64(u64),I64(i64),String(String)};
    // the final variant is feature-dependent, included as a layout upper only.
    // The enum and its Result are independent actual return/local headers.
    let number_alignment = align_of::<u64>()
        .max(align_of::<i64>())
        .max(align_of::<f64>())
        .max(align_of::<String>())
        .max(align_of::<usize>());
    let number_payload = size_of::<u64>()
        .max(size_of::<i64>())
        .max(size_of::<f64>())
        .max(size_of::<String>());
    let parser_number = tagged_layout_data(number_payload, number_alignment);
    let parser_number_result = tagged_layout_data(
        parser_number.max(size_of::<serde_json::Error>()),
        number_alignment,
    );

    // read::Reference<'a,'b,str>={Borrowed(&str),Copied(&str)} is private to
    // serde_json's read module. Name its tag/payload and independent Result.
    let text_reference = tagged_layout_data(size_of::<&str>(), align_of::<&str>());
    let text_reference_result = tagged_layout_data(
        text_reference.max(size_of::<serde_json::Error>()),
        align_of::<&str>(),
    );

    size_of::<Parser>()
        + PARSER_DEPTH * (2 * access
            + size_of::<Value>() + size_of::<Option<Value>>()
            + size_of::<Vec<Value>>() + size_of::<Map<String,Value>>()
            + size_of::<String>() + size_of::<Option<String>>()
            + size_of::<Result<Value,serde_json::Error>>()
            + size_of::<Result<(),serde_json::Error>>()
            + size_of::<&mut Parser>() + size_of::<usize>()
            + key_class + optional_key_class + key_result + optional_key_result
            + size_of::<Result<Option<Value>, serde_json::Error>>()
            + size_of::<(String, Value)>() + size_of::<Option<(String, Value)>>()
            + size_of::<Result<Option<(String, Value)>, serde_json::Error>>())
        + owned_map + owned_sequence + owned_enum + owned_variant
        + parser_number + parser_number_result
        + text_reference + text_reference_result
        + size_of::<Result<f64, serde_json::Error>>()
        + size_of::<Result<u64, serde_json::Error>>()
        + size_of::<Result<u16, serde_json::Error>>()
        + size_of::<Result<Option<u8>, serde_json::Error>>()
        + size_of::<Option<u8>>()
        + 2 * size_of::<usize>() // actual read::Position{line,column}
        + size_of::<Vec<u8>>()
        // RawValue is repr(transparent) over str. This names its real owned
        // String/Box<str> views without requiring raw_value to be enabled.
        + size_of::<Box<str>>() + size_of::<String>()
        + size_of::<&str>() + size_of::<std::str::Chars<'static>>()
        + size_of::<Option<char>>() + size_of::<[u16;2]>()
        + size_of::<Result<&str,std::str::Utf8Error>>()
        + size_of::<Result<f64,std::num::ParseFloatError>>()
        + size_of::<f64>() + size_of::<u64>() + size_of::<i64>()
        + error_counter_scratch_data()
}

fn error_counter_scratch_data() -> usize {
    // Names both old/new error and formatted/boxed message views while custom
    // converts the prior Error; parse_line_col has five indices + two results.
    2 * size_of::<serde_json::Error>()
        + 2 * size_of::<String>()
        + 2 * size_of::<Box<str>>()
        + size_of::<Result<Value, serde_json::Error>>()
        + size_of::<std::fmt::Arguments<'static>>()
        + size_of::<std::fmt::Formatter<'static>>()
        + size_of::<serde::de::Unexpected<'static>>()
        + size_of::<&dyn serde::de::Expected>()
        // Pinned zmij::Buffer is [MaybeUninit<u8>;24]; serde_json uses it in
        // JsonUnexpected::Float without a directly accessible Provider API.
        + size_of::<[std::mem::MaybeUninit<u8>; 24]>()
        // Core Display's u64/i64/usize decimal buffer on the selected64-bit
        // toolchain (also20 in its optimize_for_size implementation).
        + size_of::<[std::mem::MaybeUninit<u8>; 20]>()
        + size_of::<Result<usize, std::num::ParseIntError>>()
        + size_of::<Option<(usize, usize)>>()
        + size_of::<&str>()
        + 7 * size_of::<usize>()
}

/// Bounds a private Rust enum/Option/Result from its pinned payload roster.
fn tagged_layout_data(payload: usize, alignment: usize) -> usize {
    // All named enums have at most four variants. A usize tag dominates the
    // discriminant; one payload/tag boundary and one final tail may each pad.
    payload + size_of::<usize>() + 2 * (alignment - 1)
}

fn field_layout<T>() -> usize {
    size_of::<T>() + align_of::<T>() - 1
}
fn pair_layout<A, B>() -> usize {
    size_of::<A>() + align_of::<A>() - 1 + size_of::<B>() + align_of::<B>() - 1
        + align_of::<A>().max(align_of::<B>())
        - 1
}

// Exact fixed Display alternatives in pinned serde_json1.0.150 error.rs. Message
// payloads remain separate: Debug quotes expand at most sixfold, and generic
// Value/RawValue visitors have only the fixed expectations named below.
const FIXED_ERRORS: &[&str] = &[
    "EOF while parsing a list",
    "EOF while parsing an object",
    "EOF while parsing a string",
    "EOF while parsing a value",
    "expected `:`",
    "expected `,` or `]`",
    "expected `,` or `}`",
    "expected ident",
    "expected value",
    "expected `\"`",
    "invalid escape",
    "invalid number",
    "number out of range",
    "invalid unicode code point",
    "control character (\\u0000-\\u001F) found while parsing a string",
    "key must be a string",
    "invalid value: expected key to be a number in quotes",
    "float key must be finite (got NaN or +/-inf)",
    "lone leading surrogate in hex escape",
    "trailing comma",
    "trailing characters",
    "unexpected end of hex escape",
    "recursion limit exceeded",
    "null",
    "any valid JSON value",
    "a string",
    "a string key",
    "Value",
    "RawValue",
];

// The generic Value/RawValue adapter can additionally format these exact
// serde de::Error contexts. Summing the alternatives is a conservative bound
// on the fixed portion; no unrelated DTO field names are imported.
const ERROR_CONTEXTS: &[&str] = &[
    "invalid type: ",
    "invalid value: ",
    "invalid length ",
    ", expected ",
    "raw value",
    "value is missing",
    "fewer elements in map",
    "fewer elements in array",
    "integer ``, unsigned integer ``, floating point ``, boolean ``",
    "unit value, sequence, map, string, number ",
];

pub(super) fn error_text_length_data(extent: usize) -> Result<usize, ProviderError> {
    let mut fixed = 0usize;
    for name in FIXED_ERRORS.iter().chain(ERROR_CONTEXTS) {
        fixed = add(fixed, name.len())?;
    }
    // JSON/Rust Debug string escaping uses at most six bytes per source byte.
    // Signed i64, u64, zmij's finite f64 and collection length are independent
    // alternatives; adding their 21/20/24/20 widths covers all of them.
    let numeric = 21 + 20 + 24 + 20;
    let location = " at line ".len() + 20 + " column ".len() + 20;
    add(add(mul(6, extent)?, fixed)?, add(numeric, location)?)
}

fn error_header_data() -> Result<usize, ProviderError> {
    // Actual private ErrorImpl owns ErrorCode + line + column. ErrorCode's
    // largest payload is Box<str> or io::Error and has one enum discriminant.
    // Field and final tail alignment are separately bounded, without relying
    // on a guessed whole struct size or an unrelated public Deserializer.
    let alignment = align_of::<Box<str>>()
        .max(align_of::<std::io::Error>())
        .max(align_of::<usize>());
    add(
        add(
            size_of::<Box<str>>().max(size_of::<std::io::Error>()),
            3 * size_of::<usize>(),
        )?,
        mul(4, alignment - 1)?,
    )
}

fn error_storage_data(extent: usize) -> Result<usize, ProviderError> {
    let text = error_text_length_data(extent)?;
    let formatted_string = byte_bank_growth_data(text, 1)?;
    let boxed_message = text;
    let previous_boxed_message = text;

    // map_err(Error::custom) holds the preceding Error while Display writes
    // a fresh String, then make_error shrinks it into Box<str>. make_error's
    // parse_line_col removes the terminal location text and stores its two
    // coordinates. Display restores exactly that ONE suffix at the next
    // layer; suffixes never accumulate through the recursive custom wrappers.
    // Every independently bounded layer pays these owners; payload shrinkage
    // across layers is deliberately not assumed.
    add(
        mul(2, error_header_data()?)?,
        add(
            formatted_string,
            add(boxed_message, previous_boxed_message)?,
        )?,
    )
}

pub(super) fn quote_counter_scratch_data() -> usize {
    type Extent =
        crate::retained_metadata::serialization_storage::OriginalJsonValueStorageExtentData;
    original_json_value_storage_extent_counter_scratch_data()
        + size_of::<JsonValueReparseConstructionData>()
        + size_of::<Result<JsonValueReparseConstructionData, ProviderError>>()
        // add_string_data holds its first lexical row while parser_storage_data
        // derives the separate parser-bank population from a second row.
        + 2 * size_of::<Extent>()
        + size_of::<Result<Extent, ProviderError>>()
        + size_of::<(usize, usize)>()
        + size_of::<Result<(usize, usize), ProviderError>>()
        + size_of::<(usize, usize, usize)>()
        + size_of::<Result<(usize, usize, usize), ProviderError>>()
        + size_of::<std::slice::Iter<'static, &'static str>>()
        + size_of::<std::iter::Chain<std::slice::Iter<'static, &'static str>, std::slice::Iter<'static, &'static str>>>()
        + size_of::<Result<usize, ProviderError>>()
        + size_of::<u32>() // checked_ilog2 output
        // actual_extent, maximum, extent and layers in add_string_data;
        // copy/shrink/scratch/error/transient in parser_storage_data;
        // fixed/numeric/location in error_text_length_data;
        // alignment/header and text/formatter/old/new message in error helpers.
        + (4 + 5 + 3 + 2 + 5) * size_of::<usize>()
        // Actual private-layout calculation locals: access/owned adapters,
        // KeyClass/Option/Result and ParserNumber payload/alignment/results.
        + (5 + 5 + 4 + 2) * size_of::<usize>()
}
