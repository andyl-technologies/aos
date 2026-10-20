//! Names controls of the actual contract scalar and Bytes codec constructors.
//!
//! Encoded/decoded Vec/String backing, parser DOMs and diagnostic messages are
//! independent dynamic constructor demand. These declarations execute no codec
//! and provide no permission or physical process-stack bound. Public base64
//! layouts and private-local mirrors are pinned to base64 0.22.1.

use super::Bytes;
use base64::{
    DecodeError, DecodeSliceError, Engine,
    engine::{DecodeMetadata, DecodePaddingMode, GeneralPurpose},
};
use std::{mem::size_of, slice, str};

type Estimate = <GeneralPurpose as Engine>::DecodeEstimate;

// Layout-only mirrors name actual Engine::encode/internal_encode arguments,
// shadowed unrolled u64 reads and suffix locals. They are never instantiated.
#[allow(dead_code)]
struct EncodeControls<'a> {
    engine: &'a GeneralPurpose,
    input: &'a [u8],
    output: &'a mut [u8],
    encoded_size: usize,
    output_bank: Vec<u8>,
    string_result: Result<String, std::string::FromUtf8Error>,
    input_index: usize,
    last_fast_index: usize,
    output_index: usize,
    input_chunk: &'a [u8],
    output_chunk: &'a mut [u8],
    first_word: u64,
    second_word: u64,
    third_word: u64,
    fourth_word: u64,
    remainder: usize,
    remainder_start: usize,
    written: usize,
    padding_bytes: usize,
    encoded_bytes: usize,
    complete_chunks: usize,
    complete_output: usize,
    checked_complete_output: Option<usize>,
    encoded_remainder: usize,
    encoded_length: Option<usize>,
    read_word: [u8; 8],
    read_word_result: Result<[u8; 8], std::array::TryFromSliceError>,
    utf8_result: Result<&'a str, str::Utf8Error>,
}

// Decode::inner retains its estimate/bank while decode_helper, complete_quads,
// the chunk loop and terminal suffix run. Each actual family is independent.
#[allow(dead_code)]
struct DecodeControls<'a> {
    engine: &'a GeneralPurpose,
    input: &'a [u8],
    estimate: Estimate,
    output_bank: Vec<u8>,
    written: usize,
    result: Result<Vec<u8>, DecodeError>,
    metadata: DecodeMetadata,
    metadata_result: Result<DecodeMetadata, DecodeSliceError>,
    mapped_metadata_result: Result<DecodeMetadata, DecodeError>,
    table: &'a [u8; 256],
    trailing_bits: bool,
    padding_mode: DecodePaddingMode,
    output: &'a mut [u8],
    complete_nonterminal: usize,
    after_unrolled_chunks: usize,
    unrolled_input: usize,
    unrolled_output: usize,
    complete_output: usize,
    chunk_index: usize,
    chunk: &'a [u8],
    chunk_output: &'a mut [u8],
    output_after_unroll: &'a mut [u8],
    chunks: std::iter::Enumerate<slice::ChunksExact<'a, u8>>,
    quad_chunks: std::iter::Enumerate<slice::ChunksExact<'a, u8>>,
}

#[allow(dead_code)]
struct CompleteQuadsControls<'a> {
    input: &'a [u8],
    input_remainder: usize,
    output_length: usize,
    table: &'a [u8; 256],
    last_byte: u8,
    complete_nonterminal: usize,
    debug_suffix_range: std::ops::RangeInclusive<usize>,
    result: Result<usize, DecodeSliceError>,
}

// decode_chunk_8 and decode_chunk_4 each expose their own to_be_bytes output.
#[allow(dead_code)]
struct ChunkControls<'a, Word, const N: usize> {
    input: &'a [u8],
    input_start: usize,
    table: &'a [u8; 256],
    output: &'a mut [u8],
    morsels: [u8; N],
    accumulator: Word,
    bytes: [u8; N],
    result: Result<(), DecodeError>,
}

#[allow(dead_code)]
struct SuffixControls<'a> {
    input: &'a [u8],
    input_index: usize,
    output: &'a mut [u8],
    output_index: usize,
    table: &'a [u8; 256],
    trailing_bits: bool,
    padding_mode: DecodePaddingMode,
    morsel_count: usize,
    padding_count: usize,
    first_padding: usize,
    last_symbol: u8,
    morsels: [u8; 4],
    leftover_index: usize,
    symbol: u8,
    bad_padding_index: usize,
    morsel: u8,
    output_count: usize,
    leftover: u32,
    mask: u32,
    high_byte: u8,
    input_cursor: std::iter::Enumerate<slice::Iter<'a, u8>>,
    output_cursor: std::ops::Range<usize>,
    output_byte: Option<&'a mut u8>,
    output_byte_result: Result<&'a mut u8, DecodeSliceError>,
    metadata: DecodeMetadata,
    result: Result<DecodeMetadata, DecodeSliceError>,
}

impl Bytes {
    /// Names the actual base64url String formatter's fixed constructor controls.
    ///
    /// The encoded String/Vec backing and its independent serializer copy remain
    /// dynamic demand. This includes the actual engine layout conservatively
    /// without assuming promotion of the defining URL_SAFE_NO_PAD constant.
    pub fn serialization_counter_scratch_data() -> usize {
        size_of::<GeneralPurpose>()
            + size_of::<EncodeControls<'static>>()
            + size_of::<String>()
            + size_of::<Result<String, std::string::FromUtf8Error>>()
            + size_of::<Option<usize>>()
    }

    /// Names the actual base64url decoder's fixed constructor controls.
    ///
    /// The original JSON String, estimated decoded Vec and error messages are
    /// separate dynamic demand. Chunk8/chunk4/suffix are conservatively summed;
    /// their field rosters name the actual sequential helper families.
    pub fn deserialization_counter_scratch_data() -> usize {
        size_of::<GeneralPurpose>()
            + size_of::<DecodeControls<'static>>()
            + size_of::<CompleteQuadsControls<'static>>()
            + size_of::<ChunkControls<'static, u64, 8>>()
            + size_of::<ChunkControls<'static, u32, 4>>()
            + size_of::<SuffixControls<'static>>()
            + size_of::<String>()
            + size_of::<Result<String, serde_json::Error>>()
            + size_of::<Result<Self, DecodeError>>()
            + size_of::<Result<Self, serde_json::Error>>()
    }
}

// Actual Id/decimal wrappers deserialize a String, inspect borrowed bytes and
// parse the finite native scalar. Version additionally owns Number and RyuJS.
#[allow(dead_code)]
struct ScalarControls<'a> {
    input: String,
    string_result: Result<String, serde_json::Error>,
    preserved_identifier_result: Result<super::Id, super::IdFromOwnedError>,
    bytes: str::Bytes<'a>,
    digits: &'a str,
    signed_prefix: Option<&'a str>,
    first: Option<u8>,
    scalar: u64,
    parse_result: Result<u64, std::num::ParseIntError>,
    parse_error: std::num::ParseIntError,
    contract_error: crate::ContractError,
    identifier_result: Result<super::Id, crate::ContractError>,
    unsigned_result: Result<super::U64, crate::ContractError>,
    number: serde_json::Number,
    number_result: Result<serde_json::Number, serde_json::Error>,
    unsigned: Option<u64>,
    converted: Result<u16, std::num::TryFromIntError>,
    float: Option<f64>,
    buffer: ryu_js::Buffer,
    formatted: &'a str,
    version_result: Result<u16, std::num::ParseIntError>,
}

/// Names fixed Id, U64 and version deserializer controls without decoding.
///
/// The caller separately admits actual owned String/DTO backing, serde adapter
/// frames and error construction. This sums only the defining scalar wrappers;
/// it neither invokes Validate nor supplies a codec/native authority.
pub fn scalar_deserialization_counter_scratch_bytes_data() -> usize {
    size_of::<ScalarControls<'static>>()
        + super::IdFromOwnedError::construction_transient_bytes_data()
        + super::IdFromOwnedError::construction_counter_scratch_bytes_data()
        + size_of::<serde_json::Error>()
        + size_of::<Result<(), serde_json::Error>>()
        + size_of::<Result<super::U64, serde_json::Error>>()
        + size_of::<Result<super::Id, serde_json::Error>>()
        + size_of::<Result<u16, serde_json::Error>>()
}
