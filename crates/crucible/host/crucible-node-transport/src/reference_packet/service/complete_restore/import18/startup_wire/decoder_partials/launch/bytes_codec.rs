//! Names the actual base64 0.22.1 decode path reached by the Bytes visitor.
//!
//! The engine uses one estimate, a returned Vec, complete-quad loops, fixed
//! chunk accumulators and a terminal suffix. Alternative chunk helpers are
//! conservatively summed. This is fixed layout DATA, excluding the encoded
//! String, decoded Vec backing and allocated serde error text.

use base64::{
    DecodeError, DecodeSliceError,
    engine::{
        DecodeMetadata, DecodePaddingMode,
        general_purpose::{GeneralPurpose, GeneralPurposeEstimate},
    },
};
use std::mem::size_of;

pub(super) fn counter_scratch_data() -> usize {
    // Engine::decode, its inner function and internal_decode retain distinct
    // argument/return views; the engine and its tables remain borrowed.
    let engine = size_of::<&GeneralPurpose>() * 3
        + size_of::<&String>()
        + size_of::<&[u8]>() * 3
        + size_of::<&mut [u8]>() * 2
        + size_of::<GeneralPurposeEstimate>() * 2
        + size_of::<Vec<u8>>()
        + size_of::<usize>() // bytes_written
        + size_of::<Result<Vec<u8>, DecodeError>>() * 2
        + size_of::<Result<DecodeMetadata, DecodeSliceError>>() * 2;

    // decode_helper: five complete/unrolled lengths, two loop indices and
    // input_index; both actual chunks_exact iterators and output subviews.
    let helper = size_of::<&[u8]>() * 3
        + size_of::<GeneralPurposeEstimate>()
        + size_of::<&mut [u8]>() * 4
        + size_of::<&[u8; 256]>()
        + size_of::<bool>()
        + size_of::<DecodePaddingMode>()
        + size_of::<usize>() * 8
        + size_of::<std::iter::Enumerate<std::slice::ChunksExact<'static, u8>>>() * 2
        + size_of::<Result<usize, DecodeSliceError>>()
        + size_of::<Result<DecodeMetadata, DecodeSliceError>>()
        + size_of::<Result<(), DecodeError>>();

    let complete_quads = size_of::<&[u8]>()
        + size_of::<usize>() * 3 // remainder, output length and complete length
        + size_of::<&[u8; 256]>()
        + size_of::<u8>() // trailing byte
        + size_of::<Result<usize, DecodeSliceError>>();

    let chunk_arguments = size_of::<&[u8]>()
        + size_of::<usize>()
        + size_of::<&[u8; 256]>()
        + size_of::<&mut [u8]>()
        + size_of::<Result<(), DecodeError>>();
    let chunk8 = chunk_arguments + size_of::<[u8; 8]>() * 2 + size_of::<u64>();
    let chunk4 = chunk_arguments + size_of::<[u8; 4]>() * 2 + size_of::<u32>();

    engine + helper + complete_quads + chunk8 + chunk4 + suffix() + display()
}

fn suffix() -> usize {
    size_of::<&[u8]>()
        + size_of::<&mut [u8]>()
        + size_of::<&[u8; 256]>()
        // Input/output indices, morsel/padding counts, first padding offset,
        // leftover index, bad-padding index and output byte count.
        + size_of::<usize>() * 8
        + size_of::<bool>()
        + size_of::<DecodePaddingMode>()
        + size_of::<[u8; 4]>() // morsels
        + size_of::<u8>() * 4 // last_symbol, input byte, morsel and hi_byte
        + size_of::<u32>() * 2 // leftover_num and mask
        + size_of::<std::iter::Enumerate<std::slice::Iter<'static, u8>>>()
        + size_of::<std::ops::Range<usize>>()
        + size_of::<Option<&mut u8>>()
        + size_of::<Result<&mut u8, DecodeSliceError>>()
        + size_of::<DecodeError>()
        + size_of::<DecodeSliceError>()
        + size_of::<DecodeMetadata>()
        + size_of::<Option<usize>>()
        + size_of::<Result<DecodeMetadata, DecodeSliceError>>()
}

fn display() -> usize {
    size_of::<&DecodeError>()
        + size_of::<&mut std::fmt::Formatter<'static>>()
        + size_of::<std::fmt::Arguments<'static>>()
        + size_of::<std::fmt::Result>()
        + size_of::<usize>()
        + size_of::<u8>()
        + size_of::<&usize>()
        + size_of::<&u8>()
        + size_of::<String>()
        + size_of::<Box<str>>()
        + size_of::<serde_json::Error>()
}
