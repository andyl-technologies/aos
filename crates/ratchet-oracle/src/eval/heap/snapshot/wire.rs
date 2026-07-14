//! Wire codecs shared by the heap-image snapshot segments: list element
//! words, string contexts, primop registry references, relocation kinds, and
//! the little-endian read helpers (RFC-0007 doc 31 §1).
//!
//! Split out of `snapshot.rs` under the RFC-0007 §2 file-size cap; every item
//! moved verbatim and is `pub(super)` to the snapshot module tree.

use ratchet_value::heap::FlatObjectKind;

use super::super::{EvalModuleId, EvalPrimOp, EvalPrimOpArg};
use super::{EvalHeapSnapshotError, LIST_ELEMENT_WORD_LEN};
use crate::compile::IrId;
use crate::compile::builtins::{PINNED_NIX_VERSION, lookup_builtin};
use crate::string::{ContextElement, ContextKind, StringContext};
use crate::syntax::{Span, Symbol};
use crate::value::Value;
use crate::value::compressed::CompressedValueWord;

/// Decodes a list payload's little-endian words into runtime [`Value`]s.
///
/// The words are address-free Candidate-C words; each resolves unchanged once
/// its domain is re-registered against the restored base.
///
/// # Errors
///
/// Returns [`EvalHeapSnapshotError::MalformedListPayload`] when `bytes` is not a
/// whole number of word-sized chunks or a chunk is not a valid value word.
pub(super) fn decode_list_elements(bytes: &[u8]) -> Result<Vec<Value>, EvalHeapSnapshotError> {
    if bytes.len() % LIST_ELEMENT_WORD_LEN != 0 {
        return Err(EvalHeapSnapshotError::MalformedListPayload {
            byte_len: bytes.len(),
        });
    }
    let mut elements = Vec::with_capacity(bytes.len() / LIST_ELEMENT_WORD_LEN);
    for chunk in bytes.chunks_exact(LIST_ELEMENT_WORD_LEN) {
        let mut word = [0u8; LIST_ELEMENT_WORD_LEN];
        word.copy_from_slice(chunk);
        let raw = u64::from_le_bytes(word);
        let word = CompressedValueWord::from_raw(raw).map_err(|_| {
            EvalHeapSnapshotError::MalformedListPayload {
                byte_len: bytes.len(),
            }
        })?;
        elements.push(Value::from_word(word));
    }
    Ok(elements)
}

/// Encodes a string context's elements into the opaque bytes of a
/// [`ContextPayload`].
///
/// Layout (little-endian): `count(u32)`, then per element `kind(u8) |
/// path_len(u32) | path`, followed by `output_len(u32) | output` only for
/// [`ContextKind::SingleOutput`]. The elements are already in canonical order.
pub(super) fn encode_context(context: &StringContext) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&(context.len() as u32).to_le_bytes());
    for element in context.elements() {
        bytes.push(context_kind_byte(element.kind()));
        let path = element.path();
        bytes.extend_from_slice(&(path.len() as u32).to_le_bytes());
        bytes.extend_from_slice(path);
        if let Some(output) = element.output() {
            bytes.extend_from_slice(&(output.len() as u32).to_le_bytes());
            bytes.extend_from_slice(output);
        }
    }
    bytes
}

/// Decodes the opaque bytes of a [`ContextPayload`] back into a [`StringContext`].
///
/// # Errors
///
/// Returns [`EvalHeapSnapshotError::MalformedContextPayload`] when `bytes` is
/// truncated, carries an unknown kind tag, has trailing bytes, or names an empty
/// context path (which the element constructors reject).
pub(super) fn decode_context(bytes: &[u8]) -> Result<StringContext, EvalHeapSnapshotError> {
    decode_context_inner(bytes).ok_or(EvalHeapSnapshotError::MalformedContextPayload {
        byte_len: bytes.len(),
    })
}

/// Fallible core of [`decode_context`]; returns `None` on any malformed input.
pub(super) fn decode_context_inner(bytes: &[u8]) -> Option<StringContext> {
    let mut cursor = 0usize;
    let count = read_le_u32(bytes, &mut cursor)? as usize;
    // Push without pre-reserving: `count` is untrusted, so a bogus value must not
    // drive a large speculative allocation before the bytes are consumed.
    let mut elements = Vec::new();
    for _ in 0..count {
        let kind = *bytes.get(cursor)?;
        cursor += 1;
        let path = read_length_prefixed(bytes, &mut cursor)?;
        let element = match kind {
            0 => ContextElement::opaque_path(path).ok()?,
            1 => {
                let output = read_length_prefixed(bytes, &mut cursor)?;
                ContextElement::single_output(path, output).ok()?
            }
            2 => ContextElement::deep_derivation(path).ok()?,
            _ => return None,
        };
        elements.push(element);
    }
    // Reject trailing bytes so a malformed segment is a loud miss, not silent.
    if cursor != bytes.len() {
        return None;
    }
    Some(StringContext::new(elements))
}

/// Maps a [`ContextKind`] to its wire tag byte.
pub(super) fn context_kind_byte(kind: ContextKind) -> u8 {
    match kind {
        ContextKind::OpaquePath => 0,
        ContextKind::SingleOutput => 1,
        ContextKind::DeepDerivation => 2,
    }
}

/// Reads a little-endian `u32` at `*cursor`, advancing it, or `None` if truncated.
pub(super) fn read_le_u32(bytes: &[u8], cursor: &mut usize) -> Option<u32> {
    let end = cursor.checked_add(4)?;
    let field: [u8; 4] = bytes.get(*cursor..end)?.try_into().ok()?;
    *cursor = end;
    Some(u32::from_le_bytes(field))
}

/// Reads a `u32`-length-prefixed byte run at `*cursor`, advancing past it.
pub(super) fn read_length_prefixed(bytes: &[u8], cursor: &mut usize) -> Option<Vec<u8>> {
    let len = read_le_u32(bytes, cursor)? as usize;
    let end = cursor.checked_add(len)?;
    let run = bytes.get(*cursor..end)?.to_vec();
    *cursor = end;
    Some(run)
}

/// Reads a little-endian `u64` at `*cursor`, advancing it, or `None` if truncated.
pub(super) fn read_le_u64(bytes: &[u8], cursor: &mut usize) -> Option<u64> {
    let end = cursor.checked_add(8)?;
    let field: [u8; 8] = bytes.get(*cursor..end)?.try_into().ok()?;
    *cursor = end;
    Some(u64::from_le_bytes(field))
}

/// Encodes a captured primop as a stable builtin-registry reference plus its
/// applied arguments (RFC-0007 doc 31 §1 step-2 primop capture).
///
/// Layout (little-endian): `version_len(u32) | version | symbol(u32) |
/// builtin_present(u8) | [name_len(u32) | name] | arg_count(u32) | arg*`, where
/// each arg is `module(u32) | id(u32) | span_start(u32) | span_end(u32) |
/// value_word(u64)`. The version pins the builtin surface so restore can refuse a
/// mismatched registry; the builtin name is the registry reference re-resolved on
/// load. Argument values are address-free Candidate-C words.
pub(super) fn encode_primop(primop: &EvalPrimOp) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&(PINNED_NIX_VERSION.len() as u32).to_le_bytes());
    bytes.extend_from_slice(PINNED_NIX_VERSION);
    bytes.extend_from_slice(&primop.symbol().as_u32().to_le_bytes());
    match primop.builtin() {
        Some(builtin) => {
            let name = builtin.name();
            bytes.push(1);
            bytes.extend_from_slice(&(name.len() as u32).to_le_bytes());
            bytes.extend_from_slice(name);
        }
        None => bytes.push(0),
    }
    bytes.extend_from_slice(&(primop.args().len() as u32).to_le_bytes());
    for arg in primop.args() {
        bytes.extend_from_slice(&arg.module().as_u32().to_le_bytes());
        bytes.extend_from_slice(&arg.id().as_u32().to_le_bytes());
        bytes.extend_from_slice(&arg.span().start.to_le_bytes());
        bytes.extend_from_slice(&arg.span().end.to_le_bytes());
        bytes.extend_from_slice(&arg.value().word().raw().to_le_bytes());
    }
    bytes
}

/// Decodes a primop payload into an [`EvalPrimOp`], re-resolving its builtin
/// against the registry.
///
/// # Errors
///
/// Returns [`EvalHeapSnapshotError::RegistryVersionMismatch`] when the pinned
/// builtin-surface version differs, [`EvalHeapSnapshotError::UnknownBuiltin`]
/// when a referenced builtin name is not in the registry, and
/// [`EvalHeapSnapshotError::MalformedPrimopPayload`] on truncated or invalid
/// bytes.
pub(super) fn decode_primop(bytes: &[u8]) -> Result<EvalPrimOp, EvalHeapSnapshotError> {
    let malformed = || EvalHeapSnapshotError::MalformedPrimopPayload {
        byte_len: bytes.len(),
    };
    let mut cursor = 0usize;
    let version = read_length_prefixed(bytes, &mut cursor).ok_or_else(malformed)?;
    if version.as_slice() != PINNED_NIX_VERSION {
        return Err(EvalHeapSnapshotError::RegistryVersionMismatch {
            expected: PINNED_NIX_VERSION.to_vec(),
            found: version,
        });
    }
    let symbol = Symbol::new(read_le_u32(bytes, &mut cursor).ok_or_else(malformed)?);
    let builtin = match bytes.get(cursor).copied() {
        Some(1) => {
            cursor += 1;
            let name = read_length_prefixed(bytes, &mut cursor).ok_or_else(malformed)?;
            Some(lookup_builtin(&name).ok_or(EvalHeapSnapshotError::UnknownBuiltin { name })?)
        }
        Some(0) => {
            cursor += 1;
            None
        }
        _ => return Err(malformed()),
    };
    let arg_count = read_le_u32(bytes, &mut cursor).ok_or_else(malformed)? as usize;
    let mut args = Vec::new();
    for _ in 0..arg_count {
        let module = EvalModuleId::new(read_le_u32(bytes, &mut cursor).ok_or_else(malformed)?);
        let id = IrId::new(read_le_u32(bytes, &mut cursor).ok_or_else(malformed)?);
        let start = read_le_u32(bytes, &mut cursor).ok_or_else(malformed)?;
        let end = read_le_u32(bytes, &mut cursor).ok_or_else(malformed)?;
        let raw = read_le_u64(bytes, &mut cursor).ok_or_else(malformed)?;
        let word = CompressedValueWord::from_raw(raw).map_err(|_| malformed())?;
        args.push(EvalPrimOpArg::new_in_module(
            module,
            id,
            Span::new(start, end),
            Value::from_word(word),
        ));
    }
    if cursor != bytes.len() {
        return Err(malformed());
    }
    Ok(match builtin {
        Some(builtin) => EvalPrimOp::registered_with_args(symbol, builtin, args),
        None => EvalPrimOp::with_args(symbol, args),
    })
}

/// Decodes a relocation-entry kind byte into a [`FlatObjectKind`].
pub(super) fn kind_from_byte(byte: u8) -> Result<FlatObjectKind, EvalHeapSnapshotError> {
    match byte {
        b if b == FlatObjectKind::String as u8 => Ok(FlatObjectKind::String),
        b if b == FlatObjectKind::Path as u8 => Ok(FlatObjectKind::Path),
        b if b == FlatObjectKind::Attrs as u8 => Ok(FlatObjectKind::Attrs),
        kind => Err(EvalHeapSnapshotError::UnknownKind { kind }),
    }
}

/// Returns whether one of the sorted `(offset, size)` ranges contains `point`.
pub(super) fn range_contains(ranges: &[(usize, usize)], point: usize) -> bool {
    let position = ranges.partition_point(|&(start, _)| start <= point);
    position
        .checked_sub(1)
        .and_then(|index| ranges.get(index))
        .is_some_and(|&(start, size)| point < start + size)
}
