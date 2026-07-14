//! Owned-storage data payloads: over-threshold attrsets and strings (RFC-0007
//! doc 31 §1 step-3 increment 5).
//!
//! Attrsets above the flat-inline element threshold and strings above the
//! flat-inline byte threshold keep their *moved owned `Vec`s* behind the arena
//! payload (a measured churn-workload decision — see `flat_values`), so the
//! dumped reservation lanes carry only their `Vec` headers, which point at
//! process-heap memory that is freed with the source heap. Restoring them by
//! witness rebase (the flat-storage path) would leave dangling buffers, so
//! capture serializes the owned arrays into dedicated payload segments and
//! restore rebuilds owned storage over the dumped object, exactly as the list
//! element `Vec`s always have.
//!
//! An owned string's context rides inside its payload (instead of the
//! context-payload segment, which supplements *relocated* strings).
//!
//! # Wire format
//!
//! Inside [`OwnedAttrsPayload`] / [`OwnedStringPayload`] bytes (little-endian):
//!
//! ```text
//! owned-attrs  := count(u32)
//!               | { symbol(u32) | value_word(u64)
//!                 | pos_flag(u8) [ module(u32) | span(u32,u32) ] }*count
//!               | source_order(u32)*count | iteration_order(u32)*count
//! owned-string := byte_len(u32) | bytes | ctx_len(u32) | context
//! ```
//!
//! Raw interned symbol ids and attr-position module ids are valid in-process
//! only (the step-3 cross-process re-intern boundary).

use ratchet_value::heap::{ArenaIndex, OwnedAttrsPayload, OwnedStringPayload};

use super::super::EvalHeap;
use super::EvalHeapSnapshotError;
use super::wire::{decode_context, encode_context, read_le_u32, read_le_u64, read_length_prefixed};
use crate::attrs::{AttrEntry, AttrPosition, FlatAttrs};
use crate::heap::flat::FlatObjectKind;
use crate::string::NixString;
use crate::syntax::{Span, Symbol};
use crate::value::Value;
use crate::value::compressed::CompressedValueWord;

/// Encodes one owned-storage attrset's arrays (see the module wire format).
pub(super) fn encode_owned_attrs(attrs: &FlatAttrs) -> Vec<u8> {
    let entries = attrs.entries_by_symbol();
    let mut out = Vec::new();
    out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    for entry in entries {
        out.extend_from_slice(&entry.key.as_u32().to_le_bytes());
        out.extend_from_slice(&entry.value.word().raw().to_le_bytes());
        match &entry.position {
            Some(position) => {
                out.push(1);
                out.extend_from_slice(&position.module.to_le_bytes());
                out.extend_from_slice(&position.span.start.to_le_bytes());
                out.extend_from_slice(&position.span.end.to_le_bytes());
            }
            None => out.push(0),
        }
    }
    for slot in attrs.source_order() {
        out.extend_from_slice(&slot.to_le_bytes());
    }
    for slot in attrs.iteration_order() {
        out.extend_from_slice(&slot.to_le_bytes());
    }
    out
}

/// Encodes one owned-storage string's bytes and context.
pub(super) fn encode_owned_string(string: &NixString) -> Vec<u8> {
    let bytes = string.bytes();
    let context = encode_context(string.context());
    let mut out = Vec::with_capacity(8 + bytes.len() + context.len());
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
    out.extend_from_slice(&(context.len() as u32).to_le_bytes());
    out.extend_from_slice(&context);
    out
}

impl EvalHeap {
    /// Rebuilds one over-threshold attrset's owned arrays and overwrites the
    /// restored object's stale dumped payload.
    ///
    /// The dumped payload's metadata words are plain data and are preserved;
    /// only the attrs arrays are rebuilt. Untrusted-input discipline: exact
    /// length accounting, permutation bounds, and strict entry sort order are
    /// all validated before construction, so a forged image cannot smuggle an
    /// attrset that violates the selection invariants.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapSnapshotError::ObjectOutsideReservation`] when the
    /// index does not resolve,
    /// [`EvalHeapSnapshotError::MalformedAttrsPayload`] when the bytes do not
    /// decode or violate the attrset invariants, and
    /// [`EvalHeapSnapshotError::FlatResolve`] when the object cannot be
    /// resolved for rewriting.
    pub(super) fn restore_owned_attrs_payload(
        &mut self,
        payload: &OwnedAttrsPayload,
    ) -> Result<(), EvalHeapSnapshotError> {
        let index = payload.index;
        let malformed = || EvalHeapSnapshotError::MalformedAttrsPayload { index };
        let ptr = self
            .flat_arena
            .pointer_for_index(ArenaIndex::new(index))
            .ok_or(EvalHeapSnapshotError::ObjectOutsideReservation)?;
        let bytes = &payload.attrs_bytes;
        let mut cursor = 0usize;
        let count = read_le_u32(bytes, &mut cursor).ok_or_else(malformed)? as usize;
        // Untrusted count: entries are length-checked as the cursor advances.
        let mut entries: Vec<AttrEntry> = Vec::new();
        for _ in 0..count {
            let key = Symbol::new(read_le_u32(bytes, &mut cursor).ok_or_else(malformed)?);
            let raw = read_le_u64(bytes, &mut cursor).ok_or_else(malformed)?;
            let word = CompressedValueWord::from_raw(raw).map_err(|_| malformed())?;
            let value = Value::from_word(word);
            let entry = match bytes.get(cursor).copied() {
                Some(0) => {
                    cursor += 1;
                    AttrEntry::new(key, value)
                }
                Some(1) => {
                    cursor += 1;
                    let module = read_le_u32(bytes, &mut cursor).ok_or_else(malformed)?;
                    let start = read_le_u32(bytes, &mut cursor).ok_or_else(malformed)?;
                    let end = read_le_u32(bytes, &mut cursor).ok_or_else(malformed)?;
                    AttrEntry::with_position(
                        key,
                        value,
                        AttrPosition::new(module, Span::new(start, end)),
                    )
                }
                _ => return Err(malformed()),
            };
            entries.push(entry);
        }
        // Strictly increasing symbol ids: the binary-search selection invariant
        // (also rules out duplicate keys).
        if !entries
            .windows(2)
            .all(|pair| pair[0].key.as_u32() < pair[1].key.as_u32())
        {
            return Err(malformed());
        }
        let mut read_permutation = || -> Result<Vec<u32>, EvalHeapSnapshotError> {
            let mut permutation = Vec::new();
            for _ in 0..count {
                let slot = read_le_u32(bytes, &mut cursor).ok_or_else(malformed)?;
                if slot as usize >= count {
                    return Err(malformed());
                }
                permutation.push(slot);
            }
            Ok(permutation)
        };
        let source_order = read_permutation()?;
        let iteration_order = read_permutation()?;
        if cursor != bytes.len() {
            return Err(malformed());
        }

        // The dumped metadata words are plain data; read them before the
        // payload is overwritten. (The stale attrs `Vec` headers are never
        // read or dropped: `restore_payload` overwrites without dropping.)
        let metadata = self
            .flat_attrs
            .resolve(ptr, FlatObjectKind::Attrs)
            .map_err(EvalHeapSnapshotError::FlatResolve)?
            .payload()
            .metadata;
        let attrs = FlatAttrs::from_restored_parts(entries, source_order, iteration_order);
        self.flat_attrs
            .restore_payload(
                ptr,
                FlatObjectKind::Attrs,
                super::super::FlatAttrsPayload { metadata, attrs },
            )
            .map_err(EvalHeapSnapshotError::FlatResolve)
    }

    /// Rebuilds one over-threshold string's owned bytes (and context) and
    /// overwrites the restored object's stale dumped payload.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapSnapshotError::ObjectOutsideReservation`] when the
    /// index does not resolve as a string or path,
    /// [`EvalHeapSnapshotError::MalformedStringPayload`] when the bytes or
    /// context do not decode, and [`EvalHeapSnapshotError::FlatResolve`] when
    /// the object cannot be resolved for rewriting.
    pub(super) fn restore_owned_string_payload(
        &mut self,
        payload: &OwnedStringPayload,
    ) -> Result<(), EvalHeapSnapshotError> {
        let index = payload.index;
        let malformed = || EvalHeapSnapshotError::MalformedStringPayload { index };
        let ptr = self
            .flat_arena
            .pointer_for_index(ArenaIndex::new(index))
            .ok_or(EvalHeapSnapshotError::ObjectOutsideReservation)?;
        let kind = self
            .flat
            .kind_of(ptr)
            .ok_or(EvalHeapSnapshotError::ObjectOutsideReservation)?;
        if !matches!(kind, FlatObjectKind::String | FlatObjectKind::Path) {
            return Err(EvalHeapSnapshotError::ObjectOutsideReservation);
        }
        let bytes = &payload.string_bytes;
        let mut cursor = 0usize;
        let string_bytes = read_length_prefixed(bytes, &mut cursor).ok_or_else(malformed)?;
        let context_bytes = read_length_prefixed(bytes, &mut cursor).ok_or_else(malformed)?;
        if cursor != bytes.len() {
            return Err(malformed());
        }
        let context = decode_context(&context_bytes).map_err(|_| malformed())?;
        self.flat
            .restore_payload(ptr, kind, NixString::new(string_bytes, context))
            .map_err(EvalHeapSnapshotError::FlatResolve)
    }
}
