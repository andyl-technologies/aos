//! Typed heap-object registry for the tree-walk evaluator.
//!
//! Runtime [`Value`] words carry opaque [`HeapObject`] pointers. This registry
//! owns the typed Rust-side objects behind those pointers for the safe tree-walk
//! oracle: the bump arena provides stable opaque handles, while a side table
//! maps those handles back to checked [`NixString`] values.

use std::ptr::NonNull;

use thiserror::Error;

use crate::heap::arena::{ArenaError, ArenaStats, BumpArena};
use crate::string::NixString;
use crate::value::{HeapObject, Value, ValueError, ValueTag};

/// Owns typed heap values allocated by one tree-walk evaluation.
#[derive(Debug)]
pub struct EvalHeap {
    arena: BumpArena,
    records: Vec<HeapRecord>,
}

impl Default for EvalHeap {
    fn default() -> Self {
        Self::new()
    }
}

impl EvalHeap {
    /// Creates an empty evaluator heap.
    pub const fn new() -> Self {
        Self {
            arena: BumpArena::new(),
            records: Vec::new(),
        }
    }

    /// Creates an empty evaluator heap with an explicit first arena chunk size.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError::Arena`] if the requested chunk size is invalid
    /// or overflows while being rounded to the arena word size.
    pub fn with_initial_chunk_bytes(chunk_bytes: usize) -> Result<Self, EvalHeapError> {
        Ok(Self {
            arena: BumpArena::with_initial_chunk_bytes(chunk_bytes)
                .map_err(EvalHeapError::Arena)?,
            records: Vec::new(),
        })
    }

    /// Returns current bump-arena accounting.
    pub fn arena_stats(&self) -> ArenaStats {
        self.arena.stats()
    }

    /// Returns the number of typed objects registered in this heap.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Returns whether this heap contains no typed objects.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Allocates a Nix string object and returns its opaque runtime value.
    ///
    /// The returned value is only meaningful while this [`EvalHeap`] remains
    /// alive. Use [`EvalHeap::get_string`] to recover the typed string.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if record storage cannot be reserved, if the
    /// bump arena cannot reserve a string handle, or if the resulting handle
    /// violates the runtime value alignment contract.
    pub fn alloc_string(&mut self, string: NixString) -> Result<Value, EvalHeapError> {
        self.reserve_record_slot()?;
        let allocation = self
            .arena
            .aos_alloc_string(string.len())
            .map_err(EvalHeapError::Arena)?;
        let value = Value::string(allocation.ptr).map_err(EvalHeapError::Value)?;
        self.records.push(HeapRecord {
            ptr: allocation.ptr,
            object: HeapObjectValue::String(string),
        });
        Ok(value)
    }

    /// Returns the string object referenced by `value`.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError::Value`] if `value` is not a string value.
    /// Returns [`EvalHeapError::UnknownPointer`] if the string handle does not
    /// belong to this heap.
    pub fn get_string(&self, value: Value) -> Result<&NixString, EvalHeapError> {
        let ptr = value.as_string_ptr().map_err(EvalHeapError::Value)?;
        self.get_string_ptr(ptr)
    }

    /// Returns the string object referenced by an opaque heap pointer.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError::UnknownPointer`] if `ptr` does not belong to
    /// this heap.
    pub fn get_string_ptr(&self, ptr: NonNull<HeapObject>) -> Result<&NixString, EvalHeapError> {
        let record = self
            .record(ptr)
            .ok_or_else(|| EvalHeapError::unknown(ValueTag::String, ptr))?;
        match &record.object {
            HeapObjectValue::String(string) => Ok(string),
        }
    }

    fn reserve_record_slot(&mut self) -> Result<(), EvalHeapError> {
        let records = self
            .records
            .len()
            .checked_add(1)
            .ok_or(EvalHeapError::RecordLengthOverflow)?;
        self.records
            .try_reserve_exact(1)
            .map_err(|_| EvalHeapError::RecordAllocationFailed { records })
    }

    fn record(&self, ptr: NonNull<HeapObject>) -> Option<&HeapRecord> {
        let address = ptr.as_ptr() as usize;
        self.records
            .iter()
            .find(|record| record.ptr.as_ptr() as usize == address)
    }
}

#[derive(Debug)]
struct HeapRecord {
    ptr: NonNull<HeapObject>,
    object: HeapObjectValue,
}

#[derive(Debug)]
enum HeapObjectValue {
    String(NixString),
}

/// A typed evaluator-heap operation failed.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum EvalHeapError {
    /// The underlying bump arena could not allocate an opaque handle.
    #[error("evaluator heap arena error: {0}")]
    Arena(#[from] ArenaError),
    /// The heap side table length overflowed.
    #[error("evaluator heap record length overflow")]
    RecordLengthOverflow,
    /// The heap side table could not reserve space for another object.
    #[error("evaluator heap failed to reserve {records} object records")]
    RecordAllocationFailed {
        /// The requested record capacity.
        records: usize,
    },
    /// A runtime value failed a checked heap-value operation.
    #[error("heap value operation failed: {0}")]
    Value(#[from] ValueError),
    /// A heap pointer did not belong to this evaluator heap.
    #[error("unknown heap pointer for {tag:?}: 0x{address:x}")]
    UnknownPointer {
        /// The expected runtime value tag.
        tag: ValueTag,
        /// The unrecognized pointer address.
        address: usize,
    },
}

impl EvalHeapError {
    fn unknown(tag: ValueTag, ptr: NonNull<HeapObject>) -> Self {
        Self::UnknownPointer {
            tag,
            address: ptr.as_ptr() as usize,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::string::{ContextElement, StringContext};

    #[test]
    fn allocates_string_values_and_recovers_contents() {
        let mut heap = EvalHeap::with_initial_chunk_bytes(64).expect("heap creates");
        let value = heap
            .alloc_string(NixString::from_bytes(b"hello".to_vec()))
            .expect("string allocates");

        assert_eq!(value.tag(), ValueTag::String);
        assert_eq!(heap.len(), 1);
        assert_eq!(
            heap.get_string(value).expect("string exists").bytes(),
            b"hello"
        );
        assert_eq!(heap.arena_stats().chunks, 1);
    }

    #[test]
    fn multiple_string_values_keep_distinct_heap_records() {
        let mut heap = EvalHeap::with_initial_chunk_bytes(128).expect("heap creates");
        let first = heap
            .alloc_string(NixString::from_bytes(b"first".to_vec()))
            .expect("first string allocates");
        let second = heap
            .alloc_string(NixString::from_bytes(b"second".to_vec()))
            .expect("second string allocates");

        assert_ne!(first.payload_bits(), second.payload_bits());
        assert_eq!(heap.len(), 2);
        assert_eq!(
            heap.get_string(first).expect("first exists").bytes(),
            b"first"
        );
        assert_eq!(
            heap.get_string(second).expect("second exists").bytes(),
            b"second"
        );
    }

    #[test]
    fn preserves_context_bearing_strings() {
        let context = StringContext::singleton(
            ContextElement::opaque_path(b"/nix/store/source".to_vec()).expect("context builds"),
        )
        .expect("singleton context allocates");
        let string = NixString::new(b"payload".to_vec(), context);
        let mut heap = EvalHeap::new();
        let value = heap.alloc_string(string).expect("string allocates");
        let stored = heap.get_string(value).expect("string exists");

        assert_eq!(stored.bytes(), b"payload");
        assert!(stored.has_context());
        assert_eq!(stored.context().len(), 1);
        assert_eq!(stored.context().elements()[0].path(), b"/nix/store/source");
    }

    #[test]
    fn rejects_string_values_from_another_live_heap() {
        let heap = EvalHeap::new();
        let mut other = EvalHeap::new();
        let foreign = other
            .alloc_string(NixString::from_bytes(b"foreign".to_vec()))
            .expect("foreign string allocates");
        let ptr = foreign.as_string_ptr().expect("foreign is a string");
        let error = heap
            .get_string(foreign)
            .expect_err("foreign pointer is not in this heap");

        assert_eq!(error, EvalHeapError::unknown(ValueTag::String, ptr));
    }

    #[test]
    fn rejects_wrong_value_tags_for_string_lookup() {
        let heap = EvalHeap::new();
        let error = heap
            .get_string(Value::int(1))
            .expect_err("integer is not a string");

        assert_eq!(
            error,
            EvalHeapError::Value(ValueError::Type {
                expected: "string",
                actual: ValueTag::Int,
            })
        );
    }

    #[test]
    fn reports_unknown_string_pointers() {
        let heap = EvalHeap::new();
        let ptr = NonNull::<HeapObject>::dangling();
        let value = Value::string(ptr).expect("dangling pointer is aligned");
        let error = heap
            .get_string(value)
            .expect_err("pointer does not belong to heap");

        assert_eq!(error, EvalHeapError::unknown(ValueTag::String, ptr));
    }

    #[test]
    fn propagates_invalid_initial_arena_chunk_size() {
        let error = EvalHeap::with_initial_chunk_bytes(0).expect_err("zero chunk size is invalid");

        assert_eq!(
            error,
            EvalHeapError::Arena(ArenaError::InvalidChunkSize { chunk_bytes: 0 })
        );
    }
}
