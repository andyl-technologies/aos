//! Typed heap-object registry for the tree-walk evaluator.
//!
//! Runtime [`Value`] words carry opaque [`HeapObject`] pointers. This registry
//! owns the typed Rust-side objects behind those pointers for the safe tree-walk
//! oracle: the bump arena provides stable opaque handles, while a side table
//! maps those handles back to checked [`NixString`], path [`NixString`],
//! [`NixList`], [`FlatAttrs`], [`EvalLambda`], and [`EvalThunk`] values.

use std::ptr::NonNull;
use std::rc::Rc;

use thiserror::Error;

use super::env::{EvalEnv, EvalWithEnv};
use super::thunk::ThunkCell;
use crate::attrs::FlatAttrs;
use crate::compile::{FrameId, IrId};
use crate::heap::arena::{ArenaError, ArenaStats, BumpArena};
use crate::list::NixList;
use crate::string::NixString;
use crate::value::{HeapObject, Value, ValueError, ValueTag};

/// A suspended tree-walk thunk heap record.
///
/// The record stores the lowered thunk body, captured lexical and dynamic
/// `with` environments, and serial state/result cell.
#[derive(Debug)]
pub struct EvalThunk {
    body: IrId,
    env: EvalEnv,
    with_env: EvalWithEnv,
    cell: ThunkCell,
}

impl EvalThunk {
    /// Creates a suspended environment-free thunk record for `body`.
    pub fn new(body: IrId) -> Self {
        Self::with_env(body, EvalEnv::default())
    }

    /// Creates a suspended thunk record for `body` and `env`.
    pub fn with_env(body: IrId, env: EvalEnv) -> Self {
        Self::with_captures(body, env, EvalWithEnv::default())
    }

    /// Creates a suspended thunk record with lexical and dynamic captures.
    pub fn with_captures(body: IrId, env: EvalEnv, with_env: EvalWithEnv) -> Self {
        Self {
            body,
            env,
            with_env,
            cell: ThunkCell::new(),
        }
    }

    /// Returns the lowered body this thunk will evaluate when forced.
    pub const fn body(&self) -> IrId {
        self.body
    }

    /// Returns the lexical environment captured when this thunk was allocated.
    pub const fn env(&self) -> &EvalEnv {
        &self.env
    }

    /// Returns the dynamic `with` environment captured when this thunk was allocated.
    pub const fn with_scope_env(&self) -> &EvalWithEnv {
        &self.with_env
    }

    /// Returns the serial state/result cell for this thunk.
    pub const fn cell(&self) -> &ThunkCell {
        &self.cell
    }
}

/// A user lambda closure heap record.
///
/// The record stores the lowered parameter pattern and body, the resolver frame
/// used for the call's argument slots, and the lexical and dynamic `with`
/// environments captured when the lambda was constructed.
#[derive(Debug)]
pub struct EvalLambda {
    pattern: IrId,
    body: IrId,
    frame: FrameId,
    env: EvalEnv,
    with_env: EvalWithEnv,
}

impl EvalLambda {
    /// Creates a lambda closure record.
    pub fn new(pattern: IrId, body: IrId, frame: FrameId, env: EvalEnv) -> Self {
        Self::with_captures(pattern, body, frame, env, EvalWithEnv::default())
    }

    /// Creates a lambda closure record with lexical and dynamic captures.
    pub fn with_captures(
        pattern: IrId,
        body: IrId,
        frame: FrameId,
        env: EvalEnv,
        with_env: EvalWithEnv,
    ) -> Self {
        Self {
            pattern,
            body,
            frame,
            env,
            with_env,
        }
    }

    /// Returns the lowered parameter pattern.
    pub const fn pattern(&self) -> IrId {
        self.pattern
    }

    /// Returns the lowered body expression.
    pub const fn body(&self) -> IrId {
        self.body
    }

    /// Returns the resolver frame associated with this lambda.
    pub const fn frame(&self) -> FrameId {
        self.frame
    }

    /// Returns the lexical environment captured when this lambda was allocated.
    pub const fn env(&self) -> &EvalEnv {
        &self.env
    }

    /// Returns the dynamic `with` environment captured when this lambda was allocated.
    pub const fn with_scope_env(&self) -> &EvalWithEnv {
        &self.with_env
    }
}

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

    /// Allocates a Nix path object and returns its opaque runtime value.
    ///
    /// The returned value is only meaningful while this [`EvalHeap`] remains
    /// alive. Use [`EvalHeap::get_path`] to recover the typed path bytes.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if record storage cannot be reserved, if the
    /// bump arena cannot reserve a path handle, or if the resulting handle
    /// violates the runtime value alignment contract.
    pub fn alloc_path(&mut self, path: NixString) -> Result<Value, EvalHeapError> {
        self.reserve_record_slot()?;
        let allocation = self
            .arena
            .aos_alloc_string(path.len())
            .map_err(EvalHeapError::Arena)?;
        let value = Value::path(allocation.ptr).map_err(EvalHeapError::Value)?;
        self.records.push(HeapRecord {
            ptr: allocation.ptr,
            object: HeapObjectValue::Path(path),
        });
        Ok(value)
    }

    /// Allocates a Nix list object and returns its opaque runtime value.
    ///
    /// The returned value is only meaningful while this [`EvalHeap`] remains
    /// alive. Use [`EvalHeap::get_list`] to recover the typed list.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if record storage cannot be reserved, if the
    /// bump arena cannot reserve a list handle, or if the resulting handle
    /// violates the runtime value alignment contract.
    pub fn alloc_list(&mut self, list: NixList) -> Result<Value, EvalHeapError> {
        self.reserve_record_slot()?;
        let allocation = self
            .arena
            .aos_alloc_list(list.len())
            .map_err(EvalHeapError::Arena)?;
        let value = Value::list(allocation.ptr).map_err(EvalHeapError::Value)?;
        self.records.push(HeapRecord {
            ptr: allocation.ptr,
            object: HeapObjectValue::List(list),
        });
        Ok(value)
    }

    /// Allocates an attribute-set object and returns its opaque runtime value.
    ///
    /// The returned value is only meaningful while this [`EvalHeap`] remains
    /// alive. Use [`EvalHeap::get_attrs`] to recover the typed attrset.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if record storage cannot be reserved, if the
    /// attrset length cannot fit the runtime slot count, if the bump arena
    /// cannot reserve an attrset handle, or if the resulting handle violates
    /// the runtime value alignment contract.
    pub fn alloc_attrs(&mut self, shape: u32, attrs: FlatAttrs) -> Result<Value, EvalHeapError> {
        self.reserve_record_slot()?;
        let slots = u32::try_from(attrs.len())
            .map_err(|_| EvalHeapError::Arena(ArenaError::SizeOverflow))?;
        let allocation = self
            .arena
            .aos_alloc_attrs(shape, slots)
            .map_err(EvalHeapError::Arena)?;
        let value = Value::attrs(allocation.ptr).map_err(EvalHeapError::Value)?;
        self.records.push(HeapRecord {
            ptr: allocation.ptr,
            object: HeapObjectValue::Attrs(attrs),
        });
        Ok(value)
    }

    /// Allocates a lambda closure object and returns its opaque runtime value.
    ///
    /// The returned value is only meaningful while this [`EvalHeap`] remains
    /// alive. Use [`EvalHeap::get_lambda`] to recover the typed closure.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if record storage cannot be reserved, if the
    /// bump arena cannot reserve a lambda handle, or if the resulting handle
    /// violates the runtime value alignment contract.
    pub fn alloc_lambda(&mut self, lambda: EvalLambda) -> Result<Value, EvalHeapError> {
        self.reserve_record_slot()?;
        let allocation = self
            .arena
            .aos_alloc_lambda()
            .map_err(EvalHeapError::Arena)?;
        let value = Value::lambda(allocation.ptr).map_err(EvalHeapError::Value)?;
        self.records.push(HeapRecord {
            ptr: allocation.ptr,
            object: HeapObjectValue::Lambda(Rc::new(lambda)),
        });
        Ok(value)
    }

    /// Allocates a suspended thunk object and returns its opaque runtime value.
    ///
    /// The returned value is only meaningful while this [`EvalHeap`] remains
    /// alive. Use [`EvalHeap::get_thunk`] to recover the typed thunk record.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if record storage cannot be reserved, if the
    /// bump arena cannot reserve a thunk handle, or if the resulting handle
    /// violates the runtime value alignment contract.
    pub fn alloc_thunk(&mut self, thunk: EvalThunk) -> Result<Value, EvalHeapError> {
        self.reserve_record_slot()?;
        let allocation = self.arena.aos_alloc_thunk().map_err(EvalHeapError::Arena)?;
        let value = Value::thunk(allocation.ptr).map_err(EvalHeapError::Value)?;
        self.records.push(HeapRecord {
            ptr: allocation.ptr,
            object: HeapObjectValue::Thunk(Rc::new(thunk)),
        });
        Ok(value)
    }

    /// Returns the string object referenced by `value`.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError::Value`] if `value` is not a string value.
    /// Returns [`EvalHeapError::UnknownPointer`] if the string handle does not
    /// belong to this heap. Returns [`EvalHeapError::RecordTypeMismatch`] if
    /// the handle belongs to this heap but references a non-string record.
    pub fn get_string(&self, value: Value) -> Result<&NixString, EvalHeapError> {
        let ptr = value.as_string_ptr().map_err(EvalHeapError::Value)?;
        self.get_string_ptr(ptr)
    }

    /// Returns the string object referenced by an opaque heap pointer.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError::UnknownPointer`] if `ptr` does not belong to
    /// this heap. Returns [`EvalHeapError::RecordTypeMismatch`] if `ptr`
    /// belongs to this heap but references a non-string record.
    pub fn get_string_ptr(&self, ptr: NonNull<HeapObject>) -> Result<&NixString, EvalHeapError> {
        let record = self.record_or_unknown(ValueTag::String, ptr)?;
        match &record.object {
            HeapObjectValue::String(string) => Ok(string),
            object => Err(EvalHeapError::record_type_mismatch(
                ValueTag::String,
                object.tag(),
                ptr,
            )),
        }
    }

    /// Returns the path object referenced by `value`.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError::Value`] if `value` is not a path value.
    /// Returns [`EvalHeapError::UnknownPointer`] if the path handle does not
    /// belong to this heap. Returns [`EvalHeapError::RecordTypeMismatch`] if
    /// the handle belongs to this heap but references a non-path record.
    pub fn get_path(&self, value: Value) -> Result<&NixString, EvalHeapError> {
        let ptr = value.as_path_ptr().map_err(EvalHeapError::Value)?;
        self.get_path_ptr(ptr)
    }

    /// Returns the path object referenced by an opaque heap pointer.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError::UnknownPointer`] if `ptr` does not belong to
    /// this heap. Returns [`EvalHeapError::RecordTypeMismatch`] if `ptr`
    /// belongs to this heap but references a non-path record.
    pub fn get_path_ptr(&self, ptr: NonNull<HeapObject>) -> Result<&NixString, EvalHeapError> {
        let record = self.record_or_unknown(ValueTag::Path, ptr)?;
        match &record.object {
            HeapObjectValue::Path(path) => Ok(path),
            object => Err(EvalHeapError::record_type_mismatch(
                ValueTag::Path,
                object.tag(),
                ptr,
            )),
        }
    }

    /// Returns the list object referenced by `value`.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError::Value`] if `value` is not a list value.
    /// Returns [`EvalHeapError::UnknownPointer`] if the list handle does not
    /// belong to this heap. Returns [`EvalHeapError::RecordTypeMismatch`] if
    /// the handle belongs to this heap but references a non-list record.
    pub fn get_list(&self, value: Value) -> Result<&NixList, EvalHeapError> {
        let ptr = value.as_list_ptr().map_err(EvalHeapError::Value)?;
        self.get_list_ptr(ptr)
    }

    /// Returns the list object referenced by an opaque heap pointer.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError::UnknownPointer`] if `ptr` does not belong to
    /// this heap. Returns [`EvalHeapError::RecordTypeMismatch`] if `ptr`
    /// belongs to this heap but references a non-list record.
    pub fn get_list_ptr(&self, ptr: NonNull<HeapObject>) -> Result<&NixList, EvalHeapError> {
        let record = self.record_or_unknown(ValueTag::List, ptr)?;
        match &record.object {
            HeapObjectValue::List(list) => Ok(list),
            object => Err(EvalHeapError::record_type_mismatch(
                ValueTag::List,
                object.tag(),
                ptr,
            )),
        }
    }

    /// Returns the attribute-set object referenced by `value`.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError::Value`] if `value` is not an attrset value.
    /// Returns [`EvalHeapError::UnknownPointer`] if the attrset handle does not
    /// belong to this heap. Returns [`EvalHeapError::RecordTypeMismatch`] if
    /// the handle belongs to this heap but references a non-attrset record.
    pub fn get_attrs(&self, value: Value) -> Result<&FlatAttrs, EvalHeapError> {
        let ptr = value.as_attrs_ptr().map_err(EvalHeapError::Value)?;
        self.get_attrs_ptr(ptr)
    }

    /// Returns the attribute-set object referenced by an opaque heap pointer.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError::UnknownPointer`] if `ptr` does not belong to
    /// this heap. Returns [`EvalHeapError::RecordTypeMismatch`] if `ptr`
    /// belongs to this heap but references a non-attrset record.
    pub fn get_attrs_ptr(&self, ptr: NonNull<HeapObject>) -> Result<&FlatAttrs, EvalHeapError> {
        let record = self.record_or_unknown(ValueTag::Attrs, ptr)?;
        match &record.object {
            HeapObjectValue::Attrs(attrs) => Ok(attrs),
            object => Err(EvalHeapError::record_type_mismatch(
                ValueTag::Attrs,
                object.tag(),
                ptr,
            )),
        }
    }

    /// Returns the lambda closure object referenced by `value`.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError::Value`] if `value` is not a lambda value.
    /// Returns [`EvalHeapError::UnknownPointer`] if the lambda handle does not
    /// belong to this heap. Returns [`EvalHeapError::RecordTypeMismatch`] if
    /// the handle belongs to this heap but references a non-lambda record.
    pub fn get_lambda(&self, value: Value) -> Result<&EvalLambda, EvalHeapError> {
        let ptr = value.as_lambda_ptr().map_err(EvalHeapError::Value)?;
        self.get_lambda_ptr(ptr)
    }

    /// Returns the lambda closure object referenced by an opaque heap pointer.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError::UnknownPointer`] if `ptr` does not belong to
    /// this heap. Returns [`EvalHeapError::RecordTypeMismatch`] if `ptr`
    /// belongs to this heap but references a non-lambda record.
    pub fn get_lambda_ptr(&self, ptr: NonNull<HeapObject>) -> Result<&EvalLambda, EvalHeapError> {
        let record = self.record_or_unknown(ValueTag::Lambda, ptr)?;
        match &record.object {
            HeapObjectValue::Lambda(lambda) => Ok(lambda.as_ref()),
            object => Err(EvalHeapError::record_type_mismatch(
                ValueTag::Lambda,
                object.tag(),
                ptr,
            )),
        }
    }

    /// Returns the suspended thunk object referenced by `value`.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError::Value`] if `value` is not a thunk value.
    /// Returns [`EvalHeapError::UnknownPointer`] if the thunk handle does not
    /// belong to this heap. Returns [`EvalHeapError::RecordTypeMismatch`] if
    /// the handle belongs to this heap but references a non-thunk record.
    pub fn get_thunk(&self, value: Value) -> Result<&EvalThunk, EvalHeapError> {
        let ptr = value.as_thunk_ptr().map_err(EvalHeapError::Value)?;
        self.get_thunk_ptr(ptr)
    }

    /// Returns the suspended thunk object referenced by an opaque heap pointer.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError::UnknownPointer`] if `ptr` does not belong to
    /// this heap. Returns [`EvalHeapError::RecordTypeMismatch`] if `ptr`
    /// belongs to this heap but references a non-thunk record.
    pub fn get_thunk_ptr(&self, ptr: NonNull<HeapObject>) -> Result<&EvalThunk, EvalHeapError> {
        let record = self.record_or_unknown(ValueTag::Thunk, ptr)?;
        match &record.object {
            HeapObjectValue::Thunk(thunk) => Ok(thunk.as_ref()),
            object => Err(EvalHeapError::record_type_mismatch(
                ValueTag::Thunk,
                object.tag(),
                ptr,
            )),
        }
    }

    /// Clones the thunk handle so forcing can release the heap borrow before
    /// re-entering evaluation.
    pub(crate) fn clone_thunk(&self, value: Value) -> Result<Rc<EvalThunk>, EvalHeapError> {
        let ptr = value.as_thunk_ptr().map_err(EvalHeapError::Value)?;
        let record = self.record_or_unknown(ValueTag::Thunk, ptr)?;
        match &record.object {
            HeapObjectValue::Thunk(thunk) => Ok(Rc::clone(thunk)),
            object => Err(EvalHeapError::record_type_mismatch(
                ValueTag::Thunk,
                object.tag(),
                ptr,
            )),
        }
    }

    /// Clones the lambda handle so application can release the heap borrow
    /// before evaluating the body.
    pub(crate) fn clone_lambda(&self, value: Value) -> Result<Rc<EvalLambda>, EvalHeapError> {
        let ptr = value.as_lambda_ptr().map_err(EvalHeapError::Value)?;
        let record = self.record_or_unknown(ValueTag::Lambda, ptr)?;
        match &record.object {
            HeapObjectValue::Lambda(lambda) => Ok(Rc::clone(lambda)),
            object => Err(EvalHeapError::record_type_mismatch(
                ValueTag::Lambda,
                object.tag(),
                ptr,
            )),
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

    fn record_or_unknown(
        &self,
        tag: ValueTag,
        ptr: NonNull<HeapObject>,
    ) -> Result<&HeapRecord, EvalHeapError> {
        self.record(ptr)
            .ok_or_else(|| EvalHeapError::unknown(tag, ptr))
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
    Path(NixString),
    List(NixList),
    Attrs(FlatAttrs),
    Lambda(Rc<EvalLambda>),
    Thunk(Rc<EvalThunk>),
}

impl HeapObjectValue {
    const fn tag(&self) -> ValueTag {
        match self {
            Self::String(_) => ValueTag::String,
            Self::Path(_) => ValueTag::Path,
            Self::List(_) => ValueTag::List,
            Self::Attrs(_) => ValueTag::Attrs,
            Self::Lambda(_) => ValueTag::Lambda,
            Self::Thunk(_) => ValueTag::Thunk,
        }
    }
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
    /// A heap pointer belonged to this heap but referenced another typed object.
    #[error("heap record type mismatch at 0x{address:x}: expected {expected:?}, got {actual:?}")]
    RecordTypeMismatch {
        /// The expected runtime value tag.
        expected: ValueTag,
        /// The actual typed record tag.
        actual: ValueTag,
        /// The pointer address shared by the runtime value and heap record.
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

    fn record_type_mismatch(
        expected: ValueTag,
        actual: ValueTag,
        ptr: NonNull<HeapObject>,
    ) -> Self {
        Self::RecordTypeMismatch {
            expected,
            actual,
            address: ptr.as_ptr() as usize,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::ThunkState;
    use super::*;
    use crate::attrs::AttrEntry;
    use crate::string::{ContextElement, StringContext};
    use crate::syntax::SymbolTable;

    fn attrs_with_one_entry() -> FlatAttrs {
        let mut symbols = SymbolTable::new();
        let key = symbols.intern(b"name").expect("symbol interns");
        FlatAttrs::new(vec![AttrEntry::new(key, Value::int(7))], &symbols).expect("attrset builds")
    }

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
    fn allocates_path_values_and_recovers_bytes() {
        let mut heap = EvalHeap::with_initial_chunk_bytes(128).expect("heap creates");
        let value = heap
            .alloc_path(NixString::from_bytes(b"/tmp/source".to_vec()))
            .expect("path allocates");

        assert_eq!(value.tag(), ValueTag::Path);
        assert_eq!(heap.len(), 1);
        assert_eq!(
            heap.get_path(value).expect("path exists").bytes(),
            b"/tmp/source"
        );
        assert_eq!(heap.arena_stats().chunks, 1);
    }

    #[test]
    fn allocates_list_values_and_recovers_spine() {
        let mut heap = EvalHeap::with_initial_chunk_bytes(128).expect("heap creates");
        let value = heap
            .alloc_list(NixList::new(vec![Value::int(1), Value::bool(true)]))
            .expect("list allocates");

        assert_eq!(value.tag(), ValueTag::List);
        assert_eq!(heap.len(), 1);
        let list = heap.get_list(value).expect("list exists");
        assert_eq!(list.len(), 2);
        assert_eq!(list.get(0).expect("first element").as_int(), Ok(1));
        assert_eq!(list.get(1).expect("second element").as_bool(), Ok(true));
        assert_eq!(heap.arena_stats().chunks, 1);
    }

    #[test]
    fn allocates_thunk_values_and_recovers_body() {
        let mut heap = EvalHeap::with_initial_chunk_bytes(128).expect("heap creates");
        let body = IrId::new(7);
        let value = heap
            .alloc_thunk(EvalThunk::new(body))
            .expect("thunk allocates");

        assert_eq!(value.tag(), ValueTag::Thunk);
        assert_eq!(heap.len(), 1);
        let thunk = heap.get_thunk(value).expect("thunk exists");
        assert_eq!(thunk.body(), body);
        assert_eq!(thunk.cell().state(), Ok(ThunkState::Suspended));
        assert_eq!(heap.arena_stats().chunks, 1);
    }

    #[test]
    fn allocates_lambda_values_and_recovers_closure() {
        let mut heap = EvalHeap::with_initial_chunk_bytes(128).expect("heap creates");
        let pattern = IrId::new(3);
        let body = IrId::new(7);
        let frame = FrameId::new(1);
        let value = heap
            .alloc_lambda(EvalLambda::new(pattern, body, frame, EvalEnv::default()))
            .expect("lambda allocates");

        assert_eq!(value.tag(), ValueTag::Lambda);
        assert_eq!(heap.len(), 1);
        let lambda = heap.get_lambda(value).expect("lambda exists");
        assert_eq!(lambda.pattern(), pattern);
        assert_eq!(lambda.body(), body);
        assert_eq!(lambda.frame(), frame);
        assert!(lambda.env().frames().is_empty());
        assert_eq!(heap.arena_stats().chunks, 1);
    }

    #[test]
    fn allocates_attr_values_and_recovers_entries() {
        let mut symbols = SymbolTable::new();
        let key = symbols.intern(b"name").expect("symbol interns");
        let attrs = FlatAttrs::new(vec![AttrEntry::new(key, Value::int(7))], &symbols)
            .expect("attrs build");
        let mut heap = EvalHeap::with_initial_chunk_bytes(128).expect("heap creates");
        let value = heap.alloc_attrs(42, attrs).expect("attrs allocate");

        assert_eq!(value.tag(), ValueTag::Attrs);
        assert_eq!(heap.len(), 1);
        let attrs = heap.get_attrs(value).expect("attrs exist");
        assert_eq!(attrs.len(), 1);
        assert_eq!(attrs.get(key).expect("name exists").as_int(), Ok(7));
        assert_eq!(heap.arena_stats().chunks, 1);
    }

    #[test]
    fn mixed_heap_object_types_keep_distinct_records() {
        let mut heap = EvalHeap::with_initial_chunk_bytes(512).expect("heap creates");
        let string = heap
            .alloc_string(NixString::from_bytes(b"name".to_vec()))
            .expect("string allocates");
        let path = heap
            .alloc_path(NixString::from_bytes(b"/tmp/name".to_vec()))
            .expect("path allocates");
        let list = heap
            .alloc_list(NixList::new(vec![Value::int(7)]))
            .expect("list allocates");
        let attrs = heap
            .alloc_attrs(9, attrs_with_one_entry())
            .expect("attrs allocate");
        let thunk = heap
            .alloc_thunk(EvalThunk::new(IrId::new(3)))
            .expect("thunk allocates");

        assert_ne!(string.payload_bits(), path.payload_bits());
        assert_ne!(string.payload_bits(), list.payload_bits());
        assert_ne!(string.payload_bits(), attrs.payload_bits());
        assert_ne!(string.payload_bits(), thunk.payload_bits());
        assert_ne!(path.payload_bits(), list.payload_bits());
        assert_ne!(path.payload_bits(), attrs.payload_bits());
        assert_ne!(path.payload_bits(), thunk.payload_bits());
        assert_ne!(list.payload_bits(), attrs.payload_bits());
        assert_ne!(list.payload_bits(), thunk.payload_bits());
        assert_ne!(attrs.payload_bits(), thunk.payload_bits());
        assert_eq!(heap.len(), 5);
        assert_eq!(
            heap.get_string(string).expect("string exists").bytes(),
            b"name"
        );
        assert_eq!(
            heap.get_path(path).expect("path exists").bytes(),
            b"/tmp/name"
        );
        assert_eq!(
            heap.get_list(list)
                .expect("list exists")
                .get(0)
                .expect("first element")
                .as_int(),
            Ok(7)
        );
        assert_eq!(heap.get_attrs(attrs).expect("attrs exist").len(), 1);
        assert_eq!(
            heap.get_thunk(thunk).expect("thunk exists").body(),
            IrId::new(3)
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
    fn rejects_path_values_from_another_live_heap() {
        let heap = EvalHeap::new();
        let mut other = EvalHeap::new();
        let foreign = other
            .alloc_path(NixString::from_bytes(b"/tmp/foreign".to_vec()))
            .expect("foreign path allocates");
        let ptr = foreign.as_path_ptr().expect("foreign is a path");
        let error = heap
            .get_path(foreign)
            .expect_err("foreign pointer is not in this heap");

        assert_eq!(error, EvalHeapError::unknown(ValueTag::Path, ptr));
    }

    #[test]
    fn rejects_list_values_from_another_live_heap() {
        let heap = EvalHeap::new();
        let mut other = EvalHeap::new();
        let foreign = other
            .alloc_list(NixList::new(vec![Value::int(1)]))
            .expect("foreign list allocates");
        let ptr = foreign.as_list_ptr().expect("foreign is a list");
        let error = heap
            .get_list(foreign)
            .expect_err("foreign pointer is not in this heap");

        assert_eq!(error, EvalHeapError::unknown(ValueTag::List, ptr));
    }

    #[test]
    fn rejects_attr_values_from_another_live_heap() {
        let heap = EvalHeap::new();
        let mut other = EvalHeap::new();
        let foreign = other
            .alloc_attrs(0, attrs_with_one_entry())
            .expect("foreign attrs allocate");
        let ptr = foreign.as_attrs_ptr().expect("foreign is an attrset");
        let error = heap
            .get_attrs(foreign)
            .expect_err("foreign pointer is not in this heap");

        assert_eq!(error, EvalHeapError::unknown(ValueTag::Attrs, ptr));
    }

    #[test]
    fn rejects_thunk_values_from_another_live_heap() {
        let heap = EvalHeap::new();
        let mut other = EvalHeap::new();
        let foreign = other
            .alloc_thunk(EvalThunk::new(IrId::new(1)))
            .expect("foreign thunk allocates");
        let ptr = foreign.as_thunk_ptr().expect("foreign is a thunk");
        let error = heap
            .get_thunk(foreign)
            .expect_err("foreign pointer is not in this heap");

        assert_eq!(error, EvalHeapError::unknown(ValueTag::Thunk, ptr));
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
    fn rejects_wrong_value_tags_for_path_lookup() {
        let heap = EvalHeap::new();
        let error = heap
            .get_path(Value::int(1))
            .expect_err("integer is not a path");

        assert_eq!(
            error,
            EvalHeapError::Value(ValueError::Type {
                expected: "path",
                actual: ValueTag::Int,
            })
        );
    }

    #[test]
    fn rejects_wrong_value_tags_for_list_lookup() {
        let heap = EvalHeap::new();
        let error = heap
            .get_list(Value::int(1))
            .expect_err("integer is not a list");

        assert_eq!(
            error,
            EvalHeapError::Value(ValueError::Type {
                expected: "list",
                actual: ValueTag::Int,
            })
        );
    }

    #[test]
    fn rejects_wrong_value_tags_for_thunk_lookup() {
        let heap = EvalHeap::new();
        let error = heap
            .get_thunk(Value::int(1))
            .expect_err("integer is not a thunk");

        assert_eq!(
            error,
            EvalHeapError::Value(ValueError::Type {
                expected: "thunk",
                actual: ValueTag::Int,
            })
        );
    }

    #[test]
    fn rejects_wrong_value_tags_for_attrs_lookup() {
        let heap = EvalHeap::new();
        let error = heap
            .get_attrs(Value::int(1))
            .expect_err("integer is not an attrset");

        assert_eq!(
            error,
            EvalHeapError::Value(ValueError::Type {
                expected: "attrs",
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
    fn reports_unknown_path_pointers() {
        let heap = EvalHeap::new();
        let ptr = NonNull::<HeapObject>::dangling();
        let value = Value::path(ptr).expect("dangling pointer is aligned");
        let error = heap
            .get_path(value)
            .expect_err("pointer does not belong to heap");

        assert_eq!(error, EvalHeapError::unknown(ValueTag::Path, ptr));
    }

    #[test]
    fn reports_unknown_list_pointers() {
        let heap = EvalHeap::new();
        let ptr = NonNull::<HeapObject>::dangling();
        let value = Value::list(ptr).expect("dangling pointer is aligned");
        let error = heap
            .get_list(value)
            .expect_err("pointer does not belong to heap");

        assert_eq!(error, EvalHeapError::unknown(ValueTag::List, ptr));
    }

    #[test]
    fn reports_unknown_thunk_pointers() {
        let heap = EvalHeap::new();
        let ptr = NonNull::<HeapObject>::dangling();
        let value = Value::thunk(ptr).expect("dangling pointer is aligned");
        let error = heap
            .get_thunk(value)
            .expect_err("pointer does not belong to heap");

        assert_eq!(error, EvalHeapError::unknown(ValueTag::Thunk, ptr));
    }

    #[test]
    fn reports_unknown_lambda_pointers() {
        let heap = EvalHeap::new();
        let ptr = NonNull::<HeapObject>::dangling();
        let value = Value::lambda(ptr).expect("dangling pointer is aligned");
        let error = heap
            .get_lambda(value)
            .expect_err("pointer does not belong to heap");

        assert_eq!(error, EvalHeapError::unknown(ValueTag::Lambda, ptr));
    }

    #[test]
    fn reports_unknown_attrs_pointers() {
        let heap = EvalHeap::new();
        let ptr = NonNull::<HeapObject>::dangling();
        let value = Value::attrs(ptr).expect("dangling pointer is aligned");
        let error = heap
            .get_attrs(value)
            .expect_err("pointer does not belong to heap");

        assert_eq!(error, EvalHeapError::unknown(ValueTag::Attrs, ptr));
    }

    #[test]
    fn reports_heap_record_type_mismatches() {
        let mut heap = EvalHeap::new();
        let list = heap.alloc_list(NixList::empty()).expect("list allocates");
        let list_ptr = list.as_list_ptr().expect("list pointer");
        let mislabeled_string = Value::string(list_ptr).expect("same pointer can carry string tag");

        let error = heap
            .get_string(mislabeled_string)
            .expect_err("record is not a string");

        assert_eq!(
            error,
            EvalHeapError::record_type_mismatch(ValueTag::String, ValueTag::List, list_ptr)
        );
        let mislabeled_path = Value::path(list_ptr).expect("same pointer can carry path tag");

        let error = heap
            .get_path(mislabeled_path)
            .expect_err("record is not a path");

        assert_eq!(
            error,
            EvalHeapError::record_type_mismatch(ValueTag::Path, ValueTag::List, list_ptr)
        );

        let string = heap
            .alloc_string(NixString::from_bytes(b"payload".to_vec()))
            .expect("string allocates");
        let string_ptr = string.as_string_ptr().expect("string pointer");
        let mislabeled_list = Value::list(string_ptr).expect("same pointer can carry list tag");

        let error = heap
            .get_list(mislabeled_list)
            .expect_err("record is not a list");

        assert_eq!(
            error,
            EvalHeapError::record_type_mismatch(ValueTag::List, ValueTag::String, string_ptr)
        );
        let mislabeled_thunk = Value::thunk(string_ptr).expect("same pointer can carry thunk tag");

        let error = heap
            .get_thunk(mislabeled_thunk)
            .expect_err("record is not a thunk");

        assert_eq!(
            error,
            EvalHeapError::record_type_mismatch(ValueTag::Thunk, ValueTag::String, string_ptr)
        );
        let mislabeled_lambda =
            Value::lambda(string_ptr).expect("same pointer can carry lambda tag");

        let error = heap
            .get_lambda(mislabeled_lambda)
            .expect_err("record is not a lambda");

        assert_eq!(
            error,
            EvalHeapError::record_type_mismatch(ValueTag::Lambda, ValueTag::String, string_ptr)
        );
        let mislabeled_attrs = Value::attrs(string_ptr).expect("same pointer can carry attrs tag");

        let error = heap
            .get_attrs(mislabeled_attrs)
            .expect_err("record is not an attrset");

        assert_eq!(
            error,
            EvalHeapError::record_type_mismatch(ValueTag::Attrs, ValueTag::String, string_ptr)
        );
        let mislabeled_path = Value::path(string_ptr).expect("same pointer can carry path tag");

        let error = heap
            .get_path(mislabeled_path)
            .expect_err("record is not a path");

        assert_eq!(
            error,
            EvalHeapError::record_type_mismatch(ValueTag::Path, ValueTag::String, string_ptr)
        );

        let thunk = heap
            .alloc_thunk(EvalThunk::new(IrId::new(0)))
            .expect("thunk allocates");
        let thunk_ptr = thunk.as_thunk_ptr().expect("thunk pointer");
        let mislabeled_list = Value::list(thunk_ptr).expect("same pointer can carry list tag");

        let error = heap
            .get_list(mislabeled_list)
            .expect_err("record is not a list");

        assert_eq!(
            error,
            EvalHeapError::record_type_mismatch(ValueTag::List, ValueTag::Thunk, thunk_ptr)
        );

        let lambda = heap
            .alloc_lambda(EvalLambda::new(
                IrId::new(0),
                IrId::new(1),
                FrameId::new(0),
                EvalEnv::default(),
            ))
            .expect("lambda allocates");
        let lambda_ptr = lambda.as_lambda_ptr().expect("lambda pointer");
        let mislabeled_string =
            Value::string(lambda_ptr).expect("same pointer can carry string tag");

        let error = heap
            .get_string(mislabeled_string)
            .expect_err("record is not a string");

        assert_eq!(
            error,
            EvalHeapError::record_type_mismatch(ValueTag::String, ValueTag::Lambda, lambda_ptr)
        );
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
