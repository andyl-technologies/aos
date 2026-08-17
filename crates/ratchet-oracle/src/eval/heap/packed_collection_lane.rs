//! Registry-free immutable collection destinations for moving publication.
//!
//! Lists use an eight-byte range record over exact Candidate-C value words.
//! Attrsets retain every [`crate::attrs::FlatAttrs`] observable without a
//! per-object map: entries are symbol-sorted for binary search, while compact
//! source and lexicographic order lanes retain both iteration orders.
//! Positions occupy a sparse twelve-byte lane.
//!
//! Source identity maps exist only in [`PackedCollectionLaneBuilder`].
//! Finalization consumes and drops them; [`PackedCollectionLane`] contains
//! only seven contiguous vectors.

use std::collections::HashMap;
use std::hash::Hash;
use std::mem;

use thiserror::Error;

use crate::attrs::repr::AttrSetReprKind;
use crate::attrs::shape::ShapeId;
use crate::syntax::{Span, Symbol};

use super::EvalHeapAttrsMetadata;
use super::packed_thunk_lane::PackedValueWord;

const NO_POSITION: u32 = u32::MAX;
const ATTR_HAS_PROJECTED_SHAPE: u32 = 1;
const ATTR_REPR_HAMT: u32 = 1 << 1;
const ATTR_VALID_FLAGS: u32 = ATTR_HAS_PROJECTED_SHAPE | ATTR_REPR_HAMT;

fn checked_index(index: usize, lane: &'static str) -> Result<u32, PackedCollectionLaneError> {
    u32::try_from(index).map_err(|_| PackedCollectionLaneError::IndexOverflow { lane, index })
}

fn checked_range(
    start: usize,
    count: usize,
    lane: &'static str,
) -> Result<(u32, u32), PackedCollectionLaneError> {
    let start = checked_index(start, lane)?;
    let count = u32::try_from(count)
        .map_err(|_| PackedCollectionLaneError::CountOverflow { lane, count })?;
    start
        .checked_add(count)
        .ok_or(PackedCollectionLaneError::RangeOverflow { lane, start, count })?;
    Ok((start, count))
}

fn checked_bytes<T>(
    elements: usize,
    lane: &'static str,
) -> Result<usize, PackedCollectionLaneError> {
    elements
        .checked_mul(mem::size_of::<T>())
        .ok_or(PackedCollectionLaneError::ByteAccountingOverflow { lane, elements })
}

/// A direct packed-list record coordinate.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct PackedListRef(u32);

impl PackedListRef {
    /// Builds a direct coordinate for checked lane resolution.
    pub(crate) const fn from_index(index: u32) -> Self {
        Self(index)
    }

    /// Returns the fixed-record index.
    pub(crate) const fn index(self) -> u32 {
        self.0
    }
}

/// A direct packed-attrset record coordinate.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct PackedAttrsRef(u32);

impl PackedAttrsRef {
    /// Builds a direct coordinate for checked lane resolution.
    pub(crate) const fn from_index(index: u32) -> Self {
        Self(index)
    }

    /// Returns the fixed-record index.
    pub(crate) const fn index(self) -> u32 {
        self.0
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PackedListRecord {
    start: u32,
    count: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PackedAttrsRecord {
    shape: u32,
    projected_shape: u32,
    start: u32,
    count: u32,
    flags: u32,
}

impl PackedAttrsRecord {
    fn new(metadata: EvalHeapAttrsMetadata, start: u32, count: u32) -> Self {
        let projected_shape = metadata.projected_shape().map_or(0, ShapeId::as_u32);
        let mut flags = metadata
            .projected_shape()
            .map_or(0, |_| ATTR_HAS_PROJECTED_SHAPE);
        if metadata.repr() == AttrSetReprKind::Hamt {
            flags |= ATTR_REPR_HAMT;
        }
        Self {
            shape: metadata.shape(),
            projected_shape,
            start,
            count,
            flags,
        }
    }
}

/// One symbol-sorted packed attribute binding.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PackedAttrEntry {
    value: PackedValueWord,
    symbol: u32,
    position: u32,
}

impl PackedAttrEntry {
    /// Returns the binding symbol.
    pub(crate) const fn symbol(self) -> Symbol {
        Symbol::new(self.symbol)
    }

    /// Returns the exact Candidate-C binding value.
    pub(crate) const fn value(self) -> PackedValueWord {
        self.value
    }

    /// Returns the sparse source-position coordinate, when one is present.
    pub(crate) const fn position_index(self) -> Option<u32> {
        if self.position == NO_POSITION {
            None
        } else {
            Some(self.position)
        }
    }
}

/// One optional source provenance record.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PackedAttrPosition {
    module: u32,
    start: u32,
    end: u32,
}

impl PackedAttrPosition {
    /// Returns the source module coordinate.
    pub(crate) const fn module(self) -> u32 {
        self.module
    }

    /// Returns the source byte span.
    pub(crate) const fn span(self) -> Span {
        Span::new(self.start, self.end)
    }
}

/// Builder input for one immutable attr binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PackedAttrBinding {
    symbol: Symbol,
    value: PackedValueWord,
    position: Option<PackedAttrPosition>,
}

impl PackedAttrBinding {
    /// Creates a binding without source provenance.
    pub(crate) const fn new(symbol: Symbol, value: PackedValueWord) -> Self {
        Self {
            symbol,
            value,
            position: None,
        }
    }

    /// Creates a binding with exact source provenance.
    pub(crate) const fn with_position(
        symbol: Symbol,
        value: PackedValueWord,
        module: u32,
        span: Span,
    ) -> Self {
        Self {
            symbol,
            value,
            position: Some(PackedAttrPosition {
                module,
                start: span.start,
                end: span.end,
            }),
        }
    }
}

/// Per-lane byte accounting for a packed immutable collection destination.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PackedCollectionLaneBytes {
    /// Bytes in the finalized lane's seven vector descriptors.
    pub(crate) control: usize,
    /// Bytes in list records.
    pub(crate) list_records: usize,
    /// Bytes in list values.
    pub(crate) list_values: usize,
    /// Bytes in attrset records.
    pub(crate) attrs_records: usize,
    /// Bytes in symbol-sorted attr entries.
    pub(crate) attrs_entries: usize,
    /// Bytes in sparse source-position records.
    pub(crate) positions: usize,
    /// Bytes in construction-order indices.
    pub(crate) source_order: usize,
    /// Bytes in lexicographic-order indices.
    pub(crate) iteration_order: usize,
}

impl PackedCollectionLaneBytes {
    /// Returns the checked sum of every reported lane.
    ///
    /// # Errors
    ///
    /// Returns [`PackedCollectionLaneError::ByteAccountingTotalOverflow`] if
    /// the individual exact byte counts cannot be summed in `usize`.
    pub(crate) fn total(self) -> Result<usize, PackedCollectionLaneError> {
        [
            self.control,
            self.list_records,
            self.list_values,
            self.attrs_records,
            self.attrs_entries,
            self.positions,
            self.source_order,
            self.iteration_order,
        ]
        .into_iter()
        .try_fold(0usize, |total, bytes| {
            total
                .checked_add(bytes)
                .ok_or(PackedCollectionLaneError::ByteAccountingTotalOverflow)
        })
    }
}

/// A finalized immutable collection destination with no object registry.
#[derive(Debug, Default)]
pub(crate) struct PackedCollectionLane {
    lists: Vec<PackedListRecord>,
    list_values: Vec<PackedValueWord>,
    attrs: Vec<PackedAttrsRecord>,
    attr_entries: Vec<PackedAttrEntry>,
    positions: Vec<PackedAttrPosition>,
    source_order: Vec<u32>,
    iteration_order: Vec<u32>,
}

/// Checked borrowed slices behind one finalized packed attrset.
///
/// Construction verifies every range and every sparse position/order index
/// without allocating. Symbol ordering and permutation uniqueness are builder
/// invariants validated before a lane is finalized.
#[derive(Clone, Copy, Debug)]
pub(crate) struct PackedAttrsViewParts<'a> {
    entries: &'a [PackedAttrEntry],
    positions: &'a [PackedAttrPosition],
    source_order: &'a [u32],
    iteration_order: &'a [u32],
}

impl<'a> PackedAttrsViewParts<'a> {
    /// Returns bindings in symbol-id order.
    pub(crate) const fn entries(self) -> &'a [PackedAttrEntry] {
        self.entries
    }

    /// Returns the lane-wide sparse source-position table.
    pub(crate) const fn positions(self) -> &'a [PackedAttrPosition] {
        self.positions
    }

    /// Returns binding slots in construction order.
    pub(crate) const fn source_order(self) -> &'a [u32] {
        self.source_order
    }

    /// Returns binding slots in observable lexicographic order.
    pub(crate) const fn iteration_order(self) -> &'a [u32] {
        self.iteration_order
    }
}

/// Exact logical element counts admitted for a direct collection build.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct PackedCollectionLaneCapacities {
    /// List range records.
    pub(crate) lists: usize,
    /// Candidate-C list element words.
    pub(crate) list_values: usize,
    /// Attrset records.
    pub(crate) attrs: usize,
    /// Symbol-sorted attr bindings.
    pub(crate) attr_entries: usize,
    /// Sparse source positions.
    pub(crate) positions: usize,
    /// Attr construction-order indices.
    pub(crate) source_order: usize,
    /// Attr observable iteration-order indices.
    pub(crate) iteration_order: usize,
}

impl PackedCollectionLane {
    /// Returns initialized bytes, including the fixed lane control structure.
    ///
    /// # Errors
    ///
    /// Returns [`PackedCollectionLaneError`] if byte arithmetic overflows.
    pub(crate) fn initialized_bytes(
        &self,
    ) -> Result<PackedCollectionLaneBytes, PackedCollectionLaneError> {
        self.bytes_with(
            self.lists.len(),
            self.list_values.len(),
            self.attrs.len(),
            self.attr_entries.len(),
            self.positions.len(),
            self.source_order.len(),
            self.iteration_order.len(),
        )
    }

    /// Returns allocated vector-capacity bytes plus the control structure.
    ///
    /// # Errors
    ///
    /// Returns [`PackedCollectionLaneError`] if byte arithmetic overflows.
    pub(crate) fn capacity_bytes(
        &self,
    ) -> Result<PackedCollectionLaneBytes, PackedCollectionLaneError> {
        self.bytes_with(
            self.lists.capacity(),
            self.list_values.capacity(),
            self.attrs.capacity(),
            self.attr_entries.capacity(),
            self.positions.capacity(),
            self.source_order.capacity(),
            self.iteration_order.capacity(),
        )
    }

    fn bytes_with(
        &self,
        lists: usize,
        list_values: usize,
        attrs: usize,
        entries: usize,
        positions: usize,
        source_order: usize,
        iteration_order: usize,
    ) -> Result<PackedCollectionLaneBytes, PackedCollectionLaneError> {
        Ok(PackedCollectionLaneBytes {
            control: mem::size_of::<Self>(),
            list_records: checked_bytes::<PackedListRecord>(lists, "list-record")?,
            list_values: checked_bytes::<PackedValueWord>(list_values, "list-value")?,
            attrs_records: checked_bytes::<PackedAttrsRecord>(attrs, "attrs-record")?,
            attrs_entries: checked_bytes::<PackedAttrEntry>(entries, "attrs-entry")?,
            positions: checked_bytes::<PackedAttrPosition>(positions, "attr-position")?,
            source_order: checked_bytes::<u32>(source_order, "source-order")?,
            iteration_order: checked_bytes::<u32>(iteration_order, "iteration-order")?,
        })
    }

    /// Returns one packed list's exact value slice.
    ///
    /// # Errors
    ///
    /// Returns [`PackedCollectionLaneError`] for a stale reference or malformed
    /// stored range.
    pub(crate) fn list(
        &self,
        reference: PackedListRef,
    ) -> Result<&[PackedValueWord], PackedCollectionLaneError> {
        let record = self
            .lists
            .get(reference.0 as usize)
            .ok_or(PackedCollectionLaneError::UnknownList { index: reference.0 })?;
        checked_slice(
            &self.list_values,
            record.start,
            record.count,
            "list-value",
            reference.0,
        )
    }

    /// Returns one list element by direct local index.
    ///
    /// # Errors
    ///
    /// Returns [`PackedCollectionLaneError`] for a stale list, malformed range,
    /// or out-of-range local index.
    pub(crate) fn list_get(
        &self,
        reference: PackedListRef,
        index: u32,
    ) -> Result<PackedValueWord, PackedCollectionLaneError> {
        self.list(reference)?.get(index as usize).copied().ok_or(
            PackedCollectionLaneError::LocalIndexOutOfRange {
                object: "list",
                index,
            },
        )
    }

    /// Returns exact attrset metadata.
    ///
    /// # Errors
    ///
    /// Returns [`PackedCollectionLaneError`] for a stale reference or malformed
    /// metadata flags.
    pub(crate) fn attrs_metadata(
        &self,
        reference: PackedAttrsRef,
    ) -> Result<EvalHeapAttrsMetadata, PackedCollectionLaneError> {
        let record = self.attrs_record(reference)?;
        if record.flags & !ATTR_VALID_FLAGS != 0 {
            return Err(PackedCollectionLaneError::MalformedAttrsFlags {
                attrs: reference.0,
                flags: record.flags,
            });
        }
        let repr = if record.flags & ATTR_REPR_HAMT != 0 {
            AttrSetReprKind::Hamt
        } else {
            AttrSetReprKind::Flat
        };
        Ok(if record.flags & ATTR_HAS_PROJECTED_SHAPE != 0 {
            EvalHeapAttrsMetadata::with_projected_shape(
                record.shape,
                repr,
                ShapeId::new(record.projected_shape),
            )
        } else {
            EvalHeapAttrsMetadata::new(record.shape, repr)
        })
    }

    /// Returns symbol-sorted entries from the builder-validated immutable lane.
    ///
    /// # Errors
    ///
    /// Returns [`PackedCollectionLaneError`] for stale or malformed ranges.
    pub(crate) fn attrs_entries(
        &self,
        reference: PackedAttrsRef,
    ) -> Result<&[PackedAttrEntry], PackedCollectionLaneError> {
        let record = self.attrs_record(reference)?;
        checked_slice(
            &self.attr_entries,
            record.start,
            record.count,
            "attrs-entry",
            reference.0,
        )
    }

    /// Resolves the allocation-free read view of one finalized attrset.
    ///
    /// The finalized builder has already established strict symbol ordering
    /// and complete permutation uniqueness. This constructor rechecks every
    /// borrowed range and every index that will be followed by a view, so a
    /// stale or structurally truncated reference cannot escape.
    ///
    /// # Errors
    ///
    /// Returns [`PackedCollectionLaneError`] for a stale reference, malformed
    /// range, out-of-range source-position coordinate, or out-of-range order
    /// coordinate.
    pub(crate) fn attrs_view_parts(
        &self,
        reference: PackedAttrsRef,
    ) -> Result<PackedAttrsViewParts<'_>, PackedCollectionLaneError> {
        let record = self.attrs_record(reference)?;
        let entries = checked_slice(
            &self.attr_entries,
            record.start,
            record.count,
            "attrs-entry",
            reference.0,
        )?;
        let source_order = checked_slice(
            &self.source_order,
            record.start,
            record.count,
            "source-order",
            reference.0,
        )?;
        let iteration_order = checked_slice(
            &self.iteration_order,
            record.start,
            record.count,
            "iteration-order",
            reference.0,
        )?;
        for entry in entries {
            if let Some(position) = entry.position_index()
                && self.positions.get(position as usize).is_none()
            {
                return Err(PackedCollectionLaneError::MalformedPositionIndex {
                    attrs: reference.0,
                    position,
                });
            }
        }
        for (lane, order) in [
            ("source-order", source_order),
            ("iteration-order", iteration_order),
        ] {
            for index in order {
                if *index >= record.count {
                    return Err(PackedCollectionLaneError::MalformedOrderIndex {
                        lane,
                        index: *index,
                        count: record.count,
                    });
                }
            }
        }
        Ok(PackedAttrsViewParts {
            entries,
            positions: &self.positions,
            source_order,
            iteration_order,
        })
    }

    /// Finds one binding through binary search over symbol-sorted entries.
    ///
    /// # Errors
    ///
    /// Returns [`PackedCollectionLaneError`] if the attrset storage is
    /// malformed.
    pub(crate) fn attrs_get(
        &self,
        reference: PackedAttrsRef,
        symbol: Symbol,
    ) -> Result<Option<PackedValueWord>, PackedCollectionLaneError> {
        let entries = self.attrs_entries(reference)?;
        Ok(entries
            .binary_search_by_key(&symbol, |entry| entry.symbol())
            .ok()
            .and_then(|slot| entries.get(slot))
            .map(|entry| entry.value()))
    }

    /// Returns one binding's optional source provenance.
    ///
    /// # Errors
    ///
    /// Returns [`PackedCollectionLaneError`] for malformed attr storage, a
    /// local slot out of range, or a malformed position index.
    pub(crate) fn attrs_position(
        &self,
        reference: PackedAttrsRef,
        symbol_slot: u32,
    ) -> Result<Option<PackedAttrPosition>, PackedCollectionLaneError> {
        let entry = self
            .attrs_entries(reference)?
            .get(symbol_slot as usize)
            .ok_or(PackedCollectionLaneError::LocalIndexOutOfRange {
                object: "attrs-entry",
                index: symbol_slot,
            })?;
        if entry.position == NO_POSITION {
            return Ok(None);
        }
        self.positions
            .get(entry.position as usize)
            .copied()
            .map(Some)
            .ok_or(PackedCollectionLaneError::MalformedPositionIndex {
                attrs: reference.0,
                position: entry.position,
            })
    }

    /// Returns one construction-order entry.
    ///
    /// # Errors
    ///
    /// Returns [`PackedCollectionLaneError`] for malformed storage,
    /// permutations, or a local order index out of range.
    pub(crate) fn attrs_source_entry(
        &self,
        reference: PackedAttrsRef,
        index: u32,
    ) -> Result<&PackedAttrEntry, PackedCollectionLaneError> {
        self.attrs_order_entry(reference, index, true)
    }

    /// Returns one observable lexicographic-order entry.
    ///
    /// # Errors
    ///
    /// Returns [`PackedCollectionLaneError`] for malformed storage,
    /// permutations, or a local order index out of range.
    pub(crate) fn attrs_iteration_entry(
        &self,
        reference: PackedAttrsRef,
        index: u32,
    ) -> Result<&PackedAttrEntry, PackedCollectionLaneError> {
        self.attrs_order_entry(reference, index, false)
    }

    fn attrs_order_entry(
        &self,
        reference: PackedAttrsRef,
        index: u32,
        source: bool,
    ) -> Result<&PackedAttrEntry, PackedCollectionLaneError> {
        let record = self.attrs_record(reference)?;
        let entries = self.attrs_entries(reference)?;
        let (lane, name) = if source {
            (&self.source_order, "source-order")
        } else {
            (&self.iteration_order, "iteration-order")
        };
        let order = checked_slice(lane, record.start, record.count, name, reference.0)?;
        let slot = order.get(index as usize).copied().ok_or(
            PackedCollectionLaneError::LocalIndexOutOfRange {
                object: name,
                index,
            },
        )?;
        entries
            .get(slot as usize)
            .ok_or(PackedCollectionLaneError::MalformedOrderIndex {
                lane: name,
                index: slot,
                count: record.count,
            })
    }

    fn attrs_record(
        &self,
        reference: PackedAttrsRef,
    ) -> Result<&PackedAttrsRecord, PackedCollectionLaneError> {
        self.attrs
            .get(reference.0 as usize)
            .ok_or(PackedCollectionLaneError::UnknownAttrs { index: reference.0 })
    }

    /// Audits every invariant of one finalized immutable attrset.
    ///
    /// Direct lookup and iteration rely on the consuming builder having
    /// performed this validation once. Publication boundaries and untrusted
    /// restore paths can call this method before exposing a lane.
    ///
    /// # Errors
    ///
    /// Returns [`PackedCollectionLaneError`] for malformed metadata, ranges,
    /// symbol order, positions, or order permutations.
    pub(crate) fn validate_attrs(
        &self,
        reference: PackedAttrsRef,
    ) -> Result<(), PackedCollectionLaneError> {
        self.attrs_metadata(reference)?;
        let entries = self.attrs_entries(reference)?;
        validate_symbol_order(entries)?;
        for entry in entries {
            if entry.position != NO_POSITION && (entry.position as usize) >= self.positions.len() {
                return Err(PackedCollectionLaneError::MalformedPositionIndex {
                    attrs: reference.0,
                    position: entry.position,
                });
            }
        }
        let record = self.attrs_record(reference)?;
        let source = checked_slice(
            &self.source_order,
            record.start,
            record.count,
            "source-order",
            reference.0,
        )?;
        validate_permutation(source, record.count, "source-order")?;
        let iteration = checked_slice(
            &self.iteration_order,
            record.start,
            record.count,
            "iteration-order",
            reference.0,
        )?;
        validate_permutation(iteration, record.count, "iteration-order")
    }
}

fn checked_slice<'a, T>(
    lane: &'a [T],
    start: u32,
    count: u32,
    name: &'static str,
    object: u32,
) -> Result<&'a [T], PackedCollectionLaneError> {
    let start_usize = start as usize;
    let end = start_usize.checked_add(count as usize).ok_or(
        PackedCollectionLaneError::MalformedRange {
            lane: name,
            object,
            start,
            count,
        },
    )?;
    lane.get(start_usize..end)
        .ok_or(PackedCollectionLaneError::MalformedRange {
            lane: name,
            object,
            start,
            count,
        })
}

fn validate_symbol_order(entries: &[PackedAttrEntry]) -> Result<(), PackedCollectionLaneError> {
    for pair in entries.windows(2) {
        if pair[0].symbol == pair[1].symbol {
            return Err(PackedCollectionLaneError::DuplicateSymbol {
                symbol: pair[0].symbol,
            });
        }
        if pair[0].symbol > pair[1].symbol {
            return Err(PackedCollectionLaneError::SymbolsNotSorted {
                previous: pair[0].symbol,
                next: pair[1].symbol,
            });
        }
    }
    Ok(())
}

fn validate_permutation(
    order: &[u32],
    count: u32,
    lane: &'static str,
) -> Result<(), PackedCollectionLaneError> {
    if order.len() != count as usize {
        return Err(PackedCollectionLaneError::MalformedOrderLength {
            lane,
            actual: order.len(),
            expected: count,
        });
    }
    let mut seen = Vec::new();
    seen.try_reserve_exact(order.len()).map_err(|_| {
        PackedCollectionLaneError::AllocationFailed {
            lane: "order-validation",
        }
    })?;
    seen.resize(order.len(), false);
    for &index in order {
        let Some(slot) = seen.get_mut(index as usize) else {
            return Err(PackedCollectionLaneError::MalformedOrderIndex { lane, index, count });
        };
        if *slot {
            return Err(PackedCollectionLaneError::DuplicateOrderIndex { lane, index });
        }
        *slot = true;
    }
    Ok(())
}

/// A pre-reserved, source-map-free packed collection builder.
///
/// List and attrset coordinates are assigned directly by append order. The
/// moving collector supplies already translated values and therefore needs no
/// temporary source-identity hash maps in this builder.
#[derive(Debug)]
pub(crate) struct PackedCollectionLaneDirectBuilder {
    lane: PackedCollectionLane,
    admitted: PackedCollectionLaneCapacities,
    admitted_capacity_bytes: PackedCollectionLaneBytes,
}

impl PackedCollectionLaneDirectBuilder {
    /// Reserves every admitted collection lane before appending any object.
    ///
    /// # Errors
    ///
    /// Returns [`PackedCollectionLaneError`] if a count cannot be represented,
    /// byte accounting overflows, or any complete reservation fails.
    pub(crate) fn try_new(
        admitted: PackedCollectionLaneCapacities,
    ) -> Result<Self, PackedCollectionLaneError> {
        validate_collection_capacities(admitted)?;
        let mut lane = PackedCollectionLane::default();
        reserve_collection_lane(&mut lane.lists, admitted.lists, "list-record")?;
        reserve_collection_lane(&mut lane.list_values, admitted.list_values, "list-value")?;
        reserve_collection_lane(&mut lane.attrs, admitted.attrs, "attrs-record")?;
        reserve_collection_lane(&mut lane.attr_entries, admitted.attr_entries, "attrs-entry")?;
        reserve_collection_lane(&mut lane.positions, admitted.positions, "attr-position")?;
        reserve_collection_lane(
            &mut lane.source_order,
            admitted.source_order,
            "source-order",
        )?;
        reserve_collection_lane(
            &mut lane.iteration_order,
            admitted.iteration_order,
            "iteration-order",
        )?;
        let admitted_capacity_bytes = lane.capacity_bytes()?;
        Ok(Self {
            lane,
            admitted,
            admitted_capacity_bytes,
        })
    }

    /// Appends one immutable list at its preassigned next coordinate.
    ///
    /// # Errors
    ///
    /// Returns [`PackedCollectionLaneError`] before mutation when the list
    /// record or value admission is exhausted or a direct range overflows.
    pub(crate) fn append_list(
        &mut self,
        values: &[PackedValueWord],
    ) -> Result<PackedListRef, PackedCollectionLaneError> {
        preflight_collection_capacity(
            "list-record",
            self.lane.lists.len(),
            1,
            self.admitted.lists,
        )?;
        preflight_collection_capacity(
            "list-value",
            self.lane.list_values.len(),
            values.len(),
            self.admitted.list_values,
        )?;
        let reference = PackedListRef(checked_index(self.lane.lists.len(), "list-record")?);
        let (start, count) =
            checked_range(self.lane.list_values.len(), values.len(), "list-value")?;
        self.ensure_capacity_unchanged()?;
        self.lane.list_values.extend_from_slice(values);
        self.lane.lists.push(PackedListRecord { start, count });
        self.ensure_capacity_unchanged()?;
        Ok(reference)
    }

    /// Appends one immutable attrset at its preassigned next coordinate.
    ///
    /// `bindings` must be strictly symbol-sorted and both order slices must be
    /// complete permutations over the binding slots.
    ///
    /// # Errors
    ///
    /// Returns [`PackedCollectionLaneError`] before mutation for malformed
    /// input, exhausted lane admission, coordinate overflow, or capacity drift.
    pub(crate) fn append_attrs(
        &mut self,
        metadata: EvalHeapAttrsMetadata,
        bindings: &[PackedAttrBinding],
        source_order: &[u32],
        iteration_order: &[u32],
    ) -> Result<PackedAttrsRef, PackedCollectionLaneError> {
        let (_, count) = checked_range(0, bindings.len(), "attrs-entry")?;
        if source_order.len() != bindings.len() {
            return Err(PackedCollectionLaneError::MalformedOrderLength {
                lane: "source-order",
                actual: source_order.len(),
                expected: count,
            });
        }
        if iteration_order.len() != bindings.len() {
            return Err(PackedCollectionLaneError::MalformedOrderLength {
                lane: "iteration-order",
                actual: iteration_order.len(),
                expected: count,
            });
        }
        validate_binding_symbol_order(bindings)?;
        validate_permutation(source_order, count, "source-order")?;
        validate_permutation(iteration_order, count, "iteration-order")?;
        if self.lane.attr_entries.len() != self.lane.source_order.len()
            || self.lane.attr_entries.len() != self.lane.iteration_order.len()
        {
            return Err(PackedCollectionLaneError::BuilderLaneDesynchronized);
        }
        let position_count = bindings
            .iter()
            .filter(|binding| binding.position.is_some())
            .count();
        for (name, initialized, additional, admitted) in [
            (
                "attrs-record",
                self.lane.attrs.len(),
                1,
                self.admitted.attrs,
            ),
            (
                "attrs-entry",
                self.lane.attr_entries.len(),
                bindings.len(),
                self.admitted.attr_entries,
            ),
            (
                "attr-position",
                self.lane.positions.len(),
                position_count,
                self.admitted.positions,
            ),
            (
                "source-order",
                self.lane.source_order.len(),
                source_order.len(),
                self.admitted.source_order,
            ),
            (
                "iteration-order",
                self.lane.iteration_order.len(),
                iteration_order.len(),
                self.admitted.iteration_order,
            ),
        ] {
            preflight_collection_capacity(name, initialized, additional, admitted)?;
        }
        let reference = PackedAttrsRef(checked_index(self.lane.attrs.len(), "attrs-record")?);
        let (start, _) =
            checked_range(self.lane.attr_entries.len(), bindings.len(), "attrs-entry")?;
        checked_range(self.lane.positions.len(), position_count, "attr-position")?;
        self.ensure_capacity_unchanged()?;
        for binding in bindings {
            let position = match binding.position {
                Some(position) => {
                    let index = checked_index(self.lane.positions.len(), "attr-position")?;
                    if index == NO_POSITION {
                        return Err(PackedCollectionLaneError::ReservedPositionIndex);
                    }
                    self.lane.positions.push(position);
                    index
                }
                None => NO_POSITION,
            };
            self.lane.attr_entries.push(PackedAttrEntry {
                value: binding.value,
                symbol: binding.symbol.as_u32(),
                position,
            });
        }
        self.lane.source_order.extend_from_slice(source_order);
        self.lane.iteration_order.extend_from_slice(iteration_order);
        self.lane
            .attrs
            .push(PackedAttrsRecord::new(metadata, start, count));
        self.ensure_capacity_unchanged()?;
        Ok(reference)
    }

    /// Returns initialized bytes accumulated so far.
    ///
    /// # Errors
    ///
    /// Returns [`PackedCollectionLaneError`] if byte accounting overflows.
    pub(crate) fn initialized_bytes(
        &self,
    ) -> Result<PackedCollectionLaneBytes, PackedCollectionLaneError> {
        self.lane.initialized_bytes()
    }

    /// Returns allocator-granted capacity fixed at construction.
    ///
    /// # Errors
    ///
    /// Returns [`PackedCollectionLaneError`] if byte accounting overflows.
    pub(crate) fn capacity_bytes(
        &self,
    ) -> Result<PackedCollectionLaneBytes, PackedCollectionLaneError> {
        self.lane.capacity_bytes()
    }

    /// Finalizes the lane without requiring every admission slot to be filled.
    ///
    /// # Errors
    ///
    /// Returns [`PackedCollectionLaneError`] if any backing vector capacity
    /// changed after admission.
    pub(crate) fn finish(self) -> Result<PackedCollectionLane, PackedCollectionLaneError> {
        self.ensure_capacity_unchanged()?;
        Ok(self.lane)
    }

    fn ensure_capacity_unchanged(&self) -> Result<(), PackedCollectionLaneError> {
        let actual = self.lane.capacity_bytes()?;
        if actual != self.admitted_capacity_bytes {
            return Err(PackedCollectionLaneError::CapacityChanged {
                admitted: self.admitted_capacity_bytes.total()?,
                actual: actual.total()?,
            });
        }
        Ok(())
    }
}

fn reserve_collection_lane<T>(
    lane: &mut Vec<T>,
    count: usize,
    name: &'static str,
) -> Result<(), PackedCollectionLaneError> {
    lane.try_reserve_exact(count)
        .map_err(|_| PackedCollectionLaneError::AllocationFailed { lane: name })
}

fn preflight_collection_capacity(
    lane: &'static str,
    initialized: usize,
    additional: usize,
    admitted: usize,
) -> Result<(), PackedCollectionLaneError> {
    let attempted =
        initialized
            .checked_add(additional)
            .ok_or(PackedCollectionLaneError::RangeOverflow {
                lane,
                start: u32::MAX,
                count: u32::MAX,
            })?;
    if attempted > admitted {
        return Err(PackedCollectionLaneError::CapacityExceeded {
            lane,
            admitted,
            attempted,
        });
    }
    Ok(())
}

fn validate_collection_capacities(
    admitted: PackedCollectionLaneCapacities,
) -> Result<(), PackedCollectionLaneError> {
    for (lane, count) in [
        ("list-record", admitted.lists),
        ("attrs-record", admitted.attrs),
    ] {
        if count != 0 {
            checked_index(count.saturating_sub(1), lane)?;
        }
    }
    for (lane, count) in [
        ("list-value", admitted.list_values),
        ("attrs-entry", admitted.attr_entries),
        ("source-order", admitted.source_order),
        ("iteration-order", admitted.iteration_order),
    ] {
        checked_range(0, count, lane)?;
    }
    if admitted.positions > NO_POSITION as usize {
        return Err(PackedCollectionLaneError::ReservedPositionIndex);
    }
    Ok(())
}

/// A temporary source-identity deduplicating collection builder.
#[derive(Debug)]
pub(crate) struct PackedCollectionLaneBuilder<SourceId> {
    lane: PackedCollectionLane,
    lists: HashMap<SourceId, PackedListRef>,
    attrs: HashMap<SourceId, PackedAttrsRef>,
}

impl<SourceId> Default for PackedCollectionLaneBuilder<SourceId> {
    fn default() -> Self {
        Self {
            lane: PackedCollectionLane::default(),
            lists: HashMap::new(),
            attrs: HashMap::new(),
        }
    }
}

impl<SourceId> PackedCollectionLaneBuilder<SourceId>
where
    SourceId: Eq + Hash,
{
    /// Creates an empty temporary builder.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Interns one immutable packed list.
    ///
    /// # Errors
    ///
    /// Returns [`PackedCollectionLaneError`] for coordinate overflow or failed
    /// storage reservation.
    pub(crate) fn intern_list(
        &mut self,
        source: SourceId,
        values: &[PackedValueWord],
    ) -> Result<PackedListRef, PackedCollectionLaneError> {
        if let Some(reference) = self.lists.get(&source).copied() {
            return Ok(reference);
        }
        let reference = PackedListRef(checked_index(self.lane.lists.len(), "list-record")?);
        let (start, count) =
            checked_range(self.lane.list_values.len(), values.len(), "list-value")?;
        self.lists
            .try_reserve(1)
            .map_err(|_| PackedCollectionLaneError::AllocationFailed {
                lane: "list-source-dedup",
            })?;
        self.lane.lists.try_reserve_exact(1).map_err(|_| {
            PackedCollectionLaneError::AllocationFailed {
                lane: "list-record",
            }
        })?;
        self.lane
            .list_values
            .try_reserve_exact(values.len())
            .map_err(|_| PackedCollectionLaneError::AllocationFailed { lane: "list-value" })?;
        self.lane.list_values.extend_from_slice(values);
        self.lane.lists.push(PackedListRecord { start, count });
        self.lists.insert(source, reference);
        Ok(reference)
    }

    /// Interns one immutable packed attrset.
    ///
    /// `bindings` must be strictly sorted by symbol. Both order slices must be
    /// complete permutations over binding slots.
    ///
    /// # Errors
    ///
    /// Returns [`PackedCollectionLaneError`] for duplicates, malformed order,
    /// coordinate overflow, or failed storage reservation.
    pub(crate) fn intern_attrs(
        &mut self,
        source: SourceId,
        metadata: EvalHeapAttrsMetadata,
        bindings: &[PackedAttrBinding],
        source_order: &[u32],
        iteration_order: &[u32],
    ) -> Result<PackedAttrsRef, PackedCollectionLaneError> {
        if let Some(reference) = self.attrs.get(&source).copied() {
            return Ok(reference);
        }
        let (_, count) = checked_range(0, bindings.len(), "attrs-entry")?;
        if source_order.len() != bindings.len() {
            return Err(PackedCollectionLaneError::MalformedOrderLength {
                lane: "source-order",
                actual: source_order.len(),
                expected: count,
            });
        }
        if iteration_order.len() != bindings.len() {
            return Err(PackedCollectionLaneError::MalformedOrderLength {
                lane: "iteration-order",
                actual: iteration_order.len(),
                expected: count,
            });
        }
        validate_binding_symbol_order(bindings)?;
        validate_permutation(source_order, count, "source-order")?;
        validate_permutation(iteration_order, count, "iteration-order")?;
        if self.lane.attr_entries.len() != self.lane.source_order.len()
            || self.lane.attr_entries.len() != self.lane.iteration_order.len()
        {
            return Err(PackedCollectionLaneError::BuilderLaneDesynchronized);
        }
        let reference = PackedAttrsRef(checked_index(self.lane.attrs.len(), "attrs-record")?);
        let (start, _) =
            checked_range(self.lane.attr_entries.len(), bindings.len(), "attrs-entry")?;
        let position_count = bindings
            .iter()
            .filter(|binding| binding.position.is_some())
            .count();
        checked_range(self.lane.positions.len(), position_count, "attr-position")?;

        self.attrs
            .try_reserve(1)
            .map_err(|_| PackedCollectionLaneError::AllocationFailed {
                lane: "attrs-source-dedup",
            })?;
        self.lane.attrs.try_reserve_exact(1).map_err(|_| {
            PackedCollectionLaneError::AllocationFailed {
                lane: "attrs-record",
            }
        })?;
        self.lane
            .attr_entries
            .try_reserve_exact(bindings.len())
            .map_err(|_| PackedCollectionLaneError::AllocationFailed {
                lane: "attrs-entry",
            })?;
        self.lane
            .positions
            .try_reserve_exact(position_count)
            .map_err(|_| PackedCollectionLaneError::AllocationFailed {
                lane: "attr-position",
            })?;
        self.lane
            .source_order
            .try_reserve_exact(source_order.len())
            .map_err(|_| PackedCollectionLaneError::AllocationFailed {
                lane: "source-order",
            })?;
        self.lane
            .iteration_order
            .try_reserve_exact(iteration_order.len())
            .map_err(|_| PackedCollectionLaneError::AllocationFailed {
                lane: "iteration-order",
            })?;

        for binding in bindings {
            let position = match binding.position {
                Some(position) => {
                    let index = checked_index(self.lane.positions.len(), "attr-position")?;
                    if index == NO_POSITION {
                        return Err(PackedCollectionLaneError::ReservedPositionIndex);
                    }
                    self.lane.positions.push(position);
                    index
                }
                None => NO_POSITION,
            };
            self.lane.attr_entries.push(PackedAttrEntry {
                value: binding.value,
                symbol: binding.symbol.as_u32(),
                position,
            });
        }
        self.lane.source_order.extend_from_slice(source_order);
        self.lane.iteration_order.extend_from_slice(iteration_order);
        self.lane
            .attrs
            .push(PackedAttrsRecord::new(metadata, start, count));
        self.attrs.insert(source, reference);
        Ok(reference)
    }

    /// Drops temporary source maps and returns finalized contiguous lanes.
    pub(crate) fn finish(self) -> PackedCollectionLane {
        let Self { lane, lists, attrs } = self;
        drop(lists);
        drop(attrs);
        lane
    }
}

fn validate_binding_symbol_order(
    bindings: &[PackedAttrBinding],
) -> Result<(), PackedCollectionLaneError> {
    for pair in bindings.windows(2) {
        let previous = pair[0].symbol.as_u32();
        let next = pair[1].symbol.as_u32();
        if previous == next {
            return Err(PackedCollectionLaneError::DuplicateSymbol { symbol: previous });
        }
        if previous > next {
            return Err(PackedCollectionLaneError::SymbolsNotSorted { previous, next });
        }
    }
    Ok(())
}

/// A checked packed immutable collection failure.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub(crate) enum PackedCollectionLaneError {
    /// A direct lane index exceeds `u32`.
    #[error("packed {lane} index {index} does not fit in u32")]
    IndexOverflow {
        /// The affected lane.
        lane: &'static str,
        /// The rejected index.
        index: usize,
    },
    /// A direct lane count exceeds `u32`.
    #[error("packed {lane} count {count} does not fit in u32")]
    CountOverflow {
        /// The affected lane.
        lane: &'static str,
        /// The rejected count.
        count: usize,
    },
    /// A direct range exceeds `u32`.
    #[error("packed {lane} range start={start} count={count} overflows u32")]
    RangeOverflow {
        /// The affected lane.
        lane: &'static str,
        /// The range start.
        start: u32,
        /// The range count.
        count: u32,
    },
    /// Safe destination storage could not grow.
    #[error("packed collection destination could not reserve {lane} storage")]
    AllocationFailed {
        /// The affected lane.
        lane: &'static str,
    },
    /// An append exceeded a caller-admitted logical lane count.
    #[error("packed {lane} capacity {admitted} rejects length {attempted}")]
    CapacityExceeded {
        /// The affected lane.
        lane: &'static str,
        /// The exact admitted element count.
        admitted: usize,
        /// The length the rejected append would have produced.
        attempted: usize,
    },
    /// A pre-reserved lane grew after admission.
    #[error("packed collection capacity changed from {admitted} bytes to {actual} bytes")]
    CapacityChanged {
        /// Capacity measured immediately after pre-reservation.
        admitted: usize,
        /// Capacity observed after append or at finalization.
        actual: usize,
    },
    /// A byte count multiplication overflowed.
    #[error("packed {lane} byte accounting overflows for {elements} elements")]
    ByteAccountingOverflow {
        /// The affected lane.
        lane: &'static str,
        /// The element count.
        elements: usize,
    },
    /// The exact per-lane byte counts cannot be summed.
    #[error("packed collection total byte accounting overflows")]
    ByteAccountingTotalOverflow,
    /// A list coordinate is stale.
    #[error("packed list index {index} is not initialized")]
    UnknownList {
        /// The stale coordinate.
        index: u32,
    },
    /// An attrset coordinate is stale.
    #[error("packed attrs index {index} is not initialized")]
    UnknownAttrs {
        /// The stale coordinate.
        index: u32,
    },
    /// A stored range lies outside its lane.
    #[error("packed {lane} object {object} has malformed range start={start} count={count}")]
    MalformedRange {
        /// The affected lane.
        lane: &'static str,
        /// The owning record.
        object: u32,
        /// The stored range start.
        start: u32,
        /// The stored range count.
        count: u32,
    },
    /// A local object index is out of range.
    #[error("packed {object} local index {index} is out of range")]
    LocalIndexOutOfRange {
        /// The object or lane.
        object: &'static str,
        /// The rejected local index.
        index: u32,
    },
    /// Attr metadata contains reserved flags.
    #[error("packed attrs {attrs} has malformed flags 0x{flags:08x}")]
    MalformedAttrsFlags {
        /// The attrset record.
        attrs: u32,
        /// The rejected flags.
        flags: u32,
    },
    /// Attr entries contain the same symbol more than once.
    #[error("packed attrs contains duplicate symbol {symbol}")]
    DuplicateSymbol {
        /// The duplicate raw symbol.
        symbol: u32,
    },
    /// Attr entries are not strictly sorted by symbol.
    #[error("packed attrs symbols are not sorted: {previous} before {next}")]
    SymbolsNotSorted {
        /// The previous raw symbol.
        previous: u32,
        /// The following raw symbol.
        next: u32,
    },
    /// An order lane does not match the binding count.
    #[error("packed {lane} length {actual} does not match {expected}")]
    MalformedOrderLength {
        /// The affected order lane.
        lane: &'static str,
        /// The observed length.
        actual: usize,
        /// The required length.
        expected: u32,
    },
    /// An order lane index lies outside the binding array.
    #[error("packed {lane} index {index} lies outside count {count}")]
    MalformedOrderIndex {
        /// The affected order lane.
        lane: &'static str,
        /// The rejected slot.
        index: u32,
        /// The binding count.
        count: u32,
    },
    /// An order lane repeats one binding slot.
    #[error("packed {lane} repeats index {index}")]
    DuplicateOrderIndex {
        /// The affected order lane.
        lane: &'static str,
        /// The repeated slot.
        index: u32,
    },
    /// One binding's source-position coordinate is malformed.
    #[error("packed attrs {attrs} has malformed position index {position}")]
    MalformedPositionIndex {
        /// The owning attrset.
        attrs: u32,
        /// The rejected position coordinate.
        position: u32,
    },
    /// The position sentinel would collide with an allocated position.
    #[error("packed attr position index reserves u32::MAX for absence")]
    ReservedPositionIndex,
    /// Internal parallel attr lanes no longer share one coordinate space.
    #[error("packed attr builder lanes are desynchronized")]
    BuilderLaneDesynchronized,
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use super::*;
    use crate::heap::{ArenaDomainId, ArenaIndex};
    use crate::value::ValueTag;
    use crate::value::compressed::CompressedValueWord;

    fn packed(word: CompressedValueWord) -> PackedValueWord {
        PackedValueWord::new(word)
    }

    fn int(value: i32) -> PackedValueWord {
        packed(CompressedValueWord::inline_int(i64::from(value)).unwrap())
    }

    fn all_value_kinds() -> Vec<PackedValueWord> {
        let domain = ArenaDomainId::from_raw((1 << 23) - 1).unwrap();
        let mut values = vec![
            int(i32::MIN),
            packed(CompressedValueWord::boxed_int(
                domain,
                ArenaIndex::new(u32::MAX - 1),
            )),
            packed(CompressedValueWord::boxed_float(
                domain,
                ArenaIndex::new(u32::MAX),
            )),
            packed(CompressedValueWord::boolean(false)),
            packed(CompressedValueWord::boolean(true)),
            packed(CompressedValueWord::null()),
        ];
        for (index, tag) in [
            ValueTag::String,
            ValueTag::Path,
            ValueTag::List,
            ValueTag::Attrs,
            ValueTag::Lambda,
            ValueTag::Primop,
            ValueTag::External,
            ValueTag::Thunk,
        ]
        .into_iter()
        .enumerate()
        {
            values.push(packed(
                CompressedValueWord::heap(domain, tag, ArenaIndex::new(index as u32)).unwrap(),
            ));
        }
        values.push(packed(
            CompressedValueWord::heap(domain, ValueTag::Thunk, ArenaIndex::new(u32::MAX))
                .unwrap()
                .with_forced_bit()
                .unwrap(),
        ));
        values
    }

    #[test]
    fn exact_layouts_and_byte_accounting_match_contract() {
        assert_eq!(mem::size_of::<PackedListRef>(), 4);
        assert_eq!(mem::size_of::<PackedAttrsRef>(), 4);
        assert_eq!(mem::size_of::<PackedListRecord>(), 8);
        assert_eq!(mem::size_of::<PackedAttrsRecord>(), 20);
        assert_eq!(mem::size_of::<PackedAttrEntry>(), 16);
        assert_eq!(mem::align_of::<PackedAttrEntry>(), 8);
        assert_eq!(mem::size_of::<PackedAttrPosition>(), 12);
        assert_eq!(mem::size_of::<PackedCollectionLane>(), 168);
        assert_eq!(PackedListRef::from_index(9).index(), 9);
        assert_eq!(PackedAttrsRef::from_index(11).index(), 11);

        let mut builder = PackedCollectionLaneBuilder::new();
        let _empty = builder.intern_list(1_u8, &[]).unwrap();
        let _list = builder.intern_list(2_u8, &[int(1), int(2)]).unwrap();
        let bindings = [
            PackedAttrBinding::new(Symbol::new(1), int(3)),
            PackedAttrBinding::with_position(Symbol::new(2), int(4), 7, Span::new(8, 9)),
        ];
        let _attrs = builder
            .intern_attrs(
                3_u8,
                EvalHeapAttrsMetadata::new(5, AttrSetReprKind::Flat),
                &bindings,
                &[1, 0],
                &[0, 1],
            )
            .unwrap();
        let lane = builder.finish();
        let initialized = lane.initialized_bytes().unwrap();
        assert_eq!(
            initialized,
            PackedCollectionLaneBytes {
                control: 168,
                list_records: 16,
                list_values: 16,
                attrs_records: 20,
                attrs_entries: 32,
                positions: 12,
                source_order: 8,
                iteration_order: 8,
            }
        );
        assert_eq!(initialized.total(), Ok(280));
        let capacity = lane.capacity_bytes().unwrap();
        assert!(capacity.total().unwrap() >= initialized.total().unwrap());
        assert!(capacity.list_records >= initialized.list_records);
        assert!(capacity.attrs_entries >= initialized.attrs_entries);
    }

    #[test]
    fn direct_builder_exact_fill_and_underfill_preserve_capacity() {
        let admitted = PackedCollectionLaneCapacities {
            lists: 2,
            list_values: 2,
            attrs: 1,
            attr_entries: 2,
            positions: 1,
            source_order: 2,
            iteration_order: 2,
        };
        let mut underfilled = PackedCollectionLaneDirectBuilder::try_new(admitted).unwrap();
        let capacity = underfilled.capacity_bytes().unwrap();
        let list = underfilled.append_list(&[int(1)]).unwrap();
        assert_eq!(list.index(), 0);
        assert_eq!(underfilled.capacity_bytes().unwrap(), capacity);
        let lane = underfilled.finish().unwrap();
        assert_eq!(lane.list(list), Ok([int(1)].as_slice()));
        assert_eq!(lane.capacity_bytes().unwrap(), capacity);

        let mut exact = PackedCollectionLaneDirectBuilder::try_new(admitted).unwrap();
        let exact_capacity = exact.capacity_bytes().unwrap();
        exact.append_list(&[]).unwrap();
        exact.append_list(&[int(1), int(2)]).unwrap();
        let bindings = [
            PackedAttrBinding::new(Symbol::new(1), int(3)),
            PackedAttrBinding::with_position(Symbol::new(2), int(4), 5, Span::new(6, 7)),
        ];
        let attrs = exact
            .append_attrs(
                EvalHeapAttrsMetadata::new(8, AttrSetReprKind::Flat),
                &bindings,
                &[1, 0],
                &[0, 1],
            )
            .unwrap();
        let initialized = exact.initialized_bytes().unwrap();
        let lane = exact.finish().unwrap();
        assert_eq!(lane.capacity_bytes().unwrap(), exact_capacity);
        assert_eq!(lane.initialized_bytes().unwrap(), initialized);
        assert_eq!(lane.attrs_get(attrs, Symbol::new(2)), Ok(Some(int(4))));
    }

    #[test]
    fn direct_builder_rejects_overfill_before_growth() {
        let admitted = PackedCollectionLaneCapacities {
            lists: 1,
            list_values: 1,
            attrs: 1,
            attr_entries: 1,
            positions: 0,
            source_order: 1,
            iteration_order: 1,
        };
        let mut builder = PackedCollectionLaneDirectBuilder::try_new(admitted).unwrap();
        let capacity = builder.capacity_bytes().unwrap();
        builder.append_list(&[int(1)]).unwrap();
        let initialized = builder.initialized_bytes().unwrap();
        assert_eq!(
            builder.append_list(&[]),
            Err(PackedCollectionLaneError::CapacityExceeded {
                lane: "list-record",
                admitted: 1,
                attempted: 2,
            })
        );
        assert_eq!(builder.initialized_bytes().unwrap(), initialized);
        assert_eq!(builder.capacity_bytes().unwrap(), capacity);

        let positioned = [PackedAttrBinding::with_position(
            Symbol::new(1),
            int(2),
            3,
            Span::new(4, 5),
        )];
        assert_eq!(
            builder.append_attrs(
                EvalHeapAttrsMetadata::new(6, AttrSetReprKind::Flat),
                &positioned,
                &[0],
                &[0],
            ),
            Err(PackedCollectionLaneError::CapacityExceeded {
                lane: "attr-position",
                admitted: 0,
                attempted: 1,
            })
        );
        assert_eq!(builder.initialized_bytes().unwrap(), initialized);
        assert_eq!(builder.capacity_bytes().unwrap(), capacity);
    }

    #[test]
    fn empty_and_multi_value_lists_round_trip_every_candidate_c_kind() {
        let values = all_value_kinds();
        let mut builder = PackedCollectionLaneBuilder::new();
        let empty = builder.intern_list(1_u8, &[]).unwrap();
        let full = builder.intern_list(2_u8, &values).unwrap();
        let duplicate = builder.intern_list(2_u8, &[int(99)]).unwrap();
        let lane = builder.finish();
        assert_eq!(duplicate, full);
        assert_eq!(lane.list(empty), Ok([].as_slice()));
        assert_eq!(lane.list(full), Ok(values.as_slice()));
        for (index, value) in values.into_iter().enumerate() {
            assert_eq!(lane.list_get(full, index as u32), Ok(value));
        }
        assert_eq!(
            lane.list_get(full, u32::MAX),
            Err(PackedCollectionLaneError::LocalIndexOutOfRange {
                object: "list",
                index: u32::MAX
            })
        );
    }

    #[test]
    fn attrs_preserve_metadata_lookup_positions_and_both_orders() {
        let metadata = EvalHeapAttrsMetadata::with_projected_shape(
            u32::MAX,
            AttrSetReprKind::Hamt,
            ShapeId::new(u32::MAX),
        );
        let bindings = [
            PackedAttrBinding::new(Symbol::new(2), int(20)),
            PackedAttrBinding::with_position(
                Symbol::new(5),
                packed(CompressedValueWord::boolean(true)),
                u32::MAX,
                Span::new(10, 20),
            ),
            PackedAttrBinding::new(Symbol::new(9), packed(CompressedValueWord::null())),
        ];
        let mut builder = PackedCollectionLaneBuilder::new();
        let attrs = builder
            .intern_attrs(1_u8, metadata, &bindings, &[2, 0, 1], &[1, 2, 0])
            .unwrap();
        let duplicate = builder
            .intern_attrs(
                1_u8,
                EvalHeapAttrsMetadata::new(0, AttrSetReprKind::Flat),
                &[],
                &[],
                &[],
            )
            .unwrap();
        let lane = builder.finish();
        assert_eq!(duplicate, attrs);
        assert_eq!(lane.validate_attrs(attrs), Ok(()));
        assert_eq!(lane.attrs_metadata(attrs), Ok(metadata));
        assert_eq!(lane.attrs_get(attrs, Symbol::new(2)), Ok(Some(int(20))));
        assert_eq!(lane.attrs_get(attrs, Symbol::new(7)), Ok(None));
        assert_eq!(
            lane.attrs_source_entry(attrs, 0)
                .map(|entry| entry.symbol()),
            Ok(Symbol::new(9))
        );
        assert_eq!(
            lane.attrs_source_entry(attrs, 2)
                .map(|entry| entry.symbol()),
            Ok(Symbol::new(5))
        );
        assert_eq!(
            lane.attrs_iteration_entry(attrs, 0)
                .map(|entry| entry.symbol()),
            Ok(Symbol::new(5))
        );
        assert_eq!(
            lane.attrs_iteration_entry(attrs, 2)
                .map(|entry| entry.symbol()),
            Ok(Symbol::new(2))
        );
        assert_eq!(lane.attrs_position(attrs, 0), Ok(None));
        let position = lane.attrs_position(attrs, 1).unwrap().unwrap();
        assert_eq!(position.module(), u32::MAX);
        assert_eq!(position.span(), Span::new(10, 20));
    }

    #[test]
    fn attrs_builder_rejects_duplicate_unsorted_and_malformed_orders() {
        let metadata = EvalHeapAttrsMetadata::new(0, AttrSetReprKind::Flat);
        let duplicate = [
            PackedAttrBinding::new(Symbol::new(1), int(1)),
            PackedAttrBinding::new(Symbol::new(1), int(2)),
        ];
        let mut builder = PackedCollectionLaneBuilder::new();
        assert_eq!(
            builder.intern_attrs(1_u8, metadata, &duplicate, &[0, 1], &[0, 1]),
            Err(PackedCollectionLaneError::DuplicateSymbol { symbol: 1 })
        );
        let unsorted = [
            PackedAttrBinding::new(Symbol::new(2), int(1)),
            PackedAttrBinding::new(Symbol::new(1), int(2)),
        ];
        assert_eq!(
            builder.intern_attrs(2_u8, metadata, &unsorted, &[0, 1], &[0, 1]),
            Err(PackedCollectionLaneError::SymbolsNotSorted {
                previous: 2,
                next: 1
            })
        );
        let valid = [
            PackedAttrBinding::new(Symbol::new(1), int(1)),
            PackedAttrBinding::new(Symbol::new(2), int(2)),
        ];
        assert_eq!(
            builder.intern_attrs(3_u8, metadata, &valid, &[0, 0], &[0, 1]),
            Err(PackedCollectionLaneError::DuplicateOrderIndex {
                lane: "source-order",
                index: 0
            })
        );
        assert_eq!(
            builder.intern_attrs(4_u8, metadata, &valid, &[0, 2], &[0, 1]),
            Err(PackedCollectionLaneError::MalformedOrderIndex {
                lane: "source-order",
                index: 2,
                count: 2
            })
        );
    }

    #[test]
    fn finalized_malformed_ranges_flags_indices_and_symbols_fail_closed() {
        let metadata = EvalHeapAttrsMetadata::new(0, AttrSetReprKind::Flat);
        let bindings = [
            PackedAttrBinding::with_position(Symbol::new(1), int(1), 2, Span::new(3, 4)),
            PackedAttrBinding::new(Symbol::new(2), int(2)),
        ];
        let mut builder = PackedCollectionLaneBuilder::new();
        let list = builder.intern_list(1_u8, &[int(1)]).unwrap();
        let attrs = builder
            .intern_attrs(2_u8, metadata, &bindings, &[0, 1], &[1, 0])
            .unwrap();
        let mut lane = builder.finish();

        lane.lists[list.0 as usize].start = u32::MAX;
        assert!(matches!(
            lane.list(list),
            Err(PackedCollectionLaneError::MalformedRange {
                lane: "list-value",
                ..
            })
        ));
        lane.attrs[attrs.0 as usize].flags = 1 << 31;
        assert!(matches!(
            lane.attrs_metadata(attrs),
            Err(PackedCollectionLaneError::MalformedAttrsFlags { .. })
        ));
        lane.attrs[attrs.0 as usize].flags = 0;
        lane.attr_entries[0].position = u32::MAX - 1;
        assert!(matches!(
            lane.attrs_position(attrs, 0),
            Err(PackedCollectionLaneError::MalformedPositionIndex { .. })
        ));
        lane.attr_entries[0].position = NO_POSITION;
        lane.source_order[1] = 0;
        assert_eq!(
            lane.validate_attrs(attrs),
            Err(PackedCollectionLaneError::DuplicateOrderIndex {
                lane: "source-order",
                index: 0
            })
        );
        lane.source_order[1] = 1;
        lane.attr_entries[1].symbol = 1;
        assert_eq!(
            lane.validate_attrs(attrs),
            Err(PackedCollectionLaneError::DuplicateSymbol { symbol: 1 })
        );
    }

    #[test]
    fn checked_coordinates_reject_range_and_byte_overflow() {
        assert_eq!(
            checked_range((u32::MAX - 1) as usize, 2, "test"),
            Err(PackedCollectionLaneError::RangeOverflow {
                lane: "test",
                start: u32::MAX - 1,
                count: 2
            })
        );
        assert_eq!(
            checked_bytes::<u64>(usize::MAX, "test"),
            Err(PackedCollectionLaneError::ByteAccountingOverflow {
                lane: "test",
                elements: usize::MAX
            })
        );
    }

    #[derive(Debug)]
    struct DroppingSource {
        id: u32,
        drops: Arc<AtomicUsize>,
    }

    impl PartialEq for DroppingSource {
        fn eq(&self, other: &Self) -> bool {
            self.id == other.id
        }
    }

    impl Eq for DroppingSource {}

    impl Hash for DroppingSource {
        fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
            self.id.hash(state);
        }
    }

    impl Drop for DroppingSource {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn finalization_drops_both_temporary_source_maps() {
        let drops = Arc::new(AtomicUsize::new(0));
        let mut builder = PackedCollectionLaneBuilder::new();
        builder
            .intern_list(
                DroppingSource {
                    id: 1,
                    drops: Arc::clone(&drops),
                },
                &[int(1)],
            )
            .unwrap();
        builder
            .intern_attrs(
                DroppingSource {
                    id: 2,
                    drops: Arc::clone(&drops),
                },
                EvalHeapAttrsMetadata::new(0, AttrSetReprKind::Flat),
                &[],
                &[],
                &[],
            )
            .unwrap();
        assert_eq!(drops.load(Ordering::Relaxed), 0);
        let lane = builder.finish();
        assert_eq!(drops.load(Ordering::Relaxed), 2);
        assert_eq!(lane.list(PackedListRef(0)), Ok([int(1)].as_slice()));
    }
}
