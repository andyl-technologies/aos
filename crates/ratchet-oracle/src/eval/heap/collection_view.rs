//! Allocation-free read views over ordinary and packed immutable collections.
//!
//! These views are the representation boundary between the active flat heap
//! and a future packed generation. They borrow either backing store and return
//! evaluator values and attribute entries by value, so packed storage never
//! needs to materialize a [`NixList`] or [`FlatAttrs`] compatibility object.

use std::iter::FusedIterator;

#[cfg(any(
    feature = "compact_destination_probe",
    feature = "evacuation_plan_probe"
))]
use crate::attrs::AttrPosition;
use crate::attrs::order::{AttrOrderError, AttrOrderRepr};
use crate::attrs::{AttrEntry, AttrError, FlatAttrs};
use crate::list::{NixList, NixListError};
use crate::syntax::{Symbol, SymbolTable};
use crate::value::Value;

#[cfg(any(
    feature = "compact_destination_probe",
    feature = "evacuation_plan_probe"
))]
use super::packed_collection_lane::{
    PackedAttrsRef, PackedAttrsViewParts, PackedCollectionLane, PackedCollectionLaneError,
    PackedListRef,
};
#[cfg(any(
    feature = "compact_destination_probe",
    feature = "evacuation_plan_probe"
))]
use super::packed_thunk_lane::PackedValueWord;

/// A borrowed list spine backed by the flat heap or a packed generation.
#[derive(Clone, Copy, Debug)]
pub(crate) enum EvalListView<'a> {
    /// An ordinary flat-heap list.
    Flat(&'a NixList),
    /// A packed list's exact Candidate-C value run.
    #[cfg(any(
        feature = "compact_destination_probe",
        feature = "evacuation_plan_probe"
    ))]
    Packed(&'a [PackedValueWord]),
}

impl<'a> From<&'a NixList> for EvalListView<'a> {
    fn from(list: &'a NixList) -> Self {
        Self::flat(list)
    }
}

impl<'a> EvalListView<'a> {
    /// Borrows an ordinary flat list.
    pub(crate) const fn flat(list: &'a NixList) -> Self {
        Self::Flat(list)
    }

    /// Resolves and borrows one packed list.
    ///
    /// # Errors
    ///
    /// Returns [`PackedCollectionLaneError`] when `reference` is stale or its
    /// stored value range is malformed.
    #[cfg(any(
        feature = "compact_destination_probe",
        feature = "evacuation_plan_probe"
    ))]
    pub(crate) fn packed(
        lane: &'a PackedCollectionLane,
        reference: PackedListRef,
    ) -> Result<Self, PackedCollectionLaneError> {
        lane.list(reference).map(Self::Packed)
    }

    /// Returns the number of list elements.
    pub(crate) fn len(self) -> usize {
        match self {
            Self::Flat(list) => list.len(),
            #[cfg(any(
                feature = "compact_destination_probe",
                feature = "evacuation_plan_probe"
            ))]
            Self::Packed(values) => values.len(),
        }
    }

    /// Returns whether the list is empty.
    pub(crate) fn is_empty(self) -> bool {
        self.len() == 0
    }

    /// Returns one element without materializing its backing list.
    pub(crate) fn get(self, index: usize) -> Option<Value> {
        match self {
            Self::Flat(list) => list.get(index),
            #[cfg(any(
                feature = "compact_destination_probe",
                feature = "evacuation_plan_probe"
            ))]
            Self::Packed(values) => values.get(index).copied().map(packed_value),
        }
    }

    /// Iterates over copied evaluator values in source order.
    pub(crate) fn iter(self) -> EvalListViewIter<'a> {
        let inner = match self {
            Self::Flat(list) => EvalListViewIterInner::Flat(list.iter()),
            #[cfg(any(
                feature = "compact_destination_probe",
                feature = "evacuation_plan_probe"
            ))]
            Self::Packed(values) => EvalListViewIterInner::Packed(values.iter()),
        };
        EvalListViewIter { inner }
    }

    /// Concatenates two borrowed spines into one owned flat list.
    ///
    /// # Errors
    ///
    /// Returns [`NixListError`] when the combined length overflows or exact
    /// result storage cannot be reserved.
    pub(crate) fn concat(self, other: Self) -> Result<NixList, NixListError> {
        let len = self
            .len()
            .checked_add(other.len())
            .ok_or(NixListError::LengthOverflow {
                left: self.len(),
                right: other.len(),
            })?;
        let mut elements = Vec::new();
        elements
            .try_reserve_exact(len)
            .map_err(|_| NixListError::AllocationFailed { len })?;
        elements.extend(self.iter());
        elements.extend(other.iter());
        Ok(NixList::new(elements))
    }
}

/// A copied-value iterator over an [`EvalListView`].
#[derive(Clone, Debug)]
pub(crate) struct EvalListViewIter<'a> {
    inner: EvalListViewIterInner<'a>,
}

#[derive(Clone, Debug)]
enum EvalListViewIterInner<'a> {
    Flat(std::slice::Iter<'a, Value>),
    #[cfg(any(
        feature = "compact_destination_probe",
        feature = "evacuation_plan_probe"
    ))]
    Packed(std::slice::Iter<'a, PackedValueWord>),
}

impl Iterator for EvalListViewIter<'_> {
    type Item = Value;

    fn next(&mut self) -> Option<Self::Item> {
        match &mut self.inner {
            EvalListViewIterInner::Flat(values) => values.next().copied(),
            #[cfg(any(
                feature = "compact_destination_probe",
                feature = "evacuation_plan_probe"
            ))]
            EvalListViewIterInner::Packed(values) => values.next().copied().map(packed_value),
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = match &self.inner {
            EvalListViewIterInner::Flat(values) => values.len(),
            #[cfg(any(
                feature = "compact_destination_probe",
                feature = "evacuation_plan_probe"
            ))]
            EvalListViewIterInner::Packed(values) => values.len(),
        };
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for EvalListViewIter<'_> {}
impl FusedIterator for EvalListViewIter<'_> {}

/// A borrowed attrset backed by the flat heap or a packed generation.
#[derive(Clone, Copy, Debug)]
pub(crate) enum EvalAttrsView<'a> {
    /// An ordinary flat-heap attrset.
    Flat(&'a FlatAttrs),
    /// Checked slices from one finalized packed attrset.
    #[cfg(any(
        feature = "compact_destination_probe",
        feature = "evacuation_plan_probe"
    ))]
    Packed(PackedAttrsViewParts<'a>),
}

impl<'a> From<&'a FlatAttrs> for EvalAttrsView<'a> {
    fn from(attrs: &'a FlatAttrs) -> Self {
        Self::flat(attrs)
    }
}

impl<'a> EvalAttrsView<'a> {
    /// Borrows an ordinary flat attrset.
    pub(crate) const fn flat(attrs: &'a FlatAttrs) -> Self {
        Self::Flat(attrs)
    }

    /// Resolves and borrows one packed attrset.
    ///
    /// # Errors
    ///
    /// Returns [`PackedCollectionLaneError`] when `reference` is stale or any
    /// range, sparse position, or order coordinate followed by the view is
    /// malformed.
    #[cfg(any(
        feature = "compact_destination_probe",
        feature = "evacuation_plan_probe"
    ))]
    pub(crate) fn packed(
        lane: &'a PackedCollectionLane,
        reference: PackedAttrsRef,
    ) -> Result<Self, PackedCollectionLaneError> {
        lane.attrs_view_parts(reference).map(Self::Packed)
    }

    /// Returns the number of bindings.
    pub(crate) fn len(self) -> usize {
        match self {
            Self::Flat(attrs) => attrs.len(),
            #[cfg(any(
                feature = "compact_destination_probe",
                feature = "evacuation_plan_probe"
            ))]
            Self::Packed(parts) => parts.entries().len(),
        }
    }

    /// Returns whether the attrset is empty.
    pub(crate) fn is_empty(self) -> bool {
        self.len() == 0
    }

    /// Returns the value bound to `key`.
    pub(crate) fn get(self, key: Symbol) -> Option<Value> {
        self.symbol_slot(key)
            .and_then(|slot| self.entry_by_symbol(slot as usize))
            .map(|entry| entry.value)
    }

    /// Returns one copied binding for `key`.
    pub(crate) fn get_entry(self, key: Symbol) -> Option<AttrEntry> {
        self.symbol_slot(key)
            .and_then(|slot| self.entry_by_symbol(slot as usize))
    }

    /// Returns whether `key` is present.
    pub(crate) fn contains_key(self, key: Symbol) -> bool {
        self.symbol_slot(key).is_some()
    }

    /// Returns the symbol-order slot holding `key`.
    pub(crate) fn symbol_slot(self, key: Symbol) -> Option<u32> {
        let slot = match self {
            Self::Flat(attrs) => attrs
                .entries_by_symbol()
                .binary_search_by_key(&key, |entry| entry.key)
                .ok(),
            #[cfg(any(
                feature = "compact_destination_probe",
                feature = "evacuation_plan_probe"
            ))]
            Self::Packed(parts) => parts
                .entries()
                .binary_search_by_key(&key, |entry| entry.symbol())
                .ok(),
        }?;
        u32::try_from(slot).ok()
    }

    /// Returns one copied binding by its symbol-order slot.
    pub(crate) fn entry_by_symbol(self, slot: usize) -> Option<AttrEntry> {
        match self {
            Self::Flat(attrs) => attrs.entries_by_symbol().get(slot).copied(),
            #[cfg(any(
                feature = "compact_destination_probe",
                feature = "evacuation_plan_probe"
            ))]
            Self::Packed(parts) => {
                let entry = parts.entries().get(slot).copied()?;
                let position = entry
                    .position_index()
                    .and_then(|index| parts.positions().get(index as usize))
                    .copied()
                    .map(|position| AttrPosition::new(position.module(), position.span()));
                Some(AttrEntry {
                    key: entry.symbol(),
                    value: packed_value(entry.value()),
                    position,
                })
            }
        }
    }

    /// Iterates over copied bindings in symbol-id order.
    pub(crate) fn iter_by_symbol(self) -> EvalAttrsViewIter<'a> {
        EvalAttrsViewIter::new(self, EvalAttrsViewOrder::Symbol)
    }

    /// Iterates over copied bindings in construction order.
    pub(crate) fn iter_source_order(self) -> EvalAttrsViewIter<'a> {
        EvalAttrsViewIter::new(self, EvalAttrsViewOrder::Source)
    }

    /// Iterates over copied bindings in observable lexicographic order.
    pub(crate) fn iter_lexicographic(self) -> EvalAttrsViewIter<'a> {
        EvalAttrsViewIter::new(self, EvalAttrsViewOrder::Iteration)
    }

    /// Returns whether construction order already equals lexicographic order.
    pub(crate) fn source_order_is_lexicographic(self) -> bool {
        self.iter_source_order()
            .map(|entry| entry.key)
            .eq(self.iter_lexicographic().map(|entry| entry.key))
    }

    /// Validates that observable iteration is raw-byte lexicographic.
    ///
    /// # Errors
    ///
    /// Returns [`AttrOrderError`] for an unknown symbol or an out-of-order
    /// adjacent key pair.
    pub(crate) fn validate_lexicographic(
        self,
        symbols: &SymbolTable,
    ) -> Result<(), AttrOrderError> {
        let repr = AttrOrderRepr::Flat;
        let mut previous: Option<(Symbol, &[u8])> = None;
        for entry in self.iter_lexicographic() {
            let name = symbols
                .resolve(entry.key)
                .ok_or(AttrOrderError::UnknownSymbol {
                    repr,
                    key: entry.key,
                })?;
            if let Some((previous_key, previous_name)) = previous
                && previous_name > name
            {
                return Err(AttrOrderError::OutOfOrder {
                    repr,
                    left_key: previous_key,
                    right_key: entry.key,
                    left_name: previous_name.to_vec().into_boxed_slice(),
                    right_name: name.to_vec().into_boxed_slice(),
                });
            }
            previous = Some((entry.key, name));
        }
        Ok(())
    }

    /// Copies this view into an owned flat attrset at an explicit result boundary.
    ///
    /// # Errors
    ///
    /// Returns [`AttrError`] when exact entry storage cannot be reserved or
    /// reconstruction rejects malformed symbols or duplicate keys.
    pub(crate) fn try_to_owned(self, symbols: &SymbolTable) -> Result<FlatAttrs, AttrError> {
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(self.len())
            .map_err(|_| AttrError::AllocationFailed {
                entries: self.len(),
            })?;
        entries.extend(self.iter_source_order());
        FlatAttrs::new(entries, symbols)
    }

    fn ordered_slot(self, order: EvalAttrsViewOrder, index: usize) -> Option<usize> {
        match (self, order) {
            (_, EvalAttrsViewOrder::Symbol) => (index < self.len()).then_some(index),
            (Self::Flat(attrs), EvalAttrsViewOrder::Source) => {
                attrs.source_order().get(index).map(|slot| *slot as usize)
            }
            (Self::Flat(attrs), EvalAttrsViewOrder::Iteration) => attrs
                .iteration_order()
                .get(index)
                .map(|slot| *slot as usize),
            #[cfg(any(
                feature = "compact_destination_probe",
                feature = "evacuation_plan_probe"
            ))]
            (Self::Packed(parts), EvalAttrsViewOrder::Source) => {
                parts.source_order().get(index).map(|slot| *slot as usize)
            }
            #[cfg(any(
                feature = "compact_destination_probe",
                feature = "evacuation_plan_probe"
            ))]
            (Self::Packed(parts), EvalAttrsViewOrder::Iteration) => parts
                .iteration_order()
                .get(index)
                .map(|slot| *slot as usize),
        }
    }
}

/// A copied-entry iterator over an [`EvalAttrsView`].
#[derive(Clone, Debug)]
pub(crate) struct EvalAttrsViewIter<'a> {
    view: EvalAttrsView<'a>,
    order: EvalAttrsViewOrder,
    next: usize,
}

impl<'a> EvalAttrsViewIter<'a> {
    fn new(view: EvalAttrsView<'a>, order: EvalAttrsViewOrder) -> Self {
        Self {
            view,
            order,
            next: 0,
        }
    }
}

impl Iterator for EvalAttrsViewIter<'_> {
    type Item = AttrEntry;

    fn next(&mut self) -> Option<Self::Item> {
        let slot = self.view.ordered_slot(self.order, self.next)?;
        self.next += 1;
        self.view.entry_by_symbol(slot)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.view.len().saturating_sub(self.next);
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for EvalAttrsViewIter<'_> {}
impl FusedIterator for EvalAttrsViewIter<'_> {}

#[derive(Clone, Copy, Debug)]
enum EvalAttrsViewOrder {
    Symbol,
    Source,
    Iteration,
}

#[cfg(any(
    feature = "compact_destination_probe",
    feature = "evacuation_plan_probe"
))]
#[inline]
const fn packed_value(value: PackedValueWord) -> Value {
    Value::from_word(value.compressed())
}

#[cfg(all(
    test,
    any(
        feature = "compact_destination_probe",
        feature = "evacuation_plan_probe"
    )
))]
mod tests {
    use super::*;
    use crate::attrs::{AttrPosition, repr::AttrSetReprKind};
    use crate::eval::heap::EvalHeapAttrsMetadata;
    use crate::syntax::{Span, SymbolTable};

    use super::super::packed_collection_lane::{PackedAttrBinding, PackedCollectionLaneBuilder};

    fn packed(value: Value) -> PackedValueWord {
        PackedValueWord::new(value.word())
    }

    fn raw_values(values: impl IntoIterator<Item = Value>) -> Vec<u64> {
        values.into_iter().map(|value| value.word().raw()).collect()
    }

    fn entry_snapshot(
        entries: impl IntoIterator<Item = AttrEntry>,
    ) -> Vec<(u32, u64, Option<AttrPosition>)> {
        entries
            .into_iter()
            .map(|entry| (entry.key.as_u32(), entry.value.word().raw(), entry.position))
            .collect()
    }

    #[test]
    fn flat_and_packed_list_views_have_identical_lookup_and_iteration() {
        let list = NixList::new(vec![Value::int(-7), Value::bool(true), Value::null()]);
        let packed_values = list.iter().copied().map(packed).collect::<Vec<_>>();
        let mut builder = PackedCollectionLaneBuilder::new();
        let reference = builder
            .intern_list(1_u32, &packed_values)
            .expect("packed list builds");
        let lane = builder.finish();
        let flat = EvalListView::flat(&list);
        let packed = EvalListView::packed(&lane, reference).expect("packed list resolves");

        assert_eq!(flat.len(), packed.len());
        assert!(!flat.is_empty());
        for index in 0..=list.len() {
            assert_eq!(
                flat.get(index).map(|value| value.word().raw()),
                packed.get(index).map(|value| value.word().raw())
            );
        }
        assert_eq!(raw_values(flat.iter()), raw_values(packed.iter()));
    }

    #[test]
    fn flat_and_packed_attrs_views_preserve_lookup_and_all_orders() {
        let mut symbols = SymbolTable::new();
        let a = symbols.intern(b"a").expect("a interns");
        let m = symbols.intern(b"m").expect("m interns");
        let z = symbols.intern(b"z").expect("z interns");
        let attrs = FlatAttrs::new(
            vec![
                AttrEntry::with_position(m, Value::int(20), AttrPosition::new(7, Span::new(8, 13))),
                AttrEntry::new(z, Value::bool(true)),
                AttrEntry::new(a, Value::null()),
            ],
            &symbols,
        )
        .expect("flat attrs build");
        let bindings = attrs
            .entries_by_symbol()
            .iter()
            .map(|entry| match entry.position {
                Some(position) => PackedAttrBinding::with_position(
                    entry.key,
                    packed(entry.value),
                    position.module,
                    position.span,
                ),
                None => PackedAttrBinding::new(entry.key, packed(entry.value)),
            })
            .collect::<Vec<_>>();
        let mut builder = PackedCollectionLaneBuilder::new();
        let reference = builder
            .intern_attrs(
                1_u32,
                EvalHeapAttrsMetadata::new(41, AttrSetReprKind::Flat),
                &bindings,
                attrs.source_order(),
                attrs.iteration_order(),
            )
            .expect("packed attrs build");
        let lane = builder.finish();
        let flat = EvalAttrsView::flat(&attrs);
        let packed = EvalAttrsView::packed(&lane, reference).expect("packed attrs resolve");

        assert_eq!(flat.len(), packed.len());
        assert!(!packed.is_empty());
        for key in [a, m, z, Symbol::new(999)] {
            assert_eq!(flat.contains_key(key), packed.contains_key(key));
            assert_eq!(flat.symbol_slot(key), packed.symbol_slot(key));
            assert_eq!(
                flat.get(key).map(|value| value.word().raw()),
                packed.get(key).map(|value| value.word().raw())
            );
        }
        assert_eq!(
            entry_snapshot(flat.iter_by_symbol()),
            entry_snapshot(packed.iter_by_symbol())
        );
        assert_eq!(
            entry_snapshot(flat.iter_source_order()),
            entry_snapshot(packed.iter_source_order())
        );
        assert_eq!(
            entry_snapshot(flat.iter_lexicographic()),
            entry_snapshot(packed.iter_lexicographic())
        );
    }
}
