//! Linear right-biased merge (Nix `//`) over flat attribute sets.
//!
//! [`FlatAttrs::update_right_biased`] is the evaluator's `//` fast path: both
//! operands already store entries sorted by symbol id alongside their
//! source-order and lexicographic permutations, so the merge walks the two
//! sorted arrays once and remaps the existing permutations instead of
//! re-sorting the combined entry set the way [`FlatAttrs::new`] must for
//! unsorted input. The result is representation-identical to the unsorted
//! construction path, which the tests in this module enforce against a
//! reference implementation.

use super::{AttrError, FlatAttrs};
use crate::syntax::SymbolTable;

impl FlatAttrs {
    /// Merges `right` over `self` with Nix `//` semantics in one linear pass.
    ///
    /// The result is representation-identical (see [`FlatAttrs::raw_eq`]) to
    /// calling [`FlatAttrs::new`] on the concatenation of `self`'s surviving
    /// entries in symbol order followed by `right`'s entries in symbol order:
    /// keys present in both operands take `right`'s value and position,
    /// storage stays sorted by symbol id, the source-order permutation
    /// reflects that surviving-left-then-right input order, and the
    /// lexicographic permutation is merged from the operands' existing
    /// permutations instead of re-sorted. Both operands must come from the
    /// same symbol universe as `symbols`.
    ///
    /// This is the evaluator's `//` fast path: two sorted entry arrays merge
    /// in `O(left + right)` without the sorting, duplicate scanning, and rank
    /// re-sorting that [`FlatAttrs::new`] performs on unsorted input.
    ///
    /// # Errors
    ///
    /// Returns [`AttrError::TooManyEntries`] if the combined entry count
    /// cannot be represented in the `u32` slot permutation. Returns
    /// [`AttrError::AllocationFailed`] if result storage cannot be reserved.
    /// Returns [`AttrError::UnknownSymbol`] if a key cannot be resolved
    /// through `symbols`. Returns [`AttrError::SlotOutOfBounds`] if either
    /// operand's internal permutations are inconsistent with its entries.
    pub fn update_right_biased(
        &self,
        right: &Self,
        symbols: &SymbolTable,
    ) -> Result<Self, AttrError> {
        /// Marks a left entry that `right` overrides out of the result.
        const DROPPED: u32 = u32::MAX;

        let capacity = self
            .len()
            .checked_add(right.len())
            .ok_or(AttrError::TooManyEntries { len: usize::MAX })?;
        u32::try_from(capacity).map_err(|_| AttrError::TooManyEntries { len: capacity })?;
        let reserve = |len: usize| -> Result<Vec<u32>, AttrError> {
            let mut slots = Vec::new();
            slots
                .try_reserve_exact(len)
                .map_err(|_| AttrError::AllocationFailed { entries: len })?;
            Ok(slots)
        };

        // Pass 1: merge the two symbol-sorted entry arrays, right-biased.
        // Record where each operand slot landed in the merged storage so the
        // permutations can be remapped without re-sorting.
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(capacity)
            .map_err(|_| AttrError::AllocationFailed { entries: capacity })?;
        let mut left_slots = reserve(self.len())?;
        let mut right_slots = reserve(right.len())?;
        let left_entries = self.entries_by_symbol();
        let right_entries = right.entries_by_symbol();
        let (mut i, mut j) = (0, 0);
        while let (Some(left_entry), Some(right_entry)) =
            (left_entries.get(i), right_entries.get(j))
        {
            let slot = entries.len() as u32;
            match left_entry.key.cmp(&right_entry.key) {
                std::cmp::Ordering::Less => {
                    entries.push(*left_entry);
                    left_slots.push(slot);
                    i += 1;
                }
                std::cmp::Ordering::Greater => {
                    entries.push(*right_entry);
                    right_slots.push(slot);
                    j += 1;
                }
                std::cmp::Ordering::Equal => {
                    entries.push(*right_entry);
                    left_slots.push(DROPPED);
                    right_slots.push(slot);
                    i += 1;
                    j += 1;
                }
            }
        }
        for left_entry in &left_entries[i..] {
            left_slots.push(entries.len() as u32);
            entries.push(*left_entry);
        }
        for right_entry in &right_entries[j..] {
            right_slots.push(entries.len() as u32);
            entries.push(*right_entry);
        }
        let len = entries.len();

        // Source order: the construction order is left survivors in symbol
        // order followed by right entries in symbol order, so the inverse
        // permutation is the surviving left slots followed by the right slots.
        let mut source_order = reserve(len)?;
        source_order.extend(left_slots.iter().copied().filter(|&slot| slot != DROPPED));
        source_order.extend_from_slice(&right_slots);

        // Lexicographic order: each operand's permutation is already sorted
        // by rank, relative byte order of live symbols is invariant under
        // symbol-table growth, and the merged key set has no duplicates, so
        // merging the two rank-sorted streams reproduces a full re-sort.
        let rank_of = |slot: u32| -> Result<u32, AttrError> {
            let key = entries
                .get(slot as usize)
                .ok_or(AttrError::SlotOutOfBounds {
                    slot: slot as usize,
                    len,
                })?
                .key;
            symbols
                .lexicographic_rank(key)
                .ok_or(AttrError::UnknownSymbol { key })
        };
        let remap = |slots: &[u32], order: &[u32]| -> Result<Vec<u32>, AttrError> {
            let mut remapped = reserve(order.len())?;
            for &slot in order {
                let mapped = *slots.get(slot as usize).ok_or(AttrError::SlotOutOfBounds {
                    slot: slot as usize,
                    len: slots.len(),
                })?;
                remapped.push(mapped);
            }
            Ok(remapped)
        };
        let left_lex = remap(&left_slots, self.iteration_order())?;
        let right_lex = remap(&right_slots, right.iteration_order())?;
        let mut iteration_order = reserve(len)?;
        let mut left_stream = left_lex.iter().copied().filter(|&slot| slot != DROPPED);
        let mut right_stream = right_lex.iter().copied();
        let mut left_head = match left_stream.next() {
            Some(slot) => Some((slot, rank_of(slot)?)),
            None => None,
        };
        let mut right_head = match right_stream.next() {
            Some(slot) => Some((slot, rank_of(slot)?)),
            None => None,
        };
        loop {
            match (left_head, right_head) {
                (Some((left_slot, left_rank)), Some((_, right_rank)))
                    if left_rank < right_rank =>
                {
                    iteration_order.push(left_slot);
                    left_head = match left_stream.next() {
                        Some(slot) => Some((slot, rank_of(slot)?)),
                        None => None,
                    };
                }
                (_, Some((right_slot, _))) => {
                    iteration_order.push(right_slot);
                    right_head = match right_stream.next() {
                        Some(slot) => Some((slot, rank_of(slot)?)),
                        None => None,
                    };
                }
                (Some((left_slot, _)), None) => {
                    iteration_order.push(left_slot);
                    left_head = match left_stream.next() {
                        Some(slot) => Some((slot, rank_of(slot)?)),
                        None => None,
                    };
                }
                (None, None) => break,
            }
        }

        Ok(Self {
            entries,
            source_order,
            iteration_order,
        })
    }}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attrs::{AttrEntry, AttrPosition};
    use crate::syntax::{Span, Symbol};
    use crate::value::Value;

    fn symbols(names: &[&[u8]]) -> (SymbolTable, Vec<Symbol>) {
        let mut table = SymbolTable::new();
        let mut ids = Vec::new();
        for name in names {
            ids.push(table.intern(name).expect("symbol interns"));
        }
        (table, ids)
    }

    /// Reference `//` construction: the unsorted-input path the evaluator
    /// used before [`FlatAttrs::update_right_biased`] existed.
    fn reference_update(left: &FlatAttrs, right: &FlatAttrs, symbols: &SymbolTable) -> FlatAttrs {
        let mut input: Vec<AttrEntry> = left
            .entries_by_symbol()
            .iter()
            .filter(|entry| !right.contains_key(entry.key))
            .copied()
            .collect();
        input.extend_from_slice(right.entries_by_symbol());
        FlatAttrs::new(input, symbols).expect("reference merge builds")
    }

    #[test]
    fn update_right_biased_matches_reference_construction() {
        let (mut symbols, ids) = symbols(&[b"z", b"a", b"m", b"b", b"q"]);
        let left = FlatAttrs::new(
            vec![
                AttrEntry::new(ids[0], Value::int(1)),
                AttrEntry::with_position(ids[1], Value::int(2), AttrPosition::new(0, Span::new(0, 1))),
                AttrEntry::new(ids[2], Value::int(3)),
            ],
            &symbols,
        )
        .expect("left attrset builds");
        // Interleave later interns so symbol-id order and lexicographic order
        // diverge between the operands.
        let late = symbols.intern(b"aa").expect("late symbol interns");
        let right = FlatAttrs::new(
            vec![
                AttrEntry::with_position(ids[1], Value::int(20), AttrPosition::new(1, Span::new(5, 9))),
                AttrEntry::new(ids[3], Value::int(4)),
                AttrEntry::new(late, Value::int(5)),
            ],
            &symbols,
        )
        .expect("right attrset builds");

        let merged = left
            .update_right_biased(&right, &symbols)
            .expect("linear merge builds");
        assert!(merged.raw_eq(&reference_update(&left, &right, &symbols)));
        // Right bias: overridden key takes right's value and position.
        assert_eq!(merged.get(ids[1]).expect("a survives").as_int(), Ok(20));
        assert_eq!(
            merged.get_entry(ids[1]).expect("a survives").position,
            Some(AttrPosition::new(1, Span::new(5, 9))),
        );
    }

    #[test]
    fn update_right_biased_handles_empty_and_disjoint_operands() {
        let (symbols, ids) = symbols(&[b"c", b"a", b"b", b"d"]);
        let empty = FlatAttrs::empty();
        let left = FlatAttrs::new(
            vec![
                AttrEntry::new(ids[0], Value::int(1)),
                AttrEntry::new(ids[1], Value::int(2)),
            ],
            &symbols,
        )
        .expect("left attrset builds");
        let right = FlatAttrs::new(
            vec![
                AttrEntry::new(ids[2], Value::int(3)),
                AttrEntry::new(ids[3], Value::int(4)),
            ],
            &symbols,
        )
        .expect("right attrset builds");

        for (a, b) in [
            (&left, &right),
            (&right, &left),
            (&empty, &left),
            (&left, &empty),
            (&empty, &empty),
            (&left, &left),
        ] {
            let merged = a
                .update_right_biased(b, &symbols)
                .expect("linear merge builds");
            assert!(merged.raw_eq(&reference_update(a, b, &symbols)));
        }
    }

    #[test]
    fn update_right_biased_matches_reference_on_dense_overlaps() {
        // Exhaust small overlap patterns: every subset of a 6-key universe on
        // each side, values disambiguated per side.
        let names: Vec<Vec<u8>> = (0..6u8).map(|i| vec![b'k', b'0' + i]).collect();
        let name_refs: Vec<&[u8]> = names.iter().map(Vec::as_slice).collect();
        let (symbols, ids) = symbols(&name_refs);
        let build = |mask: u32, base: i64| -> FlatAttrs {
            let entries = ids
                .iter()
                .enumerate()
                .filter(|(index, _)| mask & (1 << index) != 0)
                .map(|(index, &id)| AttrEntry::new(id, Value::int(base + index as i64)))
                .collect();
            FlatAttrs::new(entries, &symbols).expect("masked attrset builds")
        };
        for left_mask in 0..64u32 {
            for right_mask in [0u32, 1, 21, 42, 63, left_mask, !left_mask & 63] {
                let left = build(left_mask, 0);
                let right = build(right_mask, 100);
                let merged = left
                    .update_right_biased(&right, &symbols)
                    .expect("linear merge builds");
                assert!(
                    merged.raw_eq(&reference_update(&left, &right, &symbols)),
                    "divergence for left mask {left_mask:#08b} right mask {right_mask:#08b}",
                );
            }
        }
    }}
