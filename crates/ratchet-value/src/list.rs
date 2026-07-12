//! Immutable Nix list representation.
//!
//! The Phase-1 baseline keeps list spines as contiguous vectors of [`Value`],
//! with length tracked by the safe Rust container rather than a frozen runtime
//! ABI header. Elements remain ordinary runtime values and may themselves be
//! thunks; forcing a list observes only the spine. Later heap layouts can replace
//! the backing storage with an inline flexible-array object without changing the
//! safe access surface here.

use thiserror::Error;

use crate::value::Value;

/// A safe immutable Nix list spine backed by contiguous values.
#[derive(Clone, Debug, Default)]
pub struct NixList {
    elements: Vec<Value>,
}

impl NixList {
    /// Creates an empty list.
    pub const fn empty() -> Self {
        Self {
            elements: Vec::new(),
        }
    }

    /// Creates a list from already-lowered element values.
    ///
    /// The input vector becomes the list spine in order. Element values are not
    /// forced by construction.
    pub fn new(elements: Vec<Value>) -> Self {
        Self { elements }
    }

    /// Returns the number of elements in the list spine.
    pub fn len(&self) -> usize {
        self.elements.len()
    }

    /// Returns whether the list has no elements.
    pub fn is_empty(&self) -> bool {
        self.elements.is_empty()
    }

    /// Returns a copied element at `index`.
    pub fn get(&self, index: usize) -> Option<Value> {
        self.elements.get(index).copied()
    }

    /// Returns a shared reference to the element at `index`.
    pub fn get_ref(&self, index: usize) -> Option<&Value> {
        self.elements.get(index)
    }

    /// Returns all elements as a contiguous slice.
    pub fn as_slice(&self) -> &[Value] {
        &self.elements
    }

    /// Returns representation-level list spine equality.
    ///
    /// This is not Nix semantic equality: element thunks are not forced and
    /// heap-backed children compare by their raw runtime handles. Hash-consing
    /// tables use this after a structural-hash hit to confirm whether a list
    /// spine can be shared safely.
    pub fn raw_eq(&self, other: &Self) -> bool {
        self.len() == other.len()
            && self
                .iter()
                .zip(other.iter())
                .all(|(left, right)| left.raw_eq(*right))
    }

    /// Concatenates two list spines without forcing their elements.
    ///
    /// The returned list contains copied [`Value`] handles in source order.
    ///
    /// # Errors
    ///
    /// Returns [`NixListError::LengthOverflow`] if the combined length overflows
    /// `usize`, or [`NixListError::AllocationFailed`] if the resulting spine
    /// cannot reserve enough storage.
    pub fn concat(&self, other: &Self) -> Result<Self, NixListError> {
        let len = self
            .elements
            .len()
            .checked_add(other.elements.len())
            .ok_or(NixListError::LengthOverflow {
                left: self.elements.len(),
                right: other.elements.len(),
            })?;
        let mut elements = Vec::new();
        elements
            .try_reserve_exact(len)
            .map_err(|_| NixListError::AllocationFailed { len })?;
        elements.extend_from_slice(&self.elements);
        elements.extend_from_slice(&other.elements);
        Ok(Self { elements })
    }

    /// Iterates over list elements in source order.
    pub fn iter(&self) -> std::slice::Iter<'_, Value> {
        self.elements.iter()
    }

    /// Consumes the list and returns the underlying contiguous element vector.
    pub fn into_vec(self) -> Vec<Value> {
        self.elements
    }
}

impl From<Vec<Value>> for NixList {
    fn from(elements: Vec<Value>) -> Self {
        Self::new(elements)
    }
}

impl<'a> IntoIterator for &'a NixList {
    type Item = &'a Value;
    type IntoIter = std::slice::Iter<'a, Value>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// A Nix list operation failed.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum NixListError {
    /// Concatenating two list spines overflowed `usize`.
    #[error("list length overflow while combining lengths {left} and {right}")]
    LengthOverflow {
        /// The left list length.
        left: usize,
        /// The right list length.
        right: usize,
    },
    /// The list spine could not reserve storage.
    #[error("failed to reserve {len} list elements")]
    AllocationFailed {
        /// The requested element capacity.
        len: usize,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::value::HeapObject;

    fn int_values(values: &[Value]) -> Vec<i64> {
        values
            .iter()
            .map(|value| value.as_int().expect("value is an int"))
            .collect()
    }

    #[test]
    fn empty_list_has_empty_spine() {
        let list = NixList::empty();

        assert!(list.is_empty());
        assert_eq!(list.len(), 0);
        assert!(list.as_slice().is_empty());
        assert_eq!(list.iter().len(), 0);
    }

    #[test]
    fn list_preserves_source_order() {
        let list = NixList::new(vec![Value::int(1), Value::int(2), Value::int(3)]);

        assert_eq!(list.len(), 3);
        assert_eq!(int_values(list.as_slice()), vec![1, 2, 3]);
        assert_eq!(list.get(0).expect("first element").as_int(), Ok(1));
        assert_eq!(list.get(2).expect("third element").as_int(), Ok(3));
        assert!(list.get(3).is_none());
    }

    #[test]
    fn iterators_are_exact_size_and_borrow_elements() {
        let list = NixList::from(vec![Value::int(4), Value::int(5)]);
        let mut iter = (&list).into_iter();

        assert_eq!(iter.len(), 2);
        assert_eq!(iter.next().expect("first").as_int(), Ok(4));
        assert_eq!(iter.len(), 1);
        assert_eq!(iter.next().expect("second").as_int(), Ok(5));
        assert!(iter.next().is_none());
    }

    #[test]
    fn into_vec_returns_contiguous_elements() {
        let list = NixList::new(vec![Value::int(8), Value::int(13)]);
        let elements = list.into_vec();

        assert_eq!(int_values(&elements), vec![8, 13]);
    }

    // Builds thunk values from hand-picked fake pointers (8, 16); under the
    // Candidate-C carrier `Value::thunk` resolves the pointer through the
    // reservation registry, so a pointer outside any live reservation is
    // rejected. The list ordering/handle semantics under test are exercised on
    // the variant by the parity battery over real heap lists.
    #[cfg(not(feature = "candidate_c_value"))]
    #[test]
    fn concat_preserves_order_without_forcing_elements() {
        let left_ptr = std::ptr::NonNull::new(8usize as *mut HeapObject).expect("non-null pointer");
        let right_ptr =
            std::ptr::NonNull::new(16usize as *mut HeapObject).expect("non-null pointer");
        let left_thunk = Value::thunk(left_ptr).expect("thunk pointer");
        let right_thunk = Value::thunk(right_ptr).expect("thunk pointer");
        let left = NixList::new(vec![Value::int(1), left_thunk]);
        let right = NixList::new(vec![right_thunk, Value::int(4)]);

        let concat = left.concat(&right).expect("concat succeeds");

        assert_eq!(concat.len(), 4);
        assert_eq!(concat.get(0).expect("first").as_int(), Ok(1));
        assert!(concat.get(1).expect("second").raw_eq(left_thunk));
        assert!(concat.get(2).expect("third").raw_eq(right_thunk));
        assert_eq!(concat.get(3).expect("fourth").as_int(), Ok(4));
    }

    // Same fake-pointer construction as the concat test above; gated for the
    // same reason (Candidate-C rejects pointers outside a live reservation).
    #[cfg(not(feature = "candidate_c_value"))]
    #[test]
    fn raw_equality_compares_element_handles_without_forcing() {
        let shared_ptr =
            std::ptr::NonNull::new(8usize as *mut HeapObject).expect("non-null pointer");
        let distinct_ptr =
            std::ptr::NonNull::new(16usize as *mut HeapObject).expect("non-null pointer");
        let shared_thunk = Value::thunk(shared_ptr).expect("thunk pointer");
        let distinct_thunk = Value::thunk(distinct_ptr).expect("thunk pointer");

        assert!(
            NixList::new(vec![Value::int(1), shared_thunk])
                .raw_eq(&NixList::new(vec![Value::int(1), shared_thunk]))
        );
        assert!(
            !NixList::new(vec![Value::int(1), shared_thunk])
                .raw_eq(&NixList::new(vec![Value::int(1), distinct_thunk]))
        );
        assert!(
            !NixList::new(vec![Value::int(1)])
                .raw_eq(&NixList::new(vec![Value::int(1), Value::int(2)]))
        );
    }

    #[test]
    fn concat_handles_empty_lists() {
        let empty = NixList::empty();
        let values = NixList::new(vec![Value::bool(true)]);

        let left_empty = empty.concat(&values).expect("concat succeeds");
        assert_eq!(left_empty.len(), 1);
        assert_eq!(left_empty.get(0).expect("element").as_bool(), Ok(true));

        let right_empty = values.concat(&empty).expect("concat succeeds");
        assert_eq!(right_empty.len(), 1);
        assert_eq!(right_empty.get(0).expect("element").as_bool(), Ok(true));

        assert!(empty.concat(&empty).expect("concat succeeds").is_empty());
    }
}
