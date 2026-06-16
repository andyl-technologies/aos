//! Immutable Nix list representation.
//!
//! The Phase-1 baseline keeps list spines as contiguous vectors of [`Value`],
//! with length tracked by the safe Rust container rather than a frozen runtime
//! ABI header. Elements remain ordinary runtime values and may themselves be
//! thunks; forcing a list observes only the spine. Later heap layouts can replace
//! the backing storage with an inline flexible-array object without changing the
//! safe access surface here.

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

#[cfg(test)]
mod tests {
    use super::*;

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
}
