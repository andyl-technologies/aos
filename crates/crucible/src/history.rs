//! Append-mostly sequences whose clones share their retained history.
//!
//! The scheduler stages, seals, and retains RUN authority by cloning its whole
//! state. Event-log history, observations, and RUN publication tables grow for
//! the life of a run, so element-wise copies would make every quantum cost
//! time proportional to everything that happened before it.
//!
//! [`History`] stores elements in fixed-size immutable chunks behind reference
//! counts, plus one short mutable tail:
//!
//! ```text
//! sealed: [chunk 0: 64 elements] [chunk 1: 64 elements] ...   (shared)
//! tail:   [0..64 elements]                                    (copy on write)
//! ```
//!
//! Cloning copies two reference counts. The first push after a clone copies
//! at most one partial tail, and sealing a full tail copies only the chunk
//! pointer table when another clone still shares it. Element order, equality,
//! and iteration are exactly those of the equivalent `Vec`.

use std::fmt;
use std::hash::{Hash, Hasher};
use std::iter::FusedIterator;
use std::ops::Index;
use std::sync::Arc;

/// Number of elements in every sealed chunk.
///
/// Small enough that the copy-on-write tail stays cheap, large enough that the
/// chunk pointer table stays short for long runs.
const CHUNK_LEN: usize = 64;

/// An ordered sequence with structurally shared, append-mostly storage.
///
/// `History` offers the read surface of a slice (`len`, `get`, indexing,
/// iteration from either end) and the growth surface of a `Vec` (`push`,
/// `extend`). Clones are constant time and share every sealed element, so a
/// long history can be snapshotted as often as the scheduler needs.
///
/// Elements are not contiguous in memory; use [`History::to_vec`] when an
/// owned slice is required.
///
/// # Examples
///
/// ```
/// use crucible::History;
///
/// let mut log = History::new();
/// log.extend([1, 2, 3]);
/// let snapshot = log.clone();
/// log.push(4);
///
/// assert_eq!(snapshot, [1, 2, 3]);
/// assert_eq!(log.len(), 4);
/// assert_eq!(log.iter().rev().next(), Some(&4));
/// ```
pub struct History<T> {
    // Every sealed chunk holds exactly `CHUNK_LEN` elements, so chunk `i`
    // starts at element `i * CHUNK_LEN` in every history of equal length.
    sealed: Arc<Vec<Arc<Vec<T>>>>,
    tail: Arc<Vec<T>>,
}

impl<T> History<T> {
    /// Builds an empty history.
    #[must_use]
    pub fn new() -> Self {
        Self {
            sealed: Arc::new(Vec::new()),
            tail: Arc::new(Vec::new()),
        }
    }

    /// Returns the number of elements.
    #[must_use]
    pub fn len(&self) -> usize {
        self.sealed.len() * CHUNK_LEN + self.tail.len()
    }

    /// Returns `true` when the history holds no elements.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.sealed.is_empty() && self.tail.is_empty()
    }

    /// Returns the element at `index`, or `None` when it is out of bounds.
    #[must_use]
    pub fn get(&self, index: usize) -> Option<&T> {
        let sealed_len = self.sealed.len() * CHUNK_LEN;
        if index < sealed_len {
            self.sealed
                .get(index / CHUNK_LEN)
                .and_then(|chunk| chunk.get(index % CHUNK_LEN))
        } else {
            self.tail.get(index - sealed_len)
        }
    }

    /// Returns the first element, or `None` when the history is empty.
    #[must_use]
    pub fn first(&self) -> Option<&T> {
        self.get(0)
    }

    /// Returns the last element, or `None` when the history is empty.
    #[must_use]
    pub fn last(&self) -> Option<&T> {
        self.tail
            .last()
            .or_else(|| self.sealed.last().and_then(|chunk| chunk.last()))
    }

    /// Returns an iterator over the elements in order.
    pub fn iter(&self) -> Iter<'_, T> {
        Iter {
            chunks: self.sealed.iter(),
            front: [].iter(),
            back: self.tail.iter(),
            remaining: self.len(),
        }
    }

    /// Returns `true` when the history holds an element equal to `value`.
    #[must_use]
    pub fn contains(&self, value: &T) -> bool
    where
        T: PartialEq,
    {
        self.iter().any(|element| element == value)
    }

    /// Returns `true` when both histories share all of their storage.
    ///
    /// Shared storage implies equal contents; the converse does not hold.
    #[must_use]
    pub fn shares_storage_with(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.sealed, &other.sealed) && Arc::ptr_eq(&self.tail, &other.tail)
    }
}

impl<T: Clone> History<T> {
    /// Appends one element.
    ///
    /// Only storage still shared with another clone is copied: at most the
    /// partial tail, and the chunk pointer table when the tail seals.
    pub fn push(&mut self, value: T) {
        let tail = Arc::make_mut(&mut self.tail);
        if tail.capacity() < CHUNK_LEN {
            tail.reserve_exact(CHUNK_LEN - tail.len());
        }
        tail.push(value);
        if tail.len() == CHUNK_LEN {
            let full = std::mem::replace(tail, Vec::with_capacity(CHUNK_LEN));
            Arc::make_mut(&mut self.sealed).push(Arc::new(full));
        }
    }

    /// Returns a mutable reference to the element at `index`, or `None` when
    /// it is out of bounds.
    ///
    /// The chunk holding the element is copied first when another clone
    /// shares it, so no other history observes the change.
    pub fn get_mut(&mut self, index: usize) -> Option<&mut T> {
        let sealed_len = self.sealed.len() * CHUNK_LEN;
        if index < sealed_len {
            let chunk = Arc::make_mut(&mut self.sealed).get_mut(index / CHUNK_LEN)?;
            Arc::make_mut(chunk).get_mut(index % CHUNK_LEN)
        } else {
            Arc::make_mut(&mut self.tail).get_mut(index - sealed_len)
        }
    }

    /// Returns a mutable reference to the last element, or `None` when the
    /// history is empty.
    pub fn last_mut(&mut self) -> Option<&mut T> {
        let index = self.len().checked_sub(1)?;
        self.get_mut(index)
    }

    /// Removes every element without disturbing other clones.
    pub fn clear(&mut self) {
        *self = Self::new();
    }

    /// Copies the elements into an owned vector.
    #[must_use]
    pub fn to_vec(&self) -> Vec<T> {
        let mut elements = Vec::with_capacity(self.len());
        for chunk in self.sealed.iter() {
            elements.extend_from_slice(chunk);
        }
        elements.extend_from_slice(&self.tail);
        elements
    }
}

impl<T> Default for History<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> Clone for History<T> {
    fn clone(&self) -> Self {
        Self {
            sealed: Arc::clone(&self.sealed),
            tail: Arc::clone(&self.tail),
        }
    }
}

impl<T: fmt::Debug> fmt::Debug for History<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_list().entries(self.iter()).finish()
    }
}

impl<T: PartialEq> PartialEq for History<T> {
    fn eq(&self, other: &Self) -> bool {
        if self.len() != other.len() {
            return false;
        }
        if self.shares_storage_with(other) {
            return true;
        }
        // Equal lengths imply identical chunk boundaries, so shared chunks
        // can be skipped without comparing their elements.
        self.sealed
            .iter()
            .zip(other.sealed.iter())
            .all(|(left, right)| Arc::ptr_eq(left, right) || left == right)
            && self.tail == other.tail
    }
}

impl<T: Eq> Eq for History<T> {}

impl<T: PartialEq> PartialEq<[T]> for History<T> {
    fn eq(&self, other: &[T]) -> bool {
        self.len() == other.len() && self.iter().eq(other.iter())
    }
}

impl<T: PartialEq> PartialEq<&[T]> for History<T> {
    fn eq(&self, other: &&[T]) -> bool {
        *self == **other
    }
}

impl<T: PartialEq, const N: usize> PartialEq<[T; N]> for History<T> {
    fn eq(&self, other: &[T; N]) -> bool {
        *self == other[..]
    }
}

impl<T: PartialEq> PartialEq<Vec<T>> for History<T> {
    fn eq(&self, other: &Vec<T>) -> bool {
        *self == other[..]
    }
}

impl<T: PartialEq> PartialEq<History<T>> for Vec<T> {
    fn eq(&self, other: &History<T>) -> bool {
        *other == self[..]
    }
}

impl<T: PartialEq> PartialEq<History<T>> for [T] {
    fn eq(&self, other: &History<T>) -> bool {
        *other == *self
    }
}

impl<T: Hash> Hash for History<T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // Matches the slice encoding: length prefix, then elements in order.
        state.write_usize(self.len());
        for element in self {
            element.hash(state);
        }
    }
}

impl<T> Index<usize> for History<T> {
    type Output = T;

    /// Returns the element at `index`.
    ///
    /// # Panics
    ///
    /// Panics when `index` is out of bounds, like slice indexing.
    fn index(&self, index: usize) -> &T {
        let sealed_len = self.sealed.len() * CHUNK_LEN;
        if index < sealed_len {
            &self.sealed[index / CHUNK_LEN][index % CHUNK_LEN]
        } else {
            &self.tail[index - sealed_len]
        }
    }
}

impl<T> From<Vec<T>> for History<T> {
    fn from(elements: Vec<T>) -> Self {
        let mut sealed = Vec::with_capacity(elements.len() / CHUNK_LEN);
        let mut chunk = Vec::with_capacity(CHUNK_LEN);
        for element in elements {
            chunk.push(element);
            if chunk.len() == CHUNK_LEN {
                sealed.push(Arc::new(std::mem::replace(
                    &mut chunk,
                    Vec::with_capacity(CHUNK_LEN),
                )));
            }
        }
        Self {
            sealed: Arc::new(sealed),
            tail: Arc::new(chunk),
        }
    }
}

impl<T> FromIterator<T> for History<T> {
    fn from_iter<I: IntoIterator<Item = T>>(elements: I) -> Self {
        Self::from(elements.into_iter().collect::<Vec<_>>())
    }
}

impl<T: Clone> Extend<T> for History<T> {
    fn extend<I: IntoIterator<Item = T>>(&mut self, elements: I) {
        for element in elements {
            self.push(element);
        }
    }
}

impl<'a, T> IntoIterator for &'a History<T> {
    type Item = &'a T;
    type IntoIter = Iter<'a, T>;

    fn into_iter(self) -> Iter<'a, T> {
        self.iter()
    }
}

/// Borrowing iterator over a [`History`], created by [`History::iter`].
#[derive(Clone, Debug)]
pub struct Iter<'a, T> {
    chunks: std::slice::Iter<'a, Arc<Vec<T>>>,
    front: std::slice::Iter<'a, T>,
    back: std::slice::Iter<'a, T>,
    remaining: usize,
}

impl<'a, T> Iterator for Iter<'a, T> {
    type Item = &'a T;

    fn next(&mut self) -> Option<&'a T> {
        loop {
            if let Some(element) = self.front.next() {
                self.remaining -= 1;
                return Some(element);
            }
            match self.chunks.next() {
                Some(chunk) => self.front = chunk.iter(),
                None => break,
            }
        }
        let element = self.back.next()?;
        self.remaining -= 1;
        Some(element)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl<T> DoubleEndedIterator for Iter<'_, T> {
    fn next_back(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(element) = self.back.next_back() {
                self.remaining -= 1;
                return Some(element);
            }
            match self.chunks.next_back() {
                Some(chunk) => self.back = chunk.iter(),
                None => break,
            }
        }
        let element = self.front.next_back()?;
        self.remaining -= 1;
        Some(element)
    }
}

impl<T> ExactSizeIterator for Iter<'_, T> {}

impl<T> FusedIterator for Iter<'_, T> {}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference(len: usize) -> Vec<usize> {
        (0..len).collect()
    }

    #[test]
    fn matches_vec_semantics_across_chunk_boundaries() {
        for len in [
            0,
            1,
            CHUNK_LEN - 1,
            CHUNK_LEN,
            CHUNK_LEN + 1,
            3 * CHUNK_LEN + 7,
        ] {
            let expected = reference(len);
            let mut pushed = History::new();
            pushed.extend(expected.iter().copied());
            let converted = History::from(expected.clone());

            for history in [&pushed, &converted] {
                assert_eq!(history.len(), len);
                assert_eq!(history.is_empty(), len == 0);
                assert_eq!(history.to_vec(), expected);
                assert!(history.iter().eq(expected.iter()));
                assert!(history.iter().rev().eq(expected.iter().rev()));
                assert_eq!(history.iter().len(), len);
                assert_eq!(history.first(), expected.first());
                assert_eq!(history.last(), expected.last());
                assert_eq!(history.get(len), None);
                for index in 0..len {
                    assert_eq!(history[index], expected[index]);
                }
            }
            assert_eq!(pushed, converted);
        }
    }

    #[test]
    fn mixed_direction_iteration_yields_each_element_once() {
        let history = History::from(reference(2 * CHUNK_LEN + 5));
        let mut iter = history.iter();
        let mut seen = Vec::new();
        while let Some(front) = iter.next() {
            seen.push(*front);
            if let Some(back) = iter.next_back() {
                seen.push(*back);
            }
        }
        seen.sort_unstable();
        assert_eq!(seen, reference(2 * CHUNK_LEN + 5));
    }

    #[test]
    fn clones_are_isolated_from_later_writes() {
        let mut original = History::from(reference(CHUNK_LEN + 3));
        let snapshot = original.clone();
        assert!(original.shares_storage_with(&snapshot));

        original.push(1000);
        *original.get_mut(0).unwrap() = 2000;
        *original.last_mut().unwrap() = 3000;

        assert_eq!(snapshot, reference(CHUNK_LEN + 3));
        assert_eq!(original[0], 2000);
        assert_eq!(original.last(), Some(&3000));
        assert_eq!(original.len(), CHUNK_LEN + 4);
    }

    #[test]
    fn sealing_after_a_clone_keeps_the_snapshot_intact() {
        let mut original = History::from(reference(CHUNK_LEN - 1));
        let snapshot = original.clone();
        original.extend([CHUNK_LEN - 1, CHUNK_LEN]);

        assert_eq!(snapshot, reference(CHUNK_LEN - 1));
        assert_eq!(original, reference(CHUNK_LEN + 1));
    }

    #[test]
    fn equality_compares_contents_not_storage() {
        let left = History::from(reference(CHUNK_LEN * 2));
        let right: History<usize> = reference(CHUNK_LEN * 2).into_iter().collect();
        let shorter = History::from(reference(CHUNK_LEN * 2 - 1));
        let mut changed = left.clone();
        *changed.get_mut(CHUNK_LEN).unwrap() = usize::MAX;

        assert_eq!(left, right);
        assert_ne!(left, shorter);
        assert_ne!(left, changed);
        assert_eq!(reference(CHUNK_LEN * 2), left);
    }

    #[test]
    fn clear_leaves_clones_untouched() {
        let mut original = History::from(reference(5));
        let snapshot = original.clone();
        original.clear();

        assert!(original.is_empty());
        assert_eq!(snapshot.len(), 5);
    }
}
