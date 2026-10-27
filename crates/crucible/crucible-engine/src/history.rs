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
/// ```rust
/// use crucible_engine::History;
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

    /// Returns an iterator over the elements from `start` onward.
    ///
    /// Positioning costs constant time, so iterating a recent suffix does not
    /// walk the retained prefix. A `start` at or beyond the end yields nothing.
    pub fn iter_from(&self, start: usize) -> Iter<'_, T> {
        let len = self.len();
        if start >= len {
            return Iter {
                chunks: [].iter(),
                front: [].iter(),
                back: [].iter(),
                remaining: 0,
            };
        }
        let sealed_len = self.sealed.len() * CHUNK_LEN;
        if start >= sealed_len {
            return Iter {
                chunks: [].iter(),
                front: [].iter(),
                back: self.tail[start - sealed_len..].iter(),
                remaining: len - start,
            };
        }
        let chunk = start / CHUNK_LEN;
        Iter {
            chunks: self.sealed[chunk + 1..].iter(),
            front: self.sealed[chunk][start % CHUNK_LEN..].iter(),
            back: self.tail.iter(),
            remaining: len - start,
        }
    }

    /// Returns an iterator over the elements whose indices fall in `range`.
    ///
    /// Positioning costs constant time, like [`History::iter_from`]. A range
    /// that ends beyond the history is clipped to its length.
    pub fn range(&self, range: std::ops::Range<usize>) -> std::iter::Take<Iter<'_, T>> {
        let len = range.end.min(self.len()).saturating_sub(range.start);
        self.iter_from(range.start).take(len)
    }

    /// Returns `true` when `prefix` equals the first `prefix.len()` elements.
    ///
    /// Like [`History::prefix_eq`], sealed chunks the two histories share are
    /// not compared element by element.
    #[must_use]
    pub fn starts_with(&self, prefix: &Self) -> bool
    where
        T: PartialEq,
    {
        self.prefix_eq(prefix, prefix.len())
    }

    /// Returns `true` when the elements from `start` onward begin with `other`.
    ///
    /// The comparison positions at `start` in constant time and reads only
    /// `other.len()` elements of this history.
    #[must_use]
    pub fn has_run_at(&self, start: usize, other: &[T]) -> bool
    where
        T: PartialEq,
    {
        start
            .checked_add(other.len())
            .is_some_and(|end| end <= self.len())
            && self.iter_from(start).zip(other).all(|(a, b)| a == b)
    }

    /// Returns `true` when both histories hold at least `len` elements and
    /// their first `len` elements are equal.
    ///
    /// Sealed chunks that both histories share are skipped without comparing
    /// their elements, so comparing a history with a clone that has grown
    /// since costs time proportional to the unshared part only.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use crucible_engine::History;
    ///
    /// let mut base = History::new();
    /// base.extend([1, 2, 3]);
    /// let mut grown = base.clone();
    /// grown.push(4);
    ///
    /// assert!(grown.prefix_eq(&base, 3));
    /// assert!(!grown.prefix_eq(&base, 4));
    /// ```
    #[must_use]
    pub fn prefix_eq(&self, other: &Self, len: usize) -> bool
    where
        T: PartialEq,
    {
        if len > self.len() || len > other.len() {
            return false;
        }

        let mut start = 0;
        while start < len {
            let chunk = start / CHUNK_LEN;
            let end = len.min((chunk + 1) * CHUNK_LEN);
            let shared = match (self.sealed.get(chunk), other.sealed.get(chunk)) {
                (Some(left), Some(right)) => Arc::ptr_eq(left, right),
                _ => false,
            };
            if !shared && (start..end).any(|index| self.get(index) != other.get(index)) {
                return false;
            }
            start = end;
        }
        true
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

    /// Returns the first `len` elements as a history that shares this one's
    /// sealed chunks, or `None` when `len` exceeds the length.
    ///
    /// Only the chunk pointer table and at most one partial chunk are copied,
    /// so a prefix of a long history costs memory proportional to its chunk
    /// count rather than to its elements.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use crucible_engine::History;
    ///
    /// let mut log = History::new();
    /// log.extend(0..200);
    /// let prefix = log.prefix(130).expect("prefix within the history");
    ///
    /// assert_eq!(prefix.len(), 130);
    /// assert!(log.starts_with(&prefix));
    /// assert!(log.prefix(201).is_none());
    /// ```
    #[must_use]
    pub fn prefix(&self, len: usize) -> Option<Self> {
        if len > self.len() {
            return None;
        }
        if len == self.len() {
            return Some(self.clone());
        }

        // Every sealed chunk is full, so the prefix keeps the first `full`
        // chunks whole and copies `partial` elements of the next one.
        let full = len / CHUNK_LEN;
        let partial = len % CHUNK_LEN;
        let sealed = if full == self.sealed.len() {
            Arc::clone(&self.sealed)
        } else {
            Arc::new(self.sealed.get(..full)?.to_vec())
        };
        let next: &[T] = match self.sealed.get(full) {
            Some(chunk) => chunk,
            None => &self.tail,
        };
        Some(Self {
            sealed,
            tail: Arc::new(next.get(..partial)?.to_vec()),
        })
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

impl<T: PartialEq> PartialEq<Vec<T>> for &History<T> {
    fn eq(&self, other: &Vec<T>) -> bool {
        **self == other[..]
    }
}

impl<T: PartialEq, const N: usize> PartialEq<[T; N]> for &History<T> {
    fn eq(&self, other: &[T; N]) -> bool {
        **self == other[..]
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
        // Length prefix, then every element in order, so equal histories hash
        // equally regardless of how their storage is shared.
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
    fn prefixes_share_sealed_chunks_and_grow_independently() {
        let source_len = 3 * CHUNK_LEN + 7;
        let mut source = History::new();
        source.extend(reference(source_len));

        for len in [
            0,
            1,
            CHUNK_LEN - 1,
            CHUNK_LEN,
            CHUNK_LEN + 1,
            3 * CHUNK_LEN,
            source_len - 1,
            source_len,
        ] {
            let Some(mut prefix) = source.prefix(len) else {
                panic!("prefix {len} is within the source");
            };

            assert_eq!(prefix.to_vec(), reference(len));
            assert!(source.starts_with(&prefix));
            for chunk in 0..len / CHUNK_LEN {
                assert!(Arc::ptr_eq(&prefix.sealed[chunk], &source.sealed[chunk]));
            }

            prefix.extend([usize::MAX; CHUNK_LEN + 1]);
            assert_eq!(prefix.len(), len + CHUNK_LEN + 1);
            assert_eq!(source.to_vec(), reference(source_len));
        }
        assert!(source.prefix(source_len + 1).is_none());
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
        if let Some(first) = original.get_mut(0) {
            *first = 2000;
        }
        if let Some(last) = original.last_mut() {
            *last = 3000;
        }

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
        if let Some(middle) = changed.get_mut(CHUNK_LEN) {
            *middle = usize::MAX;
        }

        assert_eq!(left, right);
        assert_ne!(left, shorter);
        assert_ne!(left, changed);
        assert_eq!(reference(CHUNK_LEN * 2), left);
    }

    #[test]
    fn prefix_equality_compares_shared_and_copied_storage_alike() {
        let base = History::from(reference(2 * CHUNK_LEN + 3));
        let mut grown = base.clone();
        grown.extend([7, 8, 9]);
        let copied = History::from(reference(2 * CHUNK_LEN + 3));
        let mut changed = base.clone();
        if let Some(element) = changed.get_mut(CHUNK_LEN + 1) {
            *element = usize::MAX;
        }

        for len in [0, 1, CHUNK_LEN, CHUNK_LEN + 2, 2 * CHUNK_LEN + 3] {
            assert!(grown.prefix_eq(&base, len), "shared prefix {len}");
            assert!(copied.prefix_eq(&base, len), "copied prefix {len}");
        }
        assert!(!grown.prefix_eq(&base, 2 * CHUNK_LEN + 4));
        assert!(changed.prefix_eq(&base, CHUNK_LEN + 1));
        assert!(!changed.prefix_eq(&base, CHUNK_LEN + 2));
    }

    #[test]
    fn range_clips_to_the_history_and_crosses_chunks() {
        let history = History::from(reference(2 * CHUNK_LEN + 5));

        let middle = (CHUNK_LEN - 2)..(CHUNK_LEN + 3);
        assert!(
            history
                .range(middle.clone())
                .eq(reference(2 * CHUNK_LEN + 5)[middle].iter())
        );
        assert!(
            history
                .range((2 * CHUNK_LEN)..usize::MAX)
                .copied()
                .eq((2 * CHUNK_LEN)..(2 * CHUNK_LEN + 5))
        );
        assert_eq!(history.range(5..5).count(), 0);
        // A reversed range is empty rather than a panic.
        assert_eq!(
            history.range(std::ops::Range { start: 9, end: 3 }).count(),
            0
        );
        assert_eq!(history.range((3 * CHUNK_LEN)..(4 * CHUNK_LEN)).count(), 0);
    }

    #[test]
    fn starts_with_compares_unshared_chunks_by_content() {
        let prefix = History::from(reference(CHUNK_LEN + 3));
        let mut extended = prefix.clone();
        extended.extend((CHUNK_LEN + 3)..(3 * CHUNK_LEN));
        let rebuilt = History::from(reference(3 * CHUNK_LEN));
        let mut diverged = rebuilt.clone();
        if let Some(first) = diverged.get_mut(0) {
            *first = usize::MAX;
        }

        assert!(extended.starts_with(&prefix));
        assert!(rebuilt.starts_with(&prefix));
        assert!(!diverged.starts_with(&prefix));
        assert!(!prefix.starts_with(&extended));
        assert!(prefix.starts_with(&History::new()));
    }

    #[test]
    fn has_run_at_matches_only_complete_runs() {
        let history = History::from(reference(CHUNK_LEN + 4));
        let run = reference(CHUNK_LEN + 4)[(CHUNK_LEN - 1)..(CHUNK_LEN + 2)].to_vec();

        assert!(history.has_run_at(CHUNK_LEN - 1, &run));
        assert!(!history.has_run_at(CHUNK_LEN, &run));
        assert!(!history.has_run_at(CHUNK_LEN + 3, &[CHUNK_LEN + 3, CHUNK_LEN + 4]));
        assert!(!history.has_run_at(usize::MAX, &[0]));
        assert!(history.has_run_at(CHUNK_LEN + 4, &[]));
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
