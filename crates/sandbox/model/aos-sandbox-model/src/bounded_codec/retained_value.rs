//! Shares actual pure temporary custody across bounded codec/model engines.
//!
//! This is a mechanical move guard. The caller supplies its existing empty
//! destination; actual authority, financial admission and success disposition
//! remain in the closed upper operation that owns the input and destination.

use std::ops::{Deref, DerefMut};

/// Moves reached pure DATA into an existing destination when its scope ends.
///
/// A missing destination preserves ordinary local Drop timing. A supplied
/// destination must be empty; neither this type nor its contents grants IO,
/// receiving capacity, replay authority or successful completion.
#[doc(hidden)]
pub struct CaptureOnDropV1<'original, T> {
    value: Option<T>,
    sink: Option<&'original mut Option<T>>,
}

impl<'original, T> CaptureOnDropV1<'original, T> {
    /// Creates one local owner and an optional empty failure destination.
    pub fn new(value: T, sink: Option<&'original mut Option<T>>) -> Self {
        Self {
            value: Some(value),
            sink,
        }
    }

    /// Moves the actual value out at its caller's completed transfer boundary.
    ///
    /// Aborts if a prior consuming operation already removed that value.
    pub fn into_inner(mut self) -> T {
        let Some(value) = self.value.take() else {
            std::process::abort();
        };
        value
    }

    /// Disposes this actual local value at a completed pure leaf boundary.
    pub fn discard_positive(mut self) {
        self.sink = None;
        drop(self.value.take());
    }
}

impl<T> Deref for CaptureOnDropV1<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        let Some(value) = self.value.as_ref() else {
            std::process::abort();
        };
        value
    }
}

impl<T> DerefMut for CaptureOnDropV1<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        let Some(value) = self.value.as_mut() else {
            std::process::abort();
        };
        value
    }
}

impl<T> Drop for CaptureOnDropV1<'_, T> {
    fn drop(&mut self) {
        if let (Some(sink), Some(value)) = (self.sink.as_deref_mut(), self.value.take()) {
            // Replacing a previous failed destination would destroy custody.
            // Once entry and positive path disposal keep every sink empty here.
            if sink.is_some() {
                std::process::abort();
            }
            *sink = Some(value);
        }
    }
}

/// Iterates ordinary owned DATA or borrows the same retained input.
#[doc(hidden)]
pub enum RetainingIterV1<'value, T: Copy> {
    /// Keeps the ordinary consuming iterator and its Drop boundary.
    Ordinary(std::vec::IntoIter<T>),
    /// Borrows the actual caller-retained vector.
    Retained(std::slice::Iter<'value, T>),
}

impl<T: Copy> Iterator for RetainingIterV1<'_, T> {
    type Item = T;

    fn next(&mut self) -> Option<T> {
        match self {
            Self::Ordinary(iter) => iter.next(),
            Self::Retained(iter) => iter.next().copied(),
        }
    }
}

impl<T: Copy> DoubleEndedIterator for RetainingIterV1<'_, T> {
    fn next_back(&mut self) -> Option<T> {
        match self {
            Self::Ordinary(iter) => iter.next_back(),
            Self::Retained(iter) => iter.next_back().copied(),
        }
    }
}

impl<T: Copy> CaptureOnDropV1<'_, Vec<T>> {
    /// Borrows retained DATA or moves the ordinary vector into its iterator.
    ///
    /// Aborts if a previous consuming operation already removed that value.
    pub fn iter_or_take(&mut self) -> RetainingIterV1<'_, T> {
        if self.sink.is_some() {
            let Some(value) = self.value.as_ref() else {
                std::process::abort();
            };
            RetainingIterV1::Retained(value.iter())
        } else {
            let Some(value) = self.value.take() else {
                std::process::abort();
            };
            RetainingIterV1::Ordinary(value.into_iter())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::rc::Rc;

    struct DropCount(Rc<Cell<usize>>);

    impl Drop for DropCount {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }

    #[test]
    fn negative_scope_moves_actual_value_without_dropping_it() {
        let drops = Rc::new(Cell::new(0));
        let mut destination = None;
        let result = (|| -> Result<(), ()> {
            let _actual = CaptureOnDropV1::new(DropCount(drops.clone()), Some(&mut destination));
            Err(())
        })();

        assert!(result.is_err());
        assert!(destination.is_some());
        assert_eq!(drops.get(), 0);
        drop(destination);
        assert_eq!(drops.get(), 1);
    }

    #[test]
    fn completed_transfer_and_leaf_disposal_leave_no_failed_destination() {
        let drops = Rc::new(Cell::new(0));
        let mut destination = None;
        let actual = CaptureOnDropV1::new(DropCount(drops.clone()), Some(&mut destination))
            .into_inner();

        assert!(destination.is_none());
        assert_eq!(drops.get(), 0);
        drop(actual);
        CaptureOnDropV1::new(DropCount(drops.clone()), Some(&mut destination))
            .discard_positive();
        assert!(destination.is_none());
        assert_eq!(drops.get(), 2);
    }

    #[test]
    fn missing_destination_keeps_scope_drop_and_consuming_iteration() {
        let drops = Rc::new(Cell::new(0));
        {
            let _ordinary = CaptureOnDropV1::new(DropCount(drops.clone()), None);
            assert_eq!(drops.get(), 0);
        }
        assert_eq!(drops.get(), 1);

        let mut ordinary = CaptureOnDropV1::new(vec![1, 2, 3], None);
        let mut iter = ordinary.iter_or_take();
        assert!(matches!(iter, RetainingIterV1::Ordinary(_)));
        assert_eq!(iter.next(), Some(1));
        assert_eq!(iter.next_back(), Some(3));
        assert_eq!(iter.next(), Some(2));
    }

    #[test]
    fn retained_iteration_keeps_the_same_whole_vector_on_early_return() {
        let mut destination = None;
        {
            let mut actual = CaptureOnDropV1::new(vec![1, 2, 3], Some(&mut destination));
            let mut iter = actual.iter_or_take();
            assert!(matches!(iter, RetainingIterV1::Retained(_)));
            assert_eq!(iter.next(), Some(1));
        }
        assert_eq!(destination, Some(vec![1, 2, 3]));
    }
}
