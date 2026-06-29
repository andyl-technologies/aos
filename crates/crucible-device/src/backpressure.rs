//! Deterministic full-ring backpressure modeled as a bounded FIFO.
//!
//! When a sub-node's inbound request ring or a consumer's response ring is full,
//! the producing side must *block at its current boundary* and resume when the
//! consumer frees a slot — never drop, reorder, or re-time a frame ([IO-32]).
//! This module owns [`BoundedQueue`], a fixed-capacity FIFO whose `push`/`pop`
//! semantics mirror the `crucible-shmem` SPSC ring
//! ([`crucible_shmem::RingHeader`]): a power-of-two capacity, monotonic
//! head/tail indices, `QueueFull` on a full ring, and a derived
//! [`BackpressureState`] that a futex waiter consults.
//!
//! The backpressure decision is a pure function of `(capacity, live depth)` —
//! never of host scheduling — so two runs that reach the same queue depth at the
//! same virtual time block and wake at byte-identical points.
//!
//! ```text
//! capacity = power of two
//! live     = write_idx - read_idx           (0 ..= capacity)
//! push     -> Err(PushError{item}) when live == capacity   (block here; IO-32)
//! pop      -> None                  when live == 0          (nothing to deliver)
//! state    -> Blocked when full, Runnable otherwise (the futex condition)
//! ```
//!
//! A full-ring `push` hands the rejected item *back* to the producer
//! ([`PushError`]) rather than dropping it, so a block-and-wake retry can
//! re-push the exact same frame without cloning ([IO-32], [SHM-26]).
//!
//! The in-process queue remains the test-double backing store. The production
//! shmem path in [`crate::subnode::IoCore::process_shmem_inbox`] and
//! [`crate::subnode::IoCore::advance_to_shmem`] uses real
//! [`crucible_shmem::RingHeader`] / [`crucible_shmem::FrameEntry`] storage plus
//! [`crucible_shmem::NodeSlot`] wake calls while preserving these same
//! block-and-wake semantics.

use std::collections::VecDeque;

use crate::error::DeviceError;

/// Whether a producer may proceed or must block on a full ring.
///
/// Mirrors the futex condition of [SHM-26]: a producer that observes
/// [`BackpressureState::Blocked`] parks at its current boundary and is woken
/// when [`BoundedQueue::pop`] frees a slot and the state returns to
/// [`BackpressureState::Runnable`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackpressureState {
    /// The ring has free space; a producer may push without blocking.
    Runnable,
    /// The ring is full; a producer must block until a consumer frees a slot.
    Blocked,
}

/// A full-ring `push` rejection that hands the unbuffered item back.
///
/// The producer blocked at its boundary ([IO-32]): the ring was full, so the
/// item was *not* enqueued and is returned here for a lossless re-push after a
/// consumer frees a slot. The `capacity` records the ring size for diagnostics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PushError<T> {
    /// The item that could not be enqueued, returned for a later retry.
    pub item: T,
    /// The fixed ring capacity in entries.
    pub capacity: u64,
}

impl<T> PushError<T> {
    /// Consumes the error and returns the rejected item.
    pub fn into_item(self) -> T {
        self.item
    }
}

/// A fixed-capacity FIFO mirroring SPSC-ring backpressure semantics.
///
/// Pushes onto a full ring fail with [`DeviceError::RingFull`] (the producer
/// blocks); pops drain in strict FIFO order. Monotonic `write_idx`/`read_idx`
/// counters make the live depth — and therefore the backpressure decision — a
/// pure function of how many items have been pushed and popped, independent of
/// host timing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BoundedQueue<T> {
    items: VecDeque<T>,
    capacity: u64,
    write_idx: u64,
    read_idx: u64,
}

impl<T> BoundedQueue<T> {
    /// Creates an empty bounded queue with a power-of-two capacity.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError::RingFull`] (re-purposed as the capacity-shape
    /// rejection) when `capacity` is zero or not a power of two, matching the
    /// SPSC ring's capacity contract ([SHM-19]).
    pub fn new(capacity: u64) -> Result<Self, DeviceError> {
        if capacity == 0 || !capacity.is_power_of_two() {
            return Err(DeviceError::RingFull { capacity });
        }
        Ok(Self {
            items: VecDeque::new(),
            capacity,
            write_idx: 0,
            read_idx: 0,
        })
    }

    /// Returns the fixed ring capacity in entries.
    #[must_use]
    pub fn capacity(&self) -> u64 {
        self.capacity
    }

    /// Returns the number of live (pushed-but-not-popped) entries.
    #[must_use]
    pub fn live(&self) -> u64 {
        self.write_idx - self.read_idx
    }

    /// Returns `true` when the ring is full and producers must block.
    #[must_use]
    pub fn is_full(&self) -> bool {
        self.live() == self.capacity
    }

    /// Returns `true` when the ring holds no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.live() == 0
    }

    /// Returns the producer's backpressure condition.
    #[must_use]
    pub fn state(&self) -> BackpressureState {
        if self.is_full() {
            BackpressureState::Blocked
        } else {
            BackpressureState::Runnable
        }
    }

    /// Pushes an entry, or hands it back as deterministic backpressure.
    ///
    /// On success the entry joins the tail and `write_idx` advances. On a full
    /// ring the entry is returned inside [`PushError`] so no data is lost — the
    /// producer blocks at its boundary and re-pushes the same item after the
    /// consumer drains ([IO-32]).
    ///
    /// # Errors
    ///
    /// Returns [`PushError`] (carrying `item`) when the ring is at capacity; the
    /// caller must wait for a [`BoundedQueue::pop`] before retrying ([IO-32]).
    pub fn push(&mut self, item: T) -> Result<(), PushError<T>> {
        if self.is_full() {
            return Err(PushError {
                item,
                capacity: self.capacity,
            });
        }
        self.items.push_back(item);
        self.write_idx += 1;
        Ok(())
    }

    /// Pops the head entry in FIFO order, or `None` when empty.
    ///
    /// A successful pop advances `read_idx`, freeing a slot and (if the ring was
    /// full) transitioning the producer's [`BackpressureState`] back to
    /// [`BackpressureState::Runnable`] — the wake condition of [IO-32].
    pub fn pop(&mut self) -> Option<T> {
        let item = self.items.pop_front()?;
        self.read_idx += 1;
        Some(item)
    }

    /// Returns a read-only view of the head entry without removing it.
    #[must_use]
    pub fn front(&self) -> Option<&T> {
        self.items.front()
    }

    /// Returns the live entries in FIFO order for snapshotting.
    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.items.iter()
    }
}

#[cfg(test)]
mod tests {
    use std::fmt::Debug;

    use super::*;

    /// Unwraps a result in tests, panicking with the error on failure.
    fn ok<T, E: Debug>(result: Result<T, E>) -> T {
        result.unwrap_or_else(|error| panic!("expected Ok, got {error:?}"))
    }

    #[test]
    fn rejects_non_power_of_two_capacity() {
        assert!(matches!(
            BoundedQueue::<u8>::new(0),
            Err(DeviceError::RingFull { .. })
        ));
        assert!(matches!(
            BoundedQueue::<u8>::new(3),
            Err(DeviceError::RingFull { .. })
        ));
        assert!(BoundedQueue::<u8>::new(4).is_ok());
    }

    #[test]
    fn full_ring_blocks_then_wakes_without_drop_or_reorder() {
        let mut queue = ok(BoundedQueue::new(2));
        ok(queue.push(10));
        ok(queue.push(20));
        assert_eq!(queue.state(), BackpressureState::Blocked);

        // Producer blocks: the third push is rejected, not dropped. The rejected
        // item is handed back inside the error for a lossless re-push.
        let rejected = match queue.push(30) {
            Err(error) => error,
            Ok(()) => panic!("a full ring must reject the push"),
        };
        assert_eq!(rejected.item, 30);
        assert_eq!(rejected.capacity, 2);

        // Consumer frees a slot -> producer wakes.
        assert_eq!(queue.pop(), Some(10));
        assert_eq!(queue.state(), BackpressureState::Runnable);

        // The retry re-pushes the exact handed-back item, preserving FIFO order.
        ok(queue.push(rejected.into_item()));
        assert_eq!(queue.pop(), Some(20));
        assert_eq!(queue.pop(), Some(30));
        assert_eq!(queue.pop(), None);
    }

    #[test]
    fn live_depth_tracks_push_and_pop() {
        let mut queue = ok(BoundedQueue::new(4));
        assert_eq!(queue.live(), 0);
        ok(queue.push(1));
        ok(queue.push(2));
        assert_eq!(queue.live(), 2);
        queue.pop();
        assert_eq!(queue.live(), 1);
    }
}
