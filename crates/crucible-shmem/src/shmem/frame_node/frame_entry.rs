//! Fixed-capacity shared-memory frame entry and its wire-layout constants.

use core::fmt;

use super::*;

/// A shared-memory frame whose delivery time is carried in band.
#[repr(C)]
pub struct FrameEntry {
    /// The consumer icount at which the frame becomes visible.
    pub delivery_icount: u64,
    /// The producer node id.
    pub src_node: u32,
    /// The per-producer sequence number.
    pub seq: u32,
    /// The number of valid bytes in [`FrameEntry::data`].
    pub len: u16,
    delivery_state: AtomicU8,
    pub(crate) _pad: [u8; 1],
    delivery_attempts: AtomicU32,
    last_delivery_attempt_icount: AtomicU64,
    /// The fixed-capacity frame payload buffer.
    pub data: [u8; MAX_FRAME_DATA],
}

/// Byte offset of [`FrameEntry`]'s delivery-icount field.
pub const FRAME_ENTRY_DELIVERY_ICOUNT_OFFSET: usize =
    core::mem::offset_of!(FrameEntry, delivery_icount);
/// Byte offset of [`FrameEntry`]'s source-node field.
pub const FRAME_ENTRY_SRC_NODE_OFFSET: usize = core::mem::offset_of!(FrameEntry, src_node);
/// Byte offset of [`FrameEntry`]'s producer-sequence field.
pub const FRAME_ENTRY_SEQ_OFFSET: usize = core::mem::offset_of!(FrameEntry, seq);
/// Byte offset of [`FrameEntry`]'s payload-length field.
pub const FRAME_ENTRY_LEN_OFFSET: usize = core::mem::offset_of!(FrameEntry, len);
/// Byte offset of [`FrameEntry`]'s consumer-owned delivery state.
pub const FRAME_ENTRY_DELIVERY_STATE_OFFSET: usize =
    core::mem::offset_of!(FrameEntry, delivery_state);
/// Byte offset of [`FrameEntry`]'s reserved padding bytes.
pub const FRAME_ENTRY_PAD_OFFSET: usize = core::mem::offset_of!(FrameEntry, _pad);
/// Byte offset of [`FrameEntry`]'s consumer-owned delivery-attempt count.
pub const FRAME_ENTRY_DELIVERY_ATTEMPTS_OFFSET: usize =
    core::mem::offset_of!(FrameEntry, delivery_attempts);
/// Byte offset of [`FrameEntry`]'s last concrete delivery-attempt coordinate.
pub const FRAME_ENTRY_LAST_DELIVERY_ATTEMPT_ICOUNT_OFFSET: usize =
    core::mem::offset_of!(FrameEntry, last_delivery_attempt_icount);
/// Byte offset of [`FrameEntry`]'s payload data.
pub const FRAME_ENTRY_DATA_OFFSET: usize = core::mem::offset_of!(FrameEntry, data);
/// Wire size of one [`FrameEntry`].
pub const FRAME_ENTRY_SIZE: usize = core::mem::size_of::<FrameEntry>();
/// Wire alignment of one [`FrameEntry`].
pub const FRAME_ENTRY_ALIGN: usize = core::mem::align_of::<FrameEntry>();

const _: () = assert!(FRAME_ENTRY_DELIVERY_ICOUNT_OFFSET == 0);
const _: () = assert!(FRAME_ENTRY_SRC_NODE_OFFSET == 8);
const _: () = assert!(FRAME_ENTRY_SEQ_OFFSET == 12);
const _: () = assert!(FRAME_ENTRY_LEN_OFFSET == 16);
const _: () = assert!(FRAME_ENTRY_DELIVERY_STATE_OFFSET == 18);
const _: () = assert!(FRAME_ENTRY_PAD_OFFSET == 19);
const _: () = assert!(FRAME_ENTRY_DELIVERY_ATTEMPTS_OFFSET == 20);
const _: () = assert!(FRAME_ENTRY_LAST_DELIVERY_ATTEMPT_ICOUNT_OFFSET == 24);
const _: () = assert!(FRAME_ENTRY_DATA_OFFSET == 32);
const _: () = assert!(FRAME_ENTRY_SIZE == FRAME_ENTRY_DATA_OFFSET + MAX_FRAME_DATA);
const _: () = assert!(FRAME_ENTRY_ALIGN == 8);
const _: () = assert!(core::mem::offset_of!(FrameEntry, delivery_icount) == 0);
const _: () = assert!(core::mem::offset_of!(FrameEntry, src_node) == 8);
const _: () = assert!(core::mem::offset_of!(FrameEntry, seq) == 12);
const _: () = assert!(core::mem::offset_of!(FrameEntry, len) == 16);
const _: () = assert!(core::mem::offset_of!(FrameEntry, delivery_state) == 18);
const _: () = assert!(core::mem::offset_of!(FrameEntry, data) == FRAME_ENTRY_DATA_OFFSET);
#[rustfmt::skip]
 const _: () = assert!(core::mem::size_of::<FrameEntry>() == FRAME_ENTRY_DATA_OFFSET + MAX_FRAME_DATA);
const _: () = assert!(core::mem::align_of::<FrameEntry>() == 8);

impl FrameEntry {
    /// Builds a frame entry with an in-band delivery icount.
    ///
    /// # Errors
    ///
    /// Returns [`FrameEntryError::PayloadLengthExceedsCapacity`] when `payload`
    /// is too large for [`MAX_FRAME_DATA`].
    pub fn new(
        delivery_icount: u64,
        src_node: u32,
        seq: u32,
        payload: &[u8],
    ) -> Result<Self, FrameEntryError> {
        if payload.len() > MAX_FRAME_DATA {
            return Err(FrameEntryError::PayloadLengthExceedsCapacity {
                len: payload.len(),
                capacity: MAX_FRAME_DATA,
            });
        }

        let mut data = [0; MAX_FRAME_DATA];
        data[..payload.len()].copy_from_slice(payload);

        Ok(Self {
            delivery_icount,
            src_node,
            seq,
            len: payload.len() as u16,
            delivery_state: AtomicU8::new(FRAME_DELIVERY_PENDING),
            _pad: [0; 1],
            delivery_attempts: AtomicU32::new(0),
            last_delivery_attempt_icount: AtomicU64::new(0),
            data,
        })
    }

    /// Returns the consumer-owned canonical delivery state.
    ///
    /// # Errors
    ///
    /// Returns [`FrameDeliveryStateError::UnknownState`] when the shared state
    /// byte is not defined by this ABI version.
    pub fn delivery_state(&self) -> Result<FrameDeliveryState, FrameDeliveryStateError> {
        match self.delivery_state.load(Ordering::Acquire) {
            FRAME_DELIVERY_PENDING => Ok(FrameDeliveryState::Pending),
            FRAME_DELIVERY_RETAINED => Ok(FrameDeliveryState::Retained),
            state => Err(FrameDeliveryStateError::UnknownState { state }),
        }
    }

    /// Marks this live consumer-owned frame as retained after backpressure.
    ///
    /// The transition is idempotent so a deterministic retry that remains
    /// backpressured preserves the same canonical proof.
    ///
    /// # Errors
    ///
    /// Returns [`FrameDeliveryStateError::UnknownState`] when the shared state
    /// byte is not defined by this ABI version.
    pub fn mark_delivery_retained(&self) -> Result<(), FrameDeliveryStateError> {
        match self.delivery_state.compare_exchange(
            FRAME_DELIVERY_PENDING,
            FRAME_DELIVERY_RETAINED,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) | Err(FRAME_DELIVERY_RETAINED) => Ok(()),
            Err(state) => Err(FrameDeliveryStateError::UnknownState { state }),
        }
    }

    /// Returns the number of concrete guest delivery attempts for this frame.
    #[must_use]
    pub fn delivery_attempts(&self) -> u32 {
        self.delivery_attempts.load(Ordering::Acquire)
    }

    /// Returns the guest coordinate of the most recent retained delivery attempt.
    #[must_use]
    pub fn last_delivery_attempt_icount(&self) -> u64 {
        self.last_delivery_attempt_icount.load(Ordering::Acquire)
    }

    /// Records one concrete guest delivery attempt under a fixed hard bound.
    ///
    /// # Errors
    ///
    /// Returns [`FrameDeliveryAttemptError`] without modifying shared state
    /// when the coordinate precedes delivery, does not advance beyond the
    /// previous attempt, or `limit` attempts have already occurred.
    pub fn record_delivery_attempt(
        &self,
        current_icount: u64,
        limit: u32,
    ) -> Result<u32, FrameDeliveryAttemptError> {
        if current_icount < self.delivery_icount {
            return Err(FrameDeliveryAttemptError::CoordinateBeforeDelivery {
                delivery_icount: self.delivery_icount,
                current_icount,
            });
        }
        let previous_attempts = self.delivery_attempts();
        let previous_icount = self.last_delivery_attempt_icount();
        if previous_attempts > 0 && current_icount <= previous_icount {
            return Err(FrameDeliveryAttemptError::NonIncreasingCoordinate {
                previous_icount,
                current_icount,
            });
        }
        let attempts = self
            .delivery_attempts
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                (current < limit).then(|| current + 1)
            })
            .map(|previous| previous + 1)
            .map_err(|attempts| FrameDeliveryAttemptError::LimitReached { attempts, limit })?;
        self.last_delivery_attempt_icount
            .store(current_icount, Ordering::Release);
        Ok(attempts)
    }

    pub(crate) fn restore_delivery_attempt(&self, attempts: u32, last_attempt_icount: u64) {
        self.delivery_attempts.store(attempts, Ordering::Release);
        self.last_delivery_attempt_icount
            .store(last_attempt_icount, Ordering::Release);
    }

    /// Returns `true` when this frame is visible at `consumer_current_icount`.
    #[must_use]
    pub fn is_deliverable_at(&self, consumer_current_icount: u64) -> bool {
        self.delivery_icount <= consumer_current_icount
    }

    /// Returns the deterministic per-consumer delivery-order key.
    #[must_use]
    pub fn delivery_key(&self) -> FrameDeliveryKey {
        FrameDeliveryKey {
            delivery_icount: self.delivery_icount,
            src_node: self.src_node,
            seq: self.seq,
        }
    }

    /// Returns the valid payload bytes.
    ///
    /// # Errors
    ///
    /// Returns [`FrameEntryError::PayloadLengthExceedsCapacity`] when a frame
    /// read from shared memory advertises a length greater than
    /// [`MAX_FRAME_DATA`].
    pub fn payload(&self) -> Result<&[u8], FrameEntryError> {
        let len = usize::from(self.len);
        if len > MAX_FRAME_DATA {
            Err(FrameEntryError::PayloadLengthExceedsCapacity {
                len,
                capacity: MAX_FRAME_DATA,
            })
        } else {
            Ok(&self.data[..len])
        }
    }

    /// Returns `true` when the frame-entry padding bytes are zero.
    #[must_use]
    pub fn padding_bytes_are_zero(&self) -> bool {
        self._pad.iter().all(|byte| *byte == 0)
    }

    pub(crate) fn canonicalized_for_snapshot(&self) -> Result<Self, SpscRingError> {
        let len = usize::from(self.len);
        if len > MAX_FRAME_DATA {
            return Err(SpscRingError::InvalidFrameLength {
                len,
                capacity: MAX_FRAME_DATA,
            });
        }
        let delivery_state =
            self.delivery_state()
                .map_err(|FrameDeliveryStateError::UnknownState { state }| {
                    SpscRingError::InvalidFrameDeliveryState { state }
                })?;
        let delivery_attempts = self.delivery_attempts();
        let last_attempt_icount = self.last_delivery_attempt_icount();
        match delivery_state {
            FrameDeliveryState::Pending if delivery_attempts != 0 || last_attempt_icount != 0 => {
                return Err(SpscRingError::InvalidFrameDeliveryAttempts {
                    state: delivery_state as u8,
                    attempts: delivery_attempts,
                });
            }
            FrameDeliveryState::Retained
                if delivery_attempts == 0 || delivery_attempts > MAX_FRAME_DELIVERY_ATTEMPTS =>
            {
                return Err(SpscRingError::InvalidFrameDeliveryAttempts {
                    state: delivery_state as u8,
                    attempts: delivery_attempts,
                });
            }
            FrameDeliveryState::Retained if last_attempt_icount < self.delivery_icount => {
                return Err(SpscRingError::InvalidFrameDeliveryAttemptIcount {
                    delivery_icount: self.delivery_icount,
                    attempt_icount: last_attempt_icount,
                });
            }
            _ => {}
        }

        let mut canonical = self.clone();
        canonical._pad = [0; 1];
        canonical.data[len..].fill(0);
        Ok(canonical)
    }
}

/// Consumer-owned state for one canonical inbound delivery.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameDeliveryState {
    /// The consumer has not reported guest backpressure for this frame.
    Pending = FRAME_DELIVERY_PENDING,
    /// A real guest delivery attempt was backpressured and must be retried.
    Retained = FRAME_DELIVERY_RETAINED,
}

/// Wire value for a frame that has not been backpressured.
pub const FRAME_DELIVERY_PENDING: u8 = 0;
/// Wire value for a frame retained after guest backpressure.
pub const FRAME_DELIVERY_RETAINED: u8 = 1;
/// Hard ceiling on retained guest RX attempts represented by the public ABI.
pub const MAX_FRAME_DELIVERY_ATTEMPTS: u32 = 1_024;

/// Failure to admit another concrete guest delivery attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum FrameDeliveryAttemptError {
    /// The canonical attempt counter reached its fixed limit.
    #[error("frame delivery attempt limit reached: attempts={attempts}, limit={limit}")]
    LimitReached {
        /// Attempts already made for this frame.
        attempts: u32,
        /// Maximum attempts admitted for this frame.
        limit: u32,
    },
    /// An attempt was recorded before the frame became visible.
    #[error(
        "frame delivery attempt coordinate {current_icount} precedes delivery {delivery_icount}"
    )]
    CoordinateBeforeDelivery {
        /// The frame's canonical delivery coordinate.
        delivery_icount: u64,
        /// The rejected concrete attempt coordinate.
        current_icount: u64,
    },
    /// A retry did not advance beyond the previous concrete attempt.
    #[error(
        "frame delivery attempt coordinate {current_icount} did not advance past {previous_icount}"
    )]
    NonIncreasingCoordinate {
        /// The last admitted concrete attempt coordinate.
        previous_icount: u64,
        /// The rejected retry coordinate.
        current_icount: u64,
    },
}

impl Clone for FrameEntry {
    fn clone(&self) -> Self {
        Self {
            delivery_icount: self.delivery_icount,
            src_node: self.src_node,
            seq: self.seq,
            len: self.len,
            delivery_state: AtomicU8::new(self.delivery_state.load(Ordering::Acquire)),
            _pad: self._pad,
            delivery_attempts: AtomicU32::new(self.delivery_attempts.load(Ordering::Acquire)),
            last_delivery_attempt_icount: AtomicU64::new(
                self.last_delivery_attempt_icount.load(Ordering::Acquire),
            ),
            data: self.data,
        }
    }
}

impl fmt::Debug for FrameEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FrameEntry")
            .field("delivery_icount", &self.delivery_icount)
            .field("src_node", &self.src_node)
            .field("seq", &self.seq)
            .field("len", &self.len)
            .field(
                "delivery_state",
                &self.delivery_state.load(Ordering::Acquire),
            )
            .field(
                "delivery_attempts",
                &self.delivery_attempts.load(Ordering::Acquire),
            )
            .field(
                "last_delivery_attempt_icount",
                &self.last_delivery_attempt_icount.load(Ordering::Acquire),
            )
            .field("data", &self.data)
            .finish()
    }
}

impl PartialEq for FrameEntry {
    fn eq(&self, other: &Self) -> bool {
        self.delivery_icount == other.delivery_icount
            && self.src_node == other.src_node
            && self.seq == other.seq
            && self.len == other.len
            && self.delivery_state.load(Ordering::Acquire)
                == other.delivery_state.load(Ordering::Acquire)
            && self._pad == other._pad
            && self.delivery_attempts.load(Ordering::Acquire)
                == other.delivery_attempts.load(Ordering::Acquire)
            && self.last_delivery_attempt_icount.load(Ordering::Acquire)
                == other.last_delivery_attempt_icount.load(Ordering::Acquire)
            && self.data == other.data
    }
}

impl Eq for FrameEntry {}

impl Default for FrameEntry {
    fn default() -> Self {
        Self {
            delivery_icount: 0,
            src_node: 0,
            seq: 0,
            len: 0,
            delivery_state: AtomicU8::new(FRAME_DELIVERY_PENDING),
            _pad: [0; 1],
            delivery_attempts: AtomicU32::new(0),
            last_delivery_attempt_icount: AtomicU64::new(0),
            data: [0; MAX_FRAME_DATA],
        }
    }
}
