//! Network transmit interception and outbound ring enqueueing.
//!
//! The QEMU TX callback hands guest-emitted Ethernet frames to this module. The
//! core owns only registration-time-fixed metadata and a per-ring sequence
//! counter; callers provide the already-mapped outbound ring storage for
//! `(vm_slot -> SLOT_NET_ROUTER)`.

use std::{
    cell::Cell,
    os::raw::{c_int, c_void},
};

use thiserror::Error;

use crucible_shmem::{DirectedRing, FrameEntry, RingHeader, SLOT_NET_ROUTER, SpscRingError};

use crate::shmem_ordering::PluginShmemOrdering;

const NET_ROUTER_SLOT_U32: u32 = SLOT_NET_ROUTER as u32;
/// QEMU plugin API symbol used to register network TX interception.
pub const QEMU_PLUGIN_REGISTER_NET_TX_CB_SYMBOL: &str = "qemu_plugin_register_net_tx_cb";
const QEMU_PLUGIN_REGISTER_NET_TX_CB_SYMBOL_C: &[u8] = b"qemu_plugin_register_net_tx_cb\0";

/// Network TX callback body passed to QEMU's transmit path.
pub type QemuNetTxCbFn = extern "C" fn(*const u8, usize, *mut c_void) -> c_int;
/// QEMU network TX callback registration exported by `crucible-net-tx-callback`.
pub type QemuRegisterNetTxCbFn = extern "C" fn(Option<QemuNetTxCbFn>, *mut c_void);

/// Resolves QEMU's network TX callback registration export from the loaded process.
#[cfg(unix)]
#[must_use]
pub fn resolve_qemu_register_net_tx_cb_symbol() -> Option<QemuRegisterNetTxCbFn> {
    // SAFETY: `dlsym` receives a static NUL-terminated symbol name and returns
    // either null or a process symbol address. The QEMU patch defines this
    // symbol with the exact `QemuRegisterNetTxCbFn` ABI; callers fail closed
    // when it is absent.
    let symbol = unsafe {
        libc::dlsym(
            libc::RTLD_DEFAULT,
            QEMU_PLUGIN_REGISTER_NET_TX_CB_SYMBOL_C.as_ptr().cast(),
        )
    };
    if symbol.is_null() {
        None
    } else {
        // SAFETY: Non-null `symbol` was resolved for
        // `qemu_plugin_register_net_tx_cb`, whose patched QEMU declaration
        // matches `QemuRegisterNetTxCbFn`.
        Some(unsafe { std::mem::transmute::<*mut c_void, QemuRegisterNetTxCbFn>(symbol) })
    }
}

/// Resolves QEMU's network TX callback registration export from the loaded process.
#[cfg(not(unix))]
#[must_use]
pub const fn resolve_qemu_register_net_tx_cb_symbol() -> Option<QemuRegisterNetTxCbFn> {
    None
}

/// Registration-time-fixed network TX enqueue state.
#[derive(Debug)]
pub struct PluginNetworkTx {
    src_slot: u32,
    dst_slot: u32,
    ring_index: u32,
    next_seq: Cell<u32>,
}

impl PluginNetworkTx {
    /// Builds a TX state object from the directed ring selected at registration.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkTxError::WrongOutboundRing`] when `ring` is not the
    /// outbound network-router ring for `src_slot`.
    pub fn from_directed_ring(src_slot: u32, ring: DirectedRing) -> Result<Self, NetworkTxError> {
        if ring.src_slot != src_slot || ring.dst_slot != NET_ROUTER_SLOT_U32 {
            return Err(NetworkTxError::WrongOutboundRing {
                expected_src_slot: src_slot,
                expected_dst_slot: NET_ROUTER_SLOT_U32,
                expected_ring_index: None,
                actual_src_slot: ring.src_slot,
                actual_dst_slot: ring.dst_slot,
                actual_ring_index: ring.index,
            });
        }

        Ok(Self::new(src_slot, ring.index))
    }

    /// Builds a TX state object for the outbound network-router ring.
    #[must_use]
    pub const fn new(src_slot: u32, ring_index: u32) -> Self {
        Self {
            src_slot,
            dst_slot: NET_ROUTER_SLOT_U32,
            ring_index,
            next_seq: Cell::new(0),
        }
    }

    /// Returns the VM slot whose guest frames this TX state emits.
    #[must_use]
    pub const fn src_slot(&self) -> u32 {
        self.src_slot
    }

    /// Returns the reserved network-router destination slot.
    #[must_use]
    pub const fn dst_slot(&self) -> u32 {
        self.dst_slot
    }

    /// Returns the directed ring index fixed during registration.
    #[must_use]
    pub const fn ring_index(&self) -> u32 {
        self.ring_index
    }

    /// Returns the next sequence number that a successful enqueue will assign.
    #[must_use]
    pub fn next_seq(&self) -> u32 {
        self.next_seq.get()
    }

    /// Enqueues one guest-emitted frame into the outbound network-router ring.
    ///
    /// The `emit_icount` is copied into [`FrameEntry::delivery_icount`]. The
    /// network router later re-stamps that field with link latency before
    /// delivery.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkTxError::WrongOutboundRing`] if the supplied ring view
    /// does not match registration-time-fixed state,
    /// [`NetworkTxError::PayloadTooLarge`] when `payload` exceeds
    /// [`crucible_shmem::MAX_FRAME_DATA`], [`NetworkTxError::SequenceOverflow`]
    /// when the per-ring sequence counter is exhausted, or
    /// [`NetworkTxError::RingOperation`] when the SPSC enqueue fails, including
    /// a full ring.
    pub fn enqueue_guest_frame(
        &self,
        ring: &mut NetworkTxRing<'_>,
        emit_icount: u64,
        payload: &[u8],
    ) -> Result<NetworkTxEnqueue, NetworkTxError> {
        self.check_ring(ring)?;

        let seq = self.next_seq.get();
        let frame = FrameEntry::new(emit_icount, self.src_slot, seq, payload).map_err(
            |crucible_shmem::FrameEntryError::PayloadLengthExceedsCapacity { len, capacity }| {
                NetworkTxError::PayloadTooLarge { len, capacity }
            },
        )?;
        let next_seq = seq.checked_add(1).ok_or(NetworkTxError::SequenceOverflow {
            ring_index: self.ring_index,
            next_seq: seq,
        })?;

        PluginShmemOrdering::enqueue_outbound_frame(ring.header, ring.entries, &frame).map_err(
            |source| NetworkTxError::RingOperation {
                ring_index: self.ring_index,
                source,
            },
        )?;
        self.next_seq.set(next_seq);

        Ok(NetworkTxEnqueue {
            ring_index: self.ring_index,
            emit_icount,
            src_slot: self.src_slot,
            dst_slot: self.dst_slot,
            seq,
            payload_len: payload.len(),
            next_seq,
        })
    }

    /// Enqueues a deterministic batch at one completion-boundary icount.
    ///
    /// The complete batch is validated against payload, sequence, and ring
    /// capacity limits before the first shared-memory write. This is used for
    /// frames emitted by timer bottom halves while a queued idle advance is
    /// pending: none become visible to the router until QEMU validates the
    /// exact completed target.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::enqueue_guest_frame`]. Capacity and
    /// sequence exhaustion are checked for the whole batch before any enqueue.
    pub fn enqueue_guest_frame_batch(
        &self,
        ring: &mut NetworkTxRing<'_>,
        emit_icount: u64,
        payloads: &[Vec<u8>],
    ) -> Result<Vec<NetworkTxEnqueue>, NetworkTxError> {
        self.check_ring(ring)?;
        let capacity = validated_batch_capacity(ring, payloads.len())?;
        let first_seq = self.next_seq.get();
        let batch_len =
            u32::try_from(payloads.len()).map_err(|_error| NetworkTxError::SequenceOverflow {
                ring_index: self.ring_index,
                next_seq: first_seq,
            })?;
        let final_next_seq =
            first_seq
                .checked_add(batch_len)
                .ok_or(NetworkTxError::SequenceOverflow {
                    ring_index: self.ring_index,
                    next_seq: first_seq,
                })?;

        let mut frames = Vec::with_capacity(payloads.len());
        for (offset, payload) in payloads.iter().enumerate() {
            let offset =
                u32::try_from(offset).map_err(|_error| NetworkTxError::SequenceOverflow {
                    ring_index: self.ring_index,
                    next_seq: first_seq,
                })?;
            let seq = first_seq
                .checked_add(offset)
                .ok_or(NetworkTxError::SequenceOverflow {
                    ring_index: self.ring_index,
                    next_seq: first_seq,
                })?;
            let frame = FrameEntry::new(emit_icount, self.src_slot, seq, payload).map_err(
                |crucible_shmem::FrameEntryError::PayloadLengthExceedsCapacity {
                     len,
                     capacity,
                 }| NetworkTxError::PayloadTooLarge { len, capacity },
            )?;
            frames.push((seq, frame, payload.len()));
        }

        let mut enqueues = Vec::with_capacity(frames.len());
        for (seq, frame, payload_len) in frames {
            PluginShmemOrdering::enqueue_outbound_frame(ring.header, ring.entries, &frame)
                .map_err(|source| NetworkTxError::RingOperation {
                    ring_index: self.ring_index,
                    source,
                })?;
            enqueues.push(NetworkTxEnqueue {
                ring_index: self.ring_index,
                emit_icount,
                src_slot: self.src_slot,
                dst_slot: self.dst_slot,
                seq,
                payload_len,
                next_seq: seq + 1,
            });
        }
        debug_assert_eq!(capacity, ring.entries.len() as u64);
        self.next_seq.set(final_next_seq);
        Ok(enqueues)
    }

    /// Checks whether a pending completion batch still fits without mutation.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkTxError::WrongOutboundRing`] for another ring or
    /// [`NetworkTxError::RingOperation`] for invalid/full ring state.
    pub fn preflight_guest_frame_batch(
        &self,
        ring: &NetworkTxRing<'_>,
        batch_len: usize,
    ) -> Result<(), NetworkTxError> {
        self.check_ring(ring)?;
        validated_batch_capacity(ring, batch_len).map(|_capacity| ())
    }

    fn check_ring(&self, ring: &NetworkTxRing<'_>) -> Result<(), NetworkTxError> {
        if ring.ring_index != self.ring_index
            || ring.src_slot != self.src_slot
            || ring.dst_slot != self.dst_slot
        {
            Err(NetworkTxError::WrongOutboundRing {
                expected_src_slot: self.src_slot,
                expected_dst_slot: self.dst_slot,
                expected_ring_index: Some(self.ring_index),
                actual_src_slot: ring.src_slot,
                actual_dst_slot: ring.dst_slot,
                actual_ring_index: ring.ring_index,
            })
        } else {
            Ok(())
        }
    }
}

fn validated_batch_capacity(
    ring: &NetworkTxRing<'_>,
    batch_len: usize,
) -> Result<u64, NetworkTxError> {
    let capacity = ring.entries.len();
    if !capacity.is_power_of_two() {
        return Err(NetworkTxError::RingOperation {
            ring_index: ring.ring_index,
            source: SpscRingError::InvalidCapacity { capacity },
        });
    }
    let capacity = capacity as u64;
    let read_idx = ring.header.read_index();
    let write_idx = ring.header.write_index();
    let live = write_idx.wrapping_sub(read_idx);
    if live > capacity {
        return Err(NetworkTxError::RingOperation {
            ring_index: ring.ring_index,
            source: SpscRingError::CorruptIndices {
                read_idx,
                write_idx,
                capacity,
            },
        });
    }
    let batch_len = u64::try_from(batch_len).unwrap_or(u64::MAX);
    if batch_len > capacity - live {
        return Err(NetworkTxError::RingOperation {
            ring_index: ring.ring_index,
            source: SpscRingError::QueueFull { capacity },
        });
    }
    Ok(capacity)
}

/// Handles one guest network-TX callback using registration-fixed state.
///
/// This is the safe body for the QEMU-facing `qemu_plugin_register_net_tx_cb`
/// callback once the raw patch signature is bound. It performs no global lookup
/// and takes no locks; callers supply the fixed TX state and outbound ring view.
///
/// # Errors
///
/// Returns [`NetworkTxError`] when the supplied ring is not the fixed outbound
/// router ring, the payload is oversized, the sequence counter is exhausted, or
/// the SPSC enqueue fails.
pub fn handle_network_tx_callback(
    tx: &PluginNetworkTx,
    ring: &mut NetworkTxRing<'_>,
    emit_icount: u64,
    payload: &[u8],
) -> Result<NetworkTxEnqueue, NetworkTxError> {
    tx.enqueue_guest_frame(ring, emit_icount, payload)
}

/// A mutable view of the outbound network-router ring storage.
pub struct NetworkTxRing<'a> {
    ring_index: u32,
    src_slot: u32,
    dst_slot: u32,
    header: &'a RingHeader,
    entries: &'a mut [FrameEntry],
}

impl<'a> NetworkTxRing<'a> {
    /// Builds an outbound network TX ring view.
    #[must_use]
    pub fn new(
        ring_index: u32,
        src_slot: u32,
        dst_slot: u32,
        header: &'a RingHeader,
        entries: &'a mut [FrameEntry],
    ) -> Self {
        Self {
            ring_index,
            src_slot,
            dst_slot,
            header,
            entries,
        }
    }

    /// Returns the directed ring index used for diagnostics.
    #[must_use]
    pub const fn ring_index(&self) -> u32 {
        self.ring_index
    }

    /// Returns the producer slot represented by this ring.
    #[must_use]
    pub const fn src_slot(&self) -> u32 {
        self.src_slot
    }

    /// Returns the consumer slot represented by this ring.
    #[must_use]
    pub const fn dst_slot(&self) -> u32 {
        self.dst_slot
    }
}

/// Metadata returned after one successful TX enqueue.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetworkTxEnqueue {
    ring_index: u32,
    emit_icount: u64,
    src_slot: u32,
    dst_slot: u32,
    seq: u32,
    payload_len: usize,
    next_seq: u32,
}

impl NetworkTxEnqueue {
    /// Returns the outbound directed ring index.
    #[must_use]
    pub const fn ring_index(&self) -> u32 {
        self.ring_index
    }

    /// Returns the guest icount stamped onto the frame.
    #[must_use]
    pub const fn emit_icount(&self) -> u64 {
        self.emit_icount
    }

    /// Returns the VM source slot stamped onto the frame.
    #[must_use]
    pub const fn src_slot(&self) -> u32 {
        self.src_slot
    }

    /// Returns the reserved network-router destination slot.
    #[must_use]
    pub const fn dst_slot(&self) -> u32 {
        self.dst_slot
    }

    /// Returns the per-ring sequence stamped onto the frame.
    #[must_use]
    pub const fn seq(&self) -> u32 {
        self.seq
    }

    /// Returns the number of payload bytes accepted from QEMU.
    #[must_use]
    pub const fn payload_len(&self) -> usize {
        self.payload_len
    }

    /// Returns the next sequence number after this enqueue.
    #[must_use]
    pub const fn next_seq(&self) -> u32 {
        self.next_seq
    }
}

/// An error produced by network TX interception.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum NetworkTxError {
    /// The callback was handed a ring other than the fixed outbound router ring.
    #[error(
        "network TX ring mismatch: expected src={expected_src_slot} dst={expected_dst_slot} ring={expected_ring_index:?}, got src={actual_src_slot} dst={actual_dst_slot} ring={actual_ring_index}"
    )]
    WrongOutboundRing {
        /// The VM slot fixed at registration.
        expected_src_slot: u32,
        /// The reserved router slot fixed at registration.
        expected_dst_slot: u32,
        /// The directed ring index fixed at registration, if known.
        expected_ring_index: Option<u32>,
        /// The supplied ring's producer slot.
        actual_src_slot: u32,
        /// The supplied ring's consumer slot.
        actual_dst_slot: u32,
        /// The supplied ring's directed ring index.
        actual_ring_index: u32,
    },
    /// The guest frame payload is too large for the shmem ABI frame.
    #[error("network TX payload length {len} exceeds frame capacity {capacity}")]
    PayloadTooLarge {
        /// The rejected payload length.
        len: usize,
        /// The maximum frame payload capacity.
        capacity: usize,
    },
    /// The per-ring sequence counter cannot represent another frame.
    #[error("network TX ring {ring_index} sequence overflow at {next_seq}")]
    SequenceOverflow {
        /// The directed ring index.
        ring_index: u32,
        /// The sequence value that could not be assigned.
        next_seq: u32,
    },
    /// The SPSC ring enqueue failed.
    #[error("network TX ring {ring_index} enqueue failed: {source}")]
    RingOperation {
        /// The directed ring index.
        ring_index: u32,
        /// The underlying SPSC ring failure.
        source: SpscRingError,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    use crucible_shmem::{MAX_FRAME_DATA, RegionConfig, RegionLayout, ReservedExecutorSlot};

    #[test]
    fn network_tx_state_binds_registration_time_router_ring() {
        let layout = layout();
        let router_ring = router_outbound_ring(layout, 1);
        let tx = match PluginNetworkTx::from_directed_ring(1, router_ring) {
            Ok(tx) => tx,
            Err(error) => panic!("router ring should bind: {error}"),
        };

        assert_eq!(tx.src_slot(), 1);
        assert_eq!(tx.dst_slot(), NET_ROUTER_SLOT_U32);
        assert_eq!(tx.ring_index(), router_ring.index);
        assert_eq!(tx.next_seq(), 0);

        let block_ring = DirectedRing {
            index: router_ring.index + 1,
            src_slot: 1,
            dst_slot: ReservedExecutorSlot::BlockIo.slot() as u32,
        };
        let error = match PluginNetworkTx::from_directed_ring(1, block_ring) {
            Ok(_) => panic!("block ring must not bind as network TX"),
            Err(error) => error,
        };
        assert_eq!(
            error,
            NetworkTxError::WrongOutboundRing {
                expected_src_slot: 1,
                expected_dst_slot: NET_ROUTER_SLOT_U32,
                expected_ring_index: None,
                actual_src_slot: 1,
                actual_dst_slot: ReservedExecutorSlot::BlockIo.slot() as u32,
                actual_ring_index: block_ring.index,
            }
        );

        let wrong_producer_ring = DirectedRing {
            index: router_ring.index,
            src_slot: 0,
            dst_slot: NET_ROUTER_SLOT_U32,
        };
        let error = match PluginNetworkTx::from_directed_ring(1, wrong_producer_ring) {
            Ok(_) => panic!("wrong producer must not bind as this node's network TX"),
            Err(error) => error,
        };
        assert_eq!(
            error,
            NetworkTxError::WrongOutboundRing {
                expected_src_slot: 1,
                expected_dst_slot: NET_ROUTER_SLOT_U32,
                expected_ring_index: None,
                actual_src_slot: 0,
                actual_dst_slot: NET_ROUTER_SLOT_U32,
                actual_ring_index: wrong_producer_ring.index,
            }
        );
    }

    #[test]
    fn network_tx_enqueue_stamps_emit_icount_source_sequence_and_payload() {
        let header = RingHeader::new();
        let mut entries = empty_entries(4);
        let tx = PluginNetworkTx::new(2, 12);
        let mut ring = ring_view(12, 2, &header, &mut entries);

        let first = enqueue(&tx, &mut ring, 77, b"alpha");
        let second = enqueue(&tx, &mut ring, 78, b"beta");

        assert_eq!(first.emit_icount(), 77);
        assert_eq!(first.src_slot(), 2);
        assert_eq!(first.dst_slot(), NET_ROUTER_SLOT_U32);
        assert_eq!(first.seq(), 0);
        assert_eq!(first.payload_len(), 5);
        assert_eq!(first.next_seq(), 1);
        assert_eq!(second.seq(), 1);
        assert_eq!(second.next_seq(), 2);
        assert_eq!(tx.next_seq(), 2);
        assert_eq!(header.write_index(), 2);
        assert_frame(&ring.entries[0], 77, 2, 0, b"alpha");
        assert_frame(&ring.entries[1], 78, 2, 1, b"beta");
    }

    #[test]
    fn network_tx_safe_callback_body_delegates_to_fixed_enqueue_state() {
        let header = RingHeader::new();
        let mut entries = empty_entries(4);
        let tx = PluginNetworkTx::new(2, 12);
        let mut ring = ring_view(12, 2, &header, &mut entries);

        let result = match handle_network_tx_callback(&tx, &mut ring, 88, b"callback-frame") {
            Ok(result) => result,
            Err(error) => panic!("safe TX callback body should enqueue: {error}"),
        };

        assert_eq!(result.ring_index(), 12);
        assert_eq!(result.emit_icount(), 88);
        assert_eq!(result.seq(), 0);
        assert_eq!(tx.next_seq(), 1);
        assert_frame(&ring.entries[0], 88, 2, 0, b"callback-frame");
    }

    #[test]
    fn network_tx_rejects_wrong_ring_without_enqueuing_or_advancing_sequence() {
        let header = RingHeader::new();
        let mut entries = empty_entries(4);
        let tx = PluginNetworkTx::new(2, 12);
        let mut ring = NetworkTxRing::new(13, 2, NET_ROUTER_SLOT_U32, &header, &mut entries);

        assert_eq!(
            tx.enqueue_guest_frame(&mut ring, 77, b"alpha"),
            Err(NetworkTxError::WrongOutboundRing {
                expected_src_slot: 2,
                expected_dst_slot: NET_ROUTER_SLOT_U32,
                expected_ring_index: Some(12),
                actual_src_slot: 2,
                actual_dst_slot: NET_ROUTER_SLOT_U32,
                actual_ring_index: 13,
            })
        );
        assert_eq!(tx.next_seq(), 0);
        assert_eq!(header.write_index(), 0);
    }

    #[test]
    fn network_tx_rejects_oversized_payload_without_truncation_or_sequence_advance() {
        let header = RingHeader::new();
        let mut entries = empty_entries(4);
        let tx = PluginNetworkTx::new(2, 12);
        let mut ring = ring_view(12, 2, &header, &mut entries);
        let oversized = vec![0xa5; MAX_FRAME_DATA + 1];

        assert_eq!(
            tx.enqueue_guest_frame(&mut ring, 77, &oversized),
            Err(NetworkTxError::PayloadTooLarge {
                len: MAX_FRAME_DATA + 1,
                capacity: MAX_FRAME_DATA,
            })
        );
        assert_eq!(tx.next_seq(), 0);
        assert_eq!(header.write_index(), 0);
    }

    #[test]
    fn network_tx_rejects_full_ring_loudly_without_dropping_or_sequence_advance() {
        let header = RingHeader::new();
        let mut entries = empty_entries(2);
        let tx = PluginNetworkTx::new(2, 12);
        let mut ring = ring_view(12, 2, &header, &mut entries);

        let _first = enqueue(&tx, &mut ring, 77, b"one");
        let _second = enqueue(&tx, &mut ring, 78, b"two");
        let first_before = ring.entries[0].clone();
        let second_before = ring.entries[1].clone();
        assert_eq!(
            tx.enqueue_guest_frame(&mut ring, 79, b"three"),
            Err(NetworkTxError::RingOperation {
                ring_index: 12,
                source: SpscRingError::QueueFull { capacity: 2 },
            })
        );
        assert_eq!(tx.next_seq(), 2);
        assert_eq!(header.write_index(), 2);
        assert_eq!(ring.entries[0], first_before);
        assert_eq!(ring.entries[1], second_before);
    }

    #[test]
    fn network_tx_rejects_sequence_overflow_before_enqueuing() {
        let header = RingHeader::new();
        let mut entries = empty_entries(4);
        let tx = PluginNetworkTx {
            src_slot: 2,
            dst_slot: NET_ROUTER_SLOT_U32,
            ring_index: 12,
            next_seq: Cell::new(u32::MAX),
        };
        let mut ring = ring_view(12, 2, &header, &mut entries);

        assert_eq!(
            tx.enqueue_guest_frame(&mut ring, 77, b"alpha"),
            Err(NetworkTxError::SequenceOverflow {
                ring_index: 12,
                next_seq: u32::MAX,
            })
        );
        assert_eq!(tx.next_seq(), u32::MAX);
        assert_eq!(header.write_index(), 0);
    }

    #[test]
    fn network_tx_idle_reentrant_path_uses_fixed_state_without_locks() {
        let header = RingHeader::new();
        let mut entries = empty_entries(4);
        let tx = PluginNetworkTx::new(2, 12);
        let mut ring = ring_view(12, 2, &header, &mut entries);

        emit_from_idle_handler(&tx, &mut ring, 88, b"timer-frame");
        emit_from_idle_handler(&tx, &mut ring, 89, b"guest-frame");

        assert_eq!(tx.next_seq(), 2);
        assert_frame(&ring.entries[0], 88, 2, 0, b"timer-frame");
        assert_frame(&ring.entries[1], 89, 2, 1, b"guest-frame");
    }

    #[test]
    fn network_tx_completion_batch_is_all_preflighted_before_visibility() {
        let header = RingHeader::new();
        let mut entries = empty_entries(2);
        let tx = PluginNetworkTx::new(2, 12);
        let mut ring = ring_view(12, 2, &header, &mut entries);
        let too_large = vec![b"one".to_vec(), b"two".to_vec(), b"three".to_vec()];

        assert!(matches!(
            tx.enqueue_guest_frame_batch(&mut ring, 90, &too_large),
            Err(NetworkTxError::RingOperation {
                source: SpscRingError::QueueFull { capacity: 2 },
                ..
            })
        ));
        assert_eq!(header.write_index(), 0);
        assert_eq!(tx.next_seq(), 0);

        let payloads = vec![b"one".to_vec(), b"two".to_vec()];
        let enqueues = tx
            .enqueue_guest_frame_batch(&mut ring, 90, &payloads)
            .unwrap_or_else(|error| panic!("completion batch should enqueue: {error}"));
        assert_eq!(enqueues.len(), 2);
        assert_eq!(header.write_index(), 2);
        assert_eq!(tx.next_seq(), 2);
        assert_frame(&ring.entries[0], 90, 2, 0, b"one");
        assert_frame(&ring.entries[1], 90, 2, 1, b"two");
    }

    fn emit_from_idle_handler(
        tx: &PluginNetworkTx,
        ring: &mut NetworkTxRing<'_>,
        emit_icount: u64,
        payload: &[u8],
    ) {
        if let Err(error) = tx.enqueue_guest_frame(ring, emit_icount, payload) {
            panic!("idle-context TX callback should enqueue: {error}");
        }
    }

    fn layout() -> RegionLayout {
        match RegionLayout::for_config(RegionConfig::new(2, 4, 0)) {
            Ok(layout) => layout,
            Err(error) => panic!("layout should be valid: {error}"),
        }
    }

    fn router_outbound_ring(layout: RegionLayout, vm_slot: u32) -> DirectedRing {
        let rings_per_vm = ReservedExecutorSlot::all().len() as u32 * 2;
        let index = vm_slot * rings_per_vm;
        assert!(index < layout.ring_count);
        DirectedRing {
            index,
            src_slot: vm_slot,
            dst_slot: NET_ROUTER_SLOT_U32,
        }
    }

    fn empty_entries(capacity: usize) -> Vec<FrameEntry> {
        vec![FrameEntry::default(); capacity]
    }

    fn ring_view<'a>(
        ring_index: u32,
        src_slot: u32,
        header: &'a RingHeader,
        entries: &'a mut [FrameEntry],
    ) -> NetworkTxRing<'a> {
        NetworkTxRing::new(ring_index, src_slot, NET_ROUTER_SLOT_U32, header, entries)
    }

    fn enqueue(
        tx: &PluginNetworkTx,
        ring: &mut NetworkTxRing<'_>,
        emit_icount: u64,
        payload: &[u8],
    ) -> NetworkTxEnqueue {
        match tx.enqueue_guest_frame(ring, emit_icount, payload) {
            Ok(enqueue) => enqueue,
            Err(error) => panic!("network TX frame should enqueue: {error}"),
        }
    }

    fn assert_frame(
        frame: &FrameEntry,
        delivery_icount: u64,
        src_node: u32,
        seq: u32,
        payload: &[u8],
    ) {
        assert_eq!(frame.delivery_icount, delivery_icount);
        assert_eq!(frame.src_node, src_node);
        assert_eq!(frame.seq, seq);
        assert_eq!(frame.payload(), Ok(payload));
    }
}
