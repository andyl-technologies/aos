//! Network receive injection through QEMU's lossless RX queue.
//!
//! The idle callback hands due inbound frames to this module after QEMU virtual
//! time has advanced to the deterministic wake icount. The module enforces that
//! delivery gate, queues frame payloads through a lossless backend, and flushes
//! the backend once the ordered batch has been queued.

use std::{
    fmt,
    os::raw::{c_int, c_void},
};

use thiserror::Error;

use crucible_shmem::{FrameDeliveryKey, FrameEntry, FrameEntryError};

/// QEMU patch export used to queue one RX frame losslessly.
pub const QEMU_PLUGIN_NET_SEND_SYMBOL: &str = "qemu_plugin_net_send";
/// QEMU patch export used to flush queued RX frames into the guest NIC.
pub const QEMU_PLUGIN_NET_FLUSH_SYMBOL: &str = "qemu_plugin_net_flush";
/// QEMU patch export used only for diagnostics around guest RX readiness.
pub const QEMU_PLUGIN_NET_CAN_RECEIVE_SYMBOL: &str = "qemu_plugin_net_can_receive";
const QEMU_PLUGIN_NET_SEND_SYMBOL_C: &[u8] = b"qemu_plugin_net_send\0";
const QEMU_PLUGIN_NET_FLUSH_SYMBOL_C: &[u8] = b"qemu_plugin_net_flush\0";
const QEMU_PLUGIN_NET_CAN_RECEIVE_SYMBOL_C: &[u8] = b"qemu_plugin_net_can_receive\0";

/// QEMU's lossless network RX queue function.
///
/// The patched QEMU API exports `qemu_plugin_net_send` as a payload pointer,
/// payload length pair returning zero on success and nonzero on loud failure.
pub type QemuPluginNetSendFn = extern "C" fn(*const u8, usize) -> c_int;

/// QEMU's network RX queue flush function.
///
/// The patched QEMU API exports `qemu_plugin_net_flush` as a no-argument function
/// returning zero on success and nonzero on loud failure.
pub type QemuPluginNetFlushFn = extern "C" fn() -> c_int;
/// QEMU's network RX readiness diagnostic function.
pub type QemuPluginNetCanReceiveFn = extern "C" fn() -> c_int;

/// Resolves QEMU's lossless network RX queue export from the loaded process.
#[cfg(unix)]
#[must_use]
pub fn resolve_qemu_net_send_symbol() -> Option<QemuPluginNetSendFn> {
    // SAFETY: `dlsym` receives a static NUL-terminated symbol name and returns
    // either null or a process symbol address. The QEMU patch defines this
    // symbol with the exact `QemuPluginNetSendFn` ABI; callers fail closed when
    // it is absent.
    let symbol = unsafe {
        libc::dlsym(
            libc::RTLD_DEFAULT,
            QEMU_PLUGIN_NET_SEND_SYMBOL_C.as_ptr().cast(),
        )
    };
    if symbol.is_null() {
        None
    } else {
        // SAFETY: Non-null `symbol` was resolved for `qemu_plugin_net_send`,
        // whose patched QEMU declaration matches `QemuPluginNetSendFn`.
        Some(unsafe { std::mem::transmute::<*mut c_void, QemuPluginNetSendFn>(symbol) })
    }
}

/// Resolves QEMU's lossless network RX queue export from the loaded process.
#[cfg(not(unix))]
#[must_use]
pub const fn resolve_qemu_net_send_symbol() -> Option<QemuPluginNetSendFn> {
    None
}

/// Resolves QEMU's lossless network RX flush export from the loaded process.
#[cfg(unix)]
#[must_use]
pub fn resolve_qemu_net_flush_symbol() -> Option<QemuPluginNetFlushFn> {
    // SAFETY: `dlsym` receives a static NUL-terminated symbol name and returns
    // either null or a process symbol address. The QEMU patch defines this
    // symbol with the exact `QemuPluginNetFlushFn` ABI; callers fail closed when
    // it is absent.
    let symbol = unsafe {
        libc::dlsym(
            libc::RTLD_DEFAULT,
            QEMU_PLUGIN_NET_FLUSH_SYMBOL_C.as_ptr().cast(),
        )
    };
    if symbol.is_null() {
        None
    } else {
        // SAFETY: Non-null `symbol` was resolved for `qemu_plugin_net_flush`,
        // whose patched QEMU declaration matches `QemuPluginNetFlushFn`.
        Some(unsafe { std::mem::transmute::<*mut c_void, QemuPluginNetFlushFn>(symbol) })
    }
}

/// Resolves QEMU's lossless network RX flush export from the loaded process.
#[cfg(not(unix))]
#[must_use]
pub const fn resolve_qemu_net_flush_symbol() -> Option<QemuPluginNetFlushFn> {
    None
}

/// Resolves QEMU's network RX readiness diagnostic export from the loaded process.
#[cfg(unix)]
#[must_use]
pub fn resolve_qemu_net_can_receive_symbol() -> Option<QemuPluginNetCanReceiveFn> {
    // SAFETY: `dlsym` receives a static NUL-terminated symbol name and returns
    // either null or a process symbol address. The QEMU patch defines this
    // symbol with the exact `QemuPluginNetCanReceiveFn` ABI; callers fail closed
    // when it is absent.
    let symbol = unsafe {
        libc::dlsym(
            libc::RTLD_DEFAULT,
            QEMU_PLUGIN_NET_CAN_RECEIVE_SYMBOL_C.as_ptr().cast(),
        )
    };
    if symbol.is_null() {
        None
    } else {
        // SAFETY: Non-null `symbol` was resolved for
        // `qemu_plugin_net_can_receive`, whose patched QEMU declaration matches
        // `QemuPluginNetCanReceiveFn`.
        Some(unsafe { std::mem::transmute::<*mut c_void, QemuPluginNetCanReceiveFn>(symbol) })
    }
}

/// Resolves QEMU's network RX readiness diagnostic export from the loaded process.
#[cfg(not(unix))]
#[must_use]
pub const fn resolve_qemu_net_can_receive_symbol() -> Option<QemuPluginNetCanReceiveFn> {
    None
}

/// Registration-time-fixed network RX injection state.
#[derive(Debug, Default)]
pub struct PluginNetworkRx;

impl PluginNetworkRx {
    /// Builds a network RX injection state object.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Queues every due frame into QEMU's lossless RX path and flushes it once.
    ///
    /// `passed_delivery_floor_icount` is the icount at which this idle pass began,
    /// and `current_icount` must be the plugin clock after the idle jump. Frames
    /// in that inclusive window are injected in deterministic
    /// `(delivery_icount, src_node, seq)` order.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkRxError`] when a frame is late, not yet due, advertises an
    /// invalid payload length, or when the lossless queue/flush backend reports a
    /// loud failure.
    pub fn inject_due_frames_from_idle_context<Q>(
        &self,
        rx_queue: &mut Q,
        passed_delivery_floor_icount: u64,
        current_icount: u64,
        frames: &[FrameEntry],
    ) -> Result<NetworkRxInjection, NetworkRxError>
    where
        Q: LosslessNetworkRxQueue + ?Sized,
    {
        if passed_delivery_floor_icount > current_icount {
            return Err(NetworkRxError::InvalidDeliveryWindow {
                passed_delivery_floor_icount,
                current_icount,
            });
        }

        let mut ordered_frames = frames.iter().collect::<Vec<_>>();
        ordered_frames.sort_by_key(|frame| frame.delivery_key());

        for frame in &ordered_frames {
            validate_delivery_gate(frame, passed_delivery_floor_icount, current_icount)?;
            frame.payload().map_err(|source| NetworkRxError::Payload {
                frame: frame.delivery_key(),
                source,
            })?;
        }

        let mut frame_keys = Vec::with_capacity(ordered_frames.len());
        for frame in ordered_frames {
            let frame_key = frame.delivery_key();
            let payload = frame.payload().map_err(|source| NetworkRxError::Payload {
                frame: frame_key,
                source,
            })?;
            rx_queue
                .queue_lossless_rx(payload)
                .map_err(|source| NetworkRxError::Queue {
                    frame: frame_key,
                    source,
                })?;
            frame_keys.push(frame_key);
        }

        rx_queue
            .flush_lossless_rx()
            .map_err(|source| NetworkRxError::Flush { source })?;

        Ok(NetworkRxInjection {
            current_icount,
            frame_keys,
            flushed: true,
        })
    }
}

/// Handles one idle-context network RX injection pass.
///
/// This is the safe body for the QEMU-facing RX injection path. With
/// [`QemuLosslessNetworkRxQueue`] as the backend, it calls the concrete
/// `qemu_plugin_net_send` and `qemu_plugin_net_flush` patch exports.
///
/// # Errors
///
/// Returns [`NetworkRxError`] when the delivery gate, frame payload validation,
/// queue step, or flush step fails.
pub fn handle_network_rx_idle_callback<Q>(
    network_rx: &PluginNetworkRx,
    rx_queue: &mut Q,
    passed_delivery_floor_icount: u64,
    current_icount: u64,
    frames: &[FrameEntry],
) -> Result<NetworkRxInjection, NetworkRxError>
where
    Q: LosslessNetworkRxQueue + ?Sized,
{
    network_rx.inject_due_frames_from_idle_context(
        rx_queue,
        passed_delivery_floor_icount,
        current_icount,
        frames,
    )
}

/// A QEMU RX backend that queues frames losslessly before flushing.
pub trait LosslessNetworkRxQueue {
    /// Queues one RX payload without dropping it when the guest RX queue is not ready.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkRxQueueError`] when the backend cannot queue the payload
    /// and must fail loudly instead of dropping it.
    fn queue_lossless_rx(&mut self, payload: &[u8]) -> Result<(), NetworkRxQueueError>;

    /// Flushes queued RX payloads toward the guest device.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkRxQueueError`] when the backend cannot flush the queued
    /// payloads and must fail loudly.
    fn flush_lossless_rx(&mut self) -> Result<(), NetworkRxQueueError>;
}

/// Lossless network RX backend backed by QEMU's patch exports.
#[derive(Clone, Copy, Debug)]
pub struct QemuLosslessNetworkRxQueue {
    net_send: QemuPluginNetSendFn,
    net_flush: QemuPluginNetFlushFn,
}

impl QemuLosslessNetworkRxQueue {
    /// Requires QEMU's lossless network RX patch exports.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkRxError::CapabilityUnavailable`] when either
    /// `qemu_plugin_net_send` or `qemu_plugin_net_flush` was not resolved.
    pub fn require(
        net_send: Option<QemuPluginNetSendFn>,
        net_flush: Option<QemuPluginNetFlushFn>,
    ) -> Result<Self, NetworkRxError> {
        let Some(net_send) = net_send else {
            return Err(NetworkRxError::CapabilityUnavailable {
                symbol: QEMU_PLUGIN_NET_SEND_SYMBOL,
            });
        };
        let Some(net_flush) = net_flush else {
            return Err(NetworkRxError::CapabilityUnavailable {
                symbol: QEMU_PLUGIN_NET_FLUSH_SYMBOL,
            });
        };

        Ok(Self {
            net_send,
            net_flush,
        })
    }
}

impl LosslessNetworkRxQueue for QemuLosslessNetworkRxQueue {
    fn queue_lossless_rx(&mut self, payload: &[u8]) -> Result<(), NetworkRxQueueError> {
        let status = (self.net_send)(payload.as_ptr(), payload.len());
        if status == 0 {
            Ok(())
        } else {
            Err(NetworkRxQueueError::qemu_patch(
                NetworkRxQueueOperation::Queue,
                QEMU_PLUGIN_NET_SEND_SYMBOL,
                status,
            ))
        }
    }

    fn flush_lossless_rx(&mut self) -> Result<(), NetworkRxQueueError> {
        let status = (self.net_flush)();
        if status == 0 {
            Ok(())
        } else {
            Err(NetworkRxQueueError::qemu_patch(
                NetworkRxQueueOperation::Flush,
                QEMU_PLUGIN_NET_FLUSH_SYMBOL,
                status,
            ))
        }
    }
}

/// The backend operation that produced a network RX queue error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetworkRxQueueOperation {
    /// Lossless queueing failed.
    Queue,
    /// Lossless queue flushing failed.
    Flush,
}

impl fmt::Display for NetworkRxQueueOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Queue => formatter.write_str("queue"),
            Self::Flush => formatter.write_str("flush"),
        }
    }
}

/// A loud backend error from the lossless network RX queue.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[error("network RX {operation} failed: {message}")]
pub struct NetworkRxQueueError {
    operation: NetworkRxQueueOperation,
    message: String,
}

impl NetworkRxQueueError {
    /// Builds a queueing error.
    #[must_use]
    pub fn queue(message: impl Into<String>) -> Self {
        Self::new(NetworkRxQueueOperation::Queue, message)
    }

    /// Builds a flush error.
    #[must_use]
    pub fn flush(message: impl Into<String>) -> Self {
        Self::new(NetworkRxQueueOperation::Flush, message)
    }

    /// Builds an error returned by a concrete QEMU patch export.
    #[must_use]
    pub fn qemu_patch(
        operation: NetworkRxQueueOperation,
        symbol: &'static str,
        status: c_int,
    ) -> Self {
        Self::new(
            operation,
            format!("{symbol} returned nonzero status {status}"),
        )
    }

    /// Returns the backend operation that failed.
    #[must_use]
    pub const fn operation(&self) -> NetworkRxQueueOperation {
        self.operation
    }

    /// Returns the backend-provided diagnostic message.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    fn new(operation: NetworkRxQueueOperation, message: impl Into<String>) -> Self {
        Self {
            operation,
            message: message.into(),
        }
    }
}

/// Metadata returned after an idle-context RX injection pass.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkRxInjection {
    current_icount: u64,
    frame_keys: Vec<FrameDeliveryKey>,
    flushed: bool,
}

impl NetworkRxInjection {
    /// Returns the post-jump icount used for delivery gating.
    #[must_use]
    pub const fn current_icount(&self) -> u64 {
        self.current_icount
    }

    /// Returns the injected frame keys in queue order.
    #[must_use]
    pub fn frame_keys(&self) -> &[FrameDeliveryKey] {
        &self.frame_keys
    }

    /// Returns whether the queue was flushed after the batch was queued.
    #[must_use]
    pub const fn flushed(&self) -> bool {
        self.flushed
    }
}

/// An error produced by network RX injection.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum NetworkRxError {
    /// The required QEMU network RX patch export was unavailable.
    #[error("required network RX capability {symbol} is unavailable")]
    CapabilityUnavailable {
        /// The missing QEMU patch symbol.
        symbol: &'static str,
    },
    /// The caller supplied an impossible delivery window.
    #[error(
        "network RX delivery floor {passed_delivery_floor_icount} is after current icount {current_icount}"
    )]
    InvalidDeliveryWindow {
        /// The earliest delivery icount still valid for this idle pass.
        passed_delivery_floor_icount: u64,
        /// The post-jump consumer icount.
        current_icount: u64,
    },
    /// A frame was already behind the idle-pass delivery floor.
    #[error(
        "network RX frame {frame:?} is behind delivery floor {passed_delivery_floor_icount} at current icount {current_icount}"
    )]
    DeliveryAlreadyPassed {
        /// The earliest delivery icount still valid for this idle pass.
        passed_delivery_floor_icount: u64,
        /// The post-jump consumer icount.
        current_icount: u64,
        /// The late frame's deterministic delivery key.
        frame: FrameDeliveryKey,
    },
    /// A frame is not yet visible at the post-jump icount.
    #[error("network RX frame {frame:?} is not due at current icount {current_icount}")]
    DeliveryNotReached {
        /// The post-jump consumer icount.
        current_icount: u64,
        /// The future frame's deterministic delivery key.
        frame: FrameDeliveryKey,
    },
    /// A frame advertised an invalid payload length.
    #[error("network RX frame {frame:?} has invalid payload: {source}")]
    Payload {
        /// The frame whose payload could not be borrowed.
        frame: FrameDeliveryKey,
        /// The shared-memory frame validation error.
        source: FrameEntryError,
    },
    /// Queueing a frame through the lossless backend failed loudly.
    #[error("network RX frame {frame:?} queue failed: {source}")]
    Queue {
        /// The frame that could not be queued.
        frame: FrameDeliveryKey,
        /// The backend queueing error.
        source: NetworkRxQueueError,
    },
    /// Flushing the lossless RX queue failed loudly.
    #[error("network RX flush failed: {source}")]
    Flush {
        /// The backend flush error.
        source: NetworkRxQueueError,
    },
}

fn validate_delivery_gate(
    frame: &FrameEntry,
    passed_delivery_floor_icount: u64,
    current_icount: u64,
) -> Result<(), NetworkRxError> {
    if frame.delivery_icount < passed_delivery_floor_icount {
        Err(NetworkRxError::DeliveryAlreadyPassed {
            passed_delivery_floor_icount,
            current_icount,
            frame: frame.delivery_key(),
        })
    } else if frame.delivery_icount > current_icount {
        Err(NetworkRxError::DeliveryNotReached {
            current_icount,
            frame: frame.delivery_key(),
        })
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::atomic::{AtomicUsize, Ordering};

    use crucible::{
        AdvanceOutcome, ExecutionHorizon, Icount, SchedulerError, SchedulerNodeId,
        SchedulerSendAuthorization, SchedulerSendAuthorizer, SimDouble, SimDoubleConfig,
        SimDoubleHostScheduleEvent, SimInstructionScript, SimInstructionStep, SimOutboundFrame,
    };
    use crucible_protocol::{CONTROL_PROTOCOL_VERSION, HostMsg, control_encode_host_msg};
    use crucible_shmem::{
        ABI_VERSION, AdvanceCeiling, FrameEntry, KIND_VM, MAX_FRAME_DATA, NodeSlot, RingHeader,
        SLOT_NET_ROUTER, authorize_advance_ceiling,
    };

    use crate::{
        ExactDeadlineReader, IdleWakeCause, InboundFrameRing, PluginIdleHotLoop,
        PluginShmemOrdering, QueuedIdleAdvance,
        network_tx::{NetworkTxRing, PluginNetworkTx, handle_network_tx_callback},
    };

    static QEMU_NET_SEND_COUNT: AtomicUsize = AtomicUsize::new(0);
    static QEMU_NET_SEND_LAST_LEN: AtomicUsize = AtomicUsize::new(0);
    static QEMU_NET_FLUSH_COUNT: AtomicUsize = AtomicUsize::new(0);
    static ALLOW_ALL_SENDS: AllowAllSchedulerSendAuthorizer = AllowAllSchedulerSendAuthorizer;

    struct AllowAllSchedulerSendAuthorizer;

    impl SchedulerSendAuthorizer for AllowAllSchedulerSendAuthorizer {
        fn authorize_cross_node_send(
            &self,
            producer: &SchedulerNodeId,
            consumer: &SchedulerNodeId,
        ) -> Result<SchedulerSendAuthorization, SchedulerError> {
            Ok(SchedulerSendAuthorization {
                producer: producer.clone(),
                consumer: consumer.clone(),
                topology_epoch: 0,
            })
        }
    }

    #[test]
    fn host_observable_schedule_cross_checks_sim_double_against_plugin_projection() {
        let requested_horizon = 20;
        let mut double = sim_double_for_schedule_cross_check();
        complete_sim_double_setup(&mut double);
        enqueue_double_inbound(&mut double, 7, 12, b"router-first");
        enqueue_double_inbound(&mut double, 8, 15, b"router-second");

        let horizon = ExecutionHorizon {
            icount: Icount {
                retired: requested_horizon,
            },
        };
        assert_eq!(
            double.advance_scripted_quantum(horizon, &ALLOW_ALL_SENDS),
            Ok(AdvanceOutcome::Paused {
                at: Icount { retired: 12 },
            })
        );
        assert_eq!(
            double.advance_scripted_quantum(horizon, &ALLOW_ALL_SENDS),
            Ok(AdvanceOutcome::Paused {
                at: Icount { retired: 15 },
            })
        );
        assert_eq!(
            double.advance_scripted_quantum(horizon, &ALLOW_ALL_SENDS),
            Ok(AdvanceOutcome::ReachedHorizon)
        );

        assert_eq!(
            double.host_observable_schedule(),
            plugin_projection_host_observable_schedule(requested_horizon).as_slice()
        );
    }

    #[test]
    fn host_observable_schedule_projection_waits_for_qemu_advance_completion() {
        let slot = NodeSlot::new(KIND_VM);
        let mut clock = owned_clock(0, 0);
        let ring = RingHeader::new();
        let mut entries = vec![FrameEntry::default(); 1];
        enqueue_plugin_projection_inbound_frame(
            &ring,
            &mut entries,
            frame(12, SLOT_NET_ROUTER as u32, 7, b"router-first"),
        );
        publish_ceiling(&slot, ceiling(0, 0));
        let request = PluginIdleHotLoop::begin_idle_with_inbound_rings(
            &slot,
            &clock,
            &deadline_reader(),
            [InboundFrameRing::new(0, &ring, &entries)],
            None,
        )
        .unwrap_or_else(|error| panic!("idle begin should select inbound frame: {error}"));
        publish_ceiling(&slot, ceiling(0, 12));
        let mut queue = RecordingRxQueue::ready();

        assert!(matches!(
            PluginIdleHotLoop::complete_after_scheduler_wake_from_inbound_rings_with_rx_injection(
                &slot,
                &mut clock,
                &queued_idle_advance(),
                request,
                [InboundFrameRing::new(0, &ring, &entries)],
                &PluginNetworkRx::new(),
                &mut queue,
            ),
            Err(crate::IdleHotLoopError::TimeAdvanceCompletionPending {
                target_virtual_ns: 12,
                ..
            })
        ));
        assert_eq!(clock.current_icount(), 0);
        assert_eq!(ring.read_index(), 0);
        assert!(queue.queued_payloads.is_empty());
    }

    #[test]
    fn network_rx_idle_injection_queues_due_frames_then_flushes() {
        let network_rx = PluginNetworkRx::new();
        let mut queue = RecordingRxQueue::ready();
        let frames = [
            frame(20, 9, 4, b"second"),
            frame(20, 1, 7, b"first"),
            frame(20, 9, 5, b"third"),
        ];

        let injection =
            match handle_network_rx_idle_callback(&network_rx, &mut queue, 20, 20, &frames) {
                Ok(injection) => injection,
                Err(error) => panic!("due RX frames should inject: {error}"),
            };

        assert_eq!(injection.current_icount(), 20);
        assert_eq!(
            injection.frame_keys(),
            &[
                frame(20, 1, 7, b"first").delivery_key(),
                frame(20, 9, 4, b"second").delivery_key(),
                frame(20, 9, 5, b"third").delivery_key(),
            ]
        );
        assert!(injection.flushed());
        assert_eq!(
            queue.queued_payloads,
            vec![b"first".to_vec(), b"second".to_vec(), b"third".to_vec()]
        );
        assert_eq!(queue.flush_count, 1);
    }

    #[test]
    fn network_rx_idle_injection_accepts_jumped_over_delivery_window() {
        let network_rx = PluginNetworkRx::new();
        let mut queue = RecordingRxQueue::ready();
        let frames = [
            frame(20, 9, 4, b"second"),
            frame(12, 1, 7, b"first"),
            frame(15, 9, 5, b"middle"),
        ];

        let injection =
            match handle_network_rx_idle_callback(&network_rx, &mut queue, 10, 20, &frames) {
                Ok(injection) => injection,
                Err(error) => panic!("jump-window RX frames should inject: {error}"),
            };

        assert_eq!(injection.current_icount(), 20);
        assert_eq!(
            injection.frame_keys(),
            &[
                frame(12, 1, 7, b"first").delivery_key(),
                frame(15, 9, 5, b"middle").delivery_key(),
                frame(20, 9, 4, b"second").delivery_key(),
            ]
        );
        assert!(injection.flushed());
        assert_eq!(
            queue.queued_payloads,
            vec![b"first".to_vec(), b"middle".to_vec(), b"second".to_vec()]
        );
        assert_eq!(queue.flush_count, 1);
    }

    #[test]
    fn network_rx_lossless_queue_holds_not_ready_frame_until_flush() {
        let network_rx = PluginNetworkRx::new();
        let mut queue = RecordingRxQueue::not_ready();
        let frames = [frame(20, 1, 0, b"queued")];

        let injection =
            match network_rx.inject_due_frames_from_idle_context(&mut queue, 20, 20, &frames) {
                Ok(injection) => injection,
                Err(error) => panic!("lossless queue should accept not-ready frame: {error}"),
            };

        assert_eq!(
            injection.frame_keys(),
            &[frame(20, 1, 0, b"queued").delivery_key()]
        );
        assert_eq!(queue.pending_payloads, Vec::<Vec<u8>>::new());
        assert_eq!(queue.queued_payloads, vec![b"queued".to_vec()]);
        assert_eq!(queue.flush_count, 1);
    }

    #[test]
    fn network_rx_rejects_future_frame_before_queue_or_flush() {
        let network_rx = PluginNetworkRx::new();
        let mut queue = RecordingRxQueue::ready();
        let future = frame(21, 1, 0, b"future");

        assert_eq!(
            network_rx.inject_due_frames_from_idle_context(
                &mut queue,
                20,
                20,
                std::slice::from_ref(&future),
            ),
            Err(NetworkRxError::DeliveryNotReached {
                current_icount: 20,
                frame: future.delivery_key(),
            })
        );
        assert!(queue.queued_payloads.is_empty());
        assert_eq!(queue.flush_count, 0);
    }

    #[test]
    fn network_rx_rejects_late_frame_before_queue_or_flush() {
        let network_rx = PluginNetworkRx::new();
        let mut queue = RecordingRxQueue::ready();
        let late = frame(19, 1, 0, b"late");

        assert_eq!(
            network_rx.inject_due_frames_from_idle_context(
                &mut queue,
                20,
                20,
                std::slice::from_ref(&late),
            ),
            Err(NetworkRxError::DeliveryAlreadyPassed {
                passed_delivery_floor_icount: 20,
                current_icount: 20,
                frame: late.delivery_key(),
            })
        );
        assert!(queue.queued_payloads.is_empty());
        assert_eq!(queue.flush_count, 0);
    }

    #[test]
    fn network_rx_rejects_invalid_payload_before_queue_or_flush() {
        let network_rx = PluginNetworkRx::new();
        let mut queue = RecordingRxQueue::ready();
        let mut invalid = frame(20, 1, 0, b"invalid");
        invalid.len = (MAX_FRAME_DATA + 1) as u16;

        assert_eq!(
            network_rx.inject_due_frames_from_idle_context(
                &mut queue,
                20,
                20,
                std::slice::from_ref(&invalid),
            ),
            Err(NetworkRxError::Payload {
                frame: invalid.delivery_key(),
                source: FrameEntryError::PayloadLengthExceedsCapacity {
                    len: MAX_FRAME_DATA + 1,
                    capacity: MAX_FRAME_DATA,
                },
            })
        );
        assert!(queue.queued_payloads.is_empty());
        assert_eq!(queue.flush_count, 0);
    }

    #[test]
    fn network_rx_queue_failure_is_loud_without_flush() {
        let network_rx = PluginNetworkRx::new();
        let mut queue = RecordingRxQueue::ready();
        queue.queue_error_at = Some(0);
        let frame = frame(20, 1, 0, b"fail");

        assert_eq!(
            network_rx.inject_due_frames_from_idle_context(
                &mut queue,
                20,
                20,
                std::slice::from_ref(&frame),
            ),
            Err(NetworkRxError::Queue {
                frame: frame.delivery_key(),
                source: NetworkRxQueueError::queue("test queue failure"),
            })
        );
        assert!(queue.queued_payloads.is_empty());
        assert_eq!(queue.flush_count, 0);
    }

    #[test]
    fn network_rx_flush_failure_is_loud_after_queueing() {
        let network_rx = PluginNetworkRx::new();
        let mut queue = RecordingRxQueue::ready();
        queue.fail_flush = true;
        let frame = frame(20, 1, 0, b"flush");

        assert_eq!(
            network_rx.inject_due_frames_from_idle_context(
                &mut queue,
                20,
                20,
                std::slice::from_ref(&frame),
            ),
            Err(NetworkRxError::Flush {
                source: NetworkRxQueueError::flush("test flush failure"),
            })
        );
        assert_eq!(queue.queued_payloads, vec![b"flush".to_vec()]);
        assert_eq!(queue.flush_count, 0);
    }

    #[test]
    fn network_rx_requires_qemu_net_send_and_flush_symbols() {
        assert_eq!(
            require_qemu_queue_error(None, Some(qemu_plugin_net_flush_ok)),
            NetworkRxError::CapabilityUnavailable {
                symbol: QEMU_PLUGIN_NET_SEND_SYMBOL,
            }
        );
        assert_eq!(
            require_qemu_queue_error(Some(qemu_plugin_net_send_ok), None),
            NetworkRxError::CapabilityUnavailable {
                symbol: QEMU_PLUGIN_NET_FLUSH_SYMBOL,
            }
        );
    }

    #[test]
    fn network_rx_qemu_lossless_queue_calls_patch_send_and_flush() {
        QEMU_NET_SEND_COUNT.store(0, Ordering::SeqCst);
        QEMU_NET_SEND_LAST_LEN.store(0, Ordering::SeqCst);
        QEMU_NET_FLUSH_COUNT.store(0, Ordering::SeqCst);
        let network_rx = PluginNetworkRx::new();
        let mut queue = match QemuLosslessNetworkRxQueue::require(
            Some(qemu_plugin_net_send_ok),
            Some(qemu_plugin_net_flush_ok),
        ) {
            Ok(queue) => queue,
            Err(error) => panic!("QEMU network RX symbols should bind: {error}"),
        };
        let frames = [frame(20, 1, 0, b"qemu")];

        let injection =
            match network_rx.inject_due_frames_from_idle_context(&mut queue, 20, 20, &frames) {
                Ok(injection) => injection,
                Err(error) => panic!("QEMU patch queue should inject: {error}"),
            };

        assert_eq!(
            injection.frame_keys(),
            &[frame(20, 1, 0, b"qemu").delivery_key()]
        );
        assert_eq!(QEMU_NET_SEND_COUNT.load(Ordering::SeqCst), 1);
        assert_eq!(QEMU_NET_SEND_LAST_LEN.load(Ordering::SeqCst), 4);
        assert_eq!(QEMU_NET_FLUSH_COUNT.load(Ordering::SeqCst), 1);
    }

    extern "C" fn qemu_plugin_net_send_ok(payload: *const u8, len: usize) -> c_int {
        if payload.is_null() {
            return 1;
        }
        QEMU_NET_SEND_COUNT.fetch_add(1, Ordering::SeqCst);
        QEMU_NET_SEND_LAST_LEN.store(len, Ordering::SeqCst);
        0
    }

    extern "C" fn qemu_plugin_net_flush_ok() -> c_int {
        QEMU_NET_FLUSH_COUNT.fetch_add(1, Ordering::SeqCst);
        0
    }

    fn require_qemu_queue_error(
        net_send: Option<QemuPluginNetSendFn>,
        net_flush: Option<QemuPluginNetFlushFn>,
    ) -> NetworkRxError {
        match QemuLosslessNetworkRxQueue::require(net_send, net_flush) {
            Ok(_) => panic!("QEMU queue binding should fail"),
            Err(error) => error,
        }
    }

    fn sim_double_for_schedule_cross_check() -> SimDouble {
        let script = SimInstructionScript::new(vec![SimInstructionStep {
            instruction_budget: 20,
            outbound_frames: vec![SimOutboundFrame {
                dst_slot: SLOT_NET_ROUTER as u32,
                delivery_icount: 20,
                payload: b"guest-to-router".to_vec(),
            }],
        }]);
        match SimDouble::new(SimDoubleConfig {
            script,
            ..SimDoubleConfig::default()
        }) {
            Ok(double) => double,
            Err(error) => panic!("sim double should construct: {error}"),
        }
    }

    fn complete_sim_double_setup(double: &mut SimDouble) {
        let hello_ack = control_encode_host_msg(&HostMsg::HelloAck {
            proto_version: CONTROL_PROTOCOL_VERSION,
            abi_version: ABI_VERSION,
            slot_index: 0,
            node_count: double.shmem_layout().node_count,
        });
        if let Err(error) = double.accept_host_control_frame(&hello_ack) {
            panic!("sim double hello ack should succeed: {error}");
        }

        let setup = control_encode_host_msg(&HostMsg::Setup {
            region_len: double.shmem_layout().region_size,
        });
        match double.accept_host_control_frame(&setup) {
            Ok(Some(_setup_ack)) => {}
            Ok(None) => panic!("sim double setup should return SetupAck"),
            Err(error) => panic!("sim double setup should succeed: {error}"),
        }
    }

    fn enqueue_double_inbound(
        double: &mut SimDouble,
        sequence: u32,
        delivery_icount: u64,
        payload: &[u8],
    ) {
        if let Err(error) = double.enqueue_inbound_frame_with_sequence(
            SLOT_NET_ROUTER as u32,
            sequence,
            delivery_icount,
            payload,
        ) {
            panic!("sim double inbound frame should enqueue: {error}");
        }
    }

    fn plugin_projection_host_observable_schedule(
        requested_horizon: u64,
    ) -> Vec<SimDoubleHostScheduleEvent> {
        let mut schedule = Vec::new();
        let slot = NodeSlot::new(KIND_VM);
        let mut clock = owned_clock(0, 0);
        let network_rx = PluginNetworkRx::new();
        let inbound_ring = RingHeader::new();
        let mut inbound_entries = vec![FrameEntry::default(); 4];
        enqueue_plugin_projection_inbound_frame(
            &inbound_ring,
            &mut inbound_entries,
            frame(12, SLOT_NET_ROUTER as u32, 7, b"router-first"),
        );
        enqueue_plugin_projection_inbound_frame(
            &inbound_ring,
            &mut inbound_entries,
            frame(15, SLOT_NET_ROUTER as u32, 8, b"router-second"),
        );

        append_plugin_projection_idle_rx_delivery(
            &mut schedule,
            &slot,
            &mut clock,
            &network_rx,
            &inbound_ring,
            &inbound_entries,
            requested_horizon,
            12,
            AdvanceOutcome::Paused {
                at: Icount { retired: 12 },
            },
        );

        append_plugin_projection_idle_rx_delivery(
            &mut schedule,
            &slot,
            &mut clock,
            &network_rx,
            &inbound_ring,
            &inbound_entries,
            requested_horizon,
            15,
            AdvanceOutcome::Paused {
                at: Icount { retired: 15 },
            },
        );

        push_plugin_projection_guest_horizon(
            &mut schedule,
            &mut clock,
            requested_horizon,
            20,
            AdvanceOutcome::ReachedHorizon,
        );
        push_plugin_projection_tx_emission(&mut schedule, 20, b"guest-to-router");
        schedule
    }

    // crucible-lint: allow rust-allow -- local exception is documented at the allow site.
    #[allow(clippy::too_many_arguments)]
    fn append_plugin_projection_idle_rx_delivery(
        schedule: &mut Vec<SimDoubleHostScheduleEvent>,
        slot: &NodeSlot,
        clock: &mut crate::PluginVirtualClock,
        network_rx: &PluginNetworkRx,
        inbound_ring: &RingHeader,
        inbound_entries: &[FrameEntry],
        requested_icount: u64,
        reached_icount: u64,
        outcome: AdvanceOutcome,
    ) {
        let from_icount = clock.current_icount();
        publish_ceiling(slot, ceiling(from_icount, from_icount));
        let request = match PluginIdleHotLoop::begin_idle_with_inbound_rings(
            slot,
            clock,
            &deadline_reader(),
            [InboundFrameRing::new(0, inbound_ring, inbound_entries)],
            None,
        ) {
            Ok(request) => request,
            Err(error) => {
                panic!("plugin projection idle begin should select inbound frame: {error}")
            }
        };
        assert_eq!(request.plan().cause(), IdleWakeCause::InboundFrame);
        assert_eq!(request.plan().desired_wake_icount(), reached_icount);

        publish_ceiling(slot, ceiling(from_icount, reached_icount));
        let mut rx_queue = RecordingRxQueue::ready();
        let pending =
            match PluginIdleHotLoop::complete_after_scheduler_wake_from_inbound_rings_with_rx_injection(
                slot,
                clock,
                &queued_idle_advance(),
                request,
                [InboundFrameRing::new(0, inbound_ring, inbound_entries)],
                network_rx,
                &mut rx_queue,
            ) {
                Err(crate::IdleHotLoopError::TimeAdvanceCompletionPending {
                    pending_advance,
                    ..
                }) => pending_advance,
                Ok(_result) => panic!("plugin projection must wait for QEMU completion"),
                Err(error) => panic!("plugin projection should queue time advance: {error}"),
            };
        let completion_target = i64::try_from(pending.target_virtual_ns())
            .unwrap_or_else(|error| panic!("completion target should fit: {error}"));
        let result =
            PluginIdleHotLoop::complete_after_time_advance_from_inbound_rings_with_rx_injection(
                slot,
                clock,
                request,
                pending,
                crate::TimeAdvanceCompletion::from_qemu(0, completion_target),
                [InboundFrameRing::new(0, inbound_ring, inbound_entries)],
                network_rx,
                &mut rx_queue,
            )
            .unwrap_or_else(|error| {
                panic!("plugin projection idle completion should inject RX frame: {error}")
            });
        assert_eq!(
            result.advance().source(),
            crate::PluginClockAdvanceSource::SchedulerAuthorizedIdleJump
        );
        assert_eq!(result.advance().from_icount(), from_icount);
        assert_eq!(result.advance().to_icount(), reached_icount);

        schedule.push(SimDoubleHostScheduleEvent::HorizonAdvance {
            from_icount,
            requested_icount,
            reached_icount,
            outcome,
        });
        let injection = match result.network_rx_injection() {
            Some(injection) => injection.clone(),
            None => panic!("plugin projection idle completion should report RX injection"),
        };
        assert_eq!(result.injected_frames().len(), injection.frame_keys().len());
        append_plugin_projection_rx_delivery(schedule, (injection, rx_queue.queued_payloads));
    }

    fn push_plugin_projection_guest_horizon(
        schedule: &mut Vec<SimDoubleHostScheduleEvent>,
        clock: &mut crate::PluginVirtualClock,
        requested_icount: u64,
        reached_icount: u64,
        outcome: AdvanceOutcome,
    ) {
        let from_icount = clock.current_icount();
        let delta_icount = reached_icount
            .checked_sub(from_icount)
            .unwrap_or_else(|| panic!("reached icount should not move backward"));
        let advance = match clock
            .advance_guest_instructions(delta_icount, crate::SchedulerCeiling::new(reached_icount))
        {
            Ok(advance) => advance,
            Err(error) => panic!("plugin projection clock should advance: {error}"),
        };
        assert_eq!(
            advance.source(),
            crate::PluginClockAdvanceSource::GuestInstructions
        );

        schedule.push(SimDoubleHostScheduleEvent::HorizonAdvance {
            from_icount: advance.from_icount(),
            requested_icount,
            reached_icount: advance.to_icount(),
            outcome,
        });
    }

    fn append_plugin_projection_rx_delivery(
        schedule: &mut Vec<SimDoubleHostScheduleEvent>,
        (injection, queued_payloads): (NetworkRxInjection, Vec<Vec<u8>>),
    ) {
        assert_eq!(injection.frame_keys().len(), queued_payloads.len());
        for (key, payload) in injection.frame_keys().iter().zip(queued_payloads) {
            schedule.push(SimDoubleHostScheduleEvent::FrameDelivery {
                src_slot: key.src_node,
                sequence: key.seq,
                delivery_icount: key.delivery_icount,
                payload,
            });
        }
    }

    fn push_plugin_projection_tx_emission(
        schedule: &mut Vec<SimDoubleHostScheduleEvent>,
        emit_icount: u64,
        payload: &[u8],
    ) {
        let header = RingHeader::new();
        let mut entries = vec![FrameEntry::default(); 4];
        let tx = PluginNetworkTx::new(0, 0);
        let enqueue = {
            let mut ring = NetworkTxRing::new(0, 0, SLOT_NET_ROUTER as u32, &header, &mut entries);
            match handle_network_tx_callback(&tx, &mut ring, emit_icount, payload) {
                Ok(enqueue) => enqueue,
                Err(error) => panic!("plugin projection network TX should enqueue frame: {error}"),
            }
        };
        assert_eq!(header.write_index(), 1);
        assert_eq!(entries[0].payload(), Ok(payload));

        schedule.push(SimDoubleHostScheduleEvent::FrameEmission {
            dst_slot: enqueue.dst_slot(),
            sequence: enqueue.seq(),
            delivery_icount: enqueue.emit_icount(),
            payload: payload.to_vec(),
        });
    }

    fn enqueue_plugin_projection_inbound_frame(
        header: &RingHeader,
        entries: &mut [FrameEntry],
        frame: FrameEntry,
    ) {
        if let Err(error) = PluginShmemOrdering::enqueue_outbound_frame(header, entries, &frame) {
            panic!("plugin projection inbound frame should enqueue into SPSC ring: {error}");
        }
    }

    fn owned_clock(initial_icount: u64, icount_shift: u8) -> crate::PluginVirtualClock {
        match crate::PluginVirtualClock::new(initial_icount, icount_shift, ownership()) {
            Ok(clock) => clock,
            Err(error) => panic!("plugin projection clock should construct: {error}"),
        }
    }

    fn deadline_reader() -> ExactDeadlineReader {
        match ExactDeadlineReader::require(Some(host_schedule_no_deadline)) {
            Ok(reader) => reader,
            Err(error) => panic!("plugin projection deadline reader should bind: {error}"),
        }
    }

    fn queued_idle_advance() -> QueuedIdleAdvance {
        match QueuedIdleAdvance::require(Some(host_schedule_test_direct_advance)) {
            Ok(advance) => advance,
            Err(error) => panic!("plugin projection queued advance should bind: {error}"),
        }
    }

    fn ownership() -> crate::PluginTimeControlOwnership {
        crate::PluginTimeControlOwnership::acquired_after_registration(registration_ready())
    }

    fn registration_ready() -> crate::PluginRegistrationReady {
        let mut sequence = crate::PluginRegistrationSequence::new();
        let args = crate::PluginArgs::parse("simfd=3,slot=0,fault_node_hash=1111111111111111111111111111111111111111111111111111111111111111")
            .unwrap_or_else(|error| panic!("test args should parse: {error}"));
        let mut setup_ack = None;
        for step in crate::CANONICAL_TIME_CONTROL_REGISTRATION_ORDER {
            let result = if step == crate::PluginRegistrationStep::RegisterCallbacks {
                sequence
                    .register_callbacks_for_test(
                        &args,
                        Some(host_schedule_test_deadline),
                        Some(host_schedule_test_direct_advance),
                        crate::CoverageCapabilities::none(),
                    )
                    .map(|_capabilities| ())
            } else if step == crate::PluginRegistrationStep::SendSetupAck {
                sequence.record_test_ready_setup_ack().map(|ack| {
                    setup_ack = Some(ack);
                })
            } else if step == crate::PluginRegistrationStep::WaitBootBarrier {
                let ack = setup_ack
                    .take()
                    .unwrap_or_else(|| panic!("setup ack should precede boot barrier"));
                let slot = NodeSlot::new(KIND_VM);
                publish_boot_barrier_ceiling(&slot);
                sequence.wait_boot_barrier(ack, &slot, 0).map(|_release| ())
            } else {
                sequence.record_step(step)
            };
            if let Err(error) = result {
                panic!("canonical registration step {step:?} should record: {error}");
            }
        }
        match sequence.finish() {
            Ok(ready) => ready,
            Err(error) => panic!("canonical registration should finish: {error}"),
        }
    }

    fn publish_boot_barrier_ceiling(slot: &NodeSlot) {
        let ceiling = authorize_advance_ceiling(0, crate::BOOT_BARRIER_FIRST_GUEST_ICOUNT, None)
            .unwrap_or_else(|error| panic!("boot barrier ceiling should authorize: {error}"));
        publish_ceiling(slot, ceiling);
    }

    fn ceiling(current_icount: u64, max_advance_icount: u64) -> AdvanceCeiling {
        match authorize_advance_ceiling(current_icount, max_advance_icount, None) {
            Ok(ceiling) => ceiling,
            Err(error) => panic!("plugin projection scheduler ceiling should authorize: {error}"),
        }
    }

    fn publish_ceiling(slot: &NodeSlot, ceiling: AdvanceCeiling) {
        slot.publish_scheduler_ceiling(ceiling)
            .unwrap_or_else(|error| {
                panic!("plugin projection scheduler ceiling should publish: {error}")
            });
    }

    extern "C" fn host_schedule_no_deadline() -> i64 {
        -1
    }

    extern "C" fn host_schedule_test_deadline() -> i64 {
        1
    }

    extern "C" fn host_schedule_test_direct_advance(
        _target_virtual_ns: i64,
    ) -> std::os::raw::c_int {
        0
    }

    #[derive(Debug)]
    struct RecordingRxQueue {
        ready: bool,
        queued_payloads: Vec<Vec<u8>>,
        pending_payloads: Vec<Vec<u8>>,
        flush_count: usize,
        queue_error_at: Option<usize>,
        fail_flush: bool,
    }

    impl RecordingRxQueue {
        fn ready() -> Self {
            Self {
                ready: true,
                queued_payloads: Vec::new(),
                pending_payloads: Vec::new(),
                flush_count: 0,
                queue_error_at: None,
                fail_flush: false,
            }
        }

        fn not_ready() -> Self {
            Self {
                ready: false,
                ..Self::ready()
            }
        }
    }

    impl LosslessNetworkRxQueue for RecordingRxQueue {
        fn queue_lossless_rx(&mut self, payload: &[u8]) -> Result<(), NetworkRxQueueError> {
            let queued_count = self.queued_payloads.len() + self.pending_payloads.len();
            if self.queue_error_at == Some(queued_count) {
                return Err(NetworkRxQueueError::queue("test queue failure"));
            }

            if self.ready {
                self.queued_payloads.push(payload.to_vec());
            } else {
                self.pending_payloads.push(payload.to_vec());
            }
            Ok(())
        }

        fn flush_lossless_rx(&mut self) -> Result<(), NetworkRxQueueError> {
            if self.fail_flush {
                return Err(NetworkRxQueueError::flush("test flush failure"));
            }

            self.flush_count += 1;
            self.queued_payloads.append(&mut self.pending_payloads);
            Ok(())
        }
    }

    fn frame(delivery_icount: u64, src_node: u32, seq: u32, payload: &[u8]) -> FrameEntry {
        match FrameEntry::new(delivery_icount, src_node, seq, payload) {
            Ok(frame) => frame,
            Err(error) => panic!("test frame should construct: {error}"),
        }
    }
}
