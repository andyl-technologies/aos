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

    use crucible_shmem::{FrameEntry, MAX_FRAME_DATA};

    static QEMU_NET_SEND_COUNT: AtomicUsize = AtomicUsize::new(0);
    static QEMU_NET_SEND_LAST_LEN: AtomicUsize = AtomicUsize::new(0);
    static QEMU_NET_FLUSH_COUNT: AtomicUsize = AtomicUsize::new(0);

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
