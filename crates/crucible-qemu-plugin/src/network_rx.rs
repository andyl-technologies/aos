//! Network receive injection with canonical shared-memory ownership.
//!
//! The idle callback hands due inbound frames to this module after QEMU virtual
//! time has advanced to the deterministic wake icount. The module enforces that
//! delivery gate and attempts each frame in deterministic order. A delivered
//! prefix transfers to the guest; on backpressure the first undelivered frame
//! and every successor remain in the canonical shared-memory ring so exact
//! checkpoint/restore never depends on QEMU-private packet heap state.

mod qemu_symbols;

use std::{fmt, os::raw::c_int};

use thiserror::Error;

use crucible_shmem::{
    FrameDeliveryAttemptError, FrameDeliveryKey, FrameDeliveryState, FrameDeliveryStateError,
    FrameEntry, FrameEntryError, MAX_FRAME_DELIVERY_ATTEMPTS,
};

/// Hard ceiling on concrete QEMU RX attempts for one canonical frame.
pub const NETWORK_RX_DELIVERY_ATTEMPT_LIMIT: u32 = MAX_FRAME_DELIVERY_ATTEMPTS;
/// Minimum guest-instruction distance between retained-frame RX retries.
pub const NETWORK_RX_RETRY_INTERVAL_ICOUNT: u64 =
    crucible_shmem::FRAME_DELIVERY_RETRY_INTERVAL_ICOUNT;

pub use qemu_symbols::{
    QEMU_PLUGIN_NET_INJECT_SYMBOL, QemuPluginNetInjectFn, resolve_qemu_net_inject_symbol,
};

/// Registration-time-fixed network RX injection state.
#[derive(Debug, Default)]
pub struct PluginNetworkRx;

impl PluginNetworkRx {
    /// Builds a network RX injection state object.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Delivers the longest guest-accepted prefix of the due frame batch.
    ///
    /// `passed_delivery_floor_icount` is the icount at which this idle pass began,
    /// and `current_icount` must be the plugin clock after the idle jump. Frames
    /// in that inclusive window are injected in deterministic
    /// `(delivery_icount, src_node, seq)` order.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkRxError`] when a frame is not yet due, advertises an
    /// invalid payload length, or when the canonical delivery backend reports a
    /// permanent failure. Guest backpressure is a successful retained outcome.
    pub fn inject_due_frames_from_idle_context<Q>(
        &self,
        rx_queue: &mut Q,
        passed_delivery_floor_icount: u64,
        current_icount: u64,
        frames: &[FrameEntry],
    ) -> Result<NetworkRxInjection, NetworkRxError>
    where
        Q: CanonicalNetworkRx + ?Sized,
    {
        if passed_delivery_floor_icount > current_icount {
            return Err(NetworkRxError::InvalidDeliveryWindow {
                passed_delivery_floor_icount,
                current_icount,
            });
        }

        let mut ordered_frames = frames.iter().collect::<Vec<_>>();
        ordered_frames.sort_by_key(|frame| frame.delivery_key());

        let mut retained_head_authorizes_backlog = false;
        for (index, frame) in ordered_frames.iter().enumerate() {
            let state = frame
                .delivery_state()
                .map_err(|source| network_rx_delivery_state_error(frame.delivery_key(), source))?;
            if index == 0 && state == FrameDeliveryState::Retained {
                retained_head_authorizes_backlog = true;
            } else if state == FrameDeliveryState::Retained {
                return Err(NetworkRxError::RetainedFrameIsNotHead {
                    frame: frame.delivery_key(),
                });
            }
            validate_delivery_gate(
                frame,
                passed_delivery_floor_icount,
                current_icount,
                retained_head_authorizes_backlog,
            )?;
            frame.payload().map_err(|source| NetworkRxError::Payload {
                frame: frame.delivery_key(),
                source,
            })?;
        }

        let mut delivered_frame_keys = Vec::with_capacity(ordered_frames.len());
        let mut retained_frame_key = None;
        for frame in ordered_frames {
            let frame_key = frame.delivery_key();
            let state = frame
                .delivery_state()
                .map_err(|source| network_rx_delivery_state_error(frame_key, source))?;
            if state == FrameDeliveryState::Retained {
                let retry_icount = retained_retry_icount(frame)?;
                if current_icount < retry_icount {
                    break;
                }
            }
            let payload = frame.payload().map_err(|source| NetworkRxError::Payload {
                frame: frame_key,
                source,
            })?;
            if frame.delivery_attempts() >= NETWORK_RX_DELIVERY_ATTEMPT_LIMIT {
                return Err(NetworkRxError::DeliveryAttemptLimit {
                    frame: frame_key,
                    current_icount,
                    source: FrameDeliveryAttemptError::LimitReached {
                        attempts: frame.delivery_attempts(),
                        limit: NETWORK_RX_DELIVERY_ATTEMPT_LIMIT,
                    },
                });
            }
            match rx_queue
                .try_deliver_rx(payload)
                .map_err(|source| NetworkRxError::Delivery {
                    frame: frame_key,
                    source,
                })? {
                NetworkRxDeliveryOutcome::Delivered => delivered_frame_keys.push(frame_key),
                NetworkRxDeliveryOutcome::Retained => {
                    retained_frame_key = Some(frame_key);
                    break;
                }
            }
        }

        Ok(NetworkRxInjection {
            current_icount,
            delivered_frame_keys,
            retained_frame_key,
        })
    }
}

/// Handles one idle-context network RX injection pass.
///
/// This is the safe body for the QEMU-facing RX injection path. With
/// [`QemuCanonicalNetworkRx`] as the backend, it calls the concrete
/// `qemu_plugin_net_inject` patch export without a QEMU-private queue.
///
/// # Errors
///
/// Returns [`NetworkRxError`] when the delivery gate, frame payload validation,
/// delivery step fails permanently.
pub fn handle_network_rx_idle_callback<Q>(
    network_rx: &PluginNetworkRx,
    rx_queue: &mut Q,
    passed_delivery_floor_icount: u64,
    current_icount: u64,
    frames: &[FrameEntry],
) -> Result<NetworkRxInjection, NetworkRxError>
where
    Q: CanonicalNetworkRx + ?Sized,
{
    network_rx.inject_due_frames_from_idle_context(
        rx_queue,
        passed_delivery_floor_icount,
        current_icount,
        frames,
    )
}

/// A guest RX backend that retains canonical ownership under backpressure.
pub trait CanonicalNetworkRx {
    /// Attempts one RX payload without consuming it on guest backpressure.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkRxDeliveryError`] when the backend reports a permanent
    /// capability or link failure. Backpressure returns
    /// [`NetworkRxDeliveryOutcome::Retained`].
    fn try_deliver_rx(
        &mut self,
        payload: &[u8],
    ) -> Result<NetworkRxDeliveryOutcome, NetworkRxDeliveryError>;
}

/// Result of attempting one canonical RX frame at the guest device.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetworkRxDeliveryOutcome {
    /// The guest device accepted the frame completely.
    Delivered,
    /// The guest device is backpressured; shared memory retains the frame.
    Retained,
}

/// Canonical network RX backend backed by QEMU's direct injection export.
#[derive(Clone, Copy, Debug)]
pub struct QemuCanonicalNetworkRx {
    net_inject: QemuPluginNetInjectFn,
}

impl QemuCanonicalNetworkRx {
    /// Requires QEMU's canonical network RX injection export.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkRxError::CapabilityUnavailable`] when a required
    /// network injection export was not resolved.
    pub fn require(net_inject: Option<QemuPluginNetInjectFn>) -> Result<Self, NetworkRxError> {
        let Some(net_inject) = net_inject else {
            return Err(NetworkRxError::CapabilityUnavailable {
                symbol: QEMU_PLUGIN_NET_INJECT_SYMBOL,
            });
        };
        Ok(Self { net_inject })
    }
}

impl CanonicalNetworkRx for QemuCanonicalNetworkRx {
    fn try_deliver_rx(
        &mut self,
        payload: &[u8],
    ) -> Result<NetworkRxDeliveryOutcome, NetworkRxDeliveryError> {
        match (self.net_inject)(payload.as_ptr(), payload.len()) {
            0 => Ok(NetworkRxDeliveryOutcome::Delivered),
            1 => Ok(NetworkRxDeliveryOutcome::Retained),
            status => Err(NetworkRxDeliveryError::qemu_patch(
                NetworkRxDeliveryOperation::Delivery,
                QEMU_PLUGIN_NET_INJECT_SYMBOL,
                status,
            )),
        }
    }
}

/// The backend operation that produced a network RX delivery error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetworkRxDeliveryOperation {
    /// Direct guest delivery failed permanently.
    Delivery,
}

impl fmt::Display for NetworkRxDeliveryOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Delivery => formatter.write_str("delivery"),
        }
    }
}

/// A loud permanent error from canonical network RX delivery.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[error("network RX {operation} failed: {message}")]
pub struct NetworkRxDeliveryError {
    operation: NetworkRxDeliveryOperation,
    message: String,
}

impl NetworkRxDeliveryError {
    /// Builds a delivery error.
    #[must_use]
    pub fn delivery(message: impl Into<String>) -> Self {
        Self::new(NetworkRxDeliveryOperation::Delivery, message)
    }

    /// Builds an error returned by a concrete QEMU patch export.
    #[must_use]
    pub fn qemu_patch(
        operation: NetworkRxDeliveryOperation,
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
    pub const fn operation(&self) -> NetworkRxDeliveryOperation {
        self.operation
    }

    /// Returns the backend-provided diagnostic message.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    fn new(operation: NetworkRxDeliveryOperation, message: impl Into<String>) -> Self {
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
    delivered_frame_keys: Vec<FrameDeliveryKey>,
    retained_frame_key: Option<FrameDeliveryKey>,
}

impl NetworkRxInjection {
    /// Returns the post-jump icount used for delivery gating.
    #[must_use]
    pub const fn current_icount(&self) -> u64 {
        self.current_icount
    }

    /// Returns frame keys accepted completely by the guest, in delivery order.
    #[must_use]
    pub fn delivered_frame_keys(&self) -> &[FrameDeliveryKey] {
        &self.delivered_frame_keys
    }

    /// Returns the first frame retained canonically because of guest backpressure.
    #[must_use]
    pub const fn retained_frame_key(&self) -> Option<FrameDeliveryKey> {
        self.retained_frame_key
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
    /// A frame is not yet visible at the post-jump icount.
    #[error("network RX frame {frame:?} is not due at current icount {current_icount}")]
    DeliveryNotReached {
        /// The post-jump consumer icount.
        current_icount: u64,
        /// The future frame's deterministic delivery key.
        frame: FrameDeliveryKey,
    },
    /// A frame is behind the delivery floor without retained provenance.
    #[error(
        "network RX frame {frame:?} is behind delivery floor {passed_delivery_floor_icount} at current icount {current_icount} without backpressure provenance"
    )]
    DeliveryAlreadyPassed {
        /// The delivery floor for this callback pass.
        passed_delivery_floor_icount: u64,
        /// The current consumer icount.
        current_icount: u64,
        /// The late frame lacking retained provenance.
        frame: FrameDeliveryKey,
    },
    /// A retained marker appeared on a frame other than the canonical head.
    #[error("network RX retained frame {frame:?} is not the canonical batch head")]
    RetainedFrameIsNotHead {
        /// The invalid retained frame.
        frame: FrameDeliveryKey,
    },
    /// A retained frame did not carry evidence of its first failed attempt.
    #[error("network RX retained frame {frame:?} has zero delivery attempts")]
    RetainedFrameWithoutAttempt {
        /// Invalid retained frame.
        frame: FrameDeliveryKey,
    },
    /// A retained frame's deterministic retry coordinate overflowed.
    #[error(
        "network RX retry coordinate overflowed for frame {frame:?}: attempts={attempts}, interval={interval_icount}"
    )]
    RetryCoordinateOverflow {
        /// Frame whose retry coordinate cannot be represented.
        frame: FrameDeliveryKey,
        /// Canonical failed-attempt count.
        attempts: u32,
        /// Fixed spacing between retry attempts.
        interval_icount: u64,
    },
    /// A canonical frame exhausted its bounded concrete QEMU RX attempts.
    #[error(
        "network RX frame {frame:?} exhausted its delivery-attempt bound at icount {current_icount}: {source}"
    )]
    DeliveryAttemptLimit {
        /// Canonical frame that exhausted the bound.
        frame: FrameDeliveryKey,
        /// Guest coordinate of the rejected attempt.
        current_icount: u64,
        /// Canonical attempt counter and configured hard limit.
        source: FrameDeliveryAttemptError,
    },
    /// A shared frame carries a delivery state unknown to this ABI version.
    #[error("network RX frame {frame:?} has invalid delivery state {state}")]
    InvalidDeliveryState {
        /// The affected deterministic frame key.
        frame: FrameDeliveryKey,
        /// The rejected shared-memory state byte.
        state: u8,
    },
    /// A frame advertised an invalid payload length.
    #[error("network RX frame {frame:?} has invalid payload: {source}")]
    Payload {
        /// The frame whose payload could not be borrowed.
        frame: FrameDeliveryKey,
        /// The shared-memory frame validation error.
        source: FrameEntryError,
    },
    /// Delivering a frame through the canonical backend failed loudly.
    #[error("network RX frame {frame:?} delivery failed: {source}")]
    Delivery {
        /// The frame that could not be delivered or retained canonically.
        frame: FrameDeliveryKey,
        /// The backend delivery error.
        source: NetworkRxDeliveryError,
    },
}

fn validate_delivery_gate(
    frame: &FrameEntry,
    passed_delivery_floor_icount: u64,
    current_icount: u64,
    retained_head_authorizes_backlog: bool,
) -> Result<(), NetworkRxError> {
    if frame.delivery_icount > current_icount {
        Err(NetworkRxError::DeliveryNotReached {
            current_icount,
            frame: frame.delivery_key(),
        })
    } else if frame.delivery_icount < passed_delivery_floor_icount
        && !retained_head_authorizes_backlog
    {
        Err(NetworkRxError::DeliveryAlreadyPassed {
            passed_delivery_floor_icount,
            current_icount,
            frame: frame.delivery_key(),
        })
    } else {
        Ok(())
    }
}

fn retained_retry_icount(frame: &FrameEntry) -> Result<u64, NetworkRxError> {
    let attempts = frame.delivery_attempts();
    if attempts == 0 {
        return Err(NetworkRxError::RetainedFrameWithoutAttempt {
            frame: frame.delivery_key(),
        });
    }
    frame
        .last_delivery_attempt_icount()
        .checked_add(NETWORK_RX_RETRY_INTERVAL_ICOUNT)
        .ok_or(NetworkRxError::RetryCoordinateOverflow {
            frame: frame.delivery_key(),
            attempts,
            interval_icount: NETWORK_RX_RETRY_INTERVAL_ICOUNT,
        })
}

fn network_rx_delivery_state_error(
    frame: FrameDeliveryKey,
    source: FrameDeliveryStateError,
) -> NetworkRxError {
    match source {
        FrameDeliveryStateError::UnknownState { state } => {
            NetworkRxError::InvalidDeliveryState { frame, state }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod retained_retry;

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
    fn network_rx_idle_injection_delivers_due_frames_in_order() {
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
            injection.delivered_frame_keys(),
            &[
                frame(20, 1, 7, b"first").delivery_key(),
                frame(20, 9, 4, b"second").delivery_key(),
                frame(20, 9, 5, b"third").delivery_key(),
            ]
        );
        assert_eq!(injection.retained_frame_key(), None);
        assert_eq!(
            queue.queued_payloads,
            vec![b"first".to_vec(), b"second".to_vec(), b"third".to_vec()]
        );
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
            injection.delivered_frame_keys(),
            &[
                frame(12, 1, 7, b"first").delivery_key(),
                frame(15, 9, 5, b"middle").delivery_key(),
                frame(20, 9, 4, b"second").delivery_key(),
            ]
        );
        assert_eq!(injection.retained_frame_key(), None);
        assert_eq!(
            queue.queued_payloads,
            vec![b"first".to_vec(), b"middle".to_vec(), b"second".to_vec()]
        );
    }

    #[test]
    fn network_rx_retains_canonical_frame_under_guest_backpressure() {
        let network_rx = PluginNetworkRx::new();
        let mut queue = RecordingRxQueue::not_ready();
        let frames = [frame(20, 1, 0, b"queued")];

        let injection =
            match network_rx.inject_due_frames_from_idle_context(&mut queue, 20, 20, &frames) {
                Ok(injection) => injection,
                Err(error) => panic!("backpressure should retain the canonical frame: {error}"),
            };

        assert_eq!(injection.delivered_frame_keys(), &[]);
        assert_eq!(
            injection.retained_frame_key(),
            Some(frame(20, 1, 0, b"queued").delivery_key())
        );
        assert_eq!(queue.pending_payloads, vec![b"queued".to_vec()]);
        assert_eq!(queue.queued_payloads, Vec::<Vec<u8>>::new());
        frames[0]
            .record_delivery_attempt(20, NETWORK_RX_DELIVERY_ATTEMPT_LIMIT)
            .unwrap_or_else(|error| panic!("retained attempt should be recorded: {error}"));
        assert_eq!(frames[0].delivery_attempts(), 1);
    }

    #[test]
    fn network_rx_rejects_future_frame_before_delivery() {
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
    }

    #[test]
    fn network_rx_rejects_unproven_late_frame() {
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
    }

    #[test]
    fn network_rx_rejects_invalid_payload_before_delivery() {
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
    }

    #[test]
    fn network_rx_delivery_failure_is_loud() {
        let network_rx = PluginNetworkRx::new();
        let mut queue = RecordingRxQueue::ready();
        queue.delivery_error_at = Some(0);
        let frame = frame(20, 1, 0, b"fail");

        assert_eq!(
            network_rx.inject_due_frames_from_idle_context(
                &mut queue,
                20,
                20,
                std::slice::from_ref(&frame),
            ),
            Err(NetworkRxError::Delivery {
                frame: frame.delivery_key(),
                source: NetworkRxDeliveryError::delivery("test delivery failure"),
            })
        );
        assert!(queue.queued_payloads.is_empty());
    }

    #[test]
    fn network_rx_requires_qemu_direct_injection_symbol() {
        assert_eq!(
            require_qemu_injection_error(None),
            NetworkRxError::CapabilityUnavailable {
                symbol: QEMU_PLUGIN_NET_INJECT_SYMBOL,
            }
        );
    }

    #[test]
    fn network_rx_qemu_direct_injection_transfers_delivered_frame() {
        let network_rx = PluginNetworkRx::new();
        let mut queue = match QemuCanonicalNetworkRx::require(Some(qemu_plugin_net_inject_ok)) {
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
            injection.delivered_frame_keys(),
            &[frame(20, 1, 0, b"qemu").delivery_key()]
        );
        assert_eq!(injection.retained_frame_key(), None);
    }

    #[test]
    fn network_rx_qemu_direct_injection_retains_backpressured_frame() {
        let network_rx = PluginNetworkRx::new();
        let mut queue = match QemuCanonicalNetworkRx::require(Some(qemu_plugin_net_inject_retry)) {
            Ok(queue) => queue,
            Err(error) => panic!("QEMU network RX symbols should bind: {error}"),
        };

        let injection = network_rx
            .inject_due_frames_from_idle_context(
                &mut queue,
                20,
                20,
                &[frame(20, 1, 0, b"retained")],
            )
            .unwrap_or_else(|error| panic!("backpressured frame should remain queued: {error}"));

        assert!(injection.delivered_frame_keys().is_empty());
        assert_eq!(
            injection.retained_frame_key(),
            Some(frame(20, 1, 0, b"retained").delivery_key())
        );
    }

    extern "C" fn qemu_plugin_net_inject_ok(payload: *const u8, len: usize) -> c_int {
        if payload.is_null() {
            return -1;
        }
        let _ = len;
        0
    }

    extern "C" fn qemu_plugin_net_inject_retry(_payload: *const u8, _len: usize) -> c_int {
        1
    }

    fn require_qemu_injection_error(net_inject: Option<QemuPluginNetInjectFn>) -> NetworkRxError {
        match QemuCanonicalNetworkRx::require(net_inject) {
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
        assert_eq!(
            result.injected_frames().len(),
            injection.delivered_frame_keys().len()
        );
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
        assert_eq!(
            injection.delivered_frame_keys().len(),
            queued_payloads.len()
        );
        for (key, payload) in injection.delivered_frame_keys().iter().zip(queued_payloads) {
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
        let args = crate::PluginArgs::parse("simfd=3,slot=0,fault_node_hash=1111111111111111111111111111111111111111111111111111111111111111,process_generation=1,network_tx_next_seq=0,storage_completed_history_epochs=1048576,storage_completed_history_gaps=1048576")
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
        delivery_error_at: Option<usize>,
    }

    impl RecordingRxQueue {
        fn ready() -> Self {
            Self {
                ready: true,
                queued_payloads: Vec::new(),
                pending_payloads: Vec::new(),
                delivery_error_at: None,
            }
        }

        fn not_ready() -> Self {
            Self {
                ready: false,
                ..Self::ready()
            }
        }
    }

    impl CanonicalNetworkRx for RecordingRxQueue {
        fn try_deliver_rx(
            &mut self,
            payload: &[u8],
        ) -> Result<NetworkRxDeliveryOutcome, NetworkRxDeliveryError> {
            let queued_count = self.queued_payloads.len() + self.pending_payloads.len();
            if self.delivery_error_at == Some(queued_count) {
                return Err(NetworkRxDeliveryError::delivery("test delivery failure"));
            }

            if self.ready {
                self.queued_payloads.push(payload.to_vec());
                Ok(NetworkRxDeliveryOutcome::Delivered)
            } else {
                self.pending_payloads.push(payload.to_vec());
                Ok(NetworkRxDeliveryOutcome::Retained)
            }
        }
    }

    fn frame(delivery_icount: u64, src_node: u32, seq: u32, payload: &[u8]) -> FrameEntry {
        match FrameEntry::new(delivery_icount, src_node, seq, payload) {
            Ok(frame) => frame,
            Err(error) => panic!("test frame should construct: {error}"),
        }
    }
}
