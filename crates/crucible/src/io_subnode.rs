//! Uniform deterministic I/O sub-node lifecycle.
//!
//! I/O sub-nodes model disk, 9p, and network-link devices as scheduler-owned
//! nodes with their own icount-derived clocks. They accept request frames,
//! compute deterministic completion points, expose the next exact local event,
//! drain due responses through an outbox, and snapshot/restore their queues.

use crate::{
    Icount, NodeId, SchedulerNodeId, SchedulingNodeKind, Shift, SimDuration, TimeConversionError,
    VirtualInstant, scheduler::IoCompletion,
};
use std::{collections::VecDeque, error::Error, fmt};

/// A request accepted by a deterministic I/O sub-node.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct IoSubNodeRequest {
    /// Device-local request sequence from the shared-memory ingress ring.
    pub sequence: u64,
    /// Optional planned producer sub-node that must receive this request.
    pub expected_sub_node: Option<SchedulerNodeId>,
    /// Scheduler node that will observe the response.
    pub requester: SchedulerNodeId,
    /// Requester's icount when the request became modeled input.
    pub request_icount: Icount,
    /// Modeled device latency added to `request_icount` in virtual time.
    pub modeled_latency: SimDuration,
    /// Optional planned delivery icount that must match the local completion calculation.
    pub expected_delivery_icount: Option<Icount>,
    /// Optional already-recorded per-device RNG draw used by probabilistic devices.
    pub rng_draw: Option<u64>,
    /// Opaque request payload copied from the shared-memory request frame.
    pub payload: Vec<u8>,
}

/// A response computed by a deterministic I/O sub-node.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct IoSubNodeCompletion {
    /// Device-local request sequence that produced this completion.
    pub sequence: u64,
    /// Scheduler node that computed the completion.
    pub sub_node: SchedulerNodeId,
    /// Scheduler node that will observe the response.
    pub requester: SchedulerNodeId,
    /// Requester's icount when the request became modeled input.
    pub request_icount: Icount,
    /// Icount at which the response becomes visible to the requester.
    pub delivery_icount: Icount,
    /// Modeled latency used to compute `delivery_icount`.
    pub modeled_latency: SimDuration,
    /// Optional already-recorded per-device RNG draw consumed by the response model.
    pub rng_draw: Option<u64>,
    /// Deterministic response payload for the requester.
    pub payload: Vec<u8>,
}

impl IoSubNodeCompletion {
    /// Converts this completion into the scheduler's exact local I/O payload.
    #[must_use]
    pub fn to_scheduler_completion(&self) -> IoCompletion {
        IoCompletion {
            sub_node: self.sub_node.clone(),
            target: self.requester.node.clone(),
            delivery_icount: self.delivery_icount,
            payload: self.payload.clone(),
        }
    }
}

/// Restorable deterministic state for a uniform I/O sub-node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IoSubNodeSnapshot {
    /// Scheduler node whose state was captured.
    pub node: SchedulerNodeId,
    /// Fixed icount shift used by the node-local clock.
    pub shift: Shift,
    /// Current scheduler-advanced sub-node icount.
    pub current_icount: Icount,
    /// Maximum number of in-flight completions accepted before backpressure.
    pub request_capacity: usize,
    /// Maximum number of responses held in the outbox before backpressure.
    pub response_capacity: usize,
    /// In-flight computed responses not yet visible to the requester.
    pub in_flight: Vec<IoSubNodeCompletion>,
    /// Responses computed and due but not yet consumed by the transport.
    pub response_outbox: Vec<IoSubNodeCompletion>,
}

/// The shared deterministic lifecycle required of disk, 9p, and network-link nodes.
pub trait IoSubNode {
    /// Returns the scheduler node represented by this sub-node.
    fn node(&self) -> &SchedulerNodeId;

    /// Returns the current scheduler-advanced sub-node icount.
    fn current_icount(&self) -> Icount;

    /// Enqueues one request and computes its deterministic completion.
    ///
    /// # Errors
    ///
    /// Returns [`IoSubNodeError`] when the request would exceed deterministic
    /// backpressure bounds, names a non-VM requester, computes a completion
    /// before the current sub-node clock, or when virtual-time conversion
    /// overflows.
    fn enqueue_request(&mut self, request: IoSubNodeRequest) -> Result<(), IoSubNodeError>;

    /// Advances the sub-node clock and moves due responses into the outbox.
    ///
    /// # Errors
    ///
    /// Returns [`IoSubNodeError`] when the response outbox is full or the caller
    /// attempts to move the sub-node clock backward.
    fn advance_to(
        &mut self,
        limit_icount: Icount,
    ) -> Result<Vec<IoSubNodeCompletion>, IoSubNodeError>;

    /// Returns the next exact local completion point, if one is in flight.
    fn next_exact_local_event(&self) -> Option<Icount>;

    /// Drains the response outbox in deterministic delivery order.
    fn drain_response_outbox(&mut self) -> Vec<IoSubNodeCompletion>;

    /// Captures the restorable deterministic sub-node state.
    fn snapshot(&self) -> IoSubNodeSnapshot;

    /// Restores a previously captured deterministic sub-node state.
    ///
    /// # Errors
    ///
    /// Returns [`IoSubNodeError`] when the snapshot belongs to a different
    /// scheduler node, contains invalid queue or completion state, or cannot be
    /// validated under its saved icount shift.
    fn restore(&mut self, snapshot: IoSubNodeSnapshot) -> Result<(), IoSubNodeError>;
}

/// A deterministic in-memory implementation of [`IoSubNode`] for gates and tests.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeterministicIoSubNode {
    node: SchedulerNodeId,
    shift: Shift,
    current_icount: Icount,
    request_capacity: usize,
    response_capacity: usize,
    in_flight: Vec<IoSubNodeCompletion>,
    response_outbox: VecDeque<IoSubNodeCompletion>,
}

impl DeterministicIoSubNode {
    /// Builds a deterministic I/O sub-node with bounded request and response queues.
    ///
    /// # Errors
    ///
    /// Returns [`IoSubNodeError::InvalidNodeKind`] when `node` is not a disk,
    /// 9p, or network scheduler sub-node, [`IoSubNodeError::ZeroCapacity`] when
    /// either queue capacity is zero, or [`IoSubNodeError::TimeConversion`] when
    /// `shift` is not a valid icount projection.
    pub fn new(
        node: SchedulerNodeId,
        shift: Shift,
        request_capacity: usize,
        response_capacity: usize,
    ) -> Result<Self, IoSubNodeError> {
        match node.kind {
            SchedulingNodeKind::Disk | SchedulingNodeKind::NineP | SchedulingNodeKind::Network => {}
            kind => return Err(IoSubNodeError::InvalidNodeKind { kind }),
        }
        if request_capacity == 0 {
            return Err(IoSubNodeError::ZeroCapacity {
                queue: IoSubNodeQueue::RequestInbox,
            });
        }
        if response_capacity == 0 {
            return Err(IoSubNodeError::ZeroCapacity {
                queue: IoSubNodeQueue::ResponseOutbox,
            });
        }
        validate_shift(shift)?;

        Ok(Self {
            node,
            shift,
            current_icount: Icount { retired: 0 },
            request_capacity,
            response_capacity,
            in_flight: Vec::new(),
            response_outbox: VecDeque::new(),
        })
    }

    fn completion_for(
        &self,
        request: IoSubNodeRequest,
    ) -> Result<IoSubNodeCompletion, IoSubNodeError> {
        if let Some(expected_sub_node) = &request.expected_sub_node
            && expected_sub_node != &self.node
        {
            return Err(IoSubNodeError::ExpectedSubNodeMismatch {
                expected: expected_sub_node.clone(),
                actual: self.node.clone(),
            });
        }
        if request.requester.kind != SchedulingNodeKind::Vm {
            return Err(IoSubNodeError::InvalidRequesterKind {
                kind: request.requester.kind,
            });
        }
        let delivery_icount = completion_delivery_icount(
            self.shift,
            request.request_icount,
            request.modeled_latency,
        )?;
        if delivery_icount < self.current_icount {
            return Err(IoSubNodeError::CompletionBeforeClock {
                current_icount: self.current_icount,
                delivery_icount,
            });
        }
        if let Some(expected_delivery_icount) = request.expected_delivery_icount
            && expected_delivery_icount != delivery_icount
        {
            return Err(IoSubNodeError::ExpectedDeliveryMismatch {
                expected: expected_delivery_icount,
                actual: delivery_icount,
            });
        }

        Ok(IoSubNodeCompletion {
            sequence: request.sequence,
            sub_node: self.node.clone(),
            requester: request.requester,
            request_icount: request.request_icount,
            delivery_icount,
            modeled_latency: request.modeled_latency,
            rng_draw: request.rng_draw,
            payload: deterministic_response_payload(&request.payload, request.rng_draw),
        })
    }

    fn sort_in_flight(&mut self) {
        self.in_flight.sort_by(completion_order);
    }
}

impl IoSubNode for DeterministicIoSubNode {
    fn node(&self) -> &SchedulerNodeId {
        &self.node
    }

    fn current_icount(&self) -> Icount {
        self.current_icount
    }

    fn enqueue_request(&mut self, request: IoSubNodeRequest) -> Result<(), IoSubNodeError> {
        if self.in_flight.len() >= self.request_capacity {
            return Err(IoSubNodeError::Backpressure {
                queue: IoSubNodeQueue::RequestInbox,
                capacity: self.request_capacity,
            });
        }
        let completion = self.completion_for(request)?;
        self.in_flight.push(completion);
        self.sort_in_flight();
        Ok(())
    }

    fn advance_to(
        &mut self,
        limit_icount: Icount,
    ) -> Result<Vec<IoSubNodeCompletion>, IoSubNodeError> {
        if limit_icount < self.current_icount {
            return Err(IoSubNodeError::ClockRewind {
                current_icount: self.current_icount,
                requested_icount: limit_icount,
            });
        }
        let due_count = self
            .in_flight
            .iter()
            .take_while(|completion| completion.delivery_icount <= limit_icount)
            .count();
        if due_count == 0 {
            self.current_icount = limit_icount;
            return Ok(Vec::new());
        }
        if self.response_outbox.len() + due_count > self.response_capacity {
            return Err(IoSubNodeError::Backpressure {
                queue: IoSubNodeQueue::ResponseOutbox,
                capacity: self.response_capacity,
            });
        }

        let due = self.in_flight.drain(..due_count).collect::<Vec<_>>();
        self.response_outbox.extend(due.iter().cloned());
        self.response_outbox
            .make_contiguous()
            .sort_by(completion_order);
        self.current_icount = limit_icount;
        Ok(due)
    }

    fn next_exact_local_event(&self) -> Option<Icount> {
        self.in_flight
            .first()
            .map(|completion| completion.delivery_icount)
    }

    fn drain_response_outbox(&mut self) -> Vec<IoSubNodeCompletion> {
        self.response_outbox.drain(..).collect()
    }

    fn snapshot(&self) -> IoSubNodeSnapshot {
        IoSubNodeSnapshot {
            node: self.node.clone(),
            shift: self.shift,
            current_icount: self.current_icount,
            request_capacity: self.request_capacity,
            response_capacity: self.response_capacity,
            in_flight: self.in_flight.clone(),
            response_outbox: self.response_outbox.iter().cloned().collect(),
        }
    }

    fn restore(&mut self, snapshot: IoSubNodeSnapshot) -> Result<(), IoSubNodeError> {
        if snapshot.node != self.node {
            return Err(IoSubNodeError::RestoreNodeMismatch {
                expected: self.node.node.clone(),
                actual: snapshot.node.node,
            });
        }
        validate_snapshot(&snapshot)?;
        self.shift = snapshot.shift;
        self.current_icount = snapshot.current_icount;
        self.request_capacity = snapshot.request_capacity;
        self.response_capacity = snapshot.response_capacity;
        self.in_flight = snapshot.in_flight;
        self.sort_in_flight();
        self.response_outbox = snapshot.response_outbox.into();
        Ok(())
    }
}

/// The bounded queue that produced a deterministic backpressure result.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum IoSubNodeQueue {
    /// Request ingress from the shared-memory ring.
    RequestInbox,
    /// Response egress to the shared-memory ring.
    ResponseOutbox,
}

/// An error raised by the deterministic I/O sub-node lifecycle.
#[derive(Debug, PartialEq, Eq)]
pub enum IoSubNodeError {
    /// The scheduler node kind is not one of the I/O sub-node kinds.
    InvalidNodeKind {
        /// Invalid node kind.
        kind: SchedulingNodeKind,
    },
    /// The completion requester is not a VM scheduler node.
    InvalidRequesterKind {
        /// Invalid requester kind.
        kind: SchedulingNodeKind,
    },
    /// A planned request was sent to the wrong I/O sub-node.
    ExpectedSubNodeMismatch {
        /// Planned producer sub-node.
        expected: SchedulerNodeId,
        /// Actual producer sub-node.
        actual: SchedulerNodeId,
    },
    /// A planned delivery icount did not match the sub-node's local calculation.
    ExpectedDeliveryMismatch {
        /// Planned delivery icount.
        expected: Icount,
        /// Locally computed delivery icount.
        actual: Icount,
    },
    /// A queue capacity was zero.
    ZeroCapacity {
        /// Queue whose capacity was invalid.
        queue: IoSubNodeQueue,
    },
    /// Deterministic backpressure prevented accepting or delivering work.
    Backpressure {
        /// Queue that reached capacity.
        queue: IoSubNodeQueue,
        /// Configured queue capacity.
        capacity: usize,
    },
    /// The scheduler attempted to move the sub-node clock backward.
    ClockRewind {
        /// Current sub-node icount.
        current_icount: Icount,
        /// Requested earlier icount.
        requested_icount: Icount,
    },
    /// A computed completion would be visible before the sub-node clock.
    CompletionBeforeClock {
        /// Current sub-node icount.
        current_icount: Icount,
        /// Computed delivery icount.
        delivery_icount: Icount,
    },
    /// Completion virtual-time computation overflowed.
    CompletionTimeOverflow {
        /// Request icount that overflowed after projection and latency.
        request_icount: Icount,
        /// Modeled latency that could not be added.
        modeled_latency: SimDuration,
    },
    /// Virtual-time conversion failed.
    TimeConversion(TimeConversionError),
    /// A snapshot for one sub-node was restored into another sub-node.
    RestoreNodeMismatch {
        /// Expected node id.
        expected: NodeId,
        /// Snapshot node id.
        actual: NodeId,
    },
    /// A public snapshot failed structural validation.
    InvalidSnapshot {
        /// Deterministic validation failure.
        message: String,
    },
}

impl fmt::Display for IoSubNodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidNodeKind { kind } => {
                write!(
                    formatter,
                    "scheduler node kind {kind:?} is not an I/O sub-node"
                )
            }
            Self::InvalidRequesterKind { kind } => {
                write!(formatter, "I/O requester kind {kind:?} is not a VM node")
            }
            Self::ExpectedSubNodeMismatch { expected, actual } => write!(
                formatter,
                "I/O request expected sub-node {}:{:?} but reached {}:{:?}",
                expected.node.name, expected.kind, actual.node.name, actual.kind
            ),
            Self::ExpectedDeliveryMismatch { expected, actual } => write!(
                formatter,
                "I/O request expected delivery icount {} but computed {}",
                expected.retired, actual.retired
            ),
            Self::ZeroCapacity { queue } => {
                write!(formatter, "I/O sub-node {queue:?} capacity must be nonzero")
            }
            Self::Backpressure { queue, capacity } => write!(
                formatter,
                "I/O sub-node {queue:?} reached deterministic capacity {capacity}"
            ),
            Self::ClockRewind {
                current_icount,
                requested_icount,
            } => write!(
                formatter,
                "I/O sub-node clock cannot move backward from {} to {}",
                current_icount.retired, requested_icount.retired
            ),
            Self::CompletionBeforeClock {
                current_icount,
                delivery_icount,
            } => write!(
                formatter,
                "I/O completion at {} is before sub-node clock {}",
                delivery_icount.retired, current_icount.retired
            ),
            Self::CompletionTimeOverflow {
                request_icount,
                modeled_latency,
            } => write!(
                formatter,
                "I/O completion time overflow for request icount {} latency {}ns",
                request_icount.retired, modeled_latency.nanos
            ),
            Self::TimeConversion(source) => write!(
                formatter,
                "I/O sub-node virtual-time conversion failed: {source}"
            ),
            Self::RestoreNodeMismatch { expected, actual } => write!(
                formatter,
                "I/O sub-node snapshot for {} cannot restore into {}",
                actual.name, expected.name
            ),
            Self::InvalidSnapshot { message } => write!(
                formatter,
                "I/O sub-node snapshot failed validation: {message}"
            ),
        }
    }
}

impl Error for IoSubNodeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::TimeConversion(source) => Some(source),
            Self::InvalidNodeKind { .. }
            | Self::InvalidRequesterKind { .. }
            | Self::ExpectedSubNodeMismatch { .. }
            | Self::ExpectedDeliveryMismatch { .. }
            | Self::ZeroCapacity { .. }
            | Self::Backpressure { .. }
            | Self::ClockRewind { .. }
            | Self::CompletionBeforeClock { .. }
            | Self::CompletionTimeOverflow { .. }
            | Self::RestoreNodeMismatch { .. }
            | Self::InvalidSnapshot { .. } => None,
        }
    }
}

impl From<TimeConversionError> for IoSubNodeError {
    fn from(source: TimeConversionError) -> Self {
        Self::TimeConversion(source)
    }
}

fn validate_snapshot(snapshot: &IoSubNodeSnapshot) -> Result<(), IoSubNodeError> {
    validate_shift(snapshot.shift)?;
    if !matches!(
        snapshot.node.kind,
        SchedulingNodeKind::Disk | SchedulingNodeKind::NineP | SchedulingNodeKind::Network
    ) {
        return Err(invalid_snapshot(format!(
            "node kind {:?} is not an I/O sub-node",
            snapshot.node.kind
        )));
    }
    if snapshot.request_capacity == 0 {
        return Err(invalid_snapshot(String::from(
            "request capacity must be nonzero",
        )));
    }
    if snapshot.response_capacity == 0 {
        return Err(invalid_snapshot(String::from(
            "response capacity must be nonzero",
        )));
    }
    if snapshot.in_flight.len() > snapshot.request_capacity {
        return Err(invalid_snapshot(format!(
            "in-flight queue length {} exceeds request capacity {}",
            snapshot.in_flight.len(),
            snapshot.request_capacity
        )));
    }
    if snapshot.response_outbox.len() > snapshot.response_capacity {
        return Err(invalid_snapshot(format!(
            "response outbox length {} exceeds response capacity {}",
            snapshot.response_outbox.len(),
            snapshot.response_capacity
        )));
    }
    if !is_completion_ordered(&snapshot.in_flight) {
        return Err(invalid_snapshot(String::from(
            "in-flight completions are not in deterministic order",
        )));
    }
    if !is_completion_ordered(&snapshot.response_outbox) {
        return Err(invalid_snapshot(String::from(
            "response outbox completions are not in deterministic order",
        )));
    }

    for completion in &snapshot.in_flight {
        validate_snapshot_completion(snapshot, completion, SnapshotQueue::InFlight)?;
        if completion.delivery_icount < snapshot.current_icount {
            return Err(invalid_snapshot(format!(
                "in-flight completion {} is before current clock {}",
                completion.delivery_icount.retired, snapshot.current_icount.retired
            )));
        }
    }
    for completion in &snapshot.response_outbox {
        validate_snapshot_completion(snapshot, completion, SnapshotQueue::ResponseOutbox)?;
        if completion.delivery_icount > snapshot.current_icount {
            return Err(invalid_snapshot(format!(
                "response outbox completion {} is after current clock {}",
                completion.delivery_icount.retired, snapshot.current_icount.retired
            )));
        }
    }

    Ok(())
}

fn validate_shift(shift: Shift) -> Result<(), IoSubNodeError> {
    let _ = Icount { retired: 0 }.to_virtual(shift)?;
    Ok(())
}

fn validate_snapshot_completion(
    snapshot: &IoSubNodeSnapshot,
    completion: &IoSubNodeCompletion,
    queue: SnapshotQueue,
) -> Result<(), IoSubNodeError> {
    if completion.sub_node != snapshot.node {
        return Err(invalid_snapshot(format!(
            "{queue:?} completion belongs to {}:{:?}, not {}:{:?}",
            completion.sub_node.node.name,
            completion.sub_node.kind,
            snapshot.node.node.name,
            snapshot.node.kind
        )));
    }
    if completion.requester.kind != SchedulingNodeKind::Vm {
        return Err(invalid_snapshot(format!(
            "{queue:?} completion requester {}:{:?} is not a VM node",
            completion.requester.node.name, completion.requester.kind
        )));
    }
    let expected_delivery = completion_delivery_icount(
        snapshot.shift,
        completion.request_icount,
        completion.modeled_latency,
    )?;
    if completion.delivery_icount != expected_delivery {
        return Err(invalid_snapshot(format!(
            "{queue:?} completion delivery icount {} does not match deterministic request+latency icount {}",
            completion.delivery_icount.retired, expected_delivery.retired
        )));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug)]
enum SnapshotQueue {
    InFlight,
    ResponseOutbox,
}

fn invalid_snapshot(message: String) -> IoSubNodeError {
    IoSubNodeError::InvalidSnapshot { message }
}

fn is_completion_ordered(completions: &[IoSubNodeCompletion]) -> bool {
    completions
        .windows(2)
        .all(|pair| completion_order(&pair[0], &pair[1]) != std::cmp::Ordering::Greater)
}

fn completion_delivery_icount(
    shift: Shift,
    request_icount: Icount,
    modeled_latency: SimDuration,
) -> Result<Icount, IoSubNodeError> {
    let request_time = request_icount.to_virtual(shift)?;
    let completion_time = request_time
        .nanos
        .checked_add(modeled_latency.nanos)
        .ok_or(IoSubNodeError::CompletionTimeOverflow {
            request_icount,
            modeled_latency,
        })?;
    Ok(VirtualInstant {
        nanos: completion_time,
    }
    .to_icount_ceil(shift)?)
}

fn completion_order(left: &IoSubNodeCompletion, right: &IoSubNodeCompletion) -> std::cmp::Ordering {
    left.delivery_icount
        .cmp(&right.delivery_icount)
        .then_with(|| left.sub_node.cmp(&right.sub_node))
        .then_with(|| left.sequence.cmp(&right.sequence))
        .then_with(|| left.requester.cmp(&right.requester))
}

fn deterministic_response_payload(request_payload: &[u8], rng_draw: Option<u64>) -> Vec<u8> {
    let mut payload =
        Vec::with_capacity(request_payload.len() + usize::from(rng_draw.is_some()) * 8);
    payload.extend_from_slice(request_payload);
    if let Some(draw) = rng_draw {
        payload.extend_from_slice(&draw.to_le_bytes());
    }
    payload
}
