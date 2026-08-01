//! The in-process device test harness and the idle-vs-busy-poll proof.
//!
//! RFC-0010 §15.7 states that, because each I/O sub-node is a node with a
//! request inbox and a response outbox, every device is **testable without a
//! real QEMU**: a test constructs the node, enqueues a sequence of requests at
//! chosen request-icounts, advances the clock to chosen limits, and asserts the
//! resulting responses, their delivery icounts, and the device-visible state
//! ([IO-27]). This module owns that harness and makes it reusable across the
//! three structurally-different sub-nodes (block/9p ride
//! [`IoCore`](crate::subnode::IoCore) and answer
//! `submit`/`advance_to`/`next_response`; the network link has its own
//! `emit`/`advance_to`/`next_delivery`).
//!
//! # The unified surface
//!
//! Each device kind implements [`HarnessDevice`], which projects its
//! device-specific request, advance, and drain surface onto a single normalized
//! observation: a [`DeliveryRecord`] stream. A [`DeliveryRecord`] is the
//! device-agnostic, byte-comparable shape of one delivered response —
//! `(delivery_icount, src_node, seq, correlation_id, status, payload)` — drawn
//! straight from the [`FrameDeliveryKey`] total order ([IO-10], [SHM-34]). A
//! [`Script`] is a list of [`Step`]s (enqueue a
//! request at an icount, or advance the clock to a limit); [`run_script`] drives
//! a freshly-constructed device through a script and returns the ordered
//! [`DeliveryLog`].
//!
//! ```text
//! Script = [ Step::Request{ at_icount, request },   (ARRIVE + COMPUTE)
//!            Step::AdvanceTo{ limit },               (DELIVER drains due)
//!            ... ]
//! run_script(device_factory, script) -> DeliveryLog (the ordered records)
//! ```
//!
//! # Run-twice determinism and divergence localization
//!
//! [`run_twice`] runs the same script through two independently-constructed
//! devices and compares their logs; a byte-identical pair proves the per-device
//! run-twice determinism of [IO-28]. When two runs differ, [`localize_divergence`]
//! reports the **first** differing point deterministically — the record index,
//! and within that record the first field (delivery icount, status, byte offset,
//! …) that differs — mirroring the scheduler's divergence bisector but for a
//! single device's response stream ([IO-28], [INV-10]).
//!
//! The comparison helpers are **panic-free production code**: they return a
//! structured [`Divergence`] rather than asserting, so the harness itself meets
//! the crate's no-`unwrap`/no-`panic` bar. Tests turn a [`Divergence`] into an
//! assertion at their boundary.
//!
//! # The idle-vs-busy-poll proof (§15.8)
//!
//! [`idle_busy_poll_equivalence`] drives the *same* script two ways — one big
//! `advance_to(limit)` (the idle / fast-forward path, [SCHED-28]) versus many
//! `advance_to` steps of one icount each (the busy-poll path) — and returns
//! whether the two delivery logs are byte-identical. Because a completion's
//! `delivery_icount` is fixed at COMPUTE and the in-flight queue drains strictly
//! by `delivery_icount <= limit`, the two paths MUST agree: a completion lands at
//! its exact icount regardless of how the consumer advances ([IO-29]). The
//! documented [`BUSY_POLL_SPIKE`] records the §15.8 spike conclusion ([IO-30]).
//!
//! # Coverage note: network-link emit-after-advance
//!
//! The generic harness applies every [`Step::Request`] before any advance, so a
//! link emits all of its frames while the consumer frontier is still at icount
//! zero. This means the generic path does **not** exercise
//! [`NetLink`](crate::netlink::link::NetLink)'s
//! `guard_future` clamp-to-`frontier+1` (the one link behavior whose result
//! depends on the consumer frontier *at emit time*, [IO-34]): that path requires
//! emitting after the clock has already advanced past where a frame would land.
//! The `netlink` unit tests cover the clamp and fail-loud paths directly
//! (`reorder_into_consumer_past_clamps_to_future`,
//! `reorder_into_consumer_past_fails_loud`); the harness here proves the
//! frontier-zero delivery and idle-vs-busy-poll equivalence, not the
//! emit-after-advance clamp.

use crucible_shmem::FrameDeliveryKey;

use crate::error::DeviceError;
use crate::request::ResponseStatus;

pub mod adapters;

pub use adapters::{BlockHarness, LinkRequest, NetLinkHarness, NinepHarness};

/// One normalized, byte-comparable delivered response.
///
/// This is the device-agnostic projection of a single delivery: the
/// deterministic delivery-order key (`delivery_icount`, `src_node`, `seq`), the
/// correlation id (a block/9p `request_id` or a link `frame_id`), the terminal
/// status, and the response payload. Two devices that deliver byte-identical
/// records in byte-identical order are observationally identical for the
/// purposes of [IO-28].
///
/// The fields are ordered so the natural [`PartialEq`] and the field-by-field
/// [`localize_divergence`] walk agree on what "first difference" means.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeliveryRecord {
    /// The exact icount at which the response became visible ([IO-2]).
    pub delivery_icount: u64,
    /// The source-node id stamped into the delivery key (the sub-node's id).
    pub src_node: u32,
    /// The per-delivery sequence number that breaks coincident-icount ties.
    pub seq: u32,
    /// The correlation id (block/9p `request_id`, or link `frame_id`).
    pub correlation_id: u32,
    /// The terminal status of the response.
    pub status: ResponseStatus,
    /// The response payload bytes (read data, reply frame, or delivered frame).
    pub payload: Vec<u8>,
}

impl DeliveryRecord {
    /// Builds a record from a delivery key, correlation id, status, and payload.
    #[must_use]
    pub fn new(
        key: FrameDeliveryKey,
        correlation_id: u32,
        status: ResponseStatus,
        payload: Vec<u8>,
    ) -> Self {
        Self {
            delivery_icount: key.delivery_icount,
            src_node: key.src_node,
            seq: key.seq,
            correlation_id,
            status,
            payload,
        }
    }
}

/// The ordered log of every record a script produced, in delivery order.
///
/// A `DeliveryLog` is the canonical observation of a run: [`run_script`] returns
/// one, and the determinism and idle-vs-busy-poll proofs compare two. The
/// records are in the order they were drained from the in-flight queue, which is
/// the deterministic `(delivery_icount, src_node, seq)` total order ([IO-10]).
pub type DeliveryLog = Vec<DeliveryRecord>;

/// A single step in a device test [`Script`].
///
/// A script interleaves request enqueues (ARRIVE + COMPUTE, which fixes a
/// response's delivery icount) with clock advances (DELIVER, which drains the
/// responses now due). The request payload is `R`, the device's own request
/// type (a [`crate::block::BlockRequest`], a 9p frame `Vec<u8>`, or a link
/// `(Frame, FrameDraws)` pair), so a script is fully device-specific in its
/// inputs but fully uniform in its observations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Step<R> {
    /// Enqueue `request` at the requester's emit `at_icount` (ARRIVE+COMPUTE).
    Request {
        /// The requester's icount when the request is emitted.
        at_icount: u64,
        /// The device-specific request payload.
        request: R,
    },
    /// Advance the device clock to `limit`, draining every due response.
    AdvanceTo {
        /// The icount to advance the consumer clock to.
        limit: u64,
    },
}

/// A device-specific request/advance script driving one harness run.
///
/// `R` is the device's request type. Build one with [`Script::new`] and the
/// [`Script::request`] / [`Script::advance_to`] builders, then feed it to
/// [`run_script`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Script<R> {
    steps: Vec<Step<R>>,
}

impl<R> Default for Script<R> {
    fn default() -> Self {
        Self::new()
    }
}

impl<R> Script<R> {
    /// Creates an empty script.
    #[must_use]
    pub fn new() -> Self {
        Self { steps: Vec::new() }
    }

    /// Appends a request enqueue at `at_icount` (builder form).
    #[must_use]
    pub fn request(mut self, at_icount: u64, request: R) -> Self {
        self.steps.push(Step::Request { at_icount, request });
        self
    }

    /// Appends a clock advance to `limit` (builder form).
    #[must_use]
    pub fn advance_to(mut self, limit: u64) -> Self {
        self.steps.push(Step::AdvanceTo { limit });
        self
    }

    /// Returns the script's steps in order.
    #[must_use]
    pub fn steps(&self) -> &[Step<R>] {
        &self.steps
    }

    /// Returns the largest `AdvanceTo` limit in the script, if any.
    ///
    /// This is the natural single fast-forward target for the idle path of the
    /// idle-vs-busy-poll proof: advancing once to the script's maximum limit
    /// drains everything the per-step advances would have ([IO-29]).
    #[must_use]
    pub fn max_advance_limit(&self) -> Option<u64> {
        self.steps
            .iter()
            .filter_map(|step| match step {
                Step::AdvanceTo { limit } => Some(*limit),
                Step::Request { .. } => None,
            })
            .max()
    }
}

/// A device adapter that the uniform harness can drive ([IO-27]).
///
/// Implementors project their structurally-distinct surface — block/9p's
/// `submit`/`advance_to`/`next_response`, or the link's `emit`/`advance_to`/
/// `next_delivery` — onto three uniform operations the harness composes: apply
/// one request, advance the clock, and drain due deliveries as normalized
/// [`DeliveryRecord`]s. Every method MUST be deterministic ([IO-4]); the harness
/// never reads host time.
pub trait HarnessDevice {
    /// The device-specific request type carried in a [`Step::Request`].
    type Request: Clone;

    /// Applies one request at `at_icount` (the ARRIVE + COMPUTE step).
    ///
    /// The implementor enqueues the request at the requester's emit icount and
    /// drives COMPUTE, fixing the response's delivery icount. It does **not**
    /// advance the consumer clock — that is [`HarnessDevice::advance_to`].
    ///
    /// # Errors
    ///
    /// Returns any [`DeviceError`] the device raises while enqueueing or
    /// COMPUTEing the request (ring-full backpressure, a past-delivery guard, a
    /// completion overflow, …).
    fn apply_request(&mut self, at_icount: u64, request: &Self::Request)
    -> Result<(), DeviceError>;

    /// Advances the consumer clock to `limit`, making due responses visible.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError::ClockRegression`] when `limit` is below the device's
    /// current icount, or any other [`DeviceError`] the device's advance raises.
    fn advance_to(&mut self, limit: u64) -> Result<(), DeviceError>;

    /// Drains every response made visible so far as normalized records.
    ///
    /// Returns the records in their deterministic delivery order; draining an
    /// empty outbox returns an empty `Vec`. Repeated calls return only the
    /// not-yet-drained records.
    ///
    /// # Errors
    ///
    /// Returns a [`DeviceError`] only if a delivered payload cannot be projected
    /// to a record (for a block device this means a response the device itself
    /// produced failed to decode, which indicates an internal codec bug, never
    /// external input).
    fn drain_records(&mut self) -> Result<Vec<DeliveryRecord>, DeviceError>;

    /// Returns the device's next exact local event (in-flight head icount).
    ///
    /// This is the scheduler-visible bound ([IO-3], [IO-31]); the harness uses it
    /// to size the busy-poll path's per-step advances. `None` when nothing is in
    /// flight.
    fn next_exact_local_event(&self) -> Option<u64>;
}

/// Drives a freshly-built device through `script`, returning its delivery log.
///
/// `factory` constructs the device (each run gets an independent construction so
/// `run_twice` compares two genuinely separate devices, [IO-28]). The script's
/// steps are applied in order: a [`Step::Request`] enqueues and COMPUTEs a
/// request; a [`Step::AdvanceTo`] advances the clock and the harness then drains
/// every newly-visible record into the log. The returned log is the run's
/// canonical observation.
///
/// # Errors
///
/// Returns any [`DeviceError`] raised while applying a request, advancing the
/// clock, or draining records — the run fails loudly rather than silently
/// dropping a step.
pub fn run_script<D, F>(
    mut factory: F,
    script: &Script<D::Request>,
) -> Result<DeliveryLog, DeviceError>
where
    D: HarnessDevice,
    F: FnMut() -> D,
{
    let mut device = factory();
    let mut log = DeliveryLog::new();
    for step in script.steps() {
        match step {
            Step::Request { at_icount, request } => {
                device.apply_request(*at_icount, request)?;
            }
            Step::AdvanceTo { limit } => {
                device.advance_to(*limit)?;
                log.extend(device.drain_records()?);
            }
        }
    }
    Ok(log)
}

/// The result of comparing two delivery logs for the run-twice property.
///
/// `Identical` means the two runs produced byte-identical records in identical
/// order — the success signal of [IO-28]. `Diverged` localizes the **first**
/// difference deterministically (see [`Divergence`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LogComparison {
    /// The two logs are byte-identical: run-twice determinism holds.
    Identical,
    /// The two logs differ; the contained [`Divergence`] is the first point.
    Diverged(Divergence),
}

impl LogComparison {
    /// Returns whether the two logs were byte-identical.
    #[must_use]
    pub fn is_identical(&self) -> bool {
        matches!(self, LogComparison::Identical)
    }

    /// Returns the localized divergence, if the logs differed.
    #[must_use]
    pub fn divergence(&self) -> Option<&Divergence> {
        match self {
            LogComparison::Identical => None,
            LogComparison::Diverged(d) => Some(d),
        }
    }
}

/// The first deterministically-localized point at which two runs differ.
///
/// `record_index` is the index of the first differing [`DeliveryRecord`] in
/// delivery order; `field` names which field of that record diverged first,
/// walked in the fixed field order of [`DeliveryRecord`] so localization is
/// itself deterministic ([IO-28]). A length mismatch (one run produced fewer
/// records) is reported as a divergence at the first index the shorter log lacks,
/// with [`DivergedField::Missing`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Divergence {
    /// The index of the first differing record in delivery order.
    pub record_index: usize,
    /// The first field of that record that differs.
    pub field: DivergedField,
}

/// Which field of a [`DeliveryRecord`] diverged first, in fixed walk order.
///
/// The variants are checked in the order they are listed, matching the field
/// order of [`DeliveryRecord`], so the *first* difference is always the same
/// across runs ([IO-28]). For a payload mismatch the exact differing byte offset
/// is reported, mirroring the scheduler's byte-level bisector.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DivergedField {
    /// One run produced a record the other lacked at this index.
    Missing {
        /// `true` when the left (first) run is the one missing the record.
        left_missing: bool,
    },
    /// The two records' delivery icounts differ.
    DeliveryIcount {
        /// The left run's delivery icount.
        left: u64,
        /// The right run's delivery icount.
        right: u64,
    },
    /// The two records' source-node ids differ.
    SrcNode {
        /// The left run's source-node id.
        left: u32,
        /// The right run's source-node id.
        right: u32,
    },
    /// The two records' sequence numbers differ.
    Seq {
        /// The left run's sequence number.
        left: u32,
        /// The right run's sequence number.
        right: u32,
    },
    /// The two records' correlation ids differ.
    CorrelationId {
        /// The left run's correlation id.
        left: u32,
        /// The right run's correlation id.
        right: u32,
    },
    /// The two records' terminal statuses differ.
    Status {
        /// The left run's status.
        left: ResponseStatus,
        /// The right run's status.
        right: ResponseStatus,
    },
    /// The two records' payload lengths differ.
    PayloadLen {
        /// The left run's payload length in bytes.
        left: usize,
        /// The right run's payload length in bytes.
        right: usize,
    },
    /// The payloads have equal length but differ at this byte offset.
    PayloadByte {
        /// The zero-based byte offset of the first differing byte.
        offset: usize,
        /// The left run's byte at that offset.
        left: u8,
        /// The right run's byte at that offset.
        right: u8,
    },
}

/// Compares two delivery logs and localizes the first difference, if any.
///
/// Walks the two logs in lockstep. The first index whose records differ (or that
/// one log lacks) yields a [`Divergence`] naming the record index and the first
/// differing field, in the fixed [`DeliveryRecord`] field order ([IO-28]). The
/// walk is a pure function of the two logs — no host state, no hashing — so the
/// localized point is reproducible run-to-run, the property the divergence
/// bisector relies on.
///
/// Returns [`LogComparison::Identical`] when the logs are byte-identical.
#[must_use]
pub fn compare_logs(left: &[DeliveryRecord], right: &[DeliveryRecord]) -> LogComparison {
    let common = left.len().min(right.len());
    for index in 0..common {
        if let Some(field) = first_differing_field(&left[index], &right[index]) {
            return LogComparison::Diverged(Divergence {
                record_index: index,
                field,
            });
        }
    }
    if left.len() != right.len() {
        return LogComparison::Diverged(Divergence {
            record_index: common,
            field: DivergedField::Missing {
                left_missing: left.len() < right.len(),
            },
        });
    }
    LogComparison::Identical
}

/// Localizes the divergence between two logs, or `None` if identical.
///
/// A thin projection of [`compare_logs`] for callers that want only the
/// [`Divergence`]; returns `None` exactly when the logs are byte-identical.
#[must_use]
pub fn localize_divergence(
    left: &[DeliveryRecord],
    right: &[DeliveryRecord],
) -> Option<Divergence> {
    match compare_logs(left, right) {
        LogComparison::Identical => None,
        LogComparison::Diverged(divergence) => Some(divergence),
    }
}

/// Returns the first field in which two records differ, in fixed walk order.
///
/// `None` when the records are byte-identical. The order matches the
/// [`DeliveryRecord`] field order so the "first difference" is canonical.
fn first_differing_field(left: &DeliveryRecord, right: &DeliveryRecord) -> Option<DivergedField> {
    if left.delivery_icount != right.delivery_icount {
        return Some(DivergedField::DeliveryIcount {
            left: left.delivery_icount,
            right: right.delivery_icount,
        });
    }
    if left.src_node != right.src_node {
        return Some(DivergedField::SrcNode {
            left: left.src_node,
            right: right.src_node,
        });
    }
    if left.seq != right.seq {
        return Some(DivergedField::Seq {
            left: left.seq,
            right: right.seq,
        });
    }
    if left.correlation_id != right.correlation_id {
        return Some(DivergedField::CorrelationId {
            left: left.correlation_id,
            right: right.correlation_id,
        });
    }
    if left.status != right.status {
        return Some(DivergedField::Status {
            left: left.status,
            right: right.status,
        });
    }
    if left.payload.len() != right.payload.len() {
        return Some(DivergedField::PayloadLen {
            left: left.payload.len(),
            right: right.payload.len(),
        });
    }
    for (offset, (l, r)) in left.payload.iter().zip(right.payload.iter()).enumerate() {
        if l != r {
            return Some(DivergedField::PayloadByte {
                offset,
                left: *l,
                right: *r,
            });
        }
    }
    None
}

/// Runs `script` twice through independently-built devices and compares the logs.
///
/// This is the run-twice determinism helper of [IO-28]: a
/// [`LogComparison::Identical`] result proves two independent constructions
/// driven through the same script produce byte-identical responses at
/// byte-identical delivery icounts; a [`LogComparison::Diverged`] result carries
/// the first differing point for the divergence path ([INV-10]).
///
/// # Errors
///
/// Returns any [`DeviceError`] either run raises while executing the script.
pub fn run_twice<D, F>(
    mut factory: F,
    script: &Script<D::Request>,
) -> Result<LogComparison, DeviceError>
where
    D: HarnessDevice,
    F: FnMut() -> D,
{
    let first = run_script::<D, _>(&mut factory, script)?;
    let second = run_script::<D, _>(&mut factory, script)?;
    Ok(compare_logs(&first, &second))
}

/// The result of the idle-vs-busy-poll equivalence proof for one script.
///
/// Carries both delivery logs (the idle / one-big-advance path and the busy-poll
/// / many-small-advances path) and their comparison. [`IdleBusyPoll::is_equivalent`]
/// is the [IO-29] success signal: the completion landed at its exact icount
/// regardless of how the consumer advanced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdleBusyPoll {
    /// The log produced by the idle path (one `advance_to(max_limit)`).
    pub idle_log: DeliveryLog,
    /// The log produced by the busy-poll path (repeated `advance_to(+1)`).
    pub busy_poll_log: DeliveryLog,
    /// The comparison of the two logs.
    pub comparison: LogComparison,
}

impl IdleBusyPoll {
    /// Returns whether the idle and busy-poll logs are byte-identical ([IO-29]).
    #[must_use]
    pub fn is_equivalent(&self) -> bool {
        self.comparison.is_identical()
    }
}

/// Proves a script's completions are independent of how the consumer advances.
///
/// Runs the script's requests against two freshly-built devices, then DELIVERs
/// two different ways ([IO-29]):
///
/// - the **idle / fast-forward** path advances once to the script's maximum
///   advance limit (the scheduler collapsing an idle wait to one jump,
///   [SCHED-28]) and **drains to quiescent** at that limit;
/// - the **busy-poll** path advances one icount at a time from the device's start
///   up to that same limit (the guest spinning, retiring instructions the whole
///   way), draining to quiescent at each step.
///
/// Both paths drain into a log; the two logs MUST be byte-identical because a
/// completion's `delivery_icount` is fixed at COMPUTE and the in-flight queue
/// drains strictly by `delivery_icount <= limit` — neither the size nor the count
/// of the advance steps can move a delivery off its exact icount ([IO-2],
/// [IO-29]). The drain-to-quiescent loop (`drain_to_quiescent`) is essential
/// for block/9p, whose **bounded outbox** ([IO-32]) caps any single
/// `advance_to`+`drain` at `outbox_capacity` records: without it the one-shot
/// idle drain would under-report a coincident batch larger than the outbox while
/// the per-step busy-poll path reported it in full, manufacturing a false
/// divergence on a deterministic device.
///
/// All [`Step::Request`]s in the script are applied first (in order) and the
/// advance limit is taken from [`Script::max_advance_limit`]; any
/// [`Step::AdvanceTo`] in the script only contributes its limit, since this proof
/// supplies its own two advance strategies. A script with no advance step (no
/// limit) drains nothing and the two empty logs are trivially equivalent.
///
/// # Relationship to [`run_script`]
///
/// This helper uses a **different idle model** than [`run_script`], deliberately.
/// [`run_script`] honors every in-script [`Step::AdvanceTo`] in place (advancing
/// and draining at each one, the natural in-process-double drive), whereas this
/// proof discards the in-script advance *positions* — applying all requests up
/// front, then DELIVERing via its own two strategies to a single terminal limit.
/// Because both of this helper's strategies now drain to quiescent, each reaches
/// the same terminal state as a complete `run_script` drive whose only advance is
/// a single trailing `advance_to(max_limit)`. For a script with *interleaved*
/// advances, though, `run_twice` (which preserves advance positions) and this
/// helper observe genuinely different drives; a caller must not assume one's
/// `Identical`/`Diverged` verdict transfers to the other on such a script.
///
/// # Errors
///
/// Returns any [`DeviceError`] either path raises while applying requests or
/// advancing the clock.
pub fn idle_busy_poll_equivalence<D, F>(
    mut factory: F,
    script: &Script<D::Request>,
) -> Result<IdleBusyPoll, DeviceError>
where
    D: HarnessDevice,
    F: FnMut() -> D,
{
    let limit = script.max_advance_limit().unwrap_or(0);

    // Idle path: apply every request, then one big fast-forward to `limit`,
    // then drain to quiescent. A single `drain_records` is NOT enough: block/9p
    // deliver through a *bounded outbox*, and `IoCore::advance_to` stops
    // mid-drain when the outbox fills, leaving the surplus in flight. Re-issuing
    // `advance_to(limit)` pushes the next outbox-full batch, so we loop
    // advance+drain until the device is quiescent at `limit` — the same terminal
    // state the busy-poll path reaches. Without this loop a capped idle log would
    // diverge from a fully-drained busy-poll log on a perfectly deterministic
    // device ([IO-29]).
    let idle_log = {
        let mut device = factory();
        apply_all_requests(&mut device, script)?;
        // `drain_to_quiescent` advances to `limit` itself and loops until the
        // bounded outbox is fully drained at `limit`.
        drain_to_quiescent(&mut device, limit)?
    };

    // Busy-poll path: apply every request, then advance one icount at a time,
    // draining to quiescent at every step. Per-step quiescent draining means a
    // bounded outbox cannot cap a coincident-delivery batch at any single icount.
    let busy_poll_log = {
        let mut device = factory();
        apply_all_requests(&mut device, script)?;
        let mut log = DeliveryLog::new();
        // Drain anything already due at icount zero (a request whose latency
        // rounds to the current icount) before stepping.
        log.extend(drain_to_quiescent(&mut device, 0)?);
        let mut current = 0u64;
        while current < limit {
            current += 1;
            log.extend(drain_to_quiescent(&mut device, current)?);
        }
        log
    };

    let comparison = compare_logs(&idle_log, &busy_poll_log);
    Ok(IdleBusyPoll {
        idle_log,
        busy_poll_log,
        comparison,
    })
}

/// Drains every response due at `limit`, re-advancing to clear a bounded outbox.
///
/// The crux of the idle/busy-poll equivalence on a bounded-outbox device
/// (block/9p): [`HarnessDevice::advance_to`] may stop delivering mid-drain when
/// the device's outbox fills, leaving the surplus in flight at their exact
/// icounts. This helper loops `drain_records` (and re-`advance_to(limit)` to push
/// the next outbox-full batch) until the device is **quiescent at `limit`** —
/// nothing left to drain and no in-flight head at or below `limit`. The result is
/// the complete, order-preserving set of records due by `limit`, independent of
/// the outbox capacity, so neither the size nor the count of advances can change
/// the log ([IO-29], [IO-32]).
///
/// Termination: each iteration either drains at least one record (progress) or
/// drains none, in which case the loop exits. A device whose `next_exact_local_event`
/// stays at or below `limit` while delivering nothing would be a contract
/// violation (a due response the device refuses to deliver); the loop's exit
/// condition treats "drained nothing this pass" as quiescent, so it can never
/// spin.
///
/// # Errors
///
/// Returns any [`DeviceError`] the device raises while advancing or draining.
fn drain_to_quiescent<D>(device: &mut D, limit: u64) -> Result<DeliveryLog, DeviceError>
where
    D: HarnessDevice,
{
    let mut log = DeliveryLog::new();
    loop {
        // Re-advance to the same `limit` and drain. For a bounded-outbox device
        // (block/9p) this pushes the next outbox-full batch of responses still in
        // flight at or below `limit`; for the link (no outbox) the re-advance to
        // the unchanged frontier yields nothing, so the loop ends after the
        // initial batch. Re-advancing to the current frontier is a clock no-op,
        // never a regression.
        device.advance_to(limit)?;
        let batch = device.drain_records()?;
        if batch.is_empty() {
            // Quiescent: nothing more could be made visible at `limit`. Any
            // remaining in-flight head is strictly in the future (> limit).
            break;
        }
        log.extend(batch);
    }
    Ok(log)
}

/// Applies every [`Step::Request`] in `script` in order, ignoring advance steps.
///
/// Shared by the two idle-vs-busy-poll paths so both see exactly the same
/// in-flight queue before they begin advancing.
///
/// # Errors
///
/// Returns any [`DeviceError`] the device raises while applying a request.
fn apply_all_requests<D>(device: &mut D, script: &Script<D::Request>) -> Result<(), DeviceError>
where
    D: HarnessDevice,
{
    for step in script.steps() {
        if let Step::Request { at_icount, request } = step {
            device.apply_request(*at_icount, request)?;
        }
    }
    Ok(())
}

/// The §15.8 busy-poll spike conclusion, recorded as a documented constant.
///
/// RFC-0010 §15.8 / [IO-30] asks the implementation to *characterize* guest
/// busy-polling during a blocking I/O and to record whether a mitigation is
/// warranted — a spike result, not a live measurement. [`BusyPollSpike`] is the
/// data shape of that conclusion; [`BUSY_POLL_SPIKE`] is the recorded finding.
///
/// The load-bearing facts the spike establishes, all proven in-process by
/// [`idle_busy_poll_equivalence`]:
///
/// - **Correctness is independent of idle-vs-busy-poll.** A completion lands at
///   its exact computed icount whether the consumer idles (one fast-forward) or
///   busy-polls (many single-icount advances) ([IO-29]). The idle-during-I/O
///   assumption ([IO-3]) is therefore a **performance optimization only**.
/// - **Busy-poll is a performance cost, not a correctness risk.** A spinning
///   guest retires a deterministic instruction count and defeats idle
///   fast-forward, so the wait costs real wall-clock; the *result* is identical.
/// - **Any mitigation MUST preserve exactness.** A busy-poll fast-forward may
///   collapse only a span whose deterministic outcome is provably identical to
///   running it instruction-by-instruction; it may not change which instruction
///   observes the completion ([IO-30]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BusyPollSpike {
    /// Whether correctness holds under both idle and busy-poll ([IO-29]).
    ///
    /// Always `true`: the in-process equivalence proof shows a completion lands
    /// at its exact icount under either consumer advance strategy.
    pub correctness_independent_of_poll_mode: bool,
    /// Whether busy-poll is purely a performance cost (not a correctness risk).
    ///
    /// Always `true`: a busy-poll run is slower but byte-identical.
    pub busy_poll_is_performance_only: bool,
    /// Whether any future busy-poll mitigation must preserve exactness ([IO-30]).
    ///
    /// Always `true`: a mitigation may collapse only a provably-identical span and
    /// may not move which instruction observes the completion.
    pub mitigation_must_preserve_exactness: bool,
}

/// The recorded §15.8 spike conclusion ([IO-30]).
///
/// Completion exactness is preserved under both the idle/fast-forward and the
/// busy-poll consumer paths; busy-poll is a performance concern only; and any
/// mitigation it motivates must preserve exactness. This is the documented spike
/// result the RFC requires, not a runtime measurement — the live half of the
/// claim is exercised by [`idle_busy_poll_equivalence`] across all three device
/// kinds.
pub const BUSY_POLL_SPIKE: BusyPollSpike = BusyPollSpike {
    correctness_independent_of_poll_mode: true,
    busy_poll_is_performance_only: true,
    mitigation_must_preserve_exactness: true,
};
