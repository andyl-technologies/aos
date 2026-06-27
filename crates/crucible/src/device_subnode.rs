//! Scheduling sub-nodes: the L3 seam that drives L1 I/O devices from the scheduler.
//!
//! Spec index: RFC-0010 file 15 (I/O sub-nodes) §15.1, file 08 (scheduling)
//! §8.4.1, §8.9.4.
//!
//! This module is the integration capstone that wires the `crucible-device` (L1)
//! disk/9p/network sub-nodes into the [`SingleScheduler`](crate::SingleScheduler)
//! (L3) so that **cross-node I/O injection is icount-deterministic** (Contract B,
//! [IO-2], [IO-4], [SCHED-29]). A [`DeviceSchedulingSubNode`] holds a concrete
//! device's [`IoCore`](crucible_device::IoCore) — the in-flight queue of
//! computed-not-delivered responses — together with its scheduling identity and
//! the per-device fault table.
//!
//! # The two scheduler couplings
//!
//! 1. **Horizon term.** A sub-node's
//!    [`next_exact_local_event`](DeviceSchedulingSubNode::next_exact_local_event)
//!    is its in-flight head's **final** (post-fault) `delivery_icount` ([IO-31]).
//!    The scheduler folds it into the owning VM node's
//!    [`NextExactLocalEvent::io_completion`](crate::NextExactLocalEvent) term, so
//!    an otherwise-idle requester is fast-forwarded **exactly** to its next I/O
//!    completion with no conservative slack ([IO-3], [SCHED-10]).
//! 2. **RESOLVE delivery.** When the requester's frontier reaches a completion's
//!    `delivery_icount`, [`DeviceSchedulingSubNode::deliver_due`] makes the
//!    response visible at exactly that icount in the canonical
//!    `(delivery_icount, src_node, seq)` total order ([IO-10], [SCHED-29]),
//!    transport-timing-independent, and appends the per-device fault
//!    [`Decision`](crate::Decision)s the completion drew ([SCHED-30]).
//!
//! # When fault choices are drawn vs recorded
//!
//! A probabilistic device fault (jitter/reorder/loss/duplicate/corrupt/bandwidth)
//! is **drawn from the per-device RNG at COMPUTE**, when
//! [`DeviceSchedulingSubNode::submit`] resolves the modeled completion through
//! [`crucible_device::IoFaults::resolve`]. Drawing at COMPUTE is what lets the
//! perturbed (final) `delivery_icount` enter the in-flight queue, so the horizon
//! term the scheduler reads is the **exact** completion the requester will
//! observe — never a pre-fault estimate the run would then have to deliver late.
//! The raw draws and fault outcomes are buffered with the pending completion and
//! **recorded as [`Decision`](crate::Decision)s on the RESOLVE path**, in delivery
//! order, so the recorded schedule is appended in the §8.6 total order exactly as
//! [`resolve_frame`](crate::scheduler) records a link-loss outcome ([SCHED-30]).
//!
//! ```text
//! submit(req):  COMPUTE response -> IoFaults::resolve(rng)  -> final delivery_icount
//!               buffer { delivery_icount, payload, decisions } in the inflight queue
//! horizon:      next_exact_local_event() = inflight head final delivery_icount
//! deliver_due(consumer_icount):
//!               for each completion with delivery_icount <= consumer_icount, in
//!               (delivery_icount, src_node, seq) order:
//!                 emit IoCompletion @ delivery_icount ; append its buffered decisions
//! ```

use crucible_device::{BlockDevice, BlockRequest, DeviceError, ResponseStatus};

use crate::scheduler::IoCompletion;
use crate::{
    Decision, DeviceId, FaultDecision, FaultId, NodeId, RngDecision, SchedulerNodeId, Seed,
};

/// High-bit tie-break namespace for duplicate-fault completions.
///
/// A duplicate response shares its primary's `src_node` and is delivered a fixed
/// gap later, but it must never collide with a *sibling* request's primary `seq`
/// in the `(delivery_icount, src_node, seq)` order. Primary `seq` values are small
/// sequential request counts from the device core, so OR-ing this top bit places
/// every duplicate in a disjoint namespace.
const DUPLICATE_SEQ_NAMESPACE: u32 = 1 << 31;

/// One modeled (pre-fault) completion the device COMPUTEd, ordered by its
/// modeled delivery key. Fault resolution is a pure function of the *sorted* set
/// of these, so COMPUTE/submit order never affects the result ([IO-4]).
#[derive(Clone, Debug, PartialEq, Eq)]
struct ModeledCompletion {
    /// The modeled (pre-fault) completion icount.
    modeled_icount: u64,
    /// The source-node id stamped into the delivery order key.
    src_node: u32,
    /// The per-completion sequence stamped by the device core.
    seq: u32,
    /// The modeled response status.
    status: ResponseStatus,
    /// The modeled response payload.
    payload: Vec<u8>,
}

/// One pending device completion: its final delivery icount, payload, and the
/// fault decisions it drew (recorded at RESOLVE, [SCHED-30]).
#[derive(Clone, Debug, PartialEq, Eq)]
struct PendingCompletion {
    /// The post-fault icount at which the response becomes visible ([IO-2]).
    delivery_icount: u64,
    /// The source-node id stamped into the delivery order key.
    src_node: u32,
    /// The per-completion sequence number, breaking same-icount ties.
    seq: u32,
    /// The deterministic response payload.
    payload: Vec<u8>,
    /// The fault [`Decision`]s this completion drew, recorded at RESOLVE in
    /// delivery order ([SCHED-30]).
    decisions: Vec<Decision>,
}

/// A disk/9p/network device modeled as a first-class scheduling sub-node ([IO-1]).
///
/// Holds a concrete [`BlockDevice`] (the canonical disk sub-node), its scheduling
/// identity ([`SchedulerNodeId`]), the target VM [`NodeId`] that observes its
/// completions, and the seeded per-device RNG forked by name-hash from the
/// scenario seed ([IO-21], [DET-25]). The scheduler reads
/// [`DeviceSchedulingSubNode::next_exact_local_event`] to bound the requester's
/// horizon and calls [`DeviceSchedulingSubNode::deliver_due`] at RESOLVE to make
/// completions visible at their exact icount.
#[derive(Clone, Debug)]
pub struct DeviceSchedulingSubNode {
    sub_node: SchedulerNodeId,
    target: NodeId,
    device_id: DeviceId,
    device: BlockDevice,
    seed: Seed,
    /// The modeled (pre-fault) completions, kept in delivery-key order. Fault
    /// resolution recomputes [`resolved`] from this set, so the result is a pure
    /// function of the sorted set and never depends on submit/COMPUTE order
    /// ([IO-4]).
    modeled: Vec<ModeledCompletion>,
    /// Every modeled completion resolved through the fault table in delivery
    /// order, recomputed whenever [`modeled`] grows. Ordered by
    /// `(delivery_icount, src_node, seq)`.
    resolved: Vec<PendingCompletion>,
    /// The index of the next not-yet-delivered entry in [`resolved`].
    next_delivery: usize,
    /// The device RNG cursor after resolving every modeled completion ([IO-23]).
    rng_position: u64,
}

impl DeviceSchedulingSubNode {
    /// Builds a scheduling sub-node over a block device for a target VM node.
    ///
    /// The sub-node owns the device and a seeded per-device RNG forked by
    /// name-hash from `seed` for `device_id` ([IO-21]). `sub_node` is the
    /// device's scheduling identity (the event producer); `target` is the VM node
    /// whose horizon the device's completions bound and which observes them.
    #[must_use]
    pub fn new(
        sub_node: SchedulerNodeId,
        target: NodeId,
        device_id: DeviceId,
        device: BlockDevice,
        seed: Seed,
    ) -> Self {
        Self {
            sub_node,
            target,
            device_id,
            device,
            seed,
            modeled: Vec::new(),
            resolved: Vec::new(),
            next_delivery: 0,
            rng_position: 0,
        }
    }

    /// Returns the device's scheduling-graph identity (the completion producer).
    #[must_use]
    pub fn sub_node(&self) -> &SchedulerNodeId {
        &self.sub_node
    }

    /// Returns the VM node whose horizon this device's completions bound ([IO-3]).
    #[must_use]
    pub fn target(&self) -> &NodeId {
        &self.target
    }

    /// Returns the device's content-addressed identity ([IO-26]).
    #[must_use]
    pub fn device_id(&self) -> &DeviceId {
        &self.device_id
    }

    /// Returns the seeded per-device RNG cursor (draws consumed so far, [IO-23]).
    #[must_use]
    pub fn rng_position(&self) -> u64 {
        self.rng_position
    }

    /// Returns a shared view of the held block device.
    #[must_use]
    pub fn device(&self) -> &BlockDevice {
        &self.device
    }

    /// Submits a block request at `request_icount` and COMPUTEs its completion.
    ///
    /// COMPUTEs the modeled `(delivery_icount, status, payload)` through the
    /// device and records it in delivery-key order. Fault resolution — which
    /// fixes the **final** (post-fault) `delivery_icount` the horizon reads and
    /// draws every probabilistic choice from the per-device RNG — is deferred to
    /// [`DeviceSchedulingSubNode::resolve_all`], run over the *sorted* modeled set,
    /// so the result is a pure function of the request set and the seed and is
    /// **independent of the COMPUTE/submit order** ([IO-4]). The device's own clock
    /// is never advanced here; delivery is driven solely by the scheduler through
    /// [`DeviceSchedulingSubNode::deliver_due`].
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] when the device cannot encode the request, when its
    /// inbound ring is full ([IO-32]), or when its COMPUTE step fails (a
    /// clock/overflow/past-delivery guard).
    pub fn submit(
        &mut self,
        request_icount: u64,
        request: &BlockRequest,
    ) -> Result<(), DeviceError> {
        self.device.submit(request_icount, request)?;
        // Pull every modeled completion the device has COMPUTEd into the modeled
        // set (deduplicated by delivery key), keeping it in delivery-key order so
        // fault resolution is submit-order-independent.
        for modeled in self.device.core().snapshot().inflight {
            let candidate = ModeledCompletion {
                modeled_icount: modeled.key.delivery_icount,
                src_node: modeled.key.src_node,
                seq: modeled.key.seq,
                status: modeled.response.status,
                payload: modeled.response.payload,
            };
            if self.modeled.iter().any(|existing| {
                existing.modeled_icount == candidate.modeled_icount
                    && existing.src_node == candidate.src_node
                    && existing.seq == candidate.seq
            }) {
                continue;
            }
            let pos = self.modeled.partition_point(|existing| {
                (existing.modeled_icount, existing.src_node, existing.seq)
                    <= (candidate.modeled_icount, candidate.src_node, candidate.seq)
            });
            self.modeled.insert(pos, candidate);
        }
        self.resolve_all();
        Ok(())
    }

    /// Recomputes every modeled completion through the fault table, in delivery
    /// order, from a fresh per-device RNG (RFC-0010 [IO-25], [IO-21], [IO-4]).
    ///
    /// Because resolution iterates the *sorted* modeled set from RNG position
    /// zero, the post-fault delivery icounts, the recorded draws, and the fault
    /// outcomes are a pure function of `(request set, seed)` — never of the order
    /// the requests were submitted. Already-delivered completions are preserved at
    /// their cursor so a recompute after a partial delivery never re-emits them.
    fn resolve_all(&mut self) {
        let mut rng = crate::device::device_rng(self.seed, &self.device_id, 0);
        let stream = crate::device::device_stream_id(&self.device_id);
        let mut resolved: Vec<PendingCompletion> = Vec::new();
        for modeled in &self.modeled {
            let before = rng.position();
            let outcome = self.device.faults().resolve(
                modeled.modeled_icount,
                modeled.status,
                modeled.payload.clone(),
                &mut rng,
                |ns| {
                    crucible_device::ceil_ns_to_icount(ns, self.device.core().shift_bits())
                        .unwrap_or(u64::MAX)
                },
            );
            let after = rng.position();

            // Record one RngDraw per raw value this completion consumed (in order),
            // then a FaultFires for each probabilistic fault outcome ([SCHED-30]).
            let mut decisions = Vec::new();
            let mut replay = crate::device::device_rng(self.seed, &self.device_id, before);
            let at = crate::VirtualTime {
                ticks: modeled.modeled_icount,
            };
            for _ in before..after {
                decisions.push(Decision::RngDraw(RngDecision {
                    stream: stream.clone(),
                    value: replay.next_u64(),
                }));
            }
            push_fault_outcome(
                &mut decisions,
                at,
                &self.device_id,
                "loss",
                outcome.loss_fired,
            );
            push_fault_outcome(
                &mut decisions,
                at,
                &self.device_id,
                "duplicate",
                outcome.duplicate_fired,
            );
            push_fault_outcome(
                &mut decisions,
                at,
                &self.device_id,
                "corrupt",
                outcome.corrupt_fired,
            );

            resolved.push(PendingCompletion {
                delivery_icount: outcome.primary.delivery_icount,
                src_node: modeled.src_node,
                seq: modeled.seq,
                payload: outcome.primary.payload,
                decisions,
            });
            if let Some(duplicate) = outcome.duplicate {
                resolved.push(PendingCompletion {
                    delivery_icount: duplicate.delivery_icount,
                    src_node: modeled.src_node,
                    // Duplicates live in a SEPARATE high-bit tie-break namespace
                    // (`seq | DUPLICATE_SEQ_NAMESPACE`) so a duplicate can never
                    // collide with any sibling request's primary `seq` (which are
                    // small sequential request counts). Tie-break only orders
                    // same-icount completions, so the namespace bit is harmless to
                    // ordering while guaranteeing uniqueness.
                    seq: modeled.seq | DUPLICATE_SEQ_NAMESPACE,
                    payload: duplicate.payload,
                    decisions: Vec::new(),
                });
            }
        }
        resolved.sort_by(|left, right| {
            (left.delivery_icount, left.src_node, left.seq).cmp(&(
                right.delivery_icount,
                right.src_node,
                right.seq,
            ))
        });
        self.rng_position = rng.position();
        self.resolved = resolved;
    }

    /// Returns the next not-yet-delivered completion's final delivery icount: the
    /// sub-node's next exact local event ([IO-31], [SCHED-10]).
    ///
    /// This is what the scheduler folds into the owning VM node's
    /// [`NextExactLocalEvent::io_completion`](crate::NextExactLocalEvent) term, so
    /// an idle requester is fast-forwarded exactly to its next I/O completion.
    /// Returns `None` when nothing is in flight.
    #[must_use]
    pub fn next_exact_local_event(&self) -> Option<u64> {
        self.resolved
            .get(self.next_delivery)
            .map(|head| head.delivery_icount)
    }

    /// DELIVERs every completion due at or before `consumer_icount` in canonical
    /// order, emitting [`IoCompletion`] events and the fault decisions they drew
    /// (RFC-0010 [SCHED-29], [SCHED-30], §8.9.4).
    ///
    /// A completion is **made visible at exactly its `delivery_icount`** — never
    /// at the consumer's later frontier — in the `(delivery_icount, src_node,
    /// seq)` total order ([IO-10], [SCHED-15]), independent of host or transport
    /// timing (Contract B). Each delivered completion contributes its buffered
    /// fault [`Decision`]s, in delivery order, so the recorded schedule is
    /// appended in the §8.6 total order ([SCHED-30]). Future completions stay in
    /// flight at their exact icounts.
    ///
    /// Returns the `(event, decisions)` pairs in delivery order.
    #[must_use]
    pub fn deliver_due(&mut self, consumer_icount: u64) -> Vec<(IoCompletion, Vec<Decision>)> {
        let mut delivered = Vec::new();
        while let Some(completion) = self.resolved.get(self.next_delivery) {
            if completion.delivery_icount > consumer_icount {
                break;
            }
            let event = IoCompletion {
                sub_node: self.sub_node.clone(),
                target: self.target.clone(),
                delivery_icount: crate::Icount {
                    retired: completion.delivery_icount,
                },
                payload: completion.payload.clone(),
            };
            delivered.push((event, completion.decisions.clone()));
            self.next_delivery += 1;
        }
        delivered
    }
}

/// Pushes a [`Decision::FaultFires`] for one I/O fault kind that could fire.
///
/// The fault id is the device-scoped tag [`crate::device::io_fault_id`] keys an
/// active I/O fault by ([IO-26]), so block/9p/link faults live in one namespace.
fn push_fault_outcome(
    decisions: &mut Vec<Decision>,
    at: crate::VirtualTime,
    device: &DeviceId,
    kind: &str,
    fired: bool,
) {
    let fault: FaultId = crate::device::io_fault_id(device, kind);
    decisions.push(Decision::FaultFires(FaultDecision { at, fault, fired }));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crucible_device::{BaseImage, BlockLatency, IoCore, IoFaults, Probability};

    use crate::SchedulingNodeKind;

    fn device_id(name: &str) -> DeviceId {
        DeviceId {
            name: name.to_owned(),
        }
    }

    fn node_id(name: &str) -> NodeId {
        NodeId {
            name: name.to_owned(),
        }
    }

    fn sub_node_id(name: &str) -> SchedulerNodeId {
        SchedulerNodeId {
            node: node_id(name),
            kind: SchedulingNodeKind::Disk,
        }
    }

    /// Builds a fault-free disk sub-node over a small base image.
    fn fresh_disk(seed: Seed, faults: IoFaults) -> DeviceSchedulingSubNode {
        let core = match IoCore::new(0, 7, 16, 16) {
            Ok(core) => core,
            Err(error) => panic!("io core should construct: {error}"),
        };
        let base = BaseImage::new(vec![0xab; 4096]);
        let mut device = BlockDevice::new(core, base, BlockLatency::default());
        device.set_faults(faults);
        DeviceSchedulingSubNode::new(
            sub_node_id("disk-sub"),
            node_id("vm-a"),
            device_id("disk"),
            device,
            seed,
        )
    }

    fn read_request(request_id: u32, offset: u64, count: u32) -> BlockRequest {
        BlockRequest::read(request_id, offset, count)
    }

    #[test]
    fn next_exact_local_event_is_the_inflight_head_final_icount() {
        let mut disk = fresh_disk(Seed::from_u64(0xd15c), IoFaults::none());
        // Two reads at different request icounts -> two completions in flight.
        disk.submit(0, &read_request(1, 0, 8))
            .unwrap_or_else(|error| panic!("submit should succeed: {error}"));
        disk.submit(100, &read_request(2, 0, 8))
            .unwrap_or_else(|error| panic!("submit should succeed: {error}"));

        let head = disk
            .next_exact_local_event()
            .unwrap_or_else(|| panic!("a completion must be in flight"));
        // The earlier request completes first (lower delivery icount).
        let second = disk
            .resolved
            .get(1)
            .unwrap_or_else(|| panic!("two completions in flight"))
            .delivery_icount;
        assert!(head < second, "head is the earliest completion");
    }

    #[test]
    fn deliver_due_makes_completions_visible_at_exact_icount_in_order() {
        let mut disk = fresh_disk(Seed::from_u64(0xd15c), IoFaults::none());
        disk.submit(0, &read_request(1, 0, 8))
            .unwrap_or_else(|error| panic!("submit should succeed: {error}"));
        let delivery = disk
            .next_exact_local_event()
            .unwrap_or_else(|| panic!("a completion must be in flight"));

        // Below the delivery icount: nothing is visible.
        assert!(disk.deliver_due(delivery - 1).is_empty());
        // At exactly the delivery icount: the completion becomes visible.
        let delivered = disk.deliver_due(delivery);
        assert_eq!(delivered.len(), 1);
        let (event, _decisions) = &delivered[0];
        assert_eq!(event.delivery_icount.retired, delivery);
        assert_eq!(event.target, node_id("vm-a"));
        assert!(disk.next_exact_local_event().is_none());
    }

    #[test]
    fn fault_choices_are_drawn_from_the_device_rng_and_recorded_as_decisions() {
        // A loss fault that always fires: the completion records an RngDraw (the
        // loss draw) and a FaultFires(loss, fired=true) on the RESOLVE path.
        let faults = IoFaults {
            loss: Probability::ALWAYS,
            ..IoFaults::none()
        };
        let mut disk = fresh_disk(Seed::from_u64(0xfa17), faults);
        disk.submit(0, &read_request(1, 0, 8))
            .unwrap_or_else(|error| panic!("submit should succeed: {error}"));
        let delivery = disk
            .next_exact_local_event()
            .unwrap_or_else(|| panic!("a completion must be in flight"));
        let delivered = disk.deliver_due(delivery);
        assert_eq!(delivered.len(), 1);
        let (_event, decisions) = &delivered[0];

        assert!(
            decisions
                .iter()
                .any(|decision| matches!(decision, Decision::RngDraw(_))),
            "the device RNG draws must be recorded as decisions"
        );
        assert!(
            decisions.iter().any(|decision| matches!(
                decision,
                Decision::FaultFires(FaultDecision { fired: true, fault, .. })
                    if fault == &crate::device::io_fault_id(&device_id("disk"), "loss")
            )),
            "the loss fault outcome must be recorded as fired"
        );
        // The RNG cursor advanced (the faults consumed draws).
        assert!(disk.rng_position() > 0);
    }

    #[test]
    fn run_twice_is_byte_identical() {
        let faults = IoFaults {
            jitter_window_ns: 64,
            loss: Probability::new(1, 3),
            ..IoFaults::none()
        };
        let drive = || {
            let mut disk = fresh_disk(Seed::from_u64(0x7e57), faults);
            for index in 0..4u64 {
                disk.submit(index * 50, &read_request(index as u32 + 1, 0, 8))
                    .unwrap_or_else(|error| panic!("submit should succeed: {error}"));
            }
            let mut out = Vec::new();
            // Deliver everything that is in flight.
            while let Some(delivery) = disk.next_exact_local_event() {
                out.extend(disk.deliver_due(delivery));
            }
            out
        };
        assert_eq!(drive(), drive(), "two runs must be byte-identical");
    }
}
