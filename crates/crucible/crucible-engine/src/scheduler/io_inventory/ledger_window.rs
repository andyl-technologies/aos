//! Equivalence of the pruned delivery ledger with the unpruned ledger rules.
//!
//! Continuation version 7 retained every imported delivery forever. These
//! tests drive the real scheduler through seeded import, publication, replay
//! and advance sequences and compare it step by step with a reference that
//! keeps the version 7 rules. Every accept and refuse decision must match. The
//! retained window must equal the reference ledger without the published
//! deliveries below the stopped tick, and history must never reach a staging
//! copy.

use super::*;
use crate::{BackendIoComputedReply, BackendIoQueueSnapshot};
use crucible_device::FrameDeliveryKey;

const NODE: &str = "a";

/// A small deterministic generator, so a failing seed reproduces exactly.
struct Xorshift(u64);

impl Xorshift {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, bound: u64) -> u64 {
        self.next() % bound
    }

    fn percent(&mut self, chance: u64) -> bool {
        self.below(100) < chance
    }
}

type Entry = (Vec<u8>, bool);

/// The unpruned ledger rules, plus the never-regressing observation floor.
#[derive(Default)]
struct Reference {
    entries: BTreeMap<FrameDeliveryKey, Entry>,
    current: Vec<FrameDeliveryKey>,
    observed: Option<u64>,
}

impl Reference {
    fn import(&mut self, observed: u64, completions: &[BackendIoComputedReply]) -> bool {
        if self.observed.is_some_and(|previous| observed < previous)
            || completions
                .iter()
                .any(|reply| reply.source_delivery.delivery_icount < observed)
        {
            return false;
        }
        let lost_unpublished = self.current.iter().any(|old| {
            !completions
                .iter()
                .any(|reply| reply.source_delivery == *old)
                && self
                    .entries
                    .get(old)
                    .is_some_and(|(_, published)| !published)
        });
        let replayed = completions.iter().any(|reply| {
            self.entries
                .get(&reply.source_delivery)
                .is_some_and(|(payload, published)| *published || *payload != reply.payload)
        });
        if lost_unpublished || replayed {
            return false;
        }

        for reply in completions {
            self.entries
                .entry(reply.source_delivery)
                .or_insert_with(|| (reply.payload.clone(), false));
        }
        self.current = completions
            .iter()
            .map(|reply| reply.source_delivery)
            .collect();
        self.observed = Some(observed);
        true
    }

    fn publish(&mut self, physical: FrameDeliveryKey, payload: &[u8]) -> Result<(), &'static str> {
        match self.entries.get_mut(&physical) {
            None => Err("published physical delivery lacks its actor origin"),
            Some((retained, published)) if *published || retained != payload => {
                Err("published physical delivery changed or reused its identity")
            }
            Some((_, published)) => {
                *published = true;
                Ok(())
            }
        }
    }

    fn window(&self) -> BTreeMap<FrameDeliveryKey, Entry> {
        let floor = self.observed.unwrap_or_default();
        self.entries
            .iter()
            .filter(|(physical, (_, published))| !published || physical.delivery_icount >= floor)
            .map(|(physical, entry)| (*physical, entry.clone()))
            .collect()
    }

    fn earliest_unpublished(&self) -> Option<u64> {
        self.entries
            .iter()
            .filter(|(_, (_, published))| !published)
            .map(|(physical, _)| physical.delivery_icount)
            .min()
    }
}

fn ledger(scheduler: &SingleScheduler) -> Option<&DeliveryLedger> {
    scheduler
        .imported_io
        .get(&id(NODE))
        .and_then(|node| node.queues.values().next())
        .map(|queue| &queue.deliveries)
}

fn window(scheduler: &SingleScheduler) -> BTreeMap<FrameDeliveryKey, Entry> {
    ledger(scheduler)
        .into_iter()
        .flat_map(DeliveryLedger::iter)
        .map(|(physical, delivery)| {
            (
                *physical,
                (delivery.completion.payload.clone(), delivery.published),
            )
        })
        .collect()
}

/// Builds inventories from one real observation, varying only the facts the
/// ledger reads: stopped tick, queue revision and completions.
struct Inventories {
    template: BackendIoInventory,
    revision: u64,
}

impl Inventories {
    fn new(scheduler: &SingleScheduler) -> Self {
        let (_, queue, pipeline) = fixture();
        Self {
            template: observation(scheduler, &queue, &pipeline),
            revision: 1_000,
        }
    }

    fn source_node(&self) -> u32 {
        self.template.queues[0].source_node
    }

    fn at(
        &mut self,
        observed: u64,
        completions: Vec<BackendIoComputedReply>,
    ) -> BackendIoInventory {
        // A strictly rising revision never claims an unchanged queue, and a
        // constant absent pipeline deadline stays valid at every tick.
        self.revision += 1;
        let queue = BackendIoQueueSnapshot {
            revision: NonZeroU64::new(self.revision).unwrap_or(NonZeroU64::MIN),
            next_pipeline_boundary: None,
            completions,
            ..self.template.queues[0].clone()
        };
        BackendIoInventory {
            observed: NodeCounter { ticks: observed },
            queues: vec![queue],
            ..self.template.clone()
        }
    }
}

fn reply(physical: FrameDeliveryKey, payload: Vec<u8>) -> BackendIoComputedReply {
    BackendIoComputedReply {
        source_delivery: physical,
        payload,
    }
}

/// Draws one snapshot: the reference's unpublished current entries, fresh
/// deliveries, and occasionally a loss, a mutation, or a replay.
fn draw_completions(
    rng: &mut Xorshift,
    reference: &Reference,
    source_node: u32,
    tick: u64,
) -> Vec<BackendIoComputedReply> {
    let mut drawn = BTreeMap::new();
    for physical in &reference.current {
        if let Some((payload, false)) = reference.entries.get(physical) {
            drawn.insert(*physical, payload.clone());
        }
    }
    if rng.percent(8)
        && let Some(lost) = drawn.keys().next().copied()
    {
        drawn.remove(&lost);
    }
    if rng.percent(5)
        && let Some(payload) = drawn.values_mut().next()
    {
        payload.push(0xa5);
    }
    if rng.percent(10) && !reference.entries.is_empty() {
        let index = rng.below(reference.entries.len() as u64) as usize;
        if let Some((physical, (payload, _))) = reference.entries.iter().nth(index) {
            drawn.insert(*physical, payload.clone());
        }
    }
    for _ in 0..rng.below(4) {
        let physical = FrameDeliveryKey {
            delivery_icount: tick + rng.below(60),
            src_node: source_node,
            seq: rng.below(1_000) as u32,
        };
        let payload = (0..=rng.below(3)).map(|_| rng.next() as u8).collect();
        drawn.entry(physical).or_insert(payload);
    }
    drawn
        .into_iter()
        .map(|(physical, payload)| reply(physical, payload))
        .collect()
}

fn completion_of(event: &ScheduledEvent) -> &IoCompletion {
    let ScheduledEventPayload::IoCompletion(completion) = &event.payload else {
        panic!("imported event must be an I/O completion");
    };
    completion
}

fn assert_round_trip(scheduler: &SingleScheduler) {
    let bytes = ok(ok(scheduler.checkpoint()).canonical_bytes());
    let (mut restored, _, _) = fixture();
    ok(ok(SingleSchedulerCheckpoint::from_canonical_bytes(&bytes)).restore_into(&mut restored));

    assert_eq!(restored.imported_io, scheduler.imported_io);
    assert_eq!(ok(ok(restored.checkpoint()).canonical_bytes()), bytes);
}

/// Counts the outcomes a seed exercised, so the property cannot pass vacuously.
#[derive(Default)]
struct Coverage {
    accepted_imports: usize,
    refused_imports: usize,
    publications: usize,
    refused_publications: usize,
    pruned: usize,
}

fn run_seed(seed: u64, coverage: &mut Coverage) {
    let (mut scheduler, _, _) = fixture();
    let mut inventories = Inventories::new(&scheduler);
    let source_node = inventories.source_node();
    let mut rng = Xorshift(seed);
    let mut reference = Reference::default();
    let mut published = Vec::<ScheduledEvent>::new();
    let mut tick = 0;

    for step in 0..300 {
        let choice = rng.below(100);
        if choice < 45 {
            let completions = draw_completions(&mut rng, &reference, source_node, tick);
            let before = scheduler.imported_io.clone();
            scheduler.nodes[0].set_exact_clock(NodeCounter { ticks: tick });
            let accepted = scheduler
                .import_initial_io_inventory(inventories.at(tick, completions.clone()))
                .is_ok();

            assert_eq!(
                accepted,
                reference.import(tick, &completions),
                "seed {seed} step {step} import"
            );
            if accepted {
                coverage.accepted_imports += 1;
            } else {
                coverage.refused_imports += 1;
                assert_eq!(
                    scheduler.imported_io, before,
                    "seed {seed} step {step} refusal"
                );
            }
        } else if choice < 75 {
            let pending = scheduler
                .pending_events
                .iter()
                .position(|event| matches!(event.payload, ScheduledEventPayload::IoCompletion(_)));
            let replay = rng.percent(15) && !published.is_empty();
            let event = match (replay, pending) {
                (true, _) => published[rng.below(published.len() as u64) as usize].clone(),
                (false, Some(index)) => scheduler.pending_events[index].clone(),
                (false, None) => continue,
            };
            let completion = completion_of(&event);
            let expected = reference.publish(completion.source_delivery, &completion.payload);
            let actual = scheduler.record_imported_io_publication(&event);

            match (&actual, expected) {
                (Ok(()), Ok(())) => {
                    scheduler
                        .pending_events
                        .retain(|pending| pending.key != event.key);
                    published.push(event);
                    coverage.publications += 1;
                }
                (Err(SchedulerError::BoundaryViolation { message }), Err(expected)) => {
                    assert_eq!(message, expected, "seed {seed} step {step} publication");
                    coverage.refused_publications += 1;
                }
                _ => panic!("seed {seed} step {step}: publication {actual:?} vs {expected:?}"),
            }
        } else if choice < 80 && tick > 0 {
            // A regressed stopped tick is refused even when it replays nothing.
            let regressed = tick - 1 - rng.below(tick);
            let before = scheduler.imported_io.clone();
            scheduler.nodes[0].set_exact_clock(NodeCounter { ticks: regressed });
            let refused = scheduler
                .import_initial_io_inventory(inventories.at(regressed, Vec::new()))
                .is_err();
            scheduler.nodes[0].set_exact_clock(NodeCounter { ticks: tick });

            let expected = !reference.import(regressed, &[]);
            assert_eq!(refused, expected, "seed {seed} step {step} regression");
            if refused {
                assert_eq!(scheduler.imported_io, before);
            }
        } else {
            // Advance without passing an unpublished delivery, which a later
            // snapshot must still carry at or after its stopped tick.
            let next = tick + rng.below(31);
            tick = reference
                .earliest_unpublished()
                .map_or(next, |earliest| next.min(earliest).max(tick));
        }

        assert_eq!(
            window(&scheduler),
            reference.window(),
            "seed {seed} step {step} window"
        );
        coverage.pruned = coverage
            .pruned
            .max(reference.entries.len() - reference.window().len());
        if step % 50 == 49 && ledger(&scheduler).is_some() {
            assert_round_trip(&scheduler);
        }
    }
}

#[test]
fn pruned_ledger_matches_unpruned_rules_over_seeded_sequences() {
    let mut coverage = Coverage::default();
    for seed in 1..=16 {
        run_seed(0x9e37_79b9_7f4a_7c15 ^ seed, &mut coverage);
    }

    assert!(coverage.accepted_imports > 0 && coverage.refused_imports > 0);
    assert!(coverage.publications > 0 && coverage.refused_publications > 0);
    assert!(coverage.pruned > 0);
}

/// Imports one fresh delivery at `tick + 5`, publishes it, and returns it.
fn deliver_and_publish(
    scheduler: &mut SingleScheduler,
    inventories: &mut Inventories,
    tick: u64,
    seq: u32,
) -> ScheduledEvent {
    let physical = FrameDeliveryKey {
        delivery_icount: tick + 5,
        src_node: inventories.source_node(),
        seq,
    };
    scheduler.nodes[0].set_exact_clock(NodeCounter { ticks: tick });
    ok(scheduler.import_initial_io_inventory(inventories.at(tick, vec![reply(physical, vec![7])])));

    let index = scheduler
        .pending_events
        .iter()
        .position(|event| completion_of(event).source_delivery == physical)
        .unwrap_or_else(|| panic!("imported delivery has no pending event"));
    let event = scheduler.pending_events.remove(index);
    ok(scheduler.record_imported_io_publication(&event));
    event
}

#[test]
fn staging_copies_share_a_window_that_does_not_grow_with_history() {
    let (mut scheduler, _, _) = fixture();
    let mut inventories = Inventories::new(&scheduler);
    let mut retained = Vec::new();

    for cycle in 0..400_u32 {
        deliver_and_publish(
            &mut scheduler,
            &mut inventories,
            u64::from(cycle) * 10,
            cycle,
        );
        retained.push(ledger(&scheduler).map_or(0, DeliveryLedger::len));
    }

    // Each import drops the delivery published in the previous cycle.
    assert!(retained.iter().all(|&len| len == 1), "{retained:?}");
    let staged = scheduler.clone();
    let (Some(live), Some(copy)) = (ledger(&scheduler), ledger(&staged)) else {
        panic!("imported ledger missing");
    };
    assert!(copy.shares_retired_with(live));
}

#[test]
fn pruned_delivery_cannot_return_through_a_regressed_observation() {
    let (mut scheduler, _, _) = fixture();
    let mut inventories = Inventories::new(&scheduler);
    let first = deliver_and_publish(&mut scheduler, &mut inventories, 0, 0);
    deliver_and_publish(&mut scheduler, &mut inventories, 20, 1);
    let pruned = completion_of(&first).source_delivery;
    assert!(ledger(&scheduler).is_some_and(|ledger| ledger.get(&pruned).is_none()));

    let before = scheduler.imported_io.clone();
    scheduler.nodes[0].set_exact_clock(NodeCounter { ticks: 0 });
    let replay = inventories.at(0, vec![reply(pruned, vec![7])]);
    assert!(scheduler.import_initial_io_inventory(replay).is_err());
    assert_eq!(scheduler.imported_io, before);

    scheduler.nodes[0].set_exact_clock(NodeCounter { ticks: 20 });
    let Err(SchedulerError::BoundaryViolation { message }) =
        scheduler.record_imported_io_publication(&first)
    else {
        panic!("a pruned delivery was published twice");
    };
    assert_eq!(
        message,
        "published physical delivery changed or reused its identity"
    );
}

#[test]
fn restored_ledger_refuses_a_published_delivery_below_the_floor() {
    let (mut scheduler, _, _) = fixture();
    let mut inventories = Inventories::new(&scheduler);
    deliver_and_publish(&mut scheduler, &mut inventories, 0, 0);
    ok(scheduler.validate_imported_io_ledger());

    // Publication alone never prunes; only the next import does. Moving the
    // floor past the published delivery without that import is non-canonical.
    // The published reply also leaves the queue, so only the retained ledger
    // entry contradicts the floor.
    scheduler.nodes[0].set_exact_clock(NodeCounter { ticks: 10 });
    if let Some(node) = scheduler.imported_io.get_mut(&id(NODE)) {
        node.observed = NodeCounter { ticks: 10 };
        node.queues
            .values_mut()
            .for_each(|queue| queue.current.clear());
    }

    let Err(SchedulerError::BoundaryViolation { message }) =
        scheduler.validate_imported_io_ledger()
    else {
        panic!("a retired delivery below the floor was restored");
    };
    assert_eq!(
        message,
        "restored physical ledger retains a retired delivery"
    );
}
