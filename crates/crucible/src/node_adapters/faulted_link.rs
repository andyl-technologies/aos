//! Selected native loss, duplication and corruption with original decision custody.
//!
//! Static fault programs are immutable realization inputs. This model records
//! every actually consumed input and raw draw, including zero-output loss. The
//! decoder validates data consistency; installed native qualification remains
//! responsible for authenticating the complete original capture and runtime.
//!
//! The selected canonical continuation uses this closed shape:
//!
//! ```text
//! {"version":1,"definition":{...},"native":"<unpadded-base64>","decisions":[...]}
//! ```
//!
//! Decisions retain original full input positions, sequences, payload bytes,
//! pre-resolution cursors, raw draws and resolved output keys/bytes. They are
//! historical data, never an alternate permission to mutate a live node.

use crucible_device::netlink::{
    Frame, FrameDraws, LinkCorruptionStrategy, LinkFaults, LinkSnapshot, NetLink,
    PastDeliveryPolicy, Probability, ResolveOutcome,
};
use crucible_node_contract::{Bytes, Id, Position, U64, Validate, canonical};
use serde::{Deserialize, Serialize};

use super::host::failure;
use crate::node_contract::OperationFailure;

#[path = "controlled_fault_link.rs"]
pub mod controlled;

/// Represents an exact bounded fault probability without floating point.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FaultProbability {
    /// Counts favorable outcomes within the denominator.
    pub numerator: U64,
    /// Counts possible outcomes and is strictly positive.
    pub denominator: U64,
}

impl FaultProbability {
    fn native(&self) -> Result<Probability, OperationFailure> {
        if self.denominator.get() == 0
            || self.numerator > self.denominator
            || self.denominator.get() > 1_000_000
        {
            return Err(failure("fault probability is noncanonical or unbounded"));
        }
        Ok(Probability::new(
            self.numerator.get(),
            self.denominator.get(),
        ))
    }
}

/// Borrows one original opaque frame without manufacturing native authority.
#[derive(Clone, Copy)]
pub struct FaultedInput<'a> {
    /// Preserves the authenticated original input delivery position.
    pub position: Position,
    /// Preserves the original producer sequence as native correlation data.
    pub sequence: U64,
    /// Borrows the original consumed frame bytes.
    pub payload: &'a [u8],
}

/// Defines a distinct static adverse byte transport realization.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FaultedLinkDefinition {
    /// Selects this closed fault program edition, currently one.
    pub version: u32,
    /// Binds the scenario root seed.
    pub seed: U64,
    /// Binds the stable per-link random stream name.
    pub stream: Id,
    /// Binds the native source identity without truncation.
    pub source_node: u32,
    /// Selects positive fixed native latency in picoseconds.
    pub latency_ps: U64,
    /// Selects the positive conservative native latency floor.
    pub floor_ps: U64,
    /// Selects the exact integer loss probability.
    pub loss: FaultProbability,
    /// Selects the exact integer duplication probability.
    pub duplicate: FaultProbability,
    /// Separates duplicate delivery from its original by this positive delay.
    pub duplicate_gap_ps: U64,
    /// Selects the exact integer corruption probability.
    pub corrupt: FaultProbability,
    /// Selects zero or one seeded payload-bit selector draw per input.
    pub corruption_bits: u32,
}

impl FaultedLinkDefinition {
    /// Creates an inactive native link under the complete static fault table.
    ///
    /// # Errors
    /// Refuses unknown editions, malformed streams, zero or excessive delays,
    /// noncanonical probabilities, and unsupported corruption strategies.
    pub fn instantiate(&self) -> Result<NetLink, OperationFailure> {
        self.stream
            .validate()
            .map_err(|error| failure(&error.to_string()))?;
        let faults = self.faults()?;
        if self.version != 1
            || self.floor_ps.get() == 0
            || self.floor_ps > self.latency_ps
            || self.latency_ps.get() > 1_000_000_000
            || self.duplicate_gap_ps.get() == 0
            || self.duplicate_gap_ps.get() > 1_000_000_000
            || self.corruption_bits > 1
            || (self.corrupt.numerator.get() > 0 && self.corruption_bits != 1)
            || (self.corrupt.numerator.get() == 0 && self.corruption_bits != 0)
            || (self.loss.numerator.get() == 0
                && self.duplicate.numerator.get() == 0
                && self.corrupt.numerator.get() == 0)
        {
            return Err(failure("selected adverse fault definition is unsupported"));
        }
        NetLink::new(
            self.source_node,
            self.latency_ps.get(),
            self.floor_ps.get(),
            faults,
        )
        .map_err(|error| failure(&error.to_string()))
    }

    /// Returns the exact complete native fault table.
    ///
    /// # Errors
    /// Refuses noncanonical or unbounded rational probabilities.
    pub fn faults(&self) -> Result<LinkFaults, OperationFailure> {
        Ok(LinkFaults {
            loss: self.loss.native()?,
            duplicate: self.duplicate.native()?,
            duplicate_gap_ticks: self.duplicate_gap_ps.get(),
            corrupt: self.corrupt.native()?,
            corruption_strategies: if self.corruption_bits == 0 {
                Vec::new()
            } else {
                vec![LinkCorruptionStrategy::BitFlip {
                    max_bits: self.corruption_bits,
                }]
            },
            ..LinkFaults::none()
        })
    }

    /// Resolves one original input and retains its actual native fault decisions.
    ///
    /// Credits for the complete journal and worst-case two deliveries are
    /// checked before consuming any random draw or changing native state.
    ///
    /// # Errors
    /// Refuses exhausted original-input or output credits, oversized payloads,
    /// changed native policy, invalid correlations, and native delivery errors.
    pub fn consume(
        &self,
        link: &mut NetLink,
        journal: &mut Vec<FaultDecision>,
        original: FaultedInput<'_>,
        pending_limit: usize,
    ) -> Result<ResolveOutcome, OperationFailure> {
        self.consume_in_domain(
            link,
            journal,
            original,
            pending_limit,
            "crucible/faulted-link-v1",
        )
    }

    pub(super) fn consume_in_domain(
        &self,
        link: &mut NetLink,
        journal: &mut Vec<FaultDecision>,
        original: FaultedInput<'_>,
        pending_limit: usize,
        domain: &str,
    ) -> Result<ResolveOutcome, OperationFailure> {
        let FaultedInput {
            position: input,
            sequence,
            payload,
        } = original;
        let sequence32 =
            u32::try_from(sequence.get()).map_err(|_| failure("fault correlation overflow"))?;
        if journal.len() >= 16
            || payload.len() > 1024 * 1024
            || link.faults() != &self.faults()?
            || link
                .inflight_len()
                .checked_add(2)
                .is_none_or(|pending| pending > pending_limit)
        {
            return Err(failure(
                "adverse input lacks complete pre-effect native credits",
            ));
        }
        journal
            .try_reserve(1)
            .map_err(|_| failure("adverse decision reservation failed"))?;
        let mut original_payload = Vec::new();
        original_payload
            .try_reserve_exact(payload.len())
            .map_err(|_| failure("original packet credit unavailable"))?;
        original_payload.extend_from_slice(payload);
        let mut output_buffers = [Vec::new(), Vec::new()];
        for buffer in &mut output_buffers {
            buffer
                .try_reserve_exact(payload.len())
                .map_err(|_| failure("adverse output journal credit unavailable"))?;
        }
        let mut outputs = Vec::new();
        outputs
            .try_reserve_exact(2)
            .map_err(|_| failure("adverse output journal rows unavailable"))?;
        let mut selectors = Vec::new();
        selectors
            .try_reserve_exact(self.corruption_bits as usize)
            .map_err(|_| failure("adverse selector journal credit unavailable"))?;
        let frame = Frame::new(input.time_ps.get(), sequence32, payload.to_vec());
        let native_clock = link.current_icount().into();
        let start = link.rng_position().into();
        let mut rng = link.rng(self.seed.get(), domain, self.stream.as_str());
        let (outcome, draws) = link
            .emit_with_rng_draws(&frame, &mut rng, PastDeliveryPolicy::FailLoud)
            .map_err(|error| failure(&error.to_string()))?;
        for (output, mut buffer) in outcome.deliveries.iter().zip(output_buffers) {
            buffer.extend_from_slice(&output.payload);
            outputs.push(DecisionOutput {
                time: output.key.delivery_icount.into(),
                source: output.key.src_node,
                sequence: output.key.seq,
                frame: output.frame_id,
                payload: Bytes::new(buffer),
            });
        }
        selectors.extend(draws.corruption_selectors.iter().copied().map(U64::from));
        journal.push(FaultDecision {
            input,
            sequence,
            payload: Bytes::new(original_payload),
            native_clock,
            start,
            draws: Draws {
                values: [
                    draws.jitter.into(),
                    draws.reorder.into(),
                    draws.loss.into(),
                    draws.duplicate.into(),
                    draws.corrupt.into(),
                ],
                selectors,
            },
            outputs,
        });
        Ok(outcome)
    }

    /// Restores the exact original journal and native queue under this definition.
    ///
    /// # Errors
    /// Refuses changed programs, malformed or excessive records, inconsistent
    /// original draws/output sequences, and native queued bytes absent from the
    /// retained original decision journal. This parser grants no authority.
    pub fn restore(
        &self,
        bytes: &[u8],
        maximum: usize,
    ) -> Result<(NetLink, Vec<FaultDecision>), OperationFailure> {
        let parsed =
            canonical::parse_json(bytes, maximum).map_err(|error| failure(&error.to_string()))?;
        let saved: Snapshot =
            serde_json::from_value(parsed).map_err(|error| failure(&error.to_string()))?;
        if saved.version != 1
            || saved.definition != *self
            || encode(&saved)? != bytes
            || saved.decisions.len() > 16
        {
            return Err(failure(
                "adverse continuation changed original definition or encoding",
            ));
        }
        let native =
            LinkSnapshot::from_canonical_bytes_with_limit(saved.native.as_slice(), maximum as u64)
                .map_err(|error| failure(&error.to_string()))?;
        let initial = self.instantiate()?.snapshot();
        if native.src_node != initial.src_node
            || native.ticks_per_ns != initial.ticks_per_ns
            || native.base_latency_ticks != initial.base_latency_ticks
            || native.floor_ticks != initial.floor_ticks
            || native.faults != initial.faults
            || native.lookahead_recompute_pending != initial.lookahead_recompute_pending
            || native.next_seq > 32
            || native.inflight.len() > 32
        {
            return Err(failure(
                "adverse continuation changed native policy or credit",
            ));
        }
        let mut replay = self.instantiate()?;
        let mut outputs = Vec::new();
        for decision in &saved.decisions {
            decision
                .input
                .validate()
                .map_err(|error| failure(&error.to_string()))?;
            if decision.native_clock.get() < replay.current_icount()
                || decision.native_clock.get() > native.current_icount
                || decision.payload.as_slice().len() > 1024 * 1024
                || decision.start.get() != replay.rng_position()
            {
                return Err(failure(
                    "adverse decision changed original input or random cursor",
                ));
            }
            replay
                .advance_to(decision.native_clock.get())
                .map_err(|error| failure(&error.to_string()))?;
            let frame = Frame::new(
                decision.input.time_ps.get(),
                u32::try_from(decision.sequence.get())
                    .map_err(|_| failure("adverse sequence overflow"))?,
                decision.payload.as_slice().to_vec(),
            );
            let mut rng = replay.rng(
                self.seed.get(),
                "crucible/faulted-link-v1",
                self.stream.as_str(),
            );
            let (outcome, draws) = replay
                .emit_with_rng_draws(&frame, &mut rng, PastDeliveryPolicy::FailLoud)
                .map_err(|error| failure(&error.to_string()))?;
            let actual: Vec<_> = outcome
                .deliveries
                .iter()
                .map(DecisionOutput::from_native)
                .collect();
            if decision.draws != Draws::from_native(&draws) || decision.outputs != actual {
                return Err(failure("adverse decision changed original draw or outcome"));
            }
            outputs.extend(actual);
        }
        if replay.rng_position() != native.rng_position
            || outputs.len() != native.next_seq as usize
            || native.inflight.iter().any(|pending| {
                !outputs.iter().any(|output| {
                    output.time.get() == pending.key.delivery_icount
                        && output.source == pending.key.src_node
                        && output.sequence == pending.key.seq
                        && output.frame == pending.response.request_id
                        && output.payload.as_slice() == pending.response.payload
                })
            })
        {
            return Err(failure(
                "adverse native queue is inconsistent with original decisions",
            ));
        }
        Ok((
            NetLink::restore(&native).map_err(|error| failure(&error.to_string()))?,
            saved.decisions,
        ))
    }

    pub(super) fn capture(
        &self,
        link: &NetLink,
        journal: &[FaultDecision],
        maximum: usize,
    ) -> Result<Vec<u8>, OperationFailure> {
        let bytes = encode(&Snapshot {
            version: 1,
            definition: self.clone(),
            native: Bytes::new(
                link.snapshot()
                    .canonical_bytes_with_limit(maximum as u64)
                    .map_err(|error| failure(&error.to_string()))?,
            ),
            decisions: journal.to_vec(),
        })?;
        if bytes.len() > maximum {
            return Err(failure("adverse complete capture exceeds byte ceiling"));
        }
        self.restore(&bytes, maximum)?;
        Ok(bytes)
    }
}

/// Retains one actual original input and its resolved native decisions.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FaultDecision {
    input: Position,
    sequence: U64,
    payload: Bytes,
    native_clock: U64,
    start: U64,
    draws: Draws,
    outputs: Vec<DecisionOutput>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Draws {
    values: [U64; 5],
    selectors: Vec<U64>,
}

impl Draws {
    fn from_native(draws: &FrameDraws) -> Self {
        Self {
            values: [
                draws.jitter.into(),
                draws.reorder.into(),
                draws.loss.into(),
                draws.duplicate.into(),
                draws.corrupt.into(),
            ],
            selectors: draws
                .corruption_selectors
                .iter()
                .copied()
                .map(Into::into)
                .collect(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DecisionOutput {
    time: U64,
    source: u32,
    sequence: u32,
    frame: u32,
    payload: Bytes,
}

impl DecisionOutput {
    fn from_native(value: &crucible_device::netlink::Delivery) -> Self {
        Self {
            time: value.key.delivery_icount.into(),
            source: value.key.src_node,
            sequence: value.key.seq,
            frame: value.frame_id,
            payload: Bytes::new(value.payload.clone()),
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    version: u32,
    definition: FaultedLinkDefinition,
    native: Bytes,
    decisions: Vec<FaultDecision>,
}

fn encode(value: &impl Serialize) -> Result<Vec<u8>, OperationFailure> {
    canonical::canonical_json(
        &serde_json::to_value(value).map_err(|error| failure(&error.to_string()))?,
    )
    .map_err(|error| failure(&error.to_string()))
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- Native fault custody tests panic on violated draw, output or refusal invariants.
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crucible_node_contract::Phase;

    fn probability(numerator: u64, denominator: u64) -> FaultProbability {
        FaultProbability {
            numerator: numerator.into(),
            denominator: denominator.into(),
        }
    }

    fn definition() -> FaultedLinkDefinition {
        FaultedLinkDefinition {
            version: 1,
            seed: 77.into(),
            stream: Id::new("adverse/requests").expect("name"),
            source_node: 17,
            latency_ps: 1000.into(),
            floor_ps: 1000.into(),
            loss: probability(0, 1),
            duplicate: probability(1, 1),
            duplicate_gap_ps: 100.into(),
            corrupt: probability(0, 1),
            corruption_bits: 0,
        }
    }

    fn input(time: u64) -> Position {
        Position::new(time.into(), 1.into(), Phase::Delivery)
    }

    #[test]
    fn loss_consumes_original_draws_and_retains_zero_output_decision() {
        let mut definition = definition();
        definition.loss = probability(1, 1);
        let mut native = definition.instantiate().expect("native");
        let mut journal = Vec::new();

        let outcome = definition
            .consume(
                &mut native,
                &mut journal,
                FaultedInput {
                    position: input(10),
                    sequence: 7.into(),
                    payload: &[8, 9],
                },
                32,
            )
            .expect("input");
        assert!(outcome.deliveries.is_empty());
        assert_eq!(native.rng_position(), 5);
        assert_eq!(native.snapshot().next_seq, 0);
        assert_eq!(journal.len(), 1);
        assert_eq!(journal[0].payload.as_slice(), &[8, 9]);

        let capture = definition
            .capture(&native, &journal, 1024 * 1024)
            .expect("capture");
        let (restored, saved) = definition.restore(&capture, 1024 * 1024).expect("restore");
        assert_eq!(saved, journal);
        assert_eq!(restored.snapshot(), native.snapshot());
    }

    #[test]
    fn duplicated_corrupted_packets_restore_original_draws_and_two_output_sequences() {
        let mut definition = definition();
        definition.corrupt = probability(1, 1);
        definition.corruption_bits = 1;
        let mut native = definition.instantiate().expect("native");
        let mut journal = Vec::new();
        let payload = [0, 1, 2, 3];

        let outcome = definition
            .consume(
                &mut native,
                &mut journal,
                FaultedInput {
                    position: input(10),
                    sequence: 7.into(),
                    payload: &payload,
                },
                32,
            )
            .expect("input");
        assert_eq!(outcome.deliveries.len(), 2);
        assert_eq!(outcome.deliveries[0].key.seq, 0);
        assert_eq!(outcome.deliveries[1].key.seq, 1);
        assert_eq!(outcome.deliveries[0].key.delivery_icount, 1010);
        assert_eq!(outcome.deliveries[1].key.delivery_icount, 1110);
        assert_eq!(outcome.deliveries[0].payload, outcome.deliveries[1].payload);
        let changed_bits: u32 = payload
            .iter()
            .zip(&outcome.deliveries[0].payload)
            .map(|(before, after)| (before ^ after).count_ones())
            .sum();
        assert_eq!(changed_bits, 1);
        assert_eq!(native.rng_position(), 6);

        let capture = definition
            .capture(&native, &journal, 1024 * 1024)
            .expect("capture");
        let (mut restored, mut saved) = definition.restore(&capture, 1024 * 1024).expect("restore");
        for (link, records) in [(&mut native, &mut journal), (&mut restored, &mut saved)] {
            definition
                .consume(
                    link,
                    records,
                    FaultedInput {
                        position: input(20),
                        sequence: 8.into(),
                        payload: &[4, 5],
                    },
                    32,
                )
                .expect("next original");
        }
        assert_eq!(native.snapshot(), restored.snapshot());
        assert_eq!(journal, saved);
        assert_eq!(native.rng_position(), 12);
    }

    #[test]
    fn changed_journal_seed_policy_and_output_bytes_refuse() {
        let definition = definition();
        let mut native = definition.instantiate().expect("native");
        let mut journal = Vec::new();
        definition
            .consume(
                &mut native,
                &mut journal,
                FaultedInput {
                    position: input(10),
                    sequence: 7.into(),
                    payload: &[8, 9],
                },
                32,
            )
            .expect("input");
        let capture = definition
            .capture(&native, &journal, 1024 * 1024)
            .expect("capture");

        let mut changed = definition.clone();
        changed.seed = 78.into();
        assert!(changed.restore(&capture, 1024 * 1024).is_err());
        changed = definition.clone();
        changed.loss = probability(1, 1);
        assert!(changed.restore(&capture, 1024 * 1024).is_err());
        let mut saved: Snapshot = serde_json::from_slice(&capture).expect("snapshot");
        saved.decisions[0].draws.values[2] = 0.into();
        assert!(
            definition
                .restore(&encode(&saved).expect("encoding"), 1024 * 1024)
                .is_err()
        );
        let mut saved: Snapshot = serde_json::from_slice(&capture).expect("snapshot");
        saved.decisions[0].outputs[0].payload = Bytes::new(vec![99]);
        assert!(
            definition
                .restore(&encode(&saved).expect("encoding"), 1024 * 1024)
                .is_err()
        );
    }

    #[test]
    fn insufficient_output_credit_refuses_before_draw_or_input_effect() {
        let definition = definition();
        let mut native = definition.instantiate().expect("native");
        let before = native.snapshot();
        let mut journal = Vec::new();

        assert!(
            definition
                .consume(
                    &mut native,
                    &mut journal,
                    FaultedInput {
                        position: input(10),
                        sequence: 7.into(),
                        payload: &[8, 9]
                    },
                    1
                )
                .is_err()
        );
        assert_eq!(native.snapshot(), before);
        assert!(journal.is_empty());
    }
}
