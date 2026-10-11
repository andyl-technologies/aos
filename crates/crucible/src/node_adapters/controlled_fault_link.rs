//! Immutable authored coefficient transitions and original native decision custody.
//!
//! Only an admitted `FaultInjectionV1` operation applies a live transition. The
//! program fixes all timing and topology; queued outputs keep their original
//! resolved bytes and coordinates. A continuation retains the complete original
//! mutation/input histories, including source contexts and zero-output loss.
//!
//! The selected canonical native body is distinct from static link editions:
//!
//! ```text
//! {"version":1,"program":{...},"native":"<base64>","mutations":[...],"inputs":[...]}
//! ```

use std::collections::BTreeSet;

use crucible_node_contract::{ContentRef, Phase};

use super::*;
use crate::node_contract::{
    FaultMutationRecord, FaultMutationRequest, OperationAdmission, OperationRequest,
};

const STREAM_DOMAIN: &str = "crucible/controlled-fault-link-v1";

/// Selects exact loss, duplication and corruption coefficients only.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FaultCoefficients {
    /// Selects the exact rational loss probability.
    pub loss: FaultProbability,
    /// Selects the exact rational duplication probability.
    pub duplicate: FaultProbability,
    /// Selects the exact rational corruption probability.
    pub corrupt: FaultProbability,
}

impl FaultCoefficients {
    fn validate(&self) -> Result<(), OperationFailure> {
        self.loss.native()?;
        self.duplicate.native()?;
        self.corrupt.native()?;
        Ok(())
    }

    fn reference(&self) -> Result<ContentRef, OperationFailure> {
        canonical::content_ref(&encode(self)?, "application/json")
            .map_err(|error| failure(&error.to_string()))
    }
}

/// Defines one immutable authored transition at a precise BoundaryControl cut.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthoredFaultTransition {
    /// Identifies an authored BoundaryControl coordinate at microstep zero.
    pub at: Position,
    /// Selects coefficients for inputs consumed after this operation.
    pub coefficients: FaultCoefficients,
}

/// Defines a complete installed controller and unchanged timing contract.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlledFaultProgram {
    /// Selects this controller grammar, currently one.
    pub version: u16,
    /// Binds complete original seed, stream, source and positive fixed timing.
    pub initial: FaultedLinkDefinition,
    /// Orders at most sixteen exact authored coefficient transitions.
    pub transitions: Vec<AuthoredFaultTransition>,
}

impl ControlledFaultProgram {
    /// Validates the full immutable controller without admitting an operation.
    ///
    /// # Errors
    /// Refuses unsupported initial models, empty/unbounded programs, malformed
    /// coefficients, other phases and nonincreasing authored positions.
    pub fn validate(&self) -> Result<(), OperationFailure> {
        self.initial.instantiate()?;
        if self.version != 1 || self.transitions.is_empty() || self.transitions.len() > 16 {
            return Err(failure(
                "controlled fault program is unsupported or unbounded",
            ));
        }
        let mut previous = None;
        for transition in &self.transitions {
            transition
                .at
                .validate()
                .map_err(|error| failure(&error.to_string()))?;
            transition.coefficients.validate()?;
            if transition.at.phase != Phase::BoundaryControl
                || transition.at.microstep.get() != 0
                || previous.is_some_and(|position| transition.at <= position)
            {
                return Err(failure(
                    "controller transitions require increasing BoundaryControl positions",
                ));
            }
            previous = Some(transition.at);
        }
        Ok(())
    }

    /// Binds exact complete canonical controller bytes.
    ///
    /// # Errors
    /// Refuses invalid programs or canonical serialization failures.
    pub fn reference(&self) -> Result<ContentRef, OperationFailure> {
        self.validate()?;
        canonical::content_ref(&encode(self)?, "application/json")
            .map_err(|error| failure(&error.to_string()))
    }

    fn coefficients(&self, applied: usize) -> Result<FaultCoefficients, OperationFailure> {
        if applied == 0 {
            return Ok(FaultCoefficients {
                loss: self.initial.loss.clone(),
                duplicate: self.initial.duplicate.clone(),
                corrupt: self.initial.corrupt.clone(),
            });
        }
        self.transitions
            .get(applied - 1)
            .map(|transition| transition.coefficients.clone())
            .ok_or_else(|| failure("fault controller cursor exceeds its complete program"))
    }

    fn effective(&self, applied: usize) -> Result<FaultedLinkDefinition, OperationFailure> {
        let coefficients = self.coefficients(applied)?;
        let mut effective = self.initial.clone();
        effective.loss = coefficients.loss;
        effective.duplicate = coefficients.duplicate;
        effective.corrupt = coefficients.corrupt;
        effective.corruption_bits = u32::from(effective.corrupt.numerator.get() != 0);
        Ok(effective)
    }
}

/// Owns actual native transport and the original admitted controller journal.
pub struct ControlledFaultLink {
    program: ControlledFaultProgram,
    program_reference: ContentRef,
    facet_profile: Id,
    link: NetLink,
    mutations: Vec<FaultMutationRecord>,
    inputs: Vec<FaultDecision>,
}

pub(crate) struct PreparedFaultMutation {
    pub(crate) record: FaultMutationRecord,
    pub(crate) body: crate::node_scheduling::InputPayload,
    pub(crate) tables: Vec<crate::node_scheduling::InputPayload>,
    effective: crucible_device::netlink::LinkFaults,
}

impl ControlledFaultLink {
    /// Creates an inactive native owner under its exact immutable controller.
    ///
    /// # Errors
    /// Refuses malformed programs and failed initial native construction.
    pub fn new(program: ControlledFaultProgram) -> Result<Self, OperationFailure> {
        let program_reference = program.reference()?;
        let link = program.initial.instantiate()?;
        Ok(Self {
            program,
            program_reference,
            facet_profile: Id::new(super::super::host::HOST_FAULT_INJECTION_PROFILE)
                .map_err(|error| failure(&error.to_string()))?,
            link,
            mutations: Vec::new(),
            inputs: Vec::new(),
        })
    }

    /// Borrows the complete immutable installed controller program.
    pub fn program(&self) -> &ControlledFaultProgram {
        &self.program
    }

    /// Returns the next authored request as data without native mutation.
    pub fn next_request(&self) -> Option<FaultMutationRequest> {
        self.program
            .transitions
            .get(self.mutations.len())
            .map(|transition| FaultMutationRequest {
                version: 1,
                facet_profile: self.facet_profile.clone(),
                program: self.program_reference.clone(),
                decision: U64::new(self.mutations.len() as u64),
                at: transition.at,
            })
    }

    /// Borrows the exact applied native journal without granting mutation authority.
    pub fn mutation_records(&self) -> &[FaultMutationRecord] {
        &self.mutations
    }

    pub(crate) fn original_mutation(&self, operation: &Id) -> Option<&FaultMutationRecord> {
        self.mutations
            .iter()
            .find(|record| &record.operation == operation)
    }

    pub(crate) fn native(&self) -> &NetLink {
        &self.link
    }

    pub(crate) fn native_mut(&mut self) -> &mut NetLink {
        &mut self.link
    }

    pub(crate) fn consume(
        &mut self,
        original: FaultedInput<'_>,
        pending_limit: usize,
    ) -> Result<ResolveOutcome, OperationFailure> {
        original
            .position
            .validate()
            .map_err(|error| failure(&error.to_string()))?;
        if self
            .next_request()
            .is_some_and(|request| original.position >= request.at)
        {
            return Err(failure(
                "original input awaits its admitted authored controller transition",
            ));
        }
        self.program
            .effective(self.mutations.len())?
            .consume_in_domain(
                &mut self.link,
                &mut self.inputs,
                original,
                pending_limit,
                STREAM_DOMAIN,
            )
    }

    pub(crate) fn prepare_mutation(
        &mut self,
        original: &OperationAdmission,
    ) -> Result<PreparedFaultMutation, OperationFailure> {
        let OperationRequest::FaultInjectionV1(request) = original.request() else {
            return Err(failure(
                "native coefficient change requires explicit admitted fault operation",
            ));
        };
        request.validate()?;
        if self.next_request().as_ref() != Some(request)
            || request.at.time_ps.get() != self.link.current_icount()
            || self.mutations.len() >= 16
            || self
                .mutations
                .iter()
                .any(|record| record.operation == *original.token().operation())
        {
            return Err(failure(
                "fault operation does not match original native controller state",
            ));
        }
        let previous_table = self
            .program
            .coefficients(self.mutations.len())?
            .reference()?;
        let applied_table = self
            .program
            .coefficients(self.mutations.len() + 1)?
            .reference()?;
        let mut tables = Vec::new();
        tables
            .try_reserve_exact(2)
            .map_err(|_| failure("original table proof credit unavailable"))?;
        for index in [self.mutations.len(), self.mutations.len() + 1] {
            let bytes = encode(&self.program.coefficients(index)?)?;
            let reference = canonical::content_ref(&bytes, "application/json")
                .map_err(|error| failure(&error.to_string()))?;
            tables.push(crate::node_scheduling::InputPayload { reference, bytes });
        }
        let effective = self.program.effective(self.mutations.len() + 1)?.faults()?;
        self.mutations
            .try_reserve(1)
            .map_err(|_| failure("original fault decision credit unavailable"))?;
        let record = FaultMutationRecord {
            version: 1,
            operation: original.token().operation().clone(),
            node: original.token().route().node.clone(),
            owners: original.token().route().owners.clone(),
            source: original.activation().record().into(),
            request: request.as_ref().clone(),
            input_prefix: U64::new(self.inputs.len() as u64),
            previous_table,
            applied_table,
        };
        let bytes = encode(&record)?;
        let reference = canonical::content_ref(&bytes, "application/json")
            .map_err(|error| failure(&error.to_string()))?;
        Ok(PreparedFaultMutation {
            record,
            body: crate::node_scheduling::InputPayload { reference, bytes },
            tables,
            effective,
        })
    }

    pub(crate) fn commit_mutation(
        &mut self,
        prepared: PreparedFaultMutation,
    ) -> Result<(), OperationFailure> {
        if self.next_request().as_ref() != Some(&prepared.record.request)
            || self.link.current_icount() != prepared.record.request.at.time_ps.get()
            || self.inputs.len() as u64 != prepared.record.input_prefix.get()
            || self.mutations.capacity() <= self.mutations.len()
        {
            return Err(failure(
                "prepared original mutation no longer matches live native scope",
            ));
        }
        // Complete original record/receipt, table and journal capacity exist
        // before this setter. Timing remains fixed and every queued frame keeps
        // its previously resolved bytes and coordinates.
        self.link.set_faults(prepared.effective);
        self.mutations.push(prepared.record);
        Ok(())
    }

    /// Encodes complete native controller and original histories without effects.
    ///
    /// # Errors
    /// Refuses invalid or oversized original state and inconsistent native data.
    pub fn capture(&self, maximum: usize) -> Result<Vec<u8>, OperationFailure> {
        let bytes = encode(&ControlledSnapshot {
            version: 1,
            program: self.program.clone(),
            native: Bytes::new(
                self.link
                    .snapshot()
                    .canonical_bytes_with_limit(maximum as u64)
                    .map_err(|error| failure(&error.to_string()))?,
            ),
            mutations: self.mutations.clone(),
            inputs: self.inputs.clone(),
        })?;
        if bytes.len() > maximum {
            return Err(failure(
                "complete controlled-link capture exceeds finite bytes",
            ));
        }
        Self::restore(&self.program, &bytes, maximum)?;
        Ok(bytes)
    }

    /// Checks original data and rebuilds inactive native state without authority.
    ///
    /// Installed continuation qualification separately authenticates all original
    /// operation contexts and native custody. The disposable history validator
    /// never dispatches these records to a live restored owner.
    ///
    /// # Errors
    /// Refuses changed program/table/order, malformed original contexts, altered
    /// draws/outputs, unsupported native timing and exceeded history/queue limits.
    pub fn restore(
        expected: &ControlledFaultProgram,
        bytes: &[u8],
        maximum: usize,
    ) -> Result<Self, OperationFailure> {
        let saved: ControlledSnapshot = serde_json::from_value(
            canonical::parse_json(bytes, maximum).map_err(|error| failure(&error.to_string()))?,
        )
        .map_err(|error| failure(&error.to_string()))?;
        if saved.version != 1
            || &saved.program != expected
            || encode(&saved)? != bytes
            || saved.mutations.len() > 16
            || saved.inputs.len() > 16
        {
            return Err(failure(
                "controlled continuation changed program or complete bounded grammar",
            ));
        }
        let mut checked = Self::new(expected.clone())?;
        let native =
            LinkSnapshot::from_canonical_bytes_with_limit(saved.native.as_slice(), maximum as u64)
                .map_err(|error| failure(&error.to_string()))?;
        let mut seen = BTreeSet::new();
        let mut mutation_index = 0;
        for input_index in 0..=saved.inputs.len() {
            while let Some(record) = saved.mutations.get(mutation_index)
                && record.input_prefix.get() == input_index as u64
            {
                let previous = checked.program.coefficients(mutation_index)?.reference()?;
                let applied = checked
                    .program
                    .coefficients(mutation_index + 1)?
                    .reference()?;
                if record.version != 1
                    || checked.next_request().as_ref() != Some(&record.request)
                    || record.previous_table != previous
                    || record.applied_table != applied
                    || record.operation.validate().is_err()
                    || record.node.validate().is_err()
                    || record.owners.is_empty()
                    || !seen.insert(record.operation.clone())
                    || record.source.generation.get() == 0
                    || record.source.activation_id.validate().is_err()
                    || record.source.world_binding_hash.validate().is_err()
                    || record.source.boundary.validate().is_err()
                    || record.source.owners.is_empty()
                    || record.source.owners.iter().any(|owner| {
                        owner.owner.validate().is_err()
                            || owner.incarnation.validate().is_err()
                            || owner.generation.get() == 0
                    })
                    || record
                        .source
                        .owners
                        .iter()
                        .map(|owner| &owner.owner)
                        .collect::<BTreeSet<_>>()
                        .len()
                        != record.source.owners.len()
                    || record
                        .owners
                        .iter()
                        .map(|owner| &owner.owner)
                        .collect::<BTreeSet<_>>()
                        .len()
                        != record.owners.len()
                    || record.source.boundary > record.request.at
                    || record.request.at.time_ps.get() < checked.link.current_icount()
                    || record.request.at.time_ps.get() > native.current_icount
                    || record
                        .owners
                        .iter()
                        .any(|owner| !record.source.owners.contains(owner))
                {
                    return Err(failure(
                        "controlled original mutation history is inconsistent",
                    ));
                }
                checked
                    .link
                    .advance_to(record.request.at.time_ps.get())
                    .map_err(|error| failure(&error.to_string()))?;
                checked
                    .link
                    .set_faults(checked.program.effective(mutation_index + 1)?.faults()?);
                checked.mutations.push(record.clone());
                mutation_index += 1;
            }
            let Some(decision) = saved.inputs.get(input_index) else {
                break;
            };
            if decision.native_clock.get() < checked.link.current_icount()
                || decision.native_clock.get() > native.current_icount
            {
                return Err(failure("controlled input changed original native order"));
            }
            checked
                .link
                .advance_to(decision.native_clock.get())
                .map_err(|error| failure(&error.to_string()))?;
            checked.consume(
                FaultedInput {
                    position: decision.input,
                    sequence: decision.sequence,
                    payload: decision.payload.as_slice(),
                },
                32,
            )?;
            if checked.inputs.last() != Some(decision) {
                return Err(failure("controlled original input draw or output changed"));
            }
        }
        let fixed = expected.initial.instantiate()?.snapshot();
        let outputs: Vec<_> = saved
            .inputs
            .iter()
            .flat_map(|input| &input.outputs)
            .collect();
        if mutation_index != saved.mutations.len()
            || native.src_node != fixed.src_node
            || native.ticks_per_ns != fixed.ticks_per_ns
            || native.base_latency_ticks != fixed.base_latency_ticks
            || native.floor_ticks != fixed.floor_ticks
            || native.lookahead_recompute_pending != fixed.lookahead_recompute_pending
            || native.faults != *checked.link.faults()
            || native.rng_position != checked.link.rng_position()
            || native.next_seq as usize != outputs.len()
            || native.next_seq > 32
            || native.inflight.len() > 32
            || checked
                .next_request()
                .is_some_and(|request| native.current_icount > request.at.time_ps.get())
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
                "controlled native timing/RNG/FIFO differs from complete original history",
            ));
        }
        checked.link = NetLink::restore(&native).map_err(|error| failure(&error.to_string()))?;
        Ok(checked)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ControlledSnapshot {
    version: u16,
    program: ControlledFaultProgram,
    native: Bytes,
    mutations: Vec<FaultMutationRecord>,
    inputs: Vec<FaultDecision>,
}

#[cfg(test)]
#[path = "controlled_fault_link_tests.rs"]
mod tests;
