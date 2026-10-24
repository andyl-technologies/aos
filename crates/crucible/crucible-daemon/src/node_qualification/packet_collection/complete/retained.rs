//! Counts actual daemon-owned metadata without following borrowed source owners.
//!
//! Inline slots are charged by their containing Vec, Box, Rc or tree node.
//! Equal fullrefs do not deduplicate independent allocations. Only stable actual
//! Rc/Arc data addresses can share a retained owner in this bounded walk.

use std::{
    collections::{BTreeMap, BTreeSet},
    mem::{align_of, size_of},
    path::PathBuf,
    rc::{Rc, Weak},
};

use crucible_engine::node_state::{
    borrowed_btree_map_requested_storage_precredit_data as borrowed_btree_map_requested_storage,
    borrowed_btree_set_requested_storage_precredit_data as borrowed_btree_set_requested_storage,
};
use crucible_node_format::{
    Bytes, ConnectionDescriptor, ContentRef, Endpoint, HashRef, Id, NodeBindingRef, SchemaRef,
    WorldBinding,
};

use crate::node_qualification::{
    AcceptanceDecision, AcceptanceRecord, CaseEvidence, PlannedWitnessCase, QualificationClaim,
    QualificationClass, QualificationError, QualificationUnit, RequirementResult, WitnessCriterion,
    WitnessPlan,
};

use crucible_engine::node_adapters::cnp::PacketCompleteSemanticSource;
use crucible_node_transport::retained_metadata::RetainedProtocolMetadataFacts;

const SHARED_OWNERS: usize = 128;

pub(crate) struct Counter {
    bytes: usize,
    maximum: usize,
    shared: [Option<*const ()>; SHARED_OWNERS],
    shared_used: usize,
}

impl Counter {
    pub(crate) fn new(maximum: usize) -> Self {
        Self {
            bytes: 0,
            maximum,
            shared: [None; SHARED_OWNERS],
            shared_used: 0,
        }
    }

    pub(crate) fn bytes(&self) -> usize {
        self.bytes
    }

    pub(crate) fn remaining(&self) -> usize {
        self.maximum - self.bytes
    }

    pub(crate) fn add(&mut self, bytes: usize) -> Result<(), QualificationError> {
        self.bytes = self
            .bytes
            .checked_add(bytes)
            .filter(|total| *total <= self.maximum)
            .ok_or_else(exhausted)?;
        Ok(())
    }

    pub(crate) fn charge(&mut self, value: &impl Owned) -> Result<(), QualificationError> {
        value.charge(self)
    }

    /// Consumes only existing borrowed Core owner facts; no virtual callback runs.
    pub(crate) fn core(
        &mut self,
        facts: &crucible_engine::node_contract::RetainedCoreOwnerStorage<'_>,
    ) -> Result<(), QualificationError> {
        self.add(facts.independent_bytes())?;
        for root in facts.shared_allocations() {
            let identity = root.identity();
            if identity.is_null() {
                return Err(exhausted());
            }
            if self.shared[..self.shared_used].contains(&Some(identity)) {
                continue;
            }
            if self.shared_used == self.shared.len() {
                return Err(exhausted());
            }
            self.add(root.requested_bytes())?;
            self.shared[self.shared_used] = Some(identity);
            self.shared_used += 1;
        }
        Ok(())
    }

    pub(crate) fn metadata(
        &mut self,
        facts: &RetainedProtocolMetadataFacts,
    ) -> Result<(), QualificationError> {
        let bytes =
            PacketCompleteSemanticSource::complete_retained_metadata_storage_precredit_data(
                facts,
                self.remaining(),
            )
            .map_err(|_| exhausted())?;
        self.add(bytes)
    }

    /// Admits an actual shared allocation once; callers then walk its fields.
    pub(crate) fn rc<T>(&mut self, owner: &Rc<T>) -> Result<bool, QualificationError> {
        self.shared_header(Rc::as_ptr(owner).cast(), size_of::<T>(), align_of::<T>())
    }

    /// Charges a retained Weak without marking any strong payload as walked.
    pub(crate) fn weak<T>(&mut self, _owner: &Weak<T>) -> Result<(), QualificationError> {
        self.add(shared_requested_storage(size_of::<T>(), align_of::<T>())?)
    }

    pub(crate) fn shared_header(
        &mut self,
        identity: *const (),
        inline: usize,
        alignment: usize,
    ) -> Result<bool, QualificationError> {
        if self.shared[..self.shared_used].contains(&Some(identity)) {
            return Ok(false);
        }
        if self.shared_used == self.shared.len() {
            return Err(exhausted());
        }
        let bytes = shared_requested_storage(inline, alignment)?;
        self.add(bytes)?;
        self.shared[self.shared_used] = Some(identity);
        self.shared_used += 1;
        Ok(true)
    }
}

// Uses the same checked requested layout for strong and conservative Weak views.
pub(crate) fn shared_requested_storage(
    inline: usize,
    alignment: usize,
) -> Result<usize, QualificationError> {
    let padding = alignment
        .max(align_of::<usize>())
        .checked_sub(1)
        .and_then(|value| value.checked_mul(2))
        .ok_or_else(exhausted)?;
    inline
        .checked_add(2 * size_of::<usize>())
        .and_then(|bytes| bytes.checked_add(padding))
        .ok_or_else(exhausted)
}

pub(crate) trait Owned {
    fn charge(&self, counter: &mut Counter) -> Result<(), QualificationError>;
}

impl Owned for String {
    fn charge(&self, counter: &mut Counter) -> Result<(), QualificationError> {
        counter.add(self.capacity())
    }
}

impl Owned for Id {
    fn charge(&self, counter: &mut Counter) -> Result<(), QualificationError> {
        counter.add(self.allocated_capacity())
    }
}

impl Owned for PathBuf {
    fn charge(&self, counter: &mut Counter) -> Result<(), QualificationError> {
        counter.add(self.capacity())
    }
}

impl Owned for Bytes {
    fn charge(&self, counter: &mut Counter) -> Result<(), QualificationError> {
        counter.add(self.allocation_capacity())
    }
}

impl Owned for u8 {
    fn charge(&self, _: &mut Counter) -> Result<(), QualificationError> {
        Ok(())
    }
}

macro_rules! scalar {
    ($($kind:ty),+ $(,)?) => { $(impl Owned for $kind {
        fn charge(&self, _: &mut Counter) -> Result<(), QualificationError> { Ok(()) }
    })+ };
}

scalar!(
    u16,
    crucible_node_format::U64,
    crucible_node_format::Position,
    crate::node_qualification::CaseKind,
    crate::node_qualification::CaseVerdict,
    crate::node_qualification::RequirementDisposition,
    super::super::connected::PacketConnectedCaseKind
);

impl Owned for QualificationClass {
    fn charge(&self, _: &mut Counter) -> Result<(), QualificationError> {
        Ok(())
    }
}

impl<T: Owned> Owned for Vec<T> {
    fn charge(&self, counter: &mut Counter) -> Result<(), QualificationError> {
        counter.add(
            self.capacity()
                .checked_mul(size_of::<T>())
                .ok_or_else(exhausted)?,
        )?;
        for value in self {
            value.charge(counter)?;
        }
        Ok(())
    }
}

impl<T: Owned> Owned for Option<T> {
    fn charge(&self, counter: &mut Counter) -> Result<(), QualificationError> {
        if let Some(value) = self {
            value.charge(counter)?;
        }
        Ok(())
    }
}

impl<A: Owned, B: Owned> Owned for (A, B) {
    fn charge(&self, counter: &mut Counter) -> Result<(), QualificationError> {
        self.0.charge(counter)?;
        self.1.charge(counter)
    }
}

impl<K: Owned, V: Owned> Owned for BTreeMap<K, V> {
    fn charge(&self, counter: &mut Counter) -> Result<(), QualificationError> {
        counter.add(
            borrowed_btree_map_requested_storage(self, counter.remaining())
                .map_err(|_| exhausted())?,
        )?;
        for (key, value) in self {
            key.charge(counter)?;
            value.charge(counter)?;
        }
        Ok(())
    }
}

impl<T: Owned> Owned for BTreeSet<T> {
    fn charge(&self, counter: &mut Counter) -> Result<(), QualificationError> {
        counter.add(
            borrowed_btree_set_requested_storage(self, counter.remaining())
                .map_err(|_| exhausted())?,
        )?;
        for value in self {
            value.charge(counter)?;
        }
        Ok(())
    }
}

macro_rules! fields {
    ($kind:ty; $($field:ident),+ $(,)?) => {
        impl Owned for $kind {
            fn charge(&self, counter: &mut Counter) -> Result<(), QualificationError> {
                let Self { $($field),+ } = self;
                $($field.charge(counter)?;)+
                Ok(())
            }
        }
    };
}

impl<T: Owned, const N: usize> Owned for [T; N] {
    fn charge(&self, counter: &mut Counter) -> Result<(), QualificationError> {
        for value in self {
            value.charge(counter)?;
        }
        Ok(())
    }
}

fields!(super::super::PacketFixtureArtifact; role, path, content);
fields!(super::super::PacketFixtureMeasurements; peer, host, sources);
fields!(crucible_engine::node_contract::OwnerIdentity; owner, incarnation, generation);
fields!(crucible_engine::node_contract::NodeRoute; node, owners);
fields!(crucible_engine::node_contract::ActivationRecord; generation, activation_id, world_binding_hash, owners, boundary);
fields!(super::super::connected::PacketConnectedGrant; node, operation, request);
fields!(super::super::connected::PacketConnectedCase; id, kind, node, operation);
fields!(super::super::connected::PacketConnectedSchedule; nodes, grants, cases);

impl Owned for crucible_engine::node_contract::OperationRequest {
    fn charge(&self, _: &mut Counter) -> Result<(), QualificationError> {
        // This is the exact installed complete schedule, whose requests have
        // full scalar positions only. Other operation families stay closed.
        match self {
            Self::ExactRun {
                start: _,
                limit: _,
                boundary_policy: _,
            }
            | Self::BoundarySettle { start: _, limit: _ } => Ok(()),
            _ => Err(QualificationError::Refused(
                "unselected complete daemon request layout",
            )),
        }
    }
}

fields!(HashRef; algorithm, domain, digest);
fields!(ContentRef; hash, length, media_type);
fields!(Endpoint; node_id, port_id, lane_id);
fields!(SchemaRef; id, version, definition, extensions);
fields!(crucible_node_format::LiveAuthority; schema_version, session_id, incarnation_id, realization_id, activation_id, world_generation, owner_generation, input_epoch, host_receipt, extensions);
fields!(crucible_node_format::NodeBinding; compatibility, authority, extensions);
fields!(NodeBindingRef; node_id, binding_hash, extensions);
fields!(WorldBinding; schema_version, scenario_ref, node_bindings, connections, ownership_ref, coordinator_contract_ref, ordering_profile, initialization_ref, extensions);
fields!(ConnectionDescriptor; schema_version, id, producer, consumer, interface_id, features, payload_schema, minimum_latency_ps, policy_ref, capture_owner_id, extensions);
fields!(QualificationUnit; implementation, realization, descriptors, contracts, port_profiles, environment, harness, fixtures, specification);
fields!(PlannedWitnessCase; id, kind, classes, oracle);
fields!(WitnessPlan; schema, unit, classes, requirements, cases, limitations);
fields!(CaseEvidence; case, kind, verdict, classes, result, oracle);
fields!(RequirementResult; requirement, disposition, cases, not_applicable_reason);
fields!(QualificationClaim; format, version, unit, classes, catalog, applicability_policy, requirements, supersedes, limitations);
fields!(AcceptanceRecord; format, version, original_claim, original, evaluated_unit, required_classes, missing_requirements, decision);

impl Owned for WitnessCriterion {
    fn charge(&self, counter: &mut Counter) -> Result<(), QualificationError> {
        match self {
            Self::Applicable { cases, criterion } => {
                cases.charge(counter)?;
                criterion.charge(counter)
            }
            Self::NotApplicable { reason, criterion } => {
                reason.charge(counter)?;
                criterion.charge(counter)
            }
        }
    }
}

impl Owned for AcceptanceDecision {
    fn charge(&self, counter: &mut Counter) -> Result<(), QualificationError> {
        match self {
            Self::Accepted => Ok(()),
            Self::Refused { diagnostic } => diagnostic.charge(counter),
        }
    }
}

impl Owned for serde_json::Value {
    fn charge(&self, counter: &mut Counter) -> Result<(), QualificationError> {
        // The complete scene's closed identity contracts require empty extension
        // maps. Do not invent a generic dynamic-Value heap bound here; a future
        // explicitly selected nonempty extension needs its own actual observer.
        let _ = counter;
        Err(QualificationError::Refused(
            "complete daemon metadata contains an unselected dynamic Value",
        ))
    }
}

fn exhausted() -> QualificationError {
    QualificationError::Refused("complete daemon retained allocation exceeds admitted storage")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn independent_equal_buffers_count_both_spare_capacities() -> Result<(), QualificationError> {
        let mut first = String::with_capacity(4096);
        first.push_str("same");
        let second = first.clone();
        let mut counter = Counter::new(8192);
        counter.charge(&first)?;
        counter.charge(&second)?;
        assert_eq!(counter.bytes(), first.capacity() + second.capacity());
        Ok(())
    }

    #[test]
    fn weak_view_preserves_later_strong_nested_walk() -> Result<(), QualificationError> {
        let strong = Rc::new(String::with_capacity(2048));
        let weak = Rc::downgrade(&strong);
        let mut counter = Counter::new(8192);

        counter.weak(&weak)?;
        let header = counter.bytes();
        assert!(counter.rc(&strong)?);
        counter.charge(strong.as_ref())?;
        assert_eq!(counter.bytes(), 2 * header + strong.capacity());
        assert!(!counter.rc(&strong)?);

        let mut exact = Counter::new(header);
        exact.weak(&weak)?;
        assert_eq!(exact.bytes(), header);
        assert!(Counter::new(header - 1).weak(&weak).is_err());
        Ok(())
    }

    #[test]
    fn actual_shared_allocation_is_counted_once_but_equal_new_owner_is_separate()
    -> Result<(), QualificationError> {
        let first = Rc::new(7u64);
        let alias = Rc::clone(&first);
        let independent = Rc::new(7u64);
        let mut counter = Counter::new(1024);
        assert!(counter.rc(&first)?);
        let one = counter.bytes();
        assert!(!counter.rc(&alias)?);
        assert_eq!(counter.bytes(), one);
        assert!(counter.rc(&independent)?);
        assert_eq!(counter.bytes(), 2 * one);
        Ok(())
    }
}

impl Owned for crucible_node_format::NodeDescriptor {
    fn charge(&self, counter: &mut Counter) -> Result<(), QualificationError> {
        let bytes =
            crucible_engine::node_contract::NodeRuntime::original_descriptor_requested_storage_data(
                self,
                counter.remaining(),
            )
            .map_err(|_| exhausted())?;
        counter.add(bytes)
    }
}

impl Owned for crucible_node_format::BindingCompatibility {
    fn charge(&self, counter: &mut Counter) -> Result<(), QualificationError> {
        let bytes =
            crucible_engine::node_contract::NodeRuntime::original_binding_requested_storage_data(
                self,
                counter.remaining(),
            )
            .map_err(|_| exhausted())?;
        counter.add(bytes)
    }
}

impl Owned for crucible_node_format::OwnerBinding {
    fn charge(&self, counter: &mut Counter) -> Result<(), QualificationError> {
        let bytes =
            crucible_engine::node_contract::NodeRuntime::original_owner_binding_requested_storage_data(
                self,
                counter.remaining(),
            )
            .map_err(|_| exhausted())?;
        counter.add(bytes)
    }
}

impl Owned for crucible_engine::node_contract::OperationOutcome {
    fn charge(&self, counter: &mut Counter) -> Result<(), QualificationError> {
        let bytes =
            crucible_engine::node_contract::NodeRuntime::original_outcome_requested_storage_data(
                self,
                counter.remaining(),
            )
            .map_err(|_| exhausted())?;
        counter.add(bytes)
    }
}

fields!(crucible_engine::node_scheduling::InputPayload; reference, bytes);
fields!(crucible_node_format::ResourceLimits; cpu_budget_ns, memory_bytes, writable_bytes, processes, descriptors, pending_events, content_bytes, maximum_operations, extensions);
fields!(crate::node_scenario::NodeScenario; format, version, world, descriptors, compatibility, owners, requirements, content);
fields!(crate::node_scenario::ScenarioContent; reference, bytes);
fields!(crucible_engine::node_admission::ScenarioRequirements; deterministic, exact_capture, exact_continuation, durable_restart, isolated_fork, accepted_quantized_nodes, accepted_nondeterministic_nodes, accepted_limited_state_nodes, accepted_visibility_conversions);
scalar!(bool);

impl Owned for crate::node_qualification::QualificationError {
    fn charge(&self, counter: &mut Counter) -> Result<(), QualificationError> {
        match self {
            Self::Contract(error) => match error {
                crucible_node_format::ContractError::Invalid { field: _, reason } => {
                    counter.charge(reason)
                }
                crucible_node_format::ContractError::Overflow => Ok(()),
                crucible_node_format::ContractError::Json(_) => Err(QualificationError::Refused(
                    "opaque Clock JSON error storage",
                )),
            },
            Self::Refused(_) => Ok(()),
            Self::Evidence(reason) => counter.charge(reason),
        }
    }
}

impl Owned for crucible_engine::node_contract::WorldActivation {
    fn charge(&self, counter: &mut Counter) -> Result<(), QualificationError> {
        let facts = self
            .retained_requested_storage_data(counter.remaining())
            .map_err(|_| exhausted())?;
        counter.core(&facts)
    }
}

impl Owned for crucible_engine::node_contract::OperationToken {
    fn charge(&self, counter: &mut Counter) -> Result<(), QualificationError> {
        let facts = self
            .retained_requested_storage_data(counter.remaining())
            .map_err(|_| exhausted())?;
        counter.core(&facts)
    }
}

fields!(crucible_engine::node_contract::NativeRuntimeContinuationEvidence; proof, input_acknowledgements);
fields!(crucible_engine::node_state::RestoredOwnerAttestation; identity, state_domain_ids, binding_hashes, cut, event_ordinal, state_inventory, ready_receipt);

impl Owned for crucible_engine::node_scheduling::NativeInputAcknowledgement {
    fn charge(&self, counter: &mut Counter) -> Result<(), QualificationError> {
        let bytes =
            crucible_engine::node_contract::NodeRuntime::original_input_ack_requested_storage_data(
                self,
                counter.remaining(),
            )
            .map_err(|_| exhausted())?;
        counter.add(bytes)
    }
}

impl Owned for crucible_engine::node_contract::RuntimeError {
    fn charge(&self, counter: &mut Counter) -> Result<(), QualificationError> {
        use crucible_engine::node_contract::RuntimeError::*;
        match self {
            SchedulerRefused(reason) => counter.charge(reason),
            ResourceLimit
            | ThreadAffinity
            | UnknownNode
            | InvalidRoute
            | DuplicateOperation
            | OwnerBusy
            | OwnerUnavailable
            | NotActivated
            | ForeignAuthority
            | UnsupportedFacet
            | InvalidTiming
            | InvalidReceipt
            | OutstandingObligations
            | PublicationFailed => Ok(()),
        }
    }
}

impl Owned for crucible_engine::node_contract::OperationFailure {
    fn charge(&self, counter: &mut Counter) -> Result<(), QualificationError> {
        let Self { reason, effects: _ } = self;
        counter.charge(reason)
    }
}

impl Owned for crucible_engine::node_contract::RuntimePollFailure {
    fn charge(&self, counter: &mut Counter) -> Result<(), QualificationError> {
        match self {
            Self::Admission(error) => counter.charge(error),
            Self::Native(error) => counter.charge(error),
        }
    }
}

impl Owned for crucible_engine::node_admission::AdmittedGraph {
    fn charge(&self, counter: &mut Counter) -> Result<(), QualificationError> {
        let bytes = self
            .original_retained_requested_storage_precredit_data(counter.remaining())
            .map_err(|_| exhausted())?;
        counter.add(bytes)
    }
}

impl Owned for crucible_engine::node_contract::NodeRuntime {
    fn charge(&self, counter: &mut Counter) -> Result<(), QualificationError> {
        let bytes = self
            .original_retained_requested_storage_precredit_data(counter.remaining())
            .map_err(|_| exhausted())?;
        counter.add(bytes)
    }
}

impl Owned for crucible_engine::node_contract::QuarantinedRuntime {
    fn charge(&self, counter: &mut Counter) -> Result<(), QualificationError> {
        let bytes = self
            .original_retained_requested_storage_precredit_data(counter.remaining())
            .map_err(|_| exhausted())?;
        counter.add(bytes)
    }
}

impl Owned for crucible_engine::node_state::NativeArchiveRecord {
    fn charge(&self, counter: &mut Counter) -> Result<(), QualificationError> {
        let bytes = self
            .retained_record_requested_storage_data()
            .map_err(|_| exhausted())?
            .checked_sub(size_of::<Self>())
            .ok_or_else(exhausted)?;
        counter.add(bytes)
    }
}

impl Owned for crucible_campaign::ExecutionId {
    fn charge(&self, _: &mut Counter) -> Result<(), QualificationError> {
        Ok(())
    }
}

fields!(crucible_engine::node_contract::ProviderPreparationPlan; descriptors, bindings);

impl Owned for crucible_engine::node_contract::RuntimeSnapshot {
    fn charge(&self, counter: &mut Counter) -> Result<(), QualificationError> {
        let bytes =
            crucible_engine::node_contract::NodeRuntime::original_snapshot_requested_storage_data(
                self,
                counter.remaining(),
            )
            .map_err(|_| exhausted())?;
        counter.add(bytes)
    }
}

impl Owned for crucible_node_format::ContractError {
    fn charge(&self, counter: &mut Counter) -> Result<(), QualificationError> {
        match self {
            Self::Invalid { field: _, reason } => counter.charge(reason),
            Self::Overflow => Ok(()),
            Self::Json(_) => Err(QualificationError::Refused(
                "opaque retained JSON error storage",
            )),
        }
    }
}

#[cfg(test)]
mod clock_root_tests {
    use super::*;

    #[test]
    fn shared_roster_exhaustion_keeps_all_actual_owners_and_refuses_new_root()
    -> Result<(), QualificationError> {
        let originals: Vec<_> = (0..=SHARED_OWNERS).map(|value| Rc::new(value)).collect();
        let mut counter = Counter::new(usize::MAX);
        for original in &originals[..SHARED_OWNERS] {
            assert!(counter.rc(original)?);
        }
        let before = counter.bytes();
        assert!(counter.rc(&originals[SHARED_OWNERS]).is_err());
        assert_eq!(counter.bytes(), before);
        assert_eq!(originals.len(), SHARED_OWNERS + 1);
        assert!(!counter.rc(&originals[0])?);
        Ok(())
    }
}

impl Owned for crucible_node_transport::reference_packet::service::PacketConnectedSourceProgram {
    fn charge(&self, counter: &mut Counter) -> Result<(), QualificationError> {
        use crucible_node_transport::reference_packet::{
            PacketEvent, PacketProgramDefinition,
            connected::{PacketConnectedDefinition, PacketInputConnection},
            service::PacketConnectedSourceProgram,
        };
        match self {
            PacketConnectedSourceProgram::Producer { program } => {
                let PacketProgramDefinition { schema, events } = program;
                counter.charge(schema)?;
                counter.add(
                    events
                        .capacity()
                        .checked_mul(std::mem::size_of::<PacketEvent>())
                        .ok_or_else(exhausted)?,
                )?;
                for event in events {
                    let PacketEvent {
                        id,
                        evaluation: _,
                        completion: _,
                        payload,
                    } = event;
                    counter.charge(id)?;
                    counter.charge(payload)?;
                }
            }
            PacketConnectedSourceProgram::Reactive { program } => {
                let PacketConnectedDefinition {
                    schema,
                    connections,
                    output,
                } = program;
                counter.charge(schema)?;
                counter.add(
                    connections
                        .capacity()
                        .checked_mul(std::mem::size_of::<PacketInputConnection>())
                        .ok_or_else(exhausted)?,
                )?;
                for connection in connections {
                    let PacketInputConnection {
                        id,
                        policy,
                        producer,
                        consumer,
                        delay_ps: _,
                    } = connection;
                    counter.charge(id)?;
                    counter.charge(policy)?;
                    counter.charge(producer)?;
                    counter.charge(consumer)?;
                }
                counter.charge(output)?;
            }
        }
        Ok(())
    }
}
