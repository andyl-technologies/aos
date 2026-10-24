//! Reserves the finite actor on the caller's already-reserved original supervisor.
//!
//! Existing scene, supervisor, queue, slot and proposal owners stay with the
//! caller. These data quotes cover only the actor's new Box, grant/ID backing and
//! independent proposal clone; currentness/error callbacks remain caller-funded.

use super::*;
use crate::node_qualification::packet_collection::{
    complete::{retained::Counter, witness::PacketCompleteConstructionStorageData},
    connected::PacketConnectedSchedule,
};
use crucible_engine::node_contract::{
    ActivationRecord, RuntimeCustodySlot, RuntimeError, RuntimeLimits,
};
use std::mem::size_of;

// These exact strings are the legacy format!("complete-stage/batch-{index}")
// results. The selected path requests only their actual lengths, with no new
// formatter bank or alternate identifier semantics.
const STAGES: [&str; 13] = [
    "complete-stage-0",
    "complete-stage-1",
    "complete-stage-2",
    "complete-stage-3",
    "complete-stage-4",
    "complete-stage-5",
    "complete-stage-6",
    "complete-stage-7",
    "complete-stage-8",
    "complete-stage-9",
    "complete-stage-10",
    "complete-stage-11",
    "complete-stage-12",
];
const BATCHES: [&str; 13] = [
    "complete-batch-0",
    "complete-batch-1",
    "complete-batch-2",
    "complete-batch-3",
    "complete-batch-4",
    "complete-batch-5",
    "complete-batch-6",
    "complete-batch-7",
    "complete-batch-8",
    "complete-batch-9",
    "complete-batch-10",
    "complete-batch-11",
    "complete-batch-12",
];

fn authenticate_schedule_data(
    selected: &PacketConnectedSchedule,
) -> Result<schedule::Bootstrap, RuntimeError> {
    if selected.grants.len() != schedule::GRANTS {
        return Err(RuntimeError::UnsupportedFacet);
    }
    schedule::bootstrap_data(selected).map_err(|_| RuntimeError::ForeignAuthority)
}

fn reserve_grants(selected: &PacketConnectedSchedule) -> Result<Vec<Grant>, QualificationError> {
    let bootstrap = authenticate_schedule_data(selected).map_err(|_| refused())?;
    let mut grants = Vec::new();
    grants
        .try_reserve_exact(schedule::GRANTS)
        .map_err(|_| refused())?;
    for index in 0..schedule::GRANTS {
        let (member, operation, request) = bootstrap.row(index).ok_or_else(refused)?;
        let limit = match request {
            crucible_engine::node_contract::OperationRequest::ExactRun { limit, .. }
            | crucible_engine::node_contract::OperationRequest::BoundarySettle { limit, .. } => {
                limit
            }
            _ => return Err(refused()),
        };
        grants.push(Grant {
            node: selected.nodes[member].clone(),
            operation: Id::new(operation)?,
            limit,
            input: if member == 0 {
                None
            } else {
                Some((Id::new(STAGES[index])?, Id::new(BATCHES[index])?))
            },
            token: None,
        });
    }
    Ok(grants)
}

impl PacketCompleteExecutionActor {
    /// Quotes this selected Box, thirteen real grants/IDs and proposal clone.
    ///
    /// Existing source/scene/supervisor/runtime-slot roots and their callbacks
    /// are excluded; this row cannot reserve or replace any of those owners.
    ///
    /// # Errors
    /// Refuses a nonfixed schedule, unsupported owner roster, arithmetic overflow
    /// or the supplied requested-byte ceiling.
    pub(crate) fn original_construction_storage_data(
        selected: &PacketConnectedSchedule,
        proposal: &ActivationRecord,
        maximum: usize,
    ) -> Result<PacketCompleteConstructionStorageData, RuntimeError> {
        let bootstrap = authenticate_schedule_data(selected)?;
        if proposal.owners.len() != 4 {
            return Err(RuntimeError::UnsupportedFacet);
        }
        let mut counter = Counter::new(maximum);
        counter
            .add(size_of::<Self>())
            .map_err(|_| RuntimeError::ResourceLimit)?;
        counter
            .add(
                schedule::GRANTS
                    .checked_mul(size_of::<Grant>())
                    .ok_or(RuntimeError::ResourceLimit)?,
            )
            .map_err(|_| RuntimeError::ResourceLimit)?;
        for index in 0..schedule::GRANTS {
            let (member, operation, _) =
                bootstrap.row(index).ok_or(RuntimeError::UnsupportedFacet)?;
            counter
                .charge(&selected.nodes[member])
                .map_err(|_| RuntimeError::ResourceLimit)?;
            counter
                .add(operation.len())
                .map_err(|_| RuntimeError::ResourceLimit)?;
            if member != 0 {
                counter
                    .add(STAGES[index].len())
                    .map_err(|_| RuntimeError::ResourceLimit)?;
                counter
                    .add(BATCHES[index].len())
                    .map_err(|_| RuntimeError::ResourceLimit)?;
            }
        }
        counter
            .charge(proposal)
            .map_err(|_| RuntimeError::ResourceLimit)?;
        PacketCompleteConstructionStorageData::new(
            counter.bytes(),
            0,
            Self::original_construction_counter_scratch_data()?,
            maximum,
        )
    }

    /// Quotes fixed grant-builder, actual metadata and proposal-clone views.
    ///
    /// # Errors
    /// Refuses checked arithmetic overflow. Callback/compiler recursion, allocator
    /// physical overhead and existing Source/kernel owners remain separate.
    pub(crate) fn original_construction_counter_scratch_data() -> Result<usize, RuntimeError> {
        [
            schedule::bootstrap_counter_scratch_data(),
            size_of::<Counter>(),
            size_of::<Self>(),
            size_of::<Vec<Grant>>(),
            size_of::<Grant>(),
            size_of::<ActivationRecord>(),
            size_of::<PacketCompleteConstructionStorageData>(),
            size_of::<(
                usize,
                &str,
                crucible_engine::node_contract::OperationRequest,
            )>(),
            size_of::<Rc<crate::node_qualification::PacketWorldHostSupervisor>>(),
            size_of::<&dyn RuntimeCustodySlot>(),
            8 * size_of::<usize>(),
        ]
        .into_iter()
        .try_fold(0usize, |n, v| {
            n.checked_add(v).ok_or(RuntimeError::ResourceLimit)
        })
    }

    /// Counts only this actual dormant actor's new allocation backing.
    ///
    /// Scene/supervisor/slot/runtime owners are independently held and counted by
    /// the caller. Once runtime attachment or token execution starts this narrow
    /// phase refuses rather than report an incomplete active owner census.
    ///
    /// # Errors
    /// Refuses a foreign creator, nonselected/entered phase or checked excess.
    pub(crate) fn dormant_construction_storage_data(
        &self,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        let Self {
            scene: _,
            runtime,
            grants,
            next,
            phase,
            attachment_attempted,
            supervisor: _,
            supervision_proposal,
            supervision_attempted,
            process,
            thread,
        } = self;
        if *process != std::process::id() {
            return Err(RuntimeError::ForeignAuthority);
        }
        if *thread != std::thread::current().id() {
            return Err(RuntimeError::ThreadAffinity);
        }
        if *phase != Phase::Reserved
            || runtime.is_some()
            || *attachment_attempted
            || *next != 0
            || !*supervision_attempted
            || grants.iter().any(|grant| grant.token.is_some())
        {
            return Err(RuntimeError::UnsupportedFacet);
        }
        let proposal = supervision_proposal
            .as_ref()
            .ok_or(RuntimeError::UnsupportedFacet)?;
        let mut counter = Counter::new(maximum);
        counter
            .add(size_of::<Self>())
            .map_err(|_| RuntimeError::ResourceLimit)?;
        counter
            .add(
                grants
                    .capacity()
                    .checked_mul(size_of::<Grant>())
                    .ok_or(RuntimeError::ResourceLimit)?,
            )
            .map_err(|_| RuntimeError::ResourceLimit)?;
        for grant in grants {
            counter
                .charge(&grant.node)
                .map_err(|_| RuntimeError::ResourceLimit)?;
            counter
                .charge(&grant.operation)
                .map_err(|_| RuntimeError::ResourceLimit)?;
            counter
                .charge(&grant.input)
                .map_err(|_| RuntimeError::ResourceLimit)?;
        }
        counter
            .charge(proposal)
            .map_err(|_| RuntimeError::ResourceLimit)?;
        Ok(counter.bytes())
    }
}

impl PacketCompleteExecutionScene {
    /// Retains the same staged supervisor and already-reserved runtime slot.
    ///
    /// The caller admits construction/callback storage before invoking this
    /// selected route. It authenticates the original queue, actual full proposal
    /// and retained source owners, then spends actor reservation before allocation.
    /// It never calls reserve_original or constructs another cleanup supervisor.
    /// Existing attach still authenticates the genuine plan and SAME runtime queue.
    ///
    /// # Errors
    /// Refuses stale scene, foreign/entered slot or source owner mismatch, repeated
    /// actor reservation or unavailable finite storage. Failed spent reservations
    /// remain spent with the caller's same original supervisor and slot custody.
    pub(crate) fn reserve_actor_with_original_supervision(
        self: &Rc<Self>,
        supervisor: Rc<crate::node_qualification::PacketWorldHostSupervisor>,
        proposal: &ActivationRecord,
        limits: RuntimeLimits,
        slot: &dyn RuntimeCustodySlot,
    ) -> Result<Box<PacketCompleteExecutionActor>, QualificationError> {
        self.current()?;
        if proposal.owners.len() != 4
            || proposal.world_binding_hash != *self.authority.host_source().world()
            || limits.maximum_nodes != 4
            || limits.maximum_owners != 4
            || limits.maximum_operations == 0
            || limits.maximum_operations > 64
        {
            return Err(refused());
        }
        supervisor
            .authenticate_original_reserved_slot_data(proposal, limits, slot)
            .map_err(|_| refused())?;
        for source in &self.authority.roster().sources {
            let installed = source.installation();
            authenticate_proposed_owner(proposal, &installed.owner, &installed.binding)
                .map_err(|_| refused())?;
        }
        let host = self.authority.host_source().selection();
        authenticate_proposed_owner(proposal, &host.owner, &host.binding).map_err(|_| refused())?;
        if self.actor_reserved.replace(true) {
            return Err(refused());
        }
        let grants = reserve_grants(self.oracle.execution_schedule())?;
        let original_proposal = proposal.clone();
        self.current()?;
        supervisor
            .authenticate_original_reserved_slot_data(proposal, limits, slot)
            .map_err(|_| refused())?;
        Ok(Box::new(PacketCompleteExecutionActor {
            scene: Rc::clone(self),
            runtime: None,
            grants,
            next: 0,
            phase: Phase::Reserved,
            attachment_attempted: false,
            supervisor,
            supervision_proposal: Some(original_proposal),
            supervision_attempted: true,
            process: std::process::id(),
            thread: std::thread::current().id(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node_qualification::{
        PacketWorldHostSupervisor, packet_collection::connected::PacketConnectedGrant,
    };
    use crucible_engine::node_contract::OwnerIdentity;
    use crucible_node_format::{Phase as ContractPhase, U64, canonical};
    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn original_data()
    -> Result<(PacketConnectedSchedule, ActivationRecord), Box<dyn std::error::Error>> {
        let nodes = [
            Id::new("data-producer")?,
            Id::new("data-relay")?,
            Id::new("data-sink")?,
        ];
        let mut grants = Vec::new();
        for index in 0..schedule::GRANTS {
            let (member, operation, request) =
                schedule::row(index).ok_or("missing actual schedule row")?;
            grants.push(PacketConnectedGrant {
                node: nodes[member].clone(),
                operation: Id::new(operation)?,
                request,
            });
        }
        let selected = PacketConnectedSchedule {
            nodes,
            grants,
            cases: Vec::new(),
        };
        let owners = (0..4)
            .map(|index| {
                Ok(OwnerIdentity {
                    owner: Id::new(format!("data-owner-{index}"))?,
                    incarnation: Id::new(format!("data-birth-{index}"))?,
                    generation: U64::new(1),
                })
            })
            .collect::<Result<Vec<_>, crucible_node_format::ContractError>>()?;
        let proposal = ActivationRecord {
            generation: U64::new(1),
            activation_id: Id::new("data-activation")?,
            world_binding_hash: canonical::json_hash("data.fixed-actor", &"original")?,
            owners,
            boundary: Position::new(U64::new(0), U64::new(0), ContractPhase::BoundaryControl),
        };
        Ok((selected, proposal))
    }

    #[test]
    fn actual_thirteen_grants_and_independent_proposal_fit_exact_and_one_short() -> TestResult {
        let (mut selected, proposal) = original_data()?;
        // The clone bound uses actual source capacity; a clone need not retain spare slots.
        let mut node = String::from("data-relay");
        node.reserve(37);
        selected.nodes[1] = Id::new(node)?;
        for grant in &mut selected.grants {
            if grant.node.as_str() == "data-relay" {
                grant.node = selected.nodes[1].clone();
            }
        }
        let quote = PacketCompleteExecutionActor::original_construction_storage_data(
            &selected,
            &proposal,
            usize::MAX,
        )?;
        let grants = reserve_grants(&selected)?;
        let cloned = proposal.clone();
        let mut actual = Counter::new(usize::MAX);
        actual.add(size_of::<PacketCompleteExecutionActor>())?;
        actual.add(grants.capacity() * size_of::<Grant>())?;
        for grant in &grants {
            actual.charge(&grant.node)?;
            actual.charge(&grant.operation)?;
            actual.charge(&grant.input)?;
        }
        actual.charge(&cloned)?;
        assert!(quote.retained_requested_bytes >= actual.bytes());
        assert_eq!(grants.len(), 13);
        assert_eq!(
            grants.iter().filter(|grant| grant.input.is_some()).count(),
            11
        );
        assert_ne!(proposal.owners.as_ptr(), cloned.owners.as_ptr());
        let peak = quote.checked_peak_data()?;
        assert_eq!(
            PacketCompleteExecutionActor::original_construction_storage_data(
                &selected, &proposal, peak
            )?,
            quote
        );
        assert!(
            PacketCompleteExecutionActor::original_construction_storage_data(
                &selected,
                &proposal,
                peak - 1
            )
            .is_err()
        );
        selected.grants[0].operation = Id::new("foreign-data-operation")?;
        assert!(
            PacketCompleteExecutionActor::original_construction_storage_data(
                &selected,
                &proposal,
                usize::MAX
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn actual_reserved_supervisor_rejects_foreign_queue_and_changed_proposal() -> TestResult {
        let (_, proposal) = original_data()?;
        let limits = RuntimeLimits {
            maximum_nodes: 4,
            maximum_owners: 4,
            maximum_operations: 13,
            maximum_retained_outputs: 13,
        };
        let original = PacketWorldHostSupervisor::new_complete_original()?;
        let foreign = PacketWorldHostSupervisor::new_complete_original()?;
        let reserved = original.reserve_original(&proposal, limits)?;
        let _foreign_reserved = foreign.reserve_original(&proposal, limits)?;
        assert!(
            original
                .authenticate_original_reserved_slot_data(
                    &proposal,
                    limits,
                    reserved.runtime.as_ref()
                )
                .is_ok()
        );
        assert!(
            foreign
                .authenticate_original_reserved_slot_data(
                    &proposal,
                    limits,
                    reserved.runtime.as_ref()
                )
                .is_err()
        );
        let mut changed = proposal.clone();
        changed.activation_id = Id::new("foreign-data-activation")?;
        assert!(
            original
                .authenticate_original_reserved_slot_data(
                    &changed,
                    limits,
                    reserved.runtime.as_ref()
                )
                .is_err()
        );
        assert_eq!(original.observation().runtime_worlds, 1);
        assert_eq!(foreign.observation().runtime_worlds, 1);
        Ok(())
    }
}
