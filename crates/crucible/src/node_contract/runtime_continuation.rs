//! Complete runtime custody, bounded saved ledgers and fresh continuation rebinding.
//!
//! Saved records contain data only. Native handles and local permissions remain
//! in the owning runtime or its pre-reserved supervisory retention slot. Native
//! continuation proof is required before any restored permission is minted.

use std::{collections::BTreeMap, rc::Rc};

use crucible_node_contract::{ContentRef, HashRef, Id, Position, U64};
use serde::{Deserialize, Serialize};

use super::*;
use crate::node_contract::{ExactBoundaryPolicy, PublicationStatus, RetainedOperationObservation};
use crate::node_scheduling::{
    InputPayload, NativeInputAcknowledgement, SavedInputBatch, SavedReservation, SchedulingSnapshot,
};

/// Retains original complete world identity without serializing activation authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SavedRuntimeActivation {
    /// Names the source world generation.
    pub generation: U64,
    /// Names the source durable activation record.
    pub activation_id: Id,
    /// Binds the unchanged admitted implementation and model roster.
    pub world_binding_hash: HashRef,
    /// Enumerates source owners independently of fresh native incarnations.
    pub owners: Vec<OwnerIdentity>,
    /// Preserves the original activation boundary independently of capture time.
    pub boundary: Position,
}

impl From<&ActivationRecord> for SavedRuntimeActivation {
    fn from(record: &ActivationRecord) -> Self {
        Self {
            generation: record.generation,
            activation_id: record.activation_id.clone(),
            world_binding_hash: record.world_binding_hash.clone(),
            owners: record.owners.clone(),
            boundary: record.boundary,
        }
    }
}

/// Retains one authoritative owner's complete reservation and lifecycle.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SavedRuntimeOwner {
    /// Binds the original owner incarnation whose native state was captured.
    pub identity: OwnerIdentity,
    /// Preserves lifecycle without inferring physical suspension.
    pub lifecycle: Lifecycle,
    /// Retains the original mutation or acknowledgement reservation, if any.
    #[serde(deserialize_with = "required_nullable")]
    pub operation: Option<Id>,
    /// Enumerates all execution and capture participation domains.
    pub domains: Vec<Id>,
}

/// Retains original operation completion and native acknowledgement knowledge.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum SavedRuntimeResult {
    /// Preserves an outstanding original native operation without resubmitting it.
    Pending,
    /// Retains validated completion awaiting canonical commit or native ACK.
    Complete(OperationOutcome),
    /// Retains classified original failure without asserting rollback.
    Failed(OperationFailure),
    /// Retains validated completion whose native custody acknowledgement completed.
    Acknowledged(OperationOutcome),
}

/// Retains an original coordinator commitment without serializing its local permission.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SavedSchedulingCommit {
    /// Names the original logical component.
    pub node: Id,
    /// Names the original operation without assigning a replacement identity.
    pub operation: Id,
    /// Preserves the exact canonically committed native output inventory.
    pub retained_outputs: Vec<Id>,
}

/// Retains one original operation's complete runtime-ledger entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SavedRuntimeOperation {
    /// Retains the original operation identity.
    pub operation: Id,
    /// Retains the original logical component and complete source owner roster.
    pub route: NodeRoute,
    /// Preserves the original permission without widening its semantic ceiling.
    pub request: OperationRequest,
    /// Refers to the exact original staged input batch, if present.
    #[serde(deserialize_with = "required_nullable")]
    pub input_batch: Option<Id>,
    /// Retains native completion and acknowledgement knowledge.
    pub result: SavedRuntimeResult,
    /// Retains original quantum-close submission knowledge.
    #[serde(deserialize_with = "required_nullable")]
    pub close_submission: Option<Submission>,
    /// Retains uncertainty of the original dispatch.
    #[serde(deserialize_with = "required_nullable")]
    pub submission_effects: Option<EffectKnowledge>,
    /// Retains already committed coordinator outputs for ACK-only continuation.
    #[serde(deserialize_with = "required_nullable")]
    pub scheduling_commit: Option<SavedSchedulingCommit>,
}

/// Retains the complete immutable input batch independently of live authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SavedRuntimeInput {
    /// Names the target logical component.
    pub node: Id,
    /// Retains the original distinct native staging operation identity.
    pub stage_operation: Id,
    /// Retains the immutable original batch identity.
    pub batch: Id,
    /// Enumerates the original native owner incarnation roster.
    pub owners: Vec<OwnerIdentity>,
    /// Preserves the original exclusive staged input cut.
    pub cutoff: Position,
    /// Binds the original complete ordered delivery inventory.
    pub inventory: ContentRef,
    /// Retains every original input and its publication lineage.
    pub deliveries: Vec<crate::node_scheduling::event::Delivery>,
    /// Retains readable authenticated bytes throughout native input custody.
    pub payloads: Vec<InputPayload>,
    /// Retains original native staging evidence, when received.
    #[serde(deserialize_with = "required_nullable")]
    pub acknowledgement: Option<NativeInputAcknowledgement>,
    /// Retains original staging failure and effect knowledge.
    #[serde(deserialize_with = "required_nullable")]
    pub failure: Option<OperationFailure>,
    /// Records completed transfer of original staging custody to the coordinator.
    pub committed: bool,
    /// Records already committed coordinator staging evidence independently of release.
    pub coordinator_committed: bool,
}

/// Preserves complete runtime future state without serializing any native permission.
///
/// The selected host snapshot schema is versioned independently of native state
/// formats. Its exact bytes belong to the authenticated coordinator capture.
///
/// ```json
/// {"schema_version":1,"capture_ordinal":"7","operations":[],"inputs":[]}
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeSnapshot {
    /// Selects the complete runtime-ledger snapshot schema.
    #[serde(deserialize_with = "crucible_node_contract::deserialize_version")]
    pub schema_version: u16,
    /// Retains the original complete durable activation record as data only.
    pub source_activation: SavedRuntimeActivation,
    /// Binds the unchanged coordinator capture cut.
    pub capture_cut: Position,
    /// Binds the unchanged original coordinator event ordinal.
    pub capture_ordinal: U64,
    /// Enumerates every authoritative owner in canonical identity order.
    pub owners: Vec<SavedRuntimeOwner>,
    /// Enumerates all original operations, including failed and acknowledged entries.
    pub operations: Vec<SavedRuntimeOperation>,
    /// Enumerates all native input staging entries and preserved immutable buffers.
    pub inputs: Vec<SavedRuntimeInput>,
}

/// Authenticates complete native runtime-ledger continuation at an unchanged cut.
pub trait NativeRuntimeContinuationVerifier {
    /// Verifies native restored operation, ACK and staged input custody under closed gates.
    ///
    /// This trusted installed adapter must prove the exact source lineage,
    /// unchanged owner state, fresh target incarnations, preserved pending input
    /// buffers, and authentic reattachment of every original operation. Completed
    /// work must never be submitted again. Already committed outputs may perform
    /// only the original idempotent native ACK. Saved native permissions cannot
    /// authorize restored processes or transports.
    ///
    /// # Errors
    /// Rejects unavailable original custody, changed native ledger/schema, moved
    /// cuts, incomplete buffers, inadequate isolation or unsupported rebinding.
    fn verify_runtime_continuation(
        &mut self,
        snapshot: &RuntimeSnapshot,
        scheduling: &SchedulingSnapshot,
        target: &ActivationRecord,
    ) -> Result<NativeRuntimeContinuationEvidence, RuntimeError>;
}

/// Reports authentic fresh native evidence for unchanged original continuation.
#[derive(Clone, Debug)]
pub struct NativeRuntimeContinuationEvidence {
    /// Binds accepted complete native operation and coordinator lineage proof.
    pub proof: ContentRef,
    /// Reattests actual fresh native custody of every previously staged input batch.
    ///
    /// Entries retain original semantic identities, cuts and inventories while
    /// binding fresh owner incarnations and authentic fresh native proof bytes.
    pub input_acknowledgements: Vec<NativeInputAcknowledgement>,
}

/// Carries actual locally owned host serialization with immutable native evidence.
///
/// Construction is restricted to installed host adapters within this crate.
/// External provider claims cannot mint this capability for the host archive
/// signer. It grants no execution permission or cross-backend equivalence.
pub struct HostNativeCapture {
    pub(crate) node: Id,
    pub(crate) profile: Id,
    pub(crate) state: InputPayload,
    pub(crate) evidence: Vec<InputPayload>,
}

impl HostNativeCapture {
    /// Names the actual logical host node whose unchanged state was read.
    pub fn node(&self) -> &Id {
        &self.node
    }

    /// Returns the actual selected native host codec profile.
    pub fn profile(&self) -> &Id {
        &self.profile
    }

    /// Borrows the complete existing native host serializer output.
    pub fn state(&self) -> &InputPayload {
        &self.state
    }

    /// Borrows retained original immutable native receipt and payload bodies.
    pub fn evidence(&self) -> &[InputPayload] {
        &self.evidence
    }
}

/// Seals complete native continuation proof without granting execution permission.
pub struct VerifiedNativeContinuation {
    target: ActivationRecord,
    scheduler_hash: HashRef,
    reservations: Vec<SavedReservation>,
    input_batches: Vec<SavedInputBatch>,
    input_acknowledgements: Vec<NativeInputAcknowledgement>,
    proof: ContentRef,
}

impl VerifiedNativeContinuation {
    /// Returns the exact fresh generation authenticated by native continuation proof.
    pub fn target_activation(&self) -> &ActivationRecord {
        &self.target
    }

    /// Returns the authenticated complete source scheduler continuation identity.
    pub fn source_scheduler_hash(&self) -> &HashRef {
        &self.scheduler_hash
    }

    /// Borrows the exact authenticated original scheduler reservation inventory.
    pub fn scheduler_reservations(&self) -> &[SavedReservation] {
        &self.reservations
    }

    /// Borrows the exact authenticated original scheduler input custody inventory.
    pub fn scheduler_input_batches(&self) -> &[SavedInputBatch] {
        &self.input_batches
    }

    /// Borrows authentic fresh staging acknowledgements without reissuing input.
    pub fn restored_input_acknowledgements(&self) -> &[NativeInputAcknowledgement] {
        &self.input_acknowledgements
    }

    /// Returns accepted native continuation evidence bound to the original cut.
    pub fn proof(&self) -> &ContentRef {
        &self.proof
    }
}

/// Provides a pre-reserved owning mailbox for complete runtime supervision.
pub trait RuntimeCustodySlot {
    /// Checks that the reserved capacity belongs to this exact world and policy.
    ///
    /// # Errors
    /// Rejects a different activation record or resource policy before runtime formation.
    fn validate_world(
        &self,
        activation: &ActivationRecord,
        limits: RuntimeLimits,
    ) -> Result<(), RuntimeError>;

    /// Transfers every native handle and coordinator obligation without allocation failure.
    ///
    /// The installed supervisor must retain this exact complete custody beyond
    /// the slot's lifetime until authentic reclamation. It must preserve original
    /// generation/publication knowledge and original ACK-only commitments; it
    /// may not drop the capsule, release only native handles, or manufacture a
    /// replacement world. Capacity is reserved before runtime construction.
    fn retain(self: Box<Self>, custody: WholeRuntimeCustody);
}

/// Reserves authentic supervisory custody before a native runtime can exist.
pub trait RuntimeCustodySupervisor {
    /// Reserves one owning retention slot for the complete original runtime.
    ///
    /// # Errors
    /// Refuses unavailable custody, thread-affinity mismatch or resource limits
    /// before execution authority can be established.
    fn reserve_world(
        &self,
        activation: &ActivationRecord,
        limits: RuntimeLimits,
    ) -> Result<Box<dyn RuntimeCustodySlot>, RuntimeError>;
}

/// Retains an inactive native resource capsule and its complete preservation source.
pub trait PreparedNativeResources {
    /// Preserves the exact proposed generation and durable publication knowledge.
    fn quarantine_resources(
        &mut self,
        activation: &ActivationRecord,
        publication: Option<PublicationStatus>,
    );

    /// Polls authentic complete reclamation while retaining the original source.
    ///
    /// # Errors
    /// Returns native cleanup failure without dropping resources or source state.
    fn poll_reclamation(
        &mut self,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), OperationFailure>>;
}

/// Retains complete native, input, operation and coordinator state under supervision.
#[must_use = "complete runtime custody must survive until authentic native reclamation"]
pub struct WholeRuntimeCustody {
    authority: Rc<()>,
    nodes: BTreeMap<Id, Box<dyn SimulationNode>>,
    rejected_nodes: Vec<Box<dyn SimulationNode>>,
    rejected_reclamation: std::collections::VecDeque<(usize, OwnerIdentity)>,
    snapshots: BTreeMap<Id, NodeSnapshot>,
    owners: BTreeMap<Id, OwnerCustody>,
    operations: BTreeMap<Id, RetainedOperation>,
    input_batches: BTreeMap<Id, inputs::RetainedInput>,
    scheduler: Option<crate::node_scheduling::CausalScheduler>,
    prepared: Option<Box<dyn PreparedNativeResources>>,
    activation: ActivationRecord,
    publication: Option<PublicationStatus>,
    limits: RuntimeLimits,
    reclamation_cursor: Option<Id>,
}

impl WholeRuntimeCustody {
    /// Retains an inactive resource capsule in the same finite owning supervisor.
    pub fn from_prepared_resources(
        prepared: Box<dyn PreparedNativeResources>,
        activation: ActivationRecord,
        publication: Option<PublicationStatus>,
        limits: RuntimeLimits,
    ) -> Self {
        Self {
            authority: Rc::new(()),
            nodes: BTreeMap::new(),
            rejected_nodes: Vec::new(),
            rejected_reclamation: Default::default(),
            snapshots: BTreeMap::new(),
            owners: BTreeMap::new(),
            operations: BTreeMap::new(),
            input_batches: BTreeMap::new(),
            scheduler: None,
            prepared: Some(prepared),
            activation,
            publication,
            limits,
            reclamation_cursor: None,
        }
    }

    /// Reports whether a complete inactive native capsule remains owned.
    pub fn has_prepared_resources(&self) -> bool {
        self.prepared.is_some()
    }

    /// Returns the exact original complete world generation retained for supervision.
    pub fn activation(&self) -> &ActivationRecord {
        &self.activation
    }

    /// Reports actual durable publication knowledge, or no attempted publication.
    pub fn publication_status(&self) -> Option<PublicationStatus> {
        self.publication
    }

    /// Returns the count of retained original native handles.
    pub fn native_handle_count(&self) -> usize {
        self.nodes.len().saturating_add(self.rejected_nodes.len())
    }

    /// Returns the complete number of preserved original operation entries.
    pub fn operation_count(&self) -> usize {
        self.operations.len()
    }

    /// Returns the complete number of preserved native input staging entries.
    pub fn input_batch_count(&self) -> usize {
        self.input_batches.len()
    }

    /// Returns the original bounded custody policy retained with the complete world.
    pub fn limits(&self) -> RuntimeLimits {
        self.limits
    }

    /// Borrows immutable actual binding evidence without exposing native mutation.
    pub fn node_binding(&self, node: &Id) -> Option<&crucible_node_contract::NodeBinding> {
        self.snapshots.get(node).map(|snapshot| &snapshot.binding)
    }

    /// Inspects an authentic original token's retained effects without continuing it.
    pub fn operation(&self, token: &OperationToken) -> Option<RetainedOperationObservation> {
        if !Rc::ptr_eq(&self.authority, &token.authority) {
            return None;
        }
        self.operations
            .get(token.operation())
            .map(|operation| match &operation.result {
                RetainedResult::Pending => RetainedOperationObservation::Pending {
                    effects: operation.submission_effects.clone(),
                    close_submission: operation.close_submission.clone(),
                },
                RetainedResult::Complete(outcome) => RetainedOperationObservation::Complete {
                    outcome: Box::new(outcome.clone()),
                    acknowledged: false,
                },
                RetainedResult::Acknowledged(outcome) => RetainedOperationObservation::Complete {
                    outcome: Box::new(outcome.clone()),
                    acknowledged: true,
                },
                RetainedResult::Failed(failure) => {
                    RetainedOperationObservation::Failed(failure.clone())
                }
            })
    }

    /// Borrows the preserved scheduler record for separately authenticated capture evidence.
    ///
    /// # Errors
    /// Rejects an absent scheduler or an unrepresentable saved permission.
    pub fn scheduler_snapshot(
        &self,
        cut: Position,
        ordinal: U64,
    ) -> Result<SchedulingSnapshot, RuntimeError> {
        self.scheduler
            .as_ref()
            .ok_or(RuntimeError::NotActivated)?
            .snapshot(cut, ordinal)
            .map_err(|error| RuntimeError::SchedulerRefused(error.to_string()))
    }

    /// Polls at most one owner's authentic native reclamation under complete custody.
    ///
    /// # Errors
    /// Rejects unavailable native handles, thread affinity, failed cleanup or
    /// unqualified reclamation proof; failure retains all original ledger state.
    pub fn poll_reclamation(
        &mut self,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), super::RuntimePollFailure>> {
        if let Some(prepared) = &mut self.prepared {
            return prepared
                .poll_reclamation(context)
                .map_err(super::RuntimePollFailure::Native);
        }
        if !self.rejected_nodes.is_empty() {
            if self
                .rejected_nodes
                .iter()
                .any(|node| node.route().owners.is_empty())
            {
                return Poll::Ready(Err(super::RuntimePollFailure::Admission(
                    RuntimeError::InvalidRoute,
                )));
            }
            let Some((index, identity)) = self.rejected_reclamation.pop_front() else {
                return if self
                    .rejected_nodes
                    .iter()
                    .any(|node| node.route().owners.is_empty())
                {
                    Poll::Ready(Err(super::RuntimePollFailure::Admission(
                        RuntimeError::InvalidRoute,
                    )))
                } else {
                    Poll::Ready(Ok(()))
                };
            };
            let Some(node) = self.rejected_nodes.get_mut(index) else {
                self.rejected_reclamation.push_front((index, identity));
                return Poll::Ready(Err(super::RuntimePollFailure::Admission(
                    RuntimeError::InvalidRoute,
                )));
            };
            if !node.thread_affinity().permits_current_thread() {
                self.rejected_reclamation.push_front((index, identity));
                return Poll::Ready(Err(super::RuntimePollFailure::Admission(
                    RuntimeError::ThreadAffinity,
                )));
            }
            let result = node.poll_reclamation(&identity, context);
            match result {
                Poll::Ready(Ok(receipt))
                    if receipt.owner == identity && node.validate_reclamation(&receipt).is_ok() =>
                {
                    if self.rejected_reclamation.is_empty() {
                        return Poll::Ready(Ok(()));
                    }
                    context.waker().wake_by_ref();
                    return Poll::Pending;
                }
                other => {
                    self.rejected_reclamation.push_back((index, identity));
                    return match other {
                        Poll::Pending => Poll::Pending,
                        Poll::Ready(Err(error)) => {
                            Poll::Ready(Err(super::RuntimePollFailure::Native(error)))
                        }
                        Poll::Ready(Ok(_)) => Poll::Ready(Err(
                            super::RuntimePollFailure::Admission(RuntimeError::InvalidReceipt),
                        )),
                    };
                }
            }
        }
        let next = self
            .owners
            .iter()
            .filter(|(_, owner)| owner.lifecycle != Lifecycle::Released)
            .find(|(id, _)| {
                self.reclamation_cursor
                    .as_ref()
                    .is_none_or(|previous| *id > previous)
            })
            .or_else(|| {
                self.owners
                    .iter()
                    .find(|(_, owner)| owner.lifecycle != Lifecycle::Released)
            })
            .map(|(_, owner)| owner.identity.clone());
        let Some(identity) = next else {
            return Poll::Ready(Ok(()));
        };
        self.reclamation_cursor = Some(identity.owner.clone());
        let Some(node) = self
            .nodes
            .values_mut()
            .chain(self.rejected_nodes.iter_mut())
            .find(|node| node.route().owners.contains(&identity))
        else {
            return Poll::Ready(Err(super::RuntimePollFailure::Admission(
                RuntimeError::InvalidRoute,
            )));
        };
        if !node.thread_affinity().permits_current_thread() {
            return Poll::Ready(Err(super::RuntimePollFailure::Admission(
                RuntimeError::ThreadAffinity,
            )));
        }
        match node.poll_reclamation(&identity, context) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(failure)) => {
                Poll::Ready(Err(super::RuntimePollFailure::Native(failure)))
            }
            Poll::Ready(Ok(receipt)) => {
                if receipt.owner != identity || node.validate_reclamation(&receipt).is_err() {
                    return Poll::Ready(Err(super::RuntimePollFailure::Admission(
                        RuntimeError::InvalidReceipt,
                    )));
                }
                if let Some(owner) = self.owners.get_mut(&identity.owner) {
                    owner.lifecycle = Lifecycle::Released;
                }
                if self
                    .owners
                    .values()
                    .all(|owner| owner.lifecycle == Lifecycle::Released)
                {
                    Poll::Ready(Ok(()))
                } else {
                    context.waker().wake_by_ref();
                    Poll::Pending
                }
            }
        }
    }

    pub(crate) fn from_prepared(
        mut nodes: Vec<Box<dyn SimulationNode>>,
        activation: ActivationRecord,
        limits: RuntimeLimits,
    ) -> Self {
        for node in &mut nodes {
            node.quarantine_resources();
        }
        let rejected_reclamation = nodes
            .iter()
            .enumerate()
            .flat_map(|(index, node)| {
                node.route()
                    .owners
                    .iter()
                    .cloned()
                    .map(move |owner| (index, owner))
            })
            .collect();
        let owners = activation
            .owners
            .iter()
            .cloned()
            .map(|identity| {
                (
                    identity.owner.clone(),
                    OwnerCustody {
                        identity,
                        lifecycle: Lifecycle::Quarantined,
                        operation: None,
                        domains: Default::default(),
                    },
                )
            })
            .collect();
        Self {
            authority: Rc::new(()),
            nodes: BTreeMap::new(),
            rejected_nodes: nodes,
            rejected_reclamation,
            snapshots: BTreeMap::new(),
            owners,
            operations: BTreeMap::new(),
            input_batches: BTreeMap::new(),
            scheduler: None,
            prepared: None,
            activation,
            publication: None,
            limits,
            reclamation_cursor: None,
        }
    }
}

impl Drop for WholeRuntimeCustody {
    fn drop(&mut self) {
        // Installed supervisors keep this complete capsule until reclamation.
        // Native guard transfer remains mandatory if a supervisor shuts down.
        for node in self.nodes.values_mut() {
            node.quarantine_resources();
        }
        for node in &mut self.rejected_nodes {
            node.quarantine_resources();
        }
        if let Some(prepared) = &mut self.prepared {
            prepared.quarantine_resources(&self.activation, self.publication);
        }
    }
}

impl NodeRuntime {
    pub(super) fn transfer_whole_custody(&mut self) {
        let Some(slot) = self.custody_slot.take() else {
            return;
        };
        for node in self.nodes.values_mut() {
            node.quarantine_resources();
        }
        let custody = WholeRuntimeCustody {
            authority: Rc::clone(&self.authority),
            nodes: std::mem::take(&mut self.nodes),
            rejected_nodes: Vec::new(),
            rejected_reclamation: Default::default(),
            snapshots: std::mem::take(&mut self.snapshots),
            owners: std::mem::take(&mut self.owners),
            operations: std::mem::take(&mut self.operations),
            input_batches: std::mem::take(&mut self.input_batches),
            scheduler: self.scheduler.take(),
            prepared: None,
            activation: self.barrier.record().clone(),
            publication: self.barrier.publication_status_or_not_attempted(),
            limits: self.limits,
            reclamation_cursor: None,
        };
        slot.retain(custody);
    }
}

#[cfg(test)]
thread_local! {
    static TEST_CUSTODIES: std::cell::RefCell<Vec<WholeRuntimeCustody>> = const {
        std::cell::RefCell::new(Vec::new())
    };
}

#[cfg(test)]
struct TestCustodySlot;

#[cfg(test)]
impl RuntimeCustodySlot for TestCustodySlot {
    fn validate_world(&self, _: &ActivationRecord, _: RuntimeLimits) -> Result<(), RuntimeError> {
        Ok(())
    }

    fn retain(self: Box<Self>, custody: WholeRuntimeCustody) {
        TEST_CUSTODIES.with(|custodies| custodies.borrow_mut().push(custody));
    }
}

/// Returns model-only owning custody retained for the duration of the test thread.
#[cfg(test)]
pub(crate) fn test_custody_slot() -> Box<dyn RuntimeCustodySlot> {
    Box::new(TestCustodySlot)
}

#[path = "runtime_continuation/restore.rs"]
mod restore;

pub use restore::PreparedRuntimeRestore;

#[path = "runtime_continuation/snapshot.rs"]
mod snapshot;

#[path = "runtime_continuation/host_capture.rs"]
mod host_capture;

#[path = "runtime_continuation/supervisor.rs"]
mod supervisor;

pub use supervisor::RuntimeCustodyQueue;

fn required_nullable<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}
