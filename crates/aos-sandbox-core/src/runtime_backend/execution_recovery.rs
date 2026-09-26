//! Crash recovery for durably admitted and issued execution effects.

use sha2::{Digest as _, Sha256};

use crate::{ObjectDigest, ObservationSequence, PayloadBootId};

use super::{
    BackendExecutionInspectionV1, DurableExecutionEffectV1, EffectPhaseV1,
    RuntimeHandleCommitmentV1,
};

/// Stores a protected complete inventory for one exact runtime generation.
///
/// The constructor requires protected source provenance and derives the
/// complete-inventory commitment internally. An ordinary scalar "not found"
/// result cannot construct absence through a projection API.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackendExecutionInventoryV1 {
    authority_binding: ObjectDigest,
    runtime: RuntimeHandleCommitmentV1,
    payload_boot_id: PayloadBootId,
    inventory_generation: u64,
    sequence_floor: ObservationSequence,
    inventory_commitment: ObjectDigest,
    provenance_commitment: ObjectDigest,
    entries: Vec<BackendExecutionInspectionV1>,
}

impl BackendExecutionInventoryV1 {
    fn from_loaded(
        authority_binding: ObjectDigest,
        runtime: RuntimeHandleCommitmentV1,
        payload_boot_id: PayloadBootId,
        inventory_generation: u64,
        sequence_floor: ObservationSequence,
        entries: Vec<BackendExecutionInspectionV1>,
        provenance_commitment: ObjectDigest,
    ) -> Result<Self, ExecutionRecoveryError> {
        if authority_binding.as_bytes() == &[0; 32]
            || inventory_generation == 0
            || sequence_floor.get() == 0
            || provenance_commitment.as_bytes() == &[0; 32]
            || entries.len() > 4_096
        {
            return Err(ExecutionRecoveryError::InvalidInventory);
        }
        let mut previous = None;
        for entry in &entries {
            if entry.authority_binding() != authority_binding
                || entry.runtime() != &runtime
                || entry.payload_boot_id() != payload_boot_id
                || entry.sequence() < sequence_floor
                || previous.is_some_and(|execution| execution >= entry.execution())
            {
                return Err(ExecutionRecoveryError::InvalidInventory);
            }
            previous = Some(entry.execution());
        }
        let inventory_commitment = inventory_commitment(
            authority_binding,
            &runtime,
            payload_boot_id,
            inventory_generation,
            sequence_floor,
            &entries,
        );
        Ok(Self {
            authority_binding,
            runtime,
            payload_boot_id,
            inventory_generation,
            sequence_floor,
            inventory_commitment,
            provenance_commitment,
            entries,
        })
    }

    /// Returns the exact protected evidence-verifier authority binding.
    #[must_use]
    pub const fn authority_binding(&self) -> ObjectDigest {
        self.authority_binding
    }

    /// Returns the exact runtime currentness binding.
    #[must_use]
    pub const fn runtime(&self) -> &RuntimeHandleCommitmentV1 {
        &self.runtime
    }

    /// Returns the exact payload boot covered by the complete inventory.
    #[must_use]
    pub const fn payload_boot_id(&self) -> PayloadBootId {
        self.payload_boot_id
    }

    /// Returns the protected inventory generation.
    #[must_use]
    pub const fn inventory_generation(&self) -> u64 {
        self.inventory_generation
    }

    /// Returns the minimum observation sequence represented by the snapshot.
    #[must_use]
    pub const fn sequence_floor(&self) -> ObservationSequence {
        self.sequence_floor
    }

    /// Returns the complete inventory commitment.
    #[must_use]
    pub const fn inventory_commitment(&self) -> ObjectDigest {
        self.inventory_commitment
    }

    /// Returns the protected adapter provenance commitment.
    #[must_use]
    pub const fn provenance_commitment(&self) -> ObjectDigest {
        self.provenance_commitment
    }

    /// Returns exact entries in strict execution-identity order.
    #[must_use]
    pub fn entries(&self) -> &[BackendExecutionInspectionV1] {
        &self.entries
    }

    /// Derives presence by searching the complete canonical inventory.
    ///
    /// The returned value is nonconstructible outside this module and remains
    /// bound to this inventory's exact entries. It is a read-only diagnostic;
    /// recovery should normally call [`reconcile_execution_effect`] directly.
    #[must_use]
    pub fn presence_for(&self, effect: &DurableExecutionEffectV1) -> BackendExecutionPresenceV1 {
        match self
            .entries
            .binary_search_by_key(&effect.admission().execution(), |entry| entry.execution())
        {
            Ok(index) => {
                let observation = self.entries[index];
                if observation.operation() == effect.issue().idempotency().operation()
                    && observation.operation_sequence() == effect.issue().sequence()
                    && observation.effect_request_digest()
                        == effect.issue().idempotency().request_digest()
                    && observation.specification_digest()
                        == effect.admission().specification_digest()
                    && observation.admission_commitment()
                        == effect.admission().admission_commitment()
                    && observation.runtime() == effect.admission().currentness().runtime()
                    && observation.payload_boot_id()
                        == effect.admission().currentness().payload_boot_id()
                {
                    BackendExecutionPresenceV1 {
                        kind: PresenceKind::Exact(observation),
                    }
                } else {
                    BackendExecutionPresenceV1 {
                        kind: PresenceKind::Conflict,
                    }
                }
            }
            Err(_) => BackendExecutionPresenceV1 {
                kind: PresenceKind::Absent,
            },
        }
    }
}

/// Carries scalar complete-inventory fields from an authenticated loader.
pub struct BackendExecutionInventoryInputV1 {
    /// Expected protected evidence-verifier authority binding.
    pub authority_binding: ObjectDigest,
    /// Exact runtime handle commitment.
    pub runtime: RuntimeHandleCommitmentV1,
    /// Exact payload boot identity.
    pub payload_boot_id: PayloadBootId,
    /// Protected inventory generation.
    pub inventory_generation: u64,
    /// Minimum observation sequence covered.
    pub sequence_floor: ObservationSequence,
    /// Complete bounded execution entries.
    pub entries: Vec<BackendExecutionInspectionV1>,
    /// Protected adapter provenance commitment.
    pub provenance_commitment: ObjectDigest,
}

/// Authenticates complete inventory before it can become absence evidence.
///
/// This sealed TCB interface cannot be implemented by downstream callers.
#[allow(private_bounds)]
pub trait BackendExecutionInventoryLoaderV1:
    super::sealed::BackendExecutionInventoryLoaderV1
{
    /// Loader-specific storage or authentication error.
    type Error: From<ExecutionRecoveryError>;

    /// Authenticates and returns complete scalar inventory fields.
    ///
    /// # Errors
    ///
    /// Returns the loader error for incomplete, stale, unauthenticated, or
    /// unavailable protected inventory.
    fn load_authenticated_inventory(
        &mut self,
    ) -> Result<BackendExecutionInventoryInputV1, Self::Error>;
}

/// Mints complete inventory evidence through an authenticated loader.
///
/// # Errors
///
/// Returns the loader error for failed authentication or invalid loaded fields.
pub fn load_backend_execution_inventory_v1<L: BackendExecutionInventoryLoaderV1>(
    loader: &mut L,
) -> Result<BackendExecutionInventoryV1, L::Error> {
    let input = loader.load_authenticated_inventory()?;
    BackendExecutionInventoryV1::from_loaded(
        input.authority_binding,
        input.runtime,
        input.payload_boot_id,
        input.inventory_generation,
        input.sequence_floor,
        input.entries,
        input.provenance_commitment,
    )
    .map_err(Into::into)
}

/// Classifies exact execution presence inside a complete authenticated inventory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BackendExecutionPresenceV1 {
    kind: PresenceKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PresenceKind {
    Exact(BackendExecutionInspectionV1),
    Absent,
    Conflict,
}

impl BackendExecutionPresenceV1 {
    /// Returns the exact matching observation, when present and unambiguous.
    #[must_use]
    pub const fn exact(&self) -> Option<BackendExecutionInspectionV1> {
        match self.kind {
            PresenceKind::Exact(observation) => Some(observation),
            PresenceKind::Absent | PresenceKind::Conflict => None,
        }
    }

    /// Reports complete authenticated absence of the target execution.
    #[must_use]
    pub const fn is_absent(&self) -> bool {
        matches!(self.kind, PresenceKind::Absent)
    }

    /// Reports an entry whose exact identity has conflicting bindings.
    #[must_use]
    pub const fn is_conflict(&self) -> bool {
        matches!(self.kind, PresenceKind::Conflict)
    }
}

/// Directs the journal owner through one closed recovery transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionRecoveryActionV1 {
    /// The Pending record may atomically reserve its first backend issuance.
    ReserveInitialIssue,
    /// Exact backend evidence can be committed as the recovered outcome.
    CommitObserved(BackendExecutionInspectionV1),
    /// Complete authenticated absence makes the execution terminally lost.
    CommitLost {
        /// Complete inventory commitment supporting terminal absence.
        inventory_commitment: ObjectDigest,
        /// Protected adapter provenance for the exact complete inventory.
        provenance_commitment: ObjectDigest,
        /// Protected inventory generation supporting the absence conclusion.
        inventory_generation: u64,
        /// Minimum backend observation sequence represented by the inventory.
        sequence_floor: ObservationSequence,
    },
    /// The effect is already complete and should return its retained response.
    ReturnExactReplay,
    /// Conflicting or stale evidence requires operator-visible fail-closed state.
    Quarantine,
}

/// Directs recovery before any live backend inventory is requested.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionRecoveryPreflightV1 {
    /// The durable Complete record is an exact replay and needs no inventory.
    ReturnExactReplay,
    /// Pending, Issued, or Indeterminate state requires complete inventory.
    RequiresInventory,
}

/// Resolves durable exact replay before any live inventory call.
#[must_use]
pub fn preflight_execution_recovery(
    effect: &DurableExecutionEffectV1,
) -> ExecutionRecoveryPreflightV1 {
    if effect.phase() == EffectPhaseV1::Complete {
        ExecutionRecoveryPreflightV1::ReturnExactReplay
    } else {
        ExecutionRecoveryPreflightV1::RequiresInventory
    }
}

/// Reconciles one durable effect with a complete authenticated backend inventory.
///
/// This function is pure. The owning journal must commit the selected action by
/// compare-and-swap before revealing a result or invoking another effect.
/// `AuthorizeExecution` is never reissued after Issued/Indeterminate absence:
/// the command may have run and disappeared before inventory, so recovery marks
/// it Lost rather than risking duplicate execution.
///
/// # Errors
///
/// Returns [`ExecutionRecoveryError`] when inventory belongs to another runtime,
/// is older than an exact observation, or contradicts execution bindings.
pub fn reconcile_execution_effect(
    effect: &DurableExecutionEffectV1,
    inventory: &BackendExecutionInventoryV1,
) -> Result<ExecutionRecoveryActionV1, ExecutionRecoveryError> {
    if preflight_execution_recovery(effect) == ExecutionRecoveryPreflightV1::ReturnExactReplay {
        return Ok(ExecutionRecoveryActionV1::ReturnExactReplay);
    }
    let expected_runtime = effect.admission().currentness().runtime();
    if effect.admission().currentness().authority_context() != inventory.authority_binding()
        || expected_runtime != inventory.runtime()
        || effect.admission().currentness().payload_boot_id() != inventory.payload_boot_id()
    {
        return Err(ExecutionRecoveryError::CurrentnessMismatch);
    }

    let presence = inventory.presence_for(effect);
    match effect.phase() {
        EffectPhaseV1::Complete => return Ok(ExecutionRecoveryActionV1::ReturnExactReplay),
        EffectPhaseV1::Pending => {
            if !presence.is_absent() {
                return Ok(ExecutionRecoveryActionV1::Quarantine);
            }
            return Ok(ExecutionRecoveryActionV1::ReserveInitialIssue);
        }
        EffectPhaseV1::Issued | EffectPhaseV1::Indeterminate => {}
    }

    match presence.kind {
        PresenceKind::Exact(observation) => {
            if observation.execution() != effect.admission().execution()
                || observation.authority_binding() != inventory.authority_binding()
                || observation.operation() != effect.issue().idempotency().operation()
                || observation.operation_sequence() != effect.issue().sequence()
                || observation.effect_request_digest()
                    != effect.issue().idempotency().request_digest()
                || observation.specification_digest() != effect.admission().specification_digest()
                || observation.admission_commitment() != effect.admission().admission_commitment()
                || observation.runtime() != expected_runtime
                || observation.payload_boot_id()
                    != effect.admission().currentness().payload_boot_id()
            {
                return Err(ExecutionRecoveryError::ObservationMismatch);
            }
            if observation.sequence() < inventory.sequence_floor() {
                return Err(ExecutionRecoveryError::StaleObservation);
            }
            Ok(ExecutionRecoveryActionV1::CommitObserved(observation))
        }
        PresenceKind::Absent => Ok(ExecutionRecoveryActionV1::CommitLost {
            // Mutation absence cannot distinguish "never began" from a
            // command or control effect that completed and was collected.
            inventory_commitment: inventory.inventory_commitment(),
            provenance_commitment: inventory.provenance_commitment(),
            inventory_generation: inventory.inventory_generation(),
            sequence_floor: inventory.sequence_floor(),
        }),
        PresenceKind::Conflict => Ok(ExecutionRecoveryActionV1::Quarantine),
    }
}

fn inventory_commitment(
    authority_binding: ObjectDigest,
    runtime: &RuntimeHandleCommitmentV1,
    payload_boot_id: PayloadBootId,
    inventory_generation: u64,
    sequence_floor: ObservationSequence,
    entries: &[BackendExecutionInspectionV1],
) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(b"aos-sandbox-backend-execution-inventory-v1\0");
    digest.update(authority_binding.as_bytes());
    let currentness = runtime.currentness();
    digest.update(currentness.sandbox().as_bytes());
    digest.update(currentness.incarnation().as_bytes());
    digest.update(currentness.node().as_bytes());
    digest.update(currentness.assignment_epoch().get().to_be_bytes());
    digest.update(currentness.assignment_digest().as_bytes());
    digest.update(currentness.desired_generation().get().to_be_bytes());
    digest.update(currentness.namespace_generation().get().to_be_bytes());
    digest.update(runtime.plan_commitment().as_bytes());
    digest.update(runtime.handle().as_bytes());
    digest.update(payload_boot_id.as_bytes());
    digest.update(inventory_generation.to_be_bytes());
    digest.update(sequence_floor.get().to_be_bytes());
    digest.update((entries.len() as u32).to_be_bytes());
    for entry in entries {
        digest.update(entry.operation().as_bytes());
        digest.update(entry.operation_sequence().get().to_be_bytes());
        digest.update(entry.effect_request_digest().as_bytes());
        digest.update(entry.execution().as_bytes());
        digest.update(entry.specification_digest().as_bytes());
        digest.update(entry.admission_commitment().as_bytes());
        digest.update(entry.runtime().plan_commitment().as_bytes());
        digest.update(entry.runtime().handle().as_bytes());
        digest.update(entry.payload_boot_id().as_bytes());
        digest.update([execution_phase_code(entry.phase())]);
        digest.update(entry.sequence().get().to_be_bytes());
        digest.update(entry.observation_commitment().as_bytes());
    }
    ObjectDigest::from_bytes(digest.finalize().into())
}

const fn execution_phase_code(phase: super::BackendExecutionPhaseV1) -> u8 {
    match phase {
        super::BackendExecutionPhaseV1::Authorized => 1,
        super::BackendExecutionPhaseV1::Starting => 2,
        super::BackendExecutionPhaseV1::Running => 3,
        super::BackendExecutionPhaseV1::Exited => 4,
        super::BackendExecutionPhaseV1::Canceled => 5,
        super::BackendExecutionPhaseV1::Failed => 6,
        super::BackendExecutionPhaseV1::Lost => 7,
    }
}

/// Reports failure to derive a safe recovery transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ExecutionRecoveryError {
    /// Backend inventory is incomplete, unauthenticated, or uses zero fields.
    #[error("execution backend inventory is invalid")]
    InvalidInventory,
    /// Durable and backend runtime currentness differ.
    #[error("execution recovery runtime currentness does not match")]
    CurrentnessMismatch,
    /// An exact observation binds another execution, spec, or runtime.
    #[error("execution recovery observation binding does not match")]
    ObservationMismatch,
    /// An exact observation predates the complete inventory's sequence floor.
    #[error("execution recovery observation is stale")]
    StaleObservation,
}
