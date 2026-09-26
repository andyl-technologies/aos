//! Pure worker death, quarantine, repair, and attachment reconciliation model.
//!
//! The reducer carries only exact descriptors, commitments, generations, and
//! evidence digests. It performs no process, mount, cache, or filesystem effect;
//! a privileged owner must execute returned actions and feed observations back.
//! Canonical payload coding stays beside the reducer so private evidence and
//! event variants never need public raw-field constructors.

use aos_sandbox_core::{AttachmentId, ObjectDescriptor, Revision};

use super::PreparedFuseConnection;
use super::durable::{Cursor, DurableStateError, Writer};

/// Opaque authenticated observation of the current worker process.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessEvidence {
    generation: u64,
    authority: [u8; 32],
    digest: [u8; 32],
}

/// Opaque complete resource inventory for one connection generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InventoryEvidence {
    generation: u64,
    digest: [u8; 32],
}

/// Opaque proof that the exact attachment consumer has stopped.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConsumerEvidence {
    attachment: AttachmentId,
    generation: Revision,
    digest: [u8; 32],
}

impl ProcessEvidence {
    pub(crate) fn from_authenticated(
        generation: u64,
        authority: [u8; 32],
        digest: [u8; 32],
    ) -> Result<Self, LifecycleError> {
        if generation == 0 || authority == [0; 32] || digest == [0; 32] {
            return Err(LifecycleError::InvalidIdentity);
        }
        Ok(Self {
            generation,
            authority,
            digest,
        })
    }

    /// Returns the observed generation and authority commitment.
    #[must_use]
    pub const fn identity(&self) -> (u64, [u8; 32]) {
        (self.generation, self.authority)
    }

    /// Returns the authenticated observation digest.
    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }
}

impl InventoryEvidence {
    pub(crate) fn from_authenticated(
        generation: u64,
        digest: [u8; 32],
    ) -> Result<Self, LifecycleError> {
        if generation == 0 || digest == [0; 32] {
            return Err(LifecycleError::InvalidIdentity);
        }
        Ok(Self { generation, digest })
    }

    /// Returns the generation covered by the complete inventory.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns the authenticated inventory digest.
    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }
}

impl ConsumerEvidence {
    pub(crate) fn from_authenticated(
        attachment: AttachmentId,
        generation: Revision,
        digest: [u8; 32],
    ) -> Result<Self, LifecycleError> {
        if attachment.as_bytes() == &[0; 16] || generation.get() == 0 || digest == [0; 32] {
            return Err(LifecycleError::InvalidIdentity);
        }
        Ok(Self {
            attachment,
            generation,
            digest,
        })
    }

    /// Returns the attachment identity and generation proven stopped.
    #[must_use]
    pub const fn identity(&self) -> (AttachmentId, Revision) {
        (self.attachment, self.generation)
    }

    /// Returns the authenticated stop-observation digest.
    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }
}

/// Identifies one worker generation's durable phase.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkerPhase {
    /// Launch has been planned but readiness is not proven.
    Starting,
    /// Exact projection/index/lease authority passed readiness.
    Ready,
    /// Unexpected death or protocol ambiguity faulted the generation.
    Faulted,
    /// A replacement generation is prepared but not yet authoritative.
    ReplacementPrepared,
    /// The replacement is authoritative while the old generation drains.
    Draining,
    /// No worker generation remains authoritative.
    Stopped,
}

/// Tracks whether immutable publication bytes may be reused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicationHealth {
    /// The publication passed its last complete validation.
    Healthy,
    /// Worker death made integrity ambiguous; reuse is forbidden.
    Quarantined {
        /// Evidence digest for the death or integrity observation.
        evidence: ProcessEvidence,
    },
    /// A repair scan is in progress and the publication remains unusable.
    Repairing {
        /// Inventory operation commitment.
        inventory: InventoryEvidence,
    },
    /// Exact replacement bytes passed repair validation.
    Repaired {
        /// Digest of the complete repair evidence.
        evidence: [u8; 32],
    },
}

/// Summarizes consumer-visible attachment readiness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttachmentHealth {
    /// No generation has yet been published.
    Preparing,
    /// The current worker generation is ready.
    Ready,
    /// Required-view readiness was lost.
    Faulted,
    /// Hard revocation is waiting for proven consumer stop.
    Revoking,
    /// Consumer stop proves no old backing/open authority remains usable.
    Revoked,
}

/// Carries exact inventory and repaired-publication proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepairEvidence {
    /// Quarantined publication that was inspected.
    quarantined: ObjectDescriptor,
    /// Complete inventory observation commitment.
    inventory: InventoryEvidence,
    /// Exact validated replacement publication.
    repaired: ObjectDescriptor,
    /// Evidence digest covering validation and atomic publication.
    repair_digest: [u8; 32],
}

impl RepairEvidence {
    /// Joins authenticated inventory and atomic replacement-publication evidence.
    pub(crate) fn from_verified_repair(
        quarantined: ObjectDescriptor,
        inventory: InventoryEvidence,
        repaired: ObjectDescriptor,
        repair_digest: [u8; 32],
    ) -> Result<Self, LifecycleError> {
        if repair_digest == [0; 32]
            || !is_index_descriptor(&quarantined)
            || !is_index_descriptor(&repaired)
        {
            return Err(LifecycleError::InvalidIdentity);
        }
        Ok(Self {
            quarantined,
            inventory,
            repaired,
            repair_digest,
        })
    }
}

/// Describes the next privileged effect without performing it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReconciliationAction {
    /// No effect is currently authorized.
    None,
    /// Stops dispatch, records attachment fault, and optionally quarantines bytes.
    FaultConnection {
        /// Faulted connection generation.
        generation: u64,
        /// Exact suspect artifact, absent when bytes remain trusted.
        quarantine: Option<ObjectDescriptor>,
        /// Current-process evidence for the fault.
        evidence: ProcessEvidence,
    },
    /// Inventory cache publications and connection/backing ownership records.
    InventoryAndRepair {
        /// Exact inventory operation commitment.
        inventory: InventoryEvidence,
    },
    /// Launch a replacement that remains nonauthoritative until readiness.
    LaunchReplacement {
        /// New nonzero connection generation.
        generation: u64,
        /// Complete prepared-connection authority commitment.
        authority: [u8; 32],
    },
    /// Atomically publish the ready replacement and begin old-generation drain.
    PublishReplacement {
        /// Replacement connection generation.
        generation: u64,
    },
    /// Reconcile durable attachment observation with the current worker.
    RecordAttachmentHealth {
        /// Exact attachment generation.
        generation: Revision,
        /// Health value to record.
        health: AttachmentHealth,
    },
    /// Stop the consuming sandbox to complete hard revocation.
    StopConsumer,
    /// Remove only inventory-proven stale resources from an old generation.
    ReapGeneration {
        /// Proven stale connection generation.
        generation: u64,
        /// Inventory evidence authorizing exact ownership.
        inventory: InventoryEvidence,
    },
}

/// Supplies one crate-authenticated event to the lifecycle reducer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum WorkerLifecycleEvent {
    /// The planned generation passed exact readiness checks.
    Ready {
        /// Observed prepared-connection authority commitment.
        authority: [u8; 32],
    },
    /// The worker exited before an authorized clean stop.
    UnexpectedExit {
        /// Process-death and status evidence commitment.
        evidence: ProcessEvidence,
        /// True when an fs-verity/SIGBUS-style integrity failure is possible.
        publication_suspect: bool,
    },
    /// Reply or backing-registration publication became ambiguous.
    AmbiguousExternalState {
        /// Evidence commitment for the ambiguous operation and inventory fence.
        evidence: ProcessEvidence,
    },
    /// Cache inventory began for a quarantined publication.
    RepairStarted {
        /// Complete inventory operation commitment.
        inventory: InventoryEvidence,
    },
    /// Repair produced an exact validated replacement artifact.
    RepairValidated(RepairEvidence),
    /// A strictly newer connection generation was prepared.
    ReplacementPrepared {
        /// New generation, which must be exactly current plus one.
        generation: u64,
        /// Complete prepared-connection authority commitment.
        authority: [u8; 32],
        /// Exact index publication for the replacement.
        index: ObjectDescriptor,
        /// Exact projection commitment.
        projection: [u8; 32],
    },
    /// The prepared replacement passed readiness.
    ReplacementReady {
        /// Generation observed ready.
        generation: u64,
        /// Exact authority commitment observed ready.
        authority: [u8; 32],
        /// Exact replacement index observed by the ready process.
        index: ObjectDescriptor,
        /// Exact replacement projection observed by the ready process.
        projection: [u8; 32],
    },
    /// Atomic attachment publication selected the replacement.
    ReplacementPublished {
        /// Published connection generation.
        generation: u64,
    },
    /// Inventory proved all resources for one old generation drainable.
    DrainProven {
        /// Old connection generation.
        generation: u64,
        /// Complete ownership inventory evidence.
        inventory: InventoryEvidence,
    },
    /// The generation reap effect completed durably.
    ReapConfirmed {
        /// Reaped old connection generation.
        generation: u64,
        /// Same inventory evidence that authorized the effect.
        inventory: InventoryEvidence,
    },
    /// A definite retryable reap failure left the effect pending.
    ReapRetryable {
        /// Old connection generation whose reap must be retried.
        generation: u64,
        /// Same inventory evidence that authorized the effect.
        inventory: InventoryEvidence,
    },
    /// Hard revocation was requested for this attachment.
    HardRevocationRequested,
    /// The consumer stop was independently observed.
    ConsumerStopped {
        /// Stop/identity evidence commitment.
        evidence: ConsumerEvidence,
    },
}

/// One canonically decoded, authenticated durable lifecycle journal record.
pub struct DurableLifecycleEvent {
    sequence: u64,
    previous: [u8; 32],
    commitment: [u8; 32],
    event: WorkerLifecycleEvent,
}

impl DurableLifecycleEvent {
    /// Creates a record only after the journal owner verifies canonical bytes.
    pub(crate) fn from_canonical_journal(
        sequence: u64,
        previous: [u8; 32],
        commitment: [u8; 32],
        event: WorkerLifecycleEvent,
    ) -> Result<Self, LifecycleError> {
        if sequence == 0 || commitment == [0; 32] {
            return Err(LifecycleError::InvalidIdentity);
        }
        Ok(Self {
            sequence,
            previous,
            commitment,
            event,
        })
    }

    /// Returns the exact one-based journal sequence.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns the previous-record commitment.
    #[must_use]
    pub const fn previous_commitment(&self) -> [u8; 32] {
        self.previous
    }

    /// Returns this record's canonical commitment.
    #[must_use]
    pub const fn commitment(&self) -> [u8; 32] {
        self.commitment
    }
}

/// Reports an invalid or stale lifecycle observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum LifecycleError {
    /// An identity, generation, commitment, or evidence digest is zero.
    #[error("invalid worker lifecycle identity or evidence")]
    InvalidIdentity,
    /// The event does not apply in the current phase.
    #[error("worker lifecycle transition is not valid from the current phase")]
    InvalidTransition,
    /// The event describes a stale or skipped generation.
    #[error("worker lifecycle generation is stale or noncontiguous")]
    GenerationMismatch,
    /// Readiness or repair evidence differs from prepared immutable state.
    #[error("worker lifecycle evidence does not match prepared state")]
    EvidenceMismatch,
}

/// Reduces exact worker observations into bounded reconciliation actions.
pub struct WorkerLifecycle {
    attachment: AttachmentId,
    attachment_generation: Revision,
    connection_generation: u64,
    authority: [u8; 32],
    index: ObjectDescriptor,
    projection: [u8; 32],
    phase: WorkerPhase,
    publication: PublicationHealth,
    attachment_health: AttachmentHealth,
    replacement: Option<Replacement>,
    hard_revocation: bool,
    repaired_artifact: Option<ObjectDescriptor>,
    pending_reap: Option<(u64, InventoryEvidence)>,
    next_event_sequence: u64,
    replay_head: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Replacement {
    generation: u64,
    authority: [u8; 32],
    index: ObjectDescriptor,
    projection: [u8; 32],
    ready: bool,
}

/// Opaque bounded snapshot of all reducer state needed for exact recovery.
///
/// The snapshot is an in-memory representation, not a durability claim. A
/// journal owner must canonically encode and authenticate its fields, then
/// replay authenticated events after the captured replay head.
#[derive(Clone)]
pub struct WorkerLifecycleSnapshot {
    attachment: AttachmentId,
    attachment_generation: Revision,
    connection_generation: u64,
    authority: [u8; 32],
    index: ObjectDescriptor,
    projection: [u8; 32],
    phase: WorkerPhase,
    publication: PublicationHealth,
    attachment_health: AttachmentHealth,
    replacement: Option<Replacement>,
    hard_revocation: bool,
    repaired_artifact: Option<ObjectDescriptor>,
    pending_reap: Option<(u64, InventoryEvidence)>,
    next_event_sequence: u64,
    replay_head: [u8; 32],
}

impl WorkerLifecycleSnapshot {
    /// Returns the exact active consumer and attachment generations.
    #[must_use]
    pub const fn identity(&self) -> (AttachmentId, Revision, u64) {
        (
            self.attachment,
            self.attachment_generation,
            self.connection_generation,
        )
    }

    /// Returns active authority, index, and projection commitments.
    #[must_use]
    pub const fn active_artifacts(&self) -> ([u8; 32], &ObjectDescriptor, [u8; 32]) {
        (self.authority, &self.index, self.projection)
    }

    /// Returns reducer phase and health state.
    #[must_use]
    pub const fn state(&self) -> (WorkerPhase, PublicationHealth, AttachmentHealth) {
        (self.phase, self.publication, self.attachment_health)
    }

    /// Reports whether hard revocation has begun.
    #[must_use]
    pub const fn hard_revocation(&self) -> bool {
        self.hard_revocation
    }

    /// Returns an exact pending old-generation reap, when present.
    #[must_use]
    pub const fn pending_reap(&self) -> Option<(u64, InventoryEvidence)> {
        self.pending_reap
    }

    /// Returns a pending replacement's exact fields, when present.
    #[must_use]
    pub fn replacement(&self) -> Option<(u64, [u8; 32], &ObjectDescriptor, [u8; 32], bool)> {
        self.replacement.as_ref().map(|replacement| {
            (
                replacement.generation,
                replacement.authority,
                &replacement.index,
                replacement.projection,
                replacement.ready,
            )
        })
    }

    /// Returns the exact repaired artifact awaiting or serving replacement.
    #[must_use]
    pub const fn repaired_artifact(&self) -> Option<&ObjectDescriptor> {
        self.repaired_artifact.as_ref()
    }

    /// Returns the next journal sequence and current replay-chain head.
    #[must_use]
    pub const fn replay_position(&self) -> (u64, [u8; 32]) {
        (self.next_event_sequence, self.replay_head)
    }
}

impl WorkerLifecycle {
    /// Creates a nonready lifecycle for one exact attachment generation.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleError::InvalidIdentity`] for zero generations or
    /// zero authority/projection commitments.
    pub(crate) fn new(
        attachment: AttachmentId,
        attachment_generation: Revision,
        connection_generation: u64,
        authority: [u8; 32],
        index: ObjectDescriptor,
        projection: [u8; 32],
    ) -> Result<Self, LifecycleError> {
        if attachment.as_bytes() == &[0; 16]
            || attachment_generation.get() == 0
            || connection_generation == 0
            || authority == [0; 32]
            || projection == [0; 32]
            || !is_index_descriptor(&index)
        {
            return Err(LifecycleError::InvalidIdentity);
        }
        Ok(Self {
            attachment,
            attachment_generation,
            connection_generation,
            authority,
            index,
            projection,
            phase: WorkerPhase::Starting,
            publication: PublicationHealth::Healthy,
            attachment_health: AttachmentHealth::Preparing,
            replacement: None,
            hard_revocation: false,
            repaired_artifact: None,
            pending_reap: None,
            next_event_sequence: 1,
            replay_head: [0; 32],
        })
    }

    /// Returns the exact attachment and generation.
    #[must_use]
    pub const fn attachment(&self) -> (AttachmentId, Revision) {
        (self.attachment, self.attachment_generation)
    }

    /// Returns the current connection generation and phase.
    #[must_use]
    pub const fn worker_state(&self) -> (u64, WorkerPhase) {
        (self.connection_generation, self.phase)
    }

    /// Returns publication and attachment health.
    #[must_use]
    pub const fn health(&self) -> (PublicationHealth, AttachmentHealth) {
        (self.publication, self.attachment_health)
    }

    /// Returns the exact active index and projection commitments.
    #[must_use]
    pub const fn active_artifacts(&self) -> (&ObjectDescriptor, [u8; 32]) {
        (&self.index, self.projection)
    }

    /// Returns an exact bounded snapshot without claiming external durability.
    #[must_use]
    pub fn snapshot(&self) -> WorkerLifecycleSnapshot {
        WorkerLifecycleSnapshot {
            attachment: self.attachment,
            attachment_generation: self.attachment_generation,
            connection_generation: self.connection_generation,
            authority: self.authority,
            index: self.index.clone(),
            projection: self.projection,
            phase: self.phase,
            publication: self.publication,
            attachment_health: self.attachment_health,
            replacement: self.replacement.clone(),
            hard_revocation: self.hard_revocation,
            repaired_artifact: self.repaired_artifact.clone(),
            pending_reap: self.pending_reap,
            next_event_sequence: self.next_event_sequence,
            replay_head: self.replay_head,
        }
    }

    /// Restores a reducer from an opaque snapshot produced by [`Self::snapshot`].
    ///
    /// This performs no privileged effect and does not assert that the snapshot
    /// was durably stored. Journal authentication and replay remain mandatory at
    /// the process boundary.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleError`] when the snapshot contains a zero identity,
    /// malformed phase relation, invalid replacement, or incoherent reap proof.
    pub fn restore(snapshot: WorkerLifecycleSnapshot) -> Result<Self, LifecycleError> {
        validate_snapshot(&snapshot)?;
        Ok(Self {
            attachment: snapshot.attachment,
            attachment_generation: snapshot.attachment_generation,
            connection_generation: snapshot.connection_generation,
            authority: snapshot.authority,
            index: snapshot.index,
            projection: snapshot.projection,
            phase: snapshot.phase,
            publication: snapshot.publication,
            attachment_health: snapshot.attachment_health,
            replacement: snapshot.replacement,
            hard_revocation: snapshot.hard_revocation,
            repaired_artifact: snapshot.repaired_artifact,
            pending_reap: snapshot.pending_reap,
            next_event_sequence: snapshot.next_event_sequence,
            replay_head: snapshot.replay_head,
        })
    }

    /// Records authenticated readiness for the current process.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleError`] unless the evidence identifies the exact
    /// current generation and prepared-connection authority.
    pub fn record_ready(
        &mut self,
        evidence: ProcessEvidence,
    ) -> Result<ReconciliationAction, LifecycleError> {
        if evidence.generation != self.connection_generation || evidence.authority != self.authority
        {
            return Err(LifecycleError::EvidenceMismatch);
        }
        self.observe_ready(evidence.authority)
    }

    /// Records an authenticated unexpected exit or integrity fault.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleError`] for stale evidence or an invalid phase.
    pub fn record_unexpected_exit(
        &mut self,
        evidence: ProcessEvidence,
        publication_suspect: bool,
    ) -> Result<ReconciliationAction, LifecycleError> {
        self.observe_fault(evidence, publication_suspect)
    }

    /// Records an authenticated ambiguous external publication or close.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleError`] for stale evidence or an invalid phase.
    pub fn record_ambiguity(
        &mut self,
        evidence: ProcessEvidence,
    ) -> Result<ReconciliationAction, LifecycleError> {
        self.observe_fault(evidence, false)
    }

    /// Begins repair from one complete authenticated inventory.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleError`] unless the current publication is quarantined
    /// for the inventory's exact generation.
    pub fn record_repair_started(
        &mut self,
        inventory: InventoryEvidence,
    ) -> Result<ReconciliationAction, LifecycleError> {
        self.start_repair(inventory)
    }

    /// Records verifier-issued repair and replacement-artifact evidence.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleError`] unless it matches the current repair exactly.
    pub fn record_repair_validated(
        &mut self,
        evidence: RepairEvidence,
    ) -> Result<ReconciliationAction, LifecycleError> {
        self.finish_repair(evidence)
    }

    /// Prepares a replacement from one exact prepared connection artifact.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleError`] for a foreign attachment, noncontiguous
    /// generation, unusable publication health, or mismatched repaired artifact.
    pub fn prepare_replacement_from(
        &mut self,
        prepared: &PreparedFuseConnection<'_, '_, '_, '_, '_>,
    ) -> Result<ReconciliationAction, LifecycleError> {
        let (attachment, _, _) = prepared.consumer_identity();
        let (_, generation, attachment_generation) = prepared.generations();
        if attachment != self.attachment || attachment_generation != self.attachment_generation {
            return Err(LifecycleError::EvidenceMismatch);
        }
        self.prepare_replacement(
            generation,
            prepared.binding(),
            prepared.projection().index().descriptor().clone(),
            prepared.projection().commitment(),
        )
    }

    /// Records authenticated readiness for the prepared replacement.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleError`] unless evidence and every retained artifact
    /// match the exact prepared replacement.
    pub fn record_replacement_ready(
        &mut self,
        evidence: ProcessEvidence,
    ) -> Result<ReconciliationAction, LifecycleError> {
        let (index, projection) = {
            let replacement = self
                .replacement
                .as_ref()
                .ok_or(LifecycleError::InvalidTransition)?;
            (replacement.index.clone(), replacement.projection)
        };
        self.ready_replacement(evidence.generation, evidence.authority, index, projection)
    }

    /// Records atomic publication of the ready replacement generation.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleError`] unless the exact replacement is ready.
    pub fn record_replacement_published(
        &mut self,
        generation: u64,
    ) -> Result<ReconciliationAction, LifecycleError> {
        self.publish_replacement(generation)
    }

    /// Records fresh inventory proof for an old generation and authorizes reap.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleError`] for a stale generation, incomplete inventory,
    /// or an already-pending reap obligation.
    pub fn record_drain_proven(
        &mut self,
        inventory: InventoryEvidence,
    ) -> Result<ReconciliationAction, LifecycleError> {
        self.drain_proven(inventory.generation, inventory)
    }

    /// Reissues a previously authorized old-generation reap.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleError`] unless exact generation and inventory evidence
    /// remain pending, including after a replacement fault or hard revocation.
    pub fn retry_reap(
        &self,
        inventory: InventoryEvidence,
    ) -> Result<ReconciliationAction, LifecycleError> {
        self.reap_retryable(inventory.generation, inventory)
    }

    /// Confirms a previously authorized old-generation reap.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleError`] unless exact pending inventory matches.
    pub fn record_reap_confirmed(
        &mut self,
        inventory: InventoryEvidence,
    ) -> Result<ReconciliationAction, LifecycleError> {
        self.reap_confirmed(inventory.generation, inventory)
    }

    /// Begins hard revocation without discarding pending reap authority.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleError`] when revocation is already active or complete.
    pub fn request_hard_revocation(&mut self) -> Result<ReconciliationAction, LifecycleError> {
        self.advance(WorkerLifecycleEvent::HardRevocationRequested)
    }

    /// Records independent proof that the exact attachment consumer stopped.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleError`] unless hard revocation is active and evidence
    /// identifies this exact attachment generation.
    pub fn record_consumer_stopped(
        &mut self,
        evidence: ConsumerEvidence,
    ) -> Result<ReconciliationAction, LifecycleError> {
        self.advance(WorkerLifecycleEvent::ConsumerStopped { evidence })
    }

    /// Applies one exact observation and returns the next authorized effect.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleError`] for zero evidence, stale/skipped generations,
    /// mismatched readiness/repair evidence, or an event invalid in this phase.
    pub(crate) fn advance(
        &mut self,
        event: WorkerLifecycleEvent,
    ) -> Result<ReconciliationAction, LifecycleError> {
        match event {
            WorkerLifecycleEvent::Ready { authority } => self.observe_ready(authority),
            WorkerLifecycleEvent::UnexpectedExit {
                evidence,
                publication_suspect,
            } => self.observe_fault(evidence, publication_suspect),
            WorkerLifecycleEvent::AmbiguousExternalState { evidence } => {
                self.observe_fault(evidence, false)
            }
            WorkerLifecycleEvent::RepairStarted { inventory } => self.start_repair(inventory),
            WorkerLifecycleEvent::RepairValidated(evidence) => self.finish_repair(evidence),
            WorkerLifecycleEvent::ReplacementPrepared {
                generation,
                authority,
                index,
                projection,
            } => self.prepare_replacement(generation, authority, index, projection),
            WorkerLifecycleEvent::ReplacementReady {
                generation,
                authority,
                index,
                projection,
            } => self.ready_replacement(generation, authority, index, projection),
            WorkerLifecycleEvent::ReplacementPublished { generation } => {
                self.publish_replacement(generation)
            }
            WorkerLifecycleEvent::DrainProven {
                generation,
                inventory,
            } => self.drain_proven(generation, inventory),
            WorkerLifecycleEvent::ReapConfirmed {
                generation,
                inventory,
            } => self.reap_confirmed(generation, inventory),
            WorkerLifecycleEvent::ReapRetryable {
                generation,
                inventory,
            } => self.reap_retryable(generation, inventory),
            WorkerLifecycleEvent::HardRevocationRequested => {
                if self.hard_revocation || self.attachment_health == AttachmentHealth::Revoked {
                    return Err(LifecycleError::InvalidTransition);
                }
                self.hard_revocation = true;
                self.attachment_health = AttachmentHealth::Revoking;
                Ok(ReconciliationAction::StopConsumer)
            }
            WorkerLifecycleEvent::ConsumerStopped { evidence } => {
                if !self.hard_revocation
                    || evidence.attachment != self.attachment
                    || evidence.generation != self.attachment_generation
                    || evidence.digest == [0; 32]
                {
                    return Err(LifecycleError::InvalidTransition);
                }
                self.pending_reap = None;
                self.phase = WorkerPhase::Stopped;
                self.attachment_health = AttachmentHealth::Revoked;
                Ok(ReconciliationAction::RecordAttachmentHealth {
                    generation: self.attachment_generation,
                    health: AttachmentHealth::Revoked,
                })
            }
        }
    }

    /// Replays one canonical durable record exactly once and in chain order.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleError::EvidenceMismatch`] for a gap, duplicate, fork,
    /// or zero journal commitment. Reducer state changes only after the record
    /// chain is accepted; event-specific errors leave the chain unchanged.
    pub fn replay(
        &mut self,
        record: DurableLifecycleEvent,
    ) -> Result<ReconciliationAction, LifecycleError> {
        if record.sequence != self.next_event_sequence
            || record.previous != self.replay_head
            || record.commitment == [0; 32]
        {
            return Err(LifecycleError::EvidenceMismatch);
        }
        let next_sequence = self
            .next_event_sequence
            .checked_add(1)
            .ok_or(LifecycleError::GenerationMismatch)?;
        let action = self.advance(record.event)?;
        self.next_event_sequence = next_sequence;
        self.replay_head = record.commitment;
        Ok(action)
    }

    fn observe_ready(
        &mut self,
        authority: [u8; 32],
    ) -> Result<ReconciliationAction, LifecycleError> {
        if self.phase != WorkerPhase::Starting {
            return Err(LifecycleError::InvalidTransition);
        }
        if authority != self.authority {
            return Err(LifecycleError::EvidenceMismatch);
        }
        self.phase = WorkerPhase::Ready;
        self.attachment_health = AttachmentHealth::Ready;
        Ok(ReconciliationAction::RecordAttachmentHealth {
            generation: self.attachment_generation,
            health: AttachmentHealth::Ready,
        })
    }

    fn observe_fault(
        &mut self,
        evidence: ProcessEvidence,
        publication_suspect: bool,
    ) -> Result<ReconciliationAction, LifecycleError> {
        if self.phase == WorkerPhase::Stopped
            || evidence.generation != self.connection_generation
            || evidence.authority != self.authority
            || evidence.digest == [0; 32]
        {
            return Err(LifecycleError::InvalidTransition);
        }
        self.phase = WorkerPhase::Faulted;
        self.replacement = None;
        // An already proven old-generation reap remains authorized across a
        // newer worker fault. Only exact reap confirmation or independently
        // proven consumer stop may discharge that durable obligation.
        if !self.hard_revocation {
            self.attachment_health = AttachmentHealth::Faulted;
        }
        if publication_suspect {
            self.repaired_artifact = None;
            self.publication = PublicationHealth::Quarantined { evidence };
            Ok(ReconciliationAction::FaultConnection {
                generation: self.connection_generation,
                quarantine: Some(self.index.clone()),
                evidence,
            })
        } else {
            Ok(ReconciliationAction::FaultConnection {
                generation: self.connection_generation,
                quarantine: None,
                evidence,
            })
        }
    }

    fn start_repair(
        &mut self,
        inventory: InventoryEvidence,
    ) -> Result<ReconciliationAction, LifecycleError> {
        if self.hard_revocation
            || !matches!(self.publication, PublicationHealth::Quarantined { .. })
            || inventory.generation != self.connection_generation
            || inventory.digest == [0; 32]
        {
            return Err(LifecycleError::InvalidTransition);
        }
        self.publication = PublicationHealth::Repairing { inventory };
        Ok(ReconciliationAction::InventoryAndRepair { inventory })
    }

    fn finish_repair(
        &mut self,
        evidence: RepairEvidence,
    ) -> Result<ReconciliationAction, LifecycleError> {
        let PublicationHealth::Repairing { inventory } = self.publication else {
            return Err(LifecycleError::InvalidTransition);
        };
        if evidence.quarantined != self.index
            || evidence.inventory != inventory
            || evidence.repair_digest == [0; 32]
        {
            return Err(LifecycleError::EvidenceMismatch);
        }
        self.publication = PublicationHealth::Repaired {
            evidence: evidence.repair_digest,
        };
        self.repaired_artifact = Some(evidence.repaired);
        Ok(ReconciliationAction::None)
    }

    fn prepare_replacement(
        &mut self,
        generation: u64,
        authority: [u8; 32],
        index: ObjectDescriptor,
        projection: [u8; 32],
    ) -> Result<ReconciliationAction, LifecycleError> {
        if self.hard_revocation
            || !matches!(self.phase, WorkerPhase::Faulted | WorkerPhase::Ready)
            || self.replacement.is_some()
        {
            return Err(LifecycleError::InvalidTransition);
        }
        if generation
            != self
                .connection_generation
                .checked_add(1)
                .ok_or(LifecycleError::GenerationMismatch)?
        {
            return Err(LifecycleError::GenerationMismatch);
        }
        if authority == [0; 32] || projection == [0; 32] || !is_index_descriptor(&index) {
            return Err(LifecycleError::InvalidIdentity);
        }
        match self.publication {
            PublicationHealth::Healthy if index == self.index => {}
            PublicationHealth::Repaired { .. }
                if self.repaired_artifact.as_ref() == Some(&index) => {}
            PublicationHealth::Healthy | PublicationHealth::Repaired { .. } => {
                return Err(LifecycleError::EvidenceMismatch);
            }
            PublicationHealth::Quarantined { .. } | PublicationHealth::Repairing { .. } => {
                return Err(LifecycleError::InvalidTransition);
            }
        }
        self.replacement = Some(Replacement {
            generation,
            authority,
            index,
            projection,
            ready: false,
        });
        self.phase = WorkerPhase::ReplacementPrepared;
        Ok(ReconciliationAction::LaunchReplacement {
            generation,
            authority,
        })
    }

    fn ready_replacement(
        &mut self,
        generation: u64,
        authority: [u8; 32],
        index: ObjectDescriptor,
        projection: [u8; 32],
    ) -> Result<ReconciliationAction, LifecycleError> {
        if self.hard_revocation || self.phase != WorkerPhase::ReplacementPrepared {
            return Err(LifecycleError::InvalidTransition);
        }
        let replacement = self
            .replacement
            .as_mut()
            .ok_or(LifecycleError::InvalidTransition)?;
        if replacement.generation != generation
            || replacement.authority != authority
            || replacement.index != index
            || replacement.projection != projection
        {
            return Err(LifecycleError::EvidenceMismatch);
        }
        replacement.ready = true;
        Ok(ReconciliationAction::PublishReplacement { generation })
    }

    fn publish_replacement(
        &mut self,
        generation: u64,
    ) -> Result<ReconciliationAction, LifecycleError> {
        if self.hard_revocation {
            return Err(LifecycleError::InvalidTransition);
        }
        let replacement = self
            .replacement
            .take()
            .ok_or(LifecycleError::InvalidTransition)?;
        if self.phase != WorkerPhase::ReplacementPrepared
            || replacement.generation != generation
            || !replacement.ready
        {
            self.replacement = Some(replacement);
            return Err(LifecycleError::EvidenceMismatch);
        }
        self.connection_generation = replacement.generation;
        self.authority = replacement.authority;
        self.index = replacement.index;
        self.projection = replacement.projection;
        self.publication = PublicationHealth::Healthy;
        self.repaired_artifact = None;
        self.phase = WorkerPhase::Draining;
        self.attachment_health = AttachmentHealth::Ready;
        Ok(ReconciliationAction::RecordAttachmentHealth {
            generation: self.attachment_generation,
            health: AttachmentHealth::Ready,
        })
    }

    fn drain_proven(
        &mut self,
        generation: u64,
        inventory: InventoryEvidence,
    ) -> Result<ReconciliationAction, LifecycleError> {
        if self.phase != WorkerPhase::Draining
            || generation.checked_add(1) != Some(self.connection_generation)
            || inventory.generation != generation
            || inventory.digest == [0; 32]
        {
            return Err(LifecycleError::GenerationMismatch);
        }
        if self.pending_reap.is_some() {
            return Err(LifecycleError::InvalidTransition);
        }
        self.pending_reap = Some((generation, inventory));
        Ok(ReconciliationAction::ReapGeneration {
            generation,
            inventory,
        })
    }

    fn reap_retryable(
        &self,
        generation: u64,
        inventory: InventoryEvidence,
    ) -> Result<ReconciliationAction, LifecycleError> {
        if self.pending_reap != Some((generation, inventory)) {
            return Err(LifecycleError::EvidenceMismatch);
        }
        Ok(ReconciliationAction::ReapGeneration {
            generation,
            inventory,
        })
    }

    fn reap_confirmed(
        &mut self,
        generation: u64,
        inventory: InventoryEvidence,
    ) -> Result<ReconciliationAction, LifecycleError> {
        if self.pending_reap != Some((generation, inventory)) {
            return Err(LifecycleError::EvidenceMismatch);
        }
        self.pending_reap = None;
        if self.phase == WorkerPhase::Draining
            && generation.checked_add(1) == Some(self.connection_generation)
        {
            self.phase = WorkerPhase::Ready;
        }
        Ok(ReconciliationAction::None)
    }
}

fn is_index_descriptor(descriptor: &ObjectDescriptor) -> bool {
    descriptor.media_type().as_str() == crate::INDEX_MEDIA_TYPE
        && descriptor.digest().as_bytes() != &[0; 32]
        && descriptor.encoded_size() != 0
}

fn validate_snapshot(snapshot: &WorkerLifecycleSnapshot) -> Result<(), LifecycleError> {
    if snapshot.attachment.as_bytes() == &[0; 16]
        || snapshot.attachment_generation.get() == 0
        || snapshot.connection_generation == 0
        || snapshot.authority == [0; 32]
        || snapshot.projection == [0; 32]
        || !is_index_descriptor(&snapshot.index)
        || snapshot.next_event_sequence == 0
        || (snapshot.next_event_sequence == 1 && snapshot.replay_head != [0; 32])
        || (snapshot.next_event_sequence > 1 && snapshot.replay_head == [0; 32])
    {
        return Err(LifecycleError::InvalidIdentity);
    }
    match (&snapshot.replacement, snapshot.phase) {
        (Some(replacement), WorkerPhase::ReplacementPrepared)
            if replacement.generation
                == snapshot
                    .connection_generation
                    .checked_add(1)
                    .ok_or(LifecycleError::GenerationMismatch)?
                && replacement.authority != [0; 32]
                && replacement.projection != [0; 32]
                && is_index_descriptor(&replacement.index) => {}
        (None, phase) if phase != WorkerPhase::ReplacementPrepared => {}
        _ => return Err(LifecycleError::InvalidTransition),
    }
    match snapshot.publication {
        PublicationHealth::Healthy if snapshot.repaired_artifact.is_none() => {}
        PublicationHealth::Quarantined { evidence }
            if evidence.generation == snapshot.connection_generation
                && evidence.authority == snapshot.authority
                && evidence.digest != [0; 32]
                && snapshot.repaired_artifact.is_none() => {}
        PublicationHealth::Repairing { inventory }
            if inventory.generation == snapshot.connection_generation
                && inventory.digest != [0; 32]
                && snapshot.repaired_artifact.is_none() => {}
        PublicationHealth::Repaired { evidence }
            if evidence != [0; 32]
                && snapshot
                    .repaired_artifact
                    .as_ref()
                    .is_some_and(is_index_descriptor) => {}
        _ => return Err(LifecycleError::EvidenceMismatch),
    }
    if let Some((generation, inventory)) = snapshot.pending_reap {
        if generation >= snapshot.connection_generation
            || inventory.generation != generation
            || inventory.digest == [0; 32]
        {
            return Err(LifecycleError::EvidenceMismatch);
        }
    }
    if snapshot.phase == WorkerPhase::Stopped
        && (!snapshot.hard_revocation
            || snapshot.attachment_health != AttachmentHealth::Revoked
            || snapshot.pending_reap.is_some())
    {
        return Err(LifecycleError::InvalidTransition);
    }
    if snapshot.hard_revocation
        && !matches!(
            snapshot.attachment_health,
            AttachmentHealth::Revoking | AttachmentHealth::Revoked
        )
    {
        return Err(LifecycleError::InvalidTransition);
    }
    Ok(())
}

pub(super) fn encode_canonical_snapshot(
    writer: &mut Writer,
    snapshot: &WorkerLifecycleSnapshot,
    authority_binding: [u8; 32],
) -> Result<(), DurableStateError> {
    validate_snapshot(snapshot)?;
    if snapshot.authority != authority_binding {
        return Err(DurableStateError::Integrity);
    }
    writer.bytes(snapshot.attachment.as_bytes())?;
    writer.u64(snapshot.attachment_generation.get())?;
    writer.u64(snapshot.connection_generation)?;
    writer.bytes(&snapshot.authority)?;
    writer.descriptor(&snapshot.index)?;
    writer.bytes(&snapshot.projection)?;
    writer.u8(worker_phase_code(snapshot.phase))?;
    encode_publication(writer, snapshot.publication)?;
    writer.u8(attachment_health_code(snapshot.attachment_health))?;
    match &snapshot.replacement {
        Some(replacement) => {
            writer.u8(1)?;
            writer.u64(replacement.generation)?;
            writer.bytes(&replacement.authority)?;
            writer.descriptor(&replacement.index)?;
            writer.bytes(&replacement.projection)?;
            writer.u8(u8::from(replacement.ready))?;
        }
        None => writer.u8(0)?,
    }
    writer.u8(u8::from(snapshot.hard_revocation))?;
    encode_optional_descriptor(writer, snapshot.repaired_artifact.as_ref())?;
    match snapshot.pending_reap {
        Some((generation, inventory)) => {
            writer.u8(1)?;
            writer.u64(generation)?;
            encode_inventory(writer, inventory)?;
        }
        None => writer.u8(0)?,
    }
    writer.u64(snapshot.next_event_sequence)?;
    writer.bytes(&snapshot.replay_head)
}

pub(super) fn decode_canonical_snapshot(
    cursor: &mut Cursor<'_>,
    authority_binding: [u8; 32],
) -> Result<WorkerLifecycleSnapshot, DurableStateError> {
    let attachment = AttachmentId::from_bytes(cursor.array()?);
    let attachment_generation = Revision::new(cursor.u64()?);
    let connection_generation = cursor.u64()?;
    let authority = cursor.array()?;
    if authority != authority_binding {
        return Err(DurableStateError::Integrity);
    }
    let index = cursor.descriptor()?;
    let projection = cursor.array()?;
    let phase = decode_worker_phase(cursor.u8()?)?;
    let publication = decode_publication(cursor)?;
    let attachment_health = decode_attachment_health(cursor.u8()?)?;
    let replacement = match decode_bool(cursor.u8()?)? {
        true => Some(Replacement {
            generation: cursor.u64()?,
            authority: cursor.array()?,
            index: cursor.descriptor()?,
            projection: cursor.array()?,
            ready: decode_bool(cursor.u8()?)?,
        }),
        false => None,
    };
    let hard_revocation = decode_bool(cursor.u8()?)?;
    let repaired_artifact = decode_optional_descriptor(cursor)?;
    let pending_reap = match decode_bool(cursor.u8()?)? {
        true => Some((cursor.u64()?, decode_inventory(cursor)?)),
        false => None,
    };
    let snapshot = WorkerLifecycleSnapshot {
        attachment,
        attachment_generation,
        connection_generation,
        authority,
        index,
        projection,
        phase,
        publication,
        attachment_health,
        replacement,
        hard_revocation,
        repaired_artifact,
        pending_reap,
        next_event_sequence: cursor.u64()?,
        replay_head: cursor.array()?,
    };
    validate_snapshot(&snapshot)?;
    Ok(snapshot)
}

pub(super) fn encode_canonical_event(
    writer: &mut Writer,
    record: &DurableLifecycleEvent,
    authority_binding: [u8; 32],
) -> Result<(), DurableStateError> {
    writer.u64(record.sequence)?;
    writer.bytes(&record.previous)?;
    writer.bytes(&record.commitment)?;
    match &record.event {
        WorkerLifecycleEvent::Ready { authority } => {
            if *authority != authority_binding {
                return Err(DurableStateError::Integrity);
            }
            writer.u8(0)?;
            writer.bytes(authority)?;
        }
        WorkerLifecycleEvent::UnexpectedExit {
            evidence,
            publication_suspect,
        } => {
            writer.u8(1)?;
            encode_process(writer, *evidence)?;
            writer.u8(u8::from(*publication_suspect))?;
        }
        WorkerLifecycleEvent::AmbiguousExternalState { evidence } => {
            writer.u8(2)?;
            encode_process(writer, *evidence)?;
        }
        WorkerLifecycleEvent::RepairStarted { inventory } => {
            writer.u8(3)?;
            encode_inventory(writer, *inventory)?;
        }
        WorkerLifecycleEvent::RepairValidated(evidence) => {
            writer.u8(4)?;
            encode_repair(writer, evidence)?;
        }
        WorkerLifecycleEvent::ReplacementPrepared {
            generation,
            authority,
            index,
            projection,
        } => {
            writer.u8(5)?;
            writer.u64(*generation)?;
            writer.bytes(authority)?;
            writer.descriptor(index)?;
            writer.bytes(projection)?;
        }
        WorkerLifecycleEvent::ReplacementReady {
            generation,
            authority,
            index,
            projection,
        } => {
            writer.u8(6)?;
            writer.u64(*generation)?;
            writer.bytes(authority)?;
            writer.descriptor(index)?;
            writer.bytes(projection)?;
        }
        WorkerLifecycleEvent::ReplacementPublished { generation } => {
            writer.u8(7)?;
            writer.u64(*generation)?;
        }
        WorkerLifecycleEvent::DrainProven {
            generation,
            inventory,
        } => {
            writer.u8(8)?;
            writer.u64(*generation)?;
            encode_inventory(writer, *inventory)?;
        }
        WorkerLifecycleEvent::ReapConfirmed {
            generation,
            inventory,
        } => {
            writer.u8(9)?;
            writer.u64(*generation)?;
            encode_inventory(writer, *inventory)?;
        }
        WorkerLifecycleEvent::ReapRetryable {
            generation,
            inventory,
        } => {
            writer.u8(10)?;
            writer.u64(*generation)?;
            encode_inventory(writer, *inventory)?;
        }
        WorkerLifecycleEvent::HardRevocationRequested => writer.u8(11)?,
        WorkerLifecycleEvent::ConsumerStopped { evidence } => {
            writer.u8(12)?;
            encode_consumer(writer, *evidence)?;
        }
    }
    Ok(())
}

pub(super) fn decode_canonical_event(
    cursor: &mut Cursor<'_>,
    authority_binding: [u8; 32],
) -> Result<DurableLifecycleEvent, DurableStateError> {
    let sequence = cursor.u64()?;
    let previous = cursor.array()?;
    let commitment = cursor.array()?;
    let event = match cursor.u8()? {
        0 => {
            let authority = cursor.array()?;
            if authority != authority_binding {
                return Err(DurableStateError::Integrity);
            }
            WorkerLifecycleEvent::Ready { authority }
        }
        1 => WorkerLifecycleEvent::UnexpectedExit {
            evidence: decode_process(cursor)?,
            publication_suspect: decode_bool(cursor.u8()?)?,
        },
        2 => WorkerLifecycleEvent::AmbiguousExternalState {
            evidence: decode_process(cursor)?,
        },
        3 => WorkerLifecycleEvent::RepairStarted {
            inventory: decode_inventory(cursor)?,
        },
        4 => WorkerLifecycleEvent::RepairValidated(decode_repair(cursor)?),
        5 => WorkerLifecycleEvent::ReplacementPrepared {
            generation: cursor.u64()?,
            authority: cursor.array()?,
            index: cursor.descriptor()?,
            projection: cursor.array()?,
        },
        6 => WorkerLifecycleEvent::ReplacementReady {
            generation: cursor.u64()?,
            authority: cursor.array()?,
            index: cursor.descriptor()?,
            projection: cursor.array()?,
        },
        7 => WorkerLifecycleEvent::ReplacementPublished {
            generation: cursor.u64()?,
        },
        8 => WorkerLifecycleEvent::DrainProven {
            generation: cursor.u64()?,
            inventory: decode_inventory(cursor)?,
        },
        9 => WorkerLifecycleEvent::ReapConfirmed {
            generation: cursor.u64()?,
            inventory: decode_inventory(cursor)?,
        },
        10 => WorkerLifecycleEvent::ReapRetryable {
            generation: cursor.u64()?,
            inventory: decode_inventory(cursor)?,
        },
        11 => WorkerLifecycleEvent::HardRevocationRequested,
        12 => WorkerLifecycleEvent::ConsumerStopped {
            evidence: decode_consumer(cursor)?,
        },
        _ => return Err(DurableStateError::Integrity),
    };
    Ok(DurableLifecycleEvent::from_canonical_journal(
        sequence, previous, commitment, event,
    )?)
}

fn encode_process(writer: &mut Writer, evidence: ProcessEvidence) -> Result<(), DurableStateError> {
    writer.u64(evidence.generation)?;
    writer.bytes(&evidence.authority)?;
    writer.bytes(&evidence.digest)
}

fn decode_process(cursor: &mut Cursor<'_>) -> Result<ProcessEvidence, DurableStateError> {
    Ok(ProcessEvidence::from_authenticated(
        cursor.u64()?,
        cursor.array()?,
        cursor.array()?,
    )?)
}

fn encode_inventory(
    writer: &mut Writer,
    evidence: InventoryEvidence,
) -> Result<(), DurableStateError> {
    writer.u64(evidence.generation)?;
    writer.bytes(&evidence.digest)
}

fn decode_inventory(cursor: &mut Cursor<'_>) -> Result<InventoryEvidence, DurableStateError> {
    Ok(InventoryEvidence::from_authenticated(
        cursor.u64()?,
        cursor.array()?,
    )?)
}

fn encode_consumer(
    writer: &mut Writer,
    evidence: ConsumerEvidence,
) -> Result<(), DurableStateError> {
    writer.bytes(evidence.attachment.as_bytes())?;
    writer.u64(evidence.generation.get())?;
    writer.bytes(&evidence.digest)
}

fn decode_consumer(cursor: &mut Cursor<'_>) -> Result<ConsumerEvidence, DurableStateError> {
    Ok(ConsumerEvidence::from_authenticated(
        AttachmentId::from_bytes(cursor.array()?),
        Revision::new(cursor.u64()?),
        cursor.array()?,
    )?)
}

fn encode_repair(writer: &mut Writer, evidence: &RepairEvidence) -> Result<(), DurableStateError> {
    writer.descriptor(&evidence.quarantined)?;
    encode_inventory(writer, evidence.inventory)?;
    writer.descriptor(&evidence.repaired)?;
    writer.bytes(&evidence.repair_digest)
}

fn decode_repair(cursor: &mut Cursor<'_>) -> Result<RepairEvidence, DurableStateError> {
    Ok(RepairEvidence::from_verified_repair(
        cursor.descriptor()?,
        decode_inventory(cursor)?,
        cursor.descriptor()?,
        cursor.array()?,
    )?)
}

fn encode_publication(
    writer: &mut Writer,
    publication: PublicationHealth,
) -> Result<(), DurableStateError> {
    match publication {
        PublicationHealth::Healthy => writer.u8(0),
        PublicationHealth::Quarantined { evidence } => {
            writer.u8(1)?;
            encode_process(writer, evidence)
        }
        PublicationHealth::Repairing { inventory } => {
            writer.u8(2)?;
            encode_inventory(writer, inventory)
        }
        PublicationHealth::Repaired { evidence } => {
            writer.u8(3)?;
            writer.bytes(&evidence)
        }
    }
}

fn decode_publication(cursor: &mut Cursor<'_>) -> Result<PublicationHealth, DurableStateError> {
    match cursor.u8()? {
        0 => Ok(PublicationHealth::Healthy),
        1 => Ok(PublicationHealth::Quarantined {
            evidence: decode_process(cursor)?,
        }),
        2 => Ok(PublicationHealth::Repairing {
            inventory: decode_inventory(cursor)?,
        }),
        3 => Ok(PublicationHealth::Repaired {
            evidence: cursor.array()?,
        }),
        _ => Err(DurableStateError::Integrity),
    }
}

fn encode_optional_descriptor(
    writer: &mut Writer,
    descriptor: Option<&ObjectDescriptor>,
) -> Result<(), DurableStateError> {
    match descriptor {
        Some(descriptor) => {
            writer.u8(1)?;
            writer.descriptor(descriptor)
        }
        None => writer.u8(0),
    }
}

fn decode_optional_descriptor(
    cursor: &mut Cursor<'_>,
) -> Result<Option<ObjectDescriptor>, DurableStateError> {
    match decode_bool(cursor.u8()?)? {
        true => Ok(Some(cursor.descriptor()?)),
        false => Ok(None),
    }
}

const fn worker_phase_code(phase: WorkerPhase) -> u8 {
    match phase {
        WorkerPhase::Starting => 0,
        WorkerPhase::Ready => 1,
        WorkerPhase::Faulted => 2,
        WorkerPhase::ReplacementPrepared => 3,
        WorkerPhase::Draining => 4,
        WorkerPhase::Stopped => 5,
    }
}

fn decode_worker_phase(value: u8) -> Result<WorkerPhase, DurableStateError> {
    match value {
        0 => Ok(WorkerPhase::Starting),
        1 => Ok(WorkerPhase::Ready),
        2 => Ok(WorkerPhase::Faulted),
        3 => Ok(WorkerPhase::ReplacementPrepared),
        4 => Ok(WorkerPhase::Draining),
        5 => Ok(WorkerPhase::Stopped),
        _ => Err(DurableStateError::Integrity),
    }
}

const fn attachment_health_code(health: AttachmentHealth) -> u8 {
    match health {
        AttachmentHealth::Preparing => 0,
        AttachmentHealth::Ready => 1,
        AttachmentHealth::Faulted => 2,
        AttachmentHealth::Revoking => 3,
        AttachmentHealth::Revoked => 4,
    }
}

fn decode_attachment_health(value: u8) -> Result<AttachmentHealth, DurableStateError> {
    match value {
        0 => Ok(AttachmentHealth::Preparing),
        1 => Ok(AttachmentHealth::Ready),
        2 => Ok(AttachmentHealth::Faulted),
        3 => Ok(AttachmentHealth::Revoking),
        4 => Ok(AttachmentHealth::Revoked),
        _ => Err(DurableStateError::Integrity),
    }
}

fn decode_bool(value: u8) -> Result<bool, DurableStateError> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(DurableStateError::Integrity),
    }
}
