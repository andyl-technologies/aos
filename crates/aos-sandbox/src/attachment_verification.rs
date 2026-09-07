//! Persists post-attach kernel evidence before an attachment becomes ready.
//!
//! One immutable record binds the current desired attachment generation, its
//! live namespace allocation and assignment, the authenticated inventory that
//! supplied the observation, and the exact installed Mount resource:
//!
//! ```text
//! current Verify reconciliation + live namespace target
//!     -> durable installed-resource observation
//!     -> fresh inventory comparison may report Ready
//! ```
//!
//! A verification record is evidence, not broker authority. Committing it
//! intentionally invalidates the inventory snapshot from which it was derived;
//! readiness therefore requires another authenticated inventory observation.

use std::collections::BTreeMap;

use aos_proto::aos::sandbox::local::v1::{MountLifecycle, MountSourceConsistency};
use aos_sandbox_core::model::{AttachmentConsistency, AttachmentIntent, ViewMutation};
use aos_sandbox_core::{AttachmentId, ObjectDigest, RawPairedClockSample};
use aos_sandbox_protocol::{ValidatedMountInventoryRecord, ValidatedMountKernelObservation};
use sha2::{Digest as _, Sha256};

use crate::attachment_reconciliation::{
    AttachmentReconciliationActionV1, AttachmentReconciliationError,
    CurrentAttachmentReconciliationV1,
};
use crate::attachment_state::{
    self, AttachmentDesiredPresenceV1, AttachmentDesiredStateError, DurableAttachmentDesiredStateV1,
};
use crate::ownership_authority::ProtectedOwnershipClockError;
use crate::runtime_scope::{
    CurrentNamespaceTarget, DurableNamespaceTargetReferenceV1, NamespaceTargetError,
    validate_durable_reference_in_validated_namespace, validate_namespace_target_namespace,
};
use crate::{Journal, JournalError, JournalRecord, JournalTransaction, RecordNamespace};

mod format;

const NAMESPACE: RecordNamespace = RecordNamespace::AttachmentVerification;
const RESOURCE_DOMAIN: &[u8] = b"aos.sandbox.attachment-verification.mount-resource.v1\0";
const RECIPE_DOMAIN: &[u8] = b"aos.sandbox.attachment-verification.mount-recipe.v1\0";
const TRANSACTION_DOMAIN: &[u8] = b"aos.sandbox.attachment-verification.transaction.v1\0";
const MAXIMUM_VERIFICATIONS: usize = 65_536;
const MAXIMUM_NAMESPACE_BYTES: usize = 64 * 1024 * 1024;
const MAXIMUM_KERNEL_PATH_BYTES: usize = 4096;
const MAXIMUM_RECORD_BYTES: usize = format::FIXED_RECORD_BYTES + 2 * MAXIMUM_KERNEL_PATH_BYTES;

/// Reports whether exact post-attach evidence was newly recorded or replayed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttachmentVerificationOutcomeV1 {
    /// The verification became durable in this call.
    Recorded,
    /// The exact generation and evidence were already durable.
    Replay,
}

/// Exposes one validated durable post-attach verification record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableAttachmentVerificationV1 {
    record: Record,
    outcome: AttachmentVerificationOutcomeV1,
}

impl DurableAttachmentVerificationV1 {
    /// Returns whether the exact evidence was newly recorded or replayed.
    #[must_use]
    pub const fn outcome(&self) -> AttachmentVerificationOutcomeV1 {
        self.outcome
    }

    /// Returns the attachment whose installed generation was verified.
    #[must_use]
    pub const fn attachment_id(&self) -> AttachmentId {
        self.record.attachment_id
    }

    /// Returns the desired attachment generation proven by this record.
    #[must_use]
    pub const fn desired_generation(&self) -> u64 {
        self.record.desired_generation
    }

    /// Returns the stable Mount resource handle observed after attachment.
    #[must_use]
    pub const fn mount_handle(&self) -> [u8; 32] {
        self.record.mount_handle
    }

    /// Returns the non-recycled kernel mount identity observed after attachment.
    #[must_use]
    pub const fn unique_mount_id(&self) -> u64 {
        self.record.observation.unique_mount_id
    }

    /// Returns the exact authenticated inventory snapshot used for verification.
    #[must_use]
    pub const fn inventory_snapshot_digest(&self) -> ObjectDigest {
        ObjectDigest::from_bytes(self.record.inventory_snapshot_digest)
    }

    /// Returns the digest of the complete durable verification record.
    #[must_use]
    pub const fn record_digest(&self) -> ObjectDigest {
        ObjectDigest::from_bytes(self.record.digest)
    }
}

/// Reports stale planning evidence, conflicting verification, or corrupt state.
#[derive(Debug, thiserror::Error)]
pub enum AttachmentVerificationError {
    /// Reconciliation did not select one installed resource for verification.
    #[error("attachment reconciliation did not select post-attach verification")]
    NotVerifiable,
    /// The generation already has different verification or changed while committing.
    #[error("attachment verification conflicts with current state")]
    Conflict,
    /// A retained verification record or cross-reference is inconsistent.
    #[error("attachment verification history is corrupt")]
    CorruptState,
    /// The fixed verification count or retained-byte ceiling is exhausted.
    #[error("attachment verification capacity is exhausted")]
    Capacity,
    /// The retained reconciliation evidence is stale or invalid.
    #[error("attachment reconciliation failed: {0}")]
    Reconciliation(#[source] Box<AttachmentReconciliationError>),
    /// The referenced desired attachment history failed validation.
    #[error("attachment desired state failed: {0}")]
    Desired(#[source] Box<AttachmentDesiredStateError>),
    /// The referenced namespace allocation failed validation.
    #[error("namespace target failed: {0}")]
    NamespaceTarget(#[source] Box<NamespaceTargetError>),
    /// The protected journal rejected or could not persist the record.
    #[error(transparent)]
    Journal(#[from] JournalError),
}

impl From<AttachmentReconciliationError> for AttachmentVerificationError {
    fn from(error: AttachmentReconciliationError) -> Self {
        Self::Reconciliation(Box::new(error))
    }
}

impl From<AttachmentDesiredStateError> for AttachmentVerificationError {
    fn from(error: AttachmentDesiredStateError) -> Self {
        Self::Desired(Box::new(error))
    }
}

impl From<NamespaceTargetError> for AttachmentVerificationError {
    fn from(error: NamespaceTargetError) -> Self {
        Self::NamespaceTarget(Box::new(error))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Record {
    attachment_id: AttachmentId,
    desired_generation: u64,
    desired_record_digest: [u8; 32],
    namespace_target: DurableNamespaceTargetReferenceV1,
    assignment_epoch: u64,
    assignment_generation: u64,
    assignment_digest: [u8; 32],
    inventory_snapshot_digest: [u8; 32],
    inventory_request_id: [u8; 16],
    mount_handle: [u8; 32],
    resource_revision: u64,
    resource_kernel_boot_id: [u8; 16],
    recipe_digest: [u8; 32],
    resource_digest: [u8; 32],
    observation: ObservationRecord,
    digest: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ObservationRecord {
    unique_mount_id: u64,
    parent_mount_id: u64,
    mount_namespace_id: u64,
    device_major: u32,
    device_minor: u32,
    superblock_magic: u64,
    superblock_flags: u32,
    mount_attributes: u64,
    propagation: u64,
    root: Vec<u8>,
    mount_point: Vec<u8>,
    identity_map_digest: [u8; 32],
}

impl ObservationRecord {
    fn from_validated(observation: &ValidatedMountKernelObservation) -> Self {
        Self {
            unique_mount_id: observation.unique_mount_id(),
            parent_mount_id: observation.parent_mount_id(),
            mount_namespace_id: observation.mount_namespace_id(),
            device_major: observation.device_major(),
            device_minor: observation.device_minor(),
            superblock_magic: observation.superblock_magic(),
            superblock_flags: observation.superblock_flags(),
            mount_attributes: observation.mount_attributes(),
            propagation: observation.propagation(),
            root: observation.root().to_vec(),
            mount_point: observation.mount_point().to_vec(),
            identity_map_digest: *observation.identity_map_digest(),
        }
    }

    fn validate(&self) -> Result<(), AttachmentVerificationError> {
        if self.unique_mount_id == 0
            || self.parent_mount_id == 0
            || self.mount_namespace_id == 0
            || self.superblock_magic == 0
            || self.identity_map_digest == [0; 32]
            || !valid_kernel_path(&self.root)
            || !valid_kernel_path(&self.mount_point)
        {
            return Err(AttachmentVerificationError::CorruptState);
        }
        Ok(())
    }
}

impl Record {
    pub(crate) const fn record_digest(&self) -> [u8; 32] {
        self.digest
    }

    pub(crate) const fn mount_handle(&self) -> [u8; 32] {
        self.mount_handle
    }

    pub(crate) const fn unique_mount_id(&self) -> u64 {
        self.observation.unique_mount_id
    }

    fn from_current(
        desired: &DurableAttachmentDesiredStateV1,
        target: &CurrentNamespaceTarget,
        inventory_snapshot_digest: ObjectDigest,
        inventory_request_id: [u8; 16],
        resource: &ValidatedMountInventoryRecord,
    ) -> Result<Self, AttachmentVerificationError> {
        let binding = target.runtime_generation().scope().binding();
        let assignment = binding.manifest().manifest();
        let observation = resource
            .installed_observation()
            .ok_or(AttachmentVerificationError::NotVerifiable)?;
        let mut record = Self {
            attachment_id: desired.intent().id(),
            desired_generation: desired.intent().desired_generation().get(),
            desired_record_digest: *desired.record_digest().as_bytes(),
            namespace_target: target.durable_reference(),
            assignment_epoch: assignment.epoch().get(),
            assignment_generation: assignment.desired_generation().get(),
            assignment_digest: *binding.assignment_digest().as_bytes(),
            inventory_snapshot_digest: *inventory_snapshot_digest.as_bytes(),
            inventory_request_id,
            mount_handle: *resource.mount_handle(),
            resource_revision: resource.resource_revision(),
            resource_kernel_boot_id: *resource.resource_kernel_boot_id(),
            recipe_digest: mount_recipe_digest(resource),
            resource_digest: mount_resource_digest(resource),
            observation: ObservationRecord::from_validated(observation),
            digest: [0; 32],
        };
        record.digest = record.compute_digest();
        record.validate_contents()?;
        if !record.matches_current(desired, target, resource) {
            return Err(AttachmentVerificationError::Conflict);
        }
        Ok(record)
    }

    fn key(&self) -> Vec<u8> {
        let mut key = Vec::with_capacity(24);
        key.extend_from_slice(self.attachment_id.as_bytes());
        key.extend_from_slice(&self.desired_generation.to_be_bytes());
        key
    }

    fn encoded_len(&self) -> usize {
        format::FIXED_RECORD_BYTES
            .saturating_add(self.observation.root.len())
            .saturating_add(self.observation.mount_point.len())
    }

    fn validate_contents(&self) -> Result<(), AttachmentVerificationError> {
        if self.attachment_id.as_bytes() == &[0; 16]
            || self.desired_generation == 0
            || self.desired_record_digest == [0; 32]
            || self.assignment_epoch == 0
            || self.assignment_generation == 0
            || self.assignment_digest == [0; 32]
            || self.inventory_snapshot_digest == [0; 32]
            || self.inventory_request_id == [0; 16]
            || self.mount_handle == [0; 32]
            || self.resource_revision == 0
            || self.resource_kernel_boot_id == [0; 16]
            || self.recipe_digest == [0; 32]
            || self.resource_digest == [0; 32]
            || self.encoded_len() > MAXIMUM_RECORD_BYTES
            || self.compute_digest() != self.digest
        {
            return Err(AttachmentVerificationError::CorruptState);
        }
        self.observation.validate()
    }

    pub(crate) fn matches_current(
        &self,
        desired: &DurableAttachmentDesiredStateV1,
        target: &CurrentNamespaceTarget,
        resource: &ValidatedMountInventoryRecord,
    ) -> bool {
        let binding = target.runtime_generation().scope().binding();
        let assignment = binding.manifest().manifest();
        let resource_binding = resource.binding();
        let resource_fence = resource_binding.fence();
        self.attachment_id == desired.intent().id()
            && self.desired_generation == desired.intent().desired_generation().get()
            && self.desired_record_digest == *desired.record_digest().as_bytes()
            && self.namespace_target == target.durable_reference()
            && self.assignment_epoch == assignment.epoch().get()
            && self.assignment_generation == assignment.desired_generation().get()
            && self.assignment_digest == *binding.assignment_digest().as_bytes()
            && self.assignment_epoch == resource_fence.assignment_epoch()
            && self.assignment_generation == resource_fence.desired_generation()
            && self.assignment_digest == *resource_fence.assignment_digest()
            && self.namespace_target.sandbox().as_bytes() == resource_fence.sandbox_id()
            && self.namespace_target.incarnation().as_bytes() == resource_fence.incarnation_id()
            && self.namespace_target.target_generation() == resource_binding.namespace_generation()
            && self.mount_handle == *resource.mount_handle()
            && self.resource_revision == resource.resource_revision()
            && self.resource_kernel_boot_id == *resource.resource_kernel_boot_id()
            && self.recipe_digest == desired_recipe_digest(desired.intent())
            && self.recipe_digest == mount_recipe_digest(resource)
            && resource.lifecycle() == MountLifecycle::MOUNT_LIFECYCLE_INSTALLED
            && self.resource_digest == mount_resource_digest(resource)
            && resource.installed_observation().is_some_and(|observation| {
                self.observation == ObservationRecord::from_validated(observation)
            })
    }

    fn transaction(&self) -> Result<JournalTransaction, AttachmentVerificationError> {
        let mut transaction_id: [u8; 16] = Sha256::new()
            .chain_update(TRANSACTION_DOMAIN)
            .chain_update(self.digest)
            .finalize()[..16]
            .try_into()
            .map_err(|_| AttachmentVerificationError::CorruptState)?;
        if transaction_id == [0; 16] {
            transaction_id[15] = 1;
        }
        Ok(JournalTransaction::new(
            transaction_id,
            vec![JournalRecord::put(NAMESPACE, self.key(), self.encode())],
        )?)
    }
}

#[derive(Default)]
struct History {
    records: BTreeMap<(AttachmentId, u64), Record>,
    retained_bytes: usize,
}

impl History {
    fn load(journal: &mut Journal) -> Result<Self, AttachmentVerificationError> {
        journal.ensure_healthy()?;
        let mut records = BTreeMap::new();
        let mut retained_bytes = 0_usize;

        for (key, value) in journal.records(NAMESPACE) {
            retained_bytes = retained_bytes
                .checked_add(key.len())
                .and_then(|size| size.checked_add(value.len()))
                .ok_or(AttachmentVerificationError::Capacity)?;
            if records.len() >= MAXIMUM_VERIFICATIONS
                || retained_bytes > MAXIMUM_NAMESPACE_BYTES
                || value.len() > MAXIMUM_RECORD_BYTES
            {
                return Err(AttachmentVerificationError::Capacity);
            }

            let record = Record::decode(value)?;
            if key != record.key() {
                return Err(AttachmentVerificationError::CorruptState);
            }
            record.validate_contents()?;
            let identity = (record.attachment_id, record.desired_generation);
            if records.insert(identity, record).is_some() {
                return Err(AttachmentVerificationError::CorruptState);
            }
        }

        if !records.is_empty() {
            attachment_state::validate_namespace(journal)
                .map_err(|error| AttachmentVerificationError::Desired(Box::new(error)))?;
            validate_namespace_target_namespace(journal)
                .map_err(|error| AttachmentVerificationError::NamespaceTarget(Box::new(error)))?;
            for record in records.values() {
                validate_cross_references(journal, record)?;
            }
        }

        Ok(Self {
            records,
            retained_bytes,
        })
    }

    fn ensure_capacity(&self, record: &Record) -> Result<(), AttachmentVerificationError> {
        let next_bytes = self
            .retained_bytes
            .checked_add(record.key().len())
            .and_then(|size| size.checked_add(record.encoded_len()))
            .ok_or(AttachmentVerificationError::Capacity)?;
        if self.records.len() >= MAXIMUM_VERIFICATIONS || next_bytes > MAXIMUM_NAMESPACE_BYTES {
            return Err(AttachmentVerificationError::Capacity);
        }
        Ok(())
    }

    fn outcome(
        &self,
        record: &Record,
    ) -> Result<Option<AttachmentVerificationOutcomeV1>, AttachmentVerificationError> {
        match self
            .records
            .get(&(record.attachment_id, record.desired_generation))
        {
            Some(current) if current == record => Ok(Some(AttachmentVerificationOutcomeV1::Replay)),
            Some(_) => Err(AttachmentVerificationError::Conflict),
            None => Ok(None),
        }
    }
}

pub(crate) fn record_current<T>(
    journal: &mut Journal,
    reconciliation: CurrentAttachmentReconciliationV1,
    clock: &mut T,
) -> Result<DurableAttachmentVerificationV1, AttachmentVerificationError>
where
    T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
{
    let (evidence, target) = reconciliation.into_evidence_and_target();
    evidence.recheck(journal, &target, clock)?;
    let (mount_handle, unique_mount_id) = match evidence.action() {
        AttachmentReconciliationActionV1::Verify {
            mount_handle,
            unique_mount_id,
        } => (mount_handle, unique_mount_id),
        _ => return Err(AttachmentVerificationError::NotVerifiable),
    };
    let resource = evidence
        .snapshot()
        .inventory()
        .mounts()
        .iter()
        .find(|resource| resource.mount_handle() == &mount_handle)
        .ok_or(AttachmentVerificationError::Conflict)?;
    if resource
        .installed_observation()
        .is_none_or(|observation| observation.unique_mount_id() != unique_mount_id)
    {
        return Err(AttachmentVerificationError::Conflict);
    }

    let record = Record::from_current(
        evidence.desired(),
        &target,
        evidence.snapshot().record_digest(),
        evidence.snapshot().request_id(),
        resource,
    )?;
    let history = History::load(journal)?;
    let outcome = match history.outcome(&record)? {
        Some(outcome) => outcome,
        None => {
            history.ensure_capacity(&record)?;
            evidence.recheck(journal, &target, clock)?;
            journal.commit(&record.transaction()?)?;
            AttachmentVerificationOutcomeV1::Recorded
        }
    };

    let committed = History::load(journal)?;
    if committed
        .records
        .get(&(record.attachment_id, record.desired_generation))
        != Some(&record)
    {
        return Err(AttachmentVerificationError::CorruptState);
    }
    attachment_state::recheck_current(journal, evidence.desired())?;
    target.recheck(journal, clock)?;

    Ok(DurableAttachmentVerificationV1 { record, outcome })
}

pub(crate) fn current_record(
    journal: &mut Journal,
    desired: &DurableAttachmentDesiredStateV1,
) -> Result<Option<Record>, AttachmentVerificationError> {
    let history = History::load(journal)?;
    Ok(history
        .records
        .get(&(
            desired.intent().id(),
            desired.intent().desired_generation().get(),
        ))
        .filter(|record| record.desired_record_digest == *desired.record_digest().as_bytes())
        .cloned())
}

pub(crate) fn validate_namespace(journal: &mut Journal) -> Result<(), AttachmentVerificationError> {
    History::load(journal).map(|_| ())
}

fn validate_cross_references(
    journal: &mut Journal,
    record: &Record,
) -> Result<(), AttachmentVerificationError> {
    validate_durable_reference_in_validated_namespace(journal, record.namespace_target)
        .map_err(|error| AttachmentVerificationError::NamespaceTarget(Box::new(error)))?;
    let desired =
        attachment_state::get_generation(journal, record.attachment_id, record.desired_generation)?
            .ok_or(AttachmentVerificationError::CorruptState)?;
    let (consumer_sandbox, consumer_incarnation) = desired.intent().consumer();
    if desired.presence() != AttachmentDesiredPresenceV1::Present
        || desired.record_digest().as_bytes() != &record.desired_record_digest
        || consumer_sandbox != record.namespace_target.sandbox()
        || consumer_incarnation != record.namespace_target.incarnation()
        || desired.intent().expected_namespace_generation().get()
            != record.namespace_target.target_generation()
        || desired_recipe_digest(desired.intent()) != record.recipe_digest
    {
        return Err(AttachmentVerificationError::CorruptState);
    }
    Ok(())
}

pub(crate) fn mount_resource_digest(resource: &ValidatedMountInventoryRecord) -> [u8; 32] {
    let binding = resource.binding();
    let fence = binding.fence();
    let recipe = resource.recipe();
    let descriptor = recipe.view_revision();
    let attributes = recipe.attributes();
    let observation = resource.installed_observation();
    let publication = resource.publication();
    let mut digest = Sha256::new();

    digest.update(RESOURCE_DOMAIN);
    digest.update(resource.mount_handle());
    digest.update(resource.resource_revision().to_be_bytes());
    digest.update(fence.sandbox_id());
    digest.update(fence.incarnation_id());
    digest.update(fence.assignment_epoch().to_be_bytes());
    digest.update(fence.desired_generation().to_be_bytes());
    digest.update(fence.assignment_digest());
    digest.update(binding.namespace_generation().to_be_bytes());
    digest.update(recipe.attachment_id());
    digest.update(recipe.destination_slot_id());
    update_bytes(&mut digest, descriptor.media_type().as_str().as_bytes());
    digest.update(descriptor.digest().as_bytes());
    digest.update(descriptor.encoded_size().to_be_bytes());
    digest.update(recipe.source_generation().to_be_bytes());
    digest.update(recipe.resource_attachment_generation().to_be_bytes());
    digest.update(recipe.source_view_id());
    update_optional_fixed(&mut digest, recipe.source_incarnation_id());
    digest.update((recipe.source_consistency() as i32).to_be_bytes());
    digest.update([
        u8::from(attributes.read_only()),
        u8::from(attributes.no_exec()),
        u8::from(attributes.no_suid()),
        u8::from(attributes.no_device()),
        u8::from(attributes.no_atime()),
        u8::from(attributes.recursive()),
    ]);
    digest.update(attributes.mutation_mode().to_be_bytes());
    digest.update((resource.lifecycle() as i32).to_be_bytes());
    digest.update(resource.resource_kernel_boot_id());
    update_optional_u64(&mut digest, resource.detached_unique_mount_id());
    update_observation(&mut digest, observation);
    update_operation(&mut digest, resource.creation());
    update_operation(&mut digest, resource.detachment());
    update_operation(&mut digest, resource.release());
    match publication {
        Some(publication) => {
            digest.update([1]);
            digest.update(publication.operation_id());
            digest.update(publication.request_digest());
            digest.update(publication.target_mount_namespace_id().to_be_bytes());
            digest.update(publication.target_namespace_generation().to_be_bytes());
            update_optional_fixed(&mut digest, publication.replaces_mount_handle());
        }
        None => digest.update([0]),
    }
    update_optional_fixed(&mut digest, resource.replaced_by_mount_handle());
    match resource.fault() {
        Some(fault) => {
            digest.update([1]);
            digest.update((fault.from() as i32).to_be_bytes());
            digest.update(fault.failure_digest());
        }
        None => digest.update([0]),
    }
    update_optional_u64(&mut digest, resource.last_installed_unique_mount_id());
    digest.finalize().into()
}

fn mount_recipe_digest(resource: &ValidatedMountInventoryRecord) -> [u8; 32] {
    let recipe = resource.recipe();
    let descriptor = recipe.view_revision();
    let attributes = recipe.attributes();
    let mut digest = Sha256::new();

    digest.update(RECIPE_DOMAIN);
    digest.update(recipe.attachment_id());
    digest.update(recipe.destination_slot_id());
    update_bytes(&mut digest, descriptor.media_type().as_str().as_bytes());
    digest.update(descriptor.digest().as_bytes());
    digest.update(descriptor.encoded_size().to_be_bytes());
    digest.update(recipe.source_generation().to_be_bytes());
    digest.update(recipe.resource_attachment_generation().to_be_bytes());
    digest.update(recipe.source_view_id());
    update_optional_fixed(&mut digest, recipe.source_incarnation_id());
    digest.update((recipe.source_consistency() as i32).to_be_bytes());
    digest.update([
        u8::from(attributes.read_only()),
        u8::from(attributes.no_exec()),
        u8::from(attributes.no_suid()),
        u8::from(attributes.no_device()),
        u8::from(attributes.no_atime()),
        u8::from(attributes.recursive()),
    ]);
    digest.update(attributes.mutation_mode().to_be_bytes());
    digest.finalize().into()
}

fn desired_recipe_digest(intent: &AttachmentIntent) -> [u8; 32] {
    let descriptor = intent.view();
    let (source_view, source_generation) = intent.source_view();
    let attributes = intent.mount_attributes();
    let source_consistency = match intent.consistency() {
        AttachmentConsistency::ImmutableRevision => {
            MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_IMMUTABLE_REVISION
        }
        AttachmentConsistency::LocalLive => {
            MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_LOCAL_LIVE
        }
        AttachmentConsistency::BestEffortReplica => {
            MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_BEST_EFFORT_REPLICA
        }
        AttachmentConsistency::TransactionalService => {
            MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_TRANSACTIONAL_SERVICE
        }
    };
    let mutation_mode = match intent.mutation() {
        ViewMutation::ReadOnly => 0_u32,
        ViewMutation::ReadWrite => 1,
        ViewMutation::PrivateCow => 2,
        ViewMutation::AppendOnly => 3,
        ViewMutation::Service => 4,
    };
    let mut digest = Sha256::new();

    digest.update(RECIPE_DOMAIN);
    digest.update(intent.id().as_bytes());
    digest.update(intent.destination_slot().as_bytes());
    update_bytes(&mut digest, descriptor.media_type().as_str().as_bytes());
    digest.update(descriptor.digest().as_bytes());
    digest.update(descriptor.encoded_size().to_be_bytes());
    digest.update(source_generation.get().to_be_bytes());
    digest.update(intent.desired_generation().get().to_be_bytes());
    digest.update(source_view.as_bytes());
    update_optional_fixed(
        &mut digest,
        intent
            .source_incarnation()
            .as_ref()
            .map(aos_sandbox_core::IncarnationId::as_bytes),
    );
    digest.update((source_consistency as i32).to_be_bytes());
    digest.update([
        u8::from(attributes.read_only()),
        u8::from(attributes.no_exec()),
        u8::from(attributes.no_suid()),
        u8::from(attributes.no_dev()),
        u8::from(attributes.no_atime()),
        u8::from(attributes.recursive()),
    ]);
    digest.update(mutation_mode.to_be_bytes());
    digest.finalize().into()
}

fn update_observation(digest: &mut Sha256, observation: Option<&ValidatedMountKernelObservation>) {
    let Some(observation) = observation else {
        digest.update([0]);
        return;
    };
    digest.update([1]);
    digest.update(observation.unique_mount_id().to_be_bytes());
    digest.update(observation.parent_mount_id().to_be_bytes());
    digest.update(observation.mount_namespace_id().to_be_bytes());
    digest.update(observation.device_major().to_be_bytes());
    digest.update(observation.device_minor().to_be_bytes());
    digest.update(observation.superblock_magic().to_be_bytes());
    digest.update(observation.superblock_flags().to_be_bytes());
    digest.update(observation.mount_attributes().to_be_bytes());
    digest.update(observation.propagation().to_be_bytes());
    update_bytes(digest, observation.root());
    update_bytes(digest, observation.mount_point());
    digest.update(observation.identity_map_digest());
}

fn update_operation(
    digest: &mut Sha256,
    operation: Option<aos_sandbox_protocol::ValidatedMountOperationCorrelation>,
) {
    match operation {
        Some(operation) => {
            digest.update([1]);
            digest.update(operation.operation_id());
            digest.update(operation.request_digest());
        }
        None => digest.update([0]),
    }
}

fn update_optional_fixed<const N: usize>(digest: &mut Sha256, value: Option<&[u8; N]>) {
    match value {
        Some(value) => {
            digest.update([1]);
            digest.update(value);
        }
        None => digest.update([0]),
    }
}

fn update_optional_u64(digest: &mut Sha256, value: Option<u64>) {
    match value {
        Some(value) => {
            digest.update([1]);
            digest.update(value.to_be_bytes());
        }
        None => digest.update([0]),
    }
}

fn update_bytes(digest: &mut Sha256, value: &[u8]) {
    digest.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    digest.update(value);
}

fn valid_kernel_path(value: &[u8]) -> bool {
    !value.is_empty() && value.len() <= MAXIMUM_KERNEL_PATH_BYTES && !value.contains(&0)
}

#[cfg(test)]
mod tests;
