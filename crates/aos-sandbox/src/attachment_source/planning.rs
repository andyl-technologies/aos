//! Compiles one exact, nonauthorizing attachment-source custody plan.
//!
//! ```text
//! AOSASP01 | version:2 | attachment:16 | desired-generation:8 |
//! desired-digest:32 | desired-presence:1 | sandbox:16 | incarnation:16 |
//! assignment-epoch:8 | assignment-generation:8 | assignment-digest:32 |
//! namespace-generation:8 | allocation-digest:32 | policy-identity:32 |
//! attachment-lease-id:16 | lease-issued:8 | lease-expires:8 |
//! source-view-id:16 | source-revision:8 | view-identity:32 |
//! source-binding-digest:32 | pre-catalog-template-digest:32 |
//! source-lease-seconds:8 | maximum-submounts:4 | kernel-coupled:1 |
//! resource-snapshot-digest:32 | source-snapshot-digest:32 |
//! kernel-boot-id:16 | broker-instance-id:16 | journal-sequence:8 |
//! selected-acquisition:74 | selected-resource:42 | verification-digest:32 |
//! action:1
//! ```
//!
//! The encoding is exactly 637 bytes and all integers are big endian. Optional
//! selections use a one-byte presence marker followed by zero-filled fixed
//! storage. Action codes 1 through 13 cover AwaitLease, Acquire,
//! AwaitAcquisition, CompleteAcquire, Consume, AwaitAttachment,
//! CompleteConsume, Ready, DrainAttachment, Release, AwaitRelease,
//! CompleteRelease, and Released in that order. Code 14 is CancelAcquire.
//! SHA-256 uses the
//! `aos.sandbox.attachment-source-plan.v1\0` domain.

use aos_proto::aos::sandbox::local::v1::{
    ApplyMountRequest, Audience, Descriptor, MountAction, MountAttributes as WireMountAttributes,
    MountLifecycle, MountSourceAcquisitionPhase, MountSourceConsistency, MountSourceProofClass,
    RequestHeader,
};
use aos_sandbox_core::model::{AttachmentConsistency, AttachmentIntent, ViewMutation};
use aos_sandbox_core::{ObjectDescriptor, ObjectDigest, RawPairedClockSample};
use aos_sandbox_protocol::semantics::canonical_precatalog_mount_create_template_v1;
use aos_sandbox_protocol::{
    PeerCredentials, PeerPolicy, SourceRealizationBindingV1, ValidatedMountInventoryRecord,
    ValidatedMountSourceAcquisitionRecord, decode_mount_request,
};
use buffa::Message as _;
use sha2::{Digest as _, Sha256};

use crate::attachment_source::custody::{AcquisitionLineage, CustodyHistory};
use crate::attachment_state::{
    self, AttachmentDesiredPresenceV1, AttachmentDesiredStateError, DurableAttachmentDesiredStateV1,
};
use crate::attachment_verification::{self, AttachmentVerificationError};
use crate::filesystem_view_state::{
    self, FilesystemViewRevisionPresenceV1, FilesystemViewRevisionStateError,
};
use crate::mount_observation_state::{
    CurrentMountFilesystemInventoryV1, MountFilesystemInventoryError,
};
use crate::ownership_authority::ProtectedOwnershipClockError;
use crate::runtime_scope::{CurrentNamespaceTarget, NamespaceTargetError};
use crate::{Journal, JournalError};

const PLAN_MAGIC: &[u8; 8] = b"AOSASP01";
pub(super) const PLAN_DOMAIN: &[u8] = b"aos.sandbox.attachment-source-plan.v1\0";
const PLAN_VERSION: u16 = 1;
const MOUNT_RESPONSE_BYTES: u32 = 16 * 1024;

/// Bounds provider custody requested for an attachment source.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AttachmentSourceBoundsV1 {
    lease_seconds: u64,
    maximum_submounts: u32,
    kernel_coupled: bool,
}

impl AttachmentSourceBoundsV1 {
    /// Constructs one closed source-acquisition bound.
    ///
    /// # Errors
    ///
    /// Rejects a zero or protocol-excessive lease, an excessive topology
    /// ceiling, or a kernel-coupling choice inconsistent with the attachment.
    pub fn new(
        intent: &AttachmentIntent,
        lease_seconds: u64,
        maximum_submounts: u32,
    ) -> Result<Self, AttachmentSourceError> {
        if lease_seconds == 0
            || lease_seconds > aos_sandbox_source_provider_protocol::MAXIMUM_SOURCE_LEASE_SECONDS
            || maximum_submounts > aos_sandbox_source_provider_protocol::MAXIMUM_SOURCE_SUBMOUNTS
            || (!intent.mount_attributes().recursive() && maximum_submounts != 0)
        {
            return Err(AttachmentSourceError::InvalidBounds);
        }
        Ok(Self {
            lease_seconds,
            maximum_submounts,
            kernel_coupled: intent.consistency() == AttachmentConsistency::LocalLive,
        })
    }

    /// Returns the requested provider lease duration.
    #[must_use]
    pub const fn lease_seconds(self) -> u64 {
        self.lease_seconds
    }

    /// Returns the maximum admitted source-submount count.
    #[must_use]
    pub const fn maximum_submounts(self) -> u32 {
        self.maximum_submounts
    }

    /// Reports whether live kernel identity coupling is required.
    #[must_use]
    pub const fn kernel_coupled(self) -> bool {
        self.kernel_coupled
    }

    fn validate(self, intent: &AttachmentIntent) -> Result<(), AttachmentSourceError> {
        if self.lease_seconds == 0
            || self.lease_seconds
                > aos_sandbox_source_provider_protocol::MAXIMUM_SOURCE_LEASE_SECONDS
            || self.maximum_submounts
                > aos_sandbox_source_provider_protocol::MAXIMUM_SOURCE_SUBMOUNTS
            || (!intent.mount_attributes().recursive() && self.maximum_submounts != 0)
            || self.kernel_coupled != (intent.consistency() == AttachmentConsistency::LocalLive)
        {
            return Err(AttachmentSourceError::InvalidBounds);
        }
        Ok(())
    }
}

/// Selects one source-custody conclusion without granting an effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttachmentSourceActionV1 {
    /// The attachment lease has not reached its issue time.
    AwaitLease { issued_seconds: i64 },
    /// No exact source acquisition exists and one may be durably attempted.
    Acquire,
    /// Mount is still acquiring or establishing PID 1 custody.
    AwaitAcquisition {
        acquisition_id: [u8; 32],
        phase: MountSourceAcquisitionPhase,
    },
    /// A rowless Acquire is terminally canceled by release or supersession.
    CancelAcquire { acquisition_id: [u8; 32] },
    /// Exact Active source evidence may close Acquire custody.
    CompleteAcquire {
        acquisition_id: [u8; 32],
        revision: u64,
        record_digest: [u8; 32],
    },
    /// One exact Active acquisition may be consumed by detached creation.
    Consume {
        acquisition_id: [u8; 32],
        revision: u64,
        record_digest: [u8; 32],
    },
    /// The consumed source has an attachment transition not yet verified.
    AwaitAttachment {
        acquisition_id: [u8; 32],
        mount_handle: [u8; 32],
        lifecycle: MountLifecycle,
        /// Whether the exact detached-create receipt is durably custodied.
        consume_attempt_recorded: bool,
    },
    /// Exact receipt and post-attach evidence may close Consume custody.
    CompleteConsume {
        acquisition_id: [u8; 32],
        mount_handle: [u8; 32],
        lifecycle: MountLifecycle,
        verification_digest: Option<[u8; 32]>,
    },
    /// Exact source, resource, and post-attach evidence are complete.
    Ready {
        acquisition_id: [u8; 32],
        mount_handle: [u8; 32],
        verification_digest: [u8; 32],
    },
    /// An attachment resource must drain before provider custody is released.
    DrainAttachment {
        acquisition_id: [u8; 32],
        mount_handle: [u8; 32],
        lifecycle: MountLifecycle,
    },
    /// The exact acquisition may be submitted for release.
    Release {
        acquisition_id: [u8; 32],
        revision: u64,
        record_digest: [u8; 32],
    },
    /// Mount is durably releasing the exact acquisition.
    AwaitRelease { acquisition_id: [u8; 32] },
    /// Exact Released inventory may close Release custody.
    CompleteRelease {
        acquisition_id: [u8; 32],
        revision: u64,
        record_digest: [u8; 32],
    },
    /// Neither Mount resource nor source custody remains.
    Released,
}

/// Retains one current pure plan and the inputs needed to recheck it.
pub struct CurrentAttachmentSourcePlanV1 {
    pub(super) desired: DurableAttachmentDesiredStateV1,
    pub(super) inventory: CurrentMountFilesystemInventoryV1,
    pub(super) target: CurrentNamespaceTarget,
    pub(super) bounds: AttachmentSourceBoundsV1,
    pub(super) plan: CanonicalPlan,
    pub(super) action: AttachmentSourceActionV1,
}

impl CurrentAttachmentSourcePlanV1 {
    /// Borrows the exact current desired attachment generation.
    #[must_use]
    pub const fn desired(&self) -> &DurableAttachmentDesiredStateV1 {
        &self.desired
    }

    /// Returns the closed nonauthorizing source-custody action.
    #[must_use]
    pub const fn action(&self) -> AttachmentSourceActionV1 {
        self.action
    }

    /// Returns the digest of the complete canonical source plan.
    #[must_use]
    pub const fn plan_digest(&self) -> ObjectDigest {
        ObjectDigest::from_bytes(self.plan.digest)
    }

    /// Borrows the bounded canonical plan bytes retained by an attempt.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.plan.bytes
    }

    /// Returns the live target and resource snapshot for a following Mount decision.
    ///
    /// Consuming this nonauthorizing source plan does not grant a Mount effect;
    /// resource reconciliation must independently recheck both returned inputs.
    #[must_use]
    pub fn into_mount_reconciliation_inputs(
        self,
    ) -> (
        CurrentNamespaceTarget,
        crate::mount_attempt::DurableMountInventorySnapshotV1,
    ) {
        (self.target, self.inventory.into_resources())
    }

    pub(super) fn recheck<T>(
        &self,
        journal: &mut Journal,
        clock: &mut T,
    ) -> Result<(), AttachmentSourceError>
    where
        T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        let (plan, action) = compile(
            journal,
            &self.desired,
            &self.inventory,
            &self.target,
            self.bounds,
            clock,
        )?;
        if plan != self.plan || action != self.action {
            return Err(AttachmentSourceError::Changed);
        }
        Ok(())
    }
}

/// Reports stale, conflicting, abandoned, or malformed source custody.
#[derive(Debug, thiserror::Error)]
pub enum AttachmentSourceError {
    /// Requested provider lease/topology bounds are invalid.
    #[error("attachment source-acquisition bounds are invalid")]
    InvalidBounds,
    /// The desired source is not a native Mount source.
    #[error("attachment source is not supported by Mount source acquisition")]
    UnsupportedSource,
    /// Exact source, resource, assignment, or predecessor evidence conflicts.
    #[error("attachment source evidence conflicts with current state")]
    Conflict,
    /// Mount reports consumption without the exact retained resource evidence.
    #[error("attachment source custody was abandoned or became untrackable")]
    Abandoned,
    /// A source acquisition or Mount resource is faulted.
    #[error("attachment source or Mount resource is faulted")]
    Faulted,
    /// A recheck selected different current evidence or action.
    #[error("attachment source plan changed before use")]
    Changed,
    /// Attempt/completion history is malformed or exceeds its fixed bound.
    #[error("attachment source custody history is corrupt")]
    CorruptState,
    /// Attempt/completion history exhausted its fixed bound.
    #[error("attachment source custody history capacity is exhausted")]
    Capacity,
    /// Desired attachment history is unavailable or stale.
    #[error(transparent)]
    Desired(#[from] AttachmentDesiredStateError),
    /// Filesystem-view history is unavailable or stale.
    #[error(transparent)]
    View(#[from] FilesystemViewRevisionStateError),
    /// The joined Mount observation is stale or mismatched.
    #[error(transparent)]
    Inventory(#[from] MountFilesystemInventoryError),
    /// Post-attach verification history is unavailable or contradictory.
    #[error("attachment verification failed: {0}")]
    Verification(#[from] AttachmentVerificationError),
    /// Live namespace authority is stale.
    #[error(transparent)]
    Target(#[from] NamespaceTargetError),
    /// Protected wall/BOOTTIME sampling failed.
    #[error(transparent)]
    Clock(#[from] ProtectedOwnershipClockError),
    /// Canonical protocol compilation rejected the desired source.
    #[error("attachment source protocol projection is invalid")]
    Protocol,
    /// Protected journal provenance or durability failed.
    #[error(transparent)]
    Journal(#[from] JournalError),
    /// Durable Mount attempt or completion custody is corrupt.
    #[error(transparent)]
    MountAttempt(#[from] crate::MountAttemptError),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct CanonicalPlan {
    pub(super) bytes: Vec<u8>,
    pub(super) digest: [u8; 32],
    pub(super) attachment_id: [u8; 16],
    pub(super) desired_generation: u64,
    pub(super) desired_digest: [u8; 32],
    pub(super) custody_desired_generation: u64,
    pub(super) custody_desired_digest: [u8; 32],
    pub(super) source_binding_digest: [u8; 32],
    pub(super) template_digest: [u8; 32],
    pub(super) sandbox: [u8; 16],
    pub(super) incarnation: [u8; 16],
    pub(super) assignment_epoch: u64,
    pub(super) assignment_generation: u64,
    pub(super) assignment_digest: [u8; 32],
    pub(super) bounds: AttachmentSourceBoundsV1,
    pub(super) resource_snapshot_digest: [u8; 32],
    pub(super) source_snapshot_digest: [u8; 32],
    pub(super) acquisition_id: Option<[u8; 32]>,
    pub(super) acquisition_revision: Option<u64>,
    pub(super) acquisition_record_digest: Option<[u8; 32]>,
    pub(super) acquisition_phase: Option<MountSourceAcquisitionPhase>,
    pub(super) mount_handle: Option<[u8; 32]>,
    pub(super) resource_revision: Option<u64>,
    pub(super) resource_lifecycle: Option<MountLifecycle>,
    pub(super) verification_digest: Option<[u8; 32]>,
}

pub(crate) fn plan_current<T>(
    journal: &mut Journal,
    desired: DurableAttachmentDesiredStateV1,
    inventory: CurrentMountFilesystemInventoryV1,
    target: CurrentNamespaceTarget,
    bounds: AttachmentSourceBoundsV1,
    clock: &mut T,
) -> Result<CurrentAttachmentSourcePlanV1, AttachmentSourceError>
where
    T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
{
    let (plan, action) = compile(journal, &desired, &inventory, &target, bounds, clock)?;
    Ok(CurrentAttachmentSourcePlanV1 {
        desired,
        inventory,
        target,
        bounds,
        plan,
        action,
    })
}

fn compile<T>(
    journal: &mut Journal,
    desired: &DurableAttachmentDesiredStateV1,
    inventory: &CurrentMountFilesystemInventoryV1,
    target: &CurrentNamespaceTarget,
    bounds: AttachmentSourceBoundsV1,
    clock: &mut T,
) -> Result<(CanonicalPlan, AttachmentSourceActionV1), AttachmentSourceError>
where
    T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
{
    journal.ensure_protected_authority()?;
    inventory.recheck(journal)?;
    target.recheck(journal, clock)?;
    attachment_state::recheck_current(journal, desired)?;

    let sample = clock()?;
    let intent = desired.intent();
    bounds.validate(intent)?;
    let lease = intent.lease();
    let release_requested = desired.presence() == AttachmentDesiredPresenceV1::Released
        || sample.wall_seconds() >= lease.expires_seconds();
    let history = CustodyHistory::load(journal)?;
    let projection = source_projection(journal, intent, target, sample);
    let (binding_digest, template_digest) = match projection {
        Ok((binding, template_digest)) => (binding.digest(), template_digest),
        Err(AttachmentSourceError::UnsupportedSource) => {
            let outstanding = history.outstanding_acquisitions(*intent.id().as_bytes());
            let mut acquisitions = outstanding.iter().copied();
            let Some(acquisition_id) = acquisitions.next() else {
                return Err(AttachmentSourceError::UnsupportedSource);
            };
            if acquisitions.next().is_some() {
                return Err(AttachmentSourceError::Conflict);
            }
            let lineage = history.lineage(*intent.id().as_bytes(), acquisition_id)?;
            (
                ObjectDigest::from_bytes(lineage.binding_digest),
                ObjectDigest::from_bytes(lineage.template_digest),
            )
        }
        Err(error) => return Err(error),
    };
    let target_facts = TargetFacts::new(target);
    let selected = select_evidence(
        inventory,
        intent,
        *desired.record_digest().as_bytes(),
        target_facts,
        binding_digest,
        template_digest,
        bounds,
        release_requested,
        &history,
    )?;
    let action = decide(
        journal,
        desired,
        target,
        selected,
        release_requested,
        sample.wall_seconds(),
    )?;
    let plan_bounds = selected
        .lineage
        .map_or(bounds, |lineage| AttachmentSourceBoundsV1 {
            lease_seconds: lineage.lease_seconds,
            maximum_submounts: lineage.maximum_submounts,
            kernel_coupled: lineage.kernel_coupled,
        });
    let plan = CanonicalPlan::new(
        desired,
        inventory,
        target,
        plan_bounds,
        ObjectDigest::from_bytes(
            selected
                .lineage
                .map_or(*binding_digest.as_bytes(), |lineage| lineage.binding_digest),
        ),
        ObjectDigest::from_bytes(
            selected
                .lineage
                .map_or(*template_digest.as_bytes(), |lineage| {
                    lineage.template_digest
                }),
        ),
        selected,
        action,
    )?;

    attachment_state::recheck_current(journal, desired)?;
    target.recheck(journal, clock)?;
    inventory.recheck(journal)?;
    Ok((plan, action))
}

#[derive(Clone, Copy)]
struct TargetFacts {
    sandbox: [u8; 16],
    incarnation: [u8; 16],
    epoch: u64,
    generation: u64,
    digest: [u8; 32],
    namespace_generation: u64,
    allocation_digest: [u8; 32],
    policy_identity: [u8; 32],
}

impl TargetFacts {
    fn new(target: &CurrentNamespaceTarget) -> Self {
        let binding = target.runtime_generation().scope().binding();
        let assignment = binding.manifest().manifest();
        Self {
            sandbox: *assignment.sandbox().as_bytes(),
            incarnation: *assignment.incarnation().as_bytes(),
            epoch: assignment.epoch().get(),
            generation: assignment.desired_generation().get(),
            digest: *binding.assignment_digest().as_bytes(),
            namespace_generation: target.target_generation(),
            allocation_digest: *target.allocation_digest(),
            policy_identity: descriptor_identity_digest(assignment.policy()),
        }
    }
}

#[derive(Clone, Copy)]
struct SelectedEvidence<'a> {
    acquisition: Option<&'a ValidatedMountSourceAcquisitionRecord>,
    pending_acquisition_id: Option<[u8; 32]>,
    resource: Option<&'a ValidatedMountInventoryRecord>,
    cleanup: bool,
    acquire_completed: bool,
    consume_attempted: bool,
    consume_completed: bool,
    release_attempted: bool,
    lineage: Option<AcquisitionLineage>,
    cancel_acquire: bool,
}

fn select_evidence<'a>(
    inventory: &'a CurrentMountFilesystemInventoryV1,
    intent: &AttachmentIntent,
    desired_digest: [u8; 32],
    target: TargetFacts,
    binding_digest: ObjectDigest,
    template_digest: ObjectDigest,
    bounds: AttachmentSourceBoundsV1,
    release_requested: bool,
    history: &CustodyHistory,
) -> Result<SelectedEvidence<'a>, AttachmentSourceError> {
    let attachment_id = *intent.id().as_bytes();
    let mut current_acquisitions = inventory
        .source_acquisitions()
        .inventory()
        .acquisitions()
        .iter()
        .filter(|row| {
            acquisition_matches(
                row,
                target,
                intent.consistency(),
                binding_digest,
                template_digest,
            ) && row.phase() != MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_RELEASED
        });
    let current_acquisition = current_acquisitions.next();
    if current_acquisitions.next().is_some()
        || inventory
            .source_acquisitions()
            .inventory()
            .acquisitions()
            .iter()
            .any(|row| {
                acquisition_matches(
                    row,
                    target,
                    intent.consistency(),
                    binding_digest,
                    template_digest,
                ) && !history.matches_acquisition(
                    attachment_id,
                    *row.acquisition_id(),
                    *row.acquire_operation_id(),
                    *row.acquire_request_digest(),
                )
            })
    {
        return Err(AttachmentSourceError::Conflict);
    }

    let outstanding = history.outstanding_acquisitions(attachment_id);
    if inventory
        .source_acquisitions()
        .inventory()
        .acquisitions()
        .iter()
        .any(|row| history.was_cancelled(attachment_id, *row.acquisition_id()))
    {
        return Err(AttachmentSourceError::Conflict);
    }
    let current_id = current_acquisition.map(|row| *row.acquisition_id());
    let pending_current_id = history.open_current_acquire(
        attachment_id,
        intent.desired_generation().get(),
        desired_digest,
    );
    let open_acquire = history.open_acquire(attachment_id);
    let open_acquisition_id = open_acquire.map(|attempt| attempt.acquisition_id);
    let prior_ids = outstanding
        .iter()
        .copied()
        .filter(|acquisition_id| {
            Some(*acquisition_id) != current_id && Some(*acquisition_id) != pending_current_id
        })
        .collect::<Vec<_>>();
    if prior_ids.len() > 1 || pending_current_id.is_some() && !prior_ids.is_empty() {
        return Err(AttachmentSourceError::Conflict);
    }
    let prior_acquisition = prior_ids.first().and_then(|acquisition_id| {
        inventory
            .source_acquisitions()
            .inventory()
            .acquisitions()
            .iter()
            .find(|row| row.acquisition_id() == acquisition_id)
    });
    let rowless_prior = prior_ids
        .first()
        .copied()
        .filter(|acquisition_id| Some(*acquisition_id) == open_acquisition_id)
        .filter(|_| prior_acquisition.is_none());
    if !prior_ids.is_empty() && prior_acquisition.is_none() && rowless_prior.is_none() {
        return Err(AttachmentSourceError::Abandoned);
    }
    let cleanup = prior_acquisition.is_some() || rowless_prior.is_some();
    let acquisition = prior_acquisition.or(current_acquisition);
    if acquisition.is_some_and(|row| {
        !history.matches_acquisition(
            attachment_id,
            *row.acquisition_id(),
            *row.acquire_operation_id(),
            *row.acquire_request_digest(),
        ) || matches!(
            row.phase(),
            MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_RELEASING
                | MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_RELEASED
        ) && match (row.release_operation_id(), row.release_request_digest()) {
            (Some(operation_id), Some(request_digest)) => !history.matches_release(
                attachment_id,
                *row.acquisition_id(),
                *operation_id,
                *request_digest,
            ),
            _ => true,
        }
    }) {
        return Err(AttachmentSourceError::Conflict);
    }
    let pending_acquisition_id = if acquisition.is_none() {
        rowless_prior.or(pending_current_id)
    } else {
        None
    };
    let lineage = acquisition
        .map(|row| *row.acquisition_id())
        .or(pending_acquisition_id)
        .map(|acquisition_id| history.lineage(attachment_id, acquisition_id))
        .transpose()?;
    let cancel_acquire = pending_acquisition_id.is_some_and(|acquisition_id| {
        release_requested
            || lineage.is_none_or(|lineage| {
                lineage.acquisition_id != acquisition_id
                    || lineage.desired_generation != intent.desired_generation().get()
                    || lineage.desired_digest != desired_digest
                    || lineage.lease_seconds != bounds.lease_seconds
                    || lineage.maximum_submounts != bounds.maximum_submounts
                    || lineage.kernel_coupled != bounds.kernel_coupled
                    || lineage.binding_digest != *binding_digest.as_bytes()
                    || lineage.template_digest != *template_digest.as_bytes()
                    || !lineage_matches_target(lineage, target)
            })
    });
    if lineage
        .is_some_and(|lineage| acquisition.is_some_and(|row| !lineage_matches_row(lineage, row)))
    {
        return Err(AttachmentSourceError::Conflict);
    }
    let custodied_mount_handle = acquisition
        .and_then(|row| history.completed_mount_handle(attachment_id, *row.acquisition_id()));

    let mut matching_resources =
        inventory
            .resources()
            .inventory()
            .mounts()
            .iter()
            .filter(|resource| {
                resource.recipe().attachment_id() == intent.id().as_bytes()
                    && acquisition.is_some_and(|row| resource_matches_acquisition(resource, row))
                    && custodied_mount_handle
                        .is_none_or(|mount_handle| resource.mount_handle() == &mount_handle)
                    && (cleanup
                        || resource_matches_intent(resource, intent, binding_digest, target))
            });
    let resource = matching_resources.next();
    if matching_resources.next().is_some()
        || inventory
            .resources()
            .inventory()
            .mounts()
            .iter()
            .any(|candidate| {
                candidate.recipe().attachment_id() == intent.id().as_bytes()
                    && candidate.recipe().resource_attachment_generation()
                        == intent.desired_generation().get()
                    && resource
                        .is_none_or(|selected| selected.mount_handle() != candidate.mount_handle())
            })
    {
        return Err(AttachmentSourceError::Conflict);
    }
    Ok(SelectedEvidence {
        acquisition,
        pending_acquisition_id,
        resource,
        cleanup,
        acquire_completed: acquisition.is_some_and(|row| {
            history.has_completion(
                attachment_id,
                *row.acquisition_id(),
                crate::AttachmentSourceAttemptKindV1::Acquire,
            )
        }),
        consume_attempted: acquisition.is_some_and(|row| {
            history.has_attempt(
                attachment_id,
                *row.acquisition_id(),
                crate::AttachmentSourceAttemptKindV1::Consume,
            )
        }),
        consume_completed: acquisition.is_some_and(|row| {
            history.has_completion(
                attachment_id,
                *row.acquisition_id(),
                crate::AttachmentSourceAttemptKindV1::Consume,
            )
        }),
        release_attempted: acquisition.is_some_and(|row| {
            history.has_attempt(
                attachment_id,
                *row.acquisition_id(),
                crate::AttachmentSourceAttemptKindV1::Release,
            )
        }),
        lineage,
        cancel_acquire,
    })
}

fn decide(
    journal: &mut Journal,
    desired: &DurableAttachmentDesiredStateV1,
    target: &CurrentNamespaceTarget,
    selected: SelectedEvidence<'_>,
    release_requested: bool,
    now_seconds: i64,
) -> Result<AttachmentSourceActionV1, AttachmentSourceError> {
    let intent = desired.intent();
    let source_faulted = selected.acquisition.is_some_and(|acquisition| {
        acquisition.phase() == MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_FAULTED
    });
    let resource_faulted = selected
        .resource
        .is_some_and(|resource| resource.lifecycle() == MountLifecycle::MOUNT_LIFECYCLE_FAULTED);
    let must_release = release_requested || selected.cleanup || source_faulted || resource_faulted;
    if !must_release && now_seconds < intent.lease().issued_seconds() {
        return Ok(AttachmentSourceActionV1::AwaitLease {
            issued_seconds: intent.lease().issued_seconds(),
        });
    }
    let Some(acquisition) = selected.acquisition else {
        if let Some(acquisition_id) = selected.pending_acquisition_id {
            if selected.cancel_acquire {
                return Ok(AttachmentSourceActionV1::CancelAcquire { acquisition_id });
            }
            return Ok(AttachmentSourceActionV1::AwaitAcquisition {
                acquisition_id,
                phase: MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_UNSPECIFIED,
            });
        }
        return if must_release {
            Ok(AttachmentSourceActionV1::Released)
        } else {
            Ok(AttachmentSourceActionV1::Acquire)
        };
    };
    let acquisition_id = *acquisition.acquisition_id();
    match acquisition.phase() {
        MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_PENDING_QUERY
        | MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_DESCRIPTOR_CUSTODIED => {
            if selected.consume_attempted || selected.consume_completed {
                return Err(AttachmentSourceError::Conflict);
            }
            if must_release {
                // The exact pre-active row first closes Acquire custody, then
                // becomes the predecessor evidence for this Release action.
                return if selected.release_attempted {
                    Ok(AttachmentSourceActionV1::AwaitRelease { acquisition_id })
                } else {
                    Ok(AttachmentSourceActionV1::Release {
                        acquisition_id,
                        revision: acquisition.revision(),
                        record_digest: *acquisition.record_digest(),
                    })
                };
            }
            if selected.acquire_completed || selected.release_attempted {
                return Err(AttachmentSourceError::Conflict);
            }
            Ok(AttachmentSourceActionV1::AwaitAcquisition {
                acquisition_id,
                phase: acquisition.phase(),
            })
        }
        MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_ACTIVE => {
            if selected.consume_attempted || selected.consume_completed {
                return Err(AttachmentSourceError::Conflict);
            }
            if selected.resource.is_some() {
                return Err(AttachmentSourceError::Conflict);
            }
            if !selected.acquire_completed {
                return Ok(AttachmentSourceActionV1::CompleteAcquire {
                    acquisition_id,
                    revision: acquisition.revision(),
                    record_digest: *acquisition.record_digest(),
                });
            }
            if must_release {
                Ok(AttachmentSourceActionV1::Release {
                    acquisition_id,
                    revision: acquisition.revision(),
                    record_digest: *acquisition.record_digest(),
                })
            } else {
                Ok(AttachmentSourceActionV1::Consume {
                    acquisition_id,
                    revision: acquisition.revision(),
                    record_digest: *acquisition.record_digest(),
                })
            }
        }
        MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_CONSUMED
        | MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_FAULTED => {
            let Some(resource) = selected.resource else {
                if !source_faulted {
                    return Err(AttachmentSourceError::Abandoned);
                }
                if selected.consume_attempted || selected.consume_completed {
                    return Err(AttachmentSourceError::Conflict);
                }
                // A resource-absent fault closes directly into Release; no
                // detached-create receipt exists to justify Consume custody.
                return if selected.release_attempted {
                    Ok(AttachmentSourceActionV1::AwaitRelease { acquisition_id })
                } else {
                    Ok(AttachmentSourceActionV1::Release {
                        acquisition_id,
                        revision: acquisition.revision(),
                        record_digest: *acquisition.record_digest(),
                    })
                };
            };
            if !selected.acquire_completed {
                return Ok(AttachmentSourceActionV1::AwaitAttachment {
                    acquisition_id,
                    mount_handle: *resource.mount_handle(),
                    lifecycle: resource.lifecycle(),
                    consume_attempt_recorded: false,
                });
            }
            if !selected.consume_attempted {
                return Ok(AttachmentSourceActionV1::AwaitAttachment {
                    acquisition_id,
                    mount_handle: *resource.mount_handle(),
                    lifecycle: resource.lifecycle(),
                    consume_attempt_recorded: false,
                });
            }
            if must_release && !selected.consume_completed {
                if resource.lifecycle() == MountLifecycle::MOUNT_LIFECYCLE_RELEASED {
                    return Ok(AttachmentSourceActionV1::CompleteConsume {
                        acquisition_id,
                        mount_handle: *resource.mount_handle(),
                        lifecycle: resource.lifecycle(),
                        verification_digest: None,
                    });
                }
                return Ok(AttachmentSourceActionV1::DrainAttachment {
                    acquisition_id,
                    mount_handle: *resource.mount_handle(),
                    lifecycle: resource.lifecycle(),
                });
            }
            if must_release {
                if resource.lifecycle() == MountLifecycle::MOUNT_LIFECYCLE_RELEASED {
                    return Ok(AttachmentSourceActionV1::Release {
                        acquisition_id,
                        revision: acquisition.revision(),
                        record_digest: *acquisition.record_digest(),
                    });
                }
                return Ok(AttachmentSourceActionV1::DrainAttachment {
                    acquisition_id,
                    mount_handle: *resource.mount_handle(),
                    lifecycle: resource.lifecycle(),
                });
            }
            let verification = attachment_verification::current_record(journal, desired)?;
            if resource.lifecycle() == MountLifecycle::MOUNT_LIFECYCLE_INSTALLED
                && let Some(verification) = verification
                && verification.matches_current(desired, target, resource)
            {
                if !selected.consume_completed {
                    return Ok(AttachmentSourceActionV1::CompleteConsume {
                        acquisition_id,
                        mount_handle: *resource.mount_handle(),
                        lifecycle: resource.lifecycle(),
                        verification_digest: Some(verification.record_digest()),
                    });
                }
                return Ok(AttachmentSourceActionV1::Ready {
                    acquisition_id,
                    mount_handle: *resource.mount_handle(),
                    verification_digest: verification.record_digest(),
                });
            }
            if matches!(
                resource.lifecycle(),
                MountLifecycle::MOUNT_LIFECYCLE_RELEASING
                    | MountLifecycle::MOUNT_LIFECYCLE_RELEASED
            ) {
                return Err(AttachmentSourceError::Abandoned);
            }
            Ok(AttachmentSourceActionV1::AwaitAttachment {
                acquisition_id,
                mount_handle: *resource.mount_handle(),
                lifecycle: resource.lifecycle(),
                consume_attempt_recorded: true,
            })
        }
        MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_RELEASING => {
            if !selected.release_attempted {
                return Err(AttachmentSourceError::Abandoned);
            }
            if selected.resource.is_some_and(|resource| {
                resource.lifecycle() != MountLifecycle::MOUNT_LIFECYCLE_RELEASED
            }) {
                return Err(AttachmentSourceError::Conflict);
            }
            Ok(AttachmentSourceActionV1::AwaitRelease { acquisition_id })
        }
        MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_RELEASED => {
            if !must_release
                || selected.resource.is_some_and(|resource| {
                    resource.lifecycle() != MountLifecycle::MOUNT_LIFECYCLE_RELEASED
                })
            {
                return Err(AttachmentSourceError::Abandoned);
            }
            if !selected.release_attempted {
                return Err(AttachmentSourceError::Abandoned);
            }
            Ok(AttachmentSourceActionV1::CompleteRelease {
                acquisition_id,
                revision: acquisition.revision(),
                record_digest: *acquisition.record_digest(),
            })
        }
        MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_UNSPECIFIED => {
            Err(AttachmentSourceError::Faulted)
        }
    }
}

fn acquisition_matches(
    row: &ValidatedMountSourceAcquisitionRecord,
    target: TargetFacts,
    consistency: AttachmentConsistency,
    binding_digest: ObjectDigest,
    template_digest: ObjectDigest,
) -> bool {
    let wire = row.wire_record();
    row.sandbox_id() == &target.sandbox
        && row.incarnation_id() == &target.incarnation
        && row.assignment_epoch() == target.epoch
        && row.desired_generation() == target.generation
        && row.assignment_digest() == &target.digest
        && row.namespace_generation() == target.namespace_generation
        && wire.source_binding_digest == binding_digest.as_bytes()
        && wire.prospective_mount_template_digest == template_digest.as_bytes()
        && source_proof_matches(consistency, wire.proof_class.as_known())
}

fn lineage_matches_row(
    lineage: AcquisitionLineage,
    row: &ValidatedMountSourceAcquisitionRecord,
) -> bool {
    let wire = row.wire_record();
    lineage.acquisition_id == *row.acquisition_id()
        && lineage.sandbox == *row.sandbox_id()
        && lineage.incarnation == *row.incarnation_id()
        && lineage.assignment_epoch == row.assignment_epoch()
        && lineage.assignment_generation == row.desired_generation()
        && lineage.assignment_digest == *row.assignment_digest()
        && lineage.namespace_generation == row.namespace_generation()
        && lineage.binding_digest == wire.source_binding_digest.as_slice()
        && lineage.template_digest == wire.prospective_mount_template_digest.as_slice()
}

fn lineage_matches_target(lineage: AcquisitionLineage, target: TargetFacts) -> bool {
    lineage.sandbox == target.sandbox
        && lineage.incarnation == target.incarnation
        && lineage.assignment_epoch == target.epoch
        && lineage.assignment_generation == target.generation
        && lineage.assignment_digest == target.digest
        && lineage.namespace_generation == target.namespace_generation
        && lineage.allocation_digest == target.allocation_digest
        && lineage.policy_identity == target.policy_identity
}

fn source_proof_matches(
    consistency: AttachmentConsistency,
    proof: Option<MountSourceProofClass>,
) -> bool {
    matches!(
        (consistency, proof),
        (
            AttachmentConsistency::ImmutableRevision,
            Some(MountSourceProofClass::MOUNT_SOURCE_PROOF_CLASS_IMMUTABLE_TREE)
        ) | (
            AttachmentConsistency::LocalLive,
            Some(MountSourceProofClass::MOUNT_SOURCE_PROOF_CLASS_LOCAL_LIVE)
        ) | (
            AttachmentConsistency::BestEffortReplica,
            Some(MountSourceProofClass::MOUNT_SOURCE_PROOF_CLASS_BEST_EFFORT_REPLICA)
        )
    )
}

fn resource_matches_acquisition(
    resource: &ValidatedMountInventoryRecord,
    acquisition: &ValidatedMountSourceAcquisitionRecord,
) -> bool {
    let recipe = resource.recipe();
    let source = acquisition.wire_record();
    recipe.source().digest().as_bytes() == source.source_binding_digest.as_slice()
        && recipe.source_realization_handle() == source.source_realization_handle.as_slice()
        && recipe.source_physical_proof_digest() == source.source_physical_proof_digest.as_slice()
        && recipe.source_kernel_boot_id() == source.source_kernel_boot_id.as_slice()
        && Some(recipe.source_device()) == source.source_device
        && Some(recipe.source_inode()) == source.source_inode
        && Some(recipe.source_unique_mount_id()) == source.source_unique_mount_id
        && source.proof_class.as_known() == Some(recipe.source_proof_class())
        && recipe.source_provider_authority_id() == source.provider_authority_id.as_slice()
        && recipe.source_provider_authority_generation() == source.provider_authority_generation
        && recipe.source_provider_authority_digest() == source.provider_authority_digest.as_slice()
        && recipe.source_provider_resource_id() == source.provider_resource_id.as_slice()
        && recipe.source_provider_resource_generation() == source.provider_resource_generation
        && recipe.source_provider_resource_digest() == source.provider_resource_digest.as_slice()
        && recipe.source_provider_catalog_generation() == source.provider_catalog_generation
        && recipe.source_provider_catalog_digest() == source.provider_catalog_digest.as_slice()
}

fn resource_matches_intent(
    resource: &ValidatedMountInventoryRecord,
    intent: &AttachmentIntent,
    binding_digest: ObjectDigest,
    target: TargetFacts,
) -> bool {
    let recipe = resource.recipe();
    let resource_binding = resource.binding();
    let fence = resource_binding.fence();
    let attributes = recipe.attributes();
    let expected = intent.mount_attributes();
    let (source_view_id, source_revision) = intent.source_view();
    let Ok(consistency) = source_consistency(intent.consistency()) else {
        return false;
    };
    recipe.attachment_id() == intent.id().as_bytes()
        && fence.sandbox_id() == &target.sandbox
        && fence.incarnation_id() == &target.incarnation
        && fence.assignment_epoch() == target.epoch
        && fence.desired_generation() == target.generation
        && fence.assignment_digest() == &target.digest
        && resource_binding.namespace_generation() == target.namespace_generation
        && recipe.destination_slot_id() == intent.destination_slot().as_bytes()
        && recipe.view_revision() == intent.view()
        && recipe.source_generation() == source_revision.get()
        && recipe.resource_attachment_generation() == intent.desired_generation().get()
        && recipe.source_view_id() == source_view_id.as_bytes()
        && recipe.source_incarnation_id()
            == intent
                .source_incarnation()
                .as_ref()
                .map(|value| value.as_bytes())
        && recipe.source_consistency() == consistency
        && recipe.source().digest() == binding_digest
        && attributes.read_only() == expected.read_only()
        && attributes.no_exec() == expected.no_exec()
        && attributes.no_suid() == expected.no_suid()
        && attributes.no_device() == expected.no_dev()
        && attributes.no_atime() == expected.no_atime()
        && attributes.recursive() == expected.recursive()
        && attributes.mutation_mode() == mutation_mode(intent.mutation())
}

const fn mutation_mode(mutation: ViewMutation) -> u32 {
    match mutation {
        ViewMutation::ReadOnly => 0,
        ViewMutation::ReadWrite => 1,
        ViewMutation::PrivateCow => 2,
        ViewMutation::AppendOnly => 3,
        ViewMutation::Service => 4,
    }
}

fn source_projection(
    journal: &Journal,
    intent: &AttachmentIntent,
    target: &CurrentNamespaceTarget,
    sample: RawPairedClockSample,
) -> Result<(SourceRealizationBindingV1, ObjectDigest), AttachmentSourceError> {
    let (view_id, revision) = intent.source_view();
    let view = filesystem_view_state::get_revision(journal, view_id, revision)?
        .filter(|view| {
            view.presence() == FilesystemViewRevisionPresenceV1::Available
                && view.descriptor() == intent.view()
        })
        .ok_or(AttachmentSourceError::Conflict)?;
    let consistency = source_consistency(intent.consistency())?;
    let binding = SourceRealizationBindingV1::new(
        *view_id.as_bytes(),
        revision.get(),
        intent.view().clone(),
        view.source_handle().clone(),
        consistency,
        intent.source_incarnation().map(|value| *value.as_bytes()),
    )
    .map_err(|_| AttachmentSourceError::Protocol)?;
    let request = prospective_create(intent, view.source_handle(), target, consistency);
    let bytes = request.encode_to_vec();
    let peer = PeerCredentials {
        uid: 1,
        gid: 1,
        pid: Some(1),
    };
    let validated = decode_mount_request(
        &bytes,
        peer,
        PeerPolicy {
            uid: peer.uid,
            gid: Some(peer.gid),
            audience: Audience::AUDIENCE_NODE_CONTROLLER,
        },
        sample.boottime_nanoseconds(),
    )
    .map_err(|_| AttachmentSourceError::Protocol)?;
    let template = canonical_precatalog_mount_create_template_v1(&validated, &[])
        .map_err(|_| AttachmentSourceError::Protocol)?;
    Ok((binding, template.digest()))
}

fn prospective_create(
    intent: &AttachmentIntent,
    source: &aos_sandbox_core::model::ViewSource,
    target: &CurrentNamespaceTarget,
    consistency: MountSourceConsistency,
) -> ApplyMountRequest {
    let (view_id, revision) = intent.source_view();
    let lease = intent.lease();
    ApplyMountRequest {
        header: Some(RequestHeader {
            protocol_major: 2,
            protocol_minor: 0,
            request_id: vec![0xa5; 16],
            audience: Audience::AUDIENCE_NODE_CONTROLLER.into(),
            deadline_boottime_nanoseconds: target
                .runtime_generation()
                .scope()
                .deadline_boottime_nanoseconds(),
            maximum_response_bytes: MOUNT_RESPONSE_BYTES,
            ..Default::default()
        })
        .into(),
        fence: Some(crate::mount_preparation::current_fence(target)).into(),
        action: MountAction::MOUNT_ACTION_CREATE_DETACHED.into(),
        attachment_id: intent.id().as_bytes().to_vec(),
        destination_slot_id: intent.destination_slot().as_bytes().to_vec(),
        view_revision: Some(descriptor(intent.view())).into(),
        attributes: Some(attributes(intent)).into(),
        source_generation: revision.get(),
        namespace_generation: target.target_generation(),
        desired_attachment_generation: intent.desired_generation().get(),
        resource_attachment_generation: intent.desired_generation().get(),
        source_view_id: view_id.as_bytes().to_vec(),
        source_incarnation_id: intent
            .source_incarnation()
            .map_or_else(Vec::new, |value| value.as_bytes().to_vec()),
        source_consistency: consistency.into(),
        attachment_lease_id: lease.id().as_bytes().to_vec(),
        attachment_lease_issued_seconds: lease.issued_seconds(),
        attachment_lease_expires_seconds: lease.expires_seconds(),
        source_handle: aos_sandbox_core::encode_view_source(source),
        ..Default::default()
    }
}

impl CanonicalPlan {
    #[allow(clippy::too_many_arguments)]
    fn new(
        desired: &DurableAttachmentDesiredStateV1,
        inventory: &CurrentMountFilesystemInventoryV1,
        target: &CurrentNamespaceTarget,
        bounds: AttachmentSourceBoundsV1,
        binding_digest: ObjectDigest,
        template_digest: ObjectDigest,
        selected: SelectedEvidence<'_>,
        action: AttachmentSourceActionV1,
    ) -> Result<Self, AttachmentSourceError> {
        let intent = desired.intent();
        let target_facts = TargetFacts::new(target);
        let assignment = target
            .runtime_generation()
            .scope()
            .binding()
            .manifest()
            .manifest();
        let observation = inventory.observation_identity();
        let custody_desired_generation = selected
            .lineage
            .map_or(intent.desired_generation().get(), |lineage| {
                lineage.desired_generation
            });
        let custody_desired_digest = selected
            .lineage
            .map_or(*desired.record_digest().as_bytes(), |lineage| {
                lineage.desired_digest
            });
        let mut bytes = Vec::with_capacity(512);
        bytes.extend_from_slice(PLAN_MAGIC);
        bytes.extend_from_slice(&PLAN_VERSION.to_be_bytes());
        bytes.extend_from_slice(intent.id().as_bytes());
        bytes.extend_from_slice(&intent.desired_generation().get().to_be_bytes());
        bytes.extend_from_slice(desired.record_digest().as_bytes());
        bytes.push(match desired.presence() {
            AttachmentDesiredPresenceV1::Present => 1,
            AttachmentDesiredPresenceV1::Released => 2,
        });
        bytes.extend_from_slice(&target_facts.sandbox);
        bytes.extend_from_slice(&target_facts.incarnation);
        bytes.extend_from_slice(&target_facts.epoch.to_be_bytes());
        bytes.extend_from_slice(&target_facts.generation.to_be_bytes());
        bytes.extend_from_slice(&target_facts.digest);
        bytes.extend_from_slice(&target_facts.namespace_generation.to_be_bytes());
        bytes.extend_from_slice(target.allocation_digest());
        bytes.extend_from_slice(&descriptor_identity_digest(assignment.policy()));
        let lease = intent.lease();
        bytes.extend_from_slice(lease.id().as_bytes());
        bytes.extend_from_slice(&lease.issued_seconds().to_be_bytes());
        bytes.extend_from_slice(&lease.expires_seconds().to_be_bytes());
        bytes.extend_from_slice(intent.source_view().0.as_bytes());
        bytes.extend_from_slice(&intent.source_view().1.get().to_be_bytes());
        bytes.extend_from_slice(&descriptor_identity_digest(intent.view()));
        bytes.extend_from_slice(binding_digest.as_bytes());
        bytes.extend_from_slice(template_digest.as_bytes());
        bytes.extend_from_slice(&bounds.lease_seconds.to_be_bytes());
        bytes.extend_from_slice(&bounds.maximum_submounts.to_be_bytes());
        bytes.push(u8::from(bounds.kernel_coupled));
        bytes.extend_from_slice(inventory.resources().record_digest().as_bytes());
        bytes.extend_from_slice(inventory.source_acquisitions().record_digest().as_bytes());
        bytes.extend_from_slice(observation.kernel_boot_id());
        bytes.extend_from_slice(observation.broker_instance_id());
        bytes.extend_from_slice(&observation.journal_sequence().to_be_bytes());
        encode_selected(&mut bytes, selected);
        let verification_digest = match action {
            AttachmentSourceActionV1::CompleteConsume {
                verification_digest,
                ..
            } => verification_digest,
            AttachmentSourceActionV1::Ready {
                verification_digest,
                ..
            } => Some(verification_digest),
            _ => None,
        };
        bytes.extend_from_slice(&verification_digest.unwrap_or([0; 32]));
        bytes.push(action_code(action));
        if bytes.len() != super::format::PLAN_BYTES {
            return Err(AttachmentSourceError::CorruptState);
        }
        let digest = Sha256::new()
            .chain_update(PLAN_DOMAIN)
            .chain_update(&bytes)
            .finalize()
            .into();
        Ok(Self {
            bytes,
            digest,
            attachment_id: *intent.id().as_bytes(),
            desired_generation: intent.desired_generation().get(),
            desired_digest: *desired.record_digest().as_bytes(),
            custody_desired_generation,
            custody_desired_digest,
            source_binding_digest: *binding_digest.as_bytes(),
            template_digest: *template_digest.as_bytes(),
            sandbox: target_facts.sandbox,
            incarnation: target_facts.incarnation,
            assignment_epoch: target_facts.epoch,
            assignment_generation: target_facts.generation,
            assignment_digest: target_facts.digest,
            bounds,
            resource_snapshot_digest: *inventory.resources().record_digest().as_bytes(),
            source_snapshot_digest: *inventory.source_acquisitions().record_digest().as_bytes(),
            acquisition_id: selected
                .acquisition
                .map(|value| *value.acquisition_id())
                .or(selected.pending_acquisition_id),
            acquisition_revision: selected.acquisition.map(|value| value.revision()),
            acquisition_record_digest: selected.acquisition.map(|value| *value.record_digest()),
            acquisition_phase: selected.acquisition.map(|value| value.phase()),
            mount_handle: selected.resource.map(|value| *value.mount_handle()),
            resource_revision: selected.resource.map(|value| value.resource_revision()),
            resource_lifecycle: selected.resource.map(|value| value.lifecycle()),
            verification_digest,
        })
    }
}

fn encode_selected(bytes: &mut Vec<u8>, selected: SelectedEvidence<'_>) {
    if let Some(acquisition) = selected.acquisition {
        bytes.push(1);
        bytes.extend_from_slice(acquisition.acquisition_id());
        bytes.extend_from_slice(&acquisition.revision().to_be_bytes());
        bytes.extend_from_slice(acquisition.record_digest());
        bytes.push(acquisition.phase() as i32 as u8);
    } else if let Some(acquisition_id) = selected.pending_acquisition_id {
        bytes.push(1);
        bytes.extend_from_slice(&acquisition_id);
        bytes.extend_from_slice(&[0; 41]);
    } else {
        bytes.extend_from_slice(&[0; 74]);
    }
    if let Some(resource) = selected.resource {
        bytes.push(1);
        bytes.extend_from_slice(resource.mount_handle());
        bytes.extend_from_slice(&resource.resource_revision().to_be_bytes());
        bytes.push(resource.lifecycle() as i32 as u8);
    } else {
        bytes.extend_from_slice(&[0; 42]);
    }
}

fn action_code(action: AttachmentSourceActionV1) -> u8 {
    match action {
        AttachmentSourceActionV1::AwaitLease { .. } => 1,
        AttachmentSourceActionV1::Acquire => 2,
        AttachmentSourceActionV1::AwaitAcquisition { .. } => 3,
        AttachmentSourceActionV1::CompleteAcquire { .. } => 4,
        AttachmentSourceActionV1::Consume { .. } => 5,
        AttachmentSourceActionV1::AwaitAttachment { .. } => 6,
        AttachmentSourceActionV1::CompleteConsume { .. } => 7,
        AttachmentSourceActionV1::Ready { .. } => 8,
        AttachmentSourceActionV1::DrainAttachment { .. } => 9,
        AttachmentSourceActionV1::Release { .. } => 10,
        AttachmentSourceActionV1::AwaitRelease { .. } => 11,
        AttachmentSourceActionV1::CompleteRelease { .. } => 12,
        AttachmentSourceActionV1::Released => 13,
        AttachmentSourceActionV1::CancelAcquire { .. } => 14,
    }
}

fn descriptor_identity_digest(descriptor: &ObjectDescriptor) -> [u8; 32] {
    let media = descriptor.media_type().as_str().as_bytes();
    Sha256::new()
        .chain_update(b"aos.sandbox.attachment-source-descriptor.v1\0")
        .chain_update((media.len() as u64).to_be_bytes())
        .chain_update(media)
        .chain_update(descriptor.digest().as_bytes())
        .chain_update(descriptor.encoded_size().to_be_bytes())
        .finalize()
        .into()
}

fn descriptor(value: &ObjectDescriptor) -> Descriptor {
    Descriptor {
        media_type: value.media_type().as_str().to_owned(),
        sha256: value.digest().as_bytes().to_vec(),
        encoded_size: value.encoded_size(),
        ..Default::default()
    }
}

fn attributes(intent: &AttachmentIntent) -> WireMountAttributes {
    let value = intent.mount_attributes();
    WireMountAttributes {
        read_only: value.read_only(),
        no_exec: value.no_exec(),
        no_suid: value.no_suid(),
        no_device: value.no_dev(),
        no_atime: value.no_atime(),
        recursive: value.recursive(),
        mutation_mode: mutation_mode(intent.mutation()),
        ..Default::default()
    }
}

fn source_consistency(
    consistency: AttachmentConsistency,
) -> Result<MountSourceConsistency, AttachmentSourceError> {
    match consistency {
        AttachmentConsistency::ImmutableRevision => {
            Ok(MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_IMMUTABLE_REVISION)
        }
        AttachmentConsistency::LocalLive => {
            Ok(MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_LOCAL_LIVE)
        }
        AttachmentConsistency::BestEffortReplica => {
            Ok(MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_BEST_EFFORT_REPLICA)
        }
        AttachmentConsistency::TransactionalService => {
            Err(AttachmentSourceError::UnsupportedSource)
        }
    }
}
