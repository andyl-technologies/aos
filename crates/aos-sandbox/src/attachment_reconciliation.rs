//! Plans one attachment's next step from exact desired state and Mount inventory.
//!
//! The planner consumes a current desired generation and an authenticated,
//! current-target Mount reconciliation. It returns one closed observation or
//! next-step description at a time:
//!
//! ```text
//! desired generation + fresh complete Mount inventory
//!     -> wait | prepare | install | replace | verify | ready
//!     -> detach | release | fault | conflict | terminal
//! ```
//!
//! A plan is deliberately not broker authority. It retains the live namespace
//! target only so a later, separately authorized step can recheck it. Handles,
//! inventory rows, and absence never confer permission to mutate a mount.

use aos_proto::aos::sandbox::local::v1::{
    MountAction, MountFaultPhase, MountLifecycle, MountSourceConsistency,
};
use aos_sandbox_core::RawPairedClockSample;
use aos_sandbox_core::model::{AttachmentConsistency, AttachmentIntent, ViewMutation};
use aos_sandbox_protocol::ValidatedMountInventoryRecord;

use crate::Journal;
use crate::attachment_state::{
    self, AttachmentDesiredPresenceV1, AttachmentDesiredStateError, DurableAttachmentDesiredStateV1,
};
use crate::attachment_verification::{self, AttachmentVerificationError};
use crate::mount_attempt::{
    CurrentMountInventoryReconciliationV1, MountAttemptError, MountAttemptInventoryObservationV1,
    MountAttemptInventoryStatusV1,
};
use crate::ownership_authority::ProtectedOwnershipClockError;
use crate::runtime_scope::CurrentNamespaceTarget;

/// Explains why reconciliation cannot safely select an ordinary next step.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttachmentReconciliationConflictV1 {
    /// The desired source must be handled by a non-Mount service projection.
    UnsupportedSourceConsistency,
    /// The durable desired generation does not name the retained live target.
    TargetMismatch,
    /// A current resource for the destination belongs to another attachment.
    DestinationOccupied,
    /// More than one resource claims to realize the current desired generation.
    MultipleDesiredResources,
    /// A current or newer resource contradicts the immutable desired recipe.
    IncompatibleResource,
    /// A predecessor cannot be replaced under the retained assignment fence.
    ReplacementFence,
    /// Durable attempts for this desired generation demand competing transitions.
    CompetingOperations,
    /// One attempt names the attachment generation with incompatible fields.
    IncompatibleAttempt,
    /// A transition has no exact local operation that can safely resume it.
    UntrackedTransition,
    /// A released resource generation cannot be silently resurrected.
    ReleasedGeneration,
    /// Durable post-attach evidence no longer matches the installed generation.
    VerificationMismatch,
}

/// Describes one safe planning conclusion without granting effect authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttachmentReconciliationActionV1 {
    /// The attachment lease has not reached its inclusive issue time.
    AwaitLease {
        /// Inclusive wall-clock second at which planning may resume.
        issued_seconds: i64,
    },
    /// A new detached resource should be prepared from exact desired semantics.
    Prepare {
        /// Installed predecessor intended for a later atomic replacement.
        replacement_mount_handle: Option<[u8; 32]>,
    },
    /// A prepared detached resource should be installed into an empty slot.
    Install {
        /// Stable handle of the prepared resource.
        mount_handle: [u8; 32],
    },
    /// A prepared detached resource should atomically replace its predecessor.
    Replace {
        /// Stable handle of the prepared successor.
        mount_handle: [u8; 32],
        /// Stable handle of the installed predecessor.
        replacement_mount_handle: [u8; 32],
    },
    /// An installed resource requires post-attach verification before readiness.
    Verify {
        /// Stable handle whose exact inventory observation must be verified.
        mount_handle: [u8; 32],
        /// Non-recycled kernel mount identity observed by Mount.
        unique_mount_id: u64,
    },
    /// The installed generation exactly matches durable post-attach evidence.
    Ready {
        /// Stable handle of the verified installed resource.
        mount_handle: [u8; 32],
        /// Non-recycled kernel mount identity observed after attachment.
        unique_mount_id: u64,
        /// Digest of the immutable controller verification record.
        verification_digest: [u8; 32],
    },
    /// An installed resource should be detached from the consumer namespace.
    Detach {
        /// Stable handle of the installed resource.
        mount_handle: [u8; 32],
    },
    /// A prepared or draining resource should release broker custody.
    Release {
        /// Stable handle of the resource to release.
        mount_handle: [u8; 32],
    },
    /// A durable broker transition must resolve before another decision.
    Wait {
        /// Exact locally correlated operation identity.
        request_id: [u8; 16],
        /// Stable handle carrying the transition.
        mount_handle: [u8; 32],
        /// Current broker lifecycle being observed.
        lifecycle: MountLifecycle,
    },
    /// Mount recorded a terminal resource fault requiring policy intervention.
    Fault {
        /// Stable handle of the faulted resource.
        mount_handle: [u8; 32],
        /// Lifecycle phase from which Mount entered the fault.
        phase: MountFaultPhase,
        /// Sanitized, non-secret failure correlation digest.
        failure_digest: [u8; 32],
    },
    /// Valid inputs cannot be reconciled without an explicit higher-level choice.
    Conflict {
        /// Closed reason for refusing to guess a mutation.
        reason: AttachmentReconciliationConflictV1,
        /// Most directly implicated resource, when one exists.
        mount_handle: Option<[u8; 32]>,
    },
    /// The release tombstone has no remaining non-released Mount resource.
    Released,
    /// An expired present lease has drained every Mount resource.
    LeaseExpired,
}

/// Retains exact desired and inventory evidence with one descriptive action.
pub struct CurrentAttachmentReconciliationV1 {
    desired: DurableAttachmentDesiredStateV1,
    inventory: CurrentMountInventoryReconciliationV1,
    verification: Option<attachment_verification::Record>,
    action: AttachmentReconciliationActionV1,
}

pub(crate) struct AttachmentReconciliationEvidenceV1 {
    desired: DurableAttachmentDesiredStateV1,
    snapshot: crate::mount_attempt::DurableMountInventorySnapshotV1,
    attempts: Vec<MountAttemptInventoryObservationV1>,
    verification: Option<attachment_verification::Record>,
    action: AttachmentReconciliationActionV1,
}

impl CurrentAttachmentReconciliationV1 {
    /// Borrows the current durable desired attachment generation.
    #[must_use]
    pub const fn desired(&self) -> &DurableAttachmentDesiredStateV1 {
        &self.desired
    }

    /// Borrows the fresh authenticated Mount reconciliation used for planning.
    #[must_use]
    pub const fn inventory(&self) -> &CurrentMountInventoryReconciliationV1 {
        &self.inventory
    }

    /// Returns the closed non-authorizing planning conclusion.
    #[must_use]
    pub const fn action(&self) -> AttachmentReconciliationActionV1 {
        self.action
    }

    /// Recovers the retained target for a separately authorized next step.
    ///
    /// The returned proof has its original deadline. A consumer must recheck it
    /// and the desired generation rather than treating this plan as authority.
    #[must_use]
    pub fn into_target(self) -> CurrentNamespaceTarget {
        self.inventory.into_target()
    }

    pub(crate) fn into_evidence_and_target(
        self,
    ) -> (AttachmentReconciliationEvidenceV1, CurrentNamespaceTarget) {
        let (target, snapshot, attempts) = self.inventory.into_parts();
        let evidence = AttachmentReconciliationEvidenceV1 {
            desired: self.desired,
            snapshot,
            attempts,
            verification: self.verification,
            action: self.action,
        };
        (evidence, target)
    }
}

impl AttachmentReconciliationEvidenceV1 {
    pub(crate) const fn desired(&self) -> &DurableAttachmentDesiredStateV1 {
        &self.desired
    }

    pub(crate) const fn snapshot(&self) -> &crate::mount_attempt::DurableMountInventorySnapshotV1 {
        &self.snapshot
    }

    pub(crate) const fn action(&self) -> AttachmentReconciliationActionV1 {
        self.action
    }

    pub(crate) fn recheck<T>(
        &self,
        journal: &mut Journal,
        target: &CurrentNamespaceTarget,
        clock: &mut T,
    ) -> Result<(), AttachmentReconciliationError>
    where
        T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        target
            .recheck(journal, clock)
            .map_err(MountAttemptError::from)?;
        self.snapshot.recheck(journal)?;
        attachment_state::recheck_current(journal, &self.desired)?;

        let now = clock()?.wall_seconds();
        let target_facts = TargetFacts::from_target(target);
        let resources = self
            .snapshot
            .inventory()
            .mounts()
            .iter()
            .map(|resource| {
                project_resource(
                    resource,
                    self.desired.intent(),
                    target_facts,
                    self.verification.as_ref().is_some_and(|verification| {
                        verification.matches_current(&self.desired, target, resource)
                    }),
                )
            })
            .collect::<Vec<_>>();
        let attempts = self
            .attempts
            .iter()
            .copied()
            .map(project_attempt)
            .collect::<Vec<_>>();
        let action = decide(
            self.desired.presence(),
            self.desired.intent(),
            now,
            target_facts,
            &resources,
            &attempts,
            self.verification
                .as_ref()
                .map(VerificationFacts::from_record),
        );
        if action != self.action {
            return Err(AttachmentReconciliationError::ActionChanged);
        }

        attachment_state::recheck_current(journal, &self.desired)?;
        self.snapshot.recheck(journal)?;
        target
            .recheck(journal, clock)
            .map_err(MountAttemptError::from)?;
        Ok(())
    }
}

/// Reports stale evidence, corrupt history, or protected-clock failure.
#[derive(Debug, thiserror::Error)]
pub enum AttachmentReconciliationError {
    /// The desired-state history is stale, malformed, or over its fixed bound.
    #[error(transparent)]
    Desired(#[from] AttachmentDesiredStateError),
    /// The Mount inventory or its current-target comparison is stale or invalid.
    #[error(transparent)]
    Mount(#[from] MountAttemptError),
    /// Durable post-attach verification history is malformed or inconsistent.
    #[error("attachment verification failed: {0}")]
    Verification(#[source] Box<AttachmentVerificationError>),
    /// The protected clock adapter could not produce a planning observation.
    #[error(transparent)]
    Clock(#[from] ProtectedOwnershipClockError),
    /// Lease time or another rechecked input now selects a different action.
    #[error("attachment reconciliation action changed before use")]
    ActionChanged,
}

impl From<AttachmentVerificationError> for AttachmentReconciliationError {
    fn from(error: AttachmentVerificationError) -> Self {
        Self::Verification(Box::new(error))
    }
}

#[derive(Clone, Copy)]
struct TargetFacts {
    sandbox: [u8; 16],
    incarnation: [u8; 16],
    assignment_epoch: u64,
    assignment_generation: u64,
    assignment_digest: [u8; 32],
    namespace_generation: u64,
}

impl TargetFacts {
    fn from_target(target: &CurrentNamespaceTarget) -> Self {
        let binding = target.runtime_generation().scope().binding();
        let manifest = binding.manifest().manifest();
        Self {
            sandbox: *manifest.sandbox().as_bytes(),
            incarnation: *manifest.incarnation().as_bytes(),
            assignment_epoch: manifest.epoch().get(),
            assignment_generation: manifest.desired_generation().get(),
            assignment_digest: *binding.assignment_digest().as_bytes(),
            namespace_generation: target.target_generation(),
        }
    }
}

#[derive(Clone, Copy)]
struct ResourceFacts {
    handle: [u8; 32],
    generation: u64,
    lifecycle: MountLifecycle,
    same_attachment: bool,
    same_slot: bool,
    same_scope: bool,
    current_binding: bool,
    predecessor_binding: bool,
    recipe_matches: bool,
    installed_unique_mount_id: Option<u64>,
    verification_matches: bool,
    fault: Option<(MountFaultPhase, [u8; 32])>,
}

#[derive(Clone, Copy)]
struct AttemptFacts {
    request_id: [u8; 16],
    action: MountAction,
    attachment_id: [u8; 16],
    destination_slot_id: [u8; 16],
    desired_generation: u64,
    resource_generation: u64,
    mount_handle: [u8; 32],
    status: MountAttemptInventoryStatusV1,
}

#[derive(Clone, Copy)]
struct VerificationFacts {
    mount_handle: [u8; 32],
    unique_mount_id: u64,
    record_digest: [u8; 32],
}

impl VerificationFacts {
    fn from_record(record: &attachment_verification::Record) -> Self {
        Self {
            mount_handle: record.mount_handle(),
            unique_mount_id: record.unique_mount_id(),
            record_digest: record.record_digest(),
        }
    }
}

pub(crate) fn reconcile_current<T>(
    journal: &mut Journal,
    desired: DurableAttachmentDesiredStateV1,
    inventory: CurrentMountInventoryReconciliationV1,
    clock: &mut T,
) -> Result<CurrentAttachmentReconciliationV1, AttachmentReconciliationError>
where
    T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
{
    inventory.recheck(journal, clock)?;
    attachment_state::recheck_current(journal, &desired)?;
    let verification = attachment_verification::current_record(journal, &desired)?;

    let now = clock()?.wall_seconds();
    let target = TargetFacts::from_target(inventory.target());
    let resources = inventory
        .snapshot()
        .inventory()
        .mounts()
        .iter()
        .map(|resource| {
            project_resource(
                resource,
                desired.intent(),
                target,
                verification.as_ref().is_some_and(|verification| {
                    verification.matches_current(&desired, inventory.target(), resource)
                }),
            )
        })
        .collect::<Vec<_>>();
    let attempts = inventory
        .attempts()
        .iter()
        .copied()
        .map(project_attempt)
        .collect::<Vec<_>>();
    let action = decide(
        desired.presence(),
        desired.intent(),
        now,
        target,
        &resources,
        &attempts,
        verification.as_ref().map(VerificationFacts::from_record),
    );

    attachment_state::recheck_current(journal, &desired)?;
    inventory.recheck(journal, clock)?;

    Ok(CurrentAttachmentReconciliationV1 {
        desired,
        inventory,
        verification,
        action,
    })
}

fn project_attempt(observation: MountAttemptInventoryObservationV1) -> AttemptFacts {
    AttemptFacts {
        request_id: observation.request_id(),
        action: observation.action(),
        attachment_id: observation.attachment_id(),
        destination_slot_id: observation.destination_slot_id(),
        desired_generation: observation.desired_attachment_generation(),
        resource_generation: observation.resource_attachment_generation(),
        mount_handle: observation.mount_handle(),
        status: observation.status(),
    }
}

fn project_resource(
    resource: &ValidatedMountInventoryRecord,
    intent: &AttachmentIntent,
    target: TargetFacts,
    verification_matches: bool,
) -> ResourceFacts {
    let recipe = resource.recipe();
    let binding = resource.binding();
    let fence = binding.fence();
    let same_attachment = recipe.attachment_id() == intent.id().as_bytes();
    let same_slot = recipe.destination_slot_id() == intent.destination_slot().as_bytes();
    let same_scope = fence.sandbox_id() == &target.sandbox
        && fence.incarnation_id() == &target.incarnation
        && binding.namespace_generation() == target.namespace_generation;
    let current_binding = same_scope
        && fence.assignment_epoch() == target.assignment_epoch
        && fence.desired_generation() == target.assignment_generation
        && fence.assignment_digest() == &target.assignment_digest;
    let predecessor_binding = same_scope
        && (fence.assignment_epoch(), fence.desired_generation())
            < (target.assignment_epoch, target.assignment_generation);
    let fault = resource
        .fault()
        .map(|fault| (fault.from(), *fault.failure_digest()));

    ResourceFacts {
        handle: *resource.mount_handle(),
        generation: recipe.resource_attachment_generation(),
        lifecycle: resource.lifecycle(),
        same_attachment,
        same_slot,
        same_scope,
        current_binding,
        predecessor_binding,
        recipe_matches: recipe_matches_intent(resource, intent),
        installed_unique_mount_id: resource
            .installed_observation()
            .map(|observation| observation.unique_mount_id()),
        verification_matches,
        fault,
    }
}

fn recipe_matches_intent(
    resource: &ValidatedMountInventoryRecord,
    intent: &AttachmentIntent,
) -> bool {
    let recipe = resource.recipe();
    let attributes = recipe.attributes();
    let expected_attributes = intent.mount_attributes();
    let (source_view, source_revision) = intent.source_view();
    let Some(source_consistency) = source_consistency(intent.consistency()) else {
        return false;
    };

    recipe.attachment_id() == intent.id().as_bytes()
        && recipe.destination_slot_id() == intent.destination_slot().as_bytes()
        && recipe.view_revision() == intent.view()
        && recipe.source_generation() == source_revision.get()
        && recipe.resource_attachment_generation() == intent.desired_generation().get()
        && recipe.source_view_id() == source_view.as_bytes()
        && recipe.source_incarnation_id()
            == intent
                .source_incarnation()
                .as_ref()
                .map(|value| value.as_bytes())
        && recipe.source_consistency() == source_consistency
        && attributes.read_only() == expected_attributes.read_only()
        && attributes.no_exec() == expected_attributes.no_exec()
        && attributes.no_suid() == expected_attributes.no_suid()
        && attributes.no_device() == expected_attributes.no_dev()
        && attributes.no_atime() == expected_attributes.no_atime()
        && attributes.recursive() == expected_attributes.recursive()
        && attributes.mutation_mode() == mutation_mode(intent.mutation())
}

const fn source_consistency(value: AttachmentConsistency) -> Option<MountSourceConsistency> {
    match value {
        AttachmentConsistency::ImmutableRevision => {
            Some(MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_IMMUTABLE_REVISION)
        }
        AttachmentConsistency::LocalLive => {
            Some(MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_LOCAL_LIVE)
        }
        AttachmentConsistency::BestEffortReplica => {
            Some(MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_BEST_EFFORT_REPLICA)
        }
        AttachmentConsistency::TransactionalService => None,
    }
}

const fn mutation_mode(value: ViewMutation) -> u32 {
    match value {
        ViewMutation::ReadOnly => 0,
        ViewMutation::ReadWrite => 1,
        ViewMutation::PrivateCow => 2,
        ViewMutation::AppendOnly => 3,
        ViewMutation::Service => 4,
    }
}

fn decide(
    presence: AttachmentDesiredPresenceV1,
    intent: &AttachmentIntent,
    now_seconds: i64,
    target: TargetFacts,
    resources: &[ResourceFacts],
    attempts: &[AttemptFacts],
    verification: Option<VerificationFacts>,
) -> AttachmentReconciliationActionV1 {
    if source_consistency(intent.consistency()).is_none() {
        return conflict(
            AttachmentReconciliationConflictV1::UnsupportedSourceConsistency,
            None,
        );
    }
    let (consumer_sandbox, consumer_incarnation) = intent.consumer();
    if consumer_sandbox.as_bytes() != &target.sandbox
        || consumer_incarnation.as_bytes() != &target.incarnation
        || intent.expected_namespace_generation().get() != target.namespace_generation
    {
        return conflict(AttachmentReconciliationConflictV1::TargetMismatch, None);
    }

    let desired_generation = intent.desired_generation().get();
    let attachment_id = *intent.id().as_bytes();
    let destination_slot_id = *intent.destination_slot().as_bytes();
    let lease = intent.lease();
    let lease_expired = now_seconds >= lease.expires_seconds();
    let release_requested = presence == AttachmentDesiredPresenceV1::Released || lease_expired;

    if let Some(resource) = resources.iter().find(|resource| {
        resource.same_scope
            && resource.same_slot
            && !resource.same_attachment
            && occupies_destination(resource)
    }) {
        return conflict(
            AttachmentReconciliationConflictV1::DestinationOccupied,
            Some(resource.handle),
        );
    }
    if let Some(resource) = resources.iter().find(|resource| {
        resource.same_attachment
            && resource.lifecycle != MountLifecycle::MOUNT_LIFECYCLE_RELEASED
            && (!resource.same_slot || !resource.same_scope)
    }) {
        return conflict(
            AttachmentReconciliationConflictV1::IncompatibleResource,
            Some(resource.handle),
        );
    }
    if let Some(resource) = resources.iter().find(|resource| {
        resource.same_attachment
            && resource.lifecycle != MountLifecycle::MOUNT_LIFECYCLE_RELEASED
            && !resource.current_binding
            && !resource.predecessor_binding
    }) {
        let reason = if resource.generation < desired_generation {
            AttachmentReconciliationConflictV1::ReplacementFence
        } else {
            AttachmentReconciliationConflictV1::IncompatibleResource
        };
        return conflict(reason, Some(resource.handle));
    }
    if !release_requested
        && let Some(resource) = resources.iter().find(|resource| {
            resource.same_attachment
                && resource.lifecycle != MountLifecycle::MOUNT_LIFECYCLE_RELEASED
                && ((resource.current_binding
                    && (resource.generation != desired_generation || !resource.recipe_matches))
                    || (!resource.current_binding && resource.generation >= desired_generation))
        })
    {
        return conflict(
            AttachmentReconciliationConflictV1::IncompatibleResource,
            Some(resource.handle),
        );
    }
    if !release_requested && now_seconds < lease.issued_seconds() {
        return AttachmentReconciliationActionV1::AwaitLease {
            issued_seconds: lease.issued_seconds(),
        };
    }
    if let Some(action) = classify_attempts(
        release_requested,
        attachment_id,
        destination_slot_id,
        desired_generation,
        resources,
        attempts,
    ) {
        return action;
    }

    if release_requested {
        decide_release(resources, lease_expired)
    } else {
        decide_present(intent, resources, verification)
    }
}

fn classify_attempts(
    release_requested: bool,
    attachment_id: [u8; 16],
    destination_slot_id: [u8; 16],
    desired_generation: u64,
    resources: &[ResourceFacts],
    attempts: &[AttemptFacts],
) -> Option<AttachmentReconciliationActionV1> {
    let mut active = None;
    for attempt in attempts.iter().filter(|attempt| {
        attempt.attachment_id == attachment_id && attempt.desired_generation == desired_generation
    }) {
        let action_matches = if release_requested {
            matches!(
                attempt.action,
                MountAction::MOUNT_ACTION_DETACH | MountAction::MOUNT_ACTION_RELEASE
            ) && attempt.resource_generation <= desired_generation
        } else {
            matches!(
                attempt.action,
                MountAction::MOUNT_ACTION_CREATE_DETACHED
                    | MountAction::MOUNT_ACTION_INSTALL
                    | MountAction::MOUNT_ACTION_REPLACE
            ) && attempt.resource_generation == desired_generation
        };
        if attempt.destination_slot_id != destination_slot_id || !action_matches {
            return Some(conflict(
                AttachmentReconciliationConflictV1::IncompatibleAttempt,
                Some(attempt.mount_handle),
            ));
        }

        let candidate = match attempt.status {
            MountAttemptInventoryStatusV1::Pending { lifecycle } => {
                Some(AttachmentReconciliationActionV1::Wait {
                    request_id: attempt.request_id,
                    mount_handle: attempt.mount_handle,
                    lifecycle,
                })
            }
            MountAttemptInventoryStatusV1::Faulted { .. } => resources
                .iter()
                .find(|resource| resource.handle == attempt.mount_handle)
                .and_then(fault_action)
                .or_else(|| {
                    Some(conflict(
                        AttachmentReconciliationConflictV1::IncompatibleResource,
                        Some(attempt.mount_handle),
                    ))
                }),
            MountAttemptInventoryStatusV1::NotObserved
            | MountAttemptInventoryStatusV1::SucceededWithoutReceipt { .. }
            | MountAttemptInventoryStatusV1::Superseded { .. }
            | MountAttemptInventoryStatusV1::CompletionRecorded { .. } => None,
        };
        if let Some(candidate) = candidate {
            if active.is_some() {
                return Some(conflict(
                    AttachmentReconciliationConflictV1::CompetingOperations,
                    Some(attempt.mount_handle),
                ));
            }
            active = Some(candidate);
        }
    }
    active
}

fn decide_present(
    intent: &AttachmentIntent,
    resources: &[ResourceFacts],
    verification: Option<VerificationFacts>,
) -> AttachmentReconciliationActionV1 {
    let desired_generation = intent.desired_generation().get();
    let mut desired = resources.iter().filter(|resource| {
        resource.same_attachment
            && resource.same_slot
            && resource.current_binding
            && resource.generation == desired_generation
            && resource.recipe_matches
    });
    let desired_resource = desired.next();
    if desired.next().is_some() {
        return conflict(
            AttachmentReconciliationConflictV1::MultipleDesiredResources,
            desired_resource.map(|resource| resource.handle),
        );
    }

    if let Some(resource) = desired_resource {
        if verification.is_some() && !resource.verification_matches {
            return conflict(
                AttachmentReconciliationConflictV1::VerificationMismatch,
                Some(resource.handle),
            );
        }
        return match resource.lifecycle {
            MountLifecycle::MOUNT_LIFECYCLE_PREPARED => {
                match replacement_predecessor(resources, desired_generation) {
                    Ok(Some(predecessor)) => AttachmentReconciliationActionV1::Replace {
                        mount_handle: resource.handle,
                        replacement_mount_handle: predecessor.handle,
                    },
                    Ok(None) => AttachmentReconciliationActionV1::Install {
                        mount_handle: resource.handle,
                    },
                    Err(action) => action,
                }
            }
            MountLifecycle::MOUNT_LIFECYCLE_INSTALLED => {
                let Some(unique_mount_id) = resource.installed_unique_mount_id else {
                    return conflict(
                        AttachmentReconciliationConflictV1::IncompatibleResource,
                        Some(resource.handle),
                    );
                };
                match verification {
                    Some(verification) => AttachmentReconciliationActionV1::Ready {
                        mount_handle: verification.mount_handle,
                        unique_mount_id: verification.unique_mount_id,
                        verification_digest: verification.record_digest,
                    },
                    None => AttachmentReconciliationActionV1::Verify {
                        mount_handle: resource.handle,
                        unique_mount_id,
                    },
                }
            }
            MountLifecycle::MOUNT_LIFECYCLE_FAULTED => {
                fault_action(resource).unwrap_or_else(|| {
                    conflict(
                        AttachmentReconciliationConflictV1::IncompatibleResource,
                        Some(resource.handle),
                    )
                })
            }
            MountLifecycle::MOUNT_LIFECYCLE_RELEASED => conflict(
                AttachmentReconciliationConflictV1::ReleasedGeneration,
                Some(resource.handle),
            ),
            MountLifecycle::MOUNT_LIFECYCLE_ALLOCATED
            | MountLifecycle::MOUNT_LIFECYCLE_PUBLISHING
            | MountLifecycle::MOUNT_LIFECYCLE_DRAINING
            | MountLifecycle::MOUNT_LIFECYCLE_DETACHING
            | MountLifecycle::MOUNT_LIFECYCLE_RELEASING
            | MountLifecycle::MOUNT_LIFECYCLE_UNSPECIFIED => conflict(
                AttachmentReconciliationConflictV1::UntrackedTransition,
                Some(resource.handle),
            ),
        };
    }

    if verification.is_some() {
        return conflict(
            AttachmentReconciliationConflictV1::VerificationMismatch,
            None,
        );
    }

    if let Some(resource) = resources.iter().find(|resource| {
        resource.same_attachment
            && resource.same_slot
            && resource.generation < desired_generation
            && resource.lifecycle == MountLifecycle::MOUNT_LIFECYCLE_FAULTED
    }) {
        return fault_action(resource).unwrap_or_else(|| {
            conflict(
                AttachmentReconciliationConflictV1::IncompatibleResource,
                Some(resource.handle),
            )
        });
    }
    if let Some(resource) = resources.iter().find(|resource| {
        resource.same_attachment
            && resource.same_slot
            && resource.generation < desired_generation
            && matches!(
                resource.lifecycle,
                MountLifecycle::MOUNT_LIFECYCLE_ALLOCATED
                    | MountLifecycle::MOUNT_LIFECYCLE_PUBLISHING
                    | MountLifecycle::MOUNT_LIFECYCLE_DETACHING
                    | MountLifecycle::MOUNT_LIFECYCLE_RELEASING
            )
    }) {
        return conflict(
            AttachmentReconciliationConflictV1::UntrackedTransition,
            Some(resource.handle),
        );
    }
    if let Some(resource) = resources.iter().find(|resource| {
        resource.same_attachment
            && resource.same_slot
            && resource.generation < desired_generation
            && matches!(
                resource.lifecycle,
                MountLifecycle::MOUNT_LIFECYCLE_PREPARED | MountLifecycle::MOUNT_LIFECYCLE_DRAINING
            )
    }) {
        return AttachmentReconciliationActionV1::Release {
            mount_handle: resource.handle,
        };
    }

    match replacement_predecessor(resources, desired_generation) {
        Ok(predecessor) => AttachmentReconciliationActionV1::Prepare {
            replacement_mount_handle: predecessor.map(|resource| resource.handle),
        },
        Err(action) => action,
    }
}

fn replacement_predecessor(
    resources: &[ResourceFacts],
    desired_generation: u64,
) -> Result<Option<&ResourceFacts>, AttachmentReconciliationActionV1> {
    let mut installed = resources.iter().filter(|resource| {
        resource.same_attachment
            && resource.same_slot
            && resource.generation < desired_generation
            && resource.lifecycle == MountLifecycle::MOUNT_LIFECYCLE_INSTALLED
    });
    let predecessor = installed.next();
    if installed.next().is_some() {
        return Err(conflict(
            AttachmentReconciliationConflictV1::ReplacementFence,
            predecessor.map(|resource| resource.handle),
        ));
    }
    if let Some(predecessor) = predecessor
        && !predecessor.predecessor_binding
    {
        return Err(conflict(
            AttachmentReconciliationConflictV1::ReplacementFence,
            Some(predecessor.handle),
        ));
    }
    Ok(predecessor)
}

fn decide_release(
    resources: &[ResourceFacts],
    lease_expired: bool,
) -> AttachmentReconciliationActionV1 {
    let matching = |resource: &&ResourceFacts| resource.same_attachment && resource.same_slot;

    if let Some(resource) = resources
        .iter()
        .filter(matching)
        .find(|resource| resource.lifecycle == MountLifecycle::MOUNT_LIFECYCLE_FAULTED)
    {
        return fault_action(resource).unwrap_or_else(|| {
            conflict(
                AttachmentReconciliationConflictV1::IncompatibleResource,
                Some(resource.handle),
            )
        });
    }
    if let Some(resource) = resources.iter().filter(matching).find(|resource| {
        matches!(
            resource.lifecycle,
            MountLifecycle::MOUNT_LIFECYCLE_ALLOCATED
                | MountLifecycle::MOUNT_LIFECYCLE_PUBLISHING
                | MountLifecycle::MOUNT_LIFECYCLE_DETACHING
                | MountLifecycle::MOUNT_LIFECYCLE_RELEASING
        )
    }) {
        return conflict(
            AttachmentReconciliationConflictV1::UntrackedTransition,
            Some(resource.handle),
        );
    }
    if let Some(resource) = resources.iter().filter(matching).find(|resource| {
        matches!(
            resource.lifecycle,
            MountLifecycle::MOUNT_LIFECYCLE_PREPARED | MountLifecycle::MOUNT_LIFECYCLE_DRAINING
        )
    }) {
        return AttachmentReconciliationActionV1::Release {
            mount_handle: resource.handle,
        };
    }
    if let Some(resource) = resources
        .iter()
        .filter(matching)
        .find(|resource| resource.lifecycle == MountLifecycle::MOUNT_LIFECYCLE_INSTALLED)
    {
        return AttachmentReconciliationActionV1::Detach {
            mount_handle: resource.handle,
        };
    }

    if lease_expired {
        AttachmentReconciliationActionV1::LeaseExpired
    } else {
        AttachmentReconciliationActionV1::Released
    }
}

fn fault_action(resource: &ResourceFacts) -> Option<AttachmentReconciliationActionV1> {
    resource.fault.map(
        |(phase, failure_digest)| AttachmentReconciliationActionV1::Fault {
            mount_handle: resource.handle,
            phase,
            failure_digest,
        },
    )
}

const fn occupies_destination(resource: &ResourceFacts) -> bool {
    matches!(
        resource.lifecycle,
        MountLifecycle::MOUNT_LIFECYCLE_PUBLISHING
            | MountLifecycle::MOUNT_LIFECYCLE_INSTALLED
            | MountLifecycle::MOUNT_LIFECYCLE_DETACHING
            | MountLifecycle::MOUNT_LIFECYCLE_DRAINING
    ) || (matches!(
        resource.lifecycle,
        MountLifecycle::MOUNT_LIFECYCLE_RELEASING | MountLifecycle::MOUNT_LIFECYCLE_FAULTED
    ) && resource.installed_unique_mount_id.is_some())
}

const fn conflict(
    reason: AttachmentReconciliationConflictV1,
    mount_handle: Option<[u8; 32]>,
) -> AttachmentReconciliationActionV1 {
    AttachmentReconciliationActionV1::Conflict {
        reason,
        mount_handle,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use aos_proto::aos::sandbox::local::v1::{
        AssignmentFence, Descriptor, InventoryMountResourcesResponse, MountAssignmentBinding,
        MountAttributes as WireMountAttributes, MountInventoryRecord, MountKernelObservation,
        MountOperationCorrelation, MountPublicationCorrelation, MountRecipe,
    };
    use aos_sandbox_core::model::{AttachmentLease, MountAttributes};
    use aos_sandbox_core::{
        AttachmentId, AttachmentSlotId, DesiredGeneration, IncarnationId, LeaseId, MediaType,
        NamespaceGeneration, ObjectDescriptor, ObjectDigest, Revision, SandboxId, ViewId,
    };
    use aos_sandbox_protocol::decode_mount_inventory_response;
    use buffa::Message as _;

    use super::*;

    const ATTACHMENT: [u8; 16] = [1; 16];
    const SLOT: [u8; 16] = [2; 16];

    fn intent(generation: u64) -> AttachmentIntent {
        AttachmentIntent::new(
            AttachmentId::from_bytes(ATTACHMENT),
            DesiredGeneration::new(generation),
            SandboxId::from_bytes([3; 16]),
            IncarnationId::from_bytes([4; 16]),
            NamespaceGeneration::new(5),
            ViewId::from_bytes([6; 16]),
            Revision::new(generation),
            None,
            ObjectDescriptor::new(
                MediaType::new("application/vnd.aos.sandbox.view.v1+cbor").unwrap(),
                ObjectDigest::from_bytes([7; 32]),
                8,
            ),
            AttachmentSlotId::from_bytes(SLOT),
            AttachmentConsistency::ImmutableRevision,
            ViewMutation::ReadOnly,
            MountAttributes::new(true, true, true, true, true, false),
            AttachmentLease::new(LeaseId::from_bytes([9; 16]), 10, 20).unwrap(),
        )
        .unwrap()
    }

    fn service_intent(generation: u64) -> AttachmentIntent {
        AttachmentIntent::new(
            AttachmentId::from_bytes(ATTACHMENT),
            DesiredGeneration::new(generation),
            SandboxId::from_bytes([3; 16]),
            IncarnationId::from_bytes([4; 16]),
            NamespaceGeneration::new(5),
            ViewId::from_bytes([6; 16]),
            Revision::new(generation),
            None,
            ObjectDescriptor::new(
                MediaType::new("application/vnd.aos.sandbox.view.v1+cbor").unwrap(),
                ObjectDigest::from_bytes([7; 32]),
                8,
            ),
            AttachmentSlotId::from_bytes(SLOT),
            AttachmentConsistency::TransactionalService,
            ViewMutation::Service,
            MountAttributes::new(false, true, true, true, true, false),
            AttachmentLease::new(LeaseId::from_bytes([9; 16]), 10, 20).unwrap(),
        )
        .unwrap()
    }

    fn target() -> TargetFacts {
        TargetFacts {
            sandbox: [3; 16],
            incarnation: [4; 16],
            assignment_epoch: 2,
            assignment_generation: 3,
            assignment_digest: [10; 32],
            namespace_generation: 5,
        }
    }

    fn resource(handle: u8, generation: u64, lifecycle: MountLifecycle) -> ResourceFacts {
        ResourceFacts {
            handle: [handle; 32],
            generation,
            lifecycle,
            same_attachment: true,
            same_slot: true,
            same_scope: true,
            current_binding: generation == 2,
            predecessor_binding: generation == 1,
            recipe_matches: generation == 2,
            installed_unique_mount_id: (lifecycle == MountLifecycle::MOUNT_LIFECYCLE_INSTALLED)
                .then_some(u64::from(handle)),
            verification_matches: false,
            fault: None,
        }
    }

    fn decide_present_for(
        resources: &[ResourceFacts],
        attempts: &[AttemptFacts],
    ) -> AttachmentReconciliationActionV1 {
        decide(
            AttachmentDesiredPresenceV1::Present,
            &intent(2),
            15,
            target(),
            resources,
            attempts,
            None,
        )
    }

    fn installed_wire_resource() -> MountInventoryRecord {
        MountInventoryRecord {
            mount_handle: vec![11; 32],
            resource_revision: 1,
            binding: Some(MountAssignmentBinding {
                fence: Some(AssignmentFence {
                    sandbox_id: vec![3; 16],
                    incarnation_id: vec![4; 16],
                    assignment_epoch: 2,
                    desired_generation: 3,
                    assignment_digest: vec![10; 32],
                    ..Default::default()
                })
                .into(),
                namespace_generation: 5,
                ..Default::default()
            })
            .into(),
            recipe: Some(MountRecipe {
                attachment_id: ATTACHMENT.to_vec(),
                destination_slot_id: SLOT.to_vec(),
                view_revision: Some(Descriptor {
                    media_type: "application/vnd.aos.sandbox.view.v1+cbor".to_owned(),
                    sha256: vec![7; 32],
                    encoded_size: 8,
                    ..Default::default()
                })
                .into(),
                source_generation: 2,
                attributes: Some(WireMountAttributes {
                    read_only: true,
                    no_exec: true,
                    no_suid: true,
                    no_device: true,
                    no_atime: true,
                    mutation_mode: 0,
                    recursive: false,
                    ..Default::default()
                })
                .into(),
                resource_attachment_generation: 2,
                source_view_id: vec![6; 16],
                source_consistency:
                    MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_IMMUTABLE_REVISION.into(),
                ..Default::default()
            })
            .into(),
            lifecycle: MountLifecycle::MOUNT_LIFECYCLE_INSTALLED.into(),
            resource_kernel_boot_id: vec![12; 16],
            detached_unique_mount_id: Some(13),
            installed_observation: Some(MountKernelObservation {
                unique_mount_id: 13,
                parent_mount_id: 14,
                mount_namespace_id: 15,
                device_major: 8,
                device_minor: 1,
                superblock_magic: 0xef53,
                superblock_flags: 1,
                mount_attributes: 2,
                propagation: 4,
                root: b"/root".to_vec(),
                mount_point: b"/mnt/view".to_vec(),
                identity_map_digest: vec![16; 32],
                ..Default::default()
            })
            .into(),
            publication: Some(MountPublicationCorrelation {
                operation: Some(MountOperationCorrelation {
                    operation_id: vec![17; 16],
                    request_digest: vec![18; 32],
                    ..Default::default()
                })
                .into(),
                target_mount_namespace_id: 15,
                target_namespace_generation: 5,
                ..Default::default()
            })
            .into(),
            ..Default::default()
        }
    }

    fn validated_resource(record: MountInventoryRecord) -> ValidatedMountInventoryRecord {
        let response = InventoryMountResourcesResponse {
            kernel_boot_id: vec![12; 16],
            journal_sequence: 1,
            mounts: vec![record],
            broker_instance_id: vec![19; 16],
            ..Default::default()
        };
        decode_mount_inventory_response(&response.encode_to_vec(), 16 * 1024 * 1024)
            .unwrap()
            .mounts()[0]
            .clone()
    }

    #[test]
    fn present_generation_prepares_installs_replaces_and_verifies() {
        assert_eq!(
            decide_present_for(&[], &[]),
            AttachmentReconciliationActionV1::Prepare {
                replacement_mount_handle: None,
            }
        );

        let predecessor = resource(11, 1, MountLifecycle::MOUNT_LIFECYCLE_INSTALLED);
        assert_eq!(
            decide_present_for(&[predecessor], &[]),
            AttachmentReconciliationActionV1::Prepare {
                replacement_mount_handle: Some([11; 32]),
            }
        );

        let prepared = resource(12, 2, MountLifecycle::MOUNT_LIFECYCLE_PREPARED);
        assert_eq!(
            decide_present_for(&[prepared], &[]),
            AttachmentReconciliationActionV1::Install {
                mount_handle: [12; 32],
            }
        );
        assert_eq!(
            decide_present_for(&[predecessor, prepared], &[]),
            AttachmentReconciliationActionV1::Replace {
                mount_handle: [12; 32],
                replacement_mount_handle: [11; 32],
            }
        );

        let installed = resource(12, 2, MountLifecycle::MOUNT_LIFECYCLE_INSTALLED);
        assert_eq!(
            decide_present_for(&[installed], &[]),
            AttachmentReconciliationActionV1::Verify {
                mount_handle: [12; 32],
                unique_mount_id: 12,
            }
        );
    }

    #[test]
    fn only_an_exact_verified_resource_is_ready() {
        let mut installed = resource(12, 2, MountLifecycle::MOUNT_LIFECYCLE_INSTALLED);
        installed.verification_matches = true;
        let verification = VerificationFacts {
            mount_handle: [12; 32],
            unique_mount_id: 12,
            record_digest: [13; 32],
        };

        assert_eq!(
            decide(
                AttachmentDesiredPresenceV1::Present,
                &intent(2),
                15,
                target(),
                &[installed],
                &[],
                Some(verification),
            ),
            AttachmentReconciliationActionV1::Ready {
                mount_handle: [12; 32],
                unique_mount_id: 12,
                verification_digest: [13; 32],
            }
        );

        let changed = resource(12, 2, MountLifecycle::MOUNT_LIFECYCLE_INSTALLED);
        assert_eq!(
            decide(
                AttachmentDesiredPresenceV1::Present,
                &intent(2),
                15,
                target(),
                &[changed],
                &[],
                Some(verification),
            ),
            AttachmentReconciliationActionV1::Conflict {
                reason: AttachmentReconciliationConflictV1::VerificationMismatch,
                mount_handle: Some([12; 32]),
            }
        );
        assert_eq!(
            decide(
                AttachmentDesiredPresenceV1::Present,
                &intent(2),
                15,
                target(),
                &[],
                &[],
                Some(verification),
            ),
            AttachmentReconciliationActionV1::Conflict {
                reason: AttachmentReconciliationConflictV1::VerificationMismatch,
                mount_handle: None,
            }
        );
    }

    #[test]
    fn release_and_expiry_drain_without_relabeling_resource_generations() {
        let prepared = resource(11, 1, MountLifecycle::MOUNT_LIFECYCLE_PREPARED);
        assert_eq!(
            decide(
                AttachmentDesiredPresenceV1::Released,
                &intent(2),
                15,
                target(),
                &[prepared],
                &[],
                None,
            ),
            AttachmentReconciliationActionV1::Release {
                mount_handle: [11; 32],
            }
        );

        let installed = resource(11, 1, MountLifecycle::MOUNT_LIFECYCLE_INSTALLED);
        assert_eq!(
            decide(
                AttachmentDesiredPresenceV1::Released,
                &intent(2),
                15,
                target(),
                &[installed],
                &[],
                None,
            ),
            AttachmentReconciliationActionV1::Detach {
                mount_handle: [11; 32],
            }
        );
        assert_eq!(
            decide(
                AttachmentDesiredPresenceV1::Present,
                &intent(2),
                20,
                target(),
                &[],
                &[],
                None,
            ),
            AttachmentReconciliationActionV1::LeaseExpired
        );
        assert_eq!(
            decide(
                AttachmentDesiredPresenceV1::Released,
                &intent(2),
                15,
                target(),
                &[],
                &[],
                None,
            ),
            AttachmentReconciliationActionV1::Released
        );
    }

    #[test]
    fn pending_and_faulted_attempts_block_competing_plans() {
        let pending = AttemptFacts {
            request_id: [13; 16],
            action: MountAction::MOUNT_ACTION_CREATE_DETACHED,
            attachment_id: ATTACHMENT,
            destination_slot_id: SLOT,
            desired_generation: 2,
            resource_generation: 2,
            mount_handle: [14; 32],
            status: MountAttemptInventoryStatusV1::Pending {
                lifecycle: MountLifecycle::MOUNT_LIFECYCLE_ALLOCATED,
            },
        };
        assert_eq!(
            decide_present_for(&[], &[pending]),
            AttachmentReconciliationActionV1::Wait {
                request_id: [13; 16],
                mount_handle: [14; 32],
                lifecycle: MountLifecycle::MOUNT_LIFECYCLE_ALLOCATED,
            }
        );
        assert_eq!(
            decide_present_for(&[], &[pending, pending]),
            AttachmentReconciliationActionV1::Conflict {
                reason: AttachmentReconciliationConflictV1::CompetingOperations,
                mount_handle: Some([14; 32]),
            }
        );

        let mut faulted = resource(15, 2, MountLifecycle::MOUNT_LIFECYCLE_FAULTED);
        faulted.fault = Some((MountFaultPhase::MOUNT_FAULT_PHASE_PREPARED, [16; 32]));
        let fault_attempt = AttemptFacts {
            status: MountAttemptInventoryStatusV1::Faulted {
                phase: MountFaultPhase::MOUNT_FAULT_PHASE_PREPARED,
            },
            mount_handle: faulted.handle,
            ..pending
        };
        assert_eq!(
            decide_present_for(&[faulted], &[fault_attempt]),
            AttachmentReconciliationActionV1::Fault {
                mount_handle: [15; 32],
                phase: MountFaultPhase::MOUNT_FAULT_PHASE_PREPARED,
                failure_digest: [16; 32],
            }
        );
    }

    #[test]
    fn mismatched_slot_fence_and_recipe_fail_closed() {
        let mut occupied = resource(17, 2, MountLifecycle::MOUNT_LIFECYCLE_INSTALLED);
        occupied.same_attachment = false;
        assert_eq!(
            decide_present_for(&[occupied], &[]),
            AttachmentReconciliationActionV1::Conflict {
                reason: AttachmentReconciliationConflictV1::DestinationOccupied,
                mount_handle: Some([17; 32]),
            }
        );

        let mut incompatible = resource(18, 2, MountLifecycle::MOUNT_LIFECYCLE_PREPARED);
        incompatible.recipe_matches = false;
        assert_eq!(
            decide_present_for(&[incompatible], &[]),
            AttachmentReconciliationActionV1::Conflict {
                reason: AttachmentReconciliationConflictV1::IncompatibleResource,
                mount_handle: Some([18; 32]),
            }
        );

        let mut predecessor = resource(19, 1, MountLifecycle::MOUNT_LIFECYCLE_INSTALLED);
        predecessor.predecessor_binding = false;
        assert_eq!(
            decide_present_for(&[predecessor], &[]),
            AttachmentReconciliationActionV1::Conflict {
                reason: AttachmentReconciliationConflictV1::ReplacementFence,
                mount_handle: Some([19; 32]),
            }
        );
    }

    #[test]
    fn lease_issue_time_and_service_projection_are_explicit() {
        assert_eq!(
            decide(
                AttachmentDesiredPresenceV1::Present,
                &intent(2),
                9,
                target(),
                &[],
                &[],
                None,
            ),
            AttachmentReconciliationActionV1::AwaitLease { issued_seconds: 10 }
        );

        assert_eq!(
            decide(
                AttachmentDesiredPresenceV1::Present,
                &service_intent(2),
                15,
                target(),
                &[],
                &[],
                None,
            ),
            AttachmentReconciliationActionV1::Conflict {
                reason: AttachmentReconciliationConflictV1::UnsupportedSourceConsistency,
                mount_handle: None,
            }
        );
    }

    #[test]
    fn physical_recipe_matching_checks_every_mutable_recipe_dimension() {
        let expected = intent(2);
        let base = installed_wire_resource();
        let exact = validated_resource(base.clone());
        assert!(recipe_matches_intent(&exact, &expected));
        let projected = project_resource(&exact, &expected, target(), false);
        assert!(projected.current_binding);
        assert!(projected.recipe_matches);

        let mut substitutions = Vec::new();

        let mut changed = base.clone();
        changed.recipe.get_or_insert_default().attachment_id = vec![20; 16];
        substitutions.push(changed);

        let mut changed = base.clone();
        changed.recipe.get_or_insert_default().destination_slot_id = vec![20; 16];
        substitutions.push(changed);

        let mut changed = base.clone();
        changed
            .recipe
            .get_or_insert_default()
            .view_revision
            .get_or_insert_default()
            .sha256 = vec![20; 32];
        substitutions.push(changed);

        let mut changed = base.clone();
        changed.recipe.get_or_insert_default().source_generation = 3;
        substitutions.push(changed);

        let mut changed = base.clone();
        changed
            .recipe
            .get_or_insert_default()
            .resource_attachment_generation = 3;
        substitutions.push(changed);

        let mut changed = base.clone();
        changed.recipe.get_or_insert_default().source_view_id = vec![20; 16];
        substitutions.push(changed);

        let mut changed = base.clone();
        let recipe = changed.recipe.get_or_insert_default();
        recipe.source_consistency =
            MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_LOCAL_LIVE.into();
        recipe.source_incarnation_id = vec![20; 16];
        substitutions.push(changed);

        for change in [
            |attributes: &mut WireMountAttributes| attributes.no_exec = false,
            |attributes: &mut WireMountAttributes| attributes.no_atime = false,
            |attributes: &mut WireMountAttributes| attributes.recursive = true,
        ] {
            let mut changed = base.clone();
            change(
                changed
                    .recipe
                    .get_or_insert_default()
                    .attributes
                    .get_or_insert_default(),
            );
            substitutions.push(changed);
        }

        let mut changed = base;
        let attributes = changed
            .recipe
            .get_or_insert_default()
            .attributes
            .get_or_insert_default();
        attributes.read_only = false;
        attributes.mutation_mode = 1;
        substitutions.push(changed);

        for substitution in substitutions {
            assert!(!recipe_matches_intent(
                &validated_resource(substitution),
                &expected
            ));
        }
    }
}
