//! Compares one fresh Mount inventory with exact current controller history.
//!
//! Reconciliation is descriptive and fail-closed. It retains the live
//! namespace target beside a snapshot that postdates the complete durable
//! Mount-attempt and completion set. It classifies exact operation evidence but
//! never turns names, paths, an absent row, or stale audit bytes into authority.

use std::collections::{BTreeMap, BTreeSet};

use aos_proto::aos::sandbox::local::v1::{MountAction, MountFaultPhase, MountLifecycle};
use aos_sandbox_core::RawPairedClockSample;
use aos_sandbox_protocol::{
    ValidatedMountInventoryRecord, ValidatedMountRequest, detached_mount_handle_v1,
};
use sha2::{Digest as _, Sha256};

use super::DurableMountInventorySnapshotV1;
use crate::Journal;
use crate::mount_attempt::completion::CompletionHistory;
use crate::mount_attempt::{
    History as AttemptHistory, MountAttemptError, Record, decode_attempt_body,
};
use crate::ownership_authority::ProtectedOwnershipClockError;
use crate::runtime_scope::CurrentNamespaceTarget;

/// Classifies what a complete Mount inventory proves about one exact attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MountAttemptInventoryStatusV1 {
    /// The complete snapshot has no exact durable operation evidence.
    NotObserved,
    /// Mount retains exact pre-completion operation correlation.
    Pending {
        /// Current broker lifecycle carrying the operation correlation.
        lifecycle: MountLifecycle,
    },
    /// Mount durably faulted the exact operation before a controller receipt.
    Faulted {
        /// Closed phase in which Mount recorded the fault.
        phase: MountFaultPhase,
    },
    /// Mount reached the requested state but the controller lacks its receipt.
    SucceededWithoutReceipt {
        /// Current or later broker lifecycle proving the resource exists.
        lifecycle: MountLifecycle,
    },
    /// Another operation now owns the resource's current lifecycle evidence.
    Superseded {
        /// Current lifecycle that cannot be attributed to this attempt.
        lifecycle: MountLifecycle,
    },
    /// The controller receipt is durable and the resource remains inventoried.
    CompletionRecorded {
        /// Current lifecycle, which may have advanced after completion.
        lifecycle: MountLifecycle,
    },
}

/// Describes inventory evidence for one exact durable Mount attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MountAttemptInventoryObservationV1 {
    request_id: [u8; 16],
    action: MountAction,
    mount_handle: [u8; 32],
    status: MountAttemptInventoryStatusV1,
}

impl MountAttemptInventoryObservationV1 {
    /// Returns the controller and broker idempotency identity.
    #[must_use]
    pub const fn request_id(self) -> [u8; 16] {
        self.request_id
    }

    /// Returns the closed Mount action carried by the attempt.
    #[must_use]
    pub const fn action(self) -> MountAction {
        self.action
    }

    /// Returns the stable resource handle selected by the action.
    #[must_use]
    pub const fn mount_handle(self) -> [u8; 32] {
        self.mount_handle
    }

    /// Returns the exact inventory classification for this attempt.
    #[must_use]
    pub const fn status(self) -> MountAttemptInventoryStatusV1 {
        self.status
    }
}

/// Retains a current namespace proof with its fresh reconciled Mount snapshot.
///
/// This value is not attachment readiness. Its attempt classifications and
/// untracked handles are bounded planning inputs; every later effect must still
/// reacquire its own catalog and signed authority and recheck this live target.
pub struct CurrentMountInventoryReconciliationV1 {
    target: CurrentNamespaceTarget,
    snapshot: DurableMountInventorySnapshotV1,
    attempts: Vec<MountAttemptInventoryObservationV1>,
    untracked_current_mounts: Vec<[u8; 32]>,
}

impl CurrentMountInventoryReconciliationV1 {
    /// Borrows the current live namespace target retained during comparison.
    #[must_use]
    pub const fn target(&self) -> &CurrentNamespaceTarget {
        &self.target
    }

    /// Borrows the exact authenticated durable inventory snapshot.
    #[must_use]
    pub const fn snapshot(&self) -> &DurableMountInventorySnapshotV1 {
        &self.snapshot
    }

    /// Returns current-target attempts in stable request-ID order.
    #[must_use]
    pub fn attempts(&self) -> &[MountAttemptInventoryObservationV1] {
        &self.attempts
    }

    /// Returns current-bound inventory handles lacking any local attempt.
    #[must_use]
    pub fn untracked_current_mounts(&self) -> &[[u8; 32]] {
        &self.untracked_current_mounts
    }

    /// Recovers the retained target for a separately authorized next step.
    ///
    /// Any later preparation rechecks this target and does not inherit
    /// authority from the discarded inventory observation.
    #[must_use]
    pub fn into_target(self) -> CurrentNamespaceTarget {
        self.target
    }
}

pub(crate) fn reconcile_current<T>(
    journal: &mut Journal,
    target: CurrentNamespaceTarget,
    snapshot: DurableMountInventorySnapshotV1,
    clock: &mut T,
) -> Result<CurrentMountInventoryReconciliationV1, MountAttemptError>
where
    T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
{
    target.recheck(journal, clock)?;
    snapshot.recheck(journal)?;

    let attempt_history = AttemptHistory::load(journal)?;
    let completion_history = CompletionHistory::load(journal)?;
    let resources = snapshot
        .inventory
        .mounts()
        .iter()
        .map(|resource| (*resource.mount_handle(), resource))
        .collect::<BTreeMap<_, _>>();
    let target_reference = target.durable_reference();
    let mut referenced_handles = BTreeSet::new();
    let mut attempts = Vec::new();

    for record in attempt_history
        .records
        .values()
        .filter(|record| record.namespace_target == target_reference)
    {
        let request = decode_attempt_body(&record.body, record.deadline_boottime_nanoseconds)?;
        let handle = operation_handle(&request, &record.body)?;
        let resource = resources.get(&handle).copied();
        if let Some(resource) = resource {
            validate_resource_matches_request(resource, &request)?;
            validate_replacement_predecessor(&resources, resource, &request)?;
        }
        let completion_recorded = completion_history.records.contains_key(&record.request_id);
        let status = classify_attempt(record, &request, resource, completion_recorded)?;

        referenced_handles.insert(handle);
        attempts.push(MountAttemptInventoryObservationV1 {
            request_id: record.request_id,
            action: request.action(),
            mount_handle: handle,
            status,
        });
    }

    let untracked_current_mounts = snapshot
        .inventory
        .mounts()
        .iter()
        .filter(|resource| {
            resource_matches_current_target(resource, &target)
                && !referenced_handles.contains(resource.mount_handle())
        })
        .map(|resource| *resource.mount_handle())
        .collect();

    target.recheck(journal, clock)?;
    snapshot.recheck(journal)?;
    Ok(CurrentMountInventoryReconciliationV1 {
        target,
        snapshot,
        attempts,
        untracked_current_mounts,
    })
}

fn operation_handle(
    request: &ValidatedMountRequest,
    request_body: &[u8],
) -> Result<[u8; 32], MountAttemptError> {
    if request.action() == MountAction::MOUNT_ACTION_CREATE_DETACHED {
        Ok(detached_mount_handle_v1(
            Sha256::digest(request_body).into(),
        ))
    } else {
        request
            .detached_mount_handle()
            .copied()
            .ok_or(MountAttemptError::CorruptState)
    }
}

fn validate_resource_matches_request(
    resource: &ValidatedMountInventoryRecord,
    request: &ValidatedMountRequest,
) -> Result<(), MountAttemptError> {
    let binding = resource.binding();
    let fence = binding.fence();
    let request_fence = request.fence();
    let recipe = resource.recipe();
    if fence != request_fence
        || binding.namespace_generation() != request.namespace_generation()
        || recipe.attachment_id() != request.attachment_id()
        || recipe.destination_slot_id() != request.destination_slot_id()
        || recipe.source_generation() != request.source_generation()
        || request
            .view_revision()
            .is_some_and(|revision| recipe.view_revision() != revision)
        || request
            .attributes()
            .is_some_and(|attributes| recipe.attributes() != attributes)
    {
        return Err(MountAttemptError::Conflict);
    }
    Ok(())
}

fn validate_replacement_predecessor(
    resources: &BTreeMap<[u8; 32], &ValidatedMountInventoryRecord>,
    successor: &ValidatedMountInventoryRecord,
    request: &ValidatedMountRequest,
) -> Result<(), MountAttemptError> {
    let Some(predecessor_handle) = request.replacement_mount_handle() else {
        return Ok(());
    };
    let predecessor = resources
        .get(predecessor_handle)
        .copied()
        .ok_or(MountAttemptError::Conflict)?;
    if predecessor.binding() != successor.binding()
        || predecessor.recipe().attachment_id() != successor.recipe().attachment_id()
        || predecessor.recipe().destination_slot_id() != successor.recipe().destination_slot_id()
    {
        return Err(MountAttemptError::Conflict);
    }
    Ok(())
}

fn classify_attempt(
    attempt: &Record,
    request: &ValidatedMountRequest,
    resource: Option<&ValidatedMountInventoryRecord>,
    completion_recorded: bool,
) -> Result<MountAttemptInventoryStatusV1, MountAttemptError> {
    let Some(resource) = resource else {
        return if completion_recorded {
            Err(MountAttemptError::Conflict)
        } else {
            Ok(MountAttemptInventoryStatusV1::NotObserved)
        };
    };
    let lifecycle = resource.lifecycle();
    if completion_recorded {
        return Ok(MountAttemptInventoryStatusV1::CompletionRecorded { lifecycle });
    }

    if operation_matches(resource, request.action(), attempt) {
        if lifecycle == MountLifecycle::MOUNT_LIFECYCLE_FAULTED {
            let phase = resource
                .fault()
                .map(|fault| fault.from())
                .ok_or(MountAttemptError::CorruptState)?;
            return Ok(MountAttemptInventoryStatusV1::Faulted { phase });
        }
        return classify_exact_nonfault(request.action(), lifecycle);
    }

    classify_without_exact_correlation(request.action(), resource)
}

fn operation_matches(
    resource: &ValidatedMountInventoryRecord,
    action: MountAction,
    attempt: &Record,
) -> bool {
    let request_digest: [u8; 32] = Sha256::digest(&attempt.body).into();
    let matches = |operation_id: &[u8; 16], digest: &[u8; 32]| {
        operation_id == &attempt.request_id && digest == &request_digest
    };
    match action {
        MountAction::MOUNT_ACTION_CREATE_DETACHED => resource
            .creation()
            .is_some_and(|value| matches(value.operation_id(), value.request_digest())),
        MountAction::MOUNT_ACTION_INSTALL | MountAction::MOUNT_ACTION_REPLACE => resource
            .publication()
            .is_some_and(|value| matches(value.operation_id(), value.request_digest())),
        MountAction::MOUNT_ACTION_DETACH => resource
            .detachment()
            .is_some_and(|value| matches(value.operation_id(), value.request_digest())),
        MountAction::MOUNT_ACTION_RELEASE => resource
            .release()
            .is_some_and(|value| matches(value.operation_id(), value.request_digest())),
        MountAction::MOUNT_ACTION_UNSPECIFIED => false,
    }
}

fn classify_exact_nonfault(
    action: MountAction,
    lifecycle: MountLifecycle,
) -> Result<MountAttemptInventoryStatusV1, MountAttemptError> {
    let status = match (action, lifecycle) {
        (MountAction::MOUNT_ACTION_CREATE_DETACHED, MountLifecycle::MOUNT_LIFECYCLE_ALLOCATED)
        | (MountAction::MOUNT_ACTION_INSTALL, MountLifecycle::MOUNT_LIFECYCLE_PUBLISHING)
        | (MountAction::MOUNT_ACTION_REPLACE, MountLifecycle::MOUNT_LIFECYCLE_PUBLISHING)
        | (MountAction::MOUNT_ACTION_DETACH, MountLifecycle::MOUNT_LIFECYCLE_DETACHING)
        | (MountAction::MOUNT_ACTION_RELEASE, MountLifecycle::MOUNT_LIFECYCLE_RELEASING) => {
            MountAttemptInventoryStatusV1::Pending { lifecycle }
        }
        (MountAction::MOUNT_ACTION_CREATE_DETACHED, MountLifecycle::MOUNT_LIFECYCLE_PREPARED)
        | (MountAction::MOUNT_ACTION_INSTALL, MountLifecycle::MOUNT_LIFECYCLE_INSTALLED)
        | (MountAction::MOUNT_ACTION_REPLACE, MountLifecycle::MOUNT_LIFECYCLE_INSTALLED) => {
            MountAttemptInventoryStatusV1::SucceededWithoutReceipt { lifecycle }
        }
        _ => return Err(MountAttemptError::Conflict),
    };
    Ok(status)
}

fn classify_without_exact_correlation(
    action: MountAction,
    resource: &ValidatedMountInventoryRecord,
) -> Result<MountAttemptInventoryStatusV1, MountAttemptError> {
    let lifecycle = resource.lifecycle();
    let status = match action {
        MountAction::MOUNT_ACTION_CREATE_DETACHED => {
            if resource.creation().is_some() {
                return Err(MountAttemptError::Conflict);
            }
            MountAttemptInventoryStatusV1::SucceededWithoutReceipt { lifecycle }
        }
        MountAction::MOUNT_ACTION_INSTALL | MountAction::MOUNT_ACTION_REPLACE => {
            if matches!(
                lifecycle,
                MountLifecycle::MOUNT_LIFECYCLE_ALLOCATED
                    | MountLifecycle::MOUNT_LIFECYCLE_PREPARED
            ) {
                MountAttemptInventoryStatusV1::NotObserved
            } else {
                MountAttemptInventoryStatusV1::Superseded { lifecycle }
            }
        }
        MountAction::MOUNT_ACTION_DETACH => {
            if lifecycle == MountLifecycle::MOUNT_LIFECYCLE_RELEASED {
                MountAttemptInventoryStatusV1::SucceededWithoutReceipt { lifecycle }
            } else if lifecycle == MountLifecycle::MOUNT_LIFECYCLE_INSTALLED {
                MountAttemptInventoryStatusV1::NotObserved
            } else {
                MountAttemptInventoryStatusV1::Superseded { lifecycle }
            }
        }
        MountAction::MOUNT_ACTION_RELEASE => {
            if lifecycle == MountLifecycle::MOUNT_LIFECYCLE_RELEASED {
                MountAttemptInventoryStatusV1::SucceededWithoutReceipt { lifecycle }
            } else if matches!(
                lifecycle,
                MountLifecycle::MOUNT_LIFECYCLE_PREPARED | MountLifecycle::MOUNT_LIFECYCLE_DRAINING
            ) {
                MountAttemptInventoryStatusV1::NotObserved
            } else {
                MountAttemptInventoryStatusV1::Superseded { lifecycle }
            }
        }
        MountAction::MOUNT_ACTION_UNSPECIFIED => return Err(MountAttemptError::CorruptState),
    };
    Ok(status)
}

fn resource_matches_current_target(
    resource: &ValidatedMountInventoryRecord,
    target: &CurrentNamespaceTarget,
) -> bool {
    let binding = target.runtime_generation().scope().binding();
    let manifest = binding.manifest().manifest();
    let resource_binding = resource.binding();
    let fence = resource_binding.fence();
    fence.sandbox_id() == manifest.sandbox().as_bytes()
        && fence.incarnation_id() == manifest.incarnation().as_bytes()
        && fence.assignment_epoch() == manifest.epoch().get()
        && fence.desired_generation() == manifest.desired_generation().get()
        && fence.assignment_digest() == binding.assignment_digest().as_bytes()
        && resource_binding.namespace_generation() == target.target_generation()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use aos_proto::aos::sandbox::local::v1::{
        ApplyMountRequest, AssignmentFence, Audience, Descriptor, InventoryMountResourcesResponse,
        MountAssignmentBinding, MountAttributes, MountFaultCorrelation, MountInventoryRecord,
        MountKernelObservation, MountOperationCorrelation, MountPublicationCorrelation,
        MountRecipe, RequestHeader,
    };
    use aos_sandbox_core::{IncarnationId, SandboxId};
    use aos_sandbox_protocol::{
        PeerCredentials, PeerPolicy, decode_mount_inventory_response, decode_mount_request,
    };
    use buffa::Message as _;

    use super::*;
    use crate::runtime_scope::DurableNamespaceTargetReferenceV1;

    const REQUEST_ID: [u8; 16] = [13; 16];
    const HANDLE: [u8; 32] = [20; 32];

    fn request(action: MountAction) -> (Vec<u8>, ValidatedMountRequest) {
        let carries_view = matches!(
            action,
            MountAction::MOUNT_ACTION_CREATE_DETACHED
                | MountAction::MOUNT_ACTION_INSTALL
                | MountAction::MOUNT_ACTION_REPLACE
        );
        let carries_handle = action != MountAction::MOUNT_ACTION_CREATE_DETACHED;
        let wire = ApplyMountRequest {
            header: Some(RequestHeader {
                protocol_major: 1,
                protocol_minor: 2,
                request_id: REQUEST_ID.to_vec(),
                audience: Audience::AUDIENCE_NODE_CONTROLLER.into(),
                deadline_boottime_nanoseconds: 100,
                maximum_response_bytes: 16 * 1024,
                ..Default::default()
            })
            .into(),
            fence: Some(AssignmentFence {
                sandbox_id: vec![1; 16],
                incarnation_id: vec![2; 16],
                assignment_epoch: 3,
                desired_generation: 4,
                assignment_digest: vec![5; 32],
                ..Default::default()
            })
            .into(),
            action: action.into(),
            attachment_id: vec![7; 16],
            destination_slot_id: vec![8; 16],
            view_revision: carries_view
                .then(|| Descriptor {
                    media_type: "application/vnd.aos.sandbox.view.v1+cbor".to_owned(),
                    sha256: vec![9; 32],
                    encoded_size: 10,
                    ..Default::default()
                })
                .into(),
            detached_mount_handle: if carries_handle {
                HANDLE.to_vec()
            } else {
                Vec::new()
            },
            replacement_mount_handle: if action == MountAction::MOUNT_ACTION_REPLACE {
                vec![21; 32]
            } else {
                Vec::new()
            },
            attributes: carries_view
                .then(|| MountAttributes {
                    read_only: true,
                    no_exec: true,
                    no_suid: true,
                    no_device: true,
                    no_atime: true,
                    ..Default::default()
                })
                .into(),
            source_generation: 11,
            namespace_generation: 6,
            ..Default::default()
        };
        let bytes = wire.encode_to_vec();
        let peer = PeerCredentials {
            uid: 1,
            gid: 1,
            pid: Some(1),
        };
        let validated = decode_mount_request(
            &bytes,
            peer,
            PeerPolicy {
                uid: 1,
                gid: Some(1),
                audience: Audience::AUDIENCE_NODE_CONTROLLER,
            },
            99,
        )
        .unwrap();
        (bytes, validated)
    }

    fn attempt(body: Vec<u8>) -> Record {
        Record {
            request_id: REQUEST_ID,
            namespace_target: DurableNamespaceTargetReferenceV1::from_parts(
                SandboxId::from_bytes([1; 16]),
                IncarnationId::from_bytes([2; 16]),
                1,
                [1; 32],
                6,
                [2; 32],
            ),
            assignment_epoch: 3,
            desired_generation: 4,
            assignment_digest: [5; 32],
            catalog_commitment: [1; 32],
            semantic_digest: [1; 32],
            plan_digest: [1; 32],
            template_digest: [1; 32],
            lease_digest: [1; 32],
            lease_generation: 1,
            deadline_boottime_nanoseconds: 100,
            template_body: vec![1],
            body,
            packet: vec![1],
            digest: [1; 32],
        }
    }

    fn resource(
        action: MountAction,
        lifecycle: MountLifecycle,
        request_body: &[u8],
        exact_operation: bool,
    ) -> ValidatedMountInventoryRecord {
        let handle = if action == MountAction::MOUNT_ACTION_CREATE_DETACHED {
            detached_mount_handle_v1(Sha256::digest(request_body).into())
        } else {
            HANDLE
        };
        let operation = MountOperationCorrelation {
            operation_id: if exact_operation {
                REQUEST_ID.to_vec()
            } else {
                vec![14; 16]
            },
            request_digest: if exact_operation {
                Sha256::digest(request_body).to_vec()
            } else {
                vec![15; 32]
            },
            ..Default::default()
        };
        let binding = MountAssignmentBinding {
            fence: Some(AssignmentFence {
                sandbox_id: vec![1; 16],
                incarnation_id: vec![2; 16],
                assignment_epoch: 3,
                desired_generation: 4,
                assignment_digest: vec![5; 32],
                ..Default::default()
            })
            .into(),
            namespace_generation: 6,
            ..Default::default()
        };
        let recipe = MountRecipe {
            attachment_id: vec![7; 16],
            destination_slot_id: vec![8; 16],
            view_revision: Some(Descriptor {
                media_type: "application/vnd.aos.sandbox.view.v1+cbor".to_owned(),
                sha256: vec![9; 32],
                encoded_size: 10,
                ..Default::default()
            })
            .into(),
            source_generation: 11,
            attributes: Some(MountAttributes {
                read_only: true,
                no_exec: true,
                no_suid: true,
                no_device: true,
                no_atime: true,
                ..Default::default()
            })
            .into(),
            ..Default::default()
        };
        let mut wire = MountInventoryRecord {
            mount_handle: handle.to_vec(),
            resource_revision: 12,
            binding: Some(binding).into(),
            recipe: Some(recipe).into(),
            lifecycle: lifecycle.into(),
            resource_kernel_boot_id: vec![16; 16],
            ..Default::default()
        };
        match lifecycle {
            MountLifecycle::MOUNT_LIFECYCLE_ALLOCATED => {
                wire.creation = Some(operation).into();
            }
            MountLifecycle::MOUNT_LIFECYCLE_PREPARED => {
                wire.detached_unique_mount_id = Some(100);
                wire.creation = Some(operation).into();
            }
            MountLifecycle::MOUNT_LIFECYCLE_PUBLISHING => {
                wire.detached_unique_mount_id = Some(100);
                wire.publication = Some(publication(operation)).into();
            }
            MountLifecycle::MOUNT_LIFECYCLE_INSTALLED => {
                wire.detached_unique_mount_id = Some(100);
                wire.installed_observation = Some(observation()).into();
                wire.publication = Some(publication(operation)).into();
            }
            MountLifecycle::MOUNT_LIFECYCLE_DETACHING => {
                wire.detached_unique_mount_id = Some(100);
                wire.installed_observation = Some(observation()).into();
                wire.detachment = Some(operation).into();
            }
            MountLifecycle::MOUNT_LIFECYCLE_RELEASED => {}
            MountLifecycle::MOUNT_LIFECYCLE_FAULTED => {
                wire.creation = Some(operation).into();
                wire.fault = Some(MountFaultCorrelation {
                    from: MountFaultPhase::MOUNT_FAULT_PHASE_ALLOCATED.into(),
                    failure_digest: vec![18; 32],
                    ..Default::default()
                })
                .into();
            }
            _ => unreachable!(),
        }
        let response = InventoryMountResourcesResponse {
            kernel_boot_id: vec![16; 16],
            broker_instance_id: vec![17; 16],
            journal_sequence: 1,
            mounts: vec![wire],
            ..Default::default()
        }
        .encode_to_vec();
        decode_mount_inventory_response(&response, 16 * 1024)
            .unwrap()
            .mounts()[0]
            .clone()
    }

    fn publication(operation: MountOperationCorrelation) -> MountPublicationCorrelation {
        MountPublicationCorrelation {
            operation: Some(operation).into(),
            target_mount_namespace_id: 200,
            target_namespace_generation: 6,
            ..Default::default()
        }
    }

    fn observation() -> MountKernelObservation {
        MountKernelObservation {
            unique_mount_id: 100,
            parent_mount_id: 99,
            mount_namespace_id: 200,
            superblock_magic: 0xef53,
            root: b"/root".to_vec(),
            mount_point: b"/mnt/view".to_vec(),
            identity_map_digest: vec![19; 32],
            ..Default::default()
        }
    }

    #[test]
    fn exact_create_evidence_distinguishes_pending_success_and_fault() {
        let (body, request) = request(MountAction::MOUNT_ACTION_CREATE_DETACHED);
        let attempt = attempt(body.clone());
        let allocated = resource(
            request.action(),
            MountLifecycle::MOUNT_LIFECYCLE_ALLOCATED,
            &body,
            true,
        );
        let prepared = resource(
            request.action(),
            MountLifecycle::MOUNT_LIFECYCLE_PREPARED,
            &body,
            true,
        );
        let faulted = resource(
            request.action(),
            MountLifecycle::MOUNT_LIFECYCLE_FAULTED,
            &body,
            true,
        );

        assert_eq!(
            classify_attempt(&attempt, &request, Some(&allocated), false).unwrap(),
            MountAttemptInventoryStatusV1::Pending {
                lifecycle: MountLifecycle::MOUNT_LIFECYCLE_ALLOCATED
            }
        );
        assert_eq!(
            classify_attempt(&attempt, &request, Some(&prepared), false).unwrap(),
            MountAttemptInventoryStatusV1::SucceededWithoutReceipt {
                lifecycle: MountLifecycle::MOUNT_LIFECYCLE_PREPARED
            }
        );
        assert_eq!(
            classify_attempt(&attempt, &request, Some(&faulted), false).unwrap(),
            MountAttemptInventoryStatusV1::Faulted {
                phase: MountFaultPhase::MOUNT_FAULT_PHASE_ALLOCATED
            }
        );
    }

    #[test]
    fn publication_evidence_distinguishes_absence_pending_success_and_supersession() {
        let (body, request) = request(MountAction::MOUNT_ACTION_INSTALL);
        let attempt = attempt(body.clone());
        let prepared = resource(
            request.action(),
            MountLifecycle::MOUNT_LIFECYCLE_PREPARED,
            &body,
            false,
        );
        let publishing = resource(
            request.action(),
            MountLifecycle::MOUNT_LIFECYCLE_PUBLISHING,
            &body,
            true,
        );
        let installed = resource(
            request.action(),
            MountLifecycle::MOUNT_LIFECYCLE_INSTALLED,
            &body,
            true,
        );
        let other_install = resource(
            request.action(),
            MountLifecycle::MOUNT_LIFECYCLE_INSTALLED,
            &body,
            false,
        );

        assert_eq!(
            classify_attempt(&attempt, &request, None, false).unwrap(),
            MountAttemptInventoryStatusV1::NotObserved
        );
        assert_eq!(
            classify_attempt(&attempt, &request, Some(&prepared), false).unwrap(),
            MountAttemptInventoryStatusV1::NotObserved
        );
        assert_eq!(
            classify_attempt(&attempt, &request, Some(&publishing), false).unwrap(),
            MountAttemptInventoryStatusV1::Pending {
                lifecycle: MountLifecycle::MOUNT_LIFECYCLE_PUBLISHING
            }
        );
        assert_eq!(
            classify_attempt(&attempt, &request, Some(&installed), false).unwrap(),
            MountAttemptInventoryStatusV1::SucceededWithoutReceipt {
                lifecycle: MountLifecycle::MOUNT_LIFECYCLE_INSTALLED
            }
        );
        assert_eq!(
            classify_attempt(&attempt, &request, Some(&other_install), false).unwrap(),
            MountAttemptInventoryStatusV1::Superseded {
                lifecycle: MountLifecycle::MOUNT_LIFECYCLE_INSTALLED
            }
        );
    }

    #[test]
    fn completion_requires_a_matching_inventoried_resource() {
        let (body, request) = request(MountAction::MOUNT_ACTION_INSTALL);
        let attempt = attempt(body.clone());
        let installed = resource(
            request.action(),
            MountLifecycle::MOUNT_LIFECYCLE_INSTALLED,
            &body,
            true,
        );

        assert!(matches!(
            classify_attempt(&attempt, &request, None, true),
            Err(MountAttemptError::Conflict)
        ));
        assert_eq!(
            classify_attempt(&attempt, &request, Some(&installed), true).unwrap(),
            MountAttemptInventoryStatusV1::CompletionRecorded {
                lifecycle: MountLifecycle::MOUNT_LIFECYCLE_INSTALLED
            }
        );
    }

    #[test]
    fn released_resource_satisfies_an_unacknowledged_detach() {
        let (body, request) = request(MountAction::MOUNT_ACTION_DETACH);
        let attempt = attempt(body.clone());
        let released = resource(
            request.action(),
            MountLifecycle::MOUNT_LIFECYCLE_RELEASED,
            &body,
            false,
        );

        assert_eq!(
            classify_attempt(&attempt, &request, Some(&released), false).unwrap(),
            MountAttemptInventoryStatusV1::SucceededWithoutReceipt {
                lifecycle: MountLifecycle::MOUNT_LIFECYCLE_RELEASED
            }
        );
    }

    #[test]
    fn resource_identity_substitution_fails_before_classification() {
        let (body, validated) = request(MountAction::MOUNT_ACTION_INSTALL);
        let resource = resource(
            validated.action(),
            MountLifecycle::MOUNT_LIFECYCLE_INSTALLED,
            &body,
            true,
        );
        let mut wire = ApplyMountRequest::decode_from_slice(&body).unwrap();
        wire.source_generation += 1;
        let changed = wire.encode_to_vec();
        let wrong_request = decode_mount_request(
            &changed,
            PeerCredentials {
                uid: 1,
                gid: 1,
                pid: Some(1),
            },
            PeerPolicy {
                uid: 1,
                gid: Some(1),
                audience: Audience::AUDIENCE_NODE_CONTROLLER,
            },
            99,
        )
        .unwrap();

        assert!(matches!(
            validate_resource_matches_request(&resource, &wrong_request),
            Err(MountAttemptError::Conflict)
        ));
    }
}
