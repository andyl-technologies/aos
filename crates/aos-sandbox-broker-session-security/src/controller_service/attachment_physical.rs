//! Reconciles protected attachment intent against fresh authenticated Mount state.
//!
//! The result is nonauthorizing. Ready still requires the existing protected
//! post-attach verification record; this adapter never manufactures one from a
//! successful Apply response or a public projection.

use aos_proto::aos::sandbox::local::v1::MountAction;
use aos_sandbox::Journal;
use aos_sandbox::attachment_effect_owner::ProtectedAttachmentEffectOwnerV1;
use aos_sandbox::attachment_mount::PreparedCurrentAttachmentMountV1;
use aos_sandbox::attachment_reconciliation::AttachmentReconciliationActionV1;
use aos_sandbox::attachment_source::{AttachmentSourceActionV1, AttachmentSourceBoundsV1};
use aos_sandbox::attachment_state::AttachmentDesiredPresenceV1;
use aos_sandbox::ownership_authority::ProtectedOwnershipClockError;
use aos_sandbox::runtime_scope::NamespaceTargetOutcome;
use aos_sandbox_core::model::AttachmentConsistency;
use aos_sandbox_core::{AttachmentId, OperationId, SandboxId};

use super::attachment_target::ControllerAttachmentTargetInputsV1;
use super::{
    ControllerBrokerPlanSignerV1, EffectFailure, ProductionEffectExecutor, sample_ownership_clock,
};

pub(super) fn observe(
    executor: &mut ProductionEffectExecutor,
    operation: OperationId,
    attachment: AttachmentId,
    sandbox: SandboxId,
    journal: &mut Journal,
) -> Result<AttachmentReconciliationActionV1, EffectFailure> {
    if drain_pending_before_slot(executor, journal)? {
        return Err(retryable("fresh authenticated Mount inventory is pending"));
    }

    let host = executor
        .attachment_host
        .as_ref()
        .ok_or_else(|| retryable("exact Host attachment identity is unavailable"))?;
    let inputs =
        ControllerAttachmentTargetInputsV1::from_protected_configuration(host, executor.node)
            .map_err(|error| retryable(error.to_string()))?;
    let target = match inputs
        .acquire(journal, sandbox)
        .map_err(|error| retryable(error.to_string()))?
    {
        NamespaceTargetOutcome::Current(target) => *target,
        NamespaceTargetOutcome::AdvanceRequired(_) => {
            return Err(retryable(
                "attachment namespace assignment successor is pending",
            ));
        }
    };

    let mut owner = ProtectedAttachmentEffectOwnerV1::claim(journal)
        .map_err(|error| retryable(error.to_string()))?;
    let desired = owner
        .operation(operation)
        .map_err(|error| retryable(error.to_string()))?
        .ok_or_else(|| retryable("protected attachment generation is pending"))?;
    let current = owner
        .current(attachment)
        .map_err(|error| retryable(error.to_string()))?
        .ok_or_else(|| retryable("current attachment generation is unavailable"))?;
    if desired.record_digest() != current.record_digest() {
        return Err(retryable("attachment generation has a protected successor"));
    }
    if desired.presence() == AttachmentDesiredPresenceV1::Present
        && desired.intent().consistency() != AttachmentConsistency::ImmutableRevision
    {
        return Err(retryable(
            "live source-incarnation proof is not available for this attachment",
        ));
    }

    let fence = owner
        .begin_authenticated_mount_inventory()
        .map_err(|error| retryable(error.to_string()))?;
    let snapshot = {
        let mut sessions = executor
            .sessions
            .lock()
            .map_err(|_| retryable("broker session lock is poisoned"))?;
        let mount = sessions
            .mount
            .as_mut()
            .ok_or_else(|| retryable("authenticated Mount session is unavailable"))?;
        let outcome = mount
            .current_inventory_observation()
            .map_err(|error| retryable(error.to_string()))?;
        owner
            .complete_authenticated_mount_inventory(fence, &outcome)
            .map_err(|error| retryable(error.to_string()))?
    };
    let mut clock = || sample_ownership_clock().map_err(|_| ProtectedOwnershipClockError);
    let (target, snapshot, source_action) = if matches!(
        desired.presence(),
        AttachmentDesiredPresenceV1::Present | AttachmentDesiredPresenceV1::Released
    ) {
        let fence = owner
            .begin_authenticated_source_inventory()
            .map_err(|error| retryable(error.to_string()))?;
        let sources = {
            let mut sessions = executor
                .sessions
                .lock()
                .map_err(|_| retryable("broker session lock is poisoned"))?;
            let mount = sessions
                .mount
                .as_mut()
                .ok_or_else(|| retryable("authenticated Mount session is unavailable"))?;
            let outcome = mount
                .current_source_inventory_observation()
                .map_err(|error| retryable(error.to_string()))?;
            owner
                .complete_authenticated_source_inventory(fence, &outcome)
                .map_err(|error| retryable(error.to_string()))?
        };
        let inventory = owner
            .join_current_mount_filesystem_inventory(snapshot, sources)
            .map_err(|error| retryable(error.to_string()))?;
        let bounds = source_bounds(desired.intent())?;
        let source = owner
            .plan_current_source(desired.clone(), inventory, target, bounds, &mut clock)
            .map_err(|error| retryable(error.to_string()))?;
        let action = source.action();
        if executor
            .pending_attachment_source_consume
            .as_ref()
            .is_some_and(|completed| completed.desired().intent().id() == attachment)
        {
            let completed = executor
                .pending_attachment_source_consume
                .take()
                .ok_or_else(|| retryable("completed detached Create custody is unavailable"))?;
            if completed.desired().record_digest() != desired.record_digest() {
                executor.pending_attachment_source_consume = Some(completed);
                return Err(retryable(
                    "detached Create belongs to a prior desired generation",
                ));
            }
            if let Err(error) = owner.record_current_source_consume(source, &completed, &mut clock)
            {
                executor.pending_attachment_source_consume = Some(completed);
                return Err(retryable(error.to_string()));
            }
            return Err(retryable("detached Create source custody is recorded"));
        }
        if action == AttachmentSourceActionV1::Acquire {
            ensure_mount_policy(executor)?;
            let coordinates = {
                let mut sessions = executor
                    .sessions
                    .lock()
                    .map_err(|_| retryable("broker session lock is poisoned"))?;
                sessions
                    .mount
                    .as_mut()
                    .ok_or_else(|| retryable("authenticated Mount session is unavailable"))?
                    .mount_request_coordinates()
                    .map_err(|error| retryable(error.to_string()))?
            };
            let prepared = owner
                .prepare_current_source_acquire(
                    source,
                    OperationId::from_bytes(coordinates.request_id()),
                    coordinates.deadline_boottime_nanoseconds(),
                    &mut clock,
                )
                .map_err(|error| retryable(error.to_string()))?;
            let scope =
                ControllerBrokerPlanSignerV1::mount_revocation_scope_from_process_credentials()
                    .map_err(|error| retryable(error.to_string()))?;
            let plan = owner
                .current_source_acquire_plan(&prepared, scope, &mut clock)
                .map_err(|error| retryable(error.to_string()))?;
            let issued = plan.issued_seconds();
            let signed = executor
                .broker_plan_signer
                .as_ref()
                .ok_or_else(|| retryable("independent Mount plan signer is unavailable"))?
                .sign_mount_plan(plan, issued)
                .map_err(|error| retryable(error.to_string()))?;
            let bound = owner
                .bind_current_source_acquire(prepared, signed, &mut clock)
                .map_err(|error| retryable(error.to_string()))?;
            let attempt = owner
                .admit_current_source_acquire(bound, &mut clock)
                .map_err(|error| retryable(error.to_string()))?;
            executor.pending_attachment_source_attempt = Some(attempt);
            drop(owner);
            drain_pending_source_attempt(executor, journal)?;
            return Err(retryable("fresh Mount source inventory is pending"));
        }
        if matches!(action, AttachmentSourceActionV1::CompleteAcquire { .. }) {
            owner
                .complete_current_source_acquire(source, &mut clock)
                .map_err(|error| retryable(error.to_string()))?;
            return Err(retryable(
                "source custody completed; fresh Mount inventory is pending",
            ));
        }
        if action == AttachmentSourceActionV1::Released {
            let (target, resources) = source.into_mount_reconciliation_inputs();
            (target, resources, Some(action))
        } else if matches!(action, AttachmentSourceActionV1::CompleteRelease { .. }) {
            owner
                .complete_current_source_release(source, &mut clock)
                .map_err(|error| retryable(error.to_string()))?;
            return Err(retryable(
                "source release custody completed; fresh Mount inventory is pending",
            ));
        } else if matches!(action, AttachmentSourceActionV1::Release { .. }) {
            ensure_mount_policy(executor)?;
            let coordinates = {
                let mut sessions = executor
                    .sessions
                    .lock()
                    .map_err(|_| retryable("broker session lock is poisoned"))?;
                sessions
                    .mount
                    .as_mut()
                    .ok_or_else(|| retryable("authenticated Mount session is unavailable"))?
                    .mount_request_coordinates()
                    .map_err(|error| retryable(error.to_string()))?
            };
            let prepared = owner
                .prepare_current_source_release(
                    source,
                    OperationId::from_bytes(coordinates.request_id()),
                    coordinates.deadline_boottime_nanoseconds(),
                    &mut clock,
                )
                .map_err(|error| retryable(error.to_string()))?;
            let scope =
                ControllerBrokerPlanSignerV1::mount_revocation_scope_from_process_credentials()
                    .map_err(|error| retryable(error.to_string()))?;
            let plan = owner
                .current_source_release_plan(&prepared, scope, &mut clock)
                .map_err(|error| retryable(error.to_string()))?;
            let issued = plan.issued_seconds();
            let signed = executor
                .broker_plan_signer
                .as_ref()
                .ok_or_else(|| retryable("independent Mount plan signer is unavailable"))?
                .sign_mount_plan(plan, issued)
                .map_err(|error| retryable(error.to_string()))?;
            let bound = owner
                .bind_current_source_release(prepared, signed, &mut clock)
                .map_err(|error| retryable(error.to_string()))?;
            let attempt = owner
                .admit_current_source_release(bound, &mut clock)
                .map_err(|error| retryable(error.to_string()))?;
            executor.pending_attachment_source_attempt = Some(attempt);
            drop(owner);
            drain_pending_source_attempt(executor, journal)?;
            return Err(retryable("fresh Mount source inventory is pending"));
        } else {
            let (target, resources) = source.into_mount_reconciliation_inputs();
            (target, resources, Some(action))
        }
    } else {
        (target, snapshot, None)
    };
    let inventory = owner
        .reconcile_current_mount_inventory(target, snapshot, &mut clock)
        .map_err(|error| retryable(error.to_string()))?;
    let reconciliation = owner
        .reconcile_current(desired, inventory, &mut clock)
        .map_err(|error| retryable(error.to_string()))?;
    let action = reconciliation.action();
    if !source_allows_mount(source_action, action) {
        return Err(retryable(
            "protected source acquisition has not reached the Mount transition",
        ));
    }
    if !matches!(
        action,
        AttachmentReconciliationActionV1::Prepare { .. }
            | AttachmentReconciliationActionV1::Install { .. }
            | AttachmentReconciliationActionV1::Replace { .. }
            | AttachmentReconciliationActionV1::Detach { .. }
    ) {
        return Ok(action);
    }

    ensure_mount_policy(executor)?;
    let coordinates = {
        let mut sessions = executor
            .sessions
            .lock()
            .map_err(|_| retryable("broker session lock is poisoned"))?;
        sessions
            .mount
            .as_mut()
            .ok_or_else(|| retryable("authenticated Mount session is unavailable"))?
            .mount_request_coordinates()
            .map_err(|error| retryable(error.to_string()))?
    };
    let query = owner
        .prepare_authenticated_mount_catalog_query(
            reconciliation,
            coordinates.request_id(),
            coordinates.deadline_boottime_nanoseconds(),
            &mut clock,
        )
        .map_err(|error| retryable(error.to_string()))?;
    executor.pending_attachment_catalog_query = Some(query);
    drop(owner);
    drain_pending_catalog_query(executor, journal)?;
    Err(retryable("fresh authenticated Mount inventory is pending"))
}

fn source_bounds(
    intent: &aos_sandbox_core::model::AttachmentIntent,
) -> Result<AttachmentSourceBoundsV1, EffectFailure> {
    let lease = intent.lease();
    let duration = lease
        .expires_seconds()
        .checked_sub(lease.issued_seconds())
        .and_then(|seconds| u64::try_from(seconds).ok())
        .ok_or_else(|| retryable("attachment lease has invalid source duration"))?;
    let lease_seconds =
        duration.min(aos_sandbox_source_provider_protocol::MAXIMUM_SOURCE_LEASE_SECONDS);
    let maximum_submounts = if intent.mount_attributes().recursive() {
        aos_sandbox_source_provider_protocol::MAXIMUM_SOURCE_SUBMOUNTS
    } else {
        0
    };
    AttachmentSourceBoundsV1::new(intent, lease_seconds, maximum_submounts)
        .map_err(|error| retryable(error.to_string()))
}

fn source_allows_mount(
    source: Option<AttachmentSourceActionV1>,
    mount: AttachmentReconciliationActionV1,
) -> bool {
    match (source, mount) {
        (None, _) => true,
        (Some(AttachmentSourceActionV1::Released), AttachmentReconciliationActionV1::Released) => {
            true
        }
        (
            Some(AttachmentSourceActionV1::Consume { .. }),
            AttachmentReconciliationActionV1::Prepare { .. },
        ) => true,
        (
            Some(AttachmentSourceActionV1::AwaitAttachment {
                mount_handle,
                consume_attempt_recorded: true,
                ..
            }),
            AttachmentReconciliationActionV1::Install {
                mount_handle: candidate,
            }
            | AttachmentReconciliationActionV1::Replace {
                mount_handle: candidate,
                ..
            },
        ) => mount_handle == candidate,
        (
            Some(AttachmentSourceActionV1::DrainAttachment { mount_handle, .. }),
            AttachmentReconciliationActionV1::Detach {
                mount_handle: candidate,
            }
            | AttachmentReconciliationActionV1::Release {
                mount_handle: candidate,
            },
        ) => mount_handle == candidate,
        (Some(_), AttachmentReconciliationActionV1::Wait { .. }) => true,
        (
            Some(_),
            AttachmentReconciliationActionV1::Fault { .. }
            | AttachmentReconciliationActionV1::Conflict { .. },
        ) => true,
        _ => false,
    }
}

pub(super) fn drain_pending_before_slot(
    executor: &mut ProductionEffectExecutor,
    journal: &mut Journal,
) -> Result<bool, EffectFailure> {
    if executor.pending_attachment_source_attempt.is_some() {
        drain_pending_source_attempt(executor, journal)?;
        return Ok(true);
    }
    if executor.pending_attachment_mount_attempt.is_some() {
        drain_pending_mount_attempt(executor, journal)?;
        return Ok(true);
    }
    if executor.pending_attachment_catalog_query.is_some() {
        drain_pending_catalog_query(executor, journal)?;
        return Ok(true);
    }
    Ok(false)
}

fn drain_pending_source_attempt(
    executor: &mut ProductionEffectExecutor,
    journal: &mut Journal,
) -> Result<(), EffectFailure> {
    let attempt = executor
        .pending_attachment_source_attempt
        .take()
        .ok_or_else(|| retryable("retained Mount source Acquire is unavailable"))?;
    let mut clock = || sample_ownership_clock().map_err(|_| ProtectedOwnershipClockError);
    if let Err(error) = attempt.recheck(journal, &mut clock) {
        executor.pending_attachment_source_attempt = Some(attempt);
        return Err(retryable(error.to_string()));
    }
    let outcome = (|| {
        let mut sessions = executor
            .sessions
            .lock()
            .map_err(|_| retryable("broker session lock is poisoned"))?;
        sessions
            .mount
            .as_mut()
            .ok_or_else(|| retryable("authenticated Mount session is unavailable"))?
            .authenticated_mount_source_effect(&attempt)
            .map_err(|error| retryable(error.to_string()))
    })();
    let outcome = match outcome {
        Ok(outcome) => outcome,
        Err(error) => {
            executor.pending_attachment_source_attempt = Some(attempt);
            return Err(error);
        }
    };
    if let Err(error) = attempt.validate_terminal_outcome(&outcome) {
        executor.pending_attachment_source_attempt = Some(attempt);
        return Err(retryable(error.to_string()));
    }
    Ok(())
}

fn ensure_mount_policy(executor: &ProductionEffectExecutor) -> Result<(), EffectFailure> {
    executor
        .attachment_mount
        .as_ref()
        .ok_or_else(|| retryable("exact Mount attachment identity is unavailable"))?;
    ControllerBrokerPlanSignerV1::mount_trust_anchor_from_process_credentials()
        .map_err(|error| retryable(error.to_string()))?;
    executor
        .broker_plan_signer
        .as_ref()
        .ok_or_else(|| retryable("independent Mount plan signer is unavailable"))?;
    Ok(())
}

fn drain_pending_catalog_query(
    executor: &mut ProductionEffectExecutor,
    journal: &mut Journal,
) -> Result<(), EffectFailure> {
    let query = executor
        .pending_attachment_catalog_query
        .take()
        .ok_or_else(|| retryable("retained Mount catalog query is unavailable"))?;
    let outcome = (|| {
        let mut sessions = executor
            .sessions
            .lock()
            .map_err(|_| retryable("broker session lock is poisoned"))?;
        sessions
            .mount
            .as_mut()
            .ok_or_else(|| retryable("authenticated Mount session is unavailable"))?
            .authenticated_mount_catalog_preparation(query.query())
            .map_err(|error| retryable(error.to_string()))
    })();
    let outcome = match outcome {
        Ok(outcome) => outcome,
        Err(error) => {
            executor.pending_attachment_catalog_query = Some(query);
            return Err(error);
        }
    };
    let mut clock = || sample_ownership_clock().map_err(|_| ProtectedOwnershipClockError);
    let prepared = query
        .complete_authenticated(journal, &outcome, &mut clock)
        .map_err(|error| retryable(error.to_string()))?;
    admit_and_dispatch_mount(executor, prepared, journal)
}

fn admit_and_dispatch_mount(
    executor: &mut ProductionEffectExecutor,
    prepared: PreparedCurrentAttachmentMountV1,
    journal: &mut Journal,
) -> Result<(), EffectFailure> {
    ensure_mount_policy(executor)?;
    let signer = executor
        .broker_plan_signer
        .as_ref()
        .ok_or_else(|| retryable("independent Mount plan signer is unavailable"))?;
    let scope = ControllerBrokerPlanSignerV1::mount_revocation_scope_from_process_credentials()
        .map_err(|error| retryable(error.to_string()))?;
    let deadline = prepared.valid_until_boottime_nanoseconds();
    let mut owner = ProtectedAttachmentEffectOwnerV1::claim(journal)
        .map_err(|error| retryable(error.to_string()))?;
    let mut clock = || sample_ownership_clock().map_err(|_| ProtectedOwnershipClockError);
    let plan = owner
        .current_mount_plan(&prepared, scope, &mut clock)
        .map_err(|error| retryable(error.to_string()))?;
    let issued = plan.issued_seconds();
    let signed = signer
        .sign_mount_plan(plan, issued)
        .map_err(|error| retryable(error.to_string()))?;
    let bound = owner
        .bind_current_mount_plan(prepared, signed, &mut clock)
        .map_err(|error| retryable(error.to_string()))?;
    let attempt = owner
        .admit_current_mount_effect(bound, deadline, &mut clock)
        .map_err(|error| retryable(error.to_string()))?;
    executor.pending_attachment_mount_attempt = Some(attempt);
    drop(owner);
    drain_pending_mount_attempt(executor, journal)
}

fn drain_pending_mount_attempt(
    executor: &mut ProductionEffectExecutor,
    journal: &mut Journal,
) -> Result<(), EffectFailure> {
    let attempt = executor
        .pending_attachment_mount_attempt
        .take()
        .ok_or_else(|| retryable("retained Mount Apply attempt is unavailable"))?;
    let outcome = (|| {
        let mut sessions = executor
            .sessions
            .lock()
            .map_err(|_| retryable("broker session lock is poisoned"))?;
        sessions
            .mount
            .as_mut()
            .ok_or_else(|| retryable("authenticated Mount session is unavailable"))?
            .authenticated_mount_apply(attempt.attempt())
            .map_err(|error| retryable(error.to_string()))
    })();
    let outcome = match outcome {
        Ok(outcome) => outcome,
        Err(error) => {
            executor.pending_attachment_mount_attempt = Some(attempt);
            return Err(error);
        }
    };
    let mut owner = ProtectedAttachmentEffectOwnerV1::claim(journal)
        .map_err(|error| retryable(error.to_string()))?;
    let mut clock = || sample_ownership_clock().map_err(|_| ProtectedOwnershipClockError);
    let completed = owner
        .complete_authenticated_mount_effect(attempt, &outcome, &mut clock)
        .map_err(|error| retryable(error.to_string()))?;
    if completed.mount_action() == MountAction::MOUNT_ACTION_CREATE_DETACHED {
        executor.pending_attachment_source_consume = Some(completed);
    }
    Ok(())
}

fn retryable(message: impl Into<String>) -> EffectFailure {
    EffectFailure::Retryable(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_proto::aos::sandbox::local::v1::MountLifecycle;

    #[test]
    fn detached_create_requires_completed_active_source_custody() {
        let prepare = AttachmentReconciliationActionV1::Prepare {
            replacement_mount_handle: None,
        };
        assert!(!source_allows_mount(
            Some(AttachmentSourceActionV1::Acquire),
            prepare,
        ));
        assert!(!source_allows_mount(
            Some(AttachmentSourceActionV1::CompleteAcquire {
                acquisition_id: [1; 32],
                revision: 1,
                record_digest: [2; 32],
            }),
            prepare,
        ));
        assert!(source_allows_mount(
            Some(AttachmentSourceActionV1::Consume {
                acquisition_id: [1; 32],
                revision: 1,
                record_digest: [2; 32],
            }),
            prepare,
        ));
    }

    #[test]
    fn installation_and_drain_require_matching_source_phase() {
        let install = AttachmentReconciliationActionV1::Install {
            mount_handle: [3; 32],
        };
        let detach = AttachmentReconciliationActionV1::Detach {
            mount_handle: [3; 32],
        };
        let awaiting = AttachmentSourceActionV1::AwaitAttachment {
            acquisition_id: [1; 32],
            mount_handle: [3; 32],
            lifecycle: MountLifecycle::MOUNT_LIFECYCLE_PREPARED,
            consume_attempt_recorded: true,
        };
        let draining = AttachmentSourceActionV1::DrainAttachment {
            acquisition_id: [1; 32],
            mount_handle: [3; 32],
            lifecycle: MountLifecycle::MOUNT_LIFECYCLE_INSTALLED,
        };
        let uncustodied = AttachmentSourceActionV1::AwaitAttachment {
            acquisition_id: [1; 32],
            mount_handle: [3; 32],
            lifecycle: MountLifecycle::MOUNT_LIFECYCLE_PREPARED,
            consume_attempt_recorded: false,
        };
        assert!(!source_allows_mount(Some(uncustodied), install));
        assert!(source_allows_mount(Some(awaiting), install));
        assert!(!source_allows_mount(
            Some(awaiting),
            AttachmentReconciliationActionV1::Install {
                mount_handle: [4; 32],
            },
        ));
        assert!(!source_allows_mount(Some(draining), install));
        assert!(!source_allows_mount(Some(awaiting), detach));
        assert!(source_allows_mount(Some(draining), detach));
    }
}
