//! Commits attachment intent from protected View and live consumer authority.
//!
//! New and replacement sources are currently restricted to immutable Views.
//! Detach preserves the prior protected recipe, including a LocalLive source.
//! This is desired state only: later source-acquisition and Mount attachment
//! transactions must prove the physical state before any public Ready result.

use aos_proto::aos::sandbox::v1::{
    AttachViewRequest, Attachment, ViewMutation as PublicViewMutation,
};
use aos_sandbox::Journal;
use aos_sandbox::attachment_effect_owner::ProtectedAttachmentEffectOwnerV1;
use aos_sandbox::attachment_state::{AttachmentDesiredMutationV1, AttachmentDesiredPresenceV1};
use aos_sandbox::filesystem_view_state::{
    FilesystemViewRevisionPresenceV1, protected_current_filesystem_view_revision_v1,
};
use aos_sandbox::ownership_authority::ProtectedOwnershipClockError;
use aos_sandbox::runtime_scope::{CurrentNamespaceTarget, NamespaceTargetOutcome};
use aos_sandbox_core::model::{
    AttachmentConsistency, AttachmentIntent, MountAttributes, ViewConsistency, ViewMutation,
    ViewSource,
};
use aos_sandbox_core::{
    AttachmentId, AttachmentSlotId, DesiredGeneration, NamespaceGeneration, ObjectDigest,
    OperationId, Revision, SandboxId, ViewId,
};
use sha2::{Digest as _, Sha256};

use super::attachment_target::ControllerAttachmentTargetInputsV1;
use super::view_mutations::portable_descriptor;
use super::{
    DormantSandboxRequestKindV1, EffectFailure, ProductionEffectExecutor, PublicMutationEffectV1,
    sample_ownership_clock,
};

const DESIRED_REQUEST_DOMAIN: &[u8] = b"aos.sandbox.public-attachment-desired.v1\0";

#[allow(clippy::too_many_arguments)]
pub(super) fn advance_immutable_attach(
    executor: &mut ProductionEffectExecutor,
    operation: OperationId,
    context: &PublicMutationEffectV1,
    request: &AttachViewRequest,
    projection: &Attachment,
    sandbox: SandboxId,
    slot: AttachmentSlotId,
    journal: &mut Journal,
) -> Result<(), EffectFailure> {
    let attachment_id = attachment_id(projection)?;
    let view_id = view_id(projection)?;
    let revision = Revision::new(projection.source_generation);
    let descriptor = projection
        .view_revision
        .as_option()
        .ok_or_else(|| permanent("admitted attachment View descriptor is absent"))
        .and_then(portable_descriptor)?;
    let mutation = mutation(projection)?;
    let digest = request_digest(context);

    {
        let owner = ProtectedAttachmentEffectOwnerV1::claim(journal)
            .map_err(|error| retryable(error.to_string()))?;
        if let Some(previous) = owner
            .operation(operation)
            .map_err(|error| retryable(error.to_string()))?
        {
            let intent = previous.intent();
            if previous.presence() != AttachmentDesiredPresenceV1::Present
                || previous.request_digest() != digest
                || intent.id() != attachment_id
                || intent.desired_generation().get() != projection.desired_generation
                || intent.consumer().0 != sandbox
                || intent.source_view() != (view_id, revision)
                || intent.view() != &descriptor
                || intent.destination_slot() != slot
                || intent.mutation() != mutation
                || intent.consistency() != AttachmentConsistency::ImmutableRevision
                || intent.mount_attributes().no_exec() != request.noexec
            {
                return Err(permanent(
                    "protected attachment operation conflicts with admitted intent",
                ));
            }
            return Ok(());
        }
        if owner
            .current(attachment_id)
            .map_err(|error| retryable(error.to_string()))?
            .is_some()
        {
            return Err(permanent(
                "attachment creation conflicts with protected state",
            ));
        }
    }

    let source = protected_current_filesystem_view_revision_v1(journal, view_id)
        .map_err(|error| retryable(error.to_string()))?
        .ok_or_else(|| retryable("protected View revision is pending"))?;
    if source.presence() != FilesystemViewRevisionPresenceV1::Available
        || source.revision() != revision
        || source.descriptor() != &descriptor
        || source.view().mutation() != mutation
    {
        return Err(permanent(
            "admitted attachment differs from protected View revision",
        ));
    }
    if source.view().consistency() != ViewConsistency::Immutable
        || !matches!(source.source_handle(), ViewSource::ImmutableTree { .. })
    {
        return Err(retryable("live attachment source currentness is pending"));
    }

    let target = acquire_current_target(executor, journal, sandbox)?;
    let manifest = target
        .runtime_generation()
        .scope()
        .binding()
        .manifest()
        .manifest();
    if manifest.epoch().get() != projection.assignment_epoch
        || projection.desired_generation != 1
        || revision.get() == 0
    {
        return Err(permanent(
            "admitted attachment assignment or generation changed",
        ));
    }
    let incarnation = manifest.incarnation();
    let namespace = NamespaceGeneration::new(target.target_generation());
    let attributes = MountAttributes::new(
        mutation == ViewMutation::ReadOnly,
        request.noexec,
        true,
        true,
        true,
        false,
    );

    let mut owner = ProtectedAttachmentEffectOwnerV1::claim(journal)
        .map_err(|error| retryable(error.to_string()))?;
    let mut clock = || sample_ownership_clock().map_err(|_| ProtectedOwnershipClockError);
    let lease = owner
        .issue_current_lease(&target, &mut clock)
        .map_err(|error| retryable(error.to_string()))?;
    let intent = AttachmentIntent::new(
        attachment_id,
        DesiredGeneration::new(projection.desired_generation),
        sandbox,
        incarnation,
        namespace,
        view_id,
        revision,
        None,
        descriptor,
        slot,
        AttachmentConsistency::ImmutableRevision,
        mutation,
        attributes,
        lease,
    )
    .map_err(|error| permanent(error.to_string()))?;
    let mutation = AttachmentDesiredMutationV1::new(
        AttachmentDesiredPresenceV1::Present,
        intent,
        operation,
        digest,
        None,
    )
    .map_err(|error| permanent(error.to_string()))?;
    owner
        .commit_current(target, mutation, &mut clock)
        .map_err(|error| retryable(error.to_string()))?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn advance_existing(
    executor: &mut ProductionEffectExecutor,
    operation: OperationId,
    context: &PublicMutationEffectV1,
    request: &DormantSandboxRequestKindV1,
    projection: &Attachment,
    sandbox: SandboxId,
    slot: AttachmentSlotId,
    journal: &mut Journal,
) -> Result<(), EffectFailure> {
    let presence = match request {
        DormantSandboxRequestKindV1::ViewReplace(_) => AttachmentDesiredPresenceV1::Present,
        DormantSandboxRequestKindV1::ViewDetach(_) => AttachmentDesiredPresenceV1::Released,
        _ => {
            return Err(permanent(
                "existing attachment mutation has the wrong method",
            ));
        }
    };
    let attachment_id = attachment_id(projection)?;
    let view_id = view_id(projection)?;
    let revision = Revision::new(projection.source_generation);
    let descriptor = projection
        .view_revision
        .as_option()
        .ok_or_else(|| permanent("admitted attachment View descriptor is absent"))
        .and_then(portable_descriptor)?;
    let digest = request_digest(context);
    let previous = {
        let owner = ProtectedAttachmentEffectOwnerV1::claim(journal)
            .map_err(|error| retryable(error.to_string()))?;
        if let Some(completed) = owner
            .operation(operation)
            .map_err(|error| retryable(error.to_string()))?
        {
            let intent = completed.intent();
            if completed.presence() != presence
                || completed.request_digest() != digest
                || intent.id() != attachment_id
                || intent.desired_generation().get() != projection.desired_generation
                || intent.consumer().0 != sandbox
                || intent.source_view() != (view_id, revision)
                || intent.view() != &descriptor
                || intent.destination_slot() != slot
            {
                return Err(permanent(
                    "protected attachment successor conflicts with admitted intent",
                ));
            }
            return Ok(());
        }
        owner
            .current(attachment_id)
            .map_err(|error| retryable(error.to_string()))?
            .ok_or_else(|| retryable("protected predecessor attachment is pending"))?
    };
    let old_intent = previous.intent();
    if previous.presence() != AttachmentDesiredPresenceV1::Present
        || old_intent.consumer().0 != sandbox
        || old_intent.destination_slot() != slot
        || old_intent.desired_generation().get().checked_add(1)
            != Some(projection.desired_generation)
    {
        return Err(permanent(
            "admitted successor conflicts with protected predecessor",
        ));
    }

    let (consistency, source_incarnation) = if presence == AttachmentDesiredPresenceV1::Released {
        if old_intent.source_view() != (view_id, revision) || old_intent.view() != &descriptor {
            return Err(permanent("detachment changed its protected source recipe"));
        }
        (old_intent.consistency(), old_intent.source_incarnation())
    } else {
        let source = protected_current_filesystem_view_revision_v1(journal, view_id)
            .map_err(|error| retryable(error.to_string()))?
            .ok_or_else(|| retryable("replacement View revision is pending"))?;
        if source.presence() != FilesystemViewRevisionPresenceV1::Available
            || source.revision() != revision
            || source.descriptor() != &descriptor
            || source.view().mutation() != old_intent.mutation()
        {
            return Err(permanent(
                "replacement differs from protected View revision",
            ));
        }
        if source.view().consistency() != ViewConsistency::Immutable
            || !matches!(source.source_handle(), ViewSource::ImmutableTree { .. })
        {
            return Err(retryable("live replacement source currentness is pending"));
        }
        (AttachmentConsistency::ImmutableRevision, None)
    };

    let target = acquire_current_target(executor, journal, sandbox)?;
    let manifest = target
        .runtime_generation()
        .scope()
        .binding()
        .manifest()
        .manifest();
    if manifest.epoch().get() != projection.assignment_epoch
        || manifest.incarnation() != old_intent.consumer().1
        || target.target_generation() != old_intent.expected_namespace_generation().get()
    {
        return Err(retryable(
            "attachment predecessor namespace is no longer current",
        ));
    }

    let mut owner = ProtectedAttachmentEffectOwnerV1::claim(journal)
        .map_err(|error| retryable(error.to_string()))?;
    let mut clock = || sample_ownership_clock().map_err(|_| ProtectedOwnershipClockError);
    let lease = owner
        .issue_current_lease(&target, &mut clock)
        .map_err(|error| retryable(error.to_string()))?;
    let intent = AttachmentIntent::new(
        attachment_id,
        DesiredGeneration::new(projection.desired_generation),
        sandbox,
        old_intent.consumer().1,
        old_intent.expected_namespace_generation(),
        view_id,
        revision,
        source_incarnation,
        descriptor,
        slot,
        consistency,
        old_intent.mutation(),
        old_intent.mount_attributes(),
        lease,
    )
    .map_err(|error| permanent(error.to_string()))?;
    let mutation = AttachmentDesiredMutationV1::new(
        presence,
        intent,
        operation,
        digest,
        Some(previous.record_digest()),
    )
    .map_err(|error| permanent(error.to_string()))?;
    owner
        .commit_current(target, mutation, &mut clock)
        .map_err(|error| retryable(error.to_string()))?;
    Ok(())
}

fn acquire_current_target(
    executor: &ProductionEffectExecutor,
    journal: &mut Journal,
    sandbox: SandboxId,
) -> Result<CurrentNamespaceTarget, EffectFailure> {
    let host = executor
        .attachment_host
        .as_ref()
        .ok_or_else(|| retryable("exact Host attachment identity is unavailable"))?;
    let inputs =
        ControllerAttachmentTargetInputsV1::from_protected_configuration(host, executor.node)
            .map_err(|error| retryable(error.to_string()))?;
    match inputs
        .acquire(journal, sandbox)
        .map_err(|error| retryable(error.to_string()))?
    {
        NamespaceTargetOutcome::Current(target) => Ok(*target),
        NamespaceTargetOutcome::AdvanceRequired(_) => Err(retryable(
            "attachment namespace assignment successor is pending",
        )),
    }
}

fn attachment_id(projection: &Attachment) -> Result<AttachmentId, EffectFailure> {
    let bytes: [u8; 16] = projection
        .attachment_id
        .as_slice()
        .try_into()
        .map_err(|_| permanent("admitted attachment identity is invalid"))?;
    Ok(AttachmentId::from_bytes(bytes))
}

fn view_id(projection: &Attachment) -> Result<ViewId, EffectFailure> {
    let bytes: [u8; 16] = projection
        .source_view_id
        .as_slice()
        .try_into()
        .map_err(|_| permanent("admitted source View identity is invalid"))?;
    Ok(ViewId::from_bytes(bytes))
}

fn mutation(projection: &Attachment) -> Result<ViewMutation, EffectFailure> {
    match projection.mutation.as_known() {
        Some(PublicViewMutation::VIEW_MUTATION_READ_ONLY) => Ok(ViewMutation::ReadOnly),
        Some(PublicViewMutation::VIEW_MUTATION_READ_WRITE) => Ok(ViewMutation::ReadWrite),
        Some(PublicViewMutation::VIEW_MUTATION_PRIVATE_COW) => Ok(ViewMutation::PrivateCow),
        Some(PublicViewMutation::VIEW_MUTATION_APPEND_ONLY) => Ok(ViewMutation::AppendOnly),
        Some(PublicViewMutation::VIEW_MUTATION_SERVICE) => Ok(ViewMutation::Service),
        _ => Err(permanent("admitted attachment mutation is invalid")),
    }
}

fn request_digest(context: &PublicMutationEffectV1) -> ObjectDigest {
    let request = context.canonical_request();
    let digest: [u8; 32] = Sha256::new()
        .chain_update(DESIRED_REQUEST_DOMAIN)
        .chain_update(context.caller().as_bytes())
        .chain_update(context.project().as_bytes())
        .chain_update((request.len() as u64).to_be_bytes())
        .chain_update(request)
        .finalize()
        .into();
    ObjectDigest::from_bytes(digest)
}

fn permanent(message: impl Into<String>) -> EffectFailure {
    EffectFailure::Permanent(message.into())
}

fn retryable(message: impl Into<String>) -> EffectFailure {
    EffectFailure::Retryable(message.into())
}
