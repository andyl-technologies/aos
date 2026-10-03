//! Completes source-verified public filesystem-view mutations.
//!
//! Creation binds an accepted projection to exact project-sealed View bytes
//! before publishing revision one in protected controller custody. Release
//! checks that protected revision and waits for attachment and Mount custody to
//! drain before committing a terminal tombstone. Replay reads protected state
//! first, independent of staged source availability and mutable projections.

use aos_filesystem_view_core::load_exact;
use aos_proto::aos::sandbox::v1::{
    CreateViewRequest, ObjectDescriptor as ProtoObjectDescriptor, ReleaseViewRequest, ViewPhase,
};
use aos_sandbox::controller_service::public_projection::{
    PublicProjectionKindV1, PublicProjectionResourceV1, PublicProjectionStoreV1,
};
use aos_sandbox::filesystem_view_state::{
    FilesystemViewRevisionMutationV1, FilesystemViewRevisionPresenceV1,
    FilesystemViewRevisionStateError, commit_protected_filesystem_view_revision_v1,
    filesystem_view_creation_id_v1, protected_current_filesystem_view_revision_v1,
    protected_filesystem_view_revision_v1,
};
use aos_sandbox_core::{
    DecodeLimits, DescriptorRole, MediaType, ObjectDescriptor, ObjectDigest, ProjectId, Revision,
    ViewId, decode_view, validate_descriptor_role,
};
use sha2::{Digest as _, Sha256};

use super::{
    EffectFailure, EffectObservation, EffectReceipt, Journal, OperationId, PublicMutationEffectV1,
};
use crate::ProjectSealedViewObjectSourceV1;

const MAXIMUM_VIEW_BYTES: usize = 1024 * 1024;
const REQUEST_DIGEST_DOMAIN: &[u8] = b"aos.sandbox.public-view-effect.v1\0";
const CREATE_RECEIPT_MAGIC: &[u8; 8] = b"AOSVCR01";
const RELEASE_RECEIPT_MAGIC: &[u8; 8] = b"AOSVRL01";

pub(super) fn observe_create_view(
    operation_id: OperationId,
    context: &PublicMutationEffectV1,
    request: &CreateViewRequest,
    journal: &Journal,
) -> Result<EffectObservation, EffectFailure> {
    let descriptor = requested_descriptor(context.project(), request)?;
    let digest = normalized_request_digest(context);
    let derived_id = filesystem_view_creation_id_v1(operation_id);
    if let Some(revision) =
        protected_filesystem_view_revision_v1(journal, derived_id, Revision::new(1))
            .map_err(permanent)?
    {
        // A newer public projection may name a successor descriptor. The
        // protected creation record, not that mutable projection, proves the
        // completed operation. A present projection must still be in scope.
        if PublicProjectionStoreV1::new(journal)
            .get(
                PublicProjectionKindV1::FilesystemView,
                *derived_id.as_bytes(),
            )
            .map_err(permanent)?
            .is_some_and(|record| record.project() != context.project())
        {
            return Err(EffectFailure::Permanent(
                "derived View identity belongs to another project".to_owned(),
            ));
        }
        return verified_creation_receipt(operation_id, derived_id, digest, &descriptor, &revision)
            .map(EffectObservation::Applied);
    }

    let (view_id, _) = accepted_creation(operation_id, context.project(), request, journal)?;
    if view_id == derived_id {
        return Ok(EffectObservation::Absent);
    }
    let revision = protected_filesystem_view_revision_v1(journal, view_id, Revision::new(1))
        .map_err(permanent)?;
    let Some(revision) = revision else {
        return Ok(EffectObservation::Absent);
    };

    verified_creation_receipt(operation_id, view_id, digest, &descriptor, &revision)
        .map(EffectObservation::Applied)
}

fn verified_creation_receipt(
    operation_id: OperationId,
    view_id: ViewId,
    digest: ObjectDigest,
    descriptor: &ObjectDescriptor,
    revision: &aos_sandbox::filesystem_view_state::DurableFilesystemViewRevisionV1,
) -> Result<EffectReceipt, EffectFailure> {
    if revision.view_id() != view_id
        || revision.operation_id() != operation_id
        || revision.request_digest() != digest
        || revision.descriptor() != descriptor
        || revision.presence() != FilesystemViewRevisionPresenceV1::Available
    {
        return Err(EffectFailure::Permanent(
            "protected View revision conflicts with its admitted creation".to_owned(),
        ));
    }

    create_receipt(operation_id, revision.record_digest())
}

pub(super) fn apply_create_view(
    operation_id: OperationId,
    context: &PublicMutationEffectV1,
    request: &CreateViewRequest,
    journal: &mut Journal,
) -> Result<EffectReceipt, EffectFailure> {
    if let EffectObservation::Applied(receipt) =
        observe_create_view(operation_id, context, request, journal)?
    {
        return Ok(receipt);
    }

    let (view_id, descriptor) =
        accepted_creation(operation_id, context.project(), request, journal)?;
    let mut source =
        ProjectSealedViewObjectSourceV1::open_fixed(context.project()).map_err(retryable)?;
    let object = load_exact(&mut source, &descriptor, MAXIMUM_VIEW_BYTES).map_err(retryable)?;
    let view = decode_view(
        object.bytes(),
        DecodeLimits {
            maximum_bytes: MAXIMUM_VIEW_BYTES,
            ..DecodeLimits::default()
        },
    )
    .map_err(permanent)?;
    let mutation = FilesystemViewRevisionMutationV1::new(
        FilesystemViewRevisionPresenceV1::Available,
        view_id,
        Revision::new(1),
        view,
        operation_id,
        normalized_request_digest(context),
        None,
    )
    .map_err(permanent)?;
    let (revision, _) =
        commit_protected_filesystem_view_revision_v1(journal, mutation).map_err(commit_error)?;
    if revision.descriptor() != &descriptor {
        return Err(EffectFailure::Permanent(
            "committed View descriptor differs from admitted source".to_owned(),
        ));
    }

    create_receipt(operation_id, revision.record_digest())
}

pub(super) fn observe_release_view(
    operation_id: OperationId,
    context: &PublicMutationEffectV1,
    request: &ReleaseViewRequest,
    journal: &Journal,
) -> Result<EffectObservation, EffectFailure> {
    let view_id = release_view_id(request)?;
    let current =
        protected_current_filesystem_view_revision_v1(journal, view_id).map_err(permanent)?;
    let Some(current) = current else {
        return Err(EffectFailure::Retryable(
            "View release is awaiting its protected creation revision".to_owned(),
        ));
    };
    if current.presence() == FilesystemViewRevisionPresenceV1::Released {
        if current.operation_id() != operation_id
            || current.request_digest() != normalized_request_digest(context)
        {
            return Err(EffectFailure::Permanent(
                "protected View release belongs to another operation".to_owned(),
            ));
        }
        return release_receipt(operation_id, current.record_digest())
            .map(EffectObservation::Applied);
    }

    accepted_release(operation_id, context.project(), request, journal, &current)?;
    Ok(EffectObservation::Absent)
}

pub(super) fn apply_release_view(
    operation_id: OperationId,
    context: &PublicMutationEffectV1,
    request: &ReleaseViewRequest,
    journal: &mut Journal,
) -> Result<EffectReceipt, EffectFailure> {
    if let EffectObservation::Applied(receipt) =
        observe_release_view(operation_id, context, request, journal)?
    {
        return Ok(receipt);
    }

    let view_id = release_view_id(request)?;
    let previous = protected_current_filesystem_view_revision_v1(journal, view_id)
        .map_err(permanent)?
        .ok_or_else(|| {
            EffectFailure::Retryable(
                "View release is awaiting its protected creation revision".to_owned(),
            )
        })?;
    let revision = Revision::new(previous.revision().get().checked_add(1).ok_or_else(|| {
        EffectFailure::Permanent("View revision counter is exhausted".to_owned())
    })?);
    let mutation = FilesystemViewRevisionMutationV1::new(
        FilesystemViewRevisionPresenceV1::Released,
        view_id,
        revision,
        previous.view().clone(),
        operation_id,
        normalized_request_digest(context),
        Some(previous.record_digest()),
    )
    .map_err(permanent)?;
    let (released, _) = commit_protected_filesystem_view_revision_v1(journal, mutation)
        .map_err(release_commit_error)?;
    release_receipt(operation_id, released.record_digest())
}

fn accepted_release(
    operation_id: OperationId,
    project: ProjectId,
    request: &ReleaseViewRequest,
    journal: &Journal,
    previous: &aos_sandbox::filesystem_view_state::DurableFilesystemViewRevisionV1,
) -> Result<(), EffectFailure> {
    let view_id = release_view_id(request)?;
    let record = PublicProjectionStoreV1::new(journal)
        .get(PublicProjectionKindV1::FilesystemView, *view_id.as_bytes())
        .map_err(permanent)?
        .ok_or_else(|| EffectFailure::Permanent("admitted View release is absent".to_owned()))?;
    if record.project() != project || record.operation() != operation_id {
        return Err(EffectFailure::Permanent(
            "admitted View release belongs to another project or operation".to_owned(),
        ));
    }
    let PublicProjectionResourceV1::FilesystemView(view) = record.resource() else {
        return Err(EffectFailure::Permanent(
            "admitted View release has another resource kind".to_owned(),
        ));
    };
    if view.view_id.as_slice() != view_id.as_bytes()
        || view.project_id.as_slice() != project.as_bytes()
        || view.phase.as_known() != Some(ViewPhase::VIEW_PHASE_RELEASING)
        || view.active_attachment_count != 0
        || previous.presence() != FilesystemViewRevisionPresenceV1::Available
        || view.desired_generation != previous.revision().get().saturating_add(1)
        || view.revision.as_option().is_none_or(|revision| {
            !matches!(portable_descriptor(revision), Ok(descriptor) if &descriptor == previous.descriptor())
        })
    {
        return Err(EffectFailure::Permanent(
            "admitted View release conflicts with protected source revision".to_owned(),
        ));
    }
    Ok(())
}

fn release_view_id(request: &ReleaseViewRequest) -> Result<ViewId, EffectFailure> {
    let id: [u8; 16] = request
        .view_id
        .as_slice()
        .try_into()
        .map_err(|_| EffectFailure::Permanent("View release identity is invalid".to_owned()))?;
    if id == [0; 16] {
        return Err(EffectFailure::Permanent(
            "View release identity is unspecified".to_owned(),
        ));
    }
    Ok(ViewId::from_bytes(id))
}

fn release_receipt(
    operation_id: OperationId,
    revision_digest: ObjectDigest,
) -> Result<EffectReceipt, EffectFailure> {
    let mut bytes = Vec::with_capacity(56);
    bytes.extend_from_slice(RELEASE_RECEIPT_MAGIC);
    bytes.extend_from_slice(operation_id.as_bytes());
    bytes.extend_from_slice(revision_digest.as_bytes());
    EffectReceipt::new(bytes).map_err(permanent)
}

fn accepted_creation(
    operation_id: OperationId,
    project: ProjectId,
    request: &CreateViewRequest,
    journal: &Journal,
) -> Result<(ViewId, ObjectDescriptor), EffectFailure> {
    let descriptor = requested_descriptor(project, request)?;
    let store = PublicProjectionStoreV1::new(journal);
    let derived_id = filesystem_view_creation_id_v1(operation_id);
    let derived = store
        .get(
            PublicProjectionKindV1::FilesystemView,
            *derived_id.as_bytes(),
        )
        .map_err(permanent)?;
    let view = if let Some(record) = derived {
        if record.project() != project {
            return Err(EffectFailure::Permanent(
                "derived View identity belongs to another project".to_owned(),
            ));
        }
        let PublicProjectionResourceV1::FilesystemView(view) = record.resource() else {
            return Err(EffectFailure::Permanent(
                "derived View projection has another resource kind".to_owned(),
            ));
        };
        view.clone()
    } else {
        // Admissions made before derived IDs retain their operation-linked
        // projection until a successor replaces it.
        let records = store.list_operation(operation_id).map_err(permanent)?;
        let mut views = records.into_iter().filter_map(|record| {
            if record.project() != project || record.operation() != operation_id {
                return None;
            }
            match record.resource() {
                PublicProjectionResourceV1::FilesystemView(view) => Some(view.clone()),
                _ => None,
            }
        });
        let view = views.next().ok_or_else(|| {
            EffectFailure::Permanent("admitted View projection is absent".to_owned())
        })?;
        if views.next().is_some() {
            return Err(EffectFailure::Permanent(
                "creation operation has multiple View projections".to_owned(),
            ));
        }
        view
    };
    if view.project_id.as_slice() != project.as_bytes()
        || view.revision.as_option() != request.revision.as_option()
        || view.desired_generation == 0
    {
        return Err(EffectFailure::Permanent(
            "admitted View projection conflicts with the exact request".to_owned(),
        ));
    }
    let view_id: [u8; 16] =
        view.view_id.as_slice().try_into().map_err(|_| {
            EffectFailure::Permanent("admitted View identity is invalid".to_owned())
        })?;
    Ok((ViewId::from_bytes(view_id), descriptor))
}

fn requested_descriptor(
    project: ProjectId,
    request: &CreateViewRequest,
) -> Result<ObjectDescriptor, EffectFailure> {
    if request.project_id.as_slice() != project.as_bytes() {
        return Err(EffectFailure::Permanent(
            "View creation crossed its admitted project".to_owned(),
        ));
    }
    let descriptor = request
        .revision
        .as_option()
        .ok_or_else(|| EffectFailure::Permanent("View revision is absent".to_owned()))
        .and_then(portable_descriptor)?;
    Ok(descriptor)
}

pub(super) fn portable_descriptor(
    value: &ProtoObjectDescriptor,
) -> Result<ObjectDescriptor, EffectFailure> {
    let digest: [u8; 32] =
        value.sha256.as_slice().try_into().map_err(|_| {
            EffectFailure::Permanent("View descriptor digest is invalid".to_owned())
        })?;
    let media = MediaType::new(value.media_type.clone()).map_err(permanent)?;
    let descriptor =
        ObjectDescriptor::new(media, ObjectDigest::from_bytes(digest), value.encoded_size);
    validate_descriptor_role(DescriptorRole::FilesystemViewRevision, &descriptor)
        .map_err(permanent)?;
    Ok(descriptor)
}

fn normalized_request_digest(context: &PublicMutationEffectV1) -> ObjectDigest {
    let request = context.canonical_request();
    let digest: [u8; 32] = Sha256::new()
        .chain_update(REQUEST_DIGEST_DOMAIN)
        .chain_update(context.caller().as_bytes())
        .chain_update(context.project().as_bytes())
        .chain_update((request.len() as u64).to_be_bytes())
        .chain_update(request)
        .finalize()
        .into();
    ObjectDigest::from_bytes(digest)
}

fn create_receipt(
    operation_id: OperationId,
    revision_digest: ObjectDigest,
) -> Result<EffectReceipt, EffectFailure> {
    let mut bytes = Vec::with_capacity(56);
    bytes.extend_from_slice(CREATE_RECEIPT_MAGIC);
    bytes.extend_from_slice(operation_id.as_bytes());
    bytes.extend_from_slice(revision_digest.as_bytes());
    EffectReceipt::new(bytes).map_err(permanent)
}

fn permanent(error: impl ToString) -> EffectFailure {
    EffectFailure::Permanent(error.to_string())
}

fn retryable(error: impl ToString) -> EffectFailure {
    EffectFailure::Retryable(error.to_string())
}

fn commit_error(error: FilesystemViewRevisionStateError) -> EffectFailure {
    match error {
        FilesystemViewRevisionStateError::Journal(_) => retryable(error),
        _ => permanent(error),
    }
}

fn release_commit_error(error: FilesystemViewRevisionStateError) -> EffectFailure {
    match error {
        FilesystemViewRevisionStateError::Journal(_)
        | FilesystemViewRevisionStateError::Conflict => retryable(error),
        _ => permanent(error),
    }
}
