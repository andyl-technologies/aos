//! Canonical original-admission carrier and production-only construction.

use aos_proto::aos::sandbox::v1::{Attachment, FilesystemView};
use aos_sandbox_core::{IncarnationId, ObjectDigest, OperationId, PrincipalId, ProjectId};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::{AdmissionAuthorityV1, ControllerFuseAdmissionErrorV1, exact_id};
use crate::cli_model::DormantSandboxRequestKindV1 as Request;
use crate::controller_service::public_projection::{
    PublicProjectionKindV1, PublicProjectionPlanV1, PublicProjectionResourceV1,
    PublicProjectionStoreV1, decode_checked_public_projection_v1,
};
use crate::public_mutation_compiler::AuthorizedPublicMutationRequestV1;
use crate::{Journal, PublicMutationEffectV1};

const MAGIC: &[u8; 8] = b"AOSFCA01";
const HEADER_BYTES: usize = 20;
const MAXIMUM_BYTES: usize = 1024 * 1024;
const DOMAIN: &[u8] = b"aos.sandbox.controller-fuse-admission.v1\0";

#[cfg(test)]
mod tests;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredCarrier {
    operation: OperationId,
    request_digest: ObjectDigest,
    authority: AdmissionAuthorityV1,
    public_effect: Vec<u8>,
    attachment_key: Vec<u8>,
    attachment_value: Vec<u8>,
    original_view_key: Vec<u8>,
    original_view_value: Vec<u8>,
    incarnation: Option<IncarnationId>,
}

/// Retains canonical original Attach authority without granting worker reads.
///
/// Only the authenticated admission compiler constructs it. Retained bytes
/// remain historical facts after expiry/revocation; the held owner token and
/// every later current read check are separate requirements.
#[derive(Clone, Debug)]
pub struct ControllerFuseAdmissionCarrierV1 {
    stored: StoredCarrier,
    canonical: Vec<u8>,
    attachment: Attachment,
    original_view: FilesystemView,
}

impl PartialEq for ControllerFuseAdmissionCarrierV1 {
    fn eq(&self, other: &Self) -> bool {
        self.canonical == other.canonical
    }
}

impl Eq for ControllerFuseAdmissionCarrierV1 {}

impl ControllerFuseAdmissionCarrierV1 {
    /// Captures original provenance from an actual authenticated admission.
    ///
    /// # Errors
    ///
    /// Rejects missing authenticated capture, inconsistent desired/View/runtime
    /// joins, invalid canonical context or aggregate encoding bounds.
    pub(crate) fn from_authorized(
        journal: &Journal,
        authorized: &AuthorizedPublicMutationRequestV1,
        operation: OperationId,
        request_digest: [u8; 32],
        ordinary_effect: &PublicMutationEffectV1,
        desired: &(Vec<u8>, Vec<u8>),
    ) -> Result<Self, ControllerFuseAdmissionErrorV1> {
        let authority = authorized
            .fuse_authority()
            .ok_or(ControllerFuseAdmissionErrorV1::Rejected)?
            .clone();
        let record = decode_checked_public_projection_v1(&desired.0, &desired.1)
            .map_err(|_| ControllerFuseAdmissionErrorV1::Rejected)?;
        let PublicProjectionResourceV1::Attachment(attachment) = record.resource() else {
            return Err(ControllerFuseAdmissionErrorV1::Rejected);
        };

        let store = PublicProjectionStoreV1::new(journal);
        let view = store
            .get(
                PublicProjectionKindV1::FilesystemView,
                exact_id(&attachment.source_view_id)?,
            )
            .map_err(|_| ControllerFuseAdmissionErrorV1::Rejected)?
            .ok_or(ControllerFuseAdmissionErrorV1::Rejected)?;
        let view_plan =
            PublicProjectionPlanV1::new(view.project(), view.operation(), view.resource().clone())
                .map_err(|_| ControllerFuseAdmissionErrorV1::Rejected)?;
        let sandbox = store
            .get(
                PublicProjectionKindV1::Sandbox,
                exact_id(&attachment.sandbox_id)?,
            )
            .map_err(|_| ControllerFuseAdmissionErrorV1::Rejected)?
            .ok_or(ControllerFuseAdmissionErrorV1::Rejected)?;
        let PublicProjectionResourceV1::Sandbox(sandbox) = sandbox.resource() else {
            return Err(ControllerFuseAdmissionErrorV1::Rejected);
        };
        let incarnation = sandbox
            .observed
            .as_option()
            .and_then(|observed| observed.incarnation_id.as_slice().try_into().ok())
            .map(IncarnationId::from_bytes);
        if record.operation() != operation
            || record.project() != authority.project
            || view.project() != authority.project
            || sandbox.project_id.as_slice() != authority.project.as_bytes()
        {
            return Err(ControllerFuseAdmissionErrorV1::Rejected);
        }

        let stored = StoredCarrier {
            operation,
            request_digest: ObjectDigest::from_bytes(request_digest),
            authority,
            public_effect: ordinary_effect.encode_plain()?,
            attachment_key: desired.0.clone(),
            attachment_value: desired.1.clone(),
            original_view_key: view_plan.desired_key().to_vec(),
            original_view_value: view_plan.desired_value().to_vec(),
            incarnation,
        };
        Self::from_stored(stored)
    }

    fn from_stored(stored: StoredCarrier) -> Result<Self, ControllerFuseAdmissionErrorV1> {
        stored.authority.validate()?;
        if stored.operation.as_bytes() == &[0; 16]
            || stored
                .incarnation
                .is_some_and(|id| id.as_bytes() == &[0; 16])
            || stored.request_digest.as_bytes() == &[0; 32]
            || !stored.public_effect.starts_with(b"AOSPME01")
        {
            return Err(ControllerFuseAdmissionErrorV1::Rejected);
        }
        let effect = PublicMutationEffectV1::decode_plain(&stored.public_effect)?
            .ok_or(ControllerFuseAdmissionErrorV1::Rejected)?;
        let attachment_record =
            decode_checked_public_projection_v1(&stored.attachment_key, &stored.attachment_value)
                .map_err(|_| ControllerFuseAdmissionErrorV1::Rejected)?;
        let view_record = decode_checked_public_projection_v1(
            &stored.original_view_key,
            &stored.original_view_value,
        )
        .map_err(|_| ControllerFuseAdmissionErrorV1::Rejected)?;
        let PublicProjectionResourceV1::Attachment(attachment) = attachment_record.resource()
        else {
            return Err(ControllerFuseAdmissionErrorV1::Rejected);
        };
        let PublicProjectionResourceV1::FilesystemView(view) = view_record.resource() else {
            return Err(ControllerFuseAdmissionErrorV1::Rejected);
        };
        if effect.caller() != stored.authority.holder
            || effect.project() != stored.authority.project
            || effect.accepted_wall_seconds() != stored.authority.accepted_wall_seconds
            || attachment_record.operation() != stored.operation
            || attachment_record.project() != stored.authority.project
            || view_record.project() != stored.authority.project
            || attachment.source_view_id != view.view_id
            || attachment.view_revision != view.revision
            || attachment.source_generation != view.desired_generation
        {
            return Err(ControllerFuseAdmissionErrorV1::Rejected);
        }
        let matches_request = match effect.validated_request()? {
            Request::ViewAttach(request) => request.sandbox_id == attachment.sandbox_id
                && request.view_id == view.view_id
                && request.view_revision == attachment.view_revision
                && request.destination_slot_id == attachment.destination_slot_id
                && request.mutation_mode == attachment.mutation
                && attachment.phase.as_known()
                    == Some(
                        aos_proto::aos::sandbox::v1::AttachmentPhase::ATTACHMENT_PHASE_REQUESTED,
                    )
                && attachment.desired_generation == 1
                && request.mutation.as_option().is_some_and(|mutation| {
                    stored.incarnation.is_some_and(|incarnation| {
                        mutation.expected_incarnation_id.as_slice() == incarnation.as_bytes()
                    })
                }),
            Request::ViewReplace(request) => request.attachment_id == attachment.attachment_id
                && request.new_view_id == view.view_id
                && request.new_view_revision == attachment.view_revision
                && attachment.phase.as_known()
                    == Some(
                        aos_proto::aos::sandbox::v1::AttachmentPhase::ATTACHMENT_PHASE_REPLACING,
                    )
                && attachment.desired_generation > 1,
            _ => false,
        };
        let claims = stored.authority.capability.claims();
        if !matches_request
            || claims
                .sandbox
                .is_some_and(|id| id.as_bytes().as_slice() != attachment.sandbox_id)
            || claims
                .incarnation
                .is_some_and(|id| Some(id) != stored.incarnation)
            || claims
                .assignment_epoch
                .is_some_and(|epoch| epoch.get() != attachment.assignment_epoch)
        {
            return Err(ControllerFuseAdmissionErrorV1::Rejected);
        }

        let request = crate::public_mutation_compiler::ResolvedPublicMutationRequestV1::decode(
            effect.canonical_request(),
        )
        .map_err(|_| ControllerFuseAdmissionErrorV1::Rejected)?;
        let context = aos_sandbox_core::AuthorizationContext {
            now: stored.authority.accepted_wall_seconds,
            audience: claims.audience,
            holder: stored.authority.holder,
            channel_binding: stored.authority.key_binding,
            project: stored.authority.project,
            sandbox: claims.sandbox,
            incarnation: claims.incarnation,
            assignment_epoch: claims.assignment_epoch,
            revocation_generation: claims.revocation_generation,
        };
        stored
            .authority
            .capability
            .authorize(
                &context,
                request.resource_kind(),
                request.operation(),
                request
                    .selector()
                    .ok_or(ControllerFuseAdmissionErrorV1::Rejected)?,
            )
            .map_err(|_| ControllerFuseAdmissionErrorV1::Rejected)?;

        let json =
            serde_json::to_vec(&stored).map_err(|_| ControllerFuseAdmissionErrorV1::Rejected)?;
        if json
            .len()
            .checked_add(HEADER_BYTES + 32)
            .is_none_or(|length| length > MAXIMUM_BYTES)
        {
            return Err(ControllerFuseAdmissionErrorV1::Rejected);
        }
        let mut canonical = Vec::with_capacity(HEADER_BYTES + json.len() + 32);
        canonical.extend_from_slice(MAGIC);
        canonical.extend_from_slice(&1_u16.to_be_bytes());
        canonical.extend_from_slice(&[0; 6]);
        canonical.extend_from_slice(&(json.len() as u32).to_be_bytes());
        canonical.extend_from_slice(&json);
        let digest = Sha256::new()
            .chain_update(DOMAIN)
            .chain_update(&canonical)
            .finalize();
        canonical.extend_from_slice(&digest);
        let attachment = attachment.clone();
        let original_view = view.clone();
        Ok(Self {
            stored,
            canonical,
            attachment,
            original_view,
        })
    }

    /// Decodes retained historical claims without issuing an owner token.
    ///
    /// # Errors
    ///
    /// Rejects malformed versioned framing, checksum/canonical disagreement,
    /// inconsistent historical authority/resource joins or excessive bytes.
    pub(crate) fn decode(bytes: &[u8]) -> Result<Option<Self>, ControllerFuseAdmissionErrorV1> {
        if !bytes.starts_with(MAGIC) {
            return Ok(None);
        }
        if bytes.len() < HEADER_BYTES + 32
            || bytes.len() > MAXIMUM_BYTES
            || bytes[8..10] != 1_u16.to_be_bytes()
            || bytes[10..16] != [0; 6]
        {
            return Err(ControllerFuseAdmissionErrorV1::Rejected);
        }
        let length = u32::from_be_bytes(
            bytes[16..20]
                .try_into()
                .map_err(|_| ControllerFuseAdmissionErrorV1::Rejected)?,
        ) as usize;
        let end = HEADER_BYTES
            .checked_add(length)
            .ok_or(ControllerFuseAdmissionErrorV1::Rejected)?;
        if end.checked_add(32) != Some(bytes.len())
            || Sha256::new()
                .chain_update(DOMAIN)
                .chain_update(&bytes[..end])
                .finalize()
                .as_slice()
                != &bytes[end..]
        {
            return Err(ControllerFuseAdmissionErrorV1::Rejected);
        }
        let stored = serde_json::from_slice(&bytes[HEADER_BYTES..end])
            .map_err(|_| ControllerFuseAdmissionErrorV1::Rejected)?;
        let carrier = Self::from_stored(stored)?;
        if carrier.canonical != bytes {
            return Err(ControllerFuseAdmissionErrorV1::Rejected);
        }
        Ok(Some(carrier))
    }

    /// Returns exact historical canonical bytes, not read authority.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical
    }

    /// Returns the domain-separated carrier commitment.
    #[must_use]
    pub fn digest(&self) -> ObjectDigest {
        ObjectDigest::from_bytes(
            Sha256::new()
                .chain_update(DOMAIN)
                .chain_update(&self.canonical)
                .finalize()
                .into(),
        )
    }

    /// Returns the operation that atomically accepted the original Attachment.
    #[must_use]
    pub const fn operation(&self) -> OperationId {
        self.stored.operation
    }

    /// Returns the original Controller-scoped idempotency request commitment.
    #[must_use]
    pub const fn request_digest(&self) -> ObjectDigest {
        self.stored.request_digest
    }

    /// Returns the original authenticated holder for comparison only.
    #[must_use]
    pub const fn holder(&self) -> PrincipalId {
        self.stored.authority.holder
    }

    /// Returns the original authenticated project for comparison only.
    #[must_use]
    pub const fn project(&self) -> ProjectId {
        self.stored.authority.project
    }

    /// Returns the exact accepted Attachment desired record.
    #[must_use]
    pub const fn attachment(&self) -> &Attachment {
        &self.attachment
    }

    /// Returns the original View, even when its latest revision differs.
    #[must_use]
    pub const fn original_view(&self) -> &FilesystemView {
        &self.original_view
    }

    /// Returns the genuinely observed original incarnation, when present.
    ///
    /// Replace admission need not have a live runtime. An absent historical
    /// observation never substitutes for the later held Mount runtime check.
    #[must_use]
    pub const fn incarnation(&self) -> Option<IncarnationId> {
        self.stored.incarnation
    }

    /// Returns the unchanged nested public-mutation admission context.
    pub(crate) fn ordinary_effect(&self) -> &[u8] {
        &self.stored.public_effect
    }
}
