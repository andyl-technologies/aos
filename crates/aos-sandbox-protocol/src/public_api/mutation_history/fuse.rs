//! Complete AOSFCA01 historical Attachment provenance DATA and canonical codec.
//! Decoding and comparison do not grant native admission, backing or current read authority.
//!
//! ```text
//! AOSFCA01 | version:u16be=1 | reserved:6 | json-length:u32be | JSON | SHA256:32
//! ```

use aos_proto::aos::sandbox::v1::{Attachment, FilesystemView};
use aos_sandbox_core::{
    CapabilityRecord, ChannelBinding, IncarnationId, ObjectDescriptor, ObjectDigest, OperationId,
    PortableMediaType, PrincipalId, ProjectId,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use super::FuseHistoryDataError;
use crate::public_api::request::DormantSandboxRequestKindV1 as Request;
use crate::public_api::projection::{PublicProjectionResourceV1, decode_checked_public_projection_v1};
use crate::public_api::public_mutation_context::PublicMutationContextV1;

/// Historical provenance, never independently usable as current read authority.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionAuthorityV1 {
    capability: CapabilityRecord,
    holder: PrincipalId,
    key_binding: ChannelBinding,
    project: ProjectId,
    accepted_wall_seconds: i64,
    policy_generation: u64,
    policy_descriptor: ObjectDescriptor,
    controller_generation: u64,
    authorization_revision: ObjectDigest,
    authenticated_request: ObjectDigest,
}

impl AdmissionAuthorityV1 {
    /// Retains ordered historical DATA without validating or authorizing it.
    ///
    /// Native producers assemble these values in their original evaluation order.
    #[must_use]
    pub fn from_historical_parts(
        parts: (
            CapabilityRecord,
            PrincipalId,
            ChannelBinding,
            ProjectId,
            i64,
            u64,
            ObjectDescriptor,
            u64,
            ObjectDigest,
            ObjectDigest,
        ),
    ) -> Self {
        let (
            capability,
            holder,
            key_binding,
            project,
            accepted_wall_seconds,
            policy_generation,
            policy_descriptor,
            controller_generation,
            authorization_revision,
            authenticated_request,
        ) = parts;
        Self {
            capability,
            holder,
            key_binding,
            project,
            accepted_wall_seconds,
            policy_generation,
            policy_descriptor,
            controller_generation,
            authorization_revision,
            authenticated_request,
        }
    }

    /// Returns the retained historical project DATA.
    #[must_use]
    pub const fn project(&self) -> ProjectId {
        self.project
    }

    /// Checks the complete historical scalar and canonical context joins.
    ///
    /// # Errors
    /// Refuses the original malformed claims or semantic disagreement in original order.
    pub fn validate(&self) -> Result<(), FuseHistoryDataError> {
        let claims = self.capability.claims();
        if claims.holder != self.holder
            || claims.channel_binding != self.key_binding
            || claims.project != self.project
            || claims.policy_digest != self.policy_descriptor.digest()
            || self.policy_descriptor.media_type().as_str() != PortableMediaType::Policy.as_str()
            || self.policy_descriptor.encoded_size() == 0
            || self.policy_generation == 0
            || self.controller_generation == 0
            || self.accepted_wall_seconds < claims.not_before
            || self.accepted_wall_seconds >= claims.expires_at
            || self.authorization_revision.as_bytes() == &[0; 32]
            || self.authenticated_request.as_bytes() == &[0; 32]
        {
            return Err(FuseHistoryDataError::Rejected);
        }
        Ok(())
    }
}

const MAGIC: &[u8; 8] = b"AOSFCA01";
const HEADER_BYTES: usize = 20;
const MAXIMUM_BYTES: usize = 1024 * 1024;
const DOMAIN: &[u8] = b"aos.sandbox.controller-fuse-admission.v1\0";

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
/// The constructor checks historical claims and canonical joins. These facts
/// remain nonauthorizing after expiry or revocation; the genuine held owner
/// token and every later current read check remain separate Native requirements.
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
    /// Checks a complete ordered historical stored tuple without issuing authority.
    ///
    /// # Errors
    /// Refuses inconsistent claims, context/projection joins or canonical bounds.
    #[must_use]
    pub fn from_stored_parts(
        parts: (
            OperationId,
            ObjectDigest,
            AdmissionAuthorityV1,
            Vec<u8>,
            Vec<u8>,
            Vec<u8>,
            Vec<u8>,
            Vec<u8>,
            Option<IncarnationId>,
        ),
    ) -> Result<Self, FuseHistoryDataError> {
        let (
            operation,
            request_digest,
            authority,
            public_effect,
            attachment_key,
            attachment_value,
            original_view_key,
            original_view_value,
            incarnation,
        ) = parts;
        Self::from_stored(StoredCarrier {
            operation,
            request_digest,
            authority,
            public_effect,
            attachment_key,
            attachment_value,
            original_view_key,
            original_view_value,
            incarnation,
        })
    }

    fn from_stored(stored: StoredCarrier) -> Result<Self, FuseHistoryDataError> {
        stored.authority.validate()?;
        if stored.operation.as_bytes() == &[0; 16]
            || stored
                .incarnation
                .is_some_and(|id| id.as_bytes() == &[0; 16])
            || stored.request_digest.as_bytes() == &[0; 32]
            || !stored.public_effect.starts_with(b"AOSPME01")
        {
            return Err(FuseHistoryDataError::Rejected);
        }
        let effect = PublicMutationContextV1::decode(&stored.public_effect)?
            .ok_or(FuseHistoryDataError::Rejected)?;
        let attachment_record =
            decode_checked_public_projection_v1(&stored.attachment_key, &stored.attachment_value)
                .map_err(|_| FuseHistoryDataError::Rejected)?;
        let view_record = decode_checked_public_projection_v1(
            &stored.original_view_key,
            &stored.original_view_value,
        )
        .map_err(|_| FuseHistoryDataError::Rejected)?;
        let PublicProjectionResourceV1::Attachment(attachment) = attachment_record.resource()
        else {
            return Err(FuseHistoryDataError::Rejected);
        };
        let PublicProjectionResourceV1::FilesystemView(view) = view_record.resource() else {
            return Err(FuseHistoryDataError::Rejected);
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
            return Err(FuseHistoryDataError::Rejected);
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
            return Err(FuseHistoryDataError::Rejected);
        }

        let request = crate::public_api::request::ResolvedPublicMutationRequestV1::decode(
            effect.canonical_request(),
        )
        .map_err(|_| FuseHistoryDataError::Rejected)?;
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
                request.selector().ok_or(FuseHistoryDataError::Rejected)?,
            )
            .map_err(|_| FuseHistoryDataError::Rejected)?;

        let json = serde_json::to_vec(&stored).map_err(|_| FuseHistoryDataError::Rejected)?;
        if json
            .len()
            .checked_add(HEADER_BYTES + 32)
            .is_none_or(|length| length > MAXIMUM_BYTES)
        {
            return Err(FuseHistoryDataError::Rejected);
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

    /// Decodes recognized canonical historical carrier bytes without issuing authority.
    ///
    /// # Errors
    /// Refuses original framing, extent, checksum, JSON and canonical/semantic failures.
    pub fn decode(bytes: &[u8]) -> Result<Option<Self>, FuseHistoryDataError> {
        if !bytes.starts_with(MAGIC) {
            return Ok(None);
        }
        if bytes.len() < HEADER_BYTES + 32
            || bytes.len() > MAXIMUM_BYTES
            || bytes[8..10] != 1_u16.to_be_bytes()
            || bytes[10..16] != [0; 6]
        {
            return Err(FuseHistoryDataError::Rejected);
        }
        let length = u32::from_be_bytes(
            bytes[16..20]
                .try_into()
                .map_err(|_| FuseHistoryDataError::Rejected)?,
        ) as usize;
        let end = HEADER_BYTES
            .checked_add(length)
            .ok_or(FuseHistoryDataError::Rejected)?;
        if end.checked_add(32) != Some(bytes.len())
            || Sha256::new()
                .chain_update(DOMAIN)
                .chain_update(&bytes[..end])
                .finalize()
                .as_slice()
                != &bytes[end..]
        {
            return Err(FuseHistoryDataError::Rejected);
        }
        let stored = serde_json::from_slice(&bytes[HEADER_BYTES..end])
            .map_err(|_| FuseHistoryDataError::Rejected)?;
        let carrier = Self::from_stored(stored)?;
        if carrier.canonical != bytes {
            return Err(FuseHistoryDataError::Rejected);
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
    pub fn ordinary_effect(&self) -> &[u8] {
        &self.stored.public_effect
    }
}

#[cfg(test)]
mod tests;
