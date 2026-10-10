//! Canonical historical FUSE DATA enclosure and genuine Native admission capture.

use aos_proto::aos::sandbox::v1::{Attachment, FilesystemView};
use aos_sandbox_core::{IncarnationId, ObjectDigest, OperationId, PrincipalId, ProjectId};
use aos_sandbox_protocol::public_api::mutation_history::ControllerFuseAdmissionCarrierV1 as HistoricalCarrier;
use super::{ControllerFuseAdmissionErrorV1, exact_id};
use aos_sandbox_protocol::public_api::projection::{
    PublicProjectionKindV1, PublicProjectionPlanV1, PublicProjectionResourceV1,
    decode_checked_public_projection_v1,
};
use crate::controller_service::public_projection::{PublicProjectionStoreV1};
use crate::public_mutation_compiler::AuthorizedPublicMutationRequestV1;
use crate::{Journal, PublicMutationEffectV1};

#[cfg(test)]
mod tests;

/// Retains canonical original Attach authority without granting worker reads.
///
/// Only the authenticated admission compiler constructs the native enclosure. Retained bytes
/// remain historical facts after expiry/revocation; the held owner token and
/// every later current read check are separate requirements.
#[derive(Clone, Eq, PartialEq)]
pub struct ControllerFuseAdmissionCarrierV1(HistoricalCarrier);

impl std::fmt::Debug for ControllerFuseAdmissionCarrierV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&self.0, formatter)
    }
}

impl ControllerFuseAdmissionCarrierV1 {
    // These fixed crate-private projections issue no Native admission/current owner.
    pub(crate) fn from_history(history: HistoricalCarrier) -> Self {
        Self(history)
    }

    pub(crate) fn history(&self) -> &HistoricalCarrier {
        &self.0
    }

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
            || record.project() != authority.project()
            || view.project() != authority.project()
            || sandbox.project_id.as_slice() != authority.project().as_bytes()
        {
            return Err(ControllerFuseAdmissionErrorV1::Rejected);
        }

        let parts = (
            operation,
            ObjectDigest::from_bytes(request_digest),
            authority,
            ordinary_effect.encode_plain()?,
            desired.0.clone(),
            desired.1.clone(),
            view_plan.desired_key().to_vec(),
            view_plan.desired_value().to_vec(),
            incarnation,
        );
        HistoricalCarrier::from_stored_parts(parts)
            .map(Self)
            .map_err(super::history_error)
    }

    /// Decodes historical DATA without issuing a held Native owner.
    ///
    /// # Errors
    /// Retains the original flat rejection or ledger context cause.
    pub(crate) fn decode(bytes: &[u8]) -> Result<Option<Self>, ControllerFuseAdmissionErrorV1> {
        HistoricalCarrier::decode(bytes)
            .map(|carrier| carrier.map(Self))
            .map_err(super::history_error)
    }

    /// Returns exact historical canonical bytes, not read authority.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        self.0.canonical_bytes()
    }

    /// Returns the domain-separated carrier commitment.
    #[must_use]
    pub fn digest(&self) -> ObjectDigest {
        self.0.digest()
    }

    /// Returns the operation that atomically accepted the original Attachment.
    #[must_use]
    pub const fn operation(&self) -> OperationId {
        self.0.operation()
    }

    /// Returns the original Controller-scoped idempotency request commitment.
    #[must_use]
    pub const fn request_digest(&self) -> ObjectDigest {
        self.0.request_digest()
    }

    /// Returns the original authenticated holder for comparison only.
    #[must_use]
    pub const fn holder(&self) -> PrincipalId {
        self.0.holder()
    }

    /// Returns the original authenticated project for comparison only.
    #[must_use]
    pub const fn project(&self) -> ProjectId {
        self.0.project()
    }

    /// Returns the exact accepted Attachment desired record.
    #[must_use]
    pub const fn attachment(&self) -> &Attachment {
        self.0.attachment()
    }

    /// Returns the original View, even when its latest revision differs.
    #[must_use]
    pub const fn original_view(&self) -> &FilesystemView {
        self.0.original_view()
    }

    /// Returns the genuinely observed original incarnation, when present.
    ///
    /// Replace admission need not have a live runtime. An absent historical
    /// observation never substitutes for the later held Mount runtime check.
    #[must_use]
    pub const fn incarnation(&self) -> Option<IncarnationId> {
        self.0.incarnation()
    }

    /// Returns the unchanged nested public-mutation admission context.
    pub(crate) fn ordinary_effect(&self) -> &[u8] {
        self.0.ordinary_effect()
    }
}
