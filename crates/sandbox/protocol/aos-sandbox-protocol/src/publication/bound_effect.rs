//! Owns the complete checked publication-template to bound-effect DATA recipe.
//!
//! A checked draft supplies the exact template body, semantics and descriptor
//! shape. The resident plan retains that single body allocation until it is
//! consumed with operation coordinates. Native owners retain publication
//! currentness, gated admission, signing, clocks, descriptors and dispatch.

use aos_sandbox_api::aos::sandbox::local::v1::BrokerMethod;
use aos_sandbox_model::{BrokerAudience, ObjectDigest, OperationId};

use super::{AuthorityPublicationDraftV1, PublicationHistoryError};
use crate::dispatch_template::{BrokerDispatchSemanticIdentityV1, semantic_identity_digest};
use crate::domain_ledger::effect_history::{
    AuthorityEffectBindingV1, EffectDomain, EffectHistoryDataError, EffectPlan,
    MAXIMUM_REQUEST_BYTES, effect_body_digest,
};

/// Freezes one exact draft-derived broker effect as nonauthorizing DATA.
///
/// The checked publication supplies every template operand. Native admission
/// still checks its current gate and custody before any effect can execute.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityBoundEffectPlanV1 {
    plan: EffectPlan,
    source_draft_digest: ObjectDigest,
    audience: BrokerAudience,
    template_digest: ObjectDigest,
    descriptor_free: bool,
}

impl AuthorityBoundEffectPlanV1 {
    fn from_template(
        source_draft_digest: ObjectDigest,
        audience: BrokerAudience,
        method: BrokerMethod,
        template_digest: ObjectDigest,
        body: &[u8],
        semantics: BrokerDispatchSemanticIdentityV1,
        descriptor_free: bool,
    ) -> Result<Self, EffectHistoryDataError> {
        if body.is_empty() || body.len() > MAXIMUM_REQUEST_BYTES {
            return Err(EffectHistoryDataError::InvalidPlan(
                "invalid authority effect body",
            ));
        }
        let domain = EffectDomain::from_audience(audience)?;
        let body_digest = effect_body_digest(body);
        let semantic_digest = semantic_identity_digest(semantics);
        Ok(Self {
            plan: EffectPlan::from_parts((
                domain,
                Some(method),
                None,
                body.to_vec(),
                Some(AuthorityEffectBindingV1::from_parts((
                    OperationId::from_bytes([0; 16]),
                    0,
                    source_draft_digest,
                    audience,
                    method,
                    template_digest,
                    body_digest,
                    semantic_digest,
                    descriptor_free,
                    ObjectDigest::from_bytes([0; 32]),
                ))),
            )),
            source_draft_digest,
            audience,
            template_digest,
            descriptor_free,
        })
    }

    /// Returns the publication draft that supplied the exact template.
    #[must_use]
    pub fn source_draft_digest(&self) -> ObjectDigest {
        self.source_draft_digest
    }

    /// Returns the exact selected dispatch-template digest.
    #[must_use]
    pub fn template_digest(&self) -> ObjectDigest {
        self.template_digest
    }

    /// Returns the broker audience derived from the selected template.
    #[must_use]
    pub fn audience(&self) -> BrokerAudience {
        self.audience
    }

    /// Returns the exact deadline-free request body committed by the template.
    #[must_use]
    pub fn body_without_deadline(&self) -> &[u8] {
        self.plan.request()
    }

    /// Checks the closed descriptor-free Apply shape of historical DATA.
    ///
    /// This comparison establishes neither a current publication nor permission
    /// to dispatch the selected template.
    #[must_use]
    pub fn is_supported_authority_apply(&self) -> bool {
        let method_matches_audience = matches!(
            (self.audience, self.plan.method()),
            (
                BrokerAudience::Host,
                Some(BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME)
            ) | (
                BrokerAudience::Storage,
                Some(BrokerMethod::BROKER_METHOD_STORAGE_APPLY)
            ) | (
                BrokerAudience::Mount,
                Some(BrokerMethod::BROKER_METHOD_MOUNT_APPLY)
            ) | (
                BrokerAudience::Network,
                Some(BrokerMethod::BROKER_METHOD_NETWORK_APPLY)
            )
        );

        method_matches_audience && self.descriptor_free
    }

    /// Consumes the complete historical plan after fixing operation coordinates.
    ///
    /// The operation and step select DATA; no Native authority is constructed.
    ///
    /// # Errors
    ///
    /// Returns the original invalid-plan cause for an unsupported audience.
    pub fn into_inner(
        mut self,
        operation_id: OperationId,
        step: u32,
    ) -> Result<EffectPlan, EffectHistoryDataError> {
        self.plan.bind_operation(operation_id, step)?;
        Ok(self.plan)
    }
}

/// Binds an effect to one exact template selected from a checked publication draft.
///
/// The audience, broker method, deadline-free body, and semantic identity
/// are derived from the selected template and cannot be substituted by the
/// caller.
///
/// # Errors
///
/// Returns [`PublicationHistoryError::TemplateAbsent`] when the digest
/// is not present, or [`PublicationHistoryError::InvalidDraft`] if a
/// recovered template cannot produce a bounded effect binding.
pub fn bind_authority_publication_effect(
    draft: &AuthorityPublicationDraftV1,
    template_digest: ObjectDigest,
) -> Result<AuthorityBoundEffectPlanV1, PublicationHistoryError> {
    let template = draft
        .templates()
        .iter()
        .find(|template| template.digest() == template_digest)
        .ok_or(PublicationHistoryError::TemplateAbsent)?;
    AuthorityBoundEffectPlanV1::from_template(
        draft.digest(),
        template.audience(),
        template.method(),
        template.digest(),
        template.body_without_deadline(),
        template.semantics(),
        template.descriptor_roles().is_empty(),
    )
    .map_err(|_| PublicationHistoryError::InvalidDraft)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_model::{BrokerArgumentCommitment, BrokerGrantTarget, BrokerVerb};
    use crate::domain_ledger::effect_history::{EffectLedgerRecord, EffectState, encode_effect};

    #[test]
    fn guardian_audience_cannot_enter_the_generic_broker_effect_path() {
        let semantics = BrokerDispatchSemanticIdentityV1::new(
            BrokerVerb::GuardianArm,
            BrokerGrantTarget::Assignment,
            BrokerArgumentCommitment::for_canonical_bytes(b"guardian"),
        );

        assert!(matches!(
            AuthorityBoundEffectPlanV1::from_template(
                ObjectDigest::from_bytes([1; 32]),
                BrokerAudience::Guardian,
                BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME,
                ObjectDigest::from_bytes([2; 32]),
                b"guardian",
                semantics,
                true,
            ),
            Err(EffectHistoryDataError::InvalidPlan(
                "guardian authority cannot use the generic broker effect path"
            ))
        ));

        let invalid_record = EffectLedgerRecord::from_parts((
            EffectPlan::from_parts((
                EffectDomain::Host,
                Some(BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME),
                None,
                b"guardian".to_vec(),
                Some(AuthorityEffectBindingV1::from_parts((
                    OperationId::from_bytes([3; 16]),
                    0,
                    ObjectDigest::from_bytes([1; 32]),
                    BrokerAudience::Guardian,
                    BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME,
                    ObjectDigest::from_bytes([2; 32]),
                    ObjectDigest::from_bytes([4; 32]),
                    ObjectDigest::from_bytes([5; 32]),
                    true,
                    ObjectDigest::from_bytes([6; 32]),
                ))),
            )),
            EffectState::Planned,
            None,
            None,
        ));
        assert!(matches!(
            encode_effect(&invalid_record),
            Err(EffectHistoryDataError::InvalidPlan(
                "guardian authority cannot use the generic broker effect path"
            ))
        ));

        for reserved in [0, 5] {
            assert!(matches!(
                crate::domain_ledger::effect_history::audience_from_code(reserved),
                Err(EffectHistoryDataError::CorruptLedger(
                    "unknown authority effect audience"
                ))
            ));
        }
    }
}
