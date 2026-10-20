//! Materializes ordinary and selected protected configuration in one recipe.
//!
//! Each reached decoder, key, anchor and authority result is parked before the
//! next stage. A later failure cannot discard an earlier successful anchor.
//! The Native loader remains responsible for actual credential custody.

use std::error::Error;

use aos_sandbox_core::format::CanonicalCborError;
use aos_sandbox_core::model::TrustPolicy;
use aos_sandbox_core::{BrokerPlanVerificationError, OwnershipLeaseVerificationError};

use super::*;

pub(super) struct ConfigurationInputsV1 {
    pub(super) plan_policy: Vec<u8>,
    pub(super) plan_public_key: [u8; 32],
    pub(super) revocation_scope: [u8; 16],
    pub(super) lease_policy: Vec<u8>,
    pub(super) lease_public_key: [u8; 32],
    pub(super) node: [u8; 16],
    pub(super) journal_key: Zeroizing<[u8; 48]>,
}

pub(super) struct ConfigurationMaterializationV1 {
    inputs: ConfigurationInputsV1,
    domain: BrokerDomain,
    public: PublicAnchorMaterializationV2,
    authority: Option<Result<BrokerAuthority, crate::BrokerAdmissionError>>,
    public_binding: Option<ObjectDigest>,
    key_id: [u8; 16],
    secret: Zeroizing<[u8; 32]>,
    result: Option<Result<(), BrokerAuthorityConfigError>>,
}

impl ConfigurationMaterializationV1 {
    pub(super) fn new(inputs: ConfigurationInputsV1, domain: BrokerDomain) -> Self {
        Self {
            inputs,
            domain,
            public: PublicAnchorMaterializationV2::new(),
            authority: None,
            public_binding: None,
            key_id: [0; 16],
            secret: Zeroizing::new([0; 32]),
            result: None,
        }
    }

    pub(super) fn run_once(&mut self) -> Result<(), BrokerAuthorityConfigError> {
        if self.result.is_some() {
            return Err(BrokerAuthorityConfigError::Invalid("configuration reentry"));
        }
        self.result = Some(self.run_inner());

        match self.result.as_ref() {
            Some(Ok(())) => Ok(()),
            _ => Err(BrokerAuthorityConfigError::Invalid(
                "configuration materialization",
            )),
        }
    }

    fn run_inner(&mut self) -> Result<(), BrokerAuthorityConfigError> {
        let input = &self.inputs;
        self.public.run_once(
            &input.plan_policy,
            &input.plan_public_key,
            input.revocation_scope,
            &input.lease_policy,
            &input.lease_public_key,
        )?;

        self.key_id.copy_from_slice(&input.journal_key[..16]);
        self.secret.copy_from_slice(&input.journal_key[16..]);
        self.public_binding = Some(protected_configuration_binding(
            self.domain,
            &input.plan_policy,
            &input.plan_public_key,
            &input.revocation_scope,
            &input.lease_policy,
            &input.lease_public_key,
            &input.node,
            &self.key_id,
        ));

        self.authority = Some(BrokerAuthority::new_from_anchor_results_v1(
            self.domain,
            &mut self.public.plan_anchor,
            &mut self.public.lease_anchor,
            NodeId::from_bytes(input.node),
            self.key_id,
            *self.secret,
        ));
        value(&self.authority, "broker authority")?;
        Ok(())
    }

    pub(super) fn is_complete(&self) -> bool {
        matches!(self.result, Some(Ok(()))) && matches!(self.authority, Some(Ok(_)))
    }

    pub(super) fn take_completed(
        &mut self,
    ) -> Option<(BrokerAuthority, ObjectDigest, [u8; 16], Zeroizing<[u8; 32]>)> {
        if !self.is_complete() {
            return None;
        }
        let binding = self.public_binding?;
        let authority = match self.authority.take()? {
            Ok(authority) => authority,
            Err(error) => {
                self.authority = Some(Err(error));
                return None;
            }
        };
        let secret = std::mem::replace(&mut self.secret, Zeroizing::new([0; 32]));
        Some((authority, binding, self.key_id, secret))
    }

    pub(super) fn into_error(mut self) -> BrokerAuthorityConfigError {
        match self.result.take() {
            Some(Err(error)) => error,
            _ => BrokerAuthorityConfigError::Invalid("configuration materialization"),
        }
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.public
            .failure()
            .or_else(|| failed(&self.authority))
            .or_else(|| failed(&self.result))
    }
}

/// Shares the public anchor recipe without a journal key or effect issuer.
pub(super) struct PublicAnchorMaterializationV2 {
    policies: [Option<Result<TrustPolicy, CanonicalCborError>>; 4],
    plan_signer: Option<Result<KeyReference, BrokerAuthorityConfigError>>,
    lease_signer: Option<Result<KeyReference, BrokerAuthorityConfigError>>,
    media_type: Option<Result<MediaType, aos_sandbox_core::selector::InvalidMediaType>>,
    plan_anchor: Option<Result<BrokerPlanTrustAnchor, BrokerPlanVerificationError>>,
    lease_anchor: Option<Result<OwnershipLeaseTrustAnchor, OwnershipLeaseVerificationError>>,
    result: Option<Result<(), BrokerAuthorityConfigError>>,
}

impl PublicAnchorMaterializationV2 {
    pub(super) fn new() -> Self {
        Self {
            policies: [None, None, None, None],
            plan_signer: None,
            lease_signer: None,
            media_type: None,
            plan_anchor: None,
            lease_anchor: None,
            result: None,
        }
    }

    pub(super) fn run_once(
        &mut self,
        plan_policy: &[u8],
        plan_public_key: &[u8; 32],
        revocation_scope: [u8; 16],
        lease_policy: &[u8],
        lease_public_key: &[u8; 32],
    ) -> Result<(), BrokerAuthorityConfigError> {
        if self.result.is_some() {
            return Err(BrokerAuthorityConfigError::Invalid(
                "public configuration reentry",
            ));
        }
        self.result = Some(self.run_inner(
            plan_policy,
            plan_public_key,
            revocation_scope,
            lease_policy,
            lease_public_key,
        ));
        match self.result.as_ref() {
            Some(Ok(())) => Ok(()),
            Some(Err(BrokerAuthorityConfigError::Invalid(name))) => {
                Err(BrokerAuthorityConfigError::Invalid(name))
            }
            _ => Err(BrokerAuthorityConfigError::Invalid("public configuration")),
        }
    }

    fn run_inner(
        &mut self,
        plan_policy: &[u8],
        plan_public_key: &[u8; 32],
        revocation_scope: [u8; 16],
        lease_policy: &[u8],
        lease_public_key: &[u8; 32],
    ) -> Result<(), BrokerAuthorityConfigError> {
        self.policies[0] = Some(decode_trust_policy(plan_policy, policy_limits()));
        self.plan_signer = Some(select_decoded_policy_key(
            value(&self.policies[0], "trust policy")?,
            plan_public_key,
            SignaturePurpose::BrokerAuthorization,
            KeyUsage::BrokerAuthorization,
        ));
        key(&self.plan_signer)?;

        self.policies[1] = Some(decode_trust_policy(lease_policy, policy_limits()));
        self.lease_signer = Some(select_decoded_policy_key(
            value(&self.policies[1], "trust policy")?,
            lease_public_key,
            SignaturePurpose::OwnershipLease,
            KeyUsage::OwnershipLease,
        ));
        key(&self.lease_signer)?;

        self.policies[2] = Some(decode_trust_policy(plan_policy, policy_limits()));
        let plan_scope = value(&self.policies[2], PLAN_POLICY_FILE)?.trust_scope();
        self.policies[3] = Some(decode_trust_policy(lease_policy, policy_limits()));
        let lease_scope = value(&self.policies[3], LEASE_POLICY_FILE)?.trust_scope();
        self.media_type = Some(MediaType::new(
            PortableMediaType::TrustPolicy.as_str().to_owned(),
        ));
        let media_type = value(&self.media_type, "trust-policy media type")?;
        let plan_descriptor = descriptor_for_bytes(media_type.clone(), plan_policy);
        let lease_descriptor = descriptor_for_bytes(media_type.clone(), lease_policy);

        self.plan_anchor = Some(BrokerPlanTrustAnchor::from_trusted_configuration(
            plan_policy.to_vec(),
            plan_descriptor,
            plan_scope,
            key(&self.plan_signer)?.clone(),
            *plan_public_key,
            RevocationScopeId::from_bytes(revocation_scope),
            policy_limits(),
        ));
        value(&self.plan_anchor, "broker plan trust anchor")?;

        self.lease_anchor = Some(OwnershipLeaseTrustAnchor::from_trusted_configuration(
            lease_policy.to_vec(),
            lease_descriptor,
            lease_scope,
            key(&self.lease_signer)?.clone(),
            *lease_public_key,
            policy_limits(),
        ));
        value(&self.lease_anchor, "ownership lease trust anchor")?;

        Ok(())
    }

    pub(super) fn take_verifier_once(
        &mut self,
        node: [u8; 16],
    ) -> Option<crate::NetworkPublicVerifierV2> {
        if node == [0; 16]
            || !matches!(self.result, Some(Ok(())))
            || !matches!(self.plan_anchor, Some(Ok(_)))
            || !matches!(self.lease_anchor, Some(Ok(_)))
        {
            return None;
        }
        let Some(Ok(plan)) = self.plan_anchor.take() else {
            return None;
        };
        let Some(Ok(lease)) = self.lease_anchor.take() else {
            self.plan_anchor = Some(Ok(plan));
            return None;
        };
        crate::NetworkPublicVerifierV2::from_captured_anchors_v2(
            plan,
            lease,
            NodeId::from_bytes(node),
        )
        .ok()
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        failed(&self.policies[0])
            .or_else(|| failed(&self.plan_signer))
            .or_else(|| failed(&self.policies[1]))
            .or_else(|| failed(&self.lease_signer))
            .or_else(|| failed(&self.policies[2]))
            .or_else(|| failed(&self.policies[3]))
            .or_else(|| failed(&self.media_type))
            .or_else(|| failed(&self.plan_anchor))
            .or_else(|| failed(&self.lease_anchor))
            .or_else(|| failed(&self.result))
    }
}

fn value<'a, T, E>(
    slot: &'a Option<Result<T, E>>,
    name: &'static str,
) -> Result<&'a T, BrokerAuthorityConfigError> {
    match slot {
        Some(Ok(value)) => Ok(value),
        _ => Err(BrokerAuthorityConfigError::Invalid(name)),
    }
}

fn failed<T, E: Error + 'static>(slot: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    slot.as_ref()
        .and_then(|result| result.as_ref().err())
        .map(|error| error as _)
}

fn key(
    slot: &Option<Result<KeyReference, BrokerAuthorityConfigError>>,
) -> Result<&KeyReference, BrokerAuthorityConfigError> {
    match slot {
        Some(Ok(key)) => Ok(key),
        Some(Err(BrokerAuthorityConfigError::Invalid(name))) => {
            Err(BrokerAuthorityConfigError::Invalid(*name))
        }
        _ => Err(BrokerAuthorityConfigError::Invalid("trust policy")),
    }
}
