//! Interprets actual Root-held public broker-plan trust inputs once.
//!
//! This module performs canonical public-key/policy/scope comparison only. The
//! actual fixed credential owner retains native custody and funding; this DATA
//! constructor cannot sign, establish a current compiler cut or authorize any
//! broker method. Each purpose independently chooses its semantic grant.

use std::error::Error;
use aos_sandbox_model::{
    BrokerPlanTrustAnchor, DecodeLimits, MediaType, ObjectDigest, PortableMediaType,
    RevocationScopeId, descriptor_for_bytes,
};
use aos_sandbox_model::format::decode_trust_policy;
use aos_sandbox_model::model::{KeyUsage, SignaturePurpose};
use aos_sandbox_protocol::authorization_artifact::SigningAuthority;
use sha2::{Digest as _, Sha256};

#[derive(Debug, thiserror::Error)]
#[error("Root's local broker-plan trust inputs changed")]
struct Changed;

pub(in crate::policy_compiler) struct RootBrokerPlanPublicTrustDataV1 {
    pub(in crate::policy_compiler) anchor: BrokerPlanTrustAnchor,
    pub(in crate::policy_compiler) authority: SigningAuthority,
    pub(in crate::policy_compiler) revocation_scope: RevocationScopeId,
    pub(in crate::policy_compiler) policy_length: usize,
}

impl RootBrokerPlanPublicTrustDataV1 {
    pub(in crate::policy_compiler) fn from_fixed_public_data_v1(public: (&[u8], &[u8], &[u8]))
        -> Result<Self, Box<dyn Error>>
    {
        let (policy_bytes, public_key, revocation_scope) = public;
        let public_key: [u8; 32] = public_key.try_into()?;
        let revocation_scope = RevocationScopeId::from_bytes(revocation_scope.try_into()?);
        let policy = decode_trust_policy(policy_bytes, DecodeLimits::default())?;
        if policy.purpose() != SignaturePurpose::BrokerAuthorization {
            return Err(Box::new(Changed));
        }
        let fingerprint = ObjectDigest::from_bytes(Sha256::digest(public_key).into());
        let mut matches = policy.allowed_keys().iter().filter(|key| {
            key.usage() == KeyUsage::BrokerAuthorization && key.public_key_sha256() == fingerprint
        });
        let signer = matches.next().cloned().ok_or(Changed)?;
        if matches.next().is_some() { return Err(Box::new(Changed)); }
        let descriptor = descriptor_for_bytes(
            MediaType::new(PortableMediaType::TrustPolicy.as_str().to_owned())?, policy_bytes,
        );
        let anchor = BrokerPlanTrustAnchor::from_trusted_configuration(policy_bytes.to_vec(),
            descriptor.clone(), policy.trust_scope(), signer.clone(), public_key,
            revocation_scope, DecodeLimits::default())?;
        let authority = SigningAuthority::new(policy_bytes.to_vec(), descriptor,
            policy.trust_scope(), signer, public_key, SignaturePurpose::BrokerAuthorization,
            DecodeLimits::default())?;
        Ok(Self { anchor, authority, revocation_scope, policy_length: policy_bytes.len() })
    }
}

impl RootBrokerPlanPublicTrustDataV1 {
    // Three actual policy decoder lanes (direct selection, anchor and public
    // signing authority) and their two owned policy copies coexist here.
    pub(in crate::policy_compiler) fn receiving_memory_bytes_v2(public: (&[u8], &[u8], &[u8]))
        -> Option<usize> {
        if public.0.len() > aos_sandbox_protocol::authorization_artifact::SigningAuthority::maximum_canonical_policy_bytes_v1()
            || public.1.len() != 32 || public.2.len() != 16 { return None; }
        Self::receiving_policy_width_bytes_v2(public.0.len())
    }

    /// Measures the same pure recipe before a fixed native capture starts.
    /// The caller supplies its format-owned bound, never a trust-policy body.
    pub(in crate::policy_compiler) fn receiving_policy_width_bytes_v2(policy_bytes: usize)
        -> Option<usize> {
        if policy_bytes > aos_sandbox_protocol::authorization_artifact::SigningAuthority::maximum_canonical_policy_bytes_v1() {
            return None;
        }
        let policy = aos_sandbox_model::format::TrustPolicyDecodeCaptureV1::receiving_carrier_bytes_v1(policy_bytes)?
            .checked_mul(3)?;
        let raw = policy_bytes.checked_mul(2)?;
        // The selected signer is cloned into the two resident public owners,
        // outside the three decoder graphs. Each key's source text is bounded
        // by the same complete canonical input. Descriptor clones include the
        // two resident policy media types and each constructor's comparison.
        let signer_text = policy_bytes.checked_mul(2)?;
        let descriptor_text = PortableMediaType::TrustPolicy.as_str().len().checked_mul(4)?;
        std::mem::size_of::<Self>().checked_mul(3)?
            .checked_add(policy)?.checked_add(raw)?.checked_add(signer_text)?
            .checked_add(descriptor_text)
    }
}
