//! Shares canonical ownership trust-policy construction for protected consumers.
//!
//! This module validates supplied DATA. Only each caller's actual protected
//! credential original establishes where those bytes came from and pays the
//! read/decoding/model interval. It opens no file and selects no credential.

use aos_sandbox_core::{CanonicalCborError, DecodeLimits, KeyUsage, MediaType,
    OwnershipLeaseTrustAnchor, OwnershipLeaseVerificationError, PortableMediaType,
    RegistryError, SignaturePurpose, descriptor_for_bytes};
use aos_sandbox_core::format::decode_trust_policy;
use aos_sandbox_core::selector::InvalidMediaType;
use crate::OwnershipAuthorityVerifier;

/// Preserves the original canonical, registry or trust-construction refusal.
#[derive(Debug, thiserror::Error)]
pub enum OwnershipTrustConfigurationErrorV1 {
    /// The supplied policy bytes are malformed or noncanonical.
    #[error(transparent)]
    Canonical(#[from] CanonicalCborError),
    /// Required features are unsupported.
    #[error(transparent)]
    Features(#[from] RegistryError),
    /// The canonical trust-policy media type is invalid.
    #[error(transparent)]
    MediaType(#[from] InvalidMediaType),
    /// The public key or policy does not match the pinned trust generation.
    #[error(transparent)]
    Trust(#[from] OwnershipLeaseVerificationError),
    /// Policy purpose or its sole allowed key has another role.
    #[error("ownership trust policy requires one exact OwnershipLease key")]
    Binding,
}

/// Constructs verifier DATA from an independently protected policy and key.
///
/// This accepts no secret and grants no credential or observation authority.
/// The caller must admit its actual parser/model demand before calling it.
///
/// # Errors
/// Returns the original canonical/feature/trust error, or refuses a policy
/// whose purpose and sole allowed key are not both OwnershipLease.
pub fn verifier_from_protected_policy_v1(
    policy_bytes: Vec<u8>, public_key: [u8; 32], limits: DecodeLimits,
) -> Result<OwnershipAuthorityVerifier, OwnershipTrustConfigurationErrorV1> {
    let mut work = OwnershipTrustConfigurationCaptureV1::new();
    work.policy_bytes = Some(policy_bytes);
    work.public_key = Some(public_key);
    construct_verifier(&mut work, limits, false)
}

/// Retains every reached portable model while constructing one verifier.
///
/// The actual protected caller owns the input files and receiving payment.
/// This portable DATA owner is not a credential or effect authority factory.
#[must_use = "retain beside the independently protected public credential originals"]
pub struct OwnershipTrustConfigurationCaptureV1 {
    policy_bytes: Option<Vec<u8>>,
    public_key: Option<[u8; 32]>,
    parser: aos_sandbox_core::format::TrustPolicyDecodeCaptureV1,
    policy: Option<aos_sandbox_core::model::TrustPolicy>,
    authority: Option<aos_sandbox_core::model::KeyReference>,
    media_type: Option<MediaType>,
    descriptor: Option<aos_sandbox_core::ObjectDescriptor>,
    anchor: aos_sandbox_core::OwnershipLeaseTrustAnchorConstructionV1,
    verifier: Option<OwnershipAuthorityVerifier>,
    completion: Option<Result<(), OwnershipTrustConfigurationErrorV1>>,
    entered: bool,
    closed: bool,
}

/// Reports a closed retained verifier constructor without moving its actual cause.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("retained ownership trust configuration is closed")]
pub struct OwnershipTrustConfigurationClosedV1;

impl OwnershipTrustConfigurationCaptureV1 {
    /// Creates inert destinations without reading or interpreting any credential.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            policy_bytes: None,
            public_key: None,
            parser: aos_sandbox_core::format::TrustPolicyDecodeCaptureV1::new(),
            policy: None,
            authority: None,
            media_type: None,
            descriptor: None,
            anchor: aos_sandbox_core::OwnershipLeaseTrustAnchorConstructionV1::new(),
            verifier: None,
            completion: None,
            entered: false,
            closed: false,
        }
    }

    /// Borrows the chronological original parser, anchor or construction cause.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.parser.cause()
            .or_else(|| self.anchor.failure())
            .or_else(|| self.completion.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &dyn std::error::Error))
    }

    /// Borrows completed verifier DATA while keeping all configuration custody.
    #[must_use]
    pub fn verifier(&self) -> Option<&OwnershipAuthorityVerifier> {
        if !self.closed && matches!(self.completion, Some(Ok(()))) && self.failure().is_none() {
            self.verifier.as_ref()
        } else {
            None
        }
    }

    /// Bounds concrete model construction and backing before actual decoding.
    ///
    /// Input bytes are DATA from the actual protected file bound. Complete CBOR
    /// arrays cannot contain more declared elements than actual encoded bytes.
    #[must_use]
    pub fn receiving_memory_bytes_v1(input_bytes: usize) -> Option<usize> {
        use aos_sandbox_core::format::TrustPolicyDecodeCaptureV1;
        std::mem::size_of::<Self>().checked_mul(2)?
            .checked_add(TrustPolicyDecodeCaptureV1::receiving_construction_bytes_v1()?.checked_mul(2)?)?
            .checked_add(aos_sandbox_core::OwnershipLeaseTrustAnchorConstructionV1::receiving_construction_bytes_v1()?)?
            .checked_add(TrustPolicyDecodeCaptureV1::receiving_carrier_bytes_v1(input_bytes)?.checked_mul(2)?)?
            .checked_add(input_bytes.checked_mul(8)?)?
            .checked_add(4096)
    }

    /// Bounds both actual policy parses and this owner's fixed destinations.
    #[must_use]
    pub fn receiving_metadata_cells_v1(input_bytes: usize) -> Option<usize> {
        aos_sandbox_core::format::TrustPolicyDecodeCaptureV1::receiving_metadata_cells_v1(input_bytes)?
            .checked_mul(2)?.checked_add(25)
    }
}

impl Default for OwnershipTrustConfigurationCaptureV1 {
    fn default() -> Self {
        Self::new()
    }
}

/// Uses the same canonical policy and anchor engine with retained partial custody.
///
/// # Errors
/// Returns a closed marker while `capture` retains the original chronological
/// decoder/feature/binding/anchor error. Reentry never reparses or changes a pin.
pub fn verifier_from_protected_policy_retaining_v1(
    policy_bytes: Vec<u8>, public_key: [u8; 32], limits: DecodeLimits,
    capture: &mut OwnershipTrustConfigurationCaptureV1,
) -> Result<(), OwnershipTrustConfigurationClosedV1> {
    if capture.entered {
        capture.closed = true;
        return Err(OwnershipTrustConfigurationClosedV1);
    }
    capture.entered = true;
    capture.policy_bytes = Some(policy_bytes);
    capture.public_key = Some(public_key);
    capture.completion = Some(match construct_verifier(capture, limits, true) {
        Ok(verifier) => {
            capture.verifier = Some(verifier);
            Ok(())
        }
        Err(cause) => Err(cause),
    });
    if matches!(capture.completion, Some(Ok(()))) {
        Ok(())
    } else {
        Err(OwnershipTrustConfigurationClosedV1)
    }
}

fn construct_verifier(
    work: &mut OwnershipTrustConfigurationCaptureV1, limits: DecodeLimits, retained: bool,
) -> Result<OwnershipAuthorityVerifier, OwnershipTrustConfigurationErrorV1> {
    let invalid = || OwnershipTrustConfigurationErrorV1::Binding;
    let bytes = work.policy_bytes.as_ref().ok_or_else(invalid)?;
    work.policy = Some(if retained {
        aos_sandbox_core::format::decode_trust_policy_retaining_v1(bytes, limits, &mut work.parser)
            .map_err(|_| invalid())?;
        work.parser.take_policy_once().ok_or_else(invalid)?
    } else {
        decode_trust_policy(bytes, limits)?
    });
    let policy = work.policy.as_ref().ok_or_else(invalid)?;
    aos_sandbox_core::validate_required_features(policy.required_features())?;
    let [authority] = policy.allowed_keys() else { return Err(invalid()); };
    if policy.purpose() != SignaturePurpose::OwnershipLease || authority.usage() != KeyUsage::OwnershipLease {
        return Err(invalid());
    }
    work.authority = Some(authority.clone());
    work.media_type = Some(MediaType::new(PortableMediaType::TrustPolicy.as_str().to_owned())?);
    work.descriptor = Some(descriptor_for_bytes(work.media_type.take().ok_or_else(invalid)?, bytes));
    let scope = policy.trust_scope();
    let authority = work.authority.as_ref().ok_or_else(invalid)?.clone();
    let descriptor = work.descriptor.take().ok_or_else(invalid)?;
    let public = work.public_key.ok_or_else(invalid)?;
    let bytes = work.policy_bytes.take().ok_or_else(invalid)?;
    let anchor = if retained {
        OwnershipLeaseTrustAnchor::from_trusted_configuration_retaining_v1(
            bytes, descriptor, scope, authority, public, limits, &mut work.anchor,
        ).map_err(|_| invalid())?;
        work.anchor.take_anchor_once().ok_or_else(invalid)?
    } else {
        OwnershipLeaseTrustAnchor::from_trusted_configuration(
            bytes, descriptor, scope, authority, public, limits,
        )?
    };
    Ok(OwnershipAuthorityVerifier::new(anchor, work.authority.take().ok_or_else(invalid)?))
}

#[cfg(test)]
mod retained_tests;
