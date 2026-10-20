//! Retains the fixed Controller Ownership credential originals under J.
//!
//! The actual closed caller admits this complete shape before read/decode.
//! Paths, role, policy generation and secret are never supplied by a request.

use std::error::Error;
use std::path::Path;
use aos_sandbox_model::DecodeLimits;
use aos_sandbox_linux::credential::{CredentialOwnerPolicyV1, FixedRoleCredentialReadV1};
use aos_sandbox_ownership_protocol::OwnershipAuthorityVerifier;
use aos_sandbox_ownership_protocol::trusted_policy::{OwnershipTrustConfigurationCaptureV1,
    OwnershipTrustConfigurationClosedV1, verifier_from_protected_policy_retaining_v1};
use zeroize::Zeroizing;

pub(super) const MAXIMUM_POLICY_BYTES: usize = 64 * 1024;
const DIRECTORY: &str = "/run/credentials/aos-sandboxd.service";

pub(super) struct ControllerOwnershipOriginalV1 {
    entered: bool,
    secret_file: FixedRoleCredentialReadV1,
    policy_file: FixedRoleCredentialReadV1,
    public_file: FixedRoleCredentialReadV1,
    secret: Option<Zeroizing<[u8; 32]>>,
    verifier: OwnershipTrustConfigurationCaptureV1,
    verifier_result: Option<Result<(), OwnershipTrustConfigurationClosedV1>>,
    complete: bool,
}

impl Default for ControllerOwnershipOriginalV1 {
    fn default() -> Self {
        Self { entered: false, secret_file: FixedRoleCredentialReadV1::prearmed(),
            policy_file: FixedRoleCredentialReadV1::prearmed(),
            public_file: FixedRoleCredentialReadV1::prearmed(),
            secret: None, verifier: OwnershipTrustConfigurationCaptureV1::new(),
            verifier_result: None, complete: false }
    }
}

impl ControllerOwnershipOriginalV1 {
    pub(super) fn capture_once(&mut self) {
        if self.entered { return; }
        self.entered = true;
        let directory = Path::new(DIRECTORY);
        self.secret_file.read_once(directory, "ownership-session-key", 32, 32,
            true, CredentialOwnerPolicyV1::RootOrCurrent);
        let Some(Ok(Some(bytes))) = self.secret_file.outcome() else { return; };
        let Ok(secret) = <[u8; 32]>::try_from(bytes.as_slice()) else { return; };
        if secret == [0; 32] { return; }
        self.secret = Some(Zeroizing::new(secret));

        self.policy_file.read_once(directory, "ownership-lease-policy.cbor", 1, MAXIMUM_POLICY_BYTES,
            true, CredentialOwnerPolicyV1::RootOrCurrent);
        if !matches!(self.policy_file.outcome(), Some(Ok(Some(_)))) { return; }
        self.public_file.read_once(directory, "ownership-lease-public-key", 32, 32,
            true, CredentialOwnerPolicyV1::RootOrCurrent);
        let Some(Ok(Some(bytes))) = self.public_file.outcome() else { return; };
        let Ok(public) = <[u8; 32]>::try_from(bytes.as_slice()) else { return; };
        let Some(Ok(Some(bytes))) = self.policy_file.outcome() else { return; };
        // Decoder::new validates complete canonical CBOR before any schema
        // collection reserve. Counts reaching allocation fit the actual bytes.
        self.verifier_result = Some(verifier_from_protected_policy_retaining_v1(
            bytes.to_vec(), public, DecodeLimits::default(), &mut self.verifier));
        self.complete = matches!(self.verifier_result, Some(Ok(())));
    }

    pub(super) fn require_complete(&self) -> Result<(), super::OwnershipError> {
        if self.complete && self.failure().is_none() { Ok(()) } else { Err(super::OwnershipError::Closed) }
    }

    pub(super) fn verifier(&self) -> Result<&OwnershipAuthorityVerifier, super::OwnershipError> {
        self.require_complete()?;
        self.verifier.verifier().ok_or(super::OwnershipError::Closed)
    }

    pub(super) fn secret(&self) -> Result<Zeroizing<[u8; 32]>, super::OwnershipError> {
        self.require_complete()?;
        self.secret.as_ref().cloned().ok_or(super::OwnershipError::Closed)
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.secret_file.failure().or_else(|| self.policy_file.failure())
            .or_else(|| self.public_file.failure()).or_else(|| self.verifier.failure())
            .or_else(|| super::error(&self.verifier_result))
    }
}
