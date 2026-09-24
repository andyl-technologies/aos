//! Signed deployment entitlements for first public capability issuance.
//!
//! The canonical credential is a compact JSON document:
//!
//! ```json
//! {"version":1,"generation":1,"entries":[{"principal":"UUID","project":"UUID","channel_binding":[0],"policy_digest":"sha256:...","policy_generation":1,"controller_generation":1,"revocation_scope":"UUID","revocation_generation":1,"not_before":0,"expires_at":1,"validity_seconds":1,"grants":[],"delegation":{}}],"signature":[0]}
//! ```
//!
//! Arrays shown abbreviated above have exact 32- or 64-byte lengths. The
//! signature covers `domain || length:u64be || canonical JSON of the first
//! three fields`, excluding `signature`. A fixed systemd credential supplies
//! the Ed25519 verifier; neither a peer nor an RPC supplies a trust root.

use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use aos_sandbox_core::{
    DelegationLimits, Grant, ObjectDigest, PrincipalId, ProjectId, RevocationScopeId,
};

use super::InitialPublicCapabilityErrorV1;

const SIGNATURE_DOMAIN: &[u8] = b"aos.sandbox.public-capability-entitlement.v1\0";
const DOCUMENT_DIGEST_DOMAIN: &[u8] = b"aos.sandbox.public-capability-entitlement-document.v1\0";
const MAXIMUM_ENTRIES: usize = 4_096;
const MAXIMUM_BYTES: usize = 1024 * 1024;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SignedDocumentV1 {
    version: u16,
    generation: u64,
    entries: Vec<EntitlementEntryV1>,
    signature: Vec<u8>,
}

#[derive(Serialize)]
struct UnsignedDocumentV1<'a> {
    version: u16,
    generation: u64,
    entries: &'a [EntitlementEntryV1],
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UnsignedDocumentInputV1 {
    version: u16,
    generation: u64,
    entries: Vec<EntitlementEntryV1>,
}

/// Signs a bounded deployment document with an offline administrator key.
///
/// The input contains only `version`, `generation`, and `entries`. The
/// function canonicalizes it, validates the signed result with its derived
/// verifier, and returns the complete credential plus its 32-byte public key.
/// The private seed must remain outside the controller and repository.
///
/// # Errors
///
/// Rejects oversized, malformed, unsorted, or invalid entitlement documents.
pub fn sign_entitlement_document_v1(
    unsigned_bytes: &[u8],
    private_seed: &[u8; 32],
) -> Result<(Vec<u8>, [u8; 32]), InitialPublicCapabilityErrorV1> {
    if unsigned_bytes.is_empty() || unsigned_bytes.len() > MAXIMUM_BYTES {
        return Err(InitialPublicCapabilityErrorV1::Rejected);
    }
    let input: UnsignedDocumentInputV1 = serde_json::from_slice(unsigned_bytes)
        .map_err(|_| InitialPublicCapabilityErrorV1::Rejected)?;
    let unsigned = serde_json::to_vec(&UnsignedDocumentV1 {
        version: input.version,
        generation: input.generation,
        entries: &input.entries,
    })
    .map_err(|_| InitialPublicCapabilityErrorV1::Rejected)?;
    let signer = SigningKey::from_bytes(private_seed);
    let public_key = signer.verifying_key().to_bytes();
    let signature = signer.sign(&signed_bytes(&unsigned)?).to_bytes();
    let signed = serde_json::to_vec(&SignedDocumentV1 {
        version: input.version,
        generation: input.generation,
        entries: input.entries,
        signature: signature.to_vec(),
    })
    .map_err(|_| InitialPublicCapabilityErrorV1::Rejected)?;
    VerifiedEntitlementsV1::decode(&signed, &public_key)?;
    Ok((signed, public_key))
}

/// Binds one administrator-approved grant set to an exact registered holder.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct EntitlementEntryV1 {
    pub(super) principal: PrincipalId,
    pub(super) project: ProjectId,
    pub(super) channel_binding: [u8; 32],
    pub(super) policy_digest: ObjectDigest,
    pub(super) policy_generation: u64,
    pub(super) controller_generation: u64,
    pub(super) revocation_scope: RevocationScopeId,
    pub(super) revocation_generation: u64,
    pub(super) not_before: i64,
    pub(super) expires_at: i64,
    pub(super) validity_seconds: u32,
    pub(super) grants: Vec<Grant>,
    pub(super) delegation: DelegationLimits,
}

impl EntitlementEntryV1 {
    pub(super) fn matches_holder(
        &self,
        principal: PrincipalId,
        project: ProjectId,
        binding: &[u8; 32],
    ) -> bool {
        self.principal == principal && self.project == project && &self.channel_binding == binding
    }

    fn valid(&self) -> bool {
        self.principal.as_bytes() != &[0; 16]
            && self.project.as_bytes() != &[0; 16]
            && self.channel_binding != [0; 32]
            && self.policy_digest.as_bytes() != &[0; 32]
            && self.policy_generation != 0
            && self.controller_generation != 0
            && self.revocation_scope.as_bytes() != &[0; 16]
            && self.revocation_generation != 0
            && self.not_before < self.expires_at
            && (1..=3_600).contains(&self.validity_seconds)
            && !self.grants.is_empty()
            && self.grants.len() <= 1_024
    }
}

/// A verified, bounded, canonical entitlement snapshot.
pub(super) struct VerifiedEntitlementsV1 {
    digest: ObjectDigest,
    generation: u64,
    pub(super) entries: Vec<EntitlementEntryV1>,
}

impl VerifiedEntitlementsV1 {
    #[cfg(test)]
    pub(super) fn from_test_entry(entry: EntitlementEntryV1) -> Self {
        Self {
            digest: ObjectDigest::from_bytes([99; 32]),
            generation: 1,
            entries: vec![entry],
        }
    }

    pub(super) fn decode(
        bytes: &[u8],
        public_key: &[u8],
    ) -> Result<Self, InitialPublicCapabilityErrorV1> {
        if bytes.is_empty() || bytes.len() > MAXIMUM_BYTES {
            return Err(InitialPublicCapabilityErrorV1::Rejected);
        }
        let key: [u8; 32] = public_key
            .try_into()
            .map_err(|_| InitialPublicCapabilityErrorV1::Rejected)?;
        let verifier =
            VerifyingKey::from_bytes(&key).map_err(|_| InitialPublicCapabilityErrorV1::Rejected)?;
        let document: SignedDocumentV1 =
            serde_json::from_slice(bytes).map_err(|_| InitialPublicCapabilityErrorV1::Rejected)?;
        if document.version != 1
            || document.generation == 0
            || document.entries.is_empty()
            || document.entries.len() > MAXIMUM_ENTRIES
            || document.signature.len() != 64
            || document.entries.iter().any(|entry| !entry.valid())
            || document.entries.windows(2).any(|pair| {
                (
                    &pair[0].project,
                    &pair[0].principal,
                    &pair[0].channel_binding,
                ) >= (
                    &pair[1].project,
                    &pair[1].principal,
                    &pair[1].channel_binding,
                )
            })
            || serde_json::to_vec(&document)
                .map_err(|_| InitialPublicCapabilityErrorV1::Rejected)?
                != bytes
        {
            return Err(InitialPublicCapabilityErrorV1::Rejected);
        }
        let unsigned = serde_json::to_vec(&UnsignedDocumentV1 {
            version: document.version,
            generation: document.generation,
            entries: &document.entries,
        })
        .map_err(|_| InitialPublicCapabilityErrorV1::Rejected)?;
        let signed = signed_bytes(&unsigned)?;
        let signature: [u8; 64] = document
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| InitialPublicCapabilityErrorV1::Rejected)?;
        verifier
            .verify_strict(&signed, &Signature::from_bytes(&signature))
            .map_err(|_| InitialPublicCapabilityErrorV1::Rejected)?;

        Ok(Self {
            digest: ObjectDigest::from_bytes(
                Sha256::new()
                    .chain_update(DOCUMENT_DIGEST_DOMAIN)
                    .chain_update(bytes)
                    .finalize()
                    .into(),
            ),
            generation: document.generation,
            entries: document.entries,
        })
    }

    pub(super) const fn digest(&self) -> ObjectDigest {
        self.digest
    }

    pub(super) const fn generation(&self) -> u64 {
        self.generation
    }

    pub(super) fn for_holder(
        &self,
        principal: PrincipalId,
        project: ProjectId,
        binding: &[u8; 32],
    ) -> Result<&EntitlementEntryV1, InitialPublicCapabilityErrorV1> {
        self.entries
            .iter()
            .find(|entry| entry.matches_holder(principal, project, binding))
            .ok_or(InitialPublicCapabilityErrorV1::Rejected)
    }
}

fn signed_bytes(unsigned: &[u8]) -> Result<Vec<u8>, InitialPublicCapabilityErrorV1> {
    let length =
        u64::try_from(unsigned.len()).map_err(|_| InitialPublicCapabilityErrorV1::Rejected)?;
    let mut signed = Vec::with_capacity(SIGNATURE_DOMAIN.len() + 8 + unsigned.len());
    signed.extend_from_slice(SIGNATURE_DOMAIN);
    signed.extend_from_slice(&length.to_be_bytes());
    signed.extend_from_slice(unsigned);
    Ok(signed)
}

#[cfg(test)]
mod tests;
