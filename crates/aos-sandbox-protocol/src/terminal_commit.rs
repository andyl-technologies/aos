//! Protected broker terminal-CAS receipts shared with dormant domain adapters.

use aos_proto::aos::sandbox::local::v1::BrokerMethod;
use aos_sandbox_broker_session_protocol::{
    BrokerSessionKeyUsageV1, BrokerSessionSignerReferenceV1,
};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use sha2::{Digest as _, Sha256};

const RECEIPT_DOMAIN: &[u8] = b"aos.sandbox.broker-terminal-commit-receipt.v1\0";
const VERIFIER_WIRE_DOMAIN: &[u8; 16] = b"AOSBROKEROUTV001";
/// Exact byte length of one protected broker terminal verifier credential.
pub const BROKER_TERMINAL_COMMIT_VERIFIER_BYTES: usize = 16 + 16 + 8 + 32 + 16 + 8 + 32 + 32;

/// Pins the sole broker-outcome verifier accepted for Host replay finalization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrokerTerminalCommitVerifierV1 {
    signer: BrokerSessionSignerReferenceV1,
    public_key: [u8; 32],
}

impl BrokerTerminalCommitVerifierV1 {
    /// Constructs a verifier only for a strong key matching the signer reference.
    pub fn new(signer: BrokerSessionSignerReferenceV1, public_key: [u8; 32]) -> Option<Self> {
        let public_key_digest: [u8; 32] = Sha256::digest(public_key).into();
        (signer.usage() == BrokerSessionKeyUsageV1::BrokerOutcome
            && signer.public_key_digest() == public_key_digest
            && VerifyingKey::from_bytes(&public_key).is_ok_and(|key| !key.is_weak()))
        .then_some(Self { signer, public_key })
    }

    /// Returns the canonical verifier commitment retained by domain state.
    pub fn commitment(&self) -> [u8; 32] {
        verifier_commitment(&self.signer, &self.public_key)
    }

    /// Encodes the fixed verifier for protected Host configuration.
    pub fn encode(&self) -> [u8; BROKER_TERMINAL_COMMIT_VERIFIER_BYTES] {
        let mut bytes = [0_u8; BROKER_TERMINAL_COMMIT_VERIFIER_BYTES];
        bytes[..16].copy_from_slice(VERIFIER_WIRE_DOMAIN);
        bytes[16..32].copy_from_slice(&self.signer.authority_id());
        bytes[32..40].copy_from_slice(&self.signer.authority_generation().to_be_bytes());
        bytes[40..72].copy_from_slice(&self.signer.authority_digest());
        bytes[72..88].copy_from_slice(&self.signer.key_id());
        bytes[88..96].copy_from_slice(&self.signer.key_generation().to_be_bytes());
        bytes[96..128].copy_from_slice(&self.signer.public_key_digest());
        bytes[128..160].copy_from_slice(&self.public_key);
        bytes
    }

    /// Decodes a canonical protected Host verifier credential.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != BROKER_TERMINAL_COMMIT_VERIFIER_BYTES
            || &bytes[..16] != VERIFIER_WIRE_DOMAIN
        {
            return None;
        }
        let signer = BrokerSessionSignerReferenceV1::new(
            bytes[16..32].try_into().ok()?,
            u64::from_be_bytes(bytes[32..40].try_into().ok()?),
            bytes[40..72].try_into().ok()?,
            bytes[72..88].try_into().ok()?,
            u64::from_be_bytes(bytes[88..96].try_into().ok()?),
            bytes[96..128].try_into().ok()?,
            BrokerSessionKeyUsageV1::BrokerOutcome,
        )
        .ok()?;
        Self::new(signer, bytes[128..160].try_into().ok()?)
    }
}

/// Names one exact Host reservation and protected terminal CAS result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrokerTerminalCommitBindingV1 {
    reservation_locator: [u8; 32],
    method: BrokerMethod,
    request_id: [u8; 16],
    signed_request_digest: [u8; 32],
    session_binding: [u8; 32],
    signed_outcome_digest: [u8; 32],
    protected_generation: u64,
    protected_head: [u8; 32],
}

impl BrokerTerminalCommitBindingV1 {
    /// Constructs one shape-checked terminal binding.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        reservation_locator: [u8; 32],
        method: BrokerMethod,
        request_id: [u8; 16],
        signed_request_digest: [u8; 32],
        session_binding: [u8; 32],
        signed_outcome_digest: [u8; 32],
        protected_generation: u64,
        protected_head: [u8; 32],
    ) -> Option<Self> {
        (reservation_locator != [0; 32]
            && method != BrokerMethod::BROKER_METHOD_UNSPECIFIED
            && request_id != [0; 16]
            && signed_request_digest != [0; 32]
            && session_binding != [0; 32]
            && signed_outcome_digest != [0; 32]
            && protected_generation != 0
            && protected_head != [0; 32])
            .then_some(Self {
                reservation_locator,
                method,
                request_id,
                signed_request_digest,
                session_binding,
                signed_outcome_digest,
                protected_generation,
                protected_head,
            })
    }

    /// Returns the Host reservation locator.
    pub const fn reservation_locator(&self) -> [u8; 32] {
        self.reservation_locator
    }
    /// Returns the exact method.
    pub const fn method(&self) -> BrokerMethod {
        self.method
    }
    /// Returns the request identifier.
    pub const fn request_id(&self) -> [u8; 16] {
        self.request_id
    }
    /// Returns the signed-request digest.
    pub const fn signed_request_digest(&self) -> [u8; 32] {
        self.signed_request_digest
    }
    /// Returns the session binding.
    pub const fn session_binding(&self) -> [u8; 32] {
        self.session_binding
    }
    /// Returns the signed-outcome digest.
    pub const fn signed_outcome_digest(&self) -> [u8; 32] {
        self.signed_outcome_digest
    }
    /// Returns the committed protected generation.
    pub const fn protected_generation(&self) -> u64 {
        self.protected_generation
    }
    /// Returns the committed protected head.
    pub const fn protected_head(&self) -> [u8; 32] {
        self.protected_head
    }
}

/// Carries a broker-outcome-key signature over one exact post-CAS binding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrokerTerminalCommitReceiptV1 {
    binding: BrokerTerminalCommitBindingV1,
    signer: BrokerSessionSignerReferenceV1,
    public_key: [u8; 32],
    signature: [u8; 64],
}

impl BrokerTerminalCommitReceiptV1 {
    /// Signs a receipt with the protected broker-outcome key.
    pub fn sign(
        binding: BrokerTerminalCommitBindingV1,
        signer: BrokerSessionSignerReferenceV1,
        key: &SigningKey,
    ) -> Option<Self> {
        let public_key = key.verifying_key().to_bytes();
        let public_key_digest: [u8; 32] = Sha256::digest(public_key).into();
        if signer.usage() != BrokerSessionKeyUsageV1::BrokerOutcome
            || signer.public_key_digest() != public_key_digest
        {
            return None;
        }
        let signature = key.sign(&receipt_message(&binding, &signer)).to_bytes();
        Some(Self {
            binding,
            signer,
            public_key,
            signature,
        })
    }

    /// Verifies the fixed signer pin and exact expected terminal binding.
    pub fn verify(
        &self,
        expected: &BrokerTerminalCommitBindingV1,
        verifier: &BrokerTerminalCommitVerifierV1,
    ) -> bool {
        let public_key_digest: [u8; 32] = Sha256::digest(self.public_key).into();
        if &self.binding != expected
            || self.signer != verifier.signer
            || self.public_key != verifier.public_key
            || self.signer.usage() != BrokerSessionKeyUsageV1::BrokerOutcome
            || self.signer.public_key_digest() != public_key_digest
        {
            return false;
        }
        VerifyingKey::from_bytes(&self.public_key).is_ok_and(|key| {
            !key.is_weak()
                && key
                    .verify_strict(
                        &receipt_message(&self.binding, &self.signer),
                        &ed25519_dalek::Signature::from_bytes(&self.signature),
                    )
                    .is_ok()
        })
    }

    /// Verifies against a Host-retained commitment to the authenticated signer pin.
    pub fn verify_pinned_commitment(
        &self,
        expected: &BrokerTerminalCommitBindingV1,
        verifier_commitment: [u8; 32],
    ) -> bool {
        let Some(verifier) =
            BrokerTerminalCommitVerifierV1::new(self.signer.clone(), self.public_key)
        else {
            return false;
        };
        verifier.commitment() == verifier_commitment && self.verify(expected, &verifier)
    }

    /// Returns the signed terminal binding.
    pub const fn binding(&self) -> &BrokerTerminalCommitBindingV1 {
        &self.binding
    }
}

fn receipt_message(
    binding: &BrokerTerminalCommitBindingV1,
    signer: &BrokerSessionSignerReferenceV1,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(320);
    bytes.extend_from_slice(RECEIPT_DOMAIN);
    bytes.extend_from_slice(&binding.reservation_locator);
    bytes.extend_from_slice(&(binding.method as i32).to_be_bytes());
    bytes.extend_from_slice(&binding.request_id);
    bytes.extend_from_slice(&binding.signed_request_digest);
    bytes.extend_from_slice(&binding.session_binding);
    bytes.extend_from_slice(&binding.signed_outcome_digest);
    bytes.extend_from_slice(&binding.protected_generation.to_be_bytes());
    bytes.extend_from_slice(&binding.protected_head);
    bytes.extend_from_slice(&signer.authority_id());
    bytes.extend_from_slice(&signer.authority_generation().to_be_bytes());
    bytes.extend_from_slice(&signer.authority_digest());
    bytes.extend_from_slice(&signer.key_id());
    bytes.extend_from_slice(&signer.key_generation().to_be_bytes());
    bytes.extend_from_slice(&signer.public_key_digest());
    bytes.push(signer.usage() as u8);
    bytes
}

fn verifier_commitment(signer: &BrokerSessionSignerReferenceV1, public_key: &[u8; 32]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"aos.sandbox.broker-terminal-verifier.v1\0");
    digest.update(signer.authority_id());
    digest.update(signer.authority_generation().to_be_bytes());
    digest.update(signer.authority_digest());
    digest.update(signer.key_id());
    digest.update(signer.key_generation().to_be_bytes());
    digest.update(signer.public_key_digest());
    digest.update([signer.usage() as u8]);
    digest.update(public_key);
    digest.finalize().into()
}
