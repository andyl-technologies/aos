//! Fixed signed-artifact encoding and domain-separated cryptography.
//!
//! Each purpose has a distinct key use, signature domain, fixed subject width,
//! and closed method rule. Hello methods are zero; traffic artifacts carry the
//! exact existing [`BrokerMethod`]. Received signer metadata never chooses a
//! public key or trust anchor.

use aos_proto::aos::sandbox::local::v1::BrokerMethod;
use buffa::Enumeration as _;
use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};
use sha2::{Digest as _, Sha256};

use crate::model::{
    BROKER_HELLO_SUBJECT_BYTES, BROKER_OUTCOME_SUBJECT_BYTES, BROKER_REQUEST_SUBJECT_BYTES,
    BROKER_SESSION_SIGNED_OVERHEAD_BYTES, BROKER_SESSION_SIGNER_REFERENCE_BYTES,
    BrokerClientHelloSubjectV1, BrokerHelloSubjectV1, BrokerOutcomeSubjectV1,
    BrokerRequestSubjectV1, BrokerSessionKeyUsageV1, BrokerSessionProtocolV1,
    BrokerSessionSignerReferenceV1, BrokerSessionValidationError, CLIENT_HELLO_SUBJECT_BYTES,
    SIGNED_BROKER_HELLO_BYTES, SIGNED_BROKER_OUTCOME_BYTES, SIGNED_BROKER_REQUEST_BYTES,
    SIGNED_CLIENT_HELLO_BYTES, audience_code, audience_from_code, method_code, take_array,
};

const SIGNED_MAGIC: &[u8; 8] = b"AOSBSA01";
const SIGNED_VERSION: u16 = 1;
const SIGNATURE_BYTES: usize = 64;
const CLIENT_HELLO_PURPOSE: u8 = 1;
const BROKER_HELLO_PURPOSE: u8 = 2;
const CLIENT_RECORD_PURPOSE: u8 = 3;
const BROKER_OUTCOME_PURPOSE: u8 = 4;

const CLIENT_HELLO_SIGNATURE_DOMAIN: &[u8] =
    b"aos-sandbox-broker-session-client-hello-signature-v1\0";
const BROKER_HELLO_SIGNATURE_DOMAIN: &[u8] =
    b"aos-sandbox-broker-session-server-hello-signature-v1\0";
const REQUEST_SIGNATURE_DOMAIN: &[u8] = b"aos-sandbox-broker-session-request-signature-v1\0";
const OUTCOME_SIGNATURE_DOMAIN: &[u8] = b"aos-sandbox-broker-session-outcome-signature-v1\0";
const SIGNER_SET_DOMAIN: &[u8] = b"aos-sandbox-broker-session-signer-set-v1\0";
const SIGNED_CLIENT_HELLO_DIGEST_DOMAIN: &[u8] =
    b"aos-sandbox-broker-session-signed-client-hello-v1\0";
const SIGNED_REQUEST_DIGEST_DOMAIN: &[u8] = b"aos-sandbox-broker-session-signed-request-v1\0";
const SIGNED_OUTCOME_DIGEST_DOMAIN: &[u8] = b"aos-sandbox-broker-session-signed-outcome-v1\0";
pub(crate) const SESSION_BINDING_DOMAIN: &[u8] = b"aos-sandbox-broker-session-binding-v1\0";

/// Stores exact Ed25519 signature bytes without a library-native wire layout.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrokerSessionSignature([u8; SIGNATURE_BYTES]);

impl BrokerSessionSignature {
    /// Constructs an exact fixed-width signature value.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; SIGNATURE_BYTES]) -> Self {
        Self(bytes)
    }

    /// Returns the exact 64 signature bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; SIGNATURE_BYTES] {
        &self.0
    }
}

/// Reports malformed framing, signer mismatch, or failed strict verification.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum BrokerSessionArtifactError {
    /// A subject or signer reference violates its fixed semantic shape.
    #[error("invalid Broker Session Authentication subject: {0}")]
    Validation(#[from] BrokerSessionValidationError),
    /// Magic, version, purpose, method, reserved bytes, length, or trailing bytes differ.
    #[error("invalid or noncanonical Broker Session Authentication artifact")]
    InvalidEnvelope,
    /// The signer use does not match the closed artifact purpose.
    #[error("Broker Session Authentication signer use does not match artifact purpose")]
    SignerUsageMismatch,
    /// The supplied raw key does not match the signed reference fingerprint.
    #[error("Broker Session Authentication public-key fingerprint mismatch")]
    PublicKeyMismatch,
    /// The supplied Ed25519 public key is malformed or weak.
    #[error("invalid or weak Broker Session Authentication Ed25519 public key")]
    InvalidPublicKey,
    /// Strict Ed25519 verification failed.
    #[error("invalid Broker Session Authentication Ed25519 signature")]
    InvalidSignature,
}

/// Carries one signed canonical ClientHello subject.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedBrokerClientHelloV1 {
    subject: BrokerClientHelloSubjectV1,
    signer: BrokerSessionSignerReferenceV1,
    signature: BrokerSessionSignature,
}

/// Carries one signed canonical BrokerHello subject.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedBrokerHelloV1 {
    subject: BrokerHelloSubjectV1,
    signer: BrokerSessionSignerReferenceV1,
    signature: BrokerSessionSignature,
}

/// Carries one signed client-to-broker request record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedBrokerRequestV1 {
    method: BrokerMethod,
    subject: BrokerRequestSubjectV1,
    signer: BrokerSessionSignerReferenceV1,
    signature: BrokerSessionSignature,
}

/// Carries one signed broker-to-client terminal outcome, including errors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedBrokerOutcomeV1 {
    method: BrokerMethod,
    subject: BrokerOutcomeSubjectV1,
    signer: BrokerSessionSignerReferenceV1,
    signature: BrokerSessionSignature,
}

/// Retains canonical outcome DATA prepared before a signing boundary.
///
/// The preimage carries no key, endpoint, clock or admission authority. The
/// caller still supplies and validates its genuine purpose-specific key.
pub struct PreparedBrokerOutcomeV1 {
    method: BrokerMethod,
    subject: BrokerOutcomeSubjectV1,
    signer: BrokerSessionSignerReferenceV1,
    subject_bytes: Vec<u8>,
    preimage: Vec<u8>,
}

impl PreparedBrokerOutcomeV1 {
    /// Prepares the sole canonical subject and domain-separated preimage.
    ///
    /// # Errors
    /// Rejects an unknown method or a non-outcome signer usage.
    pub fn new(
        method: BrokerMethod,
        subject: BrokerOutcomeSubjectV1,
        signer: BrokerSessionSignerReferenceV1,
    ) -> Result<Self, BrokerSessionArtifactError> {
        let code = method_code(method)?;
        if signer.usage() != BrokerSessionKeyUsageV1::BrokerOutcome {
            return Err(BrokerSessionArtifactError::SignerUsageMismatch);
        }
        let subject_bytes = encode_outcome_subject(&subject);
        let preimage = signing_message(
            OUTCOME_SIGNATURE_DOMAIN, BROKER_OUTCOME_PURPOSE, code,
            &signer, &subject_bytes,
        );
        Ok(Self { method, subject, signer, subject_bytes, preimage })
    }

    /// Signs the retained preimage without reconstructing its DATA buffers.
    ///
    /// # Errors
    /// Rejects a wrong, weak or mismatched outcome key.
    pub fn sign(&self, key: &SigningKey) -> Result<SignedBrokerOutcomeV1, BrokerSessionArtifactError> {
        require_key(&self.signer, BrokerSessionKeyUsageV1::BrokerOutcome, key.verifying_key().as_bytes())?;
        Ok(self.sign_validated(key))
    }

    /// Moves this prepared outcome and key into an unvalidated owning operation.
    ///
    /// This is cryptographic DATA custody, not protected endpoint or effect
    /// authority. The caller parks the object before its fallible preparation.
    #[must_use = "park the key owner before its fallible preparation"]
    pub fn into_signing_preparation(self, key: SigningKey) -> BrokerOutcomeSigningPreparationV1 {
        BrokerOutcomeSigningPreparationV1 {
            prepared: self,
            key,
            validation: None,
            phase: OutcomeSigningPhaseV1::Fresh,
        }
    }

    fn sign_validated(&self, key: &SigningKey) -> SignedBrokerOutcomeV1 {
        SignedBrokerOutcomeV1 {
            method: self.method,
            subject: self.subject.clone(),
            signer: self.signer.clone(),
            signature: BrokerSessionSignature::from_bytes(key.sign(&self.preimage).to_bytes()),
        }
    }

    /// Fills an already reserved canonical artifact destination.
    ///
    /// # Errors
    /// Rejects nonempty/undersized storage or an artifact for other DATA.
    pub fn encode_signed_into(
        &self,
        signed: &SignedBrokerOutcomeV1,
        bytes: &mut Vec<u8>,
    ) -> Result<(), BrokerSessionArtifactError> {
        if !bytes.is_empty() || bytes.capacity() < SIGNED_BROKER_OUTCOME_BYTES
            || signed.method != self.method || signed.subject != self.subject
            || signed.signer != self.signer
        {
            return Err(BrokerSessionArtifactError::InvalidEnvelope);
        }
        encode_artifact_into(
            bytes, BROKER_OUTCOME_PURPOSE, method_code(self.method)?,
            &self.signer, &self.subject_bytes, &signed.signature,
        );
        Ok(())
    }
}

/// Owns one prepared outcome and key across a caller's final original checks.
///
/// This is not a credential, Session or effect permit. It exposes no key or
/// message and cannot replace either input. Validation errors remain owned.
pub struct BrokerOutcomeSigningPreparationV1 {
    // Preserve the old prepared-subject-before-key destructor frontier.
    prepared: PreparedBrokerOutcomeV1,
    key: SigningKey,
    validation: Option<Result<(), BrokerSessionArtifactError>>,
    phase: OutcomeSigningPhaseV1,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum OutcomeSigningPhaseV1 {
    Fresh,
    Ready,
    Closed,
}

impl BrokerOutcomeSigningPreparationV1 {
    /// Validates the original key once and retains the whole returned Result.
    ///
    /// # Errors
    /// Refuses repetition, wrong usage, fingerprint mismatch, invalid or weak
    /// keys. The actual error remains resident; the returned clone is only an
    /// artifact-error DATA diagnostic. Failure and unwind stay closed.
    pub fn prepare_once(&mut self) -> Result<(), BrokerSessionArtifactError> {
        if self.phase != OutcomeSigningPhaseV1::Fresh || self.validation.is_some() {
            self.phase = OutcomeSigningPhaseV1::Closed;
            return Err(BrokerSessionArtifactError::InvalidEnvelope);
        }

        self.phase = OutcomeSigningPhaseV1::Closed;
        self.validation = Some(require_key(
            &self.prepared.signer,
            BrokerSessionKeyUsageV1::BrokerOutcome,
            self.key.verifying_key().as_bytes(),
        ));

        match self.validation.as_ref() {
            Some(Ok(())) => {
                self.phase = OutcomeSigningPhaseV1::Ready;
                Ok(())
            }
            Some(Err(error)) => Err(error.clone()),
            None => Err(BrokerSessionArtifactError::InvalidEnvelope),
        }
    }

    /// Borrows the actual retained key-validation failure.
    #[must_use]
    pub fn failure(&self) -> Option<&BrokerSessionArtifactError> {
        self.validation.as_ref().and_then(|result| result.as_ref().err())
    }

    /// Signs the validated outcome once without rebuilding its canonical DATA.
    ///
    /// The short borrow follows the caller's final original checks and clock.
    /// No validator or canonical encoder runs behind that boundary.
    ///
    /// # Errors
    /// Refuses incomplete/failed preparation or repeated signing. Underlying
    /// signing has no fallible return; unwind leaves the attempt closed.
    pub fn sign_once(&mut self) -> Result<SignedBrokerOutcomeV1, BrokerSessionArtifactError> {
        if self.phase != OutcomeSigningPhaseV1::Ready
            || !matches!(self.validation.as_ref(), Some(Ok(())))
        {
            return Err(BrokerSessionArtifactError::InvalidEnvelope);
        }

        self.phase = OutcomeSigningPhaseV1::Closed;
        Ok(self.prepared.sign_validated(&self.key))
    }

    /// Fills the existing reserved response using this same outcome DATA.
    ///
    /// # Errors
    /// Preserves the existing response/subject/signature/capacity rejection.
    pub fn fill_signed_response(
        &self,
        response: &mut crate::projection::PreparedBrokerResponseV1,
        signed: &SignedBrokerOutcomeV1,
    ) -> Result<(), crate::projection::BrokerSessionProjectionError> {
        response.fill(&self.prepared, signed)
    }
}

macro_rules! signed_accessors {
    ($type:ty, $subject:ty) => {
        impl $type {
            /// Returns the typed fixed-width subject.
            #[must_use]
            pub const fn subject(&self) -> &$subject {
                &self.subject
            }
            /// Returns the exact signer reference.
            #[must_use]
            pub const fn signer(&self) -> &BrokerSessionSignerReferenceV1 {
                &self.signer
            }
            /// Returns the exact Ed25519 signature bytes.
            #[must_use]
            pub const fn signature(&self) -> &BrokerSessionSignature {
                &self.signature
            }
        }
    };
}

signed_accessors!(SignedBrokerClientHelloV1, BrokerClientHelloSubjectV1);
signed_accessors!(SignedBrokerHelloV1, BrokerHelloSubjectV1);
signed_accessors!(SignedBrokerRequestV1, BrokerRequestSubjectV1);
signed_accessors!(SignedBrokerOutcomeV1, BrokerOutcomeSubjectV1);

impl SignedBrokerRequestV1 {
    /// Returns the exact signed broker method.
    #[must_use]
    pub const fn method(&self) -> BrokerMethod {
        self.method
    }
}

impl SignedBrokerOutcomeV1 {
    /// Returns the exact signed broker method.
    #[must_use]
    pub const fn method(&self) -> BrokerMethod {
        self.method
    }
}

/// Computes the ordered four-reference signer-set digest.
///
/// The order is ClientHello, BrokerHello, ClientRecord, BrokerOutcome.
#[must_use]
pub fn signer_set_digest_v1(signers: &[BrokerSessionSignerReferenceV1; 4]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(SIGNER_SET_DOMAIN);
    for signer in signers {
        let mut encoded = Vec::with_capacity(BROKER_SESSION_SIGNER_REFERENCE_BYTES);
        signer.encode_into(&mut encoded);
        hasher.update(encoded);
    }
    hasher.finalize().into()
}

/// Digests the complete signed ClientHello artifact under its independent domain.
#[must_use]
pub fn complete_signed_client_hello_digest_v1(value: &SignedBrokerClientHelloV1) -> [u8; 32] {
    length_prefixed_digest(
        SIGNED_CLIENT_HELLO_DIGEST_DOMAIN,
        &value.to_canonical_bytes(),
    )
}

/// Digests the complete signed ClientRecord artifact under its independent domain.
#[must_use]
pub fn complete_signed_request_digest_v1(value: &SignedBrokerRequestV1) -> [u8; 32] {
    length_prefixed_digest(SIGNED_REQUEST_DIGEST_DOMAIN, &value.to_canonical_bytes())
}

/// Digests the complete signed BrokerOutcome artifact under its independent domain.
#[must_use]
pub fn complete_signed_outcome_digest_v1(value: &SignedBrokerOutcomeV1) -> [u8; 32] {
    complete_signed_outcome_bytes_digest_v1(&value.to_canonical_bytes())
}

pub(crate) fn complete_signed_outcome_bytes_digest_v1(bytes: &[u8]) -> [u8; 32] {
    length_prefixed_digest(SIGNED_OUTCOME_DIGEST_DOMAIN, bytes)
}

/// Signs a ClientHello with the dedicated ClientHello key.
///
/// # Errors
///
/// Returns [`BrokerSessionArtifactError`] for wrong use or fingerprint mismatch.
pub fn sign_client_hello_v1(
    subject: BrokerClientHelloSubjectV1,
    signer: BrokerSessionSignerReferenceV1,
    key: &SigningKey,
) -> Result<SignedBrokerClientHelloV1, BrokerSessionArtifactError> {
    let signature = sign(
        CLIENT_HELLO_SIGNATURE_DOMAIN,
        CLIENT_HELLO_PURPOSE,
        0,
        &encode_client_hello_subject(&subject),
        &signer,
        BrokerSessionKeyUsageV1::ClientHello,
        key,
    )?;
    Ok(SignedBrokerClientHelloV1 {
        subject,
        signer,
        signature,
    })
}

/// Signs a BrokerHello with the dedicated BrokerHello key.
///
/// # Errors
///
/// Returns [`BrokerSessionArtifactError`] for wrong use or fingerprint mismatch.
pub fn sign_broker_hello_v1(
    subject: BrokerHelloSubjectV1,
    signer: BrokerSessionSignerReferenceV1,
    key: &SigningKey,
) -> Result<SignedBrokerHelloV1, BrokerSessionArtifactError> {
    let signature = sign(
        BROKER_HELLO_SIGNATURE_DOMAIN,
        BROKER_HELLO_PURPOSE,
        0,
        &encode_broker_hello_subject(&subject),
        &signer,
        BrokerSessionKeyUsageV1::BrokerHello,
        key,
    )?;
    Ok(SignedBrokerHelloV1 {
        subject,
        signer,
        signature,
    })
}

/// Signs a ClientRecord with the dedicated client traffic key.
///
/// # Errors
///
/// Returns [`BrokerSessionArtifactError`] for an invalid method, wrong use, or fingerprint mismatch.
pub fn sign_request_v1(
    method: BrokerMethod,
    subject: BrokerRequestSubjectV1,
    signer: BrokerSessionSignerReferenceV1,
    key: &SigningKey,
) -> Result<SignedBrokerRequestV1, BrokerSessionArtifactError> {
    let method = method_code(method)?;
    let signature = sign(
        REQUEST_SIGNATURE_DOMAIN,
        CLIENT_RECORD_PURPOSE,
        method,
        &encode_request_subject(&subject),
        &signer,
        BrokerSessionKeyUsageV1::ClientRecord,
        key,
    )?;
    Ok(SignedBrokerRequestV1 {
        method: broker_method(method)?,
        subject,
        signer,
        signature,
    })
}

/// Signs a BrokerOutcome with the dedicated broker traffic key.
///
/// Every authenticated success and error uses this same terminal record shape.
///
/// # Errors
///
/// Returns [`BrokerSessionArtifactError`] for an invalid method, wrong use, or fingerprint mismatch.
pub fn sign_outcome_v1(
    method: BrokerMethod,
    subject: BrokerOutcomeSubjectV1,
    signer: BrokerSessionSignerReferenceV1,
    key: &SigningKey,
) -> Result<SignedBrokerOutcomeV1, BrokerSessionArtifactError> {
    let method = method_code(method)?;
    let signature = sign(
        OUTCOME_SIGNATURE_DOMAIN,
        BROKER_OUTCOME_PURPOSE,
        method,
        &encode_outcome_subject(&subject),
        &signer,
        BrokerSessionKeyUsageV1::BrokerOutcome,
        key,
    )?;
    Ok(SignedBrokerOutcomeV1 {
        method: broker_method(method)?,
        subject,
        signer,
        signature,
    })
}

macro_rules! hello_wire {
    ($type:ty, $purpose:expr, $usage:expr, $width:expr, $encode:ident, $decode:ident, $domain:ident) => {
        impl $type {
            /// Encodes the exact canonical signed artifact.
            #[must_use]
            pub fn to_canonical_bytes(&self) -> Vec<u8> {
                let subject = $encode(&self.subject);
                encode_artifact($purpose, 0, &self.signer, &subject, &self.signature)
            }

            /// Decodes exact framing and subject semantics without selecting trust.
            ///
            /// # Errors
            ///
            /// Returns [`BrokerSessionArtifactError`] for every malformed, unknown,
            /// reserved, trailing, noncanonical, or wrong-purpose byte.
            pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, BrokerSessionArtifactError> {
                if bytes.len() != $width {
                    return Err(BrokerSessionArtifactError::InvalidEnvelope);
                }
                let decoded = decode_artifact(bytes)?;
                require_artifact(&decoded, $purpose, 0, $usage)?;
                Ok(Self {
                    subject: $decode(decoded.subject)?,
                    signer: decoded.signer,
                    signature: decoded.signature,
                })
            }

            /// Strictly verifies this artifact with caller-selected key material.
            ///
            /// # Errors
            ///
            /// Returns [`BrokerSessionArtifactError`] for wrong use/fingerprint,
            /// a malformed or weak key, or an invalid signature.
            pub fn verify_with_public_key(
                &self,
                public_key: &[u8; 32],
            ) -> Result<(), BrokerSessionArtifactError> {
                verify(
                    $domain,
                    $purpose,
                    0,
                    &$encode(&self.subject),
                    &self.signer,
                    &self.signature,
                    $usage,
                    public_key,
                )
            }
        }
    };
}

hello_wire!(
    SignedBrokerClientHelloV1,
    CLIENT_HELLO_PURPOSE,
    BrokerSessionKeyUsageV1::ClientHello,
    SIGNED_CLIENT_HELLO_BYTES,
    encode_client_hello_subject,
    decode_client_hello_subject,
    CLIENT_HELLO_SIGNATURE_DOMAIN
);
hello_wire!(
    SignedBrokerHelloV1,
    BROKER_HELLO_PURPOSE,
    BrokerSessionKeyUsageV1::BrokerHello,
    SIGNED_BROKER_HELLO_BYTES,
    encode_broker_hello_subject,
    decode_broker_hello_subject,
    BROKER_HELLO_SIGNATURE_DOMAIN
);

macro_rules! traffic_wire {
    ($type:ty, $purpose:expr, $usage:expr, $width:expr, $encode:ident, $decode:ident, $domain:ident) => {
        impl $type {
            /// Encodes the exact canonical signed artifact.
            #[must_use]
            pub fn to_canonical_bytes(&self) -> Vec<u8> {
                let method = closed_method_code(self.method);
                encode_artifact(
                    $purpose,
                    method,
                    &self.signer,
                    &$encode(&self.subject),
                    &self.signature,
                )
            }

            /// Decodes exact framing and subject semantics without selecting trust.
            ///
            /// # Errors
            ///
            /// Returns [`BrokerSessionArtifactError`] for every malformed, unknown,
            /// reserved, trailing, noncanonical, or wrong-purpose byte.
            pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, BrokerSessionArtifactError> {
                if bytes.len() != $width {
                    return Err(BrokerSessionArtifactError::InvalidEnvelope);
                }
                let decoded = decode_artifact(bytes)?;
                if decoded.purpose != $purpose
                    || decoded.method == 0
                    || decoded.signer.usage() != $usage
                {
                    return Err(BrokerSessionArtifactError::InvalidEnvelope);
                }
                Ok(Self {
                    method: broker_method(decoded.method)?,
                    subject: $decode(decoded.subject)?,
                    signer: decoded.signer,
                    signature: decoded.signature,
                })
            }

            /// Strictly verifies this artifact with caller-selected key material.
            ///
            /// # Errors
            ///
            /// Returns [`BrokerSessionArtifactError`] for wrong use/fingerprint,
            /// a malformed or weak key, or an invalid signature.
            pub fn verify_with_public_key(
                &self,
                public_key: &[u8; 32],
            ) -> Result<(), BrokerSessionArtifactError> {
                let method = method_code(self.method)?;
                verify(
                    $domain,
                    $purpose,
                    method,
                    &$encode(&self.subject),
                    &self.signer,
                    &self.signature,
                    $usage,
                    public_key,
                )
            }
        }
    };
}

traffic_wire!(
    SignedBrokerRequestV1,
    CLIENT_RECORD_PURPOSE,
    BrokerSessionKeyUsageV1::ClientRecord,
    SIGNED_BROKER_REQUEST_BYTES,
    encode_request_subject,
    decode_request_subject,
    REQUEST_SIGNATURE_DOMAIN
);
traffic_wire!(
    SignedBrokerOutcomeV1,
    BROKER_OUTCOME_PURPOSE,
    BrokerSessionKeyUsageV1::BrokerOutcome,
    SIGNED_BROKER_OUTCOME_BYTES,
    encode_outcome_subject,
    decode_outcome_subject,
    OUTCOME_SIGNATURE_DOMAIN
);

struct DecodedArtifact<'a> {
    purpose: u8,
    method: u8,
    signer: BrokerSessionSignerReferenceV1,
    subject: &'a [u8],
    signature: BrokerSessionSignature,
}

fn encode_artifact(
    purpose: u8,
    method: u8,
    signer: &BrokerSessionSignerReferenceV1,
    subject: &[u8],
    signature: &BrokerSessionSignature,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(BROKER_SESSION_SIGNED_OVERHEAD_BYTES + subject.len());
    encode_artifact_into(&mut bytes, purpose, method, signer, subject, signature);
    bytes
}

fn encode_artifact_into(
    bytes: &mut Vec<u8>,
    purpose: u8,
    method: u8,
    signer: &BrokerSessionSignerReferenceV1,
    subject: &[u8],
    signature: &BrokerSessionSignature,
) {
    bytes.extend_from_slice(SIGNED_MAGIC);
    bytes.extend_from_slice(&SIGNED_VERSION.to_be_bytes());
    bytes.push(purpose);
    bytes.push(method);
    bytes.extend_from_slice(&[0; 4]);
    signer.encode_into(bytes);
    bytes.extend_from_slice(&(subject.len() as u32).to_be_bytes());
    bytes.extend_from_slice(subject);
    bytes.extend_from_slice(signature.as_bytes());
}

fn decode_artifact(bytes: &[u8]) -> Result<DecodedArtifact<'_>, BrokerSessionArtifactError> {
    const HEADER: usize = 8 + 2 + 1 + 1 + 4 + BROKER_SESSION_SIGNER_REFERENCE_BYTES + 4;
    if bytes.len() < HEADER + SIGNATURE_BYTES
        || bytes.get(..8) != Some(SIGNED_MAGIC)
        || bytes.get(8..10) != Some(SIGNED_VERSION.to_be_bytes().as_slice())
        || bytes
            .get(12..16)
            .is_none_or(|reserved| reserved.iter().any(|byte| *byte != 0))
    {
        return Err(BrokerSessionArtifactError::InvalidEnvelope);
    }
    let signer = BrokerSessionSignerReferenceV1::decode(
        bytes
            .get(16..136)
            .ok_or(BrokerSessionArtifactError::InvalidEnvelope)?,
    )?;
    let length = u32::from_be_bytes(take_array(bytes, 136)?) as usize;
    let subject_end = HEADER
        .checked_add(length)
        .ok_or(BrokerSessionArtifactError::InvalidEnvelope)?;
    if length == 0 || subject_end.checked_add(SIGNATURE_BYTES) != Some(bytes.len()) {
        return Err(BrokerSessionArtifactError::InvalidEnvelope);
    }
    let signature = BrokerSessionSignature::from_bytes(
        bytes
            .get(subject_end..)
            .ok_or(BrokerSessionArtifactError::InvalidEnvelope)?
            .try_into()
            .map_err(|_| BrokerSessionArtifactError::InvalidEnvelope)?,
    );
    Ok(DecodedArtifact {
        purpose: bytes[10],
        method: bytes[11],
        signer,
        subject: &bytes[HEADER..subject_end],
        signature,
    })
}

fn require_artifact(
    decoded: &DecodedArtifact<'_>,
    purpose: u8,
    method: u8,
    usage: BrokerSessionKeyUsageV1,
) -> Result<(), BrokerSessionArtifactError> {
    if decoded.purpose != purpose || decoded.method != method || decoded.signer.usage() != usage {
        Err(BrokerSessionArtifactError::InvalidEnvelope)
    } else {
        Ok(())
    }
}

fn sign(
    domain: &[u8],
    purpose: u8,
    method: u8,
    subject: &[u8],
    signer: &BrokerSessionSignerReferenceV1,
    usage: BrokerSessionKeyUsageV1,
    key: &SigningKey,
) -> Result<BrokerSessionSignature, BrokerSessionArtifactError> {
    require_key(signer, usage, key.verifying_key().as_bytes())?;
    Ok(BrokerSessionSignature::from_bytes(
        key.sign(&signing_message(domain, purpose, method, signer, subject))
            .to_bytes(),
    ))
}

#[allow(clippy::too_many_arguments)]
fn verify(
    domain: &[u8],
    purpose: u8,
    method: u8,
    subject: &[u8],
    signer: &BrokerSessionSignerReferenceV1,
    signature: &BrokerSessionSignature,
    usage: BrokerSessionKeyUsageV1,
    public_key: &[u8; 32],
) -> Result<(), BrokerSessionArtifactError> {
    require_key(signer, usage, public_key)?;
    let key = VerifyingKey::from_bytes(public_key)
        .map_err(|_| BrokerSessionArtifactError::InvalidPublicKey)?;
    if key.is_weak() {
        return Err(BrokerSessionArtifactError::InvalidPublicKey);
    }
    key.verify_strict(
        &signing_message(domain, purpose, method, signer, subject),
        &ed25519_dalek::Signature::from_bytes(signature.as_bytes()),
    )
    .map_err(|_| BrokerSessionArtifactError::InvalidSignature)
}

fn require_key(
    signer: &BrokerSessionSignerReferenceV1,
    usage: BrokerSessionKeyUsageV1,
    public_key: &[u8; 32],
) -> Result<(), BrokerSessionArtifactError> {
    if signer.usage() != usage {
        return Err(BrokerSessionArtifactError::SignerUsageMismatch);
    }
    if <[u8; 32]>::from(Sha256::digest(public_key)) != signer.public_key_digest() {
        return Err(BrokerSessionArtifactError::PublicKeyMismatch);
    }
    let key = VerifyingKey::from_bytes(public_key)
        .map_err(|_| BrokerSessionArtifactError::InvalidPublicKey)?;
    if key.is_weak() {
        return Err(BrokerSessionArtifactError::InvalidPublicKey);
    }
    Ok(())
}

fn signing_message(
    domain: &[u8],
    purpose: u8,
    method: u8,
    signer: &BrokerSessionSignerReferenceV1,
    subject: &[u8],
) -> Vec<u8> {
    let mut message = Vec::with_capacity(domain.len() + 2 + 120 + 4 + subject.len());
    message.extend_from_slice(domain);
    message.push(purpose);
    message.push(method);
    signer.encode_into(&mut message);
    message.extend_from_slice(&(subject.len() as u32).to_be_bytes());
    message.extend_from_slice(subject);
    message
}

pub(crate) fn length_prefixed_digest(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update((bytes.len() as u32).to_be_bytes());
    hasher.update(bytes);
    hasher.finalize().into()
}

fn encode_client_hello_subject(value: &BrokerClientHelloSubjectV1) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(CLIENT_HELLO_SUBJECT_BYTES);
    encode_hello_prefix(
        &mut bytes,
        value.node_id,
        value.boot_id,
        value.protocol,
        value.major,
        value.minor,
        value.audience,
        value.client_process,
        value.nonce,
    );
    bytes.extend_from_slice(&value.protected_context_digest);
    bytes.extend_from_slice(&value.cleared_fields_digest);
    bytes
}

fn encode_broker_hello_subject(value: &BrokerHelloSubjectV1) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(BROKER_HELLO_SUBJECT_BYTES);
    encode_hello_prefix(
        &mut bytes,
        value.node_id,
        value.boot_id,
        value.protocol,
        value.major,
        value.minor,
        value.audience,
        value.broker_process,
        value.nonce,
    );
    bytes.extend_from_slice(&value.protected_context_digest);
    bytes.extend_from_slice(&value.signed_client_hello_digest);
    bytes.extend_from_slice(&value.cleared_fields_digest);
    bytes
}

#[allow(clippy::too_many_arguments)]
fn encode_hello_prefix(
    bytes: &mut Vec<u8>,
    node_id: [u8; 16],
    boot_id: [u8; 16],
    protocol: BrokerSessionProtocolV1,
    major: u16,
    minor: u16,
    audience: aos_proto::aos::sandbox::local::v1::Audience,
    process: [u8; 16],
    nonce: [u8; 32],
) {
    bytes.extend_from_slice(&node_id);
    bytes.extend_from_slice(&boot_id);
    bytes.push(protocol.code());
    bytes.extend_from_slice(&major.to_be_bytes());
    bytes.extend_from_slice(&minor.to_be_bytes());
    bytes.push(closed_audience_code(audience));
    bytes.extend_from_slice(&process);
    bytes.extend_from_slice(&nonce);
}

fn decode_client_hello_subject(
    bytes: &[u8],
) -> Result<BrokerClientHelloSubjectV1, BrokerSessionArtifactError> {
    if bytes.len() != CLIENT_HELLO_SUBJECT_BYTES {
        return Err(BrokerSessionArtifactError::InvalidEnvelope);
    }
    let (node, boot, protocol, major, minor, audience, process, nonce) =
        decode_hello_prefix(bytes)?;
    Ok(BrokerClientHelloSubjectV1::new(
        node,
        boot,
        protocol,
        major,
        minor,
        audience,
        process,
        nonce,
        take_array(bytes, 86)?,
        take_array(bytes, 118)?,
    )?)
}

fn decode_broker_hello_subject(
    bytes: &[u8],
) -> Result<BrokerHelloSubjectV1, BrokerSessionArtifactError> {
    if bytes.len() != BROKER_HELLO_SUBJECT_BYTES {
        return Err(BrokerSessionArtifactError::InvalidEnvelope);
    }
    let (node, boot, protocol, major, minor, audience, process, nonce) =
        decode_hello_prefix(bytes)?;
    Ok(BrokerHelloSubjectV1::new(
        node,
        boot,
        protocol,
        major,
        minor,
        audience,
        process,
        nonce,
        take_array(bytes, 86)?,
        take_array(bytes, 118)?,
        take_array(bytes, 150)?,
    )?)
}

type HelloPrefix = (
    [u8; 16],
    [u8; 16],
    BrokerSessionProtocolV1,
    u16,
    u16,
    aos_proto::aos::sandbox::local::v1::Audience,
    [u8; 16],
    [u8; 32],
);

fn decode_hello_prefix(bytes: &[u8]) -> Result<HelloPrefix, BrokerSessionArtifactError> {
    Ok((
        take_array(bytes, 0)?,
        take_array(bytes, 16)?,
        BrokerSessionProtocolV1::from_code(bytes[32])?,
        u16::from_be_bytes(take_array(bytes, 33)?),
        u16::from_be_bytes(take_array(bytes, 35)?),
        audience_from_code(bytes[37])?,
        take_array(bytes, 38)?,
        take_array(bytes, 54)?,
    ))
}

fn encode_request_subject(value: &BrokerRequestSubjectV1) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(BROKER_REQUEST_SUBJECT_BYTES);
    bytes.extend_from_slice(&value.session_binding);
    bytes.extend_from_slice(&value.client_process);
    bytes.extend_from_slice(&value.sequence.to_be_bytes());
    bytes.extend_from_slice(&value.request_id);
    bytes.extend_from_slice(&value.cleared_fields_digest);
    bytes
}

fn decode_request_subject(
    bytes: &[u8],
) -> Result<BrokerRequestSubjectV1, BrokerSessionArtifactError> {
    if bytes.len() != BROKER_REQUEST_SUBJECT_BYTES {
        return Err(BrokerSessionArtifactError::InvalidEnvelope);
    }
    Ok(BrokerRequestSubjectV1::new(
        take_array(bytes, 0)?,
        take_array(bytes, 32)?,
        u64::from_be_bytes(take_array(bytes, 48)?),
        take_array(bytes, 56)?,
        take_array(bytes, 72)?,
    )?)
}

fn encode_outcome_subject(value: &BrokerOutcomeSubjectV1) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(BROKER_OUTCOME_SUBJECT_BYTES);
    bytes.extend_from_slice(&value.session_binding);
    bytes.extend_from_slice(&value.broker_process);
    bytes.extend_from_slice(&value.sequence.to_be_bytes());
    bytes.extend_from_slice(&value.request_id);
    bytes.extend_from_slice(&value.signed_request_digest);
    bytes.extend_from_slice(&value.cleared_fields_digest);
    bytes
}

fn decode_outcome_subject(
    bytes: &[u8],
) -> Result<BrokerOutcomeSubjectV1, BrokerSessionArtifactError> {
    if bytes.len() != BROKER_OUTCOME_SUBJECT_BYTES {
        return Err(BrokerSessionArtifactError::InvalidEnvelope);
    }
    Ok(BrokerOutcomeSubjectV1::new(
        take_array(bytes, 0)?,
        take_array(bytes, 32)?,
        u64::from_be_bytes(take_array(bytes, 48)?),
        take_array(bytes, 56)?,
        take_array(bytes, 72)?,
        take_array(bytes, 104)?,
    )?)
}

fn broker_method(code: u8) -> Result<BrokerMethod, BrokerSessionArtifactError> {
    BrokerMethod::from_i32(i32::from(code))
        .filter(|method| *method != BrokerMethod::BROKER_METHOD_UNSPECIFIED)
        .ok_or(BrokerSessionValidationError::InvalidClosedValue("method").into())
}

fn closed_method_code(method: BrokerMethod) -> u8 {
    method_code(method).unwrap_or_default()
}

fn closed_audience_code(audience: aos_proto::aos::sandbox::local::v1::Audience) -> u8 {
    audience_code(audience).unwrap_or_default()
}
