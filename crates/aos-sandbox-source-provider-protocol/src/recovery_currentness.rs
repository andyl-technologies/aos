//! Descriptor-free recovery of one original selected Acquire attempt.
//!
//! A new authenticated carrier may query an old protected attempt, but this
//! format cannot carry a lease, descriptor, or successful Acquire result. The
//! signed response is an explicit unavailable observation, not an old-session
//! SourceProvider response or permission to create a successor attempt.
//!
//! ```text
//! query: AOSSPR01 | kind=1 | version=1 | reserved[6]=0 |
//!        new-session[32] | nonce[32] | sequence:u64be |
//!        provider-id[16] | holder-id[16] | acquisition-id[32] |
//!        original-signed-request-digest[32] | mount-attempt-record-digest[32]
//! response: AOSSPR01 | kind=2 | version=1 | reserved[6]=0 |
//!        new-session[32] | query-digest[32] | acquisition-id[32] |
//!        original-signed-request-digest[32] | mount-attempt-record-digest[32] |
//!        signed-storage-plan-digest[32] | status:u8=1 | reserved[7]=0 |
//!        provider-outcome-signer[120] | signature[64]
//! native response: AOSSPR02 | kind=2 | version=1 | reserved[6]=0 |
//!        new-session[32] | query-digest[32] | acquisition-id[32] |
//!        original-signed-request-digest[32] | mount-attempt-record-digest[32] |
//!        selected-native-reservation-digest[32] | faulted-acquisition-digest[32] |
//!        retired-attempt-digest[32] | cleared-session-digest[32] |
//!        status:u8=2 | reserved[7]=0 |
//!        provider-outcome-signer[120] | signature[64]
//! ```

use aos_sandbox_core::ObjectDigest;
use ed25519_dalek::SigningKey;
use sha2::{Digest as _, Sha256};

use crate::crypto::{
    SourceProviderKeyUsageV1, SourceProviderSignature, SourceProviderSignatureError,
    SourceProviderSigningKeyV1, decode_signer, encode_signer, sign_bytes, verify_bytes,
};

const MAGIC: &[u8; 8] = b"AOSSPR01";
const NATIVE_RESPONSE_MAGIC: &[u8; 8] = b"AOSSPR02";
const VERSION: u8 = 1;
const QUERY_KIND: u8 = 1;
const RESPONSE_KIND: u8 = 2;
const QUERY_BYTES: usize = 216;
const RESPONSE_SUBJECT_BYTES: usize = 216;
const RESPONSE_BYTES: usize = RESPONSE_SUBJECT_BYTES + 120 + 64;
const NATIVE_RESPONSE_SUBJECT_BYTES: usize = RESPONSE_SUBJECT_BYTES + 96;
const NATIVE_RESPONSE_BYTES: usize = NATIVE_RESPONSE_SUBJECT_BYTES + 120 + 64;
const UNAVAILABLE_STATUS: u8 = 1;
const NATIVE_NO_DISPATCH_STATUS: u8 = 2;
const QUERY_DIGEST_DOMAIN: &[u8] = b"aos-source-provider-recovery-query-v1\0";
const RESPONSE_SIGNATURE_DOMAIN: &[u8] = b"aos-source-provider-recovery-unavailable-v1\0";
const NATIVE_RESPONSE_SIGNATURE_DOMAIN: &[u8] =
    b"aos-source-provider-native-recovery-no-dispatch-v1\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RecoveryAnswerFlavorV1 {
    LocalLive,
    NativeNoDispatch,
}

impl RecoveryAnswerFlavorV1 {
    const fn magic(self) -> &'static [u8; 8] {
        match self {
            Self::LocalLive => MAGIC,
            Self::NativeNoDispatch => NATIVE_RESPONSE_MAGIC,
        }
    }

    const fn status(self) -> u8 {
        match self {
            Self::LocalLive => UNAVAILABLE_STATUS,
            Self::NativeNoDispatch => NATIVE_NO_DISPATCH_STATUS,
        }
    }

    const fn signature_domain(self) -> &'static [u8] {
        match self {
            Self::LocalLive => RESPONSE_SIGNATURE_DOMAIN,
            Self::NativeNoDispatch => NATIVE_RESPONSE_SIGNATURE_DOMAIN,
        }
    }

    const fn subject_bytes(self) -> usize {
        match self {
            Self::LocalLive => RESPONSE_SUBJECT_BYTES,
            Self::NativeNoDispatch => NATIVE_RESPONSE_SUBJECT_BYTES,
        }
    }

    const fn response_bytes(self) -> usize {
        match self {
            Self::LocalLive => RESPONSE_BYTES,
            Self::NativeNoDispatch => NATIVE_RESPONSE_BYTES,
        }
    }
}

/// Names the exact Provider records in a terminal native no-dispatch settlement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeRecoveryTerminalDigestsV1 {
    /// The selected Applying acquisition before terminalization.
    pub reservation: ObjectDigest,
    /// The same acquisition after its durable Faulted transition.
    pub faulted_acquisition: ObjectDigest,
    /// The original attempt after its durable Retired transition.
    pub retired_attempt: ObjectDigest,
    /// The original session after its pending attempt was cleared.
    pub cleared_session: ObjectDigest,
}

impl NativeRecoveryTerminalDigestsV1 {
    fn all_nonzero(self) -> bool {
        [
            self.reservation,
            self.faulted_acquisition,
            self.retired_attempt,
            self.cleared_session,
        ]
        .iter()
        .all(|digest| digest.as_bytes() != &[0; 32])
    }
}

/// Rejects malformed, stale, or unauthenticated recovery control records.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum RecoveryCurrentnessErrorV1 {
    /// The packet is not the exact canonical version-one format.
    #[error("noncanonical SourceProvider recovery record")]
    Noncanonical,
    /// The response is not bound to the exact live original-attempt query.
    #[error("SourceProvider recovery response does not match the query")]
    Stale,
    /// The Provider outcome signature or signer is invalid.
    #[error("SourceProvider recovery signature failed: {0}")]
    Signature(#[from] SourceProviderSignatureError),
}

/// Challenges one new session about an exact original Acquire attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryCurrentnessQueryV1 {
    session_binding: ObjectDigest,
    nonce: [u8; 32],
    sequence: u64,
    provider_id: [u8; 16],
    holder_id: [u8; 16],
    acquisition_id: ObjectDigest,
    original_signed_request_digest: ObjectDigest,
    original_attempt_digest: ObjectDigest,
}

impl RecoveryCurrentnessQueryV1 {
    /// Constructs a nonauthorizing, nonce-bound original-attempt query.
    ///
    /// # Errors
    ///
    /// Rejects zero identity, nonce, sequence, or digest fields.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        session_binding: ObjectDigest,
        nonce: [u8; 32],
        sequence: u64,
        provider_id: [u8; 16],
        holder_id: [u8; 16],
        acquisition_id: ObjectDigest,
        original_signed_request_digest: ObjectDigest,
        original_attempt_digest: ObjectDigest,
    ) -> Result<Self, RecoveryCurrentnessErrorV1> {
        if session_binding.as_bytes() == &[0; 32]
            || nonce == [0; 32]
            || sequence == 0
            || provider_id == [0; 16]
            || holder_id == [0; 16]
            || acquisition_id.as_bytes() == &[0; 32]
            || original_signed_request_digest.as_bytes() == &[0; 32]
            || original_attempt_digest.as_bytes() == &[0; 32]
        {
            return Err(RecoveryCurrentnessErrorV1::Noncanonical);
        }
        Ok(Self {
            session_binding,
            nonce,
            sequence,
            provider_id,
            holder_id,
            acquisition_id,
            original_signed_request_digest,
            original_attempt_digest,
        })
    }

    /// Returns the new authenticated session binding.
    #[must_use]
    pub const fn session_binding(&self) -> ObjectDigest {
        self.session_binding
    }

    /// Returns the strictly increasing query sequence on this carrier.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns the original Provider and RootMount authority IDs.
    #[must_use]
    pub const fn authorities(&self) -> ([u8; 16], [u8; 16]) {
        (self.provider_id, self.holder_id)
    }

    /// Returns the original acquisition ID.
    #[must_use]
    pub const fn acquisition_id(&self) -> ObjectDigest {
        self.acquisition_id
    }

    /// Returns the original signed RootMount request digest.
    #[must_use]
    pub const fn original_signed_request_digest(&self) -> ObjectDigest {
        self.original_signed_request_digest
    }

    /// Returns the original protected Mount attempt record digest.
    #[must_use]
    pub const fn original_attempt_digest(&self) -> ObjectDigest {
        self.original_attempt_digest
    }

    /// Encodes the exact fixed-size query.
    #[must_use]
    pub fn to_canonical_bytes(&self) -> [u8; QUERY_BYTES] {
        let mut bytes = [0; QUERY_BYTES];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8] = QUERY_KIND;
        bytes[9] = VERSION;
        bytes[16..48].copy_from_slice(self.session_binding.as_bytes());
        bytes[48..80].copy_from_slice(&self.nonce);
        bytes[80..88].copy_from_slice(&self.sequence.to_be_bytes());
        bytes[88..104].copy_from_slice(&self.provider_id);
        bytes[104..120].copy_from_slice(&self.holder_id);
        bytes[120..152].copy_from_slice(self.acquisition_id.as_bytes());
        bytes[152..184].copy_from_slice(self.original_signed_request_digest.as_bytes());
        bytes[184..216].copy_from_slice(self.original_attempt_digest.as_bytes());
        bytes
    }

    /// Decodes only one canonical query packet.
    ///
    /// # Errors
    ///
    /// Rejects changed kind, version, size, reserved bytes, or sentinels.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, RecoveryCurrentnessErrorV1> {
        require_header(bytes, QUERY_BYTES, QUERY_KIND)?;
        Self::new(
            digest_at(bytes, 16)?,
            array_at(bytes, 48)?,
            u64_at(bytes, 80)?,
            array_at(bytes, 88)?,
            array_at(bytes, 104)?,
            digest_at(bytes, 120)?,
            digest_at(bytes, 152)?,
            digest_at(bytes, 184)?,
        )
    }

    /// Commits every challenge byte for the signed response.
    #[must_use]
    pub fn digest(&self) -> ObjectDigest {
        let mut hasher = Sha256::new();
        hasher.update(QUERY_DIGEST_DOMAIN);
        hasher.update(self.to_canonical_bytes());
        ObjectDigest::from_bytes(hasher.finalize().into())
    }
}

/// Signs a descriptor-free LocalLive Unavailable result for the exact old attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedRecoveryUnavailableV1 {
    flavor: RecoveryAnswerFlavorV1,
    session_binding: ObjectDigest,
    query_digest: ObjectDigest,
    acquisition_id: ObjectDigest,
    original_signed_request_digest: ObjectDigest,
    original_attempt_digest: ObjectDigest,
    subject_digest: ObjectDigest,
    native_terminal: Option<NativeRecoveryTerminalDigestsV1>,
    signer: SourceProviderSigningKeyV1,
    signature: SourceProviderSignature,
}

impl SignedRecoveryUnavailableV1 {
    /// Signs only the response shape; protected journal/readback is caller-owned.
    ///
    /// # Errors
    ///
    /// Rejects a zero plan digest, wrong-use signer, or key mismatch.
    pub fn sign(
        query: &RecoveryCurrentnessQueryV1,
        signed_storage_plan_digest: ObjectDigest,
        signer: SourceProviderSigningKeyV1,
        signing_key: &SigningKey,
    ) -> Result<Self, RecoveryCurrentnessErrorV1> {
        Self::sign_for_flavor(
            query,
            signed_storage_plan_digest,
            signer,
            signing_key,
            RecoveryAnswerFlavorV1::LocalLive,
            None,
        )
    }

    fn sign_for_flavor(
        query: &RecoveryCurrentnessQueryV1,
        subject_digest: ObjectDigest,
        signer: SourceProviderSigningKeyV1,
        signing_key: &SigningKey,
        flavor: RecoveryAnswerFlavorV1,
        native_terminal: Option<NativeRecoveryTerminalDigestsV1>,
    ) -> Result<Self, RecoveryCurrentnessErrorV1> {
        if subject_digest.as_bytes() == &[0; 32]
            || native_terminal.is_some() != (flavor == RecoveryAnswerFlavorV1::NativeNoDispatch)
            || native_terminal.is_some_and(|digests| {
                !digests.all_nonzero() || digests.reservation != subject_digest
            })
            || signer.usage() != SourceProviderKeyUsageV1::ProviderOutcome
            || signer.authority_id() != query.authorities().0
        {
            return Err(RecoveryCurrentnessErrorV1::Noncanonical);
        }
        let mut value = Self {
            flavor,
            session_binding: query.session_binding,
            query_digest: query.digest(),
            acquisition_id: query.acquisition_id,
            original_signed_request_digest: query.original_signed_request_digest,
            original_attempt_digest: query.original_attempt_digest,
            subject_digest,
            native_terminal,
            signer,
            signature: SourceProviderSignature::from_bytes([0; 64]),
        };
        value.signature = sign_bytes(
            flavor.signature_domain(),
            RESPONSE_KIND,
            &value.subject_bytes(),
            &value.signer,
            signing_key,
        )?;
        Ok(value)
    }

    /// Verifies the exact challenge and independently pinned Provider key.
    ///
    /// # Errors
    ///
    /// Rejects another query, signer, status, or signature.
    pub fn verify_for_query(
        &self,
        query: &RecoveryCurrentnessQueryV1,
        expected_signer: &SourceProviderSigningKeyV1,
        public_key: &[u8; 32],
    ) -> Result<(), RecoveryCurrentnessErrorV1> {
        if self.flavor != RecoveryAnswerFlavorV1::LocalLive {
            return Err(RecoveryCurrentnessErrorV1::Stale);
        }
        self.verify_for_query_inner(query, expected_signer, public_key)
    }

    fn verify_for_query_inner(
        &self,
        query: &RecoveryCurrentnessQueryV1,
        expected_signer: &SourceProviderSigningKeyV1,
        public_key: &[u8; 32],
    ) -> Result<(), RecoveryCurrentnessErrorV1> {
        if self.session_binding != query.session_binding
            || self.query_digest != query.digest()
            || self.acquisition_id != query.acquisition_id
            || self.original_signed_request_digest != query.original_signed_request_digest
            || self.original_attempt_digest != query.original_attempt_digest
            || self.subject_digest.as_bytes() == &[0; 32]
            || &self.signer != expected_signer
            || self.signer.authority_id() != query.authorities().0
        {
            return Err(RecoveryCurrentnessErrorV1::Stale);
        }
        verify_bytes(
            self.flavor.signature_domain(),
            RESPONSE_KIND,
            &self.subject_bytes(),
            &self.signer,
            &self.signature,
            public_key,
        )?;
        Ok(())
    }

    /// Returns the exact signed Storage plan observed before this result.
    #[must_use]
    pub const fn signed_storage_plan_digest(&self) -> ObjectDigest {
        self.subject_digest
    }

    /// Encodes the canonical LocalLive signed recovery result.
    #[must_use]
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = self.subject_bytes();
        encode_signer(&mut bytes, &self.signer);
        bytes.extend_from_slice(self.signature.as_bytes());
        bytes
    }

    /// Decodes one canonical signed Unavailable result.
    ///
    /// # Errors
    ///
    /// Rejects changed size, version, status, reserved bytes, or signer.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, RecoveryCurrentnessErrorV1> {
        Self::from_canonical_bytes_for_flavor(bytes, RecoveryAnswerFlavorV1::LocalLive)
    }

    fn from_canonical_bytes_for_flavor(
        bytes: &[u8],
        flavor: RecoveryAnswerFlavorV1,
    ) -> Result<Self, RecoveryCurrentnessErrorV1> {
        let subject_end = flavor.subject_bytes();
        require_header_with_magic(
            bytes,
            flavor.response_bytes(),
            RESPONSE_KIND,
            flavor.magic(),
        )?;
        if bytes[subject_end - 8] != flavor.status()
            || bytes[subject_end - 7..subject_end] != [0; 7]
        {
            return Err(RecoveryCurrentnessErrorV1::Noncanonical);
        }
        let signer = decode_signer(&bytes[subject_end..subject_end + 120])?;
        if signer.usage() != SourceProviderKeyUsageV1::ProviderOutcome {
            return Err(RecoveryCurrentnessErrorV1::Noncanonical);
        }
        let value = Self {
            flavor,
            session_binding: digest_at(bytes, 16)?,
            query_digest: digest_at(bytes, 48)?,
            acquisition_id: digest_at(bytes, 80)?,
            original_signed_request_digest: digest_at(bytes, 112)?,
            original_attempt_digest: digest_at(bytes, 144)?,
            subject_digest: digest_at(bytes, 176)?,
            native_terminal: (flavor == RecoveryAnswerFlavorV1::NativeNoDispatch)
                .then(|| -> Result<_, RecoveryCurrentnessErrorV1> {
                    Ok(NativeRecoveryTerminalDigestsV1 {
                        reservation: digest_at(bytes, 176)?,
                        faulted_acquisition: digest_at(bytes, 208)?,
                        retired_attempt: digest_at(bytes, 240)?,
                        cleared_session: digest_at(bytes, 272)?,
                    })
                })
                .transpose()?,
            signer,
            signature: SourceProviderSignature::from_bytes(array_at(bytes, subject_end + 120)?),
        };
        if value.session_binding.as_bytes() == &[0; 32]
            || value.query_digest.as_bytes() == &[0; 32]
            || value.acquisition_id.as_bytes() == &[0; 32]
            || value.original_signed_request_digest.as_bytes() == &[0; 32]
            || value.original_attempt_digest.as_bytes() == &[0; 32]
            || value.subject_digest.as_bytes() == &[0; 32]
            || value
                .native_terminal
                .is_some_and(|digests| !digests.all_nonzero())
            || value.to_canonical_bytes().as_slice() != bytes
        {
            return Err(RecoveryCurrentnessErrorV1::Noncanonical);
        }
        Ok(value)
    }

    fn subject_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.flavor.subject_bytes());
        bytes.extend_from_slice(self.flavor.magic());
        bytes.push(RESPONSE_KIND);
        bytes.push(VERSION);
        bytes.extend_from_slice(&[0; 6]);
        bytes.extend_from_slice(self.session_binding.as_bytes());
        bytes.extend_from_slice(self.query_digest.as_bytes());
        bytes.extend_from_slice(self.acquisition_id.as_bytes());
        bytes.extend_from_slice(self.original_signed_request_digest.as_bytes());
        bytes.extend_from_slice(self.original_attempt_digest.as_bytes());
        bytes.extend_from_slice(self.subject_digest.as_bytes());
        if let Some(digests) = self.native_terminal {
            bytes.extend_from_slice(digests.faulted_acquisition.as_bytes());
            bytes.extend_from_slice(digests.retired_attempt.as_bytes());
            bytes.extend_from_slice(digests.cleared_session.as_bytes());
        }
        bytes.push(self.flavor.status());
        bytes.extend_from_slice(&[0; 7]);
        bytes
    }
}

/// Signs that one native no-dispatch reservation is durably terminal at Provider.
///
/// This distinct response has no Storage plan digest, lease, or descriptor.
/// It names the exact protected pre/post records; Mount must independently
/// settle its pending attempt before treating this as terminal there.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedNativeRecoveryUnavailableV1(SignedRecoveryUnavailableV1);

impl SignedNativeRecoveryUnavailableV1 {
    /// Signs one exact, protected no-dispatch terminalization.
    ///
    /// # Errors
    ///
    /// Rejects zero record digests, wrong-use signer, or key mismatch.
    pub fn sign(
        query: &RecoveryCurrentnessQueryV1,
        terminal: NativeRecoveryTerminalDigestsV1,
        signer: SourceProviderSigningKeyV1,
        signing_key: &SigningKey,
    ) -> Result<Self, RecoveryCurrentnessErrorV1> {
        SignedRecoveryUnavailableV1::sign_for_flavor(
            query,
            terminal.reservation,
            signer,
            signing_key,
            RecoveryAnswerFlavorV1::NativeNoDispatch,
            Some(terminal),
        )
        .map(Self)
    }

    /// Verifies the exact new-session query and independently pinned Provider key.
    ///
    /// # Errors
    ///
    /// Rejects another query, signer, reservation, status, or signature.
    pub fn verify_for_query(
        &self,
        query: &RecoveryCurrentnessQueryV1,
        expected_signer: &SourceProviderSigningKeyV1,
        public_key: &[u8; 32],
    ) -> Result<(), RecoveryCurrentnessErrorV1> {
        self.0
            .verify_for_query_inner(query, expected_signer, public_key)
    }

    /// Returns the exact protected Provider terminalization record digests.
    ///
    /// # Errors
    ///
    /// Rejects a malformed native response with no terminal digest tuple.
    #[must_use]
    pub fn terminal_digests(
        &self,
    ) -> Result<NativeRecoveryTerminalDigestsV1, RecoveryCurrentnessErrorV1> {
        self.0
            .native_terminal
            .ok_or(RecoveryCurrentnessErrorV1::Noncanonical)
    }

    /// Encodes the distinct native no-dispatch response.
    #[must_use]
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        self.0.to_canonical_bytes()
    }

    /// Decodes only the canonical native no-dispatch response.
    ///
    /// # Errors
    ///
    /// Rejects another kind, version, status, signer, or noncanonical field.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, RecoveryCurrentnessErrorV1> {
        SignedRecoveryUnavailableV1::from_canonical_bytes_for_flavor(
            bytes,
            RecoveryAnswerFlavorV1::NativeNoDispatch,
        )
        .map(Self)
    }
}

fn require_header(bytes: &[u8], length: usize, kind: u8) -> Result<(), RecoveryCurrentnessErrorV1> {
    require_header_with_magic(bytes, length, kind, MAGIC)
}

fn require_header_with_magic(
    bytes: &[u8],
    length: usize,
    kind: u8,
    magic: &[u8; 8],
) -> Result<(), RecoveryCurrentnessErrorV1> {
    if bytes.len() != length
        || &bytes[..8] != magic
        || bytes[8] != kind
        || bytes[9] != VERSION
        || bytes[10..16] != [0; 6]
    {
        return Err(RecoveryCurrentnessErrorV1::Noncanonical);
    }
    Ok(())
}

fn array_at<const N: usize>(
    bytes: &[u8],
    start: usize,
) -> Result<[u8; N], RecoveryCurrentnessErrorV1> {
    bytes
        .get(start..start + N)
        .and_then(|value| value.try_into().ok())
        .ok_or(RecoveryCurrentnessErrorV1::Noncanonical)
}

fn digest_at(bytes: &[u8], start: usize) -> Result<ObjectDigest, RecoveryCurrentnessErrorV1> {
    Ok(ObjectDigest::from_bytes(array_at(bytes, start)?))
}

fn u64_at(bytes: &[u8], start: usize) -> Result<u64, RecoveryCurrentnessErrorV1> {
    Ok(u64::from_be_bytes(array_at(bytes, start)?))
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;

    use super::*;

    fn digest(byte: u8) -> ObjectDigest {
        ObjectDigest::from_bytes([byte; 32])
    }

    fn query() -> RecoveryCurrentnessQueryV1 {
        RecoveryCurrentnessQueryV1::new(
            digest(1),
            [2; 32],
            3,
            [4; 16],
            [5; 16],
            digest(6),
            digest(7),
            digest(8),
        )
        .unwrap()
    }

    fn signed(query: &RecoveryCurrentnessQueryV1) -> SignedRecoveryUnavailableV1 {
        let key = SigningKey::from_bytes(&[9; 32]);
        let signer = SourceProviderSigningKeyV1::for_signing_key(
            [4; 16],
            10,
            digest(11),
            [12; 16],
            13,
            SourceProviderKeyUsageV1::ProviderOutcome,
            &key,
        )
        .unwrap();
        SignedRecoveryUnavailableV1::sign(query, digest(14), signer, &key).unwrap()
    }

    fn signed_native(query: &RecoveryCurrentnessQueryV1) -> SignedNativeRecoveryUnavailableV1 {
        let key = SigningKey::from_bytes(&[9; 32]);
        let signer = SourceProviderSigningKeyV1::for_signing_key(
            [4; 16],
            10,
            digest(11),
            [12; 16],
            13,
            SourceProviderKeyUsageV1::ProviderOutcome,
            &key,
        )
        .unwrap();
        SignedNativeRecoveryUnavailableV1::sign(
            query,
            NativeRecoveryTerminalDigestsV1 {
                reservation: digest(15),
                faulted_acquisition: digest(16),
                retired_attempt: digest(17),
                cleared_session: digest(18),
            },
            signer,
            &key,
        )
        .unwrap()
    }

    #[test]
    fn exact_query_response_roundtrip_and_signature() {
        let query = query();
        let decoded_query =
            RecoveryCurrentnessQueryV1::from_canonical_bytes(&query.to_canonical_bytes()).unwrap();
        assert_eq!(decoded_query, query);

        let response = signed(&query);
        let decoded =
            SignedRecoveryUnavailableV1::from_canonical_bytes(&response.to_canonical_bytes())
                .unwrap();
        let key = SigningKey::from_bytes(&[9; 32]);
        decoded
            .verify_for_query(&query, &response.signer, key.verifying_key().as_bytes())
            .unwrap();
        assert_eq!(decoded.signed_storage_plan_digest(), digest(14));
    }

    #[test]
    fn replay_fork_downgrade_and_status_tamper_fail() {
        let query = query();
        let response = signed(&query);
        let key = SigningKey::from_bytes(&[9; 32]);
        let changed = RecoveryCurrentnessQueryV1::new(
            digest(1),
            [3; 32],
            3,
            [4; 16],
            [5; 16],
            digest(6),
            digest(7),
            digest(8),
        )
        .unwrap();
        assert!(
            response
                .verify_for_query(&changed, &response.signer, key.verifying_key().as_bytes())
                .is_err()
        );
        let old_session = RecoveryCurrentnessQueryV1::new(
            digest(15),
            [2; 32],
            3,
            [4; 16],
            [5; 16],
            digest(6),
            digest(7),
            digest(8),
        )
        .unwrap();
        assert!(
            response
                .verify_for_query(
                    &old_session,
                    &response.signer,
                    key.verifying_key().as_bytes()
                )
                .is_err()
        );
        let forked_attempt = RecoveryCurrentnessQueryV1::new(
            digest(1),
            [2; 32],
            3,
            [4; 16],
            [5; 16],
            digest(6),
            digest(7),
            digest(16),
        )
        .unwrap();
        assert!(
            response
                .verify_for_query(
                    &forked_attempt,
                    &response.signer,
                    key.verifying_key().as_bytes()
                )
                .is_err()
        );

        let mut bytes = response.to_canonical_bytes();
        bytes[208] = 2;
        assert!(SignedRecoveryUnavailableV1::from_canonical_bytes(&bytes).is_err());
        let mut bytes = response.to_canonical_bytes();
        bytes[176] ^= 1;
        let forged = SignedRecoveryUnavailableV1::from_canonical_bytes(&bytes).unwrap();
        assert!(
            forged
                .verify_for_query(&query, &response.signer, key.verifying_key().as_bytes())
                .is_err()
        );
        let mut bytes = query.to_canonical_bytes();
        bytes[10] = 1;
        assert!(RecoveryCurrentnessQueryV1::from_canonical_bytes(&bytes).is_err());
        let mut bytes = query.to_canonical_bytes().to_vec();
        bytes.push(0);
        assert!(RecoveryCurrentnessQueryV1::from_canonical_bytes(&bytes).is_err());
    }

    #[test]
    fn native_no_dispatch_is_distinct_and_bound_to_the_exact_query() {
        let query = query();
        let native = signed_native(&query);
        let bytes = native.to_canonical_bytes();
        let decoded = SignedNativeRecoveryUnavailableV1::from_canonical_bytes(&bytes).unwrap();
        let key = SigningKey::from_bytes(&[9; 32]);
        decoded
            .verify_for_query(&query, &native.0.signer, key.verifying_key().as_bytes())
            .unwrap();
        assert_eq!(decoded.terminal_digests().unwrap().reservation, digest(15));
        assert_eq!(
            decoded.terminal_digests().unwrap().cleared_session,
            digest(18)
        );
        assert!(SignedRecoveryUnavailableV1::from_canonical_bytes(&bytes).is_err());
        assert!(
            SignedNativeRecoveryUnavailableV1::from_canonical_bytes(
                &signed(&query).to_canonical_bytes()
            )
            .is_err()
        );

        let changed_query = RecoveryCurrentnessQueryV1::new(
            digest(1),
            [2; 32],
            3,
            [4; 16],
            [5; 16],
            digest(6),
            digest(7),
            digest(16),
        )
        .unwrap();
        assert!(
            decoded
                .verify_for_query(
                    &changed_query,
                    &native.0.signer,
                    key.verifying_key().as_bytes()
                )
                .is_err()
        );
        let wrong_key = SigningKey::from_bytes(&[19; 32]);
        let wrong_signer = SourceProviderSigningKeyV1::for_signing_key(
            [4; 16],
            10,
            digest(11),
            [20; 16],
            14,
            SourceProviderKeyUsageV1::ProviderOutcome,
            &wrong_key,
        )
        .unwrap();
        assert!(
            decoded
                .verify_for_query(&query, &wrong_signer, wrong_key.verifying_key().as_bytes())
                .is_err()
        );

        let mut tampered = bytes.clone();
        tampered[304] = UNAVAILABLE_STATUS;
        assert!(SignedNativeRecoveryUnavailableV1::from_canonical_bytes(&tampered).is_err());
        let mut tampered = bytes;
        tampered[176] ^= 1;
        let forged = SignedNativeRecoveryUnavailableV1::from_canonical_bytes(&tampered).unwrap();
        assert!(
            forged
                .verify_for_query(&query, &native.0.signer, key.verifying_key().as_bytes())
                .is_err()
        );
        let mut tampered_terminal = native.to_canonical_bytes();
        tampered_terminal[240] ^= 1;
        let forged =
            SignedNativeRecoveryUnavailableV1::from_canonical_bytes(&tampered_terminal).unwrap();
        assert!(
            forged
                .verify_for_query(&query, &native.0.signer, key.verifying_key().as_bytes())
                .is_err()
        );
    }
}
