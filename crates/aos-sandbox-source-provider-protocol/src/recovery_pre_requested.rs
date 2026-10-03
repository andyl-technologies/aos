//! Distinct, descriptor-free pre-Requested no-escape recovery DATA.
//!
//! These frames encode signed assertions and references. They do not prove a
//! protected Source archive, Root journal readback, current signer custody, or
//! permission to settle an attempt. Those checks belong to future named owners.
//!
//! ```text
//! AOSSPR03 | kind=2 | version=1 | reserved[6]=0 |
//! session[32] | query_digest[32] | acquisition[32] |
//! original_request[32] | original_attempt[32] | closure_digests[8][32] |
//! status:u8=3 | reserved[7]=0 | ProviderOutcome_signer[120] | signature[64]
//!
//! AOSRNA01 | kind=1 | version=1 | reserved[6]=0 |
//! acknowledgement_digests[11][32] | cleanup_tx[16] |
//! settled_attempt_ref[72] | faulted_acquisition_ref[72] |
//! RootMountRecord_signer[120] | signature[64]
//! ```

use aos_sandbox_core::ObjectDigest;
use ed25519_dalek::SigningKey;
use sha2::{Digest as _, Sha256};

use crate::{
    crypto::{
        SourceProviderKeyUsageV1, SourceProviderSignature, SourceProviderSignatureError,
        SourceProviderSigningKeyV1, decode_signer, encode_signer, sign_bytes, verify_bytes,
    },
    recovery_currentness::RecoveryCurrentnessQueryV1,
};

const ANSWER_MAGIC: &[u8; 8] = b"AOSSPR03";
const ACK_MAGIC: &[u8; 8] = b"AOSRNA01";
const VERSION: u8 = 1;
const ANSWER_KIND: u8 = 2;
const ACK_KIND: u8 = 1;
const ANSWER_STATUS: u8 = 3;
const ANSWER_SUBJECT_BYTES: usize = 440;
const ACK_SUBJECT_BYTES: usize = 528;
const ANSWER_SIGNATURE_DOMAIN: &[u8] = b"aos-source-provider-pre-requested-no-escape.v1\0";
const ACK_SIGNATURE_DOMAIN: &[u8] = b"aos.sandbox.mount.pre-requested-no-escape-ack.v1\0";
const ANSWER_DIGEST_DOMAIN: &[u8] = b"aos-source-provider-pre-requested-answer-digest.v1\0";

/// Fixes the distinct Source no-escape answer width.
pub const PRE_REQUESTED_NO_ESCAPE_ANSWER_BYTES_V1: usize = 624;

/// Fixes the distinct Root no-escape acknowledgement width.
pub const ROOT_NO_ESCAPE_ACK_BYTES_V1: usize = 712;

const _: () = assert!(ANSWER_SUBJECT_BYTES + 120 + 64 == PRE_REQUESTED_NO_ESCAPE_ANSWER_BYTES_V1);
const _: () = assert!(ACK_SUBJECT_BYTES + 120 + 64 == ROOT_NO_ESCAPE_ACK_BYTES_V1);

/// Reports a malformed or mismatched no-escape DATA frame.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PreRequestedRecoveryErrorV1 {
    /// The exact versioned frame, references, or reserved fields are invalid.
    #[error("noncanonical pre-Requested recovery frame")]
    Noncanonical,
    /// The signed frame does not match the independently retained live query.
    #[error("pre-Requested recovery frame does not match the query")]
    Stale,
    /// The signer fingerprint or Ed25519 signature failed verification.
    #[error("pre-Requested recovery signature failed: {0}")]
    Signature(#[from] SourceProviderSignatureError),
}

fn nonzero(digest: ObjectDigest) -> bool {
    digest.as_bytes() != &[0; 32]
}

fn array_at<const N: usize>(
    bytes: &[u8],
    start: usize,
) -> Result<[u8; N], PreRequestedRecoveryErrorV1> {
    bytes
        .get(start..start + N)
        .and_then(|value| value.try_into().ok())
        .ok_or(PreRequestedRecoveryErrorV1::Noncanonical)
}

fn digest_at(bytes: &[u8], start: usize) -> Result<ObjectDigest, PreRequestedRecoveryErrorV1> {
    Ok(ObjectDigest::from_bytes(array_at(bytes, start)?))
}

fn require_header(
    bytes: &[u8],
    width: usize,
    magic: &[u8; 8],
    kind: u8,
) -> Result<(), PreRequestedRecoveryErrorV1> {
    if bytes.len() != width
        || bytes.get(..8) != Some(magic.as_slice())
        || bytes.get(8) != Some(&kind)
        || bytes.get(9) != Some(&VERSION)
        || bytes.get(10..16) != Some([0; 6].as_slice())
    {
        return Err(PreRequestedRecoveryErrorV1::Noncanonical);
    }
    Ok(())
}

/// Names the exact Source archive and terminal owner records without granting access.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreRequestedNoEscapeDigestsV1 {
    /// The originally admitted, distinct Source capacity identity.
    pub original_source_floor: ObjectDigest,
    /// The actual signed original RootPrepared control.
    pub original_root_prepared: ObjectDigest,
    /// The actual original Applying acquisition.
    pub original_applying: ObjectDigest,
    /// The protected, query-independent signed closure archive.
    pub signed_closure_archive: ObjectDigest,
    /// The Source acquisition after its Faulted transition.
    pub faulted_acquisition: ObjectDigest,
    /// The original Source attempt after its Retired transition.
    pub retired_attempt: ObjectDigest,
    /// The original Source session after clearing the pending attempt.
    pub cleared_session: ObjectDigest,
    /// The exact successor of the Source session-history record.
    pub session_history_successor: ObjectDigest,
}

impl PreRequestedNoEscapeDigestsV1 {
    fn ordered(self) -> [ObjectDigest; 8] {
        [
            self.original_source_floor,
            self.original_root_prepared,
            self.original_applying,
            self.signed_closure_archive,
            self.faulted_acquisition,
            self.retired_attempt,
            self.cleared_session,
            self.session_history_successor,
        ]
    }

    fn valid(self) -> bool {
        self.ordered().into_iter().all(nonzero)
    }
}

/// Signs one live query about a distinct, durably closed pre-Requested Source attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedPreRequestedNoEscapeAnswerV1 {
    session_binding: ObjectDigest,
    query_digest: ObjectDigest,
    acquisition_id: ObjectDigest,
    original_signed_request: ObjectDigest,
    original_attempt: ObjectDigest,
    digests: PreRequestedNoEscapeDigestsV1,
    signer: SourceProviderSigningKeyV1,
    signature: SourceProviderSignature,
}

impl SignedPreRequestedNoEscapeAnswerV1 {
    /// Signs only canonical DATA; the caller still owes protected archive readback.
    ///
    /// # Errors
    /// Rejects missing digests, the wrong signer role or authority, or key mismatch.
    pub fn sign(
        query: &RecoveryCurrentnessQueryV1,
        digests: PreRequestedNoEscapeDigestsV1,
        signer: SourceProviderSigningKeyV1,
        signing_key: &SigningKey,
    ) -> Result<Self, PreRequestedRecoveryErrorV1> {
        if !digests.valid()
            || signer.usage() != SourceProviderKeyUsageV1::ProviderOutcome
            || signer.authority_id() != query.authorities().0
        {
            return Err(PreRequestedRecoveryErrorV1::Noncanonical);
        }
        let mut answer = Self {
            session_binding: query.session_binding(),
            query_digest: query.digest(),
            acquisition_id: query.acquisition_id(),
            original_signed_request: query.original_signed_request_digest(),
            original_attempt: query.original_attempt_digest(),
            digests,
            signer,
            signature: SourceProviderSignature::from_bytes([0; 64]),
        };
        answer.signature = sign_bytes(
            ANSWER_SIGNATURE_DOMAIN,
            ANSWER_KIND,
            &answer.subject_bytes(),
            &answer.signer,
            signing_key,
        )?;
        Ok(answer)
    }

    /// Verifies only the given live query and independently supplied signer pin.
    ///
    /// # Errors
    /// Rejects a stale query, wrong role, substituted signer, or invalid signature.
    pub fn verify_for_query(
        &self,
        query: &RecoveryCurrentnessQueryV1,
        expected_signer: &SourceProviderSigningKeyV1,
        public_key: &[u8; 32],
    ) -> Result<(), PreRequestedRecoveryErrorV1> {
        if self.session_binding != query.session_binding()
            || self.query_digest != query.digest()
            || self.acquisition_id != query.acquisition_id()
            || self.original_signed_request != query.original_signed_request_digest()
            || self.original_attempt != query.original_attempt_digest()
            || !self.digests.valid()
            || &self.signer != expected_signer
            || self.signer.usage() != SourceProviderKeyUsageV1::ProviderOutcome
            || self.signer.authority_id() != query.authorities().0
        {
            return Err(PreRequestedRecoveryErrorV1::Stale);
        }
        verify_bytes(
            ANSWER_SIGNATURE_DOMAIN,
            ANSWER_KIND,
            &self.subject_bytes(),
            &self.signer,
            &self.signature,
            public_key,
        )?;
        Ok(())
    }

    /// Returns the exact closed Source record commitments as DATA.
    #[must_use]
    pub const fn digests(&self) -> PreRequestedNoEscapeDigestsV1 {
        self.digests
    }

    /// Commits the exact signed answer bytes for a later Root terminal marker.
    #[must_use]
    pub fn digest(&self) -> ObjectDigest {
        let bytes = self.to_canonical_bytes();
        let mut hasher = Sha256::new();
        hasher.update(ANSWER_DIGEST_DOMAIN);
        hasher.update((bytes.len() as u32).to_be_bytes());
        hasher.update(bytes);
        ObjectDigest::from_bytes(hasher.finalize().into())
    }

    /// Encodes the distinct fixed-width signed answer.
    #[must_use]
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = self.subject_bytes();
        encode_signer(&mut bytes, &self.signer);
        bytes.extend_from_slice(self.signature.as_bytes());
        bytes
    }

    /// Decodes only the exact new answer shape, without asserting journal origin.
    ///
    /// # Errors
    /// Rejects another magic, version, status, size, role, reserved field, or sentinel.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, PreRequestedRecoveryErrorV1> {
        require_header(
            bytes,
            PRE_REQUESTED_NO_ESCAPE_ANSWER_BYTES_V1,
            ANSWER_MAGIC,
            ANSWER_KIND,
        )?;
        if bytes[432] != ANSWER_STATUS || bytes[433..440] != [0; 7] {
            return Err(PreRequestedRecoveryErrorV1::Noncanonical);
        }
        let digests = PreRequestedNoEscapeDigestsV1 {
            original_source_floor: digest_at(bytes, 176)?,
            original_root_prepared: digest_at(bytes, 208)?,
            original_applying: digest_at(bytes, 240)?,
            signed_closure_archive: digest_at(bytes, 272)?,
            faulted_acquisition: digest_at(bytes, 304)?,
            retired_attempt: digest_at(bytes, 336)?,
            cleared_session: digest_at(bytes, 368)?,
            session_history_successor: digest_at(bytes, 400)?,
        };
        let signer = decode_signer(&bytes[440..560])?;
        let answer = Self {
            session_binding: digest_at(bytes, 16)?,
            query_digest: digest_at(bytes, 48)?,
            acquisition_id: digest_at(bytes, 80)?,
            original_signed_request: digest_at(bytes, 112)?,
            original_attempt: digest_at(bytes, 144)?,
            digests,
            signer,
            signature: SourceProviderSignature::from_bytes(array_at(bytes, 560)?),
        };
        if ![
            answer.session_binding,
            answer.query_digest,
            answer.acquisition_id,
            answer.original_signed_request,
            answer.original_attempt,
        ]
        .into_iter()
        .all(nonzero)
            || !answer.digests.valid()
            || answer.signer.usage() != SourceProviderKeyUsageV1::ProviderOutcome
            || answer.to_canonical_bytes() != bytes
        {
            return Err(PreRequestedRecoveryErrorV1::Noncanonical);
        }
        Ok(answer)
    }

    fn subject_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(ANSWER_SUBJECT_BYTES);
        bytes.extend_from_slice(ANSWER_MAGIC);
        bytes.extend_from_slice(&[ANSWER_KIND, VERSION]);
        bytes.extend_from_slice(&[0; 6]);
        for digest in [
            self.session_binding,
            self.query_digest,
            self.acquisition_id,
            self.original_signed_request,
            self.original_attempt,
        ]
        .into_iter()
        .chain(self.digests.ordered())
        {
            bytes.extend_from_slice(digest.as_bytes());
        }
        bytes.push(ANSWER_STATUS);
        bytes.extend_from_slice(&[0; 7]);
        bytes
    }
}

/// Carries a canonical Root record reference without importing RootProtocol.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NoEscapeRecordReferenceV1 {
    /// The exact nonzero canonical record identity.
    pub id: [u8; 32],
    /// The exact positive record revision.
    pub revision: u64,
    /// The digest of the complete canonical record value.
    pub record_digest: [u8; 32],
}

impl NoEscapeRecordReferenceV1 {
    fn valid(self) -> bool {
        self.id != [0; 32] && self.revision != 0 && self.record_digest != [0; 32]
    }

    fn to_bytes(self) -> [u8; 72] {
        let mut bytes = [0; 72];
        bytes[..32].copy_from_slice(&self.id);
        bytes[32..40].copy_from_slice(&self.revision.to_be_bytes());
        bytes[40..].copy_from_slice(&self.record_digest);
        bytes
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, PreRequestedRecoveryErrorV1> {
        let value = Self {
            id: array_at(bytes, 0)?,
            revision: u64::from_be_bytes(array_at(bytes, 32)?),
            record_digest: array_at(bytes, 40)?,
        };
        value
            .valid()
            .then_some(value)
            .ok_or(PreRequestedRecoveryErrorV1::Noncanonical)
    }
}

/// Names one physically committed Root terminal without representing its readback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RootNoEscapeAckFactsV1 {
    /// The current authenticated Root/Provider Session.
    pub current_session: ObjectDigest,
    /// The live recovery query, possibly newer than the accepted answer.
    pub live_query: ObjectDigest,
    /// The answer actually archived by the terminal Root Attempt.
    pub accepted_source_answer: ObjectDigest,
    /// The query-independent signed Source closure archive.
    pub signed_source_archive: ObjectDigest,
    /// The original signed RootPrepared control.
    pub original_root_prepared: ObjectDigest,
    /// The immutable Closed disposition assertion.
    pub closed_disposition: ObjectDigest,
    /// The originally admitted Source capacity identity.
    pub original_source_floor: ObjectDigest,
    /// The retired original Root capacity identity.
    pub retired_root_floor: ObjectDigest,
    /// The retired Root capacity canonical value digest.
    pub retired_root_floor_value: ObjectDigest,
    /// The post-terminal Root sidecar canonical value digest.
    pub terminal_sidecar: ObjectDigest,
    /// The post-terminal Root Head canonical value digest.
    pub terminal_head: ObjectDigest,
    /// The actual Root terminal JournalTransaction identity.
    pub cleanup_transaction: [u8; 16],
    /// The final settled original Mount Attempt reference.
    pub settled_attempt: NoEscapeRecordReferenceV1,
    /// The final Faulted Mount Acquisition reference.
    pub faulted_acquisition: NoEscapeRecordReferenceV1,
}

impl RootNoEscapeAckFactsV1 {
    fn ordered(self) -> [ObjectDigest; 11] {
        [
            self.current_session,
            self.live_query,
            self.accepted_source_answer,
            self.signed_source_archive,
            self.original_root_prepared,
            self.closed_disposition,
            self.original_source_floor,
            self.retired_root_floor,
            self.retired_root_floor_value,
            self.terminal_sidecar,
            self.terminal_head,
        ]
    }

    fn valid(self) -> bool {
        self.ordered().into_iter().all(nonzero)
            && self.cleanup_transaction != [0; 16]
            && self.settled_attempt.valid()
            && matches!(self.settled_attempt.revision, 3 | 4)
            && self.faulted_acquisition.valid()
    }
}

/// Signs a distinct current-Root acknowledgment of one retained terminal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedRootNoEscapeAckV1 {
    facts: RootNoEscapeAckFactsV1,
    signer: SourceProviderSigningKeyV1,
    signature: SourceProviderSignature,
}

impl SignedRootNoEscapeAckV1 {
    /// Borrows the retained signer reference as nonauthorizing DATA.
    #[must_use]
    pub const fn signer(&self) -> &SourceProviderSigningKeyV1 {
        &self.signer
    }

    /// Checks only retained signature equality against an independent role pin.
    ///
    /// This does not establish the actual query, current Session, Root terminal,
    /// protected cut, archive membership or pin retirement.
    ///
    /// # Errors
    ///
    /// Rejects malformed facts, a substituted pin, wrong role or invalid signature.
    pub fn verify_retained_signature_claim(
        &self,
        expected_signer: &SourceProviderSigningKeyV1,
        public_key: &[u8; 32],
    ) -> Result<(), PreRequestedRecoveryErrorV1> {
        if !self.facts.valid()
            || &self.signer != expected_signer
            || expected_signer.usage() != SourceProviderKeyUsageV1::RootMountRecord
        {
            return Err(PreRequestedRecoveryErrorV1::Stale);
        }
        verify_bytes(
            ACK_SIGNATURE_DOMAIN,
            ACK_KIND,
            &self.subject_bytes(),
            &self.signer,
            &self.signature,
            public_key,
        )?;
        Ok(())
    }

    /// Signs only the canonical DATA shape, not a Root readback or current pin.
    ///
    /// # Errors
    /// Rejects malformed facts, query drift, wrong signer role, or key mismatch.
    pub fn sign(
        query: &RecoveryCurrentnessQueryV1,
        facts: RootNoEscapeAckFactsV1,
        signer: SourceProviderSigningKeyV1,
        signing_key: &SigningKey,
    ) -> Result<Self, PreRequestedRecoveryErrorV1> {
        if !facts.valid()
            || facts.current_session != query.session_binding()
            || facts.live_query != query.digest()
            || signer.usage() != SourceProviderKeyUsageV1::RootMountRecord
            || signer.authority_id() != query.authorities().1
        {
            return Err(PreRequestedRecoveryErrorV1::Noncanonical);
        }
        let mut ack = Self {
            facts,
            signer,
            signature: SourceProviderSignature::from_bytes([0; 64]),
        };
        ack.signature = sign_bytes(
            ACK_SIGNATURE_DOMAIN,
            ACK_KIND,
            &ack.subject_bytes(),
            &ack.signer,
            signing_key,
        )?;
        Ok(ack)
    }

    /// Verifies the current query and independently supplied RootMountRecord pin.
    ///
    /// # Errors
    /// Rejects stale session/query, signer substitution, wrong role, or signature.
    pub fn verify_for_query(
        &self,
        query: &RecoveryCurrentnessQueryV1,
        expected_signer: &SourceProviderSigningKeyV1,
        public_key: &[u8; 32],
    ) -> Result<(), PreRequestedRecoveryErrorV1> {
        if !self.facts.valid()
            || self.facts.current_session != query.session_binding()
            || self.facts.live_query != query.digest()
            || &self.signer != expected_signer
            || self.signer.usage() != SourceProviderKeyUsageV1::RootMountRecord
            || self.signer.authority_id() != query.authorities().1
        {
            return Err(PreRequestedRecoveryErrorV1::Stale);
        }
        verify_bytes(
            ACK_SIGNATURE_DOMAIN,
            ACK_KIND,
            &self.subject_bytes(),
            &self.signer,
            &self.signature,
            public_key,
        )?;
        Ok(())
    }

    /// Returns the exact terminal claims as nonauthorizing DATA.
    #[must_use]
    pub const fn facts(&self) -> RootNoEscapeAckFactsV1 {
        self.facts
    }

    /// Encodes the distinct fixed-width signed acknowledgement.
    #[must_use]
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = self.subject_bytes();
        encode_signer(&mut bytes, &self.signer);
        bytes.extend_from_slice(self.signature.as_bytes());
        bytes
    }

    /// Decodes one exact Root acknowledgement without asserting its journal origin.
    ///
    /// # Errors
    /// Rejects another magic, kind, version, size, role, reference, or sentinel.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, PreRequestedRecoveryErrorV1> {
        require_header(bytes, ROOT_NO_ESCAPE_ACK_BYTES_V1, ACK_MAGIC, ACK_KIND)?;
        let facts = RootNoEscapeAckFactsV1 {
            current_session: digest_at(bytes, 16)?,
            live_query: digest_at(bytes, 48)?,
            accepted_source_answer: digest_at(bytes, 80)?,
            signed_source_archive: digest_at(bytes, 112)?,
            original_root_prepared: digest_at(bytes, 144)?,
            closed_disposition: digest_at(bytes, 176)?,
            original_source_floor: digest_at(bytes, 208)?,
            retired_root_floor: digest_at(bytes, 240)?,
            retired_root_floor_value: digest_at(bytes, 272)?,
            terminal_sidecar: digest_at(bytes, 304)?,
            terminal_head: digest_at(bytes, 336)?,
            cleanup_transaction: array_at(bytes, 368)?,
            settled_attempt: NoEscapeRecordReferenceV1::from_bytes(&bytes[384..456])?,
            faulted_acquisition: NoEscapeRecordReferenceV1::from_bytes(&bytes[456..528])?,
        };
        let signer = decode_signer(&bytes[528..648])?;
        let ack = Self {
            facts,
            signer,
            signature: SourceProviderSignature::from_bytes(array_at(bytes, 648)?),
        };
        if !ack.facts.valid()
            || ack.signer.usage() != SourceProviderKeyUsageV1::RootMountRecord
            || ack.to_canonical_bytes() != bytes
        {
            return Err(PreRequestedRecoveryErrorV1::Noncanonical);
        }
        Ok(ack)
    }

    fn subject_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(ACK_SUBJECT_BYTES);
        bytes.extend_from_slice(ACK_MAGIC);
        bytes.extend_from_slice(&[ACK_KIND, VERSION]);
        bytes.extend_from_slice(&[0; 6]);
        for digest in self.facts.ordered() {
            bytes.extend_from_slice(digest.as_bytes());
        }
        bytes.extend_from_slice(&self.facts.cleanup_transaction);
        bytes.extend_from_slice(&self.facts.settled_attempt.to_bytes());
        bytes.extend_from_slice(&self.facts.faulted_acquisition.to_bytes());
        bytes
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;

    use super::*;
    use crate::recovery_currentness::SignedNativeRecoveryUnavailableV1;

    fn digest(byte: u8) -> ObjectDigest {
        ObjectDigest::from_bytes([byte; 32])
    }

    fn query(sequence: u64) -> RecoveryCurrentnessQueryV1 {
        RecoveryCurrentnessQueryV1::new(
            digest(1),
            [2; 32],
            sequence,
            [4; 16],
            [5; 16],
            digest(6),
            digest(7),
            digest(8),
        )
        .unwrap()
    }

    fn signer(
        authority: [u8; 16],
        usage: SourceProviderKeyUsageV1,
        key: &SigningKey,
    ) -> SourceProviderSigningKeyV1 {
        SourceProviderSigningKeyV1::for_signing_key(
            authority,
            10,
            digest(11),
            [12; 16],
            13,
            usage,
            key,
        )
        .unwrap()
    }

    fn closure() -> PreRequestedNoEscapeDigestsV1 {
        PreRequestedNoEscapeDigestsV1 {
            original_source_floor: digest(15),
            original_root_prepared: digest(16),
            original_applying: digest(17),
            signed_closure_archive: digest(18),
            faulted_acquisition: digest(19),
            retired_attempt: digest(20),
            cleared_session: digest(21),
            session_history_successor: digest(22),
        }
    }

    fn reference(id: u8, revision: u64, record: u8) -> NoEscapeRecordReferenceV1 {
        NoEscapeRecordReferenceV1 {
            id: [id; 32],
            revision,
            record_digest: [record; 32],
        }
    }

    fn ack_facts(
        query: &RecoveryCurrentnessQueryV1,
        answer: &SignedPreRequestedNoEscapeAnswerV1,
    ) -> RootNoEscapeAckFactsV1 {
        RootNoEscapeAckFactsV1 {
            current_session: query.session_binding(),
            live_query: query.digest(),
            accepted_source_answer: answer.digest(),
            signed_source_archive: digest(18),
            original_root_prepared: digest(16),
            closed_disposition: digest(23),
            original_source_floor: digest(15),
            retired_root_floor: digest(24),
            retired_root_floor_value: digest(25),
            terminal_sidecar: digest(26),
            terminal_head: digest(27),
            cleanup_transaction: [28; 16],
            settled_attempt: reference(29, 3, 30),
            faulted_acquisition: reference(31, 2, 32),
        }
    }

    fn append_signer_preimage(bytes: &mut Vec<u8>, signer: &SourceProviderSigningKeyV1) {
        bytes.extend_from_slice(&signer.authority_id());
        bytes.extend_from_slice(&signer.authority_generation().to_be_bytes());
        bytes.extend_from_slice(signer.authority_digest().as_bytes());
        bytes.extend_from_slice(&signer.key_id());
        bytes.extend_from_slice(&signer.key_generation().to_be_bytes());
        bytes.extend_from_slice(signer.public_key_digest().as_bytes());
        bytes.push(signer.usage() as u8);
        bytes.extend_from_slice(&[0; 7]);
    }

    fn independent_signature_message(
        domain: &[u8],
        code: u8,
        signer: &SourceProviderSigningKeyV1,
        subject: &[u8],
    ) -> Vec<u8> {
        let mut message = domain.to_vec();
        message.push(code);
        append_signer_preimage(&mut message, signer);
        message.extend_from_slice(&(subject.len() as u32).to_be_bytes());
        message.extend_from_slice(subject);
        message
    }

    #[test]
    fn answer_has_independent_624_byte_preimage_and_live_query_signature() {
        let query = query(3);
        let key = SigningKey::from_bytes(&[9; 32]);
        let signer = signer([4; 16], SourceProviderKeyUsageV1::ProviderOutcome, &key);
        let answer =
            SignedPreRequestedNoEscapeAnswerV1::sign(&query, closure(), signer.clone(), &key)
                .unwrap();
        let wire = answer.to_canonical_bytes();

        let mut expected = b"AOSSPR03\x02\x01\0\0\0\0\0\0".to_vec();
        for digest in [
            query.session_binding(),
            query.digest(),
            query.acquisition_id(),
            query.original_signed_request_digest(),
            query.original_attempt_digest(),
            digest(15),
            digest(16),
            digest(17),
            digest(18),
            digest(19),
            digest(20),
            digest(21),
            digest(22),
        ] {
            expected.extend_from_slice(digest.as_bytes());
        }
        expected.extend_from_slice(&[3, 0, 0, 0, 0, 0, 0, 0]);
        append_signer_preimage(&mut expected, &signer);
        expected.extend_from_slice(answer.signature.as_bytes());

        assert_eq!(wire.len(), 624);
        assert_eq!(wire, expected);
        assert_eq!(&wire[432..440], &[3, 0, 0, 0, 0, 0, 0, 0]);

        let signature = ed25519_dalek::Signature::from_bytes(answer.signature.as_bytes());
        let message = independent_signature_message(
            b"aos-source-provider-pre-requested-no-escape.v1\0",
            2,
            &signer,
            &expected[..440],
        );
        key.verifying_key()
            .verify_strict(&message, &signature)
            .unwrap();
        let wrong_domain = independent_signature_message(
            b"aos.sandbox.mount.pre-requested-no-escape-ack.v1\0",
            2,
            &signer,
            &expected[..440],
        );
        assert!(
            key.verifying_key()
                .verify_strict(&wrong_domain, &signature)
                .is_err()
        );

        let decoded = SignedPreRequestedNoEscapeAnswerV1::from_canonical_bytes(&wire).unwrap();
        assert_eq!(decoded, answer);
        decoded
            .verify_for_query(&query, &signer, key.verifying_key().as_bytes())
            .unwrap();
        assert!(SignedNativeRecoveryUnavailableV1::from_canonical_bytes(&wire).is_err());

        let mut independent_hash = Sha256::new();
        independent_hash.update(b"aos-source-provider-pre-requested-answer-digest.v1\0");
        independent_hash.update(624_u32.to_be_bytes());
        independent_hash.update(&wire);
        let expected_hash: [u8; 32] = independent_hash.finalize().into();
        assert_eq!(answer.digest().as_bytes(), &expected_hash);
    }

    #[test]
    fn answer_rejects_old_flavor_cross_query_and_noncanonical_fields() {
        let original = query(3);
        let changed = query(4);
        let key = SigningKey::from_bytes(&[9; 32]);
        let provider = signer([4; 16], SourceProviderKeyUsageV1::ProviderOutcome, &key);
        let answer =
            SignedPreRequestedNoEscapeAnswerV1::sign(&original, closure(), provider.clone(), &key)
                .unwrap();
        let wire = answer.to_canonical_bytes();
        assert!(
            answer
                .verify_for_query(&changed, &provider, key.verifying_key().as_bytes())
                .is_err()
        );
        assert!(
            SignedPreRequestedNoEscapeAnswerV1::sign(
                &original,
                closure(),
                signer([5; 16], SourceProviderKeyUsageV1::RootMountRecord, &key),
                &key,
            )
            .is_err()
        );

        for (offset, value) in [
            (0, b'X'),
            (8, 1),
            (9, 2),
            (10, 1),
            (432, 2),
            (433, 1),
            (552, 3),
        ] {
            let mut changed = wire.clone();
            changed[offset] = value;
            assert!(SignedPreRequestedNoEscapeAnswerV1::from_canonical_bytes(&changed).is_err());
        }
        assert!(SignedPreRequestedNoEscapeAnswerV1::from_canonical_bytes(&wire[..623]).is_err());
        let mut trailing = wire.clone();
        trailing.push(0);
        assert!(SignedPreRequestedNoEscapeAnswerV1::from_canonical_bytes(&trailing).is_err());
        let mut zero_digest = wire;
        zero_digest[272..304].fill(0);
        assert!(SignedPreRequestedNoEscapeAnswerV1::from_canonical_bytes(&zero_digest).is_err());

        let mut substituted = answer.to_canonical_bytes();
        substituted[272] = 23;
        let substituted =
            SignedPreRequestedNoEscapeAnswerV1::from_canonical_bytes(&substituted).unwrap();
        assert!(
            substituted
                .verify_for_query(&original, &provider, key.verifying_key().as_bytes())
                .is_err()
        );
    }

    #[test]
    fn ack_has_independent_712_byte_preimage_and_distinct_root_role() {
        let query = query(3);
        let provider_key = SigningKey::from_bytes(&[9; 32]);
        let provider = signer(
            [4; 16],
            SourceProviderKeyUsageV1::ProviderOutcome,
            &provider_key,
        );
        let answer =
            SignedPreRequestedNoEscapeAnswerV1::sign(&query, closure(), provider, &provider_key)
                .unwrap();
        let root_key = SigningKey::from_bytes(&[33; 32]);
        let root = signer(
            [5; 16],
            SourceProviderKeyUsageV1::RootMountRecord,
            &root_key,
        );
        let facts = ack_facts(&query, &answer);
        let ack = SignedRootNoEscapeAckV1::sign(&query, facts, root.clone(), &root_key).unwrap();
        let wire = ack.to_canonical_bytes();

        let mut expected = b"AOSRNA01\x01\x01\0\0\0\0\0\0".to_vec();
        for digest in [
            facts.current_session,
            facts.live_query,
            facts.accepted_source_answer,
            facts.signed_source_archive,
            facts.original_root_prepared,
            facts.closed_disposition,
            facts.original_source_floor,
            facts.retired_root_floor,
            facts.retired_root_floor_value,
            facts.terminal_sidecar,
            facts.terminal_head,
        ] {
            expected.extend_from_slice(digest.as_bytes());
        }
        expected.extend_from_slice(&[28; 16]);
        for reference in [facts.settled_attempt, facts.faulted_acquisition] {
            expected.extend_from_slice(&reference.id);
            expected.extend_from_slice(&reference.revision.to_be_bytes());
            expected.extend_from_slice(&reference.record_digest);
        }
        append_signer_preimage(&mut expected, &root);
        expected.extend_from_slice(ack.signature.as_bytes());

        assert_eq!(wire.len(), 712);
        assert_eq!(wire, expected);
        assert_eq!(&wire[416..424], &3_u64.to_be_bytes());

        let signature = ed25519_dalek::Signature::from_bytes(ack.signature.as_bytes());
        let message = independent_signature_message(
            b"aos.sandbox.mount.pre-requested-no-escape-ack.v1\0",
            1,
            &root,
            &expected[..528],
        );
        root_key
            .verifying_key()
            .verify_strict(&message, &signature)
            .unwrap();
        let wrong_domain = independent_signature_message(
            b"aos-source-provider-pre-requested-no-escape.v1\0",
            1,
            &root,
            &expected[..528],
        );
        assert!(
            root_key
                .verifying_key()
                .verify_strict(&wrong_domain, &signature)
                .is_err()
        );

        let decoded = SignedRootNoEscapeAckV1::from_canonical_bytes(&wire).unwrap();
        assert_eq!(decoded.facts(), facts);
        decoded
            .verify_for_query(&query, &root, root_key.verifying_key().as_bytes())
            .unwrap();
        assert!(SignedPreRequestedNoEscapeAnswerV1::from_canonical_bytes(&wire).is_err());
    }

    #[test]
    fn ack_rejects_cross_query_wrong_role_and_corrupt_refs() {
        let original = query(3);
        let changed = query(4);
        let provider_key = SigningKey::from_bytes(&[9; 32]);
        let provider = signer(
            [4; 16],
            SourceProviderKeyUsageV1::ProviderOutcome,
            &provider_key,
        );
        let answer = SignedPreRequestedNoEscapeAnswerV1::sign(
            &original,
            closure(),
            provider.clone(),
            &provider_key,
        )
        .unwrap();
        let root_key = SigningKey::from_bytes(&[33; 32]);
        let root = signer(
            [5; 16],
            SourceProviderKeyUsageV1::RootMountRecord,
            &root_key,
        );
        let facts = ack_facts(&original, &answer);
        let ack = SignedRootNoEscapeAckV1::sign(&original, facts, root.clone(), &root_key).unwrap();
        let wire = ack.to_canonical_bytes();
        assert!(
            ack.verify_for_query(&changed, &root, root_key.verifying_key().as_bytes())
                .is_err()
        );
        assert!(SignedRootNoEscapeAckV1::sign(&original, facts, provider, &provider_key).is_err());
        let mut old_answer = facts;
        old_answer.live_query = changed.digest();
        assert!(
            SignedRootNoEscapeAckV1::sign(&original, old_answer, root.clone(), &root_key).is_err()
        );

        for (offset, value) in [(0, b'X'), (8, 2), (9, 2), (10, 1), (423, 0), (640, 4)] {
            let mut malformed = wire.clone();
            malformed[offset] = value;
            assert!(SignedRootNoEscapeAckV1::from_canonical_bytes(&malformed).is_err());
        }
        let mut zero_answer = wire.clone();
        zero_answer[80..112].fill(0);
        assert!(SignedRootNoEscapeAckV1::from_canonical_bytes(&zero_answer).is_err());
        assert!(SignedRootNoEscapeAckV1::from_canonical_bytes(&wire[..711]).is_err());
        let mut trailing = wire;
        trailing.push(0);
        assert!(SignedRootNoEscapeAckV1::from_canonical_bytes(&trailing).is_err());

        let mut substituted = ack.to_canonical_bytes();
        substituted[112] = 34;
        let substituted = SignedRootNoEscapeAckV1::from_canonical_bytes(&substituted).unwrap();
        assert!(
            substituted
                .verify_for_query(&original, &root, root_key.verifying_key().as_bytes())
                .is_err()
        );
    }

    #[test]
    fn fresh_ack_can_name_an_older_terminal_answer_without_resigning_it() {
        let first = query(3);
        let later = query(4);
        let provider_key = SigningKey::from_bytes(&[9; 32]);
        let provider = signer(
            [4; 16],
            SourceProviderKeyUsageV1::ProviderOutcome,
            &provider_key,
        );
        let accepted =
            SignedPreRequestedNoEscapeAnswerV1::sign(&first, closure(), provider, &provider_key)
                .unwrap();
        let root_key = SigningKey::from_bytes(&[33; 32]);
        let root = signer(
            [5; 16],
            SourceProviderKeyUsageV1::RootMountRecord,
            &root_key,
        );

        let facts = ack_facts(&later, &accepted);
        assert_ne!(facts.live_query, first.digest());
        assert_eq!(facts.accepted_source_answer, accepted.digest());
        let ack = SignedRootNoEscapeAckV1::sign(&later, facts, root.clone(), &root_key).unwrap();
        ack.verify_for_query(&later, &root, root_key.verifying_key().as_bytes())
            .unwrap();
        assert!(
            ack.verify_for_query(&first, &root, root_key.verifying_key().as_bytes())
                .is_err()
        );
    }
}
