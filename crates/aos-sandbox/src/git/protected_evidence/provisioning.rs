//! One-shot administrative publication into the existing Root Git evidence journal.
//!
//! The original normal Root execution and protected PID1 credential jointly
//! admit this writer. Administration supplies accepted commitments; this is
//! not a dynamic fsck attestation, repository permission or backend constructor.
//!
//! ```text
//! AOSGEP01 || version:u16be || zero:6 || predecessor:32 || body-length:u32be ||
//! zero:4 || exact-AOSGITE1[body-length] || sha256(envelope-domain || prefix):32
//! ```

use std::error::Error;
use std::fmt;
use std::path::Path;

use sha2::{Digest as _, Sha256};

use crate::environment::{
    FixedLiveAuthorityClockV1, fixed_live_authority_clock_v1, validate_bracketed_samples_v1,
};
use crate::journal::{Journal, JournalError, JournalRecord, JournalTransaction, RecordNamespace};
use crate::normal_root::{
    ProductionNormalRootStartupV1, RootGitEvidenceCredentialCustodyV1,
    RootGitEvidenceCredentialErrorV1,
};

use super::{
    DecodedGitEvidenceV1, DIGEST_BYTES, FIXED_PREFIX_BYTES,
    GitProtectedEvidenceErrorV1, PROTECTED_GIT_EVIDENCE_JOURNAL,
    PROTECTED_GIT_EVIDENCE_KEY, PROTECTED_GIT_EVIDENCE_ROOT,
    decode_evidence, git_evidence_journal_limits, validate_currentness,
};

const MAGIC: &[u8; 8] = b"AOSGEP01";
const DOMAIN: &[u8] = b"aos.sandbox.git.root-provisioning-envelope.v1\0";
const PREFIX_BYTES: usize = 56;
const MAXIMUM_ISSUER_COUNT: usize = 256;
const MAXIMUM_BODY_BYTES: usize = FIXED_PREFIX_BYTES + 4 * MAXIMUM_ISSUER_COUNT * 32 + DIGEST_BYTES;
const MAXIMUM_ENVELOPE_BYTES: usize = PREFIX_BYTES + MAXIMUM_BODY_BYTES + DIGEST_BYTES;
const MAXIMUM_FRESH_AGE_NANOSECONDS: u64 = 30_000_000_000;

/// Reports installation data, never an authority or currentness token.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RootGitEvidenceProvisioningOutcomeV1 {
    /// No delivery was declared and no fixed credential copy exists.
    Disabled,
    /// The exact canonical successor was already present; no append occurred.
    ///
    /// This can be historical/expired. Existing evidence consumers independently
    /// check currentness before using it.
    ExactAlreadyInstalled,
    /// One exact append was synchronously read back under the original owner.
    VerifiedInstalled,
    /// A commit was attempted but exact durable completion is not established.
    OutcomeUnknown,
}

/// Classifies protected recovery without appending or renewing evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RootGitEvidenceProvisioningRecoveryV1 {
    /// No credential was declared or delivered.
    Disabled,
    /// The exact supplied afterimage is present, possibly historically expired.
    ExactAfterimage,
    /// The exact predecessor or genuinely fresh empty state is still present.
    ExactPredecessor,
}

#[derive(thiserror::Error)]
enum Failure {
    #[error("original administrative Git credential was refused")]
    Credential(#[source] RootGitEvidenceCredentialErrorV1),
    #[error("fixed Git evidence journal failed")]
    Journal(#[source] JournalError),
    #[error("canonical Git evidence was refused")]
    Evidence(#[source] GitProtectedEvidenceErrorV1),
    #[error("original live Git evidence clock failed")]
    Clock(#[source] Box<dyn Error + Send + Sync>),
    #[error("fixed Git evidence predecessor conflicts")]
    Conflict,
    #[error("original Git evidence attempt has ended")]
    Ended,
}

impl fmt::Debug for Failure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GitEvidenceFailure([retained typed cause])")
    }
}

/// Retains the first typed refusal without exposing credential bytes or paths.
pub struct RootGitEvidenceProvisioningErrorV1 {
    cause: Failure,
}

impl fmt::Debug for RootGitEvidenceProvisioningErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RootGitEvidenceProvisioningErrorV1([retained cause])")
    }
}

impl fmt::Display for RootGitEvidenceProvisioningErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("original Root Git evidence provisioning was refused")
    }
}

impl Error for RootGitEvidenceProvisioningErrorV1 {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.cause)
    }
}

impl From<RootGitEvidenceCredentialErrorV1> for Failure {
    fn from(error: RootGitEvidenceCredentialErrorV1) -> Self {
        Self::Credential(error)
    }
}

impl From<JournalError> for Failure {
    fn from(error: JournalError) -> Self {
        Self::Journal(error)
    }
}

impl From<GitProtectedEvidenceErrorV1> for Failure {
    fn from(error: GitProtectedEvidenceErrorV1) -> Self {
        Self::Evidence(error)
    }
}

struct Envelope {
    predecessor: [u8; 32],
    body: Vec<u8>,
    evidence: DecodedGitEvidenceV1,
    transaction_id: [u8; 16],
}

impl Envelope {
    fn decode(bytes: &[u8]) -> Result<Self, Failure> {
        if bytes.len() < PREFIX_BYTES + FIXED_PREFIX_BYTES + 2 * DIGEST_BYTES
            || bytes.len() > MAXIMUM_ENVELOPE_BYTES
            || bytes.get(..8) != Some(MAGIC.as_slice())
            || bytes.get(8..10) != Some(1_u16.to_be_bytes().as_slice())
            || bytes.get(10..16) != Some([0; 6].as_slice())
            || bytes.get(52..56) != Some([0; 4].as_slice())
        {
            return Err(Failure::Conflict);
        }
        let length_bytes: [u8; 4] = bytes.get(48..52).and_then(|value| value.try_into().ok())
            .ok_or(Failure::Conflict)?;
        let length = usize::try_from(u32::from_be_bytes(length_bytes)).map_err(|_| Failure::Conflict)?;
        if length > MAXIMUM_BODY_BYTES
            || PREFIX_BYTES.checked_add(length).and_then(|value| value.checked_add(DIGEST_BYTES)) != Some(bytes.len())
        {
            return Err(Failure::Conflict);
        }
        let split = bytes.len() - DIGEST_BYTES;
        let digest: [u8; 32] = Sha256::new().chain_update(DOMAIN).chain_update(&bytes[..split]).finalize().into();
        if bytes[split..] != digest {
            return Err(Failure::Conflict);
        }

        let body = &bytes[PREFIX_BYTES..split];
        // Preflight the narrower issuer counts before the sole decoder can
        // reserve arrays at its unchanged, larger consumer ceiling.
        for offset in [104, 108, 112, 116] {
            let count: [u8; 4] = body.get(offset..offset + 4)
                .and_then(|value| value.try_into().ok()).ok_or(Failure::Conflict)?;
            if u32::from_be_bytes(count) > MAXIMUM_ISSUER_COUNT as u32 {
                return Err(Failure::Conflict);
            }
        }
        let evidence = decode_evidence(body)?;
        require_duration(&evidence)?;
        let predecessor = bytes[16..48].try_into().map_err(|_| Failure::Conflict)?;
        let transaction_id: [u8; 16] = digest[..16].try_into().map_err(|_| Failure::Conflict)?;
        if transaction_id == [0; 16] {
            return Err(Failure::Conflict);
        }
        Ok(Self {
            predecessor,
            body: body.to_vec(),
            evidence,
            transaction_id,
        })
    }
}

/// Holds one original Root execution, credential and exact journal attempt.
///
/// Construction is infallible, before I/O, through the actual startup owner.
/// This type is not Clone/serde and exposes no FD, bytes, raw journal or proof
/// conversion. A failed attempt never appends again or revives after a recheck.
#[must_use = "retain original credential and journal custody until the attempt ends"]
pub struct RootGitEvidenceProvisioningAttemptV1<'root> {
    credential: RootGitEvidenceCredentialCustodyV1<'root>,
    clock: FixedLiveAuthorityClockV1,
    envelope: Option<Envelope>,
    transaction: Option<JournalTransaction>,
    journal: Option<Journal>,
    preimage: Option<Vec<u8>>,
    observed_afterimage: Option<Vec<u8>>,
    attempted: bool,
    effect_attempted: bool,
    outcome: Option<RootGitEvidenceProvisioningOutcomeV1>,
    error: Option<RootGitEvidenceProvisioningErrorV1>,
}

impl<'root> RootGitEvidenceProvisioningAttemptV1<'root> {
    pub(crate) fn new(root: &'root ProductionNormalRootStartupV1) -> Self {
        Self {
            credential: RootGitEvidenceCredentialCustodyV1::new(root),
            clock: fixed_live_authority_clock_v1(),
            envelope: None,
            transaction: None,
            journal: None,
            preimage: None,
            observed_afterimage: None,
            attempted: false,
            effect_attempted: false,
            outcome: None,
            error: None,
        }
    }

    /// Installs at most one exact predecessor-CAS successor through the sole journal.
    ///
    /// Exact already-installed data need not be currently usable evidence. New
    /// writes require the supplied boot, a 1..300s lifetime and an at-most-30s fresh
    /// monotonic observation. A repeated call does not retry any operation.
    ///
    /// # Errors
    /// Returns the first retained typed refusal on changed original custody,
    /// malformed/expired input, conflict, journal failure or ambiguous readback.
    pub fn install_once(
        &mut self,
    ) -> Result<RootGitEvidenceProvisioningOutcomeV1, &RootGitEvidenceProvisioningErrorV1> {
        if self.attempted {
            return Err(self.error.get_or_insert(RootGitEvidenceProvisioningErrorV1 {
                cause: Failure::Ended,
            }));
        }

        self.attempted = true;
        match self.install() {
            Ok(outcome) => {
                self.outcome = Some(outcome);
                Ok(outcome)
            }
            Err(cause) => {
                if self.effect_attempted {
                    self.outcome = Some(RootGitEvidenceProvisioningOutcomeV1::OutcomeUnknown);
                }
                Err(self.error.insert(RootGitEvidenceProvisioningErrorV1 { cause }))
            }
        }
    }

    /// Reopens only on a fresh original attempt and observes without any append.
    ///
    /// Historical/expired afterimages may settle installation data; they do
    /// not become current evidence. A poisoned in-process attempt retains its
    /// original writer instead of dropping/reopening it to retry a commit.
    ///
    /// # Errors
    /// Returns the retained cause on changed custody, conflict, malformed
    /// canonical state, opening failure, or reuse of an ended attempt.
    pub fn recover_without_installing(
        &mut self,
    ) -> Result<RootGitEvidenceProvisioningRecoveryV1, &RootGitEvidenceProvisioningErrorV1> {
        if self.attempted {
            return Err(self.error.get_or_insert(RootGitEvidenceProvisioningErrorV1 {
                cause: Failure::Ended,
            }));
        }

        self.attempted = true;
        match self.recover() {
            Ok(outcome) => Ok(outcome),
            Err(cause) => Err(self.error.insert(RootGitEvidenceProvisioningErrorV1 { cause })),
        }
    }

    /// Returns installation classification data, including retained ambiguity.
    #[must_use]
    pub const fn outcome(&self) -> Option<RootGitEvidenceProvisioningOutcomeV1> {
        self.outcome
    }

    fn prepare(&mut self) -> Result<bool, Failure> {
        if !self.credential.admit()? {
            return Ok(false);
        }
        self.envelope = Some(Envelope::decode(self.credential.bytes()?)?);
        let envelope = self.envelope.as_ref().ok_or(Failure::Ended)?;
        self.transaction = Some(JournalTransaction::new(
            envelope.transaction_id,
            vec![JournalRecord::put(
                RecordNamespace::RuntimeAuthority,
                PROTECTED_GIT_EVIDENCE_KEY.to_vec(),
                envelope.body.clone(),
            )],
        )?);

        self.credential.recheck()?;
        let (journal, _) = Journal::open_protected_at(
            Path::new(PROTECTED_GIT_EVIDENCE_ROOT),
            PROTECTED_GIT_EVIDENCE_JOURNAL,
            git_evidence_journal_limits(),
        )?;
        // An opener error returned no Journal; do not claim its lower local
        // flock/FD is retained. The original credential and typed cause remain.
        self.journal = Some(journal);
        self.require_journal()?;
        let journal = self.journal.as_mut().ok_or(Failure::Ended)?;
        let authority = journal.claim_protected_authority(RecordNamespace::RuntimeAuthority)?;
        self.preimage = authority.get(PROTECTED_GIT_EVIDENCE_KEY)?.map(<[u8]>::to_vec);
        if let Some(bytes) = &self.preimage {
            decode_evidence(bytes)?;
        }
        self.credential.recheck()?;
        self.require_journal()?;
        Ok(true)
    }

    fn require_journal(&self) -> Result<(), Failure> {
        let journal = self.journal.as_ref().ok_or(Failure::Ended)?;
        journal.require_protected_named_location(
            Path::new(PROTECTED_GIT_EVIDENCE_ROOT),
            PROTECTED_GIT_EVIDENCE_JOURNAL,
            0,
            git_evidence_journal_limits(),
        )?;
        journal.require_fixed_git_evidence_namespace_v1()?;
        Ok(())
    }

    fn predecessor_matches(&self) -> Result<bool, Failure> {
        let envelope = self.envelope.as_ref().ok_or(Failure::Ended)?;
        match &self.preimage {
            Some(bytes) => {
                Ok(decode_evidence(bytes)?.boot_attestation.as_bytes() == &envelope.predecessor)
            }
            None => Ok(envelope.predecessor == [0; 32]),
        }
    }

    fn install(&mut self) -> Result<RootGitEvidenceProvisioningOutcomeV1, Failure> {
        if !self.prepare()? {
            return Ok(RootGitEvidenceProvisioningOutcomeV1::Disabled);
        }
        let envelope = self.envelope.as_ref().ok_or(Failure::Ended)?;
        if self.preimage.as_deref() == Some(envelope.body.as_slice()) {
            return Ok(RootGitEvidenceProvisioningOutcomeV1::ExactAlreadyInstalled);
        }
        if !self.predecessor_matches()? {
            return Err(Failure::Conflict);
        }

        let before = self.clock.sample().map_err(|cause| Failure::Clock(Box::new(cause)))?;
        let envelope = self.envelope.as_ref().ok_or(Failure::Ended)?;
        validate_currentness(&envelope.evidence, before)?;
        require_fresh_age(before.boottime_nanoseconds(), envelope.evidence.current_boottime.get())?;
        self.credential.recheck()?;
        self.require_journal()?;
        let transaction = self.transaction.as_ref().ok_or(Failure::Ended)?;
        let journal = self.journal.as_mut().ok_or(Failure::Ended)?;
        let mut authority = journal.claim_protected_authority(RecordNamespace::RuntimeAuthority)?;
        let preflight = authority.preflight_transactions(std::slice::from_ref(transaction))?;

        // Current originals and the unchanged opaque preflight meet immediately
        // before append. No signed readback or checksum becomes a writer.
        self.credential.recheck()?;
        let effect_sample = self.clock.sample().map_err(|cause| Failure::Clock(Box::new(cause)))?;
        validate_bracketed_samples_v1(before, effect_sample)
            .map_err(|cause| Failure::Clock(Box::new(cause)))?;
        validate_currentness(&envelope.evidence, effect_sample)?;
        require_fresh_age(effect_sample.boottime_nanoseconds(), envelope.evidence.current_boottime.get())?;
        authority.validate_preflight_for_effect(&preflight, std::slice::from_ref(transaction))?;
        self.effect_attempted = true;
        authority.commit(transaction)?;
        self.observed_afterimage = authority.get(PROTECTED_GIT_EVIDENCE_KEY)?.map(<[u8]>::to_vec);
        drop(authority);

        self.credential.recheck()?;
        self.require_journal()?;
        let after = self.clock.sample().map_err(|cause| Failure::Clock(Box::new(cause)))?;
        validate_bracketed_samples_v1(effect_sample, after)
            .map_err(|cause| Failure::Clock(Box::new(cause)))?;
        let envelope = self.envelope.as_ref().ok_or(Failure::Ended)?;
        validate_currentness(&envelope.evidence, after)?;
        if self.observed_afterimage.as_deref() != Some(envelope.body.as_slice()) {
            return Err(Failure::Conflict);
        }
        Ok(RootGitEvidenceProvisioningOutcomeV1::VerifiedInstalled)
    }

    fn recover(&mut self) -> Result<RootGitEvidenceProvisioningRecoveryV1, Failure> {
        if !self.prepare()? {
            return Ok(RootGitEvidenceProvisioningRecoveryV1::Disabled);
        }
        let envelope = self.envelope.as_ref().ok_or(Failure::Ended)?;
        if self.preimage.as_deref() == Some(envelope.body.as_slice()) {
            return Ok(RootGitEvidenceProvisioningRecoveryV1::ExactAfterimage);
        }
        if self.predecessor_matches()? {
            return Ok(RootGitEvidenceProvisioningRecoveryV1::ExactPredecessor);
        }
        Err(Failure::Conflict)
    }
}

fn require_duration(evidence: &DecodedGitEvidenceV1) -> Result<(), Failure> {
    if !matches!(evidence.valid_until_unix_seconds.checked_sub(evidence.authenticated_at_unix_seconds), Some(1..=300)) {
        return Err(Failure::Conflict);
    }
    Ok(())
}

fn require_fresh_age(now: u64, supplied: u64) -> Result<(), Failure> {
    if !matches!(now.checked_sub(supplied), Some(0..=MAXIMUM_FRESH_AGE_NANOSECONDS)) {
        return Err(Failure::Conflict);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn canonical_body() -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(super::super::EVIDENCE_MAGIC);
        body.extend_from_slice(&1_u16.to_be_bytes());
        body.extend_from_slice(&[0; 6]);
        body.extend_from_slice(&[1; 32]);
        body.extend_from_slice(&[2; 32]);
        body.extend_from_slice(&1_u64.to_be_bytes());
        body.extend_from_slice(&1_u64.to_be_bytes());
        body.extend_from_slice(&301_u64.to_be_bytes());
        body.extend_from_slice(&[0; 16]);
        let checksum: [u8; 32] = Sha256::new().chain_update(super::super::EVIDENCE_DOMAIN).chain_update(&body).finalize().into();
        body.extend_from_slice(&checksum);
        body
    }

    fn envelope(body: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&1_u16.to_be_bytes());
        bytes.extend_from_slice(&[0; 6]);
        bytes.extend_from_slice(&[0; 32]);
        bytes.extend_from_slice(&(body.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&[0; 4]);
        bytes.extend_from_slice(body);
        let checksum: [u8; 32] = Sha256::new().chain_update(DOMAIN).chain_update(&bytes).finalize().into();
        bytes.extend_from_slice(&checksum);
        bytes
    }

    #[test]
    fn closed_envelope_reuses_the_existing_canonical_body_decoder() {
        let body = canonical_body();
        let bytes = envelope(&body);

        let decoded = Envelope::decode(&bytes).unwrap();

        assert_eq!(decoded.body, body);
        assert_eq!(decoded.predecessor, [0; 32]);
        assert_ne!(decoded.transaction_id, [0; 16]);
        assert_eq!(MAXIMUM_ENVELOPE_BYTES, 33_008);
    }

    #[test]
    fn structural_changes_never_construct_administrative_authority() {
        let bytes = envelope(&canonical_body());
        for offset in [0, 8, 10, 48, 52, bytes.len() - 1] {
            let mut wrong = bytes.clone();
            wrong[offset] ^= 1;
            assert!(Envelope::decode(&wrong).is_err());
        }
        let mut trailing = bytes;
        trailing.push(0);
        assert!(Envelope::decode(&trailing).is_err());
        assert!(Envelope::decode(&vec![0; MAXIMUM_ENVELOPE_BYTES + 1]).is_err());
    }

    #[test]
    fn issuer_count_is_preflighted_before_consumer_allocation() {
        let mut body = canonical_body();
        body[104..108].copy_from_slice(&257_u32.to_be_bytes());
        assert!(Envelope::decode(&envelope(&body)).is_err());
    }

    #[test]
    fn finite_freshness_math_rejects_future_or_old_samples() {
        assert!(require_fresh_age(30_000_000_001, 1).is_ok());
        assert!(require_fresh_age(30_000_000_002, 1).is_err());
        assert!(require_fresh_age(1, 2).is_err());
    }
}
