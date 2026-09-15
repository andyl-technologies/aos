//! Fixed-root protected boot-clock and validator evidence for Git replay.
//!
//! Provisioning owns this dedicated protected journal. Its singular canonical
//! record binds the validator attestation, every accepted proof commitment,
//! and one bounded boot/monotonic-clock observation. Domain journal callers
//! receive only a one-use crate-private token and cannot substitute scalars.
//!
//! ```text
//! AOSGITE1 || version:u16be || reserved:6 || validator-attestation:32 ||
//! boot:32 || monotonic:u64be || authenticated-at:u64be || valid-until:u64be ||
//! predecessor-count:u32be || graph-count:u32be || ancestry-count:u32be ||
//! validation-report-count:u32be || predecessor-boots[count]:32 ||
//! accepted-graphs[count]:32 || accepted-ancestry[count]:32 ||
//! accepted-validation-reports[count]:32 ||
//! sha256(domain || preceding-bytes):32
//! ```

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use aos_sandbox_core::ObjectDigest;
use sha2::{Digest as _, Sha256};

use crate::journal::{Journal, JournalError, JournalLimits, RecordNamespace, RecoveryReport};
use crate::lifecycle::protected_journal_adapter::ProtectedDomainJournalErrorV1;
use crate::lifecycle::protected_journal_join::ProtectedSourceDomainJournalOwnerV1;

use super::{GitBoottimeV1, GitProtectedJournalOwnerV1};

const PROTECTED_GIT_EVIDENCE_ROOT: &str = "/var/lib/aos/sandbox/source-evidence";
const PROTECTED_GIT_EVIDENCE_JOURNAL: &str = "git-authority-v1.journal";
const PROTECTED_GIT_EVIDENCE_KEY: &[u8] = b"git-claim-v1";
const EVIDENCE_MAGIC: &[u8; 8] = b"AOSGITE1";
const EVIDENCE_VERSION: u16 = 1;
const EVIDENCE_DOMAIN: &[u8] = b"aos.sandbox.git.fixed-protected-evidence.v1\0";
const MAXIMUM_ACCEPTED_EVIDENCE: usize = 262_144;
const FIXED_PREFIX_BYTES: usize = 8 + 2 + 6 + 32 + 32 + 8 + 8 + 8 + 4 * 4;
const DIGEST_BYTES: usize = 32;

/// Reports fixed-root Git evidence or downstream claim failure.
#[derive(Debug, thiserror::Error)]
pub enum GitProtectedEvidenceErrorV1 {
    /// The fixed protected evidence journal could not be opened or read.
    #[error(transparent)]
    Journal(#[from] JournalError),
    /// The protected record is malformed, changed, expired, or not yet current.
    #[error("protected Git validator and boot-clock evidence is invalid or not current")]
    InvalidEvidence,
    /// The Git domain journal failed typed claim or replay.
    #[error(transparent)]
    Domain(#[from] ProtectedDomainJournalErrorV1),
}

/// Owns the fixed protected Git validator and boot-clock evidence journal.
pub struct GitProtectedEvidenceOwnerV1 {
    journal: Journal,
    pinned_record: Vec<u8>,
}

/// Carries one singular fixed-root validator and boot-clock observation.
///
/// Construction is private to this fixed-root owner and the token intentionally
/// implements neither `Clone` nor `Copy`.
pub(crate) struct GitProtectedClaimEvidenceV1 {
    validator_attestation: ObjectDigest,
    current_boot: ObjectDigest,
    current_boottime: GitBoottimeV1,
    boot_attestation: ObjectDigest,
    authenticated_predecessor_boots: Vec<ObjectDigest>,
    accepted_graphs: Vec<ObjectDigest>,
    accepted_ancestry: Vec<ObjectDigest>,
    accepted_validation_reports: Vec<ObjectDigest>,
}

impl GitProtectedClaimEvidenceV1 {
    fn from_decoded(evidence: DecodedGitEvidenceV1) -> Self {
        Self {
            validator_attestation: evidence.validator_attestation,
            current_boot: evidence.current_boot,
            current_boottime: evidence.current_boottime,
            boot_attestation: evidence.boot_attestation,
            authenticated_predecessor_boots: evidence.predecessor_boots,
            accepted_graphs: evidence.accepted_graphs,
            accepted_ancestry: evidence.accepted_ancestry,
            accepted_validation_reports: evidence.accepted_validation_reports,
        }
    }

    #[allow(clippy::type_complexity)]
    pub(super) fn into_parts(
        self,
    ) -> (
        ObjectDigest,
        ObjectDigest,
        GitBoottimeV1,
        ObjectDigest,
        Vec<ObjectDigest>,
        Vec<ObjectDigest>,
        Vec<ObjectDigest>,
        Vec<ObjectDigest>,
    ) {
        (
            self.validator_attestation,
            self.current_boot,
            self.current_boottime,
            self.boot_attestation,
            self.authenticated_predecessor_boots,
            self.accepted_graphs,
            self.accepted_ancestry,
            self.accepted_validation_reports,
        )
    }
}

impl GitProtectedEvidenceOwnerV1 {
    /// Opens and pins the fixed protected Git evidence record.
    ///
    /// # Errors
    ///
    /// Returns [`GitProtectedEvidenceErrorV1`] unless the dedicated protected
    /// root contains exactly one canonical current record.
    pub fn open_fixed_protected() -> Result<(Self, RecoveryReport), GitProtectedEvidenceErrorV1> {
        let (mut journal, report) = Journal::open_protected_at(
            Path::new(PROTECTED_GIT_EVIDENCE_ROOT),
            PROTECTED_GIT_EVIDENCE_JOURNAL,
            git_evidence_journal_limits(),
        )?;
        let pinned_record = read_exact_evidence_record(&mut journal)?;
        let evidence = decode_evidence(&pinned_record)?;
        validate_currentness(&evidence)?;
        Ok((
            Self {
                journal,
                pinned_record,
            },
            report,
        ))
    }

    /// Claims and fully replays one Git domain journal.
    ///
    /// # Errors
    ///
    /// Returns [`GitProtectedEvidenceErrorV1`] when fixed evidence is no
    /// longer exact/current or typed Git replay fails closed.
    pub fn claim_git<'journal, 'evidence>(
        &'evidence mut self,
        journal_owner: &'journal mut ProtectedSourceDomainJournalOwnerV1,
    ) -> Result<GitProtectedJournalOwnerV1<'journal, 'evidence>, GitProtectedEvidenceErrorV1> {
        let evidence = self.issue_claim_evidence()?;
        let journal = journal_owner.journal();
        Ok(GitProtectedJournalOwnerV1::claim(journal, evidence, self)?)
    }

    pub(crate) fn issue_claim_evidence(
        &mut self,
    ) -> Result<GitProtectedClaimEvidenceV1, GitProtectedEvidenceErrorV1> {
        let evidence = self.read_pinned_evidence()?;
        Ok(GitProtectedClaimEvidenceV1::from_decoded(evidence))
    }

    pub(crate) fn revalidate_pinned(&mut self) -> Result<(), GitProtectedEvidenceErrorV1> {
        self.read_pinned_evidence().map(drop)
    }

    fn read_pinned_evidence(
        &mut self,
    ) -> Result<DecodedGitEvidenceV1, GitProtectedEvidenceErrorV1> {
        let current_record = read_exact_evidence_record(&mut self.journal)?;
        if current_record != self.pinned_record {
            return Err(GitProtectedEvidenceErrorV1::InvalidEvidence);
        }
        let evidence = decode_evidence(&current_record)?;
        validate_currentness(&evidence)?;
        Ok(evidence)
    }
}

struct DecodedGitEvidenceV1 {
    validator_attestation: ObjectDigest,
    current_boot: ObjectDigest,
    current_boottime: GitBoottimeV1,
    authenticated_at_unix_seconds: u64,
    valid_until_unix_seconds: u64,
    predecessor_boots: Vec<ObjectDigest>,
    accepted_graphs: Vec<ObjectDigest>,
    accepted_ancestry: Vec<ObjectDigest>,
    accepted_validation_reports: Vec<ObjectDigest>,
    boot_attestation: ObjectDigest,
}

fn read_exact_evidence_record(
    journal: &mut Journal,
) -> Result<Vec<u8>, GitProtectedEvidenceErrorV1> {
    let authority = journal.claim_protected_authority(RecordNamespace::RuntimeAuthority)?;
    let records = authority
        .records()?
        .take(2)
        .map(|(key, value)| (key.to_vec(), value.to_vec()))
        .collect::<Vec<_>>();
    match records.as_slice() {
        [(key, value)] if key.as_slice() == PROTECTED_GIT_EVIDENCE_KEY => Ok(value.clone()),
        _ => Err(GitProtectedEvidenceErrorV1::InvalidEvidence),
    }
}

fn decode_evidence(encoded: &[u8]) -> Result<DecodedGitEvidenceV1, GitProtectedEvidenceErrorV1> {
    if encoded.len() < FIXED_PREFIX_BYTES + DIGEST_BYTES {
        return Err(GitProtectedEvidenceErrorV1::InvalidEvidence);
    }
    let (body, stored_digest) = encoded.split_at(encoded.len() - DIGEST_BYTES);
    let expected_digest = ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(EVIDENCE_DOMAIN)
            .chain_update(body)
            .finalize()
            .into(),
    );
    if stored_digest != expected_digest.as_bytes() {
        return Err(GitProtectedEvidenceErrorV1::InvalidEvidence);
    }

    let mut cursor = EvidenceCursorV1::new(body);
    if cursor.take::<8>()? != *EVIDENCE_MAGIC
        || u16::from_be_bytes(cursor.take::<2>()?) != EVIDENCE_VERSION
        || cursor.take::<6>()? != [0; 6]
    {
        return Err(GitProtectedEvidenceErrorV1::InvalidEvidence);
    }
    let validator_attestation = ObjectDigest::from_bytes(cursor.take::<32>()?);
    let current_boot = ObjectDigest::from_bytes(cursor.take::<32>()?);
    let current_boottime = GitBoottimeV1::new(u64::from_be_bytes(cursor.take::<8>()?))
        .map_err(|_| GitProtectedEvidenceErrorV1::InvalidEvidence)?;
    let authenticated_at_unix_seconds = u64::from_be_bytes(cursor.take::<8>()?);
    let valid_until_unix_seconds = u64::from_be_bytes(cursor.take::<8>()?);
    let predecessor_count = decode_count(&mut cursor)?;
    let graph_count = decode_count(&mut cursor)?;
    let ancestry_count = decode_count(&mut cursor)?;
    let validation_report_count = decode_count(&mut cursor)?;
    if validator_attestation.as_bytes() == &[0; 32] || current_boot.as_bytes() == &[0; 32] {
        return Err(GitProtectedEvidenceErrorV1::InvalidEvidence);
    }
    let predecessor_boots = decode_digest_set(&mut cursor, predecessor_count)?;
    let accepted_graphs = decode_digest_set(&mut cursor, graph_count)?;
    let accepted_ancestry = decode_digest_set(&mut cursor, ancestry_count)?;
    let accepted_validation_reports = decode_digest_set(&mut cursor, validation_report_count)?;
    if !cursor.is_empty() || predecessor_boots.iter().any(|boot| boot == &current_boot) {
        return Err(GitProtectedEvidenceErrorV1::InvalidEvidence);
    }
    Ok(DecodedGitEvidenceV1 {
        validator_attestation,
        current_boot,
        current_boottime,
        authenticated_at_unix_seconds,
        valid_until_unix_seconds,
        predecessor_boots,
        accepted_graphs,
        accepted_ancestry,
        accepted_validation_reports,
        boot_attestation: expected_digest,
    })
}

fn decode_count(cursor: &mut EvidenceCursorV1<'_>) -> Result<usize, GitProtectedEvidenceErrorV1> {
    let count = usize::try_from(u32::from_be_bytes(cursor.take::<4>()?))
        .map_err(|_| GitProtectedEvidenceErrorV1::InvalidEvidence)?;
    if count > MAXIMUM_ACCEPTED_EVIDENCE {
        return Err(GitProtectedEvidenceErrorV1::InvalidEvidence);
    }
    Ok(count)
}

fn decode_digest_set(
    cursor: &mut EvidenceCursorV1<'_>,
    count: usize,
) -> Result<Vec<ObjectDigest>, GitProtectedEvidenceErrorV1> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(count)
        .map_err(|_| GitProtectedEvidenceErrorV1::InvalidEvidence)?;
    for _ in 0..count {
        values.push(ObjectDigest::from_bytes(cursor.take::<32>()?));
    }
    if values.iter().any(|value| value.as_bytes() == &[0; 32])
        || !values.windows(2).all(|pair| pair[0] < pair[1])
    {
        return Err(GitProtectedEvidenceErrorV1::InvalidEvidence);
    }
    Ok(values)
}

fn validate_currentness(
    evidence: &DecodedGitEvidenceV1,
) -> Result<(), GitProtectedEvidenceErrorV1> {
    let current = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| GitProtectedEvidenceErrorV1::InvalidEvidence)?
        .as_secs();
    if evidence.authenticated_at_unix_seconds == 0
        || evidence.valid_until_unix_seconds <= evidence.authenticated_at_unix_seconds
        || current < evidence.authenticated_at_unix_seconds
        || current > evidence.valid_until_unix_seconds
    {
        return Err(GitProtectedEvidenceErrorV1::InvalidEvidence);
    }
    Ok(())
}

fn git_evidence_journal_limits() -> JournalLimits {
    let maximum_record_bytes =
        FIXED_PREFIX_BYTES + MAXIMUM_ACCEPTED_EVIDENCE * 32 * 4 + DIGEST_BYTES;
    JournalLimits {
        maximum_journal_bytes: 4 * 1024 * 1024 * 1024,
        maximum_record_bytes,
        maximum_key_bytes: 64,
        maximum_records_per_transaction: 1,
        maximum_transaction_bytes: maximum_record_bytes + 512,
        maximum_transactions: 4096,
        maximum_materialized_bytes: maximum_record_bytes + 64,
        maximum_materialized_records: 1,
    }
}

struct EvidenceCursorV1<'a> {
    remaining: &'a [u8],
}

impl<'a> EvidenceCursorV1<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }

    fn take<const N: usize>(&mut self) -> Result<[u8; N], GitProtectedEvidenceErrorV1> {
        let Some((value, remaining)) = self.remaining.split_at_checked(N) else {
            return Err(GitProtectedEvidenceErrorV1::InvalidEvidence);
        };
        self.remaining = remaining;
        value
            .try_into()
            .map_err(|_| GitProtectedEvidenceErrorV1::InvalidEvidence)
    }

    const fn is_empty(&self) -> bool {
        self.remaining.is_empty()
    }
}
