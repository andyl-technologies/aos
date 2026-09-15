//! Fixed-root protected boot and paired-clock evidence for environment replay.
//!
//! Provisioning owns the dedicated protected journal and writes exactly one
//! canonical authority record. Runtime callers cannot supply boot or clock
//! scalars to the environment journal claim. This dormant owner instead
//! revalidates the fixed record and its bounded wall-currentness window before
//! minting a singular crate-private claim token.
//!
//! ```text
//! AOSENVA1 || version:u16be || reserved:6 || boot:32 || monotonic:u64be ||
//! authenticated-at:u64be || valid-until:u64be || predecessor-count:u32be ||
//! predecessor-boots[count]:32 || sha256(domain || preceding-bytes):32
//! ```

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use aos_sandbox_core::ObjectDigest;
use sha2::{Digest as _, Sha256};

use crate::journal::{Journal, JournalError, JournalLimits, RecordNamespace, RecoveryReport};
use crate::lifecycle::protected_journal_adapter::ProtectedDomainJournalErrorV1;
use crate::lifecycle::protected_journal_join::ProtectedSourceDomainJournalOwnerV1;

use super::{EnvironmentLeaseTimeV1, EnvironmentProtectedJournalOwnerV1};

const PROTECTED_ENVIRONMENT_EVIDENCE_ROOT: &str = "/var/lib/aos/sandbox/source-evidence";
const PROTECTED_ENVIRONMENT_EVIDENCE_JOURNAL: &str = "environment-authority-v1.journal";
const PROTECTED_ENVIRONMENT_EVIDENCE_KEY: &[u8] = b"environment-claim-v1";
const EVIDENCE_MAGIC: &[u8; 8] = b"AOSENVA1";
const EVIDENCE_VERSION: u16 = 1;
const EVIDENCE_DOMAIN: &[u8] = b"aos.sandbox.environment.fixed-protected-evidence.v1\0";
const MAXIMUM_PREDECESSOR_BOOTS: usize = 262_144;
const FIXED_PREFIX_BYTES: usize = 8 + 2 + 6 + 32 + 8 + 8 + 8 + 4;
const DIGEST_BYTES: usize = 32;

/// Reports fixed-root environment evidence or downstream claim failure.
#[derive(Debug, thiserror::Error)]
pub enum EnvironmentProtectedEvidenceErrorV1 {
    /// The fixed protected evidence journal could not be opened or read.
    #[error(transparent)]
    Journal(#[from] JournalError),
    /// The protected record is malformed, changed, expired, or not yet current.
    #[error("protected environment boot-clock evidence is invalid or not current")]
    InvalidEvidence,
    /// The environment domain journal failed typed claim or replay.
    #[error(transparent)]
    Domain(#[from] ProtectedDomainJournalErrorV1),
}

/// Owns the fixed protected environment boot-clock evidence journal.
pub struct EnvironmentProtectedEvidenceOwnerV1 {
    journal: Journal,
    pinned_record: Vec<u8>,
}

/// Carries one singular fixed-root boot-clock observation into journal claim.
///
/// Construction is private to this fixed-root owner and the token intentionally
/// implements neither `Clone` nor `Copy`.
pub(crate) struct EnvironmentProtectedClaimEvidenceV1 {
    current_boot: ObjectDigest,
    current_time: EnvironmentLeaseTimeV1,
    boot_attestation: ObjectDigest,
    authenticated_predecessor_boots: Vec<ObjectDigest>,
}

impl EnvironmentProtectedClaimEvidenceV1 {
    fn from_decoded(evidence: DecodedEnvironmentEvidenceV1) -> Self {
        Self {
            current_boot: evidence.current_boot,
            current_time: evidence.current_time,
            boot_attestation: evidence.attestation,
            authenticated_predecessor_boots: evidence.predecessor_boots,
        }
    }

    pub(super) fn into_parts(
        self,
    ) -> (
        ObjectDigest,
        EnvironmentLeaseTimeV1,
        ObjectDigest,
        Vec<ObjectDigest>,
    ) {
        (
            self.current_boot,
            self.current_time,
            self.boot_attestation,
            self.authenticated_predecessor_boots,
        )
    }
}

impl EnvironmentProtectedEvidenceOwnerV1 {
    /// Opens and pins the fixed protected environment evidence record.
    ///
    /// # Errors
    ///
    /// Returns [`EnvironmentProtectedEvidenceErrorV1`] unless the dedicated
    /// root is protected and contains exactly one canonical current record.
    pub fn open_fixed_protected()
    -> Result<(Self, RecoveryReport), EnvironmentProtectedEvidenceErrorV1> {
        let (mut journal, report) = Journal::open_protected_at(
            Path::new(PROTECTED_ENVIRONMENT_EVIDENCE_ROOT),
            PROTECTED_ENVIRONMENT_EVIDENCE_JOURNAL,
            environment_evidence_journal_limits(),
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

    /// Claims and fully replays one environment domain journal.
    ///
    /// # Errors
    ///
    /// Returns [`EnvironmentProtectedEvidenceErrorV1`] when fixed evidence is
    /// no longer exact/current or domain replay fails closed.
    pub fn claim_environment<'journal, 'evidence>(
        &'evidence mut self,
        journal_owner: &'journal mut ProtectedSourceDomainJournalOwnerV1,
    ) -> Result<
        EnvironmentProtectedJournalOwnerV1<'journal, 'evidence>,
        EnvironmentProtectedEvidenceErrorV1,
    > {
        let evidence = self.issue_claim_evidence()?;
        let journal = journal_owner.journal();
        Ok(EnvironmentProtectedJournalOwnerV1::claim(
            journal, evidence, self,
        )?)
    }

    pub(crate) fn issue_claim_evidence(
        &mut self,
    ) -> Result<EnvironmentProtectedClaimEvidenceV1, EnvironmentProtectedEvidenceErrorV1> {
        let evidence = self.read_pinned_evidence()?;
        Ok(EnvironmentProtectedClaimEvidenceV1::from_decoded(evidence))
    }

    pub(crate) fn revalidate_pinned(&mut self) -> Result<(), EnvironmentProtectedEvidenceErrorV1> {
        self.read_pinned_evidence().map(drop)
    }

    fn read_pinned_evidence(
        &mut self,
    ) -> Result<DecodedEnvironmentEvidenceV1, EnvironmentProtectedEvidenceErrorV1> {
        let current_record = read_exact_evidence_record(&mut self.journal)?;
        if current_record != self.pinned_record {
            return Err(EnvironmentProtectedEvidenceErrorV1::InvalidEvidence);
        }
        let evidence = decode_evidence(&current_record)?;
        validate_currentness(&evidence)?;
        Ok(evidence)
    }
}

struct DecodedEnvironmentEvidenceV1 {
    current_boot: ObjectDigest,
    current_time: EnvironmentLeaseTimeV1,
    authenticated_at_unix_seconds: u64,
    valid_until_unix_seconds: u64,
    predecessor_boots: Vec<ObjectDigest>,
    attestation: ObjectDigest,
}

fn read_exact_evidence_record(
    journal: &mut Journal,
) -> Result<Vec<u8>, EnvironmentProtectedEvidenceErrorV1> {
    let authority = journal.claim_protected_authority(RecordNamespace::RuntimeAuthority)?;
    let records = authority
        .records()?
        .take(2)
        .map(|(key, value)| (key.to_vec(), value.to_vec()))
        .collect::<Vec<_>>();
    match records.as_slice() {
        [(key, value)] if key.as_slice() == PROTECTED_ENVIRONMENT_EVIDENCE_KEY => Ok(value.clone()),
        _ => Err(EnvironmentProtectedEvidenceErrorV1::InvalidEvidence),
    }
}

fn decode_evidence(
    encoded: &[u8],
) -> Result<DecodedEnvironmentEvidenceV1, EnvironmentProtectedEvidenceErrorV1> {
    if encoded.len() < FIXED_PREFIX_BYTES + DIGEST_BYTES {
        return Err(EnvironmentProtectedEvidenceErrorV1::InvalidEvidence);
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
        return Err(EnvironmentProtectedEvidenceErrorV1::InvalidEvidence);
    }

    let mut cursor = EvidenceCursorV1::new(body);
    if cursor.take::<8>()? != *EVIDENCE_MAGIC
        || u16::from_be_bytes(cursor.take::<2>()?) != EVIDENCE_VERSION
        || cursor.take::<6>()? != [0; 6]
    {
        return Err(EnvironmentProtectedEvidenceErrorV1::InvalidEvidence);
    }
    let current_boot = ObjectDigest::from_bytes(cursor.take::<32>()?);
    let current_time = EnvironmentLeaseTimeV1::new(u64::from_be_bytes(cursor.take::<8>()?))
        .map_err(|_| EnvironmentProtectedEvidenceErrorV1::InvalidEvidence)?;
    let authenticated_at_unix_seconds = u64::from_be_bytes(cursor.take::<8>()?);
    let valid_until_unix_seconds = u64::from_be_bytes(cursor.take::<8>()?);
    let predecessor_count = usize::try_from(u32::from_be_bytes(cursor.take::<4>()?))
        .map_err(|_| EnvironmentProtectedEvidenceErrorV1::InvalidEvidence)?;
    if current_boot.as_bytes() == &[0; 32] || predecessor_count > MAXIMUM_PREDECESSOR_BOOTS {
        return Err(EnvironmentProtectedEvidenceErrorV1::InvalidEvidence);
    }
    let mut predecessor_boots = Vec::new();
    predecessor_boots
        .try_reserve_exact(predecessor_count)
        .map_err(|_| EnvironmentProtectedEvidenceErrorV1::InvalidEvidence)?;
    for _ in 0..predecessor_count {
        predecessor_boots.push(ObjectDigest::from_bytes(cursor.take::<32>()?));
    }
    if !cursor.is_empty()
        || predecessor_boots
            .iter()
            .any(|boot| boot.as_bytes() == &[0; 32] || boot == &current_boot)
        || !predecessor_boots.windows(2).all(|pair| pair[0] < pair[1])
    {
        return Err(EnvironmentProtectedEvidenceErrorV1::InvalidEvidence);
    }
    Ok(DecodedEnvironmentEvidenceV1 {
        current_boot,
        current_time,
        authenticated_at_unix_seconds,
        valid_until_unix_seconds,
        predecessor_boots,
        attestation: expected_digest,
    })
}

fn validate_currentness(
    evidence: &DecodedEnvironmentEvidenceV1,
) -> Result<(), EnvironmentProtectedEvidenceErrorV1> {
    let current = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| EnvironmentProtectedEvidenceErrorV1::InvalidEvidence)?
        .as_secs();
    if evidence.authenticated_at_unix_seconds == 0
        || evidence.valid_until_unix_seconds <= evidence.authenticated_at_unix_seconds
        || current < evidence.authenticated_at_unix_seconds
        || current > evidence.valid_until_unix_seconds
    {
        return Err(EnvironmentProtectedEvidenceErrorV1::InvalidEvidence);
    }
    Ok(())
}

fn environment_evidence_journal_limits() -> JournalLimits {
    let maximum_record_bytes = FIXED_PREFIX_BYTES + MAXIMUM_PREDECESSOR_BOOTS * 32 + DIGEST_BYTES;
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

    fn take<const N: usize>(&mut self) -> Result<[u8; N], EnvironmentProtectedEvidenceErrorV1> {
        let Some((value, remaining)) = self.remaining.split_at_checked(N) else {
            return Err(EnvironmentProtectedEvidenceErrorV1::InvalidEvidence);
        };
        self.remaining = remaining;
        value
            .try_into()
            .map_err(|_| EnvironmentProtectedEvidenceErrorV1::InvalidEvidence)
    }

    const fn is_empty(&self) -> bool {
        self.remaining.is_empty()
    }
}
