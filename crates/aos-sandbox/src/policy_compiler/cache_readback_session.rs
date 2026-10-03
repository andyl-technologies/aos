//! Durable, nonauthorizing root challenge for a Cache-owner readback.
//!
//! A protected root writer spends an epoch before exposing its fresh challenge.
//! The returned observation proves only that the pinned Cache-purpose key
//! signed the exact challenge. It does not independently prove Controller,
//! source-domain, protected Cache quota, or physical flock currentness and
//! cannot be consumed as an AOSPCB02 or public Create authority.
//!
//! ```text
//! AOSCRH01 | epoch:u64 | nonce:16 | root-source-cut:32 |
//! SHA-256(challenge-record-domain || preceding 64 bytes):32
//! ```
//!
//! V2 signer challenges use a separate `AOSCRH02` record/key so legacy V1
//! diagnostic sessions cannot strand or consume the V2 settlement lifecycle.

use std::io;
use std::path::Path;

use aos_sandbox_core::ObjectDigest;
use ed25519_dalek::VerifyingKey;
use sha2::{Digest as _, Sha256};

use crate::cache_residency::{
    CacheOwnerReadbackChallengeV1, CacheOwnerReadbackErrorV1, PinnedCacheOwnerReadbackSignerV1,
    VerifiedClosedCacheOwnerReadbackV1, VerifiedClosedCacheOwnerReadbackV2,
    verify_closed_cache_owner_readback_v1, verify_closed_cache_owner_readback_v2,
};
use crate::journal::{Journal, JournalError, ProtectedJournalAuthority, RecordNamespace};

use super::cache_readback_pin::CACHE_PIN_KEY;
use super::cache_root_settlement::{
    CacheRootSettlementV2, SETTLEMENT_ARCHIVE_WINDOW, SETTLEMENT_KEY, archive_key,
};
use super::deployment_head::{
    HEAD_KEY, PROJECT_HEAD_KEY, PROJECT_INPUT_KEY, SIGNER_PINS_KEY, encode_policy_signer_pins_v1,
};
use super::project_source_v2::{HEAD_KEY_V2, INPUT_KEY_V2};
use super::protected_owner::{
    POLICY_AUTHORITY_JOURNAL, PROTECTED_POLICY_ROOT, policy_authority_journal_limits,
};
use super::root_challenge_record::{RECORD_BYTES, RootChallengeRecordCodec};

const CHALLENGE_KEY_V1: &[u8] = b"\0aos-policy-cache-readback-challenge-v1\0";
const CHALLENGE_KEY_V2: &[u8] = b"\0aos-policy-cache-signer-challenge-v2\0";
const MAGIC_V1: &[u8; 8] = b"AOSCRH01";
const MAGIC_V2: &[u8; 8] = b"AOSCRH02";
const CUT_DOMAIN: &[u8] = b"aos.sandbox.policy-cache-readback-root-source-cut.v1\0";
const SIGNER_CUT_DOMAIN_V2: &[u8] = b"aos.sandbox.policy-cache-signer-root-source-cut.v2\0";
const RECORD_DOMAIN_V1: &[u8] = b"aos.sandbox.policy-cache-readback-challenge-record.v1\0";
const TRANSACTION_DOMAIN_V1: &[u8] =
    b"aos.sandbox.policy-cache-readback-challenge-transaction.v1\0";
const RECORD_DOMAIN_V2: &[u8] = b"aos.sandbox.policy-cache-signer-challenge-record.v2\0";
const TRANSACTION_DOMAIN_V2: &[u8] = b"aos.sandbox.policy-cache-signer-challenge-transaction.v2\0";
const CODEC_V1: RootChallengeRecordCodec = RootChallengeRecordCodec::new(
    MAGIC_V1,
    RECORD_DOMAIN_V1,
    TRANSACTION_DOMAIN_V1,
    CHALLENGE_KEY_V1,
);
const CODEC_V2: RootChallengeRecordCodec = RootChallengeRecordCodec::new(
    MAGIC_V2,
    RECORD_DOMAIN_V2,
    TRANSACTION_DOMAIN_V2,
    CHALLENGE_KEY_V2,
);

#[derive(Clone, Copy)]
struct CacheRootSourceExpectation<'a> {
    deployment_head: &'a [u8],
    project_head: &'a [u8],
    project_input: &'a [u8],
    cache_credential: &'a [u8],
    deployment_generation: u64,
    deployment_key: &'a VerifyingKey,
    project_generation: u64,
    project_key: &'a VerifyingKey,
    owner_uid: u32,
}

/// Reports a rejected closed root/Cache readback exchange.
#[derive(Debug, thiserror::Error)]
pub enum ClosedCacheReadbackSessionErrorV1 {
    /// The fixed root signer, signed source, or challenge epoch is not current.
    #[error("closed Cache readback root source or challenge is stale")]
    Stale,
    /// Root entropy failed or produced an invalid nonce.
    #[error("closed Cache readback root nonce is invalid")]
    Nonce,
    /// Protected root journal replay or durable challenge commit failed.
    #[error(transparent)]
    Journal(#[from] JournalError),
    /// The fixed Cache credential or signed packet is invalid.
    #[error(transparent)]
    Readback(#[from] CacheOwnerReadbackErrorV1),
    /// The local Controller exchange failed while the root writer was held.
    #[error(transparent)]
    Transport(#[from] io::Error),
}

/// Carries one spent root challenge without granting publication authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClosedCacheReadbackRootChallengeV1 {
    readback: CacheOwnerReadbackChallengeV1,
    epoch: u64,
}

impl ClosedCacheReadbackRootChallengeV1 {
    /// Returns the nonce and root-source cut that the physical owner must sign.
    #[must_use]
    pub const fn readback(self) -> CacheOwnerReadbackChallengeV1 {
        self.readback
    }

    /// Returns the durable, spent root challenge epoch.
    #[must_use]
    pub const fn epoch(self) -> u64 {
        self.epoch
    }
}

/// Reports signature verification under one spent root challenge.
///
/// This is evidence only, never a policy binding or effect token.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClosedCacheReadbackRootObservationV1 {
    readback: VerifiedClosedCacheOwnerReadbackV1,
    packet_digest: ObjectDigest,
    epoch: u64,
}

impl ClosedCacheReadbackRootObservationV1 {
    /// Returns the verified but nonauthorizing Cache-owner statement.
    #[must_use]
    pub const fn readback(self) -> VerifiedClosedCacheOwnerReadbackV1 {
        self.readback
    }

    /// Returns the exact response packet digest for transport acknowledgement.
    #[must_use]
    pub const fn packet_digest(self) -> ObjectDigest {
        self.packet_digest
    }

    /// Returns the consumed root challenge epoch.
    #[must_use]
    pub const fn epoch(self) -> u64 {
        self.epoch
    }
}

/// Carries a durably spent Cache-only signer challenge after Root releases its writer.
///
/// This token is only a nonauthorizing challenge. Its later verification must
/// reacquire Root last, after Controller, Source, and Cache owner custody.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StagedCacheSignerRootChallengeV2 {
    readback: CacheOwnerReadbackChallengeV1,
    epoch: u64,
}

/// Classifies only the Root journal's exact nonauthorizing packet settlement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CacheSignerRootSettlementStateV2 {
    /// This challenge has not been settled by Root.
    Unrecorded,
    /// Root durably recorded the exact signed packet for this challenge.
    Recorded,
}

/// Describes the latest V2 signer challenge under cold Root custody.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CacheSignerRootChallengeStatusV2 {
    /// No exact packet or abandonment has settled this challenge.
    Pending,
    /// Root durably revoked the challenge without a signed packet.
    Abandoned,
    /// Root durably retained the exact signed packet digest.
    Recorded(ObjectDigest),
}

/// Pairs the latest spent challenge with its protected settlement status.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CacheSignerRootChallengeReadbackV2 {
    challenge: StagedCacheSignerRootChallengeV2,
    status: CacheSignerRootChallengeStatusV2,
}

impl CacheSignerRootChallengeReadbackV2 {
    /// Returns the exact challenge required for recovery or abandonment.
    #[must_use]
    pub const fn challenge(self) -> StagedCacheSignerRootChallengeV2 {
        self.challenge
    }

    /// Returns the latest Root journal's exact resolution.
    #[must_use]
    pub const fn status(self) -> CacheSignerRootChallengeStatusV2 {
        self.status
    }
}

impl StagedCacheSignerRootChallengeV2 {
    /// Returns the exact nonce and root-source cut for both signer peers.
    #[must_use]
    pub const fn readback(self) -> CacheOwnerReadbackChallengeV1 {
        self.readback
    }

    /// Returns the durably spent root epoch.
    #[must_use]
    pub const fn epoch(self) -> u64 {
        self.epoch
    }
}

/// Reads the latest V2 signer challenge after reopening the fixed Root journal.
///
/// This is historical Root custody, never a Controller/Cache held cut or an
/// effect capability. An operator may use an exact pending readback to revoke
/// a challenge stranded by process death.
///
/// # Errors
///
/// Rejects a changed named journal, malformed challenge or settlement, or
/// unavailable protected Root custody.
pub fn read_fixed_cache_signer_challenge_v2()
-> Result<Option<CacheSignerRootChallengeReadbackV2>, ClosedCacheReadbackSessionErrorV1> {
    with_existing_fixed_cache_signer_root_journal_v2(read_cache_signer_challenge_in_journal_v2)
}

/// Compacts settled Root journal history under exclusive protected custody.
///
/// This is root-only maintenance after stopping the authority service. It
/// retains the latest challenge and bounded settlement window, but cannot run
/// while a V2 challenge is pending or a closed policy hold forbids compaction.
///
/// # Errors
///
/// Rejects a pending challenge, held policy cut, changed named journal, or an
/// ambiguous protected compaction.
pub fn compact_fixed_cache_signer_root_journal_v2() -> Result<(), ClosedCacheReadbackSessionErrorV1>
{
    with_existing_fixed_cache_signer_root_journal_v2(compact_cache_signer_root_journal_v2)
}

/// Recovers Root's recent exact V2 packet settlement without currentness.
///
/// A recorded result proves only protected Root journal history. An unrecorded
/// result means the named challenge is still pending, not that its packet is
/// valid or eligible for a new effect. This method never reopens owner custody.
///
/// # Errors
///
/// Rejects a malformed challenge, changed named journal, ambiguous settlement,
/// abandoned or retired epoch, or a packet different from the archived one.
pub fn recover_fixed_cache_signer_root_history_v2(
    epoch: u64,
    nonce: [u8; 16],
    cut: ObjectDigest,
    packet: &[u8],
) -> Result<CacheSignerRootSettlementStateV2, ClosedCacheReadbackSessionErrorV1> {
    if epoch == 0 || packet.is_empty() {
        return Err(ClosedCacheReadbackSessionErrorV1::Stale);
    }
    let challenge = StagedCacheSignerRootChallengeV2 {
        readback: CacheOwnerReadbackChallengeV1::new(nonce, cut)?,
        epoch,
    };
    with_existing_fixed_cache_signer_root_journal_v2(|journal| {
        recover_cache_signer_root_history_in_journal_v2(journal, challenge, packet)
    })
}

/// Spends a signer challenge under Root's writer, then releases that writer.
///
/// The caller must acquire Controller, Source, protected Cache, and physical
/// Cache custody only after this function returns. No receipt or effect is
/// authorized by spending the challenge. A prior epoch must be explicitly
/// recorded or abandoned first. Per-epoch Root custody preserves exact
/// historical settlement recovery within the latest 1,024 settled epochs. An older
/// query fails closed; a future live effect path needs its own recovery fence.
///
/// # Errors
///
/// Rejects changed root sources or pins, malformed prior challenge state,
/// unavailable entropy, or a failed protected commit and named readback.
#[allow(clippy::too_many_arguments)]
pub fn stage_fixed_cache_signer_challenge_v2(
    expected_deployment_head: &[u8],
    expected_project_head: &[u8],
    expected_project_input: &[u8],
    cache_credential: &[u8],
    deployment_generation: u64,
    deployment_key: &VerifyingKey,
    project_generation: u64,
    project_key: &VerifyingKey,
    expected_owner_uid: u32,
    fresh_root_nonce: impl FnOnce() -> io::Result<[u8; 16]>,
) -> Result<StagedCacheSignerRootChallengeV2, ClosedCacheReadbackSessionErrorV1> {
    let expected = CacheRootSourceExpectation {
        deployment_head: expected_deployment_head,
        project_head: expected_project_head,
        project_input: expected_project_input,
        cache_credential,
        deployment_generation,
        deployment_key,
        project_generation,
        project_key,
        owner_uid: expected_owner_uid,
    };
    with_existing_fixed_cache_signer_root_journal_v2(|journal| {
        stage_cache_signer_challenge_in_journal_v2(journal, expected, fresh_root_nonce)
    })
}

/// Verifies a V2 packet against the still-current spent Root challenge.
///
/// This reopens Root only after challenge spending released its writer. If
/// called after the Cache callback returns, the result is diagnostic rather
/// than a held cut. A future all-owner path must retain earlier owners while
/// reacquiring Root last, then consume and fence the record under a recoverable
/// CAS. This function does none of that and cannot authorize Q04/Create.
///
/// # Errors
///
/// Rejects a changed root source, pin, challenge, named journal, owner UID,
/// signer generation, nonce, cut, or signature.
#[allow(clippy::too_many_arguments)]
pub fn verify_fixed_staged_cache_signer_packet_v2(
    challenge: StagedCacheSignerRootChallengeV2,
    packet: &[u8],
    expected_deployment_head: &[u8],
    expected_project_head: &[u8],
    expected_project_input: &[u8],
    cache_credential: &[u8],
    deployment_generation: u64,
    deployment_key: &VerifyingKey,
    project_generation: u64,
    project_key: &VerifyingKey,
    expected_owner_uid: u32,
) -> Result<VerifiedClosedCacheOwnerReadbackV2, ClosedCacheReadbackSessionErrorV1> {
    let expected = CacheRootSourceExpectation {
        deployment_head: expected_deployment_head,
        project_head: expected_project_head,
        project_input: expected_project_input,
        cache_credential,
        deployment_generation,
        deployment_key,
        project_generation,
        project_key,
        owner_uid: expected_owner_uid,
    };
    with_existing_fixed_cache_signer_root_journal_v2(|journal| {
        verify_staged_cache_signer_packet_in_journal_v2(journal, challenge, packet, expected)
    })
}

/// Records one exact signed V2 packet under the still-current Root challenge.
///
/// This compare-and-swap is single-use for an epoch. A failed or ambiguous
/// commit can be examined by [`recover_fixed_cache_signer_root_settlement_v2`]
/// after cold reopen. Neither a successful record nor recovery is effect
/// authority: the future caller must retain Controller, Source, and Cache
/// custody before taking Root last, then separately settle the effect.
///
/// # Errors
///
/// Rejects a stale or already-settled challenge, changed Root source or pin,
/// malformed prior settlement, invalid signature or UID, journal failure, or
/// changed named journal location.
#[allow(clippy::too_many_arguments)]
pub fn record_fixed_cache_signer_root_settlement_v2(
    challenge: StagedCacheSignerRootChallengeV2,
    packet: &[u8],
    expected_deployment_head: &[u8],
    expected_project_head: &[u8],
    expected_project_input: &[u8],
    cache_credential: &[u8],
    deployment_generation: u64,
    deployment_key: &VerifyingKey,
    project_generation: u64,
    project_key: &VerifyingKey,
    expected_owner_uid: u32,
) -> Result<(), ClosedCacheReadbackSessionErrorV1> {
    let expected = CacheRootSourceExpectation {
        deployment_head: expected_deployment_head,
        project_head: expected_project_head,
        project_input: expected_project_input,
        cache_credential,
        deployment_generation,
        deployment_key,
        project_generation,
        project_key,
        owner_uid: expected_owner_uid,
    };
    with_existing_fixed_cache_signer_root_journal_v2(|journal| {
        record_cache_signer_root_settlement_in_journal_v2(journal, challenge, packet, expected)
    })
}

/// Durably abandons one failed signer challenge without authorizing an effect.
///
/// This is the only way to issue another nonce after a challenge with no
/// signed response. An already-recorded packet cannot be replaced by an
/// abandonment. A failed commit remains indeterminate until cold replay.
///
/// # Errors
///
/// Rejects a superseded or already-settled challenge, malformed prior state,
/// a failed protected commit, or a changed named journal location.
pub fn abandon_fixed_cache_signer_challenge_v2(
    challenge: StagedCacheSignerRootChallengeV2,
) -> Result<(), ClosedCacheReadbackSessionErrorV1> {
    with_existing_fixed_cache_signer_root_journal_v2(|journal| {
        abandon_cache_signer_challenge_in_journal_v2(journal, challenge)
    })
}

/// Replays one exact Root abandonment after an ambiguous revocation commit.
///
/// Returns `true` only for the durably abandoned current challenge, `false`
/// when no resolution was committed. A different packet settlement or a
/// superseded epoch is stale. Journal replay errors remain indeterminate.
///
/// # Errors
///
/// Rejects a changed named journal, malformed resolution, a superseded
/// challenge, or an exact epoch settled with a signed packet instead.
pub fn recover_fixed_cache_signer_abandonment_v2(
    challenge: StagedCacheSignerRootChallengeV2,
) -> Result<bool, ClosedCacheReadbackSessionErrorV1> {
    with_existing_fixed_cache_signer_root_journal_v2(|journal| {
        recover_cache_signer_abandonment_in_journal_v2(journal, challenge)
    })
}

fn with_existing_fixed_cache_signer_root_journal_v2<T>(
    action: impl FnOnce(&mut Journal) -> Result<T, ClosedCacheReadbackSessionErrorV1>,
) -> Result<T, ClosedCacheReadbackSessionErrorV1> {
    let root = Path::new(PROTECTED_POLICY_ROOT);
    let limits = policy_authority_journal_limits();
    // V2 never initializes authority custody: deployment setup must already
    // have established the protected Root journal and its lock.
    let (mut journal, _) =
        Journal::open_existing_protected_at(root, POLICY_AUTHORITY_JOURNAL, limits)?;
    journal.require_protected_named_location(root, POLICY_AUTHORITY_JOURNAL, 0, limits)?;
    let result = action(&mut journal);
    journal.require_protected_named_location(root, POLICY_AUTHORITY_JOURNAL, 0, limits)?;
    result
}

/// Replays Root's exact packet settlement after an ambiguous commit.
///
/// `Recorded` only reports durable Root bytes. It is not a receipt for a
/// Controller/Source/Cache held cut or an effect authorization. A different
/// packet settled at this epoch is rejected. The bounded protected archive
/// retains exact recovery for the latest 1,024 settled epochs.
///
/// # Errors
///
/// Rejects a foreign packet, malformed protected archive, or stale current
/// source when no settlement has yet been recorded.
#[allow(clippy::too_many_arguments)]
pub fn recover_fixed_cache_signer_root_settlement_v2(
    challenge: StagedCacheSignerRootChallengeV2,
    packet: &[u8],
    expected_deployment_head: &[u8],
    expected_project_head: &[u8],
    expected_project_input: &[u8],
    cache_credential: &[u8],
    deployment_generation: u64,
    deployment_key: &VerifyingKey,
    project_generation: u64,
    project_key: &VerifyingKey,
    expected_owner_uid: u32,
) -> Result<CacheSignerRootSettlementStateV2, ClosedCacheReadbackSessionErrorV1> {
    let expected = CacheRootSourceExpectation {
        deployment_head: expected_deployment_head,
        project_head: expected_project_head,
        project_input: expected_project_input,
        cache_credential,
        deployment_generation,
        deployment_key,
        project_generation,
        project_key,
        owner_uid: expected_owner_uid,
    };
    with_existing_fixed_cache_signer_root_journal_v2(|journal| {
        recover_cache_signer_root_settlement_in_journal_v2(journal, challenge, packet, expected)
    })
}

/// Spends a fresh root challenge and verifies one Cache-purpose signature.
///
/// Production passes only its fixed deployment credentials and generates the
/// nonce inside `fresh_root_nonce` while this function holds the root writer.
/// The cut covers root-authenticated source records only. The Controller,
/// source-domain, protected Cache, and physical Cache owners are not joined
/// here; successful verification cannot authorize Q04 or Create.
///
/// # Errors
///
/// Rejects missing or changed signer pins and signed source records, malformed
/// prior epochs, unavailable entropy, failed journal commit/readback, transport
/// loss, stale challenge, or an invalid Cache-purpose signature.
#[allow(clippy::too_many_arguments)]
pub fn with_fixed_closed_cache_readback_session_v1(
    expected_deployment_head: &[u8],
    expected_project_head: &[u8],
    expected_project_input: &[u8],
    cache_credential: &[u8],
    deployment_generation: u64,
    deployment_key: &VerifyingKey,
    project_generation: u64,
    project_key: &VerifyingKey,
    expected_owner_uid: u32,
    fresh_root_nonce: impl FnOnce() -> io::Result<[u8; 16]>,
    exchange: impl FnOnce(ClosedCacheReadbackRootChallengeV1) -> io::Result<Vec<u8>>,
) -> Result<ClosedCacheReadbackRootObservationV1, ClosedCacheReadbackSessionErrorV1> {
    let (mut journal, _) = Journal::open_protected_at(
        Path::new(PROTECTED_POLICY_ROOT),
        POLICY_AUTHORITY_JOURNAL,
        policy_authority_journal_limits(),
    )?;
    with_closed_cache_readback_session_in_journal_v1(
        &mut journal,
        expected_deployment_head,
        expected_project_head,
        expected_project_input,
        cache_credential,
        deployment_generation,
        deployment_key,
        project_generation,
        project_key,
        expected_owner_uid,
        fresh_root_nonce,
        exchange,
    )
}

#[allow(clippy::too_many_arguments)]
fn with_closed_cache_readback_session_in_journal_v1(
    journal: &mut Journal,
    expected_deployment_head: &[u8],
    expected_project_head: &[u8],
    expected_project_input: &[u8],
    cache_credential: &[u8],
    deployment_generation: u64,
    deployment_key: &VerifyingKey,
    project_generation: u64,
    project_key: &VerifyingKey,
    expected_owner_uid: u32,
    fresh_root_nonce: impl FnOnce() -> io::Result<[u8; 16]>,
    exchange: impl FnOnce(ClosedCacheReadbackRootChallengeV1) -> io::Result<Vec<u8>>,
) -> Result<ClosedCacheReadbackRootObservationV1, ClosedCacheReadbackSessionErrorV1> {
    let expected = CacheRootSourceExpectation {
        deployment_head: expected_deployment_head,
        project_head: expected_project_head,
        project_input: expected_project_input,
        cache_credential,
        deployment_generation,
        deployment_key,
        project_generation,
        project_key,
        owner_uid: expected_owner_uid,
    };
    let mut authority = journal.claim_protected_authority(RecordNamespace::DesiredState)?;
    let (signer, challenge, record) = spend_cache_root_challenge(
        &mut authority,
        expected,
        &CODEC_V1,
        CHALLENGE_KEY_V1,
        fresh_root_nonce,
        |expected, epoch| cache_root_cut(CUT_DOMAIN, expected, epoch),
    )?;

    let packet = exchange(ClosedCacheReadbackRootChallengeV1 {
        readback: challenge.readback,
        epoch: challenge.epoch,
    })?;
    let verified = verify_closed_cache_owner_readback_v1(
        &packet,
        &signer,
        challenge.readback,
        expected_owner_uid,
    )?;
    if authority.get(CHALLENGE_KEY_V1)? != Some(record.as_slice())
        || authority.get(CACHE_PIN_KEY)? != Some(cache_credential)
    {
        return Err(ClosedCacheReadbackSessionErrorV1::Stale);
    }
    Ok(ClosedCacheReadbackRootObservationV1 {
        readback: verified,
        packet_digest: ObjectDigest::from_bytes(Sha256::digest(packet).into()),
        epoch: challenge.epoch,
    })
}

fn stage_cache_signer_challenge_in_journal_v2(
    journal: &mut Journal,
    expected: CacheRootSourceExpectation<'_>,
    fresh_root_nonce: impl FnOnce() -> io::Result<[u8; 16]>,
) -> Result<StagedCacheSignerRootChallengeV2, ClosedCacheReadbackSessionErrorV1> {
    let mut authority = journal.claim_protected_authority(RecordNamespace::DesiredState)?;
    let settlement = require_consistent_cache_root_settlement_v2(&authority)?;
    let (prior_epoch, _) = CODEC_V2
        .read_prior(authority.get(CHALLENGE_KEY_V2)?)
        .ok_or(ClosedCacheReadbackSessionErrorV1::Stale)?;
    if prior_epoch != 0 && settlement.is_none_or(|record| record.epoch != prior_epoch) {
        return Err(ClosedCacheReadbackSessionErrorV1::Stale);
    }
    let (_, challenge, _) = spend_cache_root_challenge(
        &mut authority,
        expected,
        &CODEC_V2,
        CHALLENGE_KEY_V2,
        fresh_root_nonce,
        cache_signer_root_cut_v2,
    )?;
    require_consistent_cache_root_settlement_v2(&authority)?;
    Ok(challenge)
}

fn read_cache_signer_challenge_in_journal_v2(
    journal: &mut Journal,
) -> Result<Option<CacheSignerRootChallengeReadbackV2>, ClosedCacheReadbackSessionErrorV1> {
    let authority = journal.claim_protected_authority(RecordNamespace::DesiredState)?;
    let challenge_record = authority.get(CHALLENGE_KEY_V2)?;
    let (epoch, nonce) = CODEC_V2
        .read_prior(challenge_record)
        .ok_or(ClosedCacheReadbackSessionErrorV1::Stale)?;
    let settlement = require_consistent_cache_root_settlement_v2(&authority)?;
    let Some(record) = challenge_record else {
        return Ok(None);
    };

    let cut_bytes = record[32..64]
        .try_into()
        .map_err(|_| ClosedCacheReadbackSessionErrorV1::Stale)?;
    let cut = ObjectDigest::from_bytes(cut_bytes);
    let challenge = StagedCacheSignerRootChallengeV2 {
        readback: CacheOwnerReadbackChallengeV1::new(nonce, cut)?,
        epoch,
    };
    let status = match settlement {
        Some(record) if record.epoch == epoch && record.abandoned() => {
            CacheSignerRootChallengeStatusV2::Abandoned
        }
        Some(record) if record.epoch == epoch => {
            CacheSignerRootChallengeStatusV2::Recorded(record.packet_digest)
        }
        _ => CacheSignerRootChallengeStatusV2::Pending,
    };

    Ok(Some(CacheSignerRootChallengeReadbackV2 {
        challenge,
        status,
    }))
}

fn compact_cache_signer_root_journal_v2(
    journal: &mut Journal,
) -> Result<(), ClosedCacheReadbackSessionErrorV1> {
    if read_cache_signer_challenge_in_journal_v2(journal)?
        .is_some_and(|readback| readback.status() == CacheSignerRootChallengeStatusV2::Pending)
    {
        return Err(ClosedCacheReadbackSessionErrorV1::Stale);
    }
    journal.compact()?;
    read_cache_signer_challenge_in_journal_v2(journal)?;
    Ok(())
}

fn verify_staged_cache_signer_packet_in_journal_v2(
    journal: &mut Journal,
    challenge: StagedCacheSignerRootChallengeV2,
    packet: &[u8],
    expected: CacheRootSourceExpectation<'_>,
) -> Result<VerifiedClosedCacheOwnerReadbackV2, ClosedCacheReadbackSessionErrorV1> {
    let authority = journal.claim_protected_authority(RecordNamespace::DesiredState)?;
    let (verified, settlement) =
        verify_current_cache_signer_packet_v2(&authority, challenge, packet, expected)?;
    if settlement.is_some_and(|record| record.epoch == challenge.epoch) {
        return Err(ClosedCacheReadbackSessionErrorV1::Stale);
    }
    Ok(verified)
}

fn record_cache_signer_root_settlement_in_journal_v2(
    journal: &mut Journal,
    challenge: StagedCacheSignerRootChallengeV2,
    packet: &[u8],
    expected: CacheRootSourceExpectation<'_>,
) -> Result<(), ClosedCacheReadbackSessionErrorV1> {
    let mut authority = journal.claim_protected_authority(RecordNamespace::DesiredState)?;
    let (_, prior) =
        verify_current_cache_signer_packet_v2(&authority, challenge, packet, expected)?;
    if prior.is_some_and(|record| record.epoch == challenge.epoch) {
        return Err(ClosedCacheReadbackSessionErrorV1::Stale);
    }

    let packet_digest = ObjectDigest::from_bytes(Sha256::digest(packet).into());
    if packet_digest.as_bytes() == &[0; 32] {
        return Err(ClosedCacheReadbackSessionErrorV1::Stale);
    }
    let settlement = CacheRootSettlementV2 {
        epoch: challenge.epoch,
        nonce: challenge.readback.nonce(),
        cut: challenge.readback.cut(),
        packet_digest,
    };
    let record = settlement.encode();
    require_expiring_cache_root_archive_v2(&authority, settlement.epoch)?;
    authority.commit(&settlement.transaction()?)?;
    require_cache_root_source(&authority, expected)?;
    let challenge_record = CODEC_V2.encode(settlement.epoch, settlement.nonce, settlement.cut);
    if authority.get(CHALLENGE_KEY_V2)? != Some(challenge_record.as_slice())
        || authority.get(SETTLEMENT_KEY)? != Some(record.as_slice())
        || authority.get(&settlement.archive_key())? != Some(record.as_slice())
        || expired_cache_root_archive_remains_v2(&authority, settlement.epoch)?
    {
        return Err(ClosedCacheReadbackSessionErrorV1::Stale);
    }
    Ok(())
}

fn abandon_cache_signer_challenge_in_journal_v2(
    journal: &mut Journal,
    challenge: StagedCacheSignerRootChallengeV2,
) -> Result<(), ClosedCacheReadbackSessionErrorV1> {
    let mut authority = journal.claim_protected_authority(RecordNamespace::DesiredState)?;
    let record = CODEC_V2.encode(
        challenge.epoch,
        challenge.readback.nonce(),
        challenge.readback.cut(),
    );
    if authority.get(CHALLENGE_KEY_V2)? != Some(record.as_slice())
        || require_consistent_cache_root_settlement_v2(&authority)?
            .is_some_and(|settlement| settlement.epoch == challenge.epoch)
    {
        return Err(ClosedCacheReadbackSessionErrorV1::Stale);
    }

    // Abandonment is a revocation only; it need not trust now-changed sources.
    let abandonment = CacheRootSettlementV2 {
        epoch: challenge.epoch,
        nonce: challenge.readback.nonce(),
        cut: challenge.readback.cut(),
        packet_digest: ObjectDigest::from_bytes([0; 32]),
    };
    let abandonment_record = abandonment.encode();
    require_expiring_cache_root_archive_v2(&authority, abandonment.epoch)?;
    authority.commit(&abandonment.transaction()?)?;
    if authority.get(CHALLENGE_KEY_V2)? != Some(record.as_slice())
        || authority.get(SETTLEMENT_KEY)? != Some(abandonment_record.as_slice())
        || authority.get(&abandonment.archive_key())? != Some(abandonment_record.as_slice())
        || expired_cache_root_archive_remains_v2(&authority, abandonment.epoch)?
    {
        return Err(ClosedCacheReadbackSessionErrorV1::Stale);
    }
    Ok(())
}

fn recover_cache_signer_abandonment_in_journal_v2(
    journal: &mut Journal,
    challenge: StagedCacheSignerRootChallengeV2,
) -> Result<bool, ClosedCacheReadbackSessionErrorV1> {
    let authority = journal.claim_protected_authority(RecordNamespace::DesiredState)?;
    let settlement_head = require_consistent_cache_root_settlement_v2(&authority)?;
    if let Some(archived) = authority.get(&archive_key(challenge.epoch))? {
        let settlement = CacheRootSettlementV2::decode(archived)
            .ok_or(ClosedCacheReadbackSessionErrorV1::Stale)?;
        if settlement.epoch != challenge.epoch
            || settlement.nonce != challenge.readback.nonce()
            || settlement.cut != challenge.readback.cut()
            || !settlement.abandoned()
        {
            return Err(ClosedCacheReadbackSessionErrorV1::Stale);
        }
        return Ok(true);
    }
    let record = CODEC_V2.encode(
        challenge.epoch,
        challenge.readback.nonce(),
        challenge.readback.cut(),
    );
    if authority.get(CHALLENGE_KEY_V2)? != Some(record.as_slice()) {
        return Err(ClosedCacheReadbackSessionErrorV1::Stale);
    }
    match settlement_head {
        Some(settlement) if settlement.epoch == challenge.epoch => {
            if !settlement.abandoned() {
                return Err(ClosedCacheReadbackSessionErrorV1::Stale);
            }
            Ok(true)
        }
        _ => Ok(false),
    }
}

fn recover_cache_signer_root_settlement_in_journal_v2(
    journal: &mut Journal,
    challenge: StagedCacheSignerRootChallengeV2,
    packet: &[u8],
    expected: CacheRootSourceExpectation<'_>,
) -> Result<CacheSignerRootSettlementStateV2, ClosedCacheReadbackSessionErrorV1> {
    if recover_cache_signer_root_history_in_journal_v2(journal, challenge, packet)?
        == CacheSignerRootSettlementStateV2::Recorded
    {
        return Ok(CacheSignerRootSettlementStateV2::Recorded);
    }
    let authority = journal.claim_protected_authority(RecordNamespace::DesiredState)?;
    let _ = verify_current_cache_signer_packet_v2(&authority, challenge, packet, expected)?;
    Ok(CacheSignerRootSettlementStateV2::Unrecorded)
}

fn recover_cache_signer_root_history_in_journal_v2(
    journal: &mut Journal,
    challenge: StagedCacheSignerRootChallengeV2,
    packet: &[u8],
) -> Result<CacheSignerRootSettlementStateV2, ClosedCacheReadbackSessionErrorV1> {
    let authority = journal.claim_protected_authority(RecordNamespace::DesiredState)?;
    let settlement_head = require_consistent_cache_root_settlement_v2(&authority)?;
    if let Some(archived) = authority.get(&archive_key(challenge.epoch))? {
        let settlement = CacheRootSettlementV2::decode(archived)
            .ok_or(ClosedCacheReadbackSessionErrorV1::Stale)?;
        let packet_digest = ObjectDigest::from_bytes(Sha256::digest(packet).into());
        if settlement.epoch != challenge.epoch
            || settlement.nonce != challenge.readback.nonce()
            || settlement.cut != challenge.readback.cut()
            || settlement.abandoned()
            || settlement.packet_digest != packet_digest
        {
            return Err(ClosedCacheReadbackSessionErrorV1::Stale);
        }
        // The protected archive records only packets verified by Root at
        // commit. Historical recovery never extends their effect authority.
        return Ok(CacheSignerRootSettlementStateV2::Recorded);
    }
    let record = CODEC_V2.encode(
        challenge.epoch,
        challenge.readback.nonce(),
        challenge.readback.cut(),
    );
    let (current_epoch, _) = CODEC_V2
        .read_prior(authority.get(CHALLENGE_KEY_V2)?)
        .ok_or(ClosedCacheReadbackSessionErrorV1::Stale)?;
    if current_epoch != challenge.epoch
        || authority.get(CHALLENGE_KEY_V2)? != Some(record.as_slice())
        || settlement_head.is_some_and(|settlement| settlement.epoch == challenge.epoch)
    {
        return Err(ClosedCacheReadbackSessionErrorV1::Stale);
    }
    Ok(CacheSignerRootSettlementStateV2::Unrecorded)
}

fn verify_current_cache_signer_packet_v2(
    authority: &ProtectedJournalAuthority<'_>,
    challenge: StagedCacheSignerRootChallengeV2,
    packet: &[u8],
    expected: CacheRootSourceExpectation<'_>,
) -> Result<
    (
        VerifiedClosedCacheOwnerReadbackV2,
        Option<CacheRootSettlementV2>,
    ),
    ClosedCacheReadbackSessionErrorV1,
> {
    let signer = require_cache_root_source(authority, expected)?;
    let record = CODEC_V2.encode(
        challenge.epoch,
        challenge.readback.nonce(),
        challenge.readback.cut(),
    );
    if challenge.readback.cut() != cache_signer_root_cut_v2(expected, challenge.epoch)
        || authority.get(CHALLENGE_KEY_V2)? != Some(record.as_slice())
    {
        return Err(ClosedCacheReadbackSessionErrorV1::Stale);
    }
    let settlement = require_consistent_cache_root_settlement_v2(authority)?;
    let verified = verify_closed_cache_owner_readback_v2(
        packet,
        &signer,
        challenge.readback,
        expected.owner_uid,
    )?;
    require_cache_root_source(authority, expected)?;
    if authority.get(CHALLENGE_KEY_V2)? != Some(record.as_slice()) {
        return Err(ClosedCacheReadbackSessionErrorV1::Stale);
    }
    Ok((verified, settlement))
}

fn require_consistent_cache_root_settlement_v2(
    authority: &ProtectedJournalAuthority<'_>,
) -> Result<Option<CacheRootSettlementV2>, ClosedCacheReadbackSessionErrorV1> {
    let challenge = authority.get(CHALLENGE_KEY_V2)?;
    let (epoch, nonce) = CODEC_V2
        .read_prior(challenge)
        .ok_or(ClosedCacheReadbackSessionErrorV1::Stale)?;
    let Some(record) = authority.get(SETTLEMENT_KEY)? else {
        return Ok(None);
    };
    let settlement =
        CacheRootSettlementV2::decode(record).ok_or(ClosedCacheReadbackSessionErrorV1::Stale)?;
    if authority.get(&settlement.archive_key())? != Some(record) {
        return Err(ClosedCacheReadbackSessionErrorV1::Stale);
    }
    if settlement.epoch > epoch
        || (settlement.epoch == epoch
            && (settlement.nonce != nonce
                || challenge.is_none_or(|value| value[32..64] != settlement.cut.as_bytes()[..])))
    {
        return Err(ClosedCacheReadbackSessionErrorV1::Stale);
    }
    Ok(Some(settlement))
}

fn require_expiring_cache_root_archive_v2(
    authority: &ProtectedJournalAuthority<'_>,
    epoch: u64,
) -> Result<(), ClosedCacheReadbackSessionErrorV1> {
    if epoch <= SETTLEMENT_ARCHIVE_WINDOW {
        return Ok(());
    }
    let expired_epoch = epoch - SETTLEMENT_ARCHIVE_WINDOW;
    let archived = authority
        .get(&archive_key(expired_epoch))?
        .ok_or(ClosedCacheReadbackSessionErrorV1::Stale)?;
    let settlement =
        CacheRootSettlementV2::decode(archived).ok_or(ClosedCacheReadbackSessionErrorV1::Stale)?;
    if settlement.epoch != expired_epoch {
        return Err(ClosedCacheReadbackSessionErrorV1::Stale);
    }
    Ok(())
}

fn expired_cache_root_archive_remains_v2(
    authority: &ProtectedJournalAuthority<'_>,
    epoch: u64,
) -> Result<bool, ClosedCacheReadbackSessionErrorV1> {
    if epoch <= SETTLEMENT_ARCHIVE_WINDOW {
        return Ok(false);
    }
    Ok(authority
        .get(&archive_key(epoch - SETTLEMENT_ARCHIVE_WINDOW))?
        .is_some())
}

fn spend_cache_root_challenge(
    authority: &mut ProtectedJournalAuthority<'_>,
    expected: CacheRootSourceExpectation<'_>,
    codec: &RootChallengeRecordCodec,
    challenge_key: &[u8],
    fresh_root_nonce: impl FnOnce() -> io::Result<[u8; 16]>,
    cut_for_epoch: impl FnOnce(CacheRootSourceExpectation<'_>, u64) -> ObjectDigest,
) -> Result<
    (
        PinnedCacheOwnerReadbackSignerV1,
        StagedCacheSignerRootChallengeV2,
        [u8; RECORD_BYTES],
    ),
    ClosedCacheReadbackSessionErrorV1,
> {
    let signer = require_cache_root_source(authority, expected)?;
    let (prior_epoch, prior_nonce) = codec
        .read_prior(authority.get(challenge_key)?)
        .ok_or(ClosedCacheReadbackSessionErrorV1::Stale)?;
    let epoch = prior_epoch
        .checked_add(1)
        .ok_or(ClosedCacheReadbackSessionErrorV1::Stale)?;
    let nonce = fresh_root_nonce().map_err(|_| ClosedCacheReadbackSessionErrorV1::Nonce)?;
    if nonce == [0; 16] || nonce == prior_nonce {
        return Err(ClosedCacheReadbackSessionErrorV1::Nonce);
    }
    let cut = cut_for_epoch(expected, epoch);
    let readback = CacheOwnerReadbackChallengeV1::new(nonce, cut)?;
    let record = codec.encode(epoch, nonce, cut);
    authority.commit(&codec.transaction(record)?)?;
    if authority.get(challenge_key)? != Some(record.as_slice()) {
        return Err(ClosedCacheReadbackSessionErrorV1::Stale);
    }
    Ok((
        signer,
        StagedCacheSignerRootChallengeV2 { readback, epoch },
        record,
    ))
}

fn require_cache_root_source(
    authority: &ProtectedJournalAuthority<'_>,
    expected: CacheRootSourceExpectation<'_>,
) -> Result<PinnedCacheOwnerReadbackSignerV1, ClosedCacheReadbackSessionErrorV1> {
    let signer = PinnedCacheOwnerReadbackSignerV1::decode(expected.cache_credential)?;
    if expected.owner_uid == 0
        || signer.verifying_key() == expected.deployment_key
        || signer.verifying_key() == expected.project_key
    {
        return Err(ClosedCacheReadbackSessionErrorV1::Stale);
    }
    let policy_pins = encode_policy_signer_pins_v1(
        expected.deployment_generation,
        expected.deployment_key,
        expected.project_generation,
        expected.project_key,
    )
    .map_err(|_| ClosedCacheReadbackSessionErrorV1::Stale)?;
    super::binding_v2::ensure_root_binding_unheld(authority)
        .map_err(|_| ClosedCacheReadbackSessionErrorV1::Stale)?;
    if authority.get(SIGNER_PINS_KEY)? != Some(policy_pins.as_slice())
        || authority.get(CACHE_PIN_KEY)? != Some(expected.cache_credential)
        || authority.get(HEAD_KEY)? != Some(expected.deployment_head)
        || authority.get(HEAD_KEY_V2)? != Some(expected.project_head)
        || authority.get(INPUT_KEY_V2)? != Some(expected.project_input)
        || authority.get(PROJECT_HEAD_KEY)?.is_some()
        || authority.get(PROJECT_INPUT_KEY)?.is_some()
    {
        return Err(ClosedCacheReadbackSessionErrorV1::Stale);
    }
    Ok(signer)
}

fn cache_root_cut(
    domain: &[u8],
    expected: CacheRootSourceExpectation<'_>,
    epoch: u64,
) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(domain)
            .chain_update(expected.deployment_head)
            .chain_update(expected.project_head)
            .chain_update(expected.project_input)
            .chain_update(expected.cache_credential)
            .chain_update(epoch.to_be_bytes())
            .finalize()
            .into(),
    )
}

fn cache_signer_root_cut_v2(expected: CacheRootSourceExpectation<'_>, epoch: u64) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(SIGNER_CUT_DOMAIN_V2)
            .chain_update(epoch.to_be_bytes())
            .chain_update(Sha256::digest(expected.deployment_head))
            .chain_update(Sha256::digest(expected.project_head))
            .chain_update(Sha256::digest(expected.project_input))
            .chain_update(Sha256::digest(expected.cache_credential))
            .chain_update(expected.deployment_generation.to_be_bytes())
            .chain_update(expected.deployment_key.as_bytes())
            .chain_update(expected.project_generation.to_be_bytes())
            .chain_update(expected.project_key.as_bytes())
            .chain_update(expected.owner_uid.to_be_bytes())
            .finalize()
            .into(),
    )
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    use aos_sandbox_core::ProjectId;
    use ed25519_dalek::SigningKey;

    use crate::cache_residency::{
        CLOSED_CACHE_OWNER_READBACK_BYTES_V1, encode_cache_owner_readback_signer_credential_v1,
        sign_test_cache_owner_readback_v1, sign_test_cache_owner_readback_v2,
    };
    use crate::journal::{CachePolicyHoldV1, JournalLimits, JournalRecord, JournalTransaction};

    use super::*;
    use crate::policy_compiler::cache_readback_pin::admit_cache_readback_pin_in_journal_v1;
    use crate::policy_compiler::deployment_head::admit_policy_signer_pins_in_journal_v1;

    const DEPLOYMENT_HEAD: &[u8] = b"root-admitted-deployment-head";
    const PROJECT_HEAD: &[u8] = b"root-admitted-explicit-project-head";
    const PROJECT_INPUT: &[u8] = b"root-admitted-explicit-project-input";

    fn journal(directory: &Path) -> Journal {
        let uid = fs::metadata(directory).expect("test root metadata").uid();
        Journal::open_protected_at_uid(
            directory,
            "authority.journal",
            JournalLimits::default(),
            uid,
        )
        .expect("protected test journal")
        .0
    }

    fn admit_source(
        journal: &mut Journal,
        cache_pin: &[u8],
        deployment: &VerifyingKey,
        project: &VerifyingKey,
    ) {
        admit_policy_signer_pins_in_journal_v1(journal, 3, deployment, 4, project)
            .expect("root policy pins");
        admit_cache_readback_pin_in_journal_v1(journal, Some(cache_pin), 3, deployment, 4, project)
            .expect("root Cache pin");
        let records = [
            (HEAD_KEY, DEPLOYMENT_HEAD),
            (HEAD_KEY_V2, PROJECT_HEAD),
            (INPUT_KEY_V2, PROJECT_INPUT),
        ]
        .into_iter()
        .map(|(key, value)| {
            JournalRecord::put(RecordNamespace::DesiredState, key.to_vec(), value.to_vec())
        })
        .collect();
        journal
            .commit(&JournalTransaction::new([35; 16], records).expect("source transaction"))
            .expect("protected source records");
    }

    #[test]
    fn root_challenge_spends_epoch_and_rejects_replay_rotation_and_disconnect() {
        let directory = tempfile::tempdir().expect("private root fixture");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("private root mode");
        let deployment = SigningKey::from_bytes(&[2; 32]).verifying_key();
        let project = SigningKey::from_bytes(&[3; 32]).verifying_key();
        let cache_signing = SigningKey::from_bytes(&[4; 32]);
        let cache_pin =
            encode_cache_owner_readback_signer_credential_v1(5, &cache_signing.verifying_key())
                .expect("Cache pin");
        let mut root = journal(directory.path());
        admit_source(&mut root, &cache_pin, &deployment, &project);

        assert!(matches!(
            with_closed_cache_readback_session_in_journal_v1(
                &mut root,
                DEPLOYMENT_HEAD,
                PROJECT_HEAD,
                PROJECT_INPUT,
                &cache_pin,
                3,
                &deployment,
                4,
                &project,
                811,
                || Ok([0; 16]),
                |_| panic!("zero nonce must not be issued"),
            ),
            Err(ClosedCacheReadbackSessionErrorV1::Nonce)
        ));

        let mut first_packet = [0_u8; CLOSED_CACHE_OWNER_READBACK_BYTES_V1];
        let first = with_closed_cache_readback_session_in_journal_v1(
            &mut root,
            DEPLOYMENT_HEAD,
            PROJECT_HEAD,
            PROJECT_INPUT,
            &cache_pin,
            3,
            &deployment,
            4,
            &project,
            811,
            || Ok([7; 16]),
            |challenge| {
                assert_eq!(challenge.epoch(), 1);
                first_packet =
                    sign_test_cache_owner_readback_v1(challenge.readback(), 5, &cache_signing, 811)
                        .expect("signed fixture");
                Ok(first_packet.to_vec())
            },
        )
        .expect("closed signed readback");
        assert_eq!(first.epoch(), 1);
        assert_eq!(first.readback().manifest_head().0, 7);
        assert_eq!(
            first.packet_digest(),
            ObjectDigest::from_bytes(Sha256::digest(first_packet).into())
        );

        let mut second_epoch = 0;
        assert!(matches!(
            with_closed_cache_readback_session_in_journal_v1(
                &mut root,
                DEPLOYMENT_HEAD,
                PROJECT_HEAD,
                PROJECT_INPUT,
                &cache_pin,
                3,
                &deployment,
                4,
                &project,
                811,
                || Ok([8; 16]),
                |challenge| {
                    second_epoch = challenge.epoch();
                    Ok(first_packet.to_vec())
                },
            ),
            Err(ClosedCacheReadbackSessionErrorV1::Readback(
                CacheOwnerReadbackErrorV1::Stale
            ))
        ));
        assert_eq!(second_epoch, 2);

        assert!(matches!(
            with_closed_cache_readback_session_in_journal_v1(
                &mut root,
                DEPLOYMENT_HEAD,
                PROJECT_HEAD,
                PROJECT_INPUT,
                &cache_pin,
                3,
                &deployment,
                4,
                &project,
                811,
                || Ok([9; 16]),
                |_| Err(io::Error::new(io::ErrorKind::TimedOut, "lost Controller")),
            ),
            Err(ClosedCacheReadbackSessionErrorV1::Transport(_))
        ));
        drop(root);

        let mut reopened = journal(directory.path());
        let fourth = with_closed_cache_readback_session_in_journal_v1(
            &mut reopened,
            DEPLOYMENT_HEAD,
            PROJECT_HEAD,
            PROJECT_INPUT,
            &cache_pin,
            3,
            &deployment,
            4,
            &project,
            811,
            || Ok([10; 16]),
            |challenge| {
                assert_eq!(challenge.epoch(), 4);
                Ok(
                    sign_test_cache_owner_readback_v1(challenge.readback(), 5, &cache_signing, 811)
                        .expect("signed fixture")
                        .to_vec(),
                )
            },
        )
        .expect("durable challenge replay and released lock");
        assert_eq!(fourth.epoch(), 4);

        let rotated =
            encode_cache_owner_readback_signer_credential_v1(6, &cache_signing.verifying_key())
                .expect("rotated pin");
        let mut nonce_called = false;
        assert!(matches!(
            with_closed_cache_readback_session_in_journal_v1(
                &mut reopened,
                DEPLOYMENT_HEAD,
                PROJECT_HEAD,
                PROJECT_INPUT,
                &rotated,
                3,
                &deployment,
                4,
                &project,
                811,
                || {
                    nonce_called = true;
                    Ok([11; 16])
                },
                |_| Ok(first_packet.to_vec()),
            ),
            Err(ClosedCacheReadbackSessionErrorV1::Stale)
        ));
        assert!(!nonce_called);
        assert!(matches!(
            with_closed_cache_readback_session_in_journal_v1(
                &mut reopened,
                DEPLOYMENT_HEAD,
                PROJECT_HEAD,
                b"stale-project-input",
                &cache_pin,
                3,
                &deployment,
                4,
                &project,
                811,
                || Ok([12; 16]),
                |_| Ok(first_packet.to_vec()),
            ),
            Err(ClosedCacheReadbackSessionErrorV1::Stale)
        ));

        reopened
            .commit(
                &JournalTransaction::new(
                    [36; 16],
                    vec![JournalRecord::put(
                        RecordNamespace::DesiredState,
                        PROJECT_HEAD_KEY.to_vec(),
                        b"legacy-downgrade".to_vec(),
                    )],
                )
                .expect("legacy transaction"),
            )
            .expect("legacy record fixture");
        assert!(matches!(
            with_closed_cache_readback_session_in_journal_v1(
                &mut reopened,
                DEPLOYMENT_HEAD,
                PROJECT_HEAD,
                PROJECT_INPUT,
                &cache_pin,
                3,
                &deployment,
                4,
                &project,
                811,
                || Ok([13; 16]),
                |_| Ok(first_packet.to_vec()),
            ),
            Err(ClosedCacheReadbackSessionErrorV1::Stale)
        ));
    }

    #[test]
    fn staged_signer_challenge_survives_reopen_and_rejects_superseded_packet() {
        let directory = tempfile::tempdir().expect("private root fixture");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("private root mode");
        let deployment = SigningKey::from_bytes(&[2; 32]).verifying_key();
        let project = SigningKey::from_bytes(&[3; 32]).verifying_key();
        let cache_key = SigningKey::from_bytes(&[4; 32]);
        let pin = encode_cache_owner_readback_signer_credential_v1(5, &cache_key.verifying_key())
            .expect("Cache pin");
        let expected = CacheRootSourceExpectation {
            deployment_head: DEPLOYMENT_HEAD,
            project_head: PROJECT_HEAD,
            project_input: PROJECT_INPUT,
            cache_credential: &pin,
            deployment_generation: 3,
            deployment_key: &deployment,
            project_generation: 4,
            project_key: &project,
            owner_uid: 811,
        };
        let mut root = journal(directory.path());
        admit_source(&mut root, &pin, &deployment, &project);
        let legacy = CODEC_V1.encode(1, [9; 16], ObjectDigest::from_bytes([9; 32]));
        root.commit(
            &CODEC_V1
                .transaction(legacy)
                .expect("legacy challenge transaction"),
        )
        .expect("legacy diagnostic challenge");

        let first = stage_cache_signer_challenge_in_journal_v2(&mut root, expected, || Ok([7; 16]))
            .expect("spent V2 challenge");
        assert_eq!(first.epoch(), 1);
        assert_eq!(
            read_cache_signer_challenge_in_journal_v2(&mut root)
                .expect("read pending challenge")
                .expect("present challenge")
                .status(),
            CacheSignerRootChallengeStatusV2::Pending
        );
        assert!(matches!(
            compact_cache_signer_root_journal_v2(&mut root),
            Err(ClosedCacheReadbackSessionErrorV1::Stale)
        ));
        drop(root);

        let hold = CachePolicyHoldV1::new(
            ProjectId::from_bytes([1; 16]),
            ObjectDigest::from_bytes([2; 32]),
            ObjectDigest::from_bytes([3; 32]),
            ObjectDigest::from_bytes([4; 32]),
            5,
        )
        .expect("held fixture");
        let packet = sign_test_cache_owner_readback_v2(
            first.readback(),
            5,
            &cache_key,
            811,
            hold,
            ObjectDigest::from_bytes([10; 32]),
        )
        .expect("signed V2 packet");
        let mut reopened = journal(directory.path());
        let verified = verify_staged_cache_signer_packet_in_journal_v2(
            &mut reopened,
            first,
            &packet,
            expected,
        )
        .expect("V2 packet under spent Root challenge");
        assert_eq!(verified.hold(), hold);

        assert!(matches!(
            stage_cache_signer_challenge_in_journal_v2(&mut reopened, expected, || Ok([8; 16])),
            Err(ClosedCacheReadbackSessionErrorV1::Stale)
        ));
        assert!(
            !recover_cache_signer_abandonment_in_journal_v2(&mut reopened, first)
                .expect("unresolved challenge")
        );
        abandon_cache_signer_challenge_in_journal_v2(&mut reopened, first)
            .expect("durably abandon uncommitted exchange");
        compact_cache_signer_root_journal_v2(&mut reopened)
            .expect("compact only after challenge settlement");
        drop(reopened);

        let mut reopened = journal(directory.path());
        assert!(
            recover_cache_signer_abandonment_in_journal_v2(&mut reopened, first)
                .expect("cold replay finds exact abandonment")
        );
        assert_eq!(
            read_cache_signer_challenge_in_journal_v2(&mut reopened)
                .expect("read abandoned challenge")
                .expect("present challenge")
                .status(),
            CacheSignerRootChallengeStatusV2::Abandoned
        );
        assert!(matches!(
            recover_cache_signer_root_settlement_in_journal_v2(
                &mut reopened,
                first,
                &packet,
                expected,
            ),
            Err(ClosedCacheReadbackSessionErrorV1::Stale)
        ));
        assert!(matches!(
            record_cache_signer_root_settlement_in_journal_v2(
                &mut reopened,
                first,
                &packet,
                expected,
            ),
            Err(ClosedCacheReadbackSessionErrorV1::Stale)
        ));
        assert!(matches!(
            abandon_cache_signer_challenge_in_journal_v2(&mut reopened, first),
            Err(ClosedCacheReadbackSessionErrorV1::Stale)
        ));

        let second =
            stage_cache_signer_challenge_in_journal_v2(&mut reopened, expected, || Ok([8; 16]))
                .expect("next challenge");
        assert_eq!(second.epoch(), 2);
        assert!(matches!(
            verify_staged_cache_signer_packet_in_journal_v2(
                &mut reopened,
                first,
                &packet,
                expected
            ),
            Err(ClosedCacheReadbackSessionErrorV1::Stale)
        ));
        assert!(matches!(
            verify_staged_cache_signer_packet_in_journal_v2(
                &mut reopened,
                second,
                &packet,
                expected
            ),
            Err(ClosedCacheReadbackSessionErrorV1::Readback(
                CacheOwnerReadbackErrorV1::Stale
            ))
        ));
    }

    #[test]
    fn signer_settlement_is_single_use_and_recovers_exact_packet_after_cold_reopen() {
        let directory = tempfile::tempdir().expect("private root fixture");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("private root mode");
        let deployment = SigningKey::from_bytes(&[2; 32]).verifying_key();
        let project = SigningKey::from_bytes(&[3; 32]).verifying_key();
        let cache_key = SigningKey::from_bytes(&[4; 32]);
        let pin = encode_cache_owner_readback_signer_credential_v1(5, &cache_key.verifying_key())
            .expect("Cache pin");
        let expected = CacheRootSourceExpectation {
            deployment_head: DEPLOYMENT_HEAD,
            project_head: PROJECT_HEAD,
            project_input: PROJECT_INPUT,
            cache_credential: &pin,
            deployment_generation: 3,
            deployment_key: &deployment,
            project_generation: 4,
            project_key: &project,
            owner_uid: 811,
        };
        let mut root = journal(directory.path());
        admit_source(&mut root, &pin, &deployment, &project);

        let challenge =
            stage_cache_signer_challenge_in_journal_v2(&mut root, expected, || Ok([7; 16]))
                .expect("spent challenge");
        let hold = CachePolicyHoldV1::new(
            ProjectId::from_bytes([1; 16]),
            ObjectDigest::from_bytes([2; 32]),
            ObjectDigest::from_bytes([3; 32]),
            ObjectDigest::from_bytes([4; 32]),
            5,
        )
        .expect("held fixture");
        let packet = sign_test_cache_owner_readback_v2(
            challenge.readback(),
            5,
            &cache_key,
            811,
            hold,
            ObjectDigest::from_bytes([10; 32]),
        )
        .expect("signed packet");
        let other_packet = sign_test_cache_owner_readback_v2(
            challenge.readback(),
            5,
            &cache_key,
            811,
            hold,
            ObjectDigest::from_bytes([11; 32]),
        )
        .expect("other signed packet");
        assert_eq!(
            recover_cache_signer_root_settlement_in_journal_v2(
                &mut root, challenge, &packet, expected
            )
            .expect("unrecorded after spend"),
            CacheSignerRootSettlementStateV2::Unrecorded
        );
        record_cache_signer_root_settlement_in_journal_v2(&mut root, challenge, &packet, expected)
            .expect("first settlement");
        drop(root);

        let mut reopened = journal(directory.path());
        assert_eq!(
            read_cache_signer_challenge_in_journal_v2(&mut reopened)
                .expect("read recorded challenge")
                .expect("present challenge")
                .status(),
            CacheSignerRootChallengeStatusV2::Recorded(ObjectDigest::from_bytes(
                Sha256::digest(packet).into()
            ))
        );
        assert_eq!(
            recover_cache_signer_root_settlement_in_journal_v2(
                &mut reopened,
                challenge,
                &packet,
                expected,
            )
            .expect("cold replay finds exact packet"),
            CacheSignerRootSettlementStateV2::Recorded
        );
        assert!(matches!(
            verify_staged_cache_signer_packet_in_journal_v2(
                &mut reopened,
                challenge,
                &packet,
                expected,
            ),
            Err(ClosedCacheReadbackSessionErrorV1::Stale)
        ));
        assert!(matches!(
            record_cache_signer_root_settlement_in_journal_v2(
                &mut reopened,
                challenge,
                &packet,
                expected,
            ),
            Err(ClosedCacheReadbackSessionErrorV1::Stale)
        ));
        assert!(matches!(
            recover_cache_signer_root_settlement_in_journal_v2(
                &mut reopened,
                challenge,
                &other_packet,
                expected,
            ),
            Err(ClosedCacheReadbackSessionErrorV1::Stale)
        ));
        // Historical replay compares Root's retained packet archive; it no
        // longer grants present signer/source authority after a source change.
        assert_eq!(
            recover_cache_signer_root_settlement_in_journal_v2(
                &mut reopened,
                challenge,
                &packet,
                CacheRootSourceExpectation {
                    owner_uid: 812,
                    ..expected
                },
            )
            .expect("historical settlement"),
            CacheSignerRootSettlementStateV2::Recorded
        );

        let next =
            stage_cache_signer_challenge_in_journal_v2(&mut reopened, expected, || Ok([8; 16]))
                .expect("next epoch may spend");
        assert_eq!(next.epoch(), 2);
        assert_eq!(
            recover_cache_signer_root_settlement_in_journal_v2(
                &mut reopened,
                challenge,
                &packet,
                expected,
            )
            .expect("superseded epoch remains historically recoverable"),
            CacheSignerRootSettlementStateV2::Recorded
        );
    }

    #[test]
    fn malformed_settlement_blocks_replay_and_new_challenge() {
        let directory = tempfile::tempdir().expect("private root fixture");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("private root mode");
        let deployment = SigningKey::from_bytes(&[2; 32]).verifying_key();
        let project = SigningKey::from_bytes(&[3; 32]).verifying_key();
        let cache_key = SigningKey::from_bytes(&[4; 32]);
        let pin = encode_cache_owner_readback_signer_credential_v1(5, &cache_key.verifying_key())
            .expect("Cache pin");
        let expected = CacheRootSourceExpectation {
            deployment_head: DEPLOYMENT_HEAD,
            project_head: PROJECT_HEAD,
            project_input: PROJECT_INPUT,
            cache_credential: &pin,
            deployment_generation: 3,
            deployment_key: &deployment,
            project_generation: 4,
            project_key: &project,
            owner_uid: 811,
        };
        let mut root = journal(directory.path());
        admit_source(&mut root, &pin, &deployment, &project);
        let challenge =
            stage_cache_signer_challenge_in_journal_v2(&mut root, expected, || Ok([7; 16]))
                .expect("spent challenge");
        root.commit(
            &JournalTransaction::new(
                [77; 16],
                vec![JournalRecord::put(
                    RecordNamespace::DesiredState,
                    SETTLEMENT_KEY.to_vec(),
                    b"malformed settlement".to_vec(),
                )],
            )
            .expect("malformed fixture transaction"),
        )
        .expect("malformed fixture commit");
        drop(root);

        let mut reopened = journal(directory.path());
        assert!(matches!(
            stage_cache_signer_challenge_in_journal_v2(&mut reopened, expected, || Ok([8; 16])),
            Err(ClosedCacheReadbackSessionErrorV1::Stale)
        ));
        let hold = CachePolicyHoldV1::new(
            ProjectId::from_bytes([1; 16]),
            ObjectDigest::from_bytes([2; 32]),
            ObjectDigest::from_bytes([3; 32]),
            ObjectDigest::from_bytes([4; 32]),
            5,
        )
        .expect("held fixture");
        let packet = sign_test_cache_owner_readback_v2(
            challenge.readback(),
            5,
            &cache_key,
            811,
            hold,
            ObjectDigest::from_bytes([10; 32]),
        )
        .expect("signed packet");
        assert!(matches!(
            recover_cache_signer_root_settlement_in_journal_v2(
                &mut reopened,
                challenge,
                &packet,
                expected,
            ),
            Err(ClosedCacheReadbackSessionErrorV1::Stale)
        ));
    }
}
