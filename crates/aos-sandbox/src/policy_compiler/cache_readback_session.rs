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
use super::deployment_head::{
    HEAD_KEY, PROJECT_HEAD_KEY, PROJECT_INPUT_KEY, SIGNER_PINS_KEY, encode_policy_signer_pins_v1,
};
use super::project_source_v2::{HEAD_KEY_V2, INPUT_KEY_V2};
use super::protected_owner::{
    POLICY_AUTHORITY_JOURNAL, PROTECTED_POLICY_ROOT, policy_authority_journal_limits,
};
use super::root_challenge_record::{RECORD_BYTES, RootChallengeRecordCodec};

const CHALLENGE_KEY: &[u8] = b"\0aos-policy-cache-readback-challenge-v1\0";
const MAGIC: &[u8; 8] = b"AOSCRH01";
const CUT_DOMAIN: &[u8] = b"aos.sandbox.policy-cache-readback-root-source-cut.v1\0";
const SIGNER_CUT_DOMAIN_V2: &[u8] = b"aos.sandbox.policy-cache-signer-root-source-cut.v2\0";
const RECORD_DOMAIN: &[u8] = b"aos.sandbox.policy-cache-readback-challenge-record.v1\0";
const TRANSACTION_DOMAIN: &[u8] = b"aos.sandbox.policy-cache-readback-challenge-transaction.v1\0";
const CODEC: RootChallengeRecordCodec =
    RootChallengeRecordCodec::new(MAGIC, RECORD_DOMAIN, TRANSACTION_DOMAIN, CHALLENGE_KEY);

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

/// Spends a signer challenge under Root's writer, then releases that writer.
///
/// The caller must acquire Controller, Source, protected Cache, and physical
/// Cache custody only after this function returns. No receipt or effect is
/// authorized by spending the challenge.
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
    let root = Path::new(PROTECTED_POLICY_ROOT);
    let limits = policy_authority_journal_limits();
    let (mut journal, _) = Journal::open_protected_at(root, POLICY_AUTHORITY_JOURNAL, limits)?;
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
    let challenge =
        stage_cache_signer_challenge_in_journal_v2(&mut journal, expected, fresh_root_nonce)?;
    journal.require_protected_named_location(root, POLICY_AUTHORITY_JOURNAL, 0, limits)?;
    Ok(challenge)
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
    let root = Path::new(PROTECTED_POLICY_ROOT);
    let limits = policy_authority_journal_limits();
    let (mut journal, _) = Journal::open_protected_at(root, POLICY_AUTHORITY_JOURNAL, limits)?;
    journal.require_protected_named_location(root, POLICY_AUTHORITY_JOURNAL, 0, limits)?;
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
    let verified =
        verify_staged_cache_signer_packet_in_journal_v2(&mut journal, challenge, packet, expected)?;
    journal.require_protected_named_location(root, POLICY_AUTHORITY_JOURNAL, 0, limits)?;
    Ok(verified)
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
    let (signer, challenge, record) =
        spend_cache_root_challenge(&mut authority, expected, CUT_DOMAIN, fresh_root_nonce)?;

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
    if authority.get(CHALLENGE_KEY)? != Some(record.as_slice())
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
    let (_, challenge, _) = spend_cache_root_challenge(
        &mut authority,
        expected,
        SIGNER_CUT_DOMAIN_V2,
        fresh_root_nonce,
    )?;
    Ok(challenge)
}

fn verify_staged_cache_signer_packet_in_journal_v2(
    journal: &mut Journal,
    challenge: StagedCacheSignerRootChallengeV2,
    packet: &[u8],
    expected: CacheRootSourceExpectation<'_>,
) -> Result<VerifiedClosedCacheOwnerReadbackV2, ClosedCacheReadbackSessionErrorV1> {
    let authority = journal.claim_protected_authority(RecordNamespace::DesiredState)?;
    let signer = require_cache_root_source(&authority, expected)?;
    let expected_cut = cache_root_cut(SIGNER_CUT_DOMAIN_V2, expected, challenge.epoch);
    let record = CODEC.encode(
        challenge.epoch,
        challenge.readback.nonce(),
        challenge.readback.cut(),
    );
    if challenge.readback.cut() != expected_cut
        || authority.get(CHALLENGE_KEY)? != Some(record.as_slice())
    {
        return Err(ClosedCacheReadbackSessionErrorV1::Stale);
    }

    let verified = verify_closed_cache_owner_readback_v2(
        packet,
        &signer,
        challenge.readback,
        expected.owner_uid,
    )?;
    require_cache_root_source(&authority, expected)?;
    if authority.get(CHALLENGE_KEY)? != Some(record.as_slice()) {
        return Err(ClosedCacheReadbackSessionErrorV1::Stale);
    }
    Ok(verified)
}

fn spend_cache_root_challenge(
    authority: &mut ProtectedJournalAuthority<'_>,
    expected: CacheRootSourceExpectation<'_>,
    cut_domain: &[u8],
    fresh_root_nonce: impl FnOnce() -> io::Result<[u8; 16]>,
) -> Result<
    (
        PinnedCacheOwnerReadbackSignerV1,
        StagedCacheSignerRootChallengeV2,
        [u8; RECORD_BYTES],
    ),
    ClosedCacheReadbackSessionErrorV1,
> {
    let signer = require_cache_root_source(authority, expected)?;
    let (prior_epoch, prior_nonce) = CODEC
        .read_prior(authority.get(CHALLENGE_KEY)?)
        .ok_or(ClosedCacheReadbackSessionErrorV1::Stale)?;
    let epoch = prior_epoch
        .checked_add(1)
        .ok_or(ClosedCacheReadbackSessionErrorV1::Stale)?;
    let nonce = fresh_root_nonce().map_err(|_| ClosedCacheReadbackSessionErrorV1::Nonce)?;
    if nonce == [0; 16] || nonce == prior_nonce {
        return Err(ClosedCacheReadbackSessionErrorV1::Nonce);
    }
    let cut = cache_root_cut(cut_domain, expected, epoch);
    let readback = CacheOwnerReadbackChallengeV1::new(nonce, cut)?;
    let record = CODEC.encode(epoch, nonce, cut);
    authority.commit(&CODEC.transaction(record)?)?;
    if authority.get(CHALLENGE_KEY)? != Some(record.as_slice()) {
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

        let first = stage_cache_signer_challenge_in_journal_v2(&mut root, expected, || Ok([7; 16]))
            .expect("spent V2 challenge");
        assert_eq!(first.epoch(), 1);
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
}
