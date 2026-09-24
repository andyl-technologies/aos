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
    VerifiedClosedCacheOwnerReadbackV1, verify_closed_cache_owner_readback_v1,
};
use crate::journal::{Journal, JournalError, JournalRecord, JournalTransaction, RecordNamespace};

use super::cache_readback_pin::CACHE_PIN_KEY;
use super::deployment_head::{
    HEAD_KEY, PROJECT_HEAD_KEY, PROJECT_INPUT_KEY, SIGNER_PINS_KEY, encode_policy_signer_pins_v1,
};
use super::project_source_v2::{HEAD_KEY_V2, INPUT_KEY_V2};
use super::protected_owner::{
    POLICY_AUTHORITY_JOURNAL, PROTECTED_POLICY_ROOT, policy_authority_journal_limits,
};

const CHALLENGE_KEY: &[u8] = b"\0aos-policy-cache-readback-challenge-v1\0";
const MAGIC: &[u8; 8] = b"AOSCRH01";
const CUT_DOMAIN: &[u8] = b"aos.sandbox.policy-cache-readback-root-source-cut.v1\0";
const RECORD_DOMAIN: &[u8] = b"aos.sandbox.policy-cache-readback-challenge-record.v1\0";
const TRANSACTION_DOMAIN: &[u8] = b"aos.sandbox.policy-cache-readback-challenge-transaction.v1\0";
const RECORD_BYTES: usize = 96;

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
    let signer = PinnedCacheOwnerReadbackSignerV1::decode(cache_credential)?;
    if expected_owner_uid == 0
        || signer.verifying_key() == deployment_key
        || signer.verifying_key() == project_key
    {
        return Err(ClosedCacheReadbackSessionErrorV1::Stale);
    }
    let policy_pins = encode_policy_signer_pins_v1(
        deployment_generation,
        deployment_key,
        project_generation,
        project_key,
    )
    .map_err(|_| ClosedCacheReadbackSessionErrorV1::Stale)?;
    let mut authority = journal.claim_protected_authority(RecordNamespace::DesiredState)?;
    if authority.get(SIGNER_PINS_KEY)? != Some(policy_pins.as_slice())
        || authority.get(CACHE_PIN_KEY)? != Some(cache_credential)
        || authority.get(HEAD_KEY)? != Some(expected_deployment_head)
        || authority.get(HEAD_KEY_V2)? != Some(expected_project_head)
        || authority.get(INPUT_KEY_V2)? != Some(expected_project_input)
        || authority.get(PROJECT_HEAD_KEY)?.is_some()
        || authority.get(PROJECT_INPUT_KEY)?.is_some()
    {
        return Err(ClosedCacheReadbackSessionErrorV1::Stale);
    }

    let prior_epoch = read_prior_epoch(authority.get(CHALLENGE_KEY)?)?;
    let epoch = prior_epoch
        .checked_add(1)
        .ok_or(ClosedCacheReadbackSessionErrorV1::Stale)?;
    let nonce = fresh_root_nonce().map_err(|_| ClosedCacheReadbackSessionErrorV1::Nonce)?;
    if nonce == [0; 16] {
        return Err(ClosedCacheReadbackSessionErrorV1::Nonce);
    }
    let root_cut = ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(CUT_DOMAIN)
            .chain_update(expected_deployment_head)
            .chain_update(expected_project_head)
            .chain_update(expected_project_input)
            .chain_update(cache_credential)
            .chain_update(epoch.to_be_bytes())
            .finalize()
            .into(),
    );
    let readback = CacheOwnerReadbackChallengeV1::new(nonce, root_cut)?;
    let record = encode_challenge_record(epoch, readback);
    let digest = Sha256::new()
        .chain_update(TRANSACTION_DOMAIN)
        .chain_update(record)
        .finalize();
    let mut transaction_id = [0_u8; 16];
    transaction_id.copy_from_slice(&digest[..16]);
    let transaction = JournalTransaction::new(
        transaction_id,
        vec![JournalRecord::put(
            RecordNamespace::DesiredState,
            CHALLENGE_KEY.to_vec(),
            record.to_vec(),
        )],
    )?;
    authority.commit(&transaction)?;
    if authority.get(CHALLENGE_KEY)? != Some(record.as_slice()) {
        return Err(ClosedCacheReadbackSessionErrorV1::Stale);
    }

    let challenge = ClosedCacheReadbackRootChallengeV1 { readback, epoch };
    let packet = exchange(challenge)?;
    let verified =
        verify_closed_cache_owner_readback_v1(&packet, &signer, readback, expected_owner_uid)?;
    if authority.get(CHALLENGE_KEY)? != Some(record.as_slice())
        || authority.get(CACHE_PIN_KEY)? != Some(cache_credential)
    {
        return Err(ClosedCacheReadbackSessionErrorV1::Stale);
    }
    Ok(ClosedCacheReadbackRootObservationV1 {
        readback: verified,
        packet_digest: ObjectDigest::from_bytes(Sha256::digest(packet).into()),
        epoch,
    })
}

fn read_prior_epoch(record: Option<&[u8]>) -> Result<u64, ClosedCacheReadbackSessionErrorV1> {
    let Some(record) = record else { return Ok(0) };
    if record.len() != RECORD_BYTES || record[..8] != MAGIC[..] {
        return Err(ClosedCacheReadbackSessionErrorV1::Stale);
    }
    let checksum = Sha256::new()
        .chain_update(RECORD_DOMAIN)
        .chain_update(&record[..64])
        .finalize();
    if record[64..] != checksum[..] || record[16..32] == [0; 16] || record[32..64] == [0; 32] {
        return Err(ClosedCacheReadbackSessionErrorV1::Stale);
    }
    let mut epoch = [0_u8; 8];
    epoch.copy_from_slice(&record[8..16]);
    let epoch = u64::from_be_bytes(epoch);
    if epoch == 0 {
        return Err(ClosedCacheReadbackSessionErrorV1::Stale);
    }
    Ok(epoch)
}

fn encode_challenge_record(
    epoch: u64,
    challenge: CacheOwnerReadbackChallengeV1,
) -> [u8; RECORD_BYTES] {
    let mut record = [0_u8; RECORD_BYTES];
    record[..8].copy_from_slice(MAGIC);
    record[8..16].copy_from_slice(&epoch.to_be_bytes());
    record[16..32].copy_from_slice(&challenge.nonce());
    record[32..64].copy_from_slice(challenge.cut().as_bytes());
    let checksum = Sha256::new()
        .chain_update(RECORD_DOMAIN)
        .chain_update(&record[..64])
        .finalize();
    record[64..].copy_from_slice(&checksum);
    record
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    use ed25519_dalek::SigningKey;

    use crate::cache_residency::{
        CLOSED_CACHE_OWNER_READBACK_BYTES_V1, encode_cache_owner_readback_signer_credential_v1,
        sign_test_cache_owner_readback_v1,
    };
    use crate::journal::JournalLimits;

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
}
