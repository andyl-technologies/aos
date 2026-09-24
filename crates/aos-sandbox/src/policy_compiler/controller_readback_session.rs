//! Durable, nonauthorizing root challenge for a Controller hold readback.
//!
//! Root spends a fresh challenge epoch before asking the Controller signer for
//! an `AOSCTW01` receipt. The root writer remains held through verification.
//! The receipt authenticates one Controller statement but cannot transfer its
//! writer lock or authorize Q04, publication, or an effect.
//!
//! ```text
//! AOSCTH01 | epoch:u64 | nonce:16 | root-source-and-hold-cut:32 |
//! SHA-256(challenge-record-domain || preceding 64 bytes):32
//! ```

use std::{io, path::Path};

use aos_sandbox_core::ObjectDigest;
use ed25519_dalek::VerifyingKey;
use sha2::{Digest as _, Sha256};

use crate::cache_residency::PinnedCacheOwnerReadbackSignerV1;
use crate::journal::{ControllerPolicyHoldV1, Journal, JournalError, RecordNamespace};

use super::cache_readback_pin::CACHE_PIN_KEY;
use super::controller_hold_pin::CONTROLLER_HOLD_PIN_KEY;
use super::controller_hold_readback::{
    ControllerHoldReadbackChallengeV1, ControllerHoldReadbackErrorV1, PinnedControllerHoldSignerV1,
    VerifiedControllerHoldReadbackV1, verify_controller_hold_readback_v1,
};
use super::deployment_head::{
    HEAD_KEY, PROJECT_HEAD_KEY, PROJECT_INPUT_KEY, SIGNER_PINS_KEY, encode_policy_signer_pins_v1,
};
use super::project_source_v2::{HEAD_KEY_V2, INPUT_KEY_V2};
use super::protected_owner::{
    POLICY_AUTHORITY_JOURNAL, PROTECTED_POLICY_ROOT, policy_authority_journal_limits,
};
use super::root_challenge_record::{RECORD_BYTES, RootChallengeRecordCodec};

const CHALLENGE_KEY: &[u8] = b"\0aos-policy-controller-hold-challenge-v1\0";
const MAGIC: &[u8; 8] = b"AOSCTH01";
const CUT_DOMAIN: &[u8] = b"aos.sandbox.policy-controller-hold-root-cut.v1\0";
const RECORD_DOMAIN: &[u8] = b"aos.sandbox.policy-controller-hold-challenge-record.v1\0";
const TRANSACTION_DOMAIN: &[u8] = b"aos.sandbox.policy-controller-hold-challenge-transaction.v1\0";
const CODEC: RootChallengeRecordCodec =
    RootChallengeRecordCodec::new(MAGIC, RECORD_DOMAIN, TRANSACTION_DOMAIN, CHALLENGE_KEY);

/// Reports a rejected root/Controller hold readback session.
#[derive(Debug, thiserror::Error)]
pub enum ClosedControllerReadbackSessionErrorV1 {
    /// The root source, pinned signer, expected hold, or challenge is stale.
    #[error("closed Controller readback root source or challenge is stale")]
    Stale,
    /// Root entropy failed or repeated an unusable nonce.
    #[error("closed Controller readback root nonce is invalid")]
    Nonce,
    /// Protected root journal custody, replay, or commit failed.
    #[error(transparent)]
    Journal(#[from] JournalError),
    /// The Controller-purpose credential or receipt failed verification.
    #[error(transparent)]
    Readback(#[from] ControllerHoldReadbackErrorV1),
    /// The receipt transport failed after the challenge was spent.
    #[error(transparent)]
    Transport(#[from] io::Error),
}

/// Carries a spent root challenge for one claimed Controller hold.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClosedControllerRootChallengeV1 {
    readback: ControllerHoldReadbackChallengeV1,
    epoch: u64,
}

impl ClosedControllerRootChallengeV1 {
    /// Returns the nonce and root cut for the Controller-purpose signer.
    #[must_use]
    pub const fn readback(self) -> ControllerHoldReadbackChallengeV1 {
        self.readback
    }

    /// Returns the durably spent challenge epoch.
    #[must_use]
    pub const fn epoch(self) -> u64 {
        self.epoch
    }
}

/// Reports a verified Controller statement without granting Q04 authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClosedControllerRootObservationV1 {
    readback: VerifiedControllerHoldReadbackV1,
    packet_digest: ObjectDigest,
    epoch: u64,
}

impl ClosedControllerRootObservationV1 {
    /// Returns the exact signed Controller hold fields.
    #[must_use]
    pub const fn readback(self) -> VerifiedControllerHoldReadbackV1 {
        self.readback
    }

    /// Returns the digest of the signed receipt bytes.
    #[must_use]
    pub const fn packet_digest(self) -> ObjectDigest {
        self.packet_digest
    }

    /// Returns the spent root challenge epoch.
    #[must_use]
    pub const fn epoch(self) -> u64 {
        self.epoch
    }
}

/// Spends a root challenge and verifies one independently pinned Controller receipt.
///
/// The root service must pass only its fixed deployment credentials and a
/// protected service UID. `expected_hold` is a comparison target, not proof of
/// Controller custody. This library primitive has no production socket
/// callsite; the Source and Cache cuts and crash-safe release are still absent.
/// Failure spends only the root challenge; it never acquires or releases a
/// Controller hold.
///
/// # Errors
///
/// Rejects stale root records, missing or reused signer pins, an invalid held
/// identity, unavailable entropy, failed durable spend/readback, transport
/// loss, changed root journal names, or a mismatched signed receipt.
#[allow(clippy::too_many_arguments)]
pub fn with_fixed_closed_controller_readback_session_v1(
    expected_deployment_head: &[u8],
    expected_project_head: &[u8],
    expected_project_input: &[u8],
    controller_credential: &[u8],
    deployment_generation: u64,
    deployment_key: &VerifyingKey,
    project_generation: u64,
    project_key: &VerifyingKey,
    expected_owner_uid: u32,
    expected_hold: ControllerPolicyHoldV1,
    exchange: impl FnOnce(ClosedControllerRootChallengeV1) -> io::Result<Vec<u8>>,
) -> Result<ClosedControllerRootObservationV1, ClosedControllerReadbackSessionErrorV1> {
    let root = Path::new(PROTECTED_POLICY_ROOT);
    let limits = policy_authority_journal_limits();
    let (mut journal, _) = Journal::open_protected_at(root, POLICY_AUTHORITY_JOURNAL, limits)?;
    with_closed_controller_readback_session_in_journal_v1(
        &mut journal,
        |journal| {
            journal.require_protected_named_location(root, POLICY_AUTHORITY_JOURNAL, 0, limits)
        },
        expected_deployment_head,
        expected_project_head,
        expected_project_input,
        controller_credential,
        deployment_generation,
        deployment_key,
        project_generation,
        project_key,
        expected_owner_uid,
        expected_hold,
        fresh_root_nonce,
        exchange,
    )
}

fn fresh_root_nonce() -> io::Result<[u8; 16]> {
    let mut nonce = [0_u8; 16];
    let mut filled = 0;
    while filled < nonce.len() {
        let count =
            rustix::rand::getrandom(&mut nonce[filled..], rustix::rand::GetRandomFlags::empty())
                .map_err(io::Error::other)?;
        if count == 0 {
            return Err(io::Error::other("root entropy unavailable"));
        }
        filled += count;
    }
    Ok(nonce)
}

#[allow(clippy::too_many_arguments)]
fn with_closed_controller_readback_session_in_journal_v1(
    journal: &mut Journal,
    check_named_location: impl Fn(&Journal) -> Result<(), JournalError>,
    expected_deployment_head: &[u8],
    expected_project_head: &[u8],
    expected_project_input: &[u8],
    controller_credential: &[u8],
    deployment_generation: u64,
    deployment_key: &VerifyingKey,
    project_generation: u64,
    project_key: &VerifyingKey,
    expected_owner_uid: u32,
    expected_hold: ControllerPolicyHoldV1,
    fresh_root_nonce: impl FnOnce() -> io::Result<[u8; 16]>,
    exchange: impl FnOnce(ClosedControllerRootChallengeV1) -> io::Result<Vec<u8>>,
) -> Result<ClosedControllerRootObservationV1, ClosedControllerReadbackSessionErrorV1> {
    check_named_location(journal)?;
    let signer = PinnedControllerHoldSignerV1::decode(controller_credential)?;
    if expected_owner_uid == 0
        || !expected_hold.is_held()
        || signer.verifying_key() == deployment_key
        || signer.verifying_key() == project_key
    {
        return Err(ClosedControllerReadbackSessionErrorV1::Stale);
    }
    let policy_pins = encode_policy_signer_pins_v1(
        deployment_generation,
        deployment_key,
        project_generation,
        project_key,
    )
    .map_err(|_| ClosedControllerReadbackSessionErrorV1::Stale)?;

    let observation = {
        let mut authority = journal.claim_protected_authority(RecordNamespace::DesiredState)?;
        super::binding_v2::ensure_root_binding_unheld(&authority)
            .map_err(|_| ClosedControllerReadbackSessionErrorV1::Stale)?;
        if authority.get(SIGNER_PINS_KEY)? != Some(policy_pins.as_slice())
            || authority.get(CONTROLLER_HOLD_PIN_KEY)? != Some(controller_credential)
            || authority.get(HEAD_KEY)? != Some(expected_deployment_head)
            || authority.get(HEAD_KEY_V2)? != Some(expected_project_head)
            || authority.get(INPUT_KEY_V2)? != Some(expected_project_input)
            || authority.get(PROJECT_HEAD_KEY)?.is_some()
            || authority.get(PROJECT_INPUT_KEY)?.is_some()
        {
            return Err(ClosedControllerReadbackSessionErrorV1::Stale);
        }
        if let Some(cache_pin) = authority.get(CACHE_PIN_KEY)? {
            let cache = PinnedCacheOwnerReadbackSignerV1::decode(cache_pin)
                .map_err(|_| ClosedControllerReadbackSessionErrorV1::Stale)?;
            if cache.verifying_key() == signer.verifying_key() {
                return Err(ClosedControllerReadbackSessionErrorV1::Stale);
            }
        }

        let (prior_epoch, prior_nonce) = CODEC
            .read_prior(authority.get(CHALLENGE_KEY)?)
            .ok_or(ClosedControllerReadbackSessionErrorV1::Stale)?;
        let epoch = prior_epoch
            .checked_add(1)
            .ok_or(ClosedControllerReadbackSessionErrorV1::Stale)?;
        let nonce =
            fresh_root_nonce().map_err(|_| ClosedControllerReadbackSessionErrorV1::Nonce)?;
        if nonce == [0; 16] || nonce == prior_nonce {
            return Err(ClosedControllerReadbackSessionErrorV1::Nonce);
        }
        let cut = root_cut(
            expected_deployment_head,
            expected_project_head,
            expected_project_input,
            &policy_pins,
            controller_credential,
            expected_owner_uid,
            expected_hold,
            epoch,
        );
        let readback = ControllerHoldReadbackChallengeV1::new(nonce, cut)?;
        let record = CODEC.encode(epoch, readback.nonce(), readback.cut());
        let transaction = CODEC.transaction(record)?;
        authority.commit(&transaction)?;
        if authority.get(CHALLENGE_KEY)? != Some(record.as_slice()) {
            return Err(ClosedControllerReadbackSessionErrorV1::Stale);
        }
        let snapshot = authority.snapshot()?;

        let challenge = ClosedControllerRootChallengeV1 { readback, epoch };
        let packet = exchange(challenge)?;
        let verified =
            verify_controller_hold_readback_v1(&packet, &signer, readback, expected_owner_uid)?;
        if !receipt_matches_hold(verified, expected_hold)
            || authority.get(CHALLENGE_KEY)? != Some(record.as_slice())
            || authority.get(CONTROLLER_HOLD_PIN_KEY)? != Some(controller_credential)
        {
            return Err(ClosedControllerReadbackSessionErrorV1::Stale);
        }
        authority.validate_snapshot_for_effect(&snapshot)?;
        ClosedControllerRootObservationV1 {
            readback: verified,
            packet_digest: ObjectDigest::from_bytes(Sha256::digest(packet).into()),
            epoch,
        }
    };
    check_named_location(journal)?;
    Ok(observation)
}

fn root_cut(
    deployment_head: &[u8],
    project_head: &[u8],
    project_input: &[u8],
    policy_pins: &[u8],
    controller_credential: &[u8],
    expected_owner_uid: u32,
    expected_hold: ControllerPolicyHoldV1,
    epoch: u64,
) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(CUT_DOMAIN)
            .chain_update(Sha256::digest(deployment_head))
            .chain_update(Sha256::digest(project_head))
            .chain_update(Sha256::digest(project_input))
            .chain_update(policy_pins)
            .chain_update(controller_credential)
            .chain_update(expected_owner_uid.to_be_bytes())
            .chain_update(expected_hold.operation().as_bytes())
            .chain_update(expected_hold.sandbox().as_bytes())
            .chain_update(expected_hold.source().as_bytes())
            .chain_update(expected_hold.binding().as_bytes())
            .chain_update(expected_hold.epoch().to_be_bytes())
            .chain_update(epoch.to_be_bytes())
            .finalize()
            .into(),
    )
}

fn receipt_matches_hold(
    receipt: VerifiedControllerHoldReadbackV1,
    expected: ControllerPolicyHoldV1,
) -> bool {
    receipt.operation() == expected.operation()
        && receipt.sandbox() == expected.sandbox()
        && receipt.source() == expected.source()
        && receipt.binding() == expected.binding()
        && receipt.epoch() == expected.epoch()
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    use aos_sandbox_core::{OperationId, SandboxId};
    use ed25519_dalek::SigningKey;

    use super::*;
    use crate::cache_residency::encode_cache_owner_readback_signer_credential_v1;
    use crate::journal::{JournalLimits, JournalRecord, JournalTransaction};
    use crate::policy_compiler::cache_readback_pin::admit_cache_readback_pin_in_journal_v1;
    use crate::policy_compiler::controller_hold_pin::admit_controller_hold_pin_in_journal_v1;
    use crate::policy_compiler::controller_hold_readback::{
        CLOSED_CONTROLLER_HOLD_READBACK_BYTES_V1, encode_controller_hold_signer_credential_v1,
        sign_test_controller_hold_readback_v1,
    };
    use crate::policy_compiler::deployment_head::admit_policy_signer_pins_in_journal_v1;

    const DEPLOYMENT_HEAD: &[u8] = b"root-admitted-deployment-head";
    const PROJECT_HEAD: &[u8] = b"root-admitted-explicit-project-head";
    const PROJECT_INPUT: &[u8] = b"root-admitted-explicit-project-input";
    const CONTROLLER_UID: u32 = 811;

    struct Fixture {
        directory: tempfile::TempDir,
        root: Journal,
        deployment: SigningKey,
        project: SigningKey,
        controller: SigningKey,
        credential: [u8; 80],
        hold: ControllerPolicyHoldV1,
    }

    impl Fixture {
        fn new() -> Self {
            let directory = tempfile::tempdir().expect("private root fixture");
            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
                .expect("private root mode");
            let root_uid = fs::metadata(directory.path())
                .expect("root directory")
                .uid();
            let (mut root, _) = Journal::open_protected_at_uid(
                directory.path(),
                "authority.journal",
                JournalLimits::default(),
                root_uid,
            )
            .expect("root journal");
            let deployment = SigningKey::from_bytes(&[1; 32]);
            let project = SigningKey::from_bytes(&[2; 32]);
            let controller = SigningKey::from_bytes(&[3; 32]);
            let credential =
                encode_controller_hold_signer_credential_v1(4, &controller.verifying_key())
                    .expect("Controller pin");
            let hold = ControllerPolicyHoldV1::new(
                OperationId::from_bytes([5; 16]),
                SandboxId::from_bytes([6; 16]),
                ObjectDigest::from_bytes([7; 32]),
                ObjectDigest::from_bytes([8; 32]),
                9,
            )
            .expect("expected hold");

            admit_policy_signer_pins_in_journal_v1(
                &mut root,
                2,
                &deployment.verifying_key(),
                3,
                &project.verifying_key(),
            )
            .expect("policy pins");
            admit_controller_hold_pin_in_journal_v1(
                &mut root,
                Some(&credential),
                2,
                &deployment.verifying_key(),
                3,
                &project.verifying_key(),
            )
            .expect("Controller pin admission");
            let cache = SigningKey::from_bytes(&[4; 32]);
            let cache_pin =
                encode_cache_owner_readback_signer_credential_v1(5, &cache.verifying_key())
                    .expect("Cache pin");
            admit_cache_readback_pin_in_journal_v1(
                &mut root,
                Some(&cache_pin),
                2,
                &deployment.verifying_key(),
                3,
                &project.verifying_key(),
            )
            .expect("Cache pin admission");
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
            root.commit(&JournalTransaction::new([10; 16], records).expect("source transaction"))
                .expect("source records");

            Self {
                directory,
                root,
                deployment,
                project,
                controller,
                credential,
                hold,
            }
        }

        fn run(
            &mut self,
            credential: &[u8],
            expected_hold: ControllerPolicyHoldV1,
            nonce: [u8; 16],
            exchange: impl FnOnce(ClosedControllerRootChallengeV1) -> io::Result<Vec<u8>>,
        ) -> Result<ClosedControllerRootObservationV1, ClosedControllerReadbackSessionErrorV1>
        {
            with_closed_controller_readback_session_in_journal_v1(
                &mut self.root,
                Journal::require_protected_names_current_for_test,
                DEPLOYMENT_HEAD,
                PROJECT_HEAD,
                PROJECT_INPUT,
                credential,
                2,
                &self.deployment.verifying_key(),
                3,
                &self.project.verifying_key(),
                CONTROLLER_UID,
                expected_hold,
                || Ok(nonce),
                exchange,
            )
        }
    }

    #[test]
    fn spent_challenge_replays_after_disconnect_and_rejects_old_receipts() {
        let mut fixture = Fixture::new();
        let pin = fixture.credential;
        let held = fixture.hold;
        let controller = fixture.controller.clone();
        assert!(matches!(
            fixture.run(&pin, held, [0; 16], |_| panic!("zero challenge was issued")),
            Err(ClosedControllerReadbackSessionErrorV1::Nonce)
        ));

        let mut first_packet = [0_u8; CLOSED_CONTROLLER_HOLD_READBACK_BYTES_V1];
        let root_path = fixture.directory.path().join("authority.journal");
        let first = fixture
            .run(&pin, held, [11; 16], |challenge| {
                assert_eq!(challenge.epoch(), 1);
                let committed = CODEC.encode(
                    challenge.epoch(),
                    challenge.readback().nonce(),
                    challenge.readback().cut(),
                );
                let journal_bytes = fs::read(&root_path).expect("persisted root journal");
                assert!(
                    journal_bytes
                        .windows(RECORD_BYTES)
                        .any(|row| row == committed.as_slice())
                );
                first_packet = sign_test_controller_hold_readback_v1(
                    held,
                    CONTROLLER_UID,
                    challenge.readback(),
                    4,
                    &controller,
                )
                .expect("signed Controller receipt");
                Ok(first_packet.to_vec())
            })
            .expect("verified Controller receipt");
        assert_eq!(first.epoch(), 1);
        assert_eq!(first.readback().binding(), held.binding());
        assert_eq!(
            first.packet_digest(),
            ObjectDigest::from_bytes(Sha256::digest(first_packet).into())
        );

        assert!(matches!(
            fixture.run(&pin, held, [11; 16], |_| panic!("reused nonce was issued")),
            Err(ClosedControllerReadbackSessionErrorV1::Nonce)
        ));
        assert!(matches!(
            fixture.run(&pin, held, [12; 16], |challenge| {
                assert_eq!(challenge.epoch(), 2);
                Ok(first_packet.to_vec())
            }),
            Err(ClosedControllerReadbackSessionErrorV1::Readback(
                ControllerHoldReadbackErrorV1::Stale
            ))
        ));
        assert!(matches!(
            fixture.run(&pin, held, [13; 16], |challenge| {
                assert_eq!(challenge.epoch(), 3);
                Err(io::Error::from(io::ErrorKind::BrokenPipe))
            }),
            Err(ClosedControllerReadbackSessionErrorV1::Transport(_))
        ));

        let Fixture {
            directory,
            root,
            deployment,
            project,
            controller,
            credential,
            hold,
        } = fixture;
        drop(root);
        let reopened = Journal::open_protected_at_uid(
            directory.path(),
            "authority.journal",
            JournalLimits::default(),
            fs::metadata(directory.path())
                .expect("root directory")
                .uid(),
        )
        .expect("reopened root")
        .0;
        let mut fixture = Fixture {
            directory,
            root: reopened,
            deployment,
            project,
            controller,
            credential,
            hold,
        };
        let controller = fixture.controller.clone();
        let fourth = fixture
            .run(&pin, held, [14; 16], |challenge| {
                assert_eq!(challenge.epoch(), 4);
                Ok(sign_test_controller_hold_readback_v1(
                    held,
                    CONTROLLER_UID,
                    challenge.readback(),
                    4,
                    &controller,
                )
                .expect("new Controller receipt")
                .to_vec())
            })
            .expect("cold monotonic challenge");
        assert_eq!(fourth.epoch(), 4);

        fixture
            .root
            .commit(
                &JournalTransaction::new(
                    [15; 16],
                    vec![JournalRecord::put(
                        RecordNamespace::DesiredState,
                        CHALLENGE_KEY.to_vec(),
                        b"corrupt prior challenge".to_vec(),
                    )],
                )
                .expect("corrupt record transaction"),
            )
            .expect("corrupt prior challenge fixture");
        assert!(matches!(
            fixture.run(&pin, held, [16; 16], |_| panic!(
                "malformed prior challenge was accepted"
            )),
            Err(ClosedControllerReadbackSessionErrorV1::Stale)
        ));
    }

    #[test]
    fn wrong_pin_hold_and_replaced_root_name_fail_closed() {
        let mut fixture = Fixture::new();
        let pin = fixture.credential;
        let held = fixture.hold;
        let controller = fixture.controller.clone();
        let rotated = encode_controller_hold_signer_credential_v1(5, &controller.verifying_key())
            .expect("rotated pin");
        assert!(matches!(
            fixture.run(&rotated, held, [21; 16], |_| panic!(
                "rotated pin was accepted"
            )),
            Err(ClosedControllerReadbackSessionErrorV1::Stale)
        ));
        let wrong_hold = ControllerPolicyHoldV1::new(
            held.operation(),
            held.sandbox(),
            held.source(),
            ObjectDigest::from_bytes([22; 32]),
            held.epoch(),
        )
        .expect("wrong binding");
        assert!(matches!(
            fixture.run(&pin, wrong_hold, [22; 16], |challenge| {
                Ok(sign_test_controller_hold_readback_v1(
                    held,
                    CONTROLLER_UID,
                    challenge.readback(),
                    4,
                    &controller,
                )
                .expect("signed original hold")
                .to_vec())
            }),
            Err(ClosedControllerReadbackSessionErrorV1::Stale)
        ));

        let impostor = SigningKey::from_bytes(&[24; 32]);
        assert!(matches!(
            fixture.run(&pin, held, [23; 16], |challenge| {
                Ok(sign_test_controller_hold_readback_v1(
                    held,
                    CONTROLLER_UID,
                    challenge.readback(),
                    4,
                    &impostor,
                )
                .expect("impostor receipt")
                .to_vec())
            }),
            Err(ClosedControllerReadbackSessionErrorV1::Readback(
                ControllerHoldReadbackErrorV1::Signature
            ))
        ));

        let directory = fixture.directory.path().to_path_buf();
        assert!(matches!(
            fixture.run(&pin, held, [25; 16], |challenge| {
                let packet = sign_test_controller_hold_readback_v1(
                    held,
                    CONTROLLER_UID,
                    challenge.readback(),
                    4,
                    &controller,
                )
                .expect("signed held receipt");
                let named = directory.join("authority.journal");
                let replacement = directory.join("replacement.journal");
                fs::copy(&named, &replacement).expect("identical replacement bytes");
                fs::rename(&replacement, &named).expect("replace root journal name");
                Ok(packet.to_vec())
            }),
            Err(ClosedControllerReadbackSessionErrorV1::Journal(_))
        ));
    }
}
