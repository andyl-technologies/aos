//! Nonauthorizing, same-challenge Controller, Source, and Cache readback.
//!
//! Root spends the shared AOSCTH01 epoch before requesting any owner receipt.
//! The cut commits to three distinct root-pinned public keys, exact expected
//! held identities, and signed policy-source bytes. The only Cache filesystem
//! access is the fixed read-only journal view. No current transport calls this
//! primitive, and no observation it returns admits Q04 or an effect.

use std::{io, path::Path};

use aos_sandbox_core::{ObjectDigest, ProjectId};
use ed25519_dalek::VerifyingKey;
use sha2::{Digest as _, Sha256};

use crate::cache_residency::{
    CacheOwnerReadbackChallengeV1, CacheOwnerReadbackErrorV1,
    CacheResidencyProtectedJournalErrorV1, PinnedCacheOwnerReadbackSignerV1,
    VerifiedClosedCacheOwnerReadbackV1, verify_closed_cache_owner_readback_v1,
};
use crate::journal::{
    CachePolicyHoldV1, ControllerPolicyHoldV1, Journal, JournalError, RecordNamespace,
    SourceDomainPolicyHoldV1,
};

use super::cache_journal_readback::read_fixed_policy_cache_hold_v1;
use super::cache_readback_pin::CACHE_PIN_KEY;
use super::controller_hold_pin::CONTROLLER_HOLD_PIN_KEY;
use super::controller_hold_readback::{
    ControllerHoldReadbackChallengeV1, ControllerHoldReadbackErrorV1, PinnedControllerHoldSignerV1,
    verify_controller_hold_readback_v1,
};
use super::controller_readback_session::{CHALLENGE_KEY, CODEC, fresh_root_nonce};
use super::deployment_head::{
    HEAD_KEY, PROJECT_HEAD_KEY, PROJECT_INPUT_KEY, SIGNER_PINS_KEY, encode_policy_signer_pins_v1,
};
use super::project_source_v2::{HEAD_KEY_V2, INPUT_KEY_V2};
use super::protected_owner::{
    POLICY_AUTHORITY_JOURNAL, PROTECTED_POLICY_ROOT, policy_authority_journal_limits,
};
use super::source_hold_pin::SOURCE_HOLD_PIN_KEY;
use super::source_hold_readback::{
    PinnedSourceHoldReadbackSignerV1, SourceHoldReadbackChallengeV1, SourceHoldReadbackErrorV1,
    verify_current_source_hold_readback_v1,
};

const CUT_DOMAIN: &[u8] = b"aos.sandbox.policy-all-owner-readback-root-cut.v1\0";

/// Reports a rejected nonauthorizing all-owner readback.
#[derive(Debug, thiserror::Error)]
pub enum ClosedAllOwnerReadbackErrorV1 {
    /// A root source, pin, held identity, or challenge is stale.
    #[error("closed all-owner readback is stale")]
    Stale,
    /// Root entropy failed or repeated an unusable nonce.
    #[error("closed all-owner root nonce is invalid")]
    Nonce,
    /// Protected root journal custody, replay, or commit failed.
    #[error(transparent)]
    Journal(#[from] JournalError),
    /// The Controller receipt is malformed or unauthenticated.
    #[error(transparent)]
    Controller(#[from] ControllerHoldReadbackErrorV1),
    /// The Source receipt is malformed or unauthenticated.
    #[error(transparent)]
    Source(#[from] SourceHoldReadbackErrorV1),
    /// The Cache-purpose receipt is malformed or unauthenticated.
    #[error(transparent)]
    Cache(#[from] CacheOwnerReadbackErrorV1),
    /// The fixed read-only Cache journal view failed replay.
    #[error(transparent)]
    CacheJournal(#[from] CacheResidencyProtectedJournalErrorV1),
    /// An owner transport failed after the challenge was spent.
    #[error(transparent)]
    Transport(#[from] io::Error),
}

/// Fixes three independently expected held identities before root spends.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClosedAllOwnerExpectedHoldsV1 {
    /// Names the project bound by Source and Cache evidence.
    pub project: ProjectId,
    /// Names the exact Controller hold.
    pub controller: ControllerPolicyHoldV1,
    /// Names the exact Source hold and ancestry.
    pub source: SourceDomainPolicyHoldV1,
    /// Names the exact protected Cache hold and replay head.
    pub cache: CachePolicyHoldV1,
    /// Names the independently configured Controller owner UID.
    pub controller_uid: u32,
    /// Names the independently configured Cache physical owner UID.
    pub cache_uid: u32,
}

impl ClosedAllOwnerExpectedHoldsV1 {
    fn is_consistent(self) -> bool {
        self.project.as_bytes() != &[0; 16]
            && self.controller_uid != 0
            && self.cache_uid != 0
            && self.controller.is_held()
            && self.source.is_held()
            && self.cache.is_held()
            && self.controller.operation() == self.source.operation()
            && self.controller.sandbox() == self.source.sandbox()
            && self.controller.source() == self.source.controller_source()
            && self.controller.binding() == self.source.binding()
            && self.controller.binding() == self.cache.binding()
            && self.controller.epoch() == self.source.epoch()
            && self.controller.epoch() == self.cache.epoch()
            && self.project == self.cache.project()
    }
}

/// Carries one already-spent root challenge to all three purpose signers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClosedAllOwnerRootChallengeV1 {
    nonce: [u8; 16],
    cut: ObjectDigest,
    epoch: u64,
}

impl ClosedAllOwnerRootChallengeV1 {
    /// Returns the exact nonce and cut to be signed by each owner.
    #[must_use]
    pub const fn nonce(self) -> [u8; 16] {
        self.nonce
    }

    /// Returns the root-authenticated cut shared by the three receipts.
    #[must_use]
    pub const fn cut(self) -> ObjectDigest {
        self.cut
    }

    /// Returns the durably spent root challenge epoch.
    #[must_use]
    pub const fn epoch(self) -> u64 {
        self.epoch
    }
}

/// Carries three independent signed responses for one root challenge.
pub struct ClosedAllOwnerReadbackPacketsV1 {
    /// Contains the AOSCTW01 Controller receipt.
    pub controller: Vec<u8>,
    /// Contains the AOSSRB01 Source receipt.
    pub source: Vec<u8>,
    /// Contains the AOSCRB01 physical Cache receipt.
    pub cache: Vec<u8>,
}

/// Reports evidence only; it cannot be promoted into Q04 authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClosedAllOwnerRootObservationV1 {
    /// Identifies the spent root challenge epoch.
    pub epoch: u64,
    /// Commits to the exact Controller signed packet.
    pub controller_packet: ObjectDigest,
    /// Commits to the exact Source signed packet.
    pub source_packet: ObjectDigest,
    /// Commits to the exact Cache signed packet.
    pub cache_packet: ObjectDigest,
    /// Carries the separately verified physical Cache statement.
    pub physical_cache: VerifiedClosedCacheOwnerReadbackV1,
    /// Carries the exact read-only protected Cache hold observation.
    pub cache_hold: CachePolicyHoldV1,
}

/// Spends one root challenge before accepting three independently signed receipts.
///
/// The caller must supply fixed privileged public-key credentials, not request
/// bytes. Root retains only its own journal writer and replays Cache's fixed
/// read-only view; it never mounts Source/Controller journals or holds owner
/// writers. An exchange callback must not acquire a new hold that it cannot
/// release on error. A successful observation is still not a simultaneous
/// all-owner writer cut, CAS, release, or crash recovery.
///
/// # Errors
///
/// Rejects missing, changed, or reused root pins, mismatched holds, invalid
/// nonce or durable spend, transport failure, bad signatures, stale Cache
/// replay, changed root records, or changed protected root journal names.
#[allow(clippy::too_many_arguments)]
pub fn with_fixed_closed_all_owner_readback_session_v1(
    expected_deployment_head: &[u8],
    expected_project_head: &[u8],
    expected_project_input: &[u8],
    controller_credential: &[u8],
    source_credential: &[u8],
    cache_credential: &[u8],
    deployment_generation: u64,
    deployment_key: &VerifyingKey,
    project_generation: u64,
    project_key: &VerifyingKey,
    expected: ClosedAllOwnerExpectedHoldsV1,
    exchange: impl FnOnce(ClosedAllOwnerRootChallengeV1) -> io::Result<ClosedAllOwnerReadbackPacketsV1>,
) -> Result<ClosedAllOwnerRootObservationV1, ClosedAllOwnerReadbackErrorV1> {
    let root = Path::new(PROTECTED_POLICY_ROOT);
    let limits = policy_authority_journal_limits();
    let (mut journal, _) = Journal::open_protected_at(root, POLICY_AUTHORITY_JOURNAL, limits)?;
    with_closed_all_owner_readback_session_in_journal_v1(
        &mut journal,
        |journal| {
            journal.require_protected_named_location(root, POLICY_AUTHORITY_JOURNAL, 0, limits)
        },
        expected_deployment_head,
        expected_project_head,
        expected_project_input,
        controller_credential,
        source_credential,
        cache_credential,
        deployment_generation,
        deployment_key,
        project_generation,
        project_key,
        expected,
        fresh_root_nonce,
        exchange,
        || Ok(read_fixed_policy_cache_hold_v1()?.hold),
    )
}

#[allow(clippy::too_many_arguments)]
fn with_closed_all_owner_readback_session_in_journal_v1(
    journal: &mut Journal,
    check_named_location: impl Fn(&Journal) -> Result<(), JournalError>,
    expected_deployment_head: &[u8],
    expected_project_head: &[u8],
    expected_project_input: &[u8],
    controller_credential: &[u8],
    source_credential: &[u8],
    cache_credential: &[u8],
    deployment_generation: u64,
    deployment_key: &VerifyingKey,
    project_generation: u64,
    project_key: &VerifyingKey,
    expected: ClosedAllOwnerExpectedHoldsV1,
    fresh_nonce: impl FnOnce() -> io::Result<[u8; 16]>,
    exchange: impl FnOnce(ClosedAllOwnerRootChallengeV1) -> io::Result<ClosedAllOwnerReadbackPacketsV1>,
    read_cache_hold: impl FnOnce() -> Result<CachePolicyHoldV1, CacheResidencyProtectedJournalErrorV1>,
) -> Result<ClosedAllOwnerRootObservationV1, ClosedAllOwnerReadbackErrorV1> {
    check_named_location(journal)?;
    let controller = PinnedControllerHoldSignerV1::decode(controller_credential)?;
    let source = PinnedSourceHoldReadbackSignerV1::decode(source_credential)?;
    let cache = PinnedCacheOwnerReadbackSignerV1::decode(cache_credential)?;
    let keys = [
        deployment_key.as_bytes(),
        project_key.as_bytes(),
        controller.verifying_key().as_bytes(),
        source.verifying_key().as_bytes(),
        cache.verifying_key().as_bytes(),
    ];
    if !expected.is_consistent()
        || keys
            .iter()
            .enumerate()
            .any(|(index, key)| keys[..index].contains(key))
    {
        return Err(ClosedAllOwnerReadbackErrorV1::Stale);
    }
    let policy_pins = encode_policy_signer_pins_v1(
        deployment_generation,
        deployment_key,
        project_generation,
        project_key,
    )
    .map_err(|_| ClosedAllOwnerReadbackErrorV1::Stale)?;

    let observation = {
        let mut authority = journal.claim_protected_authority(RecordNamespace::DesiredState)?;
        super::binding_v2::ensure_root_binding_unheld(&authority)
            .map_err(|_| ClosedAllOwnerReadbackErrorV1::Stale)?;
        if authority.get(SIGNER_PINS_KEY)? != Some(policy_pins.as_slice())
            || authority.get(CONTROLLER_HOLD_PIN_KEY)? != Some(controller_credential)
            || authority.get(SOURCE_HOLD_PIN_KEY)? != Some(source_credential)
            || authority.get(CACHE_PIN_KEY)? != Some(cache_credential)
            || authority.get(HEAD_KEY)? != Some(expected_deployment_head)
            || authority.get(HEAD_KEY_V2)? != Some(expected_project_head)
            || authority.get(INPUT_KEY_V2)? != Some(expected_project_input)
            || authority.get(PROJECT_HEAD_KEY)?.is_some()
            || authority.get(PROJECT_INPUT_KEY)?.is_some()
        {
            return Err(ClosedAllOwnerReadbackErrorV1::Stale);
        }

        let (prior_epoch, prior_nonce) = CODEC
            .read_prior(authority.get(CHALLENGE_KEY)?)
            .ok_or(ClosedAllOwnerReadbackErrorV1::Stale)?;
        let epoch = prior_epoch
            .checked_add(1)
            .ok_or(ClosedAllOwnerReadbackErrorV1::Stale)?;
        let nonce = fresh_nonce().map_err(|_| ClosedAllOwnerReadbackErrorV1::Nonce)?;
        if nonce == [0; 16] || nonce == prior_nonce {
            return Err(ClosedAllOwnerReadbackErrorV1::Nonce);
        }
        let cut = root_cut(
            expected_deployment_head,
            expected_project_head,
            expected_project_input,
            &policy_pins,
            controller_credential,
            source_credential,
            cache_credential,
            expected,
            epoch,
        );
        let controller_challenge = ControllerHoldReadbackChallengeV1::new(nonce, cut)?;
        let source_challenge = SourceHoldReadbackChallengeV1::new(nonce, cut)?;
        let cache_challenge = CacheOwnerReadbackChallengeV1::new(nonce, cut)?;
        let record = CODEC.encode(epoch, nonce, cut);
        let transaction = CODEC.transaction(record)?;
        authority.commit(&transaction)?;
        if authority.get(CHALLENGE_KEY)? != Some(record.as_slice()) {
            return Err(ClosedAllOwnerReadbackErrorV1::Stale);
        }
        let snapshot = authority.snapshot()?;

        let packets = exchange(ClosedAllOwnerRootChallengeV1 { nonce, cut, epoch })?;
        let controller_receipt = verify_controller_hold_readback_v1(
            &packets.controller,
            &controller,
            controller_challenge,
            expected.controller_uid,
        )?;
        if controller_receipt.operation() != expected.controller.operation()
            || controller_receipt.sandbox() != expected.controller.sandbox()
            || controller_receipt.source() != expected.controller.source()
            || controller_receipt.binding() != expected.controller.binding()
            || controller_receipt.epoch() != expected.controller.epoch()
        {
            return Err(ClosedAllOwnerReadbackErrorV1::Stale);
        }
        verify_current_source_hold_readback_v1(
            &packets.source,
            &source,
            source_challenge,
            expected.project,
            expected.source,
        )?;
        let physical_cache = verify_closed_cache_owner_readback_v1(
            &packets.cache,
            &cache,
            cache_challenge,
            expected.cache_uid,
        )?;
        let cache_hold = read_cache_hold()?;
        if cache_hold != expected.cache
            || authority.get(CHALLENGE_KEY)? != Some(record.as_slice())
            || authority.get(CONTROLLER_HOLD_PIN_KEY)? != Some(controller_credential)
            || authority.get(SOURCE_HOLD_PIN_KEY)? != Some(source_credential)
            || authority.get(CACHE_PIN_KEY)? != Some(cache_credential)
        {
            return Err(ClosedAllOwnerReadbackErrorV1::Stale);
        }
        authority.validate_snapshot_for_effect(&snapshot)?;
        ClosedAllOwnerRootObservationV1 {
            epoch,
            controller_packet: ObjectDigest::from_bytes(Sha256::digest(&packets.controller).into()),
            source_packet: ObjectDigest::from_bytes(Sha256::digest(&packets.source).into()),
            cache_packet: ObjectDigest::from_bytes(Sha256::digest(&packets.cache).into()),
            physical_cache,
            cache_hold,
        }
    };
    check_named_location(journal)?;
    Ok(observation)
}

#[allow(clippy::too_many_arguments)]
fn root_cut(
    deployment_head: &[u8],
    project_head: &[u8],
    project_input: &[u8],
    policy_pins: &[u8],
    controller_pin: &[u8],
    source_pin: &[u8],
    cache_pin: &[u8],
    expected: ClosedAllOwnerExpectedHoldsV1,
    challenge_epoch: u64,
) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(CUT_DOMAIN)
            .chain_update(Sha256::digest(deployment_head))
            .chain_update(Sha256::digest(project_head))
            .chain_update(Sha256::digest(project_input))
            .chain_update(policy_pins)
            .chain_update(controller_pin)
            .chain_update(source_pin)
            .chain_update(cache_pin)
            .chain_update(expected.project.as_bytes())
            .chain_update(expected.controller_uid.to_be_bytes())
            .chain_update(expected.cache_uid.to_be_bytes())
            .chain_update(expected.controller.operation().as_bytes())
            .chain_update(expected.controller.sandbox().as_bytes())
            .chain_update(expected.controller.source().as_bytes())
            .chain_update(expected.source.ancestry().as_bytes())
            .chain_update(expected.cache.partition().as_bytes())
            .chain_update(expected.cache.cache_head().as_bytes())
            .chain_update(expected.controller.binding().as_bytes())
            .chain_update(expected.controller.epoch().to_be_bytes())
            .chain_update(challenge_epoch.to_be_bytes())
            .finalize()
            .into(),
    )
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    use aos_sandbox_core::{OperationId, SandboxId};
    use ed25519_dalek::SigningKey;

    use super::*;
    use crate::cache_residency::{
        encode_cache_owner_readback_signer_credential_v1, sign_test_cache_owner_readback_v1,
        sign_test_cache_owner_readback_with_manifest_v1,
    };
    use crate::journal::{JournalLimits, JournalRecord, JournalTransaction};
    use crate::policy_compiler::cache_readback_pin::admit_cache_readback_pin_in_journal_v1;
    use crate::policy_compiler::controller_hold_pin::admit_controller_hold_pin_in_journal_v1;
    use crate::policy_compiler::controller_hold_readback::{
        encode_controller_hold_signer_credential_v1, sign_test_controller_hold_readback_v1,
    };
    use crate::policy_compiler::deployment_head::admit_policy_signer_pins_in_journal_v1;
    use crate::policy_compiler::source_hold_pin::admit_source_hold_pin_in_journal_v1;
    use crate::policy_compiler::source_hold_readback::{
        encode_source_hold_readback_signer_credential_v1, sign_test_source_hold_readback_v1,
    };

    const DEPLOYMENT_HEAD: &[u8] = b"root-deployment-head";
    const PROJECT_HEAD: &[u8] = b"root-explicit-project-head";
    const PROJECT_INPUT: &[u8] = b"root-explicit-project-input";

    struct Fixture {
        directory: tempfile::TempDir,
        root: Option<Journal>,
        deployment: SigningKey,
        project: SigningKey,
        controller: SigningKey,
        source: SigningKey,
        cache: SigningKey,
        controller_pin: [u8; 80],
        source_pin: [u8; 80],
        cache_pin: [u8; 80],
        expected: ClosedAllOwnerExpectedHoldsV1,
    }

    impl Fixture {
        fn new() -> Self {
            let directory = tempfile::tempdir().expect("private root fixture");
            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
                .expect("private root mode");
            let uid = fs::metadata(directory.path()).expect("root metadata").uid();
            let (mut root, _) = Journal::open_protected_at_uid(
                directory.path(),
                "authority.journal",
                JournalLimits::default(),
                uid,
            )
            .expect("root journal");
            let deployment = SigningKey::from_bytes(&[1; 32]);
            let project = SigningKey::from_bytes(&[2; 32]);
            let controller = SigningKey::from_bytes(&[3; 32]);
            let source = SigningKey::from_bytes(&[4; 32]);
            let cache = SigningKey::from_bytes(&[5; 32]);
            let controller_pin =
                encode_controller_hold_signer_credential_v1(3, &controller.verifying_key())
                    .expect("Controller pin");
            let source_pin =
                encode_source_hold_readback_signer_credential_v1(4, &source.verifying_key())
                    .expect("Source pin");
            let cache_pin =
                encode_cache_owner_readback_signer_credential_v1(5, &cache.verifying_key())
                    .expect("Cache pin");
            let project_id = ProjectId::from_bytes([6; 16]);
            let operation = OperationId::from_bytes([7; 16]);
            let sandbox = SandboxId::from_bytes([8; 16]);
            let source_digest = ObjectDigest::from_bytes([9; 32]);
            let binding = ObjectDigest::from_bytes([10; 32]);
            let controller_hold =
                ControllerPolicyHoldV1::new(operation, sandbox, source_digest, binding, 11)
                    .expect("Controller hold");
            let source_hold = SourceDomainPolicyHoldV1::new(
                operation,
                sandbox,
                source_digest,
                ObjectDigest::from_bytes([12; 32]),
                binding,
                11,
            )
            .expect("Source hold");
            let cache_hold = CachePolicyHoldV1::new(
                project_id,
                ObjectDigest::from_bytes([13; 32]),
                ObjectDigest::from_bytes([14; 32]),
                binding,
                11,
            )
            .expect("Cache hold");
            let expected = ClosedAllOwnerExpectedHoldsV1 {
                project: project_id,
                controller: controller_hold,
                source: source_hold,
                cache: cache_hold,
                controller_uid: 811,
                cache_uid: 812,
            };
            admit_policy_signer_pins_in_journal_v1(
                &mut root,
                1,
                &deployment.verifying_key(),
                2,
                &project.verifying_key(),
            )
            .expect("policy pins");
            admit_controller_hold_pin_in_journal_v1(
                &mut root,
                Some(&controller_pin),
                1,
                &deployment.verifying_key(),
                2,
                &project.verifying_key(),
            )
            .expect("Controller pin admission");
            admit_cache_readback_pin_in_journal_v1(
                &mut root,
                Some(&cache_pin),
                1,
                &deployment.verifying_key(),
                2,
                &project.verifying_key(),
            )
            .expect("Cache pin admission");
            admit_source_hold_pin_in_journal_v1(
                &mut root,
                Some(&source_pin),
                1,
                &deployment.verifying_key(),
                2,
                &project.verifying_key(),
            )
            .expect("Source pin admission");
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
            root.commit(&JournalTransaction::new([15; 16], records).expect("source transaction"))
                .expect("source records");

            Self {
                directory,
                root: Some(root),
                deployment,
                project,
                controller,
                source,
                cache,
                controller_pin,
                source_pin,
                cache_pin,
                expected,
            }
        }

        fn run(
            &mut self,
            source_pin: &[u8],
            expected: ClosedAllOwnerExpectedHoldsV1,
            nonce: [u8; 16],
            exchange: impl FnOnce(
                ClosedAllOwnerRootChallengeV1,
            ) -> io::Result<ClosedAllOwnerReadbackPacketsV1>,
            read_cache: impl FnOnce()
                -> Result<CachePolicyHoldV1, CacheResidencyProtectedJournalErrorV1>,
        ) -> Result<ClosedAllOwnerRootObservationV1, ClosedAllOwnerReadbackErrorV1> {
            with_closed_all_owner_readback_session_in_journal_v1(
                self.root.as_mut().expect("open root fixture"),
                Journal::require_protected_names_current_for_test,
                DEPLOYMENT_HEAD,
                PROJECT_HEAD,
                PROJECT_INPUT,
                &self.controller_pin,
                source_pin,
                &self.cache_pin,
                1,
                &self.deployment.verifying_key(),
                2,
                &self.project.verifying_key(),
                expected,
                || Ok(nonce),
                exchange,
                read_cache,
            )
        }

        fn reopen(&mut self) {
            drop(self.root.take());
            let uid = fs::metadata(self.directory.path())
                .expect("root metadata")
                .uid();
            let replacement = Journal::open_protected_at_uid(
                self.directory.path(),
                "authority.journal",
                JournalLimits::default(),
                uid,
            )
            .expect("replay root journal")
            .0;
            self.root = Some(replacement);
        }
    }

    fn signed_packets(
        challenge: ClosedAllOwnerRootChallengeV1,
        expected: ClosedAllOwnerExpectedHoldsV1,
        controller: &SigningKey,
        source: &SigningKey,
        cache: &SigningKey,
    ) -> ClosedAllOwnerReadbackPacketsV1 {
        let controller_challenge =
            ControllerHoldReadbackChallengeV1::new(challenge.nonce(), challenge.cut()).unwrap();
        let source_challenge =
            SourceHoldReadbackChallengeV1::new(challenge.nonce(), challenge.cut()).unwrap();
        let cache_challenge =
            CacheOwnerReadbackChallengeV1::new(challenge.nonce(), challenge.cut()).unwrap();
        ClosedAllOwnerReadbackPacketsV1 {
            controller: sign_test_controller_hold_readback_v1(
                expected.controller,
                expected.controller_uid,
                controller_challenge,
                3,
                controller,
            )
            .unwrap()
            .to_vec(),
            source: sign_test_source_hold_readback_v1(
                source_challenge,
                expected.project,
                expected.source,
                4,
                source,
            )
            .to_vec(),
            cache: sign_test_cache_owner_readback_v1(cache_challenge, 5, cache, expected.cache_uid)
                .unwrap()
                .to_vec(),
        }
    }

    #[test]
    fn challenge_spends_before_exchange_and_cannot_replay_after_reopen() {
        let mut fixture = Fixture::new();
        let expected = fixture.expected;
        let source_pin = fixture.source_pin;
        let controller = fixture.controller.clone();
        let source = fixture.source.clone();
        let cache = fixture.cache.clone();
        let root_path = fixture.directory.path().join("authority.journal");
        let mut stale_packets = None;

        assert!(matches!(
            fixture.run(
                &source_pin,
                expected,
                [0; 16],
                |_| panic!("zero challenge issued"),
                || Ok(expected.cache)
            ),
            Err(ClosedAllOwnerReadbackErrorV1::Nonce)
        ));
        let first = fixture.run(
            &source_pin,
            expected,
            [16; 16],
            |challenge| {
                assert_eq!(challenge.epoch(), 1);
                let record = CODEC.encode(challenge.epoch(), challenge.nonce(), challenge.cut());
                assert!(
                    fs::read(&root_path)
                        .unwrap()
                        .windows(record.len())
                        .any(|bytes| bytes == record)
                );
                stale_packets = Some(signed_packets(
                    challenge,
                    expected,
                    &controller,
                    &source,
                    &cache,
                ));
                Err(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "owner disconnected",
                ))
            },
            || Ok(expected.cache),
        );
        assert!(matches!(
            first,
            Err(ClosedAllOwnerReadbackErrorV1::Transport(_))
        ));
        fixture.reopen();
        assert!(matches!(
            fixture.run(
                &source_pin,
                expected,
                [16; 16],
                |_| panic!("reused challenge issued"),
                || Ok(expected.cache)
            ),
            Err(ClosedAllOwnerReadbackErrorV1::Nonce)
        ));
        let stale_packets = stale_packets.expect("first signed packets");
        assert!(matches!(
            fixture.run(
                &source_pin,
                expected,
                [17; 16],
                |_| Ok(stale_packets),
                || Ok(expected.cache)
            ),
            Err(ClosedAllOwnerReadbackErrorV1::Controller(_))
        ));
        let observation = fixture
            .run(
                &source_pin,
                expected,
                [18; 16],
                |challenge| {
                    Ok(signed_packets(
                        challenge,
                        expected,
                        &controller,
                        &source,
                        &cache,
                    ))
                },
                || Ok(expected.cache),
            )
            .expect("same-challenge three-owner observation");
        assert_eq!(observation.epoch, 3);
        assert_eq!(observation.cache_hold, expected.cache);
    }

    #[test]
    fn physical_manifest_changes_are_not_joined_to_the_protected_cache_hold() {
        let mut fixture = Fixture::new();
        let expected = fixture.expected;
        let source_pin = fixture.source_pin;
        let controller = fixture.controller.clone();
        let source = fixture.source.clone();
        let cache = fixture.cache.clone();

        let first = fixture
            .run(
                &source_pin,
                expected,
                [31; 16],
                |challenge| {
                    Ok(signed_packets(
                        challenge,
                        expected,
                        &controller,
                        &source,
                        &cache,
                    ))
                },
                || Ok(expected.cache),
            )
            .expect("first nonauthorizing observation");
        let replacement_digest = ObjectDigest::from_bytes([32; 32]);
        let second = fixture
            .run(
                &source_pin,
                expected,
                [33; 16],
                |challenge| {
                    let mut packets =
                        signed_packets(challenge, expected, &controller, &source, &cache);
                    let cache_challenge =
                        CacheOwnerReadbackChallengeV1::new(challenge.nonce(), challenge.cut())
                            .expect("cache challenge");
                    packets.cache = sign_test_cache_owner_readback_with_manifest_v1(
                        cache_challenge,
                        5,
                        &cache,
                        expected.cache_uid,
                        replacement_digest,
                    )
                    .expect("changed physical manifest statement")
                    .to_vec();
                    Ok(packets)
                },
                || Ok(expected.cache),
            )
            .expect("second nonauthorizing observation");

        assert_eq!(first.cache_hold, second.cache_hold);
        assert_ne!(
            first.physical_cache.manifest_head(),
            second.physical_cache.manifest_head()
        );
        assert_eq!(second.physical_cache.manifest_head().1, replacement_digest);
    }

    #[test]
    fn missing_pin_bad_source_and_wrong_cache_hold_fail_closed() {
        let mut fixture = Fixture::new();
        let expected = fixture.expected;
        let source_pin = fixture.source_pin;
        let controller = fixture.controller.clone();
        let source = fixture.source.clone();
        let cache = fixture.cache.clone();
        let root_path = fixture.directory.path().join("authority.journal");
        let before = fs::read(&root_path).unwrap();
        let rotated =
            encode_source_hold_readback_signer_credential_v1(5, &source.verifying_key()).unwrap();
        assert!(matches!(
            fixture.run(
                &rotated,
                expected,
                [19; 16],
                |_| panic!("unadmitted pin issued"),
                || Ok(expected.cache)
            ),
            Err(ClosedAllOwnerReadbackErrorV1::Stale)
        ));
        assert_eq!(fs::read(&root_path).unwrap(), before);

        assert!(matches!(
            fixture.run(
                &source_pin,
                expected,
                [20; 16],
                |challenge| {
                    let mut packets =
                        signed_packets(challenge, expected, &controller, &source, &cache);
                    packets.source[100] ^= 1;
                    Ok(packets)
                },
                || panic!("bad Source accepted before Cache replay"),
            ),
            Err(ClosedAllOwnerReadbackErrorV1::Source(_))
        ));
        assert!(matches!(
            fixture.run(
                &source_pin,
                expected,
                [21; 16],
                |challenge| {
                    let mut packets =
                        signed_packets(challenge, expected, &controller, &source, &cache);
                    let source_challenge =
                        SourceHoldReadbackChallengeV1::new(challenge.nonce(), challenge.cut())
                            .unwrap();
                    packets.source = sign_test_source_hold_readback_v1(
                        source_challenge,
                        expected.project,
                        expected.source,
                        5,
                        &source,
                    )
                    .to_vec();
                    Ok(packets)
                },
                || panic!("wrong Source generation accepted before Cache replay"),
            ),
            Err(ClosedAllOwnerReadbackErrorV1::Source(_))
        ));
        let wrong_cache = CachePolicyHoldV1::new(
            expected.project,
            expected.cache.partition(),
            expected.cache.cache_head(),
            ObjectDigest::from_bytes([21; 32]),
            expected.cache.epoch(),
        )
        .unwrap();
        assert!(matches!(
            fixture.run(
                &source_pin,
                expected,
                [22; 16],
                |challenge| Ok(signed_packets(
                    challenge,
                    expected,
                    &controller,
                    &source,
                    &cache
                )),
                || Ok(wrong_cache),
            ),
            Err(ClosedAllOwnerReadbackErrorV1::Stale)
        ));
        assert!(matches!(
            fixture.run(
                &source_pin,
                expected,
                [23; 16],
                |challenge| {
                    let mut packets =
                        signed_packets(challenge, expected, &controller, &source, &cache);
                    packets.cache[120] ^= 1;
                    Ok(packets)
                },
                || panic!("bad Cache signature accepted before journal replay"),
            ),
            Err(ClosedAllOwnerReadbackErrorV1::Cache(_))
        ));
    }
}
