//! Reexports canonical signed Source hold comparison DATA and verification.
//!
//! The actual fixed Source signer owns native custody and signing in
//! `aos-sandbox-source`. These shared wire validators grant no protected
//! writer, key custody, Root challenge consumption, or effect authority.
//!
//! ```text
//! AOSSRB01 | version:u16 | reserved[6]=0 | signer-generation:u64 |
//! nonce[16] | root-cut[32] | project[16] | operation[16] | sandbox[16] |
//! controller-source[32] | ancestry[32] | binding[32] | epoch:u64 |
//! Ed25519 signature[64]
//!
//! AOSSPK01 | signer-generation:u64 | Ed25519 public key[32] |
//! SHA-256(Source-key-domain || preceding 48 bytes)[32]
//! ```

#[cfg(test)]
use aos_sandbox_protocol::domain_ledger::source_policy_hold::SourceDomainPolicyHoldV1;

#[cfg(test)]
use aos_sandbox_model::{ObjectDigest, ProjectId};
#[cfg(test)]
use ed25519_dalek::{Signer as _, SigningKey};

pub use aos_sandbox_ledger_replay::source_signer_data::source_hold_readback::*;

#[cfg(test)]
pub(super) fn sign_test_source_hold_readback_v1(
    challenge: SourceHoldReadbackChallengeV1,
    project: ProjectId,
    hold: SourceDomainPolicyHoldV1,
    generation: u64,
    signing_key: &SigningKey,
) -> [u8; SOURCE_HOLD_READBACK_BYTES_V1] {
    sign_fields(challenge, project, hold, generation, signing_key)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    use aos_sandbox_model::{OperationId, SandboxId};
    use crate::source_domain::ProtectedSourceDomainJournalOwnerV1;
    use aos_sandbox_source::signer_comparison::replay_source_hold;

    use super::*;

    #[test]
    fn source_witness_rejects_substitution_and_foreign_keys() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let credential = encode_source_hold_readback_signer_credential_v1(3, &key.verifying_key())
            .expect("credential");
        let signer = PinnedSourceHoldReadbackSignerV1::decode(&credential).expect("pin");
        let challenge =
            SourceHoldReadbackChallengeV1::new([4; 16], ObjectDigest::from_bytes([5; 32]))
                .expect("challenge");
        let project = ProjectId::from_bytes([6; 16]);
        let hold = SourceDomainPolicyHoldV1::new(
            OperationId::from_bytes([1; 16]),
            SandboxId::from_bytes([2; 16]),
            ObjectDigest::from_bytes([3; 32]),
            ObjectDigest::from_bytes([8; 32]),
            ObjectDigest::from_bytes([9; 32]),
            11,
        )
        .expect("hold");
        let mut packet = [0; SOURCE_HOLD_READBACK_BYTES_V1];
        packet[..8].copy_from_slice(MAGIC);
        packet[8..10].copy_from_slice(&1_u16.to_be_bytes());
        packet[16..24].copy_from_slice(&3_u64.to_be_bytes());
        packet[24..40].copy_from_slice(&challenge.nonce());
        packet[40..72].copy_from_slice(challenge.cut().as_bytes());
        packet[72..88].copy_from_slice(project.as_bytes());
        packet[88..104].copy_from_slice(hold.operation().as_bytes());
        packet[104..120].copy_from_slice(hold.sandbox().as_bytes());
        packet[120..152].copy_from_slice(hold.controller_source().as_bytes());
        packet[152..184].copy_from_slice(hold.ancestry().as_bytes());
        packet[184..216].copy_from_slice(hold.binding().as_bytes());
        packet[216..224].copy_from_slice(&hold.epoch().to_be_bytes());
        let signature = key.sign(&signature_preimage(&packet[..BODY_BYTES]));
        packet[BODY_BYTES..].copy_from_slice(&signature.to_bytes());
        assert_eq!(sign_fields(challenge, project, hold, 3, &key), packet);
        verify_current_source_hold_readback_v1(&packet, &signer, challenge, project, hold)
            .expect("exact witness");

        let wrong_hold = SourceDomainPolicyHoldV1::new(
            hold.operation(),
            hold.sandbox(),
            hold.controller_source(),
            hold.ancestry(),
            hold.binding(),
            hold.epoch() + 1,
        )
        .expect("different epoch");
        assert!(
            verify_current_source_hold_readback_v1(
                &packet, &signer, challenge, project, wrong_hold
            )
            .is_err()
        );

        let wrong_challenge =
            SourceHoldReadbackChallengeV1::new([10; 16], ObjectDigest::from_bytes([5; 32]))
                .expect("challenge");
        assert!(
            verify_current_source_hold_readback_v1(
                &packet,
                &signer,
                wrong_challenge,
                project,
                hold
            )
            .is_err()
        );
        assert!(
            verify_current_source_hold_readback_v1(
                &packet,
                &signer,
                challenge,
                ProjectId::from_bytes([11; 16]),
                hold,
            )
            .is_err()
        );
        packet[184] ^= 1;
        assert!(
            verify_current_source_hold_readback_v1(&packet, &signer, challenge, project, hold)
                .is_err()
        );
        packet[184] ^= 1;
        packet[10] = 1;
        assert!(
            verify_current_source_hold_readback_v1(&packet, &signer, challenge, project, hold)
                .is_err()
        );
        packet[10] = 0;
        let wrong_key = SigningKey::from_bytes(&[12; 32]);
        let wrong_pin =
            encode_source_hold_readback_signer_credential_v1(3, &wrong_key.verifying_key())
                .expect("credential");
        let wrong_signer = PinnedSourceHoldReadbackSignerV1::decode(&wrong_pin).expect("pin");
        assert!(
            verify_current_source_hold_readback_v1(
                &packet,
                &wrong_signer,
                challenge,
                project,
                hold
            )
            .is_err()
        );
    }

    #[test]
    fn source_key_role_and_challenge_are_strict() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let mut credential =
            encode_source_hold_readback_signer_credential_v1(1, &key.verifying_key())
                .expect("credential");
        credential[..8].copy_from_slice(b"AOSCPK01");
        assert!(PinnedSourceHoldReadbackSignerV1::decode(&credential).is_err());
        assert!(
            SourceHoldReadbackChallengeV1::new([0; 16], ObjectDigest::from_bytes([1; 32])).is_err()
        );
    }

    #[test]
    fn canonical_source_replay_rejects_unheld_or_missing_head_and_replaced_names() {
        let directory = tempfile::tempdir().expect("Source journal fixture");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("private directory");
        let uid = fs::metadata(directory.path()).expect("owner").uid();
        use crate::journal::Journal;
        use crate::source_domain::{PROTECTED_SOURCE_DOMAIN_JOURNAL, source_domain_journal_limits};
        let (mut writer, _) = Journal::open_protected_at_uid(
            directory.path(),
            PROTECTED_SOURCE_DOMAIN_JOURNAL,
            source_domain_journal_limits(),
            uid,
        )
        .expect("protected Source writer");
        let (mut unheld, _) = Journal::open_read_only_protected_at_uid_for_test(
            directory.path(), PROTECTED_SOURCE_DOMAIN_JOURNAL,
            source_domain_journal_limits(), uid,
        ).expect("read-only unheld Source journal");
        assert!(replay_source_hold(&mut unheld, ProjectId::from_bytes([9; 16])).is_err());
        drop(unheld);

        let hold = SourceDomainPolicyHoldV1::new(
            OperationId::from_bytes([1; 16]),
            SandboxId::from_bytes([2; 16]),
            ObjectDigest::from_bytes([3; 32]),
            ObjectDigest::from_bytes([4; 32]),
            ObjectDigest::from_bytes([5; 32]),
            6,
        )
        .expect("hold");
        writer
            .acquire_source_domain_policy_hold_v1(hold)
            .expect("write active hold");

        let (mut readback, _) = Journal::open_read_only_protected_at_uid_for_test(
            directory.path(),
            PROTECTED_SOURCE_DOMAIN_JOURNAL,
            source_domain_journal_limits(),
            uid,
        )
        .expect("read-only Source journal");
        assert_eq!(
            readback.physical_names_v1(),
            writer
                .protected_writer_physical_names_v1()
                .expect("writer names")
        );
        assert!(replay_source_hold(&mut readback, ProjectId::from_bytes([9; 16])).is_err());

        for name in [
            PROTECTED_SOURCE_DOMAIN_JOURNAL,
            "source-domains-v1.journal.lock",
        ] {
            let current = directory.path().join(name);
            let retained = directory.path().join(format!("{name}.retained"));
            fs::rename(&current, &retained).expect("move original name");
            fs::write(&current, []).expect("substitute fixed name");
            fs::set_permissions(&current, fs::Permissions::from_mode(0o600))
                .expect("private replacement");
            assert!(readback.check_named_currentness_at_uid_for_test().is_err());
            fs::remove_file(&current).expect("remove replacement");
            fs::rename(&retained, &current).expect("restore original name");
        }
    }

    #[test]
    fn source_writer_rejects_replaced_journal_and_lock_names() {
        let directory = tempfile::tempdir().expect("protected journal directory");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("private directory");
        let uid = fs::metadata(directory.path()).expect("owner").uid();
        let limits = crate::journal::JournalLimits::default();
        let journal = crate::journal::Journal::open_protected_at_uid(
            directory.path(),
            "source-domains-v1.journal",
            limits,
            uid,
        )
        .expect("protected journal")
        .0;
        let owner = ProtectedSourceDomainJournalOwnerV1::from_test_journal(journal);
        assert!(owner.require_named_writer_for_test().is_ok());

        for name in [
            "source-domains-v1.journal",
            "source-domains-v1.journal.lock",
        ] {
            let current = directory.path().join(name);
            let retained = directory.path().join(format!("{name}.retained"));
            fs::rename(&current, &retained).expect("orphan retained writer");
            fs::write(&current, []).expect("replace fixed name");
            fs::set_permissions(&current, fs::Permissions::from_mode(0o600))
                .expect("private replacement");
            assert!(owner.require_named_writer_for_test().is_err());
            fs::remove_file(&current).expect("remove replacement");
            fs::rename(&retained, &current).expect("restore retained writer");
            assert!(owner.require_named_writer_for_test().is_ok());
        }
    }
}
