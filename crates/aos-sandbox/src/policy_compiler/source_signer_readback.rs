//! Source-only attestation from the signer's read-only protected journal view.
//!
//! The Controller remains the journal writer. The signer validates the fixed
//! idmapped mount, replays the exact journal and typed hierarchy head, signs a
//! caller challenge, then rechecks the retained names and mount. The packet is
//! diagnostic until an ordered all-owner handoff binds it to Root's cut.

use std::path::Path;

use aos_sandbox_core::ProjectId;
use ed25519_dalek::SigningKey;
use thiserror::Error;

use crate::cache_residency::signer_mount::require_signer_mount;
use crate::hierarchy::protected_journal::replay_project_ancestry_head_v1;
use crate::journal::{
    Journal, JournalError, ProtectedJournalNamesV1, ReadOnlyProtectedJournal,
    SourceDomainPolicyHoldV1,
};
use crate::lifecycle::protected_journal_join::{
    PROTECTED_SOURCE_DOMAIN_JOURNAL, PROTECTED_SOURCE_DOMAIN_ROOT, source_domain_journal_limits,
};

use super::source_hold_readback::{
    SOURCE_HOLD_READBACK_BYTES_V1, SourceHoldReadbackChallengeV1, SourceHoldReadbackErrorV1,
    sign_fields,
};
use super::source_hold_readback_v2::{
    SOURCE_HOLD_READBACK_BYTES_V2, sign_source_hold_readback_with_names_v2,
};

const SIGNER_SOURCE_VIEW: &str = "/run/aos/sandbox-source-signer-journal";

/// Reports a failed independent Source journal attestation.
#[derive(Debug, Error)]
pub enum SourceSignerReadbackErrorV1 {
    /// The signer view or original Source root is missing or unsafe.
    #[error("unsafe Source signer journal view")]
    View,
    /// The protected journal was malformed, stale, or replaced.
    #[error(transparent)]
    Journal(#[from] JournalError),
    /// The active hold does not match the complete typed hierarchy replay.
    #[error("Source hold and typed hierarchy head are not current")]
    Stale,
    /// The challenge or signer generation is noncanonical.
    #[error(transparent)]
    Signing(#[from] SourceHoldReadbackErrorV1),
}

/// Signs the active Source hold after read-only fixed-name and typed replay.
///
/// `expected_controller_uid` is the on-disk Source journal owner. The signer
/// must hold only its independently provisioned Source-purpose key. This
/// observation grants no writer, Q04, Create, or effect authority.
///
/// # Errors
///
/// Rejects a missing or altered idmapped mount, wrong original owner, unsafe
/// journal or lock, incomplete tail, missing hold, stale hierarchy head, or
/// changed physical name during the signed observation.
pub fn sign_fixed_source_signer_readback_v1(
    expected_controller_uid: u32,
    project: ProjectId,
    challenge: SourceHoldReadbackChallengeV1,
    signer_generation: u64,
    signing_key: &SigningKey,
) -> Result<[u8; SOURCE_HOLD_READBACK_BYTES_V1], SourceSignerReadbackErrorV1> {
    with_current_source_signer_view(
        expected_controller_uid,
        project,
        signer_generation,
        |hold, _| sign_fields(challenge, project, hold, signer_generation, signing_key),
    )
}

/// Signs the held Source head and exact fixed journal/lock inode identities.
///
/// The signer still has only a read-only view. This V2 packet is
/// nonauthorizing until Root joins it to a challenge committed under the
/// matching Controller-retained Source writer and rechecks that cut.
///
/// # Errors
///
/// Rejects stale or replaced fixed names, mount, hold, ancestry, or signer
/// generation, and incomplete protected replay.
pub fn sign_fixed_source_signer_readback_v2(
    expected_controller_uid: u32,
    project: ProjectId,
    challenge: SourceHoldReadbackChallengeV1,
    signer_generation: u64,
    signing_key: &SigningKey,
) -> Result<[u8; SOURCE_HOLD_READBACK_BYTES_V2], SourceSignerReadbackErrorV1> {
    with_current_source_signer_view(
        expected_controller_uid,
        project,
        signer_generation,
        |hold, names| {
            sign_source_hold_readback_with_names_v2(
                challenge,
                project,
                hold,
                names,
                signer_generation,
                signing_key,
            )
        },
    )
}

fn with_current_source_signer_view<const N: usize>(
    expected_controller_uid: u32,
    project: ProjectId,
    signer_generation: u64,
    sign: impl FnOnce(SourceDomainPolicyHoldV1, ProtectedJournalNamesV1) -> [u8; N],
) -> Result<[u8; N], SourceSignerReadbackErrorV1> {
    if project.as_bytes() == &[0; 16] || signer_generation == 0 || expected_controller_uid == 0 {
        return Err(SourceHoldReadbackErrorV1::NonCanonical.into());
    }
    let signer_uid = rustix::process::geteuid().as_raw();
    let mount = require_signer_mount(SIGNER_SOURCE_VIEW, PROTECTED_SOURCE_DOMAIN_ROOT, signer_uid)
        .map_err(|_| SourceSignerReadbackErrorV1::View)?;
    if mount.source_uid() != expected_controller_uid {
        return Err(SourceSignerReadbackErrorV1::View);
    }

    let (mut readback, _) = Journal::open_read_only_protected_at_for_uid_bound(
        Path::new(SIGNER_SOURCE_VIEW),
        PROTECTED_SOURCE_DOMAIN_JOURNAL,
        source_domain_journal_limits(),
        signer_uid,
        mount.root_identity(),
    )?;
    let hold = replay_source_hold(&mut readback, project)?;
    let packet = sign(hold, readback.physical_names_v1());

    readback.check_named_currentness()?;
    if require_signer_mount(SIGNER_SOURCE_VIEW, PROTECTED_SOURCE_DOMAIN_ROOT, signer_uid)
        .map_err(|_| SourceSignerReadbackErrorV1::View)?
        != mount
    {
        return Err(SourceSignerReadbackErrorV1::View);
    }
    Ok(packet)
}

fn replay_source_hold(
    readback: &mut ReadOnlyProtectedJournal,
    project: ProjectId,
) -> Result<SourceDomainPolicyHoldV1, SourceSignerReadbackErrorV1> {
    let journal = readback.journal_mut();
    let hold = journal
        .source_domain_policy_hold_v1()?
        .filter(|hold| hold.is_held())
        .ok_or(SourceSignerReadbackErrorV1::Stale)?;
    let ancestry = replay_project_ancestry_head_v1(journal, project)
        .map_err(|_| SourceSignerReadbackErrorV1::Stale)?
        .ok_or(SourceSignerReadbackErrorV1::Stale)?
        .head();
    if ancestry != hold.ancestry() {
        return Err(SourceSignerReadbackErrorV1::Stale);
    }
    Ok(hold)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    use aos_sandbox_core::{ObjectDigest, OperationId, SandboxId};

    use super::*;

    #[test]
    fn read_only_source_replay_rejects_missing_head_and_replaced_names() {
        let directory = tempfile::tempdir().expect("Source journal fixture");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("private directory");
        let uid = fs::metadata(directory.path()).expect("owner").uid();
        let (mut writer, _) = Journal::open_protected_at_uid(
            directory.path(),
            PROTECTED_SOURCE_DOMAIN_JOURNAL,
            source_domain_journal_limits(),
            uid,
        )
        .expect("protected Source writer");
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
}
