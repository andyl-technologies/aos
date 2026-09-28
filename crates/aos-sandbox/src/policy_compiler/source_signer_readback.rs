//! Source-only attestation from the signer's read-only protected journal view.
//!
//! The Controller remains the journal writer. The signer validates the fixed
//! idmapped mount, replays the exact journal and typed hierarchy head, signs a
//! caller challenge, then rechecks the retained names and mount. The packet is
//! diagnostic until an ordered all-owner handoff binds it to Root's cut.

use std::path::Path;

use aos_sandbox_core::{ObjectDigest, ProjectId};
use ed25519_dalek::SigningKey;
use thiserror::Error;

use crate::cache_residency::signer_mount::require_signer_mount;
use crate::hierarchy::protected_journal::replay_project_ancestry_head_v1;
use crate::journal::{
    Journal, JournalError, ProtectedJournalNamesV1, ReadOnlyProtectedJournal,
    SourceDomainPolicyHoldV1,
};
use crate::journal::{
    replay_source_domain_challenge_v1, replay_source_project_admission_challenge_v1,
};
use crate::lifecycle::protected_journal_join::{
    PROTECTED_SOURCE_DOMAIN_JOURNAL, PROTECTED_SOURCE_DOMAIN_ROOT, source_domain_journal_limits,
};

use super::source_genesis_readback::{
    SOURCE_TREE_GENESIS_READBACK_BYTES_V1, SourceTreeGenesisChallengeV1,
    SourceTreeGenesisIntentContextV1, sign_source_tree_genesis_fields_v1,
};
use super::source_hold_readback::{
    SOURCE_HOLD_READBACK_BYTES_V1, SourceHoldReadbackChallengeV1, SourceHoldReadbackErrorV1,
    sign_fields,
};
use super::source_hold_readback_v2::{
    SOURCE_HOLD_READBACK_BYTES_V2, sign_source_hold_readback_with_names_v2,
};
use super::source_project_admission_readback::{
    SOURCE_PROJECT_ADMISSION_READBACK_BYTES_V1, SOURCE_PROJECT_RESERVATION_READBACK_BYTES_V1,
    sign_source_project_admission_fields_v1, sign_source_project_reservation_fields_v1,
};

const SIGNER_SOURCE_VIEW: &str = "/run/aos/sandbox-source-signer-journal";

/// Observes initial materialization only through the existing fixed reader view.
///
/// Empty is joined absence of every Source journal row, never a
/// project lookup miss. Prepared/Anchored require the exact original intent.
/// The V2 request supplies comparison data only; the signed observation remains
/// V1. Actual pending rows or ACK commitments, not a fresh nonce, bind replay.
/// This Source-purpose signature does not authenticate Root sender authority,
/// a current Root floor, or a Controller-retained writer.
///
/// # Errors
///
/// Rejects unsafe view/owner/names, malformed or legacy materialization, a
/// missing or substituted intent/project, mixed ACK state or changed replay.
pub fn sign_fixed_source_tree_genesis_readback_v2(
    expected_controller_uid: u32,
    project: Option<ProjectId>,
    challenge: SourceTreeGenesisChallengeV1,
    intent_context: Option<&SourceTreeGenesisIntentContextV1>,
    signer_generation: u64,
    signing_key: &SigningKey,
) -> Result<[u8; SOURCE_TREE_GENESIS_READBACK_BYTES_V1], SourceSignerReadbackErrorV1> {
    if expected_controller_uid == 0
        || signer_generation == 0
        || project.is_some_and(|project| project.as_bytes() == &[0; 16])
        || project.is_some() != challenge.intent().is_some()
        || project.is_some() != intent_context.is_some()
        || intent_context.is_some_and(|context| context.source_uid() != expected_controller_uid)
    {
        return Err(SourceHoldReadbackErrorV1::NonCanonical.into());
    }
    with_source_signer_journal_view(expected_controller_uid, |readback| {
        sign_genesis_readback_from_view(
            readback,
            project,
            challenge,
            intent_context,
            signer_generation,
            signing_key,
        )
    })
}

/// Reuses actual read-only replay; no fixture or supplied receipt can mint it.
pub(super) fn sign_genesis_readback_from_view(
    readback: &mut ReadOnlyProtectedJournal,
    project: Option<ProjectId>,
    challenge: SourceTreeGenesisChallengeV1,
    intent_context: Option<&SourceTreeGenesisIntentContextV1>,
    signer_generation: u64,
    signing_key: &SigningKey,
) -> Result<[u8; SOURCE_TREE_GENESIS_READBACK_BYTES_V1], SourceSignerReadbackErrorV1> {
    let rows = crate::hierarchy::source_genesis::validate_actual_rows(readback.journal_mut())
        .map_err(|_| SourceSignerReadbackErrorV1::Stale)?;
    let names = readback.physical_names_v1();
    let sequence = readback.journal_mut().snapshot_sequence();
    let receipt = match project {
        Some(project) => Some(
            rows.receipts
                .get(&project)
                .ok_or(SourceSignerReadbackErrorV1::Stale)?,
        ),
        None if rows.receipts.is_empty()
            && rows.pending.is_none()
            && rows.acks.is_empty()
            && readback.journal_mut().all_records().next().is_none() =>
        {
            None
        }
        None => return Err(SourceSignerReadbackErrorV1::Stale),
    };
    if receipt.map(|receipt| receipt.intent_digest()) != challenge.intent()
        || receipt.is_some() != intent_context.is_some()
        || rows
            .pending
            .as_ref()
            .is_some_and(|pending| Some(pending.project) == project && pending.names != names)
    {
        return Err(SourceSignerReadbackErrorV1::Stale);
    }
    if let (Some(receipt), Some(context)) = (receipt, intent_context) {
        // The challenge correlates this observation only. The original nonce
        // comes from the durable pending marker and must reconstruct the exact
        // intent committed by this actual receipt, including UID and roles.
        context
            .require_actual_receipt(
                receipt,
                rows.pending
                    .as_ref()
                    .filter(|pending| pending.project == receipt.project()),
            )
            .map_err(|_| SourceSignerReadbackErrorV1::Stale)?;
        if let Some(ack) = rows.acks.get(&receipt.project()) {
            context
                .require_actual_ack(receipt, ack.root_floor)
                .map_err(|_| SourceSignerReadbackErrorV1::Stale)?;
        }
    }
    let ack = project
        .and_then(|project| rows.acks.get(&project))
        .map(|ack| (ack.root_floor, ack.digest()));
    let packet = sign_source_tree_genesis_fields_v1(
        challenge,
        names,
        sequence,
        receipt,
        ack,
        signer_generation,
        signing_key,
    )?;

    if readback.physical_names_v1() != names
        || readback.journal_mut().snapshot_sequence() != sequence
        || crate::hierarchy::source_genesis::validate_actual_rows(readback.journal_mut())
            .map_err(|_| SourceSignerReadbackErrorV1::Stale)?
            != rows
    {
        return Err(SourceSignerReadbackErrorV1::Stale);
    }
    Ok(packet)
}

/// Signs the exact unconsumed Source reservation from the independent view.
///
/// This cannot prove ancestry or replace the later AOSQPR03 admission packet.
/// Root must serialize its stage against a durable cancellation marker.
///
/// # Errors
///
/// Rejects a missing/consumed row, changed digest or physical names, unsafe
/// signer view, or invalid signer generation.
pub fn sign_fixed_source_project_reservation_readback_v1(
    expected_controller_uid: u32,
    client_nonce: [u8; 16],
    project: ProjectId,
    expected_digest: ObjectDigest,
    signer_generation: u64,
    signing_key: &SigningKey,
) -> Result<[u8; SOURCE_PROJECT_RESERVATION_READBACK_BYTES_V1], SourceSignerReadbackErrorV1> {
    if expected_controller_uid == 0
        || signer_generation == 0
        || client_nonce == [0; 16]
        || project.as_bytes() == &[0; 16]
        || expected_digest.as_bytes() == &[0; 32]
    {
        return Err(SourceHoldReadbackErrorV1::NonCanonical.into());
    }
    with_source_signer_journal_view(expected_controller_uid, |readback| {
        let row = readback
            .journal_mut()
            .source_project_admission_reservation_status_v1()?
            .and_then(|(row, canceled)| (!canceled).then_some(row))
            .ok_or(SourceSignerReadbackErrorV1::Stale)?;
        let names = readback.physical_names_v1();
        if row.client_nonce() != client_nonce
            || row.project() != project
            || row.record_digest() != expected_digest
            || row.names() != names
            || readback
                .journal_mut()
                .source_project_admission_status_v1()?
                .is_some()
        {
            return Err(SourceSignerReadbackErrorV1::Stale);
        }
        let packet =
            sign_source_project_reservation_fields_v1(row, signer_generation, signing_key)?;
        if readback
            .journal_mut()
            .source_project_admission_reservation_status_v1()?
            != Some((row, false))
            || readback
                .journal_mut()
                .source_project_admission_status_v1()?
                .is_some()
            || readback.physical_names_v1() != names
        {
            return Err(SourceSignerReadbackErrorV1::Stale);
        }
        Ok(packet)
    })
}

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
        |hold, _, _| {
            Ok(sign_fields(
                challenge,
                project,
                hold,
                signer_generation,
                signing_key,
            ))
        },
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
        |hold, names, row| {
            let row = row.ok_or(SourceSignerReadbackErrorV1::Stale)?;
            if !row.matches_current(challenge.nonce(), challenge.cut(), project, hold, names)? {
                return Err(SourceSignerReadbackErrorV1::Stale);
            }
            Ok(sign_source_hold_readback_with_names_v2(
                challenge,
                project,
                hold,
                names,
                signer_generation,
                signing_key,
            ))
        },
    )
}

/// Signs a durable pre-Q04 project ancestry challenge from the Source-only view.
///
/// The signer replays the exact AOSQPA01 row, typed project ancestry, and
/// fixed physical names twice around signing. It never accepts a caller-
/// supplied ancestry digest or grants a project-source admission itself.
///
/// # Errors
///
/// Rejects a missing or changed mount, row, ancestry head, challenge, names,
/// owner UID, or signer generation.
pub fn sign_fixed_source_project_admission_readback_v1(
    expected_controller_uid: u32,
    project: ProjectId,
    challenge: SourceHoldReadbackChallengeV1,
    signer_generation: u64,
    signing_key: &SigningKey,
) -> Result<[u8; SOURCE_PROJECT_ADMISSION_READBACK_BYTES_V1], SourceSignerReadbackErrorV1> {
    if project.as_bytes() == &[0; 16] || signer_generation == 0 || expected_controller_uid == 0 {
        return Err(SourceHoldReadbackErrorV1::NonCanonical.into());
    }
    with_source_signer_journal_view(expected_controller_uid, |readback| {
        let row = replay_source_project_admission_challenge_v1(readback.journal_mut())?
            .ok_or(SourceSignerReadbackErrorV1::Stale)?;
        let ancestry = replay_project_ancestry_head_v1(readback.journal_mut(), project)
            .map_err(|_| SourceSignerReadbackErrorV1::Stale)?
            .ok_or(SourceSignerReadbackErrorV1::Stale)?
            .head();
        let names = readback.physical_names_v1();
        if !row.matches_current(
            challenge.nonce(),
            challenge.cut(),
            project,
            ancestry,
            row.stage(),
            names,
        ) {
            return Err(SourceSignerReadbackErrorV1::Stale);
        }
        let reservation = readback
            .journal_mut()
            .source_project_admission_reservation_v1()?
            .ok_or(SourceSignerReadbackErrorV1::Stale)?;
        if reservation.project() != project
            || reservation.names() != names
            || reservation.issue() != row.issue()
        {
            return Err(SourceSignerReadbackErrorV1::Stale);
        }
        let packet = sign_source_project_admission_fields_v1(
            row,
            reservation,
            signer_generation,
            signing_key,
        )?;
        let postflight = replay_source_project_admission_challenge_v1(readback.journal_mut())?;
        let current_ancestry = replay_project_ancestry_head_v1(readback.journal_mut(), project)
            .map_err(|_| SourceSignerReadbackErrorV1::Stale)?
            .ok_or(SourceSignerReadbackErrorV1::Stale)?
            .head();
        if postflight != Some(row)
            || readback
                .journal_mut()
                .source_project_admission_reservation_v1()?
                != Some(reservation)
            || current_ancestry != ancestry
        {
            return Err(SourceSignerReadbackErrorV1::Stale);
        }
        Ok(packet)
    })
}

/// Signs only the exact pending Source row for Root's nonauthorizing abort.
///
/// Unlike admission, retirement does not claim current project ancestry. Its
/// separate AOSQPR04 domain cannot satisfy Root's positive commit verifier.
///
/// # Errors
///
/// Rejects changed row, names, peer challenge, or unsafe read-only view.
pub fn sign_fixed_source_project_retirement_readback_v1(
    expected_controller_uid: u32,
    project: ProjectId,
    challenge: SourceHoldReadbackChallengeV1,
    signer_generation: u64,
    signing_key: &SigningKey,
) -> Result<[u8; SOURCE_PROJECT_ADMISSION_READBACK_BYTES_V1], SourceSignerReadbackErrorV1> {
    if project.as_bytes() == &[0; 16] || signer_generation == 0 || expected_controller_uid == 0 {
        return Err(SourceHoldReadbackErrorV1::NonCanonical.into());
    }
    with_source_signer_journal_view(expected_controller_uid, |readback| {
        let (row, settled) = readback
            .journal_mut()
            .source_project_admission_status_v1()?
            .ok_or(SourceSignerReadbackErrorV1::Stale)?;
        let names = readback.physical_names_v1();
        if settled
            || row.nonce() != challenge.nonce()
            || row.cut() != challenge.cut()
            || row.project() != project
            || row.names() != names
        {
            return Err(SourceSignerReadbackErrorV1::Stale);
        }
        let reservation = readback
            .journal_mut()
            .source_project_admission_reservation_v1()?
            .ok_or(SourceSignerReadbackErrorV1::Stale)?;
        if reservation.project() != project
            || reservation.names() != names
            || reservation.issue() != row.issue()
        {
            return Err(SourceSignerReadbackErrorV1::Stale);
        }
        let packet =
            super::source_project_admission_readback::sign_source_project_retirement_fields_v1(
                row,
                reservation,
                signer_generation,
                signing_key,
            )?;
        if readback
            .journal_mut()
            .source_project_admission_status_v1()?
            != Some((row, false))
            || readback
                .journal_mut()
                .source_project_admission_reservation_v1()?
                != Some(reservation)
            || readback.physical_names_v1() != names
        {
            return Err(SourceSignerReadbackErrorV1::Stale);
        }
        Ok(packet)
    })
}

fn with_current_source_signer_view<const N: usize>(
    expected_controller_uid: u32,
    project: ProjectId,
    signer_generation: u64,
    sign: impl FnOnce(
        SourceDomainPolicyHoldV1,
        ProtectedJournalNamesV1,
        Option<crate::journal::SourceDomainChallengeV1>,
    ) -> Result<[u8; N], SourceSignerReadbackErrorV1>,
) -> Result<[u8; N], SourceSignerReadbackErrorV1> {
    if project.as_bytes() == &[0; 16] || signer_generation == 0 || expected_controller_uid == 0 {
        return Err(SourceHoldReadbackErrorV1::NonCanonical.into());
    }
    with_source_signer_journal_view(expected_controller_uid, |readback| {
        let hold = replay_source_hold(readback, project)?;
        let row = replay_source_domain_challenge_v1(readback.journal_mut())?;
        sign(hold, readback.physical_names_v1(), row)
    })
}

pub(super) fn with_source_signer_journal_view<const N: usize>(
    expected_controller_uid: u32,
    sign: impl FnOnce(&mut ReadOnlyProtectedJournal) -> Result<[u8; N], SourceSignerReadbackErrorV1>,
) -> Result<[u8; N], SourceSignerReadbackErrorV1> {
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
    let packet = sign(&mut readback)?;

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
