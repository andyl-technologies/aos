//! Independent Source-only signature over a pre-Q04 project ancestry challenge.
//!
//! ```text
//! AOSQPR03 | version:u16=3 | reserved[6]=0 | signer-generation:u64 |
//! Root-nonce:16 | Root-cut:32 | project:16 | ancestry-head:32 |
//! AOSQPA01-digest:32 | Source directory/journal/lock identities:48 |
//! AOSQPV01-reservation-digest:32 |
//! Ed25519-signature:64
//! ```
//!
//! The signer obtains all fields from its read-only fixed-name replay. Root
//! checks this packet under its own pinned Source key and the Controller-held
//! AOSQPA01 row; it does not transfer the Source writer or authorize Create.

use aos_sandbox_core::ProjectId;
use ed25519_dalek::{Signature, Signer as _, SigningKey};

use super::root_project_admission_proof::{
    RootProjectAdmissionOutcomeProofV1, RootProjectReservationCancellationProofV1,
};
use crate::hierarchy::protected_journal::{
    HierarchyProtectedJournalErrorV1, HierarchyProtectedJournalOwnerV1,
};
use crate::journal::{
    JournalError, SourceProjectAdmissionChallengeKindV1, SourceProjectAdmissionChallengeV1,
    SourceProjectAdmissionReservationV1, replay_source_project_admission_challenge_v1,
};
use crate::lifecycle::protected_journal_join::ProtectedSourceDomainJournalOwnerV1;

use super::source_hold_readback::{
    PinnedSourceHoldReadbackSignerV1, SourceHoldReadbackChallengeV1, SourceHoldReadbackErrorV1,
};

const MAGIC: &[u8; 8] = b"AOSQPR03";
const VERSION: u16 = 3;
const RETIREMENT_MAGIC: &[u8; 8] = b"AOSQPR04";
const RETIREMENT_VERSION: u16 = 4;
const BODY_BYTES: usize = 232;
const SIGNATURE_DOMAIN: &[u8] = b"aos.sandbox.source-project-admission.readback.v1\0";
const RETIREMENT_SIGNATURE_DOMAIN: &[u8] = b"aos.sandbox.source-project-retirement.readback.v1\0";
const RESERVATION_MAGIC: &[u8; 8] = b"AOSQPR05";
const RESERVATION_SIGNATURE_DOMAIN: &[u8] = b"aos.sandbox.source-project-reservation.readback.v1\0";
const RESERVATION_BODY_BYTES: usize = 136;

/// Bounds the exact Source-only project-admission readback packet.
pub const SOURCE_PROJECT_ADMISSION_READBACK_BYTES_V1: usize = BODY_BYTES + 64;

/// Bounds the distinct Source-only reservation packet.
pub const SOURCE_PROJECT_RESERVATION_READBACK_BYTES_V1: usize = RESERVATION_BODY_BYTES + 64;

/// Signs only the current pre-stage Source reservation and physical names.
pub(super) fn sign_source_project_reservation_fields_v1(
    row: SourceProjectAdmissionReservationV1,
    generation: u64,
    signing_key: &SigningKey,
) -> Result<[u8; SOURCE_PROJECT_RESERVATION_READBACK_BYTES_V1], SourceHoldReadbackErrorV1> {
    if generation == 0 {
        return Err(SourceHoldReadbackErrorV1::NonCanonical);
    }
    let mut bytes = [0; SOURCE_PROJECT_RESERVATION_READBACK_BYTES_V1];
    bytes[..8].copy_from_slice(RESERVATION_MAGIC);
    bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
    bytes[16..24].copy_from_slice(&generation.to_be_bytes());
    bytes[24..40].copy_from_slice(&row.client_nonce());
    bytes[40..56].copy_from_slice(row.project().as_bytes());
    bytes[56..88].copy_from_slice(row.record_digest().as_bytes());
    bytes[88..136].copy_from_slice(&row.names().to_bytes());
    let signature = signing_key.sign(&signature_preimage(
        RESERVATION_SIGNATURE_DOMAIN,
        &bytes[..RESERVATION_BODY_BYTES],
    ));
    bytes[RESERVATION_BODY_BYTES..].copy_from_slice(&signature.to_bytes());
    Ok(bytes)
}

/// Verifies the exact pre-stage Source reservation under Root's pinned key.
///
/// This packet asserts only Source's current read-only replay at signing;
/// Root must serialize stage versus cancellation under its own writer.
///
/// # Errors
///
/// Rejects changed reservation, signer generation, framing, or signature.
pub fn verify_source_project_reservation_readback_v1(
    bytes: &[u8],
    signer: &PinnedSourceHoldReadbackSignerV1,
    expected: SourceProjectAdmissionReservationV1,
) -> Result<(), SourceHoldReadbackErrorV1> {
    if bytes.len() != SOURCE_PROJECT_RESERVATION_READBACK_BYTES_V1
        || bytes.get(..8) != Some(RESERVATION_MAGIC)
        || take::<2>(bytes, 8)? != 1_u16.to_be_bytes()
        || take::<6>(bytes, 10)? != [0; 6]
        || take::<8>(bytes, 16)? != signer.generation().to_be_bytes()
        || take::<16>(bytes, 24)? != expected.client_nonce()
        || take::<16>(bytes, 40)? != *expected.project().as_bytes()
        || take::<32>(bytes, 56)? != *expected.record_digest().as_bytes()
        || take::<48>(bytes, 88)? != expected.names().to_bytes()
    {
        return Err(SourceHoldReadbackErrorV1::Stale);
    }
    let signature = Signature::from_bytes(&take::<64>(bytes, RESERVATION_BODY_BYTES)?);
    signer
        .verifying_key()
        .verify_strict(
            &signature_preimage(
                RESERVATION_SIGNATURE_DOMAIN,
                &bytes[..RESERVATION_BODY_BYTES],
            ),
            &signature,
        )
        .map_err(|_| SourceHoldReadbackErrorV1::Signature)
}

/// Reserves protected Source headroom before Root may create a stage.
///
/// The row is not an ancestry claim. Its journal fence persists across crash;
/// only a later exact Root decision can retire it.
///
/// # Errors
///
/// Rejects changed fixed names, pending admission, Q04 custody, or a failed
/// protected reservation commit.
pub fn reserve_source_project_admission_v1(
    owner: &mut ProtectedSourceDomainJournalOwnerV1,
    expected: SourceProjectAdmissionReservationV1,
) -> Result<SourceProjectAdmissionReservationV1, SourceProjectAdmissionChallengeErrorV1> {
    owner.require_fixed_named_writer_v1()?;
    let names = owner.fixed_physical_names_v1()?;
    if names != expected.names()
        || owner
            .journal()
            .preview_source_project_admission_reservation_v1(
                expected.client_nonce(),
                expected.project(),
                names,
            )?
            != expected
    {
        return Err(SourceProjectAdmissionChallengeErrorV1::Stale);
    }
    let row = owner
        .journal()
        .record_source_project_admission_reservation_v1(
            expected.client_nonce(),
            expected.project(),
            names,
        )?;
    if row != expected || owner.journal().source_project_admission_reservation_v1()? != Some(row) {
        return Err(SourceProjectAdmissionChallengeErrorV1::Stale);
    }
    Ok(row)
}

/// Reads a reservation and whether exact Root cancellation retired it.
///
/// The boolean is not a general terminal flag; a normally settled challenge
/// retains the reservation and is reported separately by challenge status.
///
/// # Errors
///
/// Rejects unsafe Source writer custody or malformed reservation history.
pub fn read_source_project_reservation_status_v1(
    owner: &mut ProtectedSourceDomainJournalOwnerV1,
) -> Result<
    Option<(SourceProjectAdmissionReservationV1, bool)>,
    SourceProjectAdmissionChallengeErrorV1,
> {
    owner.require_fixed_named_writer_v1()?;
    Ok(owner
        .journal()
        .source_project_admission_reservation_status_v1()?)
}

/// Retires the exact reservation using only a peer-checked Root marker.
///
/// # Errors
///
/// Rejects changed Source custody or mismatched Root cancellation evidence.
pub fn settle_source_project_reservation_v1(
    owner: &mut ProtectedSourceDomainJournalOwnerV1,
    expected: SourceProjectAdmissionReservationV1,
    proof: RootProjectReservationCancellationProofV1,
) -> Result<(), SourceProjectAdmissionChallengeErrorV1> {
    owner.require_fixed_named_writer_v1()?;
    owner
        .journal()
        .settle_source_project_admission_reservation_v1(expected, proof)?;
    Ok(())
}

/// Reports a failed protected Source project-admission challenge cut.
#[derive(Debug, thiserror::Error)]
pub enum SourceProjectAdmissionChallengeErrorV1 {
    /// The Source writer, project ancestry, or exact challenge changed.
    #[error("Source project-admission challenge is not current")]
    Stale,
    /// Protected Source journal custody failed.
    #[error(transparent)]
    Journal(#[from] JournalError),
    /// The typed project ancestry could not be replayed.
    #[error(transparent)]
    Hierarchy(#[from] HierarchyProtectedJournalErrorV1),
}

/// Spends a Root nonce under the Controller-retained fixed Source writer.
///
/// The caller must already hold the Controller writer and retain this Source
/// writer through the Root-last admission CAS. The returned row is not a
/// transferable lock. A different nonce cannot replace an unresolved row.
///
/// # Errors
///
/// Rejects missing or changed ancestry, a Q04 hold, unsafe fixed names,
/// conflicting replay, or failed durable commit/readback.
pub fn record_current_source_project_admission_challenge_v1(
    owner: &mut ProtectedSourceDomainJournalOwnerV1,
    project: ProjectId,
    challenge: SourceHoldReadbackChallengeV1,
    stage: aos_sandbox_core::ObjectDigest,
) -> Result<SourceProjectAdmissionChallengeV1, SourceProjectAdmissionChallengeErrorV1> {
    owner.require_fixed_named_writer_v1()?;
    let names = owner.fixed_physical_names_v1()?;
    let ancestry = current_project_ancestry(owner, project)?;
    let row = owner
        .journal()
        .record_source_project_admission_challenge_v1(
            project,
            ancestry,
            challenge.nonce(),
            challenge.cut(),
            stage,
            names,
        )?;
    require_current_source_project_admission_challenge_v1(owner, row)?;
    Ok(row)
}

/// Records an abort-only Source row when ancestry cannot support admission.
///
/// This row is the same fixed size as a normal challenge and is never valid
/// for a Root commit. Its only purpose is independently signed Root abort and
/// exact peer-checked Source retirement after a failed post-stage preflight.
///
/// # Errors
///
/// Rejects unsafe fixed writer custody, a conflicting pending challenge,
/// stale names, or failed durable commit.
pub fn record_source_project_abort_only_challenge_v1(
    owner: &mut ProtectedSourceDomainJournalOwnerV1,
    project: ProjectId,
    challenge: SourceHoldReadbackChallengeV1,
    stage: aos_sandbox_core::ObjectDigest,
) -> Result<SourceProjectAdmissionChallengeV1, SourceProjectAdmissionChallengeErrorV1> {
    owner.require_fixed_named_writer_v1()?;
    let names = owner.fixed_physical_names_v1()?;
    let row = owner
        .journal()
        .record_source_project_abort_only_challenge_v1(
            project,
            challenge.nonce(),
            challenge.cut(),
            stage,
            names,
        )?;
    if owner.journal().source_project_admission_status_v1()? != Some((row, false)) {
        return Err(SourceProjectAdmissionChallengeErrorV1::Stale);
    }
    Ok(row)
}

/// Preflights current project ancestry and three Source journal transactions.
///
/// The caller must retain this owner through stage, challenge, Root decision,
/// and exact settlement. This does not stage Root or grant any project policy.
///
/// # Errors
///
/// Rejects missing ancestry, pending prior challenge, unsafe writer names,
/// Q04 hold, or insufficient protected journal capacity.
pub fn preflight_source_project_admission_v1(
    owner: &mut ProtectedSourceDomainJournalOwnerV1,
    client_nonce: [u8; 16],
    project: ProjectId,
) -> Result<SourceProjectAdmissionReservationV1, SourceProjectAdmissionChallengeErrorV1> {
    owner.require_fixed_named_writer_v1()?;
    let names = owner.fixed_physical_names_v1()?;
    let ancestry = current_project_ancestry(owner, project)?;
    owner
        .journal()
        .preflight_source_project_admission_capacity_v1(client_nonce, project, ancestry, names)?;
    Ok(owner
        .journal()
        .preview_source_project_admission_reservation_v1(client_nonce, project, names)?)
}

/// Rechecks the exact Source row and ancestry before Root-last admission.
///
/// # Errors
///
/// Rejects a changed challenge, ancestry, or physical journal/lock names.
pub fn require_current_source_project_admission_challenge_v1(
    owner: &mut ProtectedSourceDomainJournalOwnerV1,
    expected: SourceProjectAdmissionChallengeV1,
) -> Result<(), SourceProjectAdmissionChallengeErrorV1> {
    let names = owner.fixed_physical_names_v1()?;
    let ancestry = current_project_ancestry(owner, expected.project())?;
    if !expected.matches_current(
        expected.nonce(),
        expected.cut(),
        expected.project(),
        ancestry,
        expected.stage(),
        names,
    ) || replay_source_project_admission_challenge_v1(owner.journal())? != Some(expected)
    {
        return Err(SourceProjectAdmissionChallengeErrorV1::Stale);
    }
    Ok(())
}

/// Reads the exact current Source challenge and whether Root retired it.
///
/// A pending row's stage digest is the only cold-recovery key for the Root
/// outcome. The boolean describes Source's durable settlement, not Root
/// admission or current project policy.
///
/// # Errors
///
/// Rejects unsafe fixed writer custody or malformed challenge/settlement rows.
pub fn read_source_project_admission_status_v1(
    owner: &mut ProtectedSourceDomainJournalOwnerV1,
) -> Result<Option<(SourceProjectAdmissionChallengeV1, bool)>, SourceProjectAdmissionChallengeErrorV1>
{
    owner.require_fixed_named_writer_v1()?;
    Ok(owner.journal().source_project_admission_status_v1()?)
}

/// Durably retires the current Source challenge with an opaque Root outcome.
///
/// # Errors
///
/// Rejects a foreign challenge, changed physical names, unmatched Root proof,
/// or failed durable settlement.
pub fn settle_current_source_project_admission_challenge_v1(
    owner: &mut ProtectedSourceDomainJournalOwnerV1,
    expected: SourceProjectAdmissionChallengeV1,
    proof: RootProjectAdmissionOutcomeProofV1,
) -> Result<(), SourceProjectAdmissionChallengeErrorV1> {
    owner.require_fixed_named_writer_v1()?;
    owner
        .journal()
        .settle_source_project_admission_challenge_v1(expected, proof)?;
    Ok(())
}

fn current_project_ancestry(
    owner: &mut ProtectedSourceDomainJournalOwnerV1,
    project: ProjectId,
) -> Result<aos_sandbox_core::ObjectDigest, SourceProjectAdmissionChallengeErrorV1> {
    let hierarchy = HierarchyProtectedJournalOwnerV1::claim(owner)?;
    hierarchy
        .project_ancestry_head(project)?
        .map(|head| head.evidence().head())
        .ok_or(SourceProjectAdmissionChallengeErrorV1::Stale)
}

pub(super) fn sign_source_project_admission_fields_v1(
    row: SourceProjectAdmissionChallengeV1,
    reservation: SourceProjectAdmissionReservationV1,
    generation: u64,
    signing_key: &SigningKey,
) -> Result<[u8; SOURCE_PROJECT_ADMISSION_READBACK_BYTES_V1], SourceHoldReadbackErrorV1> {
    if row.kind() != SourceProjectAdmissionChallengeKindV1::Admission {
        return Err(SourceHoldReadbackErrorV1::NonCanonical);
    }
    sign_fields(
        row,
        reservation,
        generation,
        signing_key,
        MAGIC,
        VERSION,
        SIGNATURE_DOMAIN,
    )
}

pub(super) fn sign_source_project_retirement_fields_v1(
    row: SourceProjectAdmissionChallengeV1,
    reservation: SourceProjectAdmissionReservationV1,
    generation: u64,
    signing_key: &SigningKey,
) -> Result<[u8; SOURCE_PROJECT_ADMISSION_READBACK_BYTES_V1], SourceHoldReadbackErrorV1> {
    sign_fields(
        row,
        reservation,
        generation,
        signing_key,
        RETIREMENT_MAGIC,
        RETIREMENT_VERSION,
        RETIREMENT_SIGNATURE_DOMAIN,
    )
}

fn sign_fields(
    row: SourceProjectAdmissionChallengeV1,
    reservation: SourceProjectAdmissionReservationV1,
    generation: u64,
    signing_key: &SigningKey,
    magic: &[u8; 8],
    version: u16,
    domain: &[u8],
) -> Result<[u8; SOURCE_PROJECT_ADMISSION_READBACK_BYTES_V1], SourceHoldReadbackErrorV1> {
    if generation == 0
        || row.issue() != reservation.issue()
        || row.project() != reservation.project()
        || row.names() != reservation.names()
    {
        return Err(SourceHoldReadbackErrorV1::NonCanonical);
    }
    let mut bytes = [0; SOURCE_PROJECT_ADMISSION_READBACK_BYTES_V1];
    bytes[..8].copy_from_slice(magic);
    bytes[8..10].copy_from_slice(&version.to_be_bytes());
    bytes[16..24].copy_from_slice(&generation.to_be_bytes());
    bytes[24..40].copy_from_slice(&row.nonce());
    bytes[40..72].copy_from_slice(row.cut().as_bytes());
    bytes[72..88].copy_from_slice(row.project().as_bytes());
    bytes[88..120].copy_from_slice(row.ancestry().as_bytes());
    bytes[120..152].copy_from_slice(row.record_digest().as_bytes());
    bytes[152..200].copy_from_slice(&row.names().to_bytes());
    bytes[200..232].copy_from_slice(reservation.record_digest().as_bytes());
    let signature = signing_key.sign(&signature_preimage(domain, &bytes[..BODY_BYTES]));
    bytes[BODY_BYTES..].copy_from_slice(&signature.to_bytes());
    Ok(bytes)
}

/// Verifies one Source-only packet against the exact Controller-held challenge.
///
/// The caller must load the Source-purpose pin independently and obtain the
/// expected AOSQPA01 row from retained Source writer custody. A packet alone
/// does not prove Root spent its nonce or that Controller retained its writer.
///
/// # Errors
///
/// Rejects wrong role generation, challenge, row, project, physical names,
/// canonical framing, or signature.
pub fn verify_source_project_admission_readback_v1(
    bytes: &[u8],
    signer: &PinnedSourceHoldReadbackSignerV1,
    challenge: SourceHoldReadbackChallengeV1,
    project: ProjectId,
    expected: SourceProjectAdmissionChallengeV1,
    reservation_digest: aos_sandbox_core::ObjectDigest,
) -> Result<(), SourceHoldReadbackErrorV1> {
    if expected.kind() != SourceProjectAdmissionChallengeKindV1::Admission {
        return Err(SourceHoldReadbackErrorV1::NonCanonical);
    }
    verify_fields(
        bytes,
        signer,
        challenge,
        project,
        expected,
        reservation_digest,
        MAGIC,
        VERSION,
        SIGNATURE_DOMAIN,
    )
}

/// Verifies an exact Source-only retirement packet without granting ancestry.
///
/// This separate signature domain cannot be substituted for AOSQPR03 at Root
/// commit. It proves only the exact durable row and named Source journal.
///
/// # Errors
///
/// Rejects changed row, names, challenge, signer pin, framing, or signature.
pub fn verify_source_project_retirement_readback_v1(
    bytes: &[u8],
    signer: &PinnedSourceHoldReadbackSignerV1,
    challenge: SourceHoldReadbackChallengeV1,
    project: ProjectId,
    expected: SourceProjectAdmissionChallengeV1,
    reservation_digest: aos_sandbox_core::ObjectDigest,
) -> Result<(), SourceHoldReadbackErrorV1> {
    verify_fields(
        bytes,
        signer,
        challenge,
        project,
        expected,
        reservation_digest,
        RETIREMENT_MAGIC,
        RETIREMENT_VERSION,
        RETIREMENT_SIGNATURE_DOMAIN,
    )
}

#[allow(clippy::too_many_arguments)]
fn verify_fields(
    bytes: &[u8],
    signer: &PinnedSourceHoldReadbackSignerV1,
    challenge: SourceHoldReadbackChallengeV1,
    project: ProjectId,
    expected: SourceProjectAdmissionChallengeV1,
    reservation_digest: aos_sandbox_core::ObjectDigest,
    magic: &[u8; 8],
    version: u16,
    domain: &[u8],
) -> Result<(), SourceHoldReadbackErrorV1> {
    if bytes.len() != SOURCE_PROJECT_ADMISSION_READBACK_BYTES_V1
        || project.as_bytes() == &[0; 16]
        || expected.nonce() != challenge.nonce()
        || expected.cut() != challenge.cut()
        || expected.project() != project
        || bytes.get(..8) != Some(magic)
        || take::<2>(bytes, 8)? != version.to_be_bytes()
        || take::<6>(bytes, 10)? != [0; 6]
        || take::<8>(bytes, 16)? != signer.generation().to_be_bytes()
        || take::<16>(bytes, 24)? != challenge.nonce()
        || take::<32>(bytes, 40)? != *challenge.cut().as_bytes()
        || take::<16>(bytes, 72)? != *project.as_bytes()
        || take::<32>(bytes, 88)? != *expected.ancestry().as_bytes()
        || take::<32>(bytes, 120)? != *expected.record_digest().as_bytes()
        || take::<48>(bytes, 152)? != expected.names().to_bytes()
        || take::<32>(bytes, 200)? != *reservation_digest.as_bytes()
    {
        return Err(SourceHoldReadbackErrorV1::Stale);
    }
    let signature = Signature::from_bytes(&take::<64>(bytes, BODY_BYTES)?);
    signer
        .verifying_key()
        .verify_strict(
            &signature_preimage(domain, &bytes[..BODY_BYTES]),
            &signature,
        )
        .map_err(|_| SourceHoldReadbackErrorV1::Signature)
}

fn signature_preimage(domain: &[u8], body: &[u8]) -> Vec<u8> {
    let mut preimage = Vec::with_capacity(domain.len() + body.len());
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(body);
    preimage
}

fn take<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], SourceHoldReadbackErrorV1> {
    bytes
        .get(offset..offset + N)
        .and_then(|field| field.try_into().ok())
        .ok_or(SourceHoldReadbackErrorV1::NonCanonical)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    use aos_sandbox_core::ObjectDigest;
    use ed25519_dalek::SigningKey;

    use super::*;
    use crate::Journal;
    use crate::lifecycle::protected_journal_join::source_domain_journal_limits;
    use crate::policy_compiler::encode_source_hold_readback_signer_credential_v1;

    #[test]
    fn source_packet_binds_exact_durable_challenge_and_pinned_role_key() {
        let directory = tempfile::tempdir().expect("Source directory");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let uid = fs::metadata(directory.path()).unwrap().uid();
        let (mut writer, _) = Journal::open_protected_at_uid(
            directory.path(),
            "source-domains-v1.journal",
            source_domain_journal_limits(),
            uid,
        )
        .expect("protected Source writer");
        let names = writer.protected_writer_physical_names_v1().unwrap();
        let project = ProjectId::from_bytes([1; 16]);
        let ancestry = ObjectDigest::from_bytes([2; 32]);
        let challenge =
            SourceHoldReadbackChallengeV1::new([3; 16], ObjectDigest::from_bytes([4; 32])).unwrap();
        let reservation = writer
            .record_source_project_admission_reservation_v1([7; 16], project, names)
            .expect("durable reservation");
        let row = writer
            .record_source_project_admission_challenge_v1(
                project,
                ancestry,
                challenge.nonce(),
                challenge.cut(),
                aos_sandbox_core::ObjectDigest::from_bytes([6; 32]),
                names,
            )
            .expect("durable Source challenge");

        let key = SigningKey::from_bytes(&[5; 32]);
        let credential =
            encode_source_hold_readback_signer_credential_v1(6, &key.verifying_key()).unwrap();
        let signer = PinnedSourceHoldReadbackSignerV1::decode(&credential).unwrap();
        let reservation_packet =
            sign_source_project_reservation_fields_v1(reservation, 6, &key).unwrap();
        verify_source_project_reservation_readback_v1(&reservation_packet, &signer, reservation)
            .unwrap();
        let mut changed_reservation = reservation_packet;
        changed_reservation[56] ^= 1;
        assert!(
            verify_source_project_reservation_readback_v1(
                &changed_reservation,
                &signer,
                reservation,
            )
            .is_err()
        );
        let packet = sign_source_project_admission_fields_v1(row, reservation, 6, &key).unwrap();
        verify_source_project_admission_readback_v1(
            &packet,
            &signer,
            challenge,
            project,
            row,
            reservation.record_digest(),
        )
        .expect("exact signer packet");
        let retirement =
            sign_source_project_retirement_fields_v1(row, reservation, 6, &key).unwrap();
        verify_source_project_retirement_readback_v1(
            &retirement,
            &signer,
            challenge,
            project,
            row,
            reservation.record_digest(),
        )
        .expect("exact retirement packet");
        assert!(
            verify_source_project_admission_readback_v1(
                &retirement,
                &signer,
                challenge,
                project,
                row,
                reservation.record_digest(),
            )
            .is_err()
        );
        assert!(
            verify_source_project_retirement_readback_v1(
                &packet,
                &signer,
                challenge,
                project,
                row,
                reservation.record_digest(),
            )
            .is_err()
        );

        let wrong_challenge = SourceHoldReadbackChallengeV1::new([7; 16], challenge.cut()).unwrap();
        assert!(
            verify_source_project_admission_readback_v1(
                &packet,
                &signer,
                wrong_challenge,
                project,
                row,
                reservation.record_digest(),
            )
            .is_err()
        );
        let rotated =
            encode_source_hold_readback_signer_credential_v1(7, &key.verifying_key()).unwrap();
        let rotated = PinnedSourceHoldReadbackSignerV1::decode(&rotated).unwrap();
        assert!(
            verify_source_project_admission_readback_v1(
                &packet,
                &rotated,
                challenge,
                project,
                row,
                reservation.record_digest(),
            )
            .is_err()
        );
        for offset in [24, 40, 72, 88, 120, 152, 200] {
            let mut changed = packet;
            changed[offset] ^= 1;
            assert!(
                verify_source_project_admission_readback_v1(
                    &changed,
                    &signer,
                    challenge,
                    project,
                    row,
                    reservation.record_digest(),
                )
                .is_err()
            );
        }
    }
}
