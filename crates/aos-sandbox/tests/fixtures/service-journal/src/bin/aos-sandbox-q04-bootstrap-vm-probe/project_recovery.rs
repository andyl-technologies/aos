//! Installed Root recovery-only exercise for nonauthorizing project admission.
//!
//! The fixture uses real protected Source and Root journals, the fixed Root
//! socket, and the independent Source-only signer. It deliberately creates
//! only cancellation and AbortOnly outcomes: the production ancestry gate
//! remains closed until Source genesis and rollback authority are qualified.

use std::error::Error;
use std::fs;
use std::os::fd::OwnedFd;
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::net::UnixListener;
use std::os::unix::process::CommandExt as _;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use aos_sandbox::journal::{
    SOURCE_PROJECT_ADMISSION_RESERVATION_BYTES_V1, SourceProjectAdmissionReservationV1,
};
use aos_sandbox::lifecycle::protected_journal_join::ProtectedSourceDomainJournalOwnerV1;
use aos_sandbox::policy_compiler::{
    PolicyDeploymentInputsV1, RootProjectAdmissionOutcomeKindV1, RootProjectAdmissionStageV1,
    SourceHoldReadbackChallengeV1, abort_fixed_root_project_admission_over_socket_v1,
    cancel_fixed_root_project_reservation_over_socket_v1,
    prepare_fixed_root_project_intent_over_socket_v1,
    query_fixed_root_current_project_admission_stage_v1,
    query_fixed_root_project_admission_outcome_v1,
    query_fixed_root_project_reservation_cancellation_v1, read_source_project_admission_status_v1,
    read_source_project_reservation_status_v1, record_source_project_abort_only_challenge_v1,
    reserve_source_project_admission_v1, settle_current_source_project_admission_challenge_v1,
    settle_source_project_reservation_v1, stage_fixed_root_project_admission_over_socket_v1,
    verify_policy_deployment_head_v1,
};
use aos_sandbox_core::{ObjectDigest, ProjectId};
use ed25519_dalek::{Signer as _, SigningKey};
use sha2::{Digest as _, Sha256};

use super::{CONTROLLER_UID, SOURCE_SIGNER_UID, credential_path};

const PROJECT: ProjectId = ProjectId::from_bytes([1; 16]);
const CANCELED_RESERVATION: &str = "/tmp/q04-project-canceled-reservation";
const ABORTED_STAGE: &str = "/tmp/q04-project-aborted-stage";
const SOURCE_SIGNER_SOCKET: &str = "/run/aos/sandbox-source-signerd.sock";
const RESERVATION_DOMAIN: &[u8] = b"aos.sandbox.source-project-admission-reservation.v1\0";

pub(super) fn run_controller_mode(mode: &str) -> Result<(), Box<dyn Error>> {
    let (mut source, _) =
        ProtectedSourceDomainJournalOwnerV1::open_fixed_protected_for_uid(CONTROLLER_UID)?;
    match mode {
        "project-cancel-pending" => cancel_pending(&mut source),
        "project-cancel-recover" => recover_cancellation(&mut source),
        "project-stage-abort" => stage_and_abort(&mut source),
        "project-stage-pending" => stage_pending(&mut source),
        "project-stage-recover" => recover_pending_stage(&mut source),
        "project-recovery-history" => query_historical_rows(&mut source),
        "project-recovery-deny-fresh" => deny_fresh_intent(&mut source),
        _ => Err("unknown project recovery mode".into()),
    }
}

fn prospective_reservation(
    source: &mut ProtectedSourceDomainJournalOwnerV1,
    nonce: [u8; 16],
) -> Result<SourceProjectAdmissionReservationV1, Box<dyn Error>> {
    let issue = read_source_project_reservation_status_v1(source)?
        .map(|(previous, _)| {
            previous
                .issue()
                .checked_add(1)
                .ok_or("Source issue exhausted")
        })
        .transpose()?
        .unwrap_or(1);
    let names = source.fixed_physical_names_v1()?;
    let mut bytes = [0; SOURCE_PROJECT_ADMISSION_RESERVATION_BYTES_V1];
    bytes[..8].copy_from_slice(b"AOSQPV01");
    bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
    bytes[16..24].copy_from_slice(&issue.to_be_bytes());
    bytes[24..40].copy_from_slice(&nonce);
    bytes[40..56].copy_from_slice(PROJECT.as_bytes());
    bytes[56..104].copy_from_slice(&names.to_bytes());
    let checksum = Sha256::new()
        .chain_update(RESERVATION_DOMAIN)
        .chain_update(&bytes[..104])
        .finalize();
    bytes[104..].copy_from_slice(&checksum);

    // Fixture bytes are only a proposal; the production Source writer must
    // derive and commit the same row before Root can stage it.
    Ok(SourceProjectAdmissionReservationV1::from_record_bytes(
        &bytes,
    )?)
}

fn begin_stage(
    source: &mut ProtectedSourceDomainJournalOwnerV1,
    nonce: [u8; 16],
) -> Result<RootProjectAdmissionStageV1, Box<dyn Error>> {
    let preview = prospective_reservation(source, nonce)?;
    prepare_fixed_root_project_intent_over_socket_v1(preview)?;
    let reservation = reserve_source_project_admission_v1(source, preview)?;
    let stage = stage_fixed_root_project_admission_over_socket_v1(reservation)?;
    if stage.source_reservation_digest() != reservation.record_digest() {
        return Err("Root stage changed the durable Source reservation".into());
    }
    let challenge = SourceHoldReadbackChallengeV1::new(stage.root_nonce(), stage.cut())?;
    let row = record_source_project_abort_only_challenge_v1(
        source,
        PROJECT,
        challenge,
        stage.record_digest(),
    )?;
    if row.stage() != stage.record_digest() {
        return Err("AbortOnly Source row changed the Root stage".into());
    }
    Ok(stage)
}

fn cancel_pending(source: &mut ProtectedSourceDomainJournalOwnerV1) -> Result<(), Box<dyn Error>> {
    let preview = prospective_reservation(source, [0x51; 16])?;
    prepare_fixed_root_project_intent_over_socket_v1(preview)?;
    let reservation = reserve_source_project_admission_v1(source, preview)?;
    fs::write(CANCELED_RESERVATION, reservation.record_bytes())?;
    cancel_fixed_root_project_reservation_over_socket_v1(reservation)?;
    if query_fixed_root_project_reservation_cancellation_v1(reservation)?.is_none() {
        return Err("Root cancellation marker absent before expiry".into());
    }
    Ok(())
}

fn recover_cancellation(
    source: &mut ProtectedSourceDomainJournalOwnerV1,
) -> Result<(), Box<dyn Error>> {
    let (reservation, canceled) = read_source_project_reservation_status_v1(source)?
        .ok_or("pending Source reservation absent")?;
    if canceled {
        return Err("Source reservation retired before Root replay".into());
    }
    let proof = query_fixed_root_project_reservation_cancellation_v1(reservation)?
        .ok_or("expired Root did not replay cancellation")?;
    settle_source_project_reservation_v1(source, reservation, proof)?;
    Ok(())
}

fn stage_and_abort(source: &mut ProtectedSourceDomainJournalOwnerV1) -> Result<(), Box<dyn Error>> {
    let stage = begin_stage(source, [0x52; 16])?;
    let (row, settled) =
        read_source_project_admission_status_v1(source)?.ok_or("AbortOnly Source row absent")?;
    if settled {
        return Err("AbortOnly Source row was already settled".into());
    }
    abort_fixed_root_project_admission_over_socket_v1(stage.record_digest(), row)?;
    let proof = query_fixed_root_project_admission_outcome_v1(stage.record_digest())?
        .ok_or("Root abort outcome absent")?;
    if proof.outcome().kind() != RootProjectAdmissionOutcomeKindV1::Aborted {
        return Err("AbortOnly stage unexpectedly admitted project policy".into());
    }
    settle_current_source_project_admission_challenge_v1(source, row, proof)?;
    fs::write(ABORTED_STAGE, stage.record_digest().as_bytes())?;
    Ok(())
}

fn stage_pending(source: &mut ProtectedSourceDomainJournalOwnerV1) -> Result<(), Box<dyn Error>> {
    let stage = begin_stage(source, [0x53; 16])?;
    if query_fixed_root_current_project_admission_stage_v1()? != Some(stage) {
        return Err("pending Root stage not replayable before expiry".into());
    }
    Ok(())
}

fn query_historical_rows(
    source: &mut ProtectedSourceDomainJournalOwnerV1,
) -> Result<(), Box<dyn Error>> {
    let reservation =
        SourceProjectAdmissionReservationV1::from_record_bytes(&fs::read(CANCELED_RESERVATION)?)?;
    if query_fixed_root_project_reservation_cancellation_v1(reservation)?.is_none() {
        return Err("expired Root lost historical cancellation".into());
    }
    let stage = ObjectDigest::from_bytes(
        fs::read(ABORTED_STAGE)?
            .try_into()
            .map_err(|_| "invalid prior Root stage fixture")?,
    );
    let proof = query_fixed_root_project_admission_outcome_v1(stage)?
        .ok_or("expired Root lost historical abort")?;
    if proof.outcome().kind() != RootProjectAdmissionOutcomeKindV1::Aborted {
        return Err("historical AbortOnly outcome changed".into());
    }
    let (row, settled) = read_source_project_admission_status_v1(source)?
        .ok_or("pending Source row absent at expired Root restart")?;
    if settled
        || query_fixed_root_current_project_admission_stage_v1()?
            .is_none_or(|stage| stage.record_digest() != row.stage())
    {
        return Err("expired Root lost current stage for pending Source row".into());
    }
    Ok(())
}

fn recover_pending_stage(
    source: &mut ProtectedSourceDomainJournalOwnerV1,
) -> Result<(), Box<dyn Error>> {
    let (row, settled) = read_source_project_admission_status_v1(source)?
        .ok_or("pending AbortOnly Source row absent")?;
    if settled {
        return Err("Source row already retired before recovery-only Abort".into());
    }
    let stage = query_fixed_root_current_project_admission_stage_v1()?
        .ok_or("expired Root did not replay pending stage")?;
    if stage.record_digest() != row.stage() {
        return Err("Root stage changed during recovery".into());
    }
    abort_fixed_root_project_admission_over_socket_v1(stage.record_digest(), row)?;
    let proof = query_fixed_root_project_admission_outcome_v1(stage.record_digest())?
        .ok_or("recovery-only Abort did not retain outcome")?;
    if proof.outcome().kind() != RootProjectAdmissionOutcomeKindV1::Aborted {
        return Err("recovery-only Abort returned a positive outcome".into());
    }
    settle_current_source_project_admission_challenge_v1(source, row, proof)?;
    Ok(())
}

fn deny_fresh_intent(
    source: &mut ProtectedSourceDomainJournalOwnerV1,
) -> Result<(), Box<dyn Error>> {
    if query_fixed_root_current_project_admission_stage_v1()?.is_some() {
        return Err("prior Root stage remained pending after recovery".into());
    }
    let preview = prospective_reservation(source, [0x54; 16])?;
    if prepare_fixed_root_project_intent_over_socket_v1(preview).is_ok() {
        return Err("expired Root recovery listener minted a fresh intent".into());
    }
    Ok(())
}

pub(super) fn expire_deployment_credential() -> Result<(), Box<dyn Error>> {
    let root = "aos-sandbox-policy-authorityd.service";
    let now = i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())?;
    let issued = now.checked_sub(120).ok_or("VM clock underflow")?;
    let expires = now.checked_sub(60).ok_or("VM clock underflow")?;
    let mut packet = b"AOSPDH01".to_vec();
    packet.extend_from_slice(&1_u64.to_be_bytes());
    packet.extend_from_slice(&issued.to_be_bytes());
    packet.extend_from_slice(&expires.to_be_bytes());
    let inputs = [
        "node-policy.json",
        "site-policy.json",
        "backend-capabilities.json",
        "catalogs.json",
    ]
    .map(|name| fs::read(credential_path(root, name)))
    .into_iter()
    .collect::<Result<Vec<_>, _>>()?;
    for input in &inputs {
        packet.extend_from_slice(&Sha256::digest(input));
    }
    let key = SigningKey::from_bytes(&[10; 32]);
    let mut signed = b"aos.sandbox.policy-deployment-head.v1\0".to_vec();
    signed.extend_from_slice(&packet);
    packet.extend_from_slice(&key.sign(&signed).to_bytes());
    let exact = PolicyDeploymentInputsV1 {
        node: &inputs[0],
        site: &inputs[1],
        backend: &inputs[2],
        catalogs: &inputs[3],
    };
    verify_policy_deployment_head_v1(&packet, &exact, &key.verifying_key(), now - 90)?;
    if verify_policy_deployment_head_v1(&packet, &exact, &key.verifying_key(), now).is_ok() {
        return Err("replacement deployment packet is not expired".into());
    }
    fs::write(credential_path(root, "deployment-head.packet"), packet)?;
    Ok(())
}

pub(super) fn launch_source_signer() -> Result<(), Box<dyn Error>> {
    let mut arguments = std::env::args().skip(2);
    let setpriv = arguments.next().ok_or("setpriv path required")?;
    let signer = arguments.next().ok_or("Source signer path required")?;
    if arguments.next().is_some()
        || !Path::new(&setpriv).is_absolute()
        || !Path::new(&signer).is_absolute()
    {
        return Err("invalid Source signer launcher arguments".into());
    }
    let listener = UnixListener::bind(SOURCE_SIGNER_SOCKET)?;
    rustix::fs::chownat(
        rustix::fs::CWD,
        SOURCE_SIGNER_SOCKET,
        Some(rustix::process::Uid::from_raw(SOURCE_SIGNER_UID)),
        Some(rustix::process::Gid::from_raw(CONTROLLER_UID)),
        rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
    )?;
    fs::set_permissions(SOURCE_SIGNER_SOCKET, fs::Permissions::from_mode(0o660))?;
    let listener: OwnedFd = listener.into();
    let error = Command::new(setpriv)
        .args([
            "--reuid=814",
            "--regid=814",
            "--clear-groups",
            "--bounding-set=-all",
            "--inh-caps=-all",
            "--ambient-caps=-all",
        ])
        .arg(signer)
        .args(["811", "811", "814", "814"])
        .env(
            "CREDENTIALS_DIRECTORY",
            "/run/credentials/aos-sandbox-source-signerd.service",
        )
        .stdin(Stdio::from(listener))
        .exec();
    Err(error.into())
}
