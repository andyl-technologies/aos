//! Installed negative-only recovery with original Controller/Source custody.
//!
//! Only the explicit debug fixture seeds synthetic historical publisher heads.
//! Every signature, reservation, decision, floor and ACK below comes from the
//! actual fixed owner API or authenticated installed Root/Source endpoint. No
//! cached file, NotFound reply or dropped ACK is used as retirement authority.

use std::error::Error;
use std::fs;
use std::io::Write as _;
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use aos_sandbox::controller_service::journal::production_journal_limits;
use aos_sandbox::lifecycle::protected_journal_join::ProtectedSourceDomainJournalOwnerV1;
use aos_sandbox::policy_compiler::{
    CONTROLLER_PROJECT_DISPATCH_READBACK_BYTES_V1, PinnedControllerHoldSignerV1,
    ROOT_PROJECT_HISTORY_RETIRE_MAGIC, ROOT_PROJECT_NEGATIVE_INTENT_QUERY_MAGIC,
    RootProjectAdmissionOutcomeProofV1, RootProjectReservationCancellationProofV1,
    acknowledge_source_project_terminal_retirement_v1,
    cancel_fixed_root_project_reservation_over_socket_v1,
    preflight_source_project_negative_recovery_v1,
    prepare_fixed_root_project_negative_intent_over_socket_v1,
    query_fixed_root_current_project_admission_stage_v1, query_fixed_root_project_history_floor_v1,
    query_fixed_root_project_intent_v1, query_fixed_root_project_negative_intent_v1,
    query_fixed_root_project_reservation_cancellation_v1, read_source_project_admission_status_v1,
    read_source_project_reservation_status_v1, reserve_source_project_admission_v1,
    retire_fixed_root_project_history_over_socket_v1,
    settle_current_source_project_admission_challenge_v1, settle_source_project_reservation_v1,
    sign_fixed_controller_project_dispatch_readback_v1,
    sign_fixed_controller_project_terminal_readback_v1,
};
use aos_sandbox::reconciler::{
    RetainedControllerProjectAdmissionV1, accept_controller_project_admission_outcome_v1,
    accept_controller_project_history_floor_v1,
    accept_controller_project_reservation_cancellation_v1,
    fail_retired_project_history_vm_operation_v1, prepare_project_history_vm_flight_v1,
    preview_project_history_vm_reservation_v1, public_operation_resource_from_journal_v1,
    require_project_history_vm_flight_v1, retained_controller_project_admission_v1,
};
use aos_sandbox::{ControllerRequestScopeV1, Journal, JournalError};
use aos_sandbox_core::{ObjectDigest, OperationId};
use ed25519_dalek::SigningKey;

use super::{CONTROLLER_ROOT, CONTROLLER_UID, credential_path};

pub(super) const NEGATIVE_TAG: u8 = 0x60;
const ROOT_SOCKET: &str = "/run/aos/sandbox-policy-authority/current-head.sock";
const SOURCE_JOURNAL: &str = "/var/lib/aos/sandbox/source-domains/source-domains-v1.journal";

/// Holds the canonical Controller→Source writer order across each VM cut.
pub(super) struct Owners {
    pub controller: Journal,
    pub source: ProtectedSourceDomainJournalOwnerV1,
}

impl Owners {
    pub fn open() -> Result<Self, Box<dyn Error>> {
        let (controller, _) = Journal::open_protected_at_for_uid(
            Path::new(CONTROLLER_ROOT),
            "controller.journal",
            production_journal_limits(),
            CONTROLLER_UID,
        )?;
        let (source, _) =
            ProtectedSourceDomainJournalOwnerV1::open_fixed_protected_for_uid(CONTROLLER_UID)?;
        Ok(Self { controller, source })
    }

    pub fn prepare(self, tag: u8) -> Result<Self, Box<dyn Error>> {
        let Self {
            controller,
            mut source,
        } = self;
        let controller = prepare_project_history_vm_flight_v1(controller, &mut source, tag)?;
        Ok(Self { controller, source })
    }

    pub fn flight(&mut self) -> Result<RetainedControllerProjectAdmissionV1, Box<dyn Error>> {
        if let Some(flight) =
            retained_controller_project_admission_v1(&self.controller, scope()?, None)?
        {
            return Ok(flight);
        }
        let reservation = read_source_project_reservation_status_v1(&mut self.source)?
            .ok_or("VM original Source row absent")?
            .0;
        retained_controller_project_admission_v1(&self.controller, scope()?, Some(reservation))?
            .ok_or_else(|| "VM original Controller flight absent".into())
    }

    pub fn cuts(&self) -> Result<(u64, u64), Box<dyn Error>> {
        Ok((
            self.controller.snapshot_sequence(),
            fs::metadata(SOURCE_JOURNAL)?.len(),
        ))
    }

    pub fn accept_cancellation(
        &mut self,
        flight: &RetainedControllerProjectAdmissionV1,
        proof: RootProjectReservationCancellationProofV1,
    ) -> Result<(), Box<dyn Error>> {
        accept_controller_project_reservation_cancellation_v1(
            &mut self.controller,
            &mut self.source,
            flight.operation(),
            scope()?,
            flight.plan(),
            proof,
        )?;
        settle_source_project_reservation_v1(&mut self.source, flight.reservation(), proof)?;
        Ok(())
    }

    pub fn accept_outcome(
        &mut self,
        flight: &RetainedControllerProjectAdmissionV1,
        proof: RootProjectAdmissionOutcomeProofV1,
    ) -> Result<(), Box<dyn Error>> {
        let (row, _) = read_source_project_admission_status_v1(&mut self.source)?
            .ok_or("VM actual Source challenge absent")?;
        accept_controller_project_admission_outcome_v1(
            &mut self.controller,
            &mut self.source,
            flight.operation(),
            scope()?,
            flight.plan(),
            proof,
        )?;
        settle_current_source_project_admission_challenge_v1(&mut self.source, row, proof)?;
        Ok(())
    }

    pub fn finish_history(
        &mut self,
        flight: &RetainedControllerProjectAdmissionV1,
    ) -> Result<(), Box<dyn Error>> {
        let proof = match query_fixed_root_project_history_floor_v1(flight.reservation())? {
            Some(proof) => proof,
            None => {
                let packet = with_controller_key(|generation, key| {
                    Ok(sign_fixed_controller_project_terminal_readback_v1(
                        &self.controller,
                        flight.operation(),
                        generation,
                        key,
                    )?)
                })?;
                retire_fixed_root_project_history_over_socket_v1(flight.reservation(), &packet)?
            }
        };
        let acceptance = accept_controller_project_history_floor_v1(
            &mut self.controller,
            flight.operation(),
            scope()?,
            flight.plan(),
            proof,
        )?;
        acknowledge_source_project_terminal_retirement_v1(&mut self.source, proof, &acceptance)?;
        Ok(())
    }
}

pub(super) fn run(mode: &str) -> Result<(), Box<dyn Error>> {
    let mut owners = Owners::open()?;
    if mode == "project-negative-dispatch" {
        if read_source_project_reservation_status_v1(&mut owners.source)?.is_some()
            || query_fixed_root_current_project_admission_stage_v1()?.is_some()
        {
            return Err("pre-dispatch crash fixture is not empty".into());
        }
        owners = owners.prepare(NEGATIVE_TAG)?;
        let flight = owners.flight()?;
        if query_fixed_root_project_intent_v1(flight.reservation())?.is_some()
            || query_fixed_root_project_reservation_cancellation_v1(flight.reservation())?.is_some()
        {
            return Err("Root artifact preceded the Controller crash cut".into());
        }
        return require_project_history_vm_flight_v1(
            &owners.controller,
            &mut owners.source,
            NEGATIVE_TAG,
            false,
        );
    }
    if matches!(
        mode,
        "project-negative-operation-denied"
            | "project-negative-operation-terminal"
            | "project-negative-operation-replay"
    ) {
        return terminal_operation(owners, mode);
    }
    let flight = owners.flight()?;
    match mode {
        "project-negative-pin-denied" => reject_rotated_key(&mut owners, &flight),
        "project-negative-intent-lost-reply" => negative_intent(&mut owners, &flight, true),
        "project-negative-intent-retry" => negative_intent(&mut owners, &flight, false),
        "project-negative-reserve" => reserve_cancellation(&mut owners, &flight),
        "project-negative-terminal" => {
            let proof = query_fixed_root_project_reservation_cancellation_v1(flight.reservation())?
                .ok_or("cold Root cancellation absent")?;
            owners.accept_cancellation(&flight, proof)?;
            require_fenced_preview(&mut owners, &flight)
        }
        "project-negative-floor-lost-reply" => floor_without_controller_ack(&mut owners, &flight),
        "project-negative-controller-accept" => {
            let proof = query_fixed_root_project_history_floor_v1(flight.reservation())?
                .ok_or("Root floor absent before Controller acceptance")?;
            let token = accept_controller_project_history_floor_v1(
                &mut owners.controller,
                flight.operation(),
                scope()?,
                flight.plan(),
                proof,
            )?;
            drop(token);
            if retained_controller_project_admission_v1(&owners.controller, scope()?, None)?
                .is_some()
            {
                return Err("Controller RootRetired readback absent".into());
            }
            require_fenced_preview(&mut owners, &flight)
        }
        "project-negative-ack" => owners.finish_history(&flight),
        "project-negative-replay" => {
            let before = owners.cuts()?;
            owners.finish_history(&flight)?;
            require_project_history_vm_flight_v1(
                &owners.controller,
                &mut owners.source,
                NEGATIVE_TAG,
                true,
            )?;
            if owners.cuts()? != before {
                return Err("exact cold retirement replay appended an owner cut".into());
            }
            Ok(())
        }
        "project-negative-late-positive-denied" => {
            let before = owners.cuts()?;
            if aos_sandbox::policy_compiler::prepare_fixed_root_project_intent_over_socket_v1(
                flight.reservation(),
            )
            .is_ok()
                || aos_sandbox::policy_compiler::stage_fixed_root_project_admission_over_socket_v1(
                    flight.reservation(),
                )
                .is_ok()
                || owners.cuts()? != before
            {
                return Err("retired negative issue regained positive authority".into());
            }
            require_project_history_vm_flight_v1(
                &owners.controller,
                &mut owners.source,
                NEGATIVE_TAG,
                true,
            )
        }
        "project-negative-stage-denied" => reject_present_stage(&mut owners, &flight),
        _ => Err("unknown negative recovery mode".into()),
    }
}

fn terminal_operation(owners: Owners, mode: &str) -> Result<(), Box<dyn Error>> {
    let operation = OperationId::from_bytes([NEGATIVE_TAG; 16]);
    let before = owners.cuts()?;
    let Owners {
        controller,
        mut source,
    } = owners;
    let result =
        fail_retired_project_history_vm_operation_v1(controller, &mut source, NEGATIVE_TAG);
    if mode == "project-negative-operation-denied" {
        if result.is_ok() {
            return Err("original Create became terminal before complete retirement joins".into());
        }
        drop(source);
        let owners = Owners::open()?;
        let public = public_operation_resource_from_journal_v1(&owners.controller, operation)?
            .ok_or("original operation disappeared after refused terminal transition")?;
        if owners.cuts()? != before || public.completed_at.as_option().is_some() {
            return Err("refused terminal transition changed the in-flight original Create".into());
        }
        return Ok(());
    }
    let owners = Owners {
        controller: result?,
        source,
    };
    let public = public_operation_resource_from_journal_v1(&owners.controller, operation)?
        .ok_or("original terminal operation absent")?;
    if public.completed_at.as_option().is_none()
        || (mode == "project-negative-operation-replay" && owners.cuts()? != before)
    {
        return Err(
            "cold terminal replay changed or successfully completed the original Create".into(),
        );
    }
    Ok(())
}

fn negative_intent(
    owners: &mut Owners,
    flight: &RetainedControllerProjectAdmissionV1,
    lose_reply: bool,
) -> Result<(), Box<dyn Error>> {
    if read_source_project_reservation_status_v1(&mut owners.source)?.is_some() {
        return Err("Source reservation preceded durable negative intent".into());
    }
    let before = owners.cuts()?;
    let packet = dispatch_packet(owners, flight)?;
    preflight_source_project_negative_recovery_v1(&mut owners.source, flight.reservation())?;
    if lose_reply {
        discard_reply(
            ROOT_PROJECT_NEGATIVE_INTENT_QUERY_MAGIC,
            flight.reservation().client_nonce(),
            &[&packet],
        )?;
    }
    let intent = query_fixed_root_project_negative_intent_v1(flight.reservation(), &packet)?
        .ok_or("ambiguous negative intent did not persist")?;
    let replay =
        prepare_fixed_root_project_negative_intent_over_socket_v1(flight.reservation(), &packet)?;
    if replay != intent || !intent.is_retirement_only() || owners.cuts()? != before {
        return Err("negative intent retry changed original custody".into());
    }
    if aos_sandbox::policy_compiler::stage_fixed_root_project_admission_over_socket_v1(
        flight.reservation(),
    )
    .is_ok()
    {
        return Err("negative intent acquired positive stage authority".into());
    }
    Ok(())
}

fn reject_rotated_key(
    owners: &mut Owners,
    flight: &RetainedControllerProjectAdmissionV1,
) -> Result<(), Box<dyn Error>> {
    let before = owners.cuts()?;
    let packet = dispatch_packet(owners, flight)?;
    if prepare_fixed_root_project_negative_intent_over_socket_v1(flight.reservation(), &packet)
        .is_ok()
        || query_fixed_root_project_intent_v1(flight.reservation())?.is_some()
        || read_source_project_reservation_status_v1(&mut owners.source)?.is_some()
        || owners.cuts()? != before
    {
        return Err("rotated Controller credential changed historical Root authority".into());
    }
    Ok(())
}

fn reserve_cancellation(
    owners: &mut Owners,
    flight: &RetainedControllerProjectAdmissionV1,
) -> Result<(), Box<dyn Error>> {
    if query_fixed_root_current_project_admission_stage_v1()?.is_some() {
        return Err("Root stage present before cancellation-only Source append".into());
    }
    let proof = query_fixed_root_project_reservation_cancellation_v1(flight.reservation())?
        .ok_or("Root startup did not durably cancel the unstaged intent")?;
    if proof.marker().reservation() != flight.reservation().record_digest() {
        return Err("Root denial changed the original Source proposal".into());
    }
    preflight_source_project_negative_recovery_v1(&mut owners.source, flight.reservation())?;
    reserve_source_project_admission_v1(&mut owners.source, flight.reservation())?;
    if read_source_project_admission_status_v1(&mut owners.source)?.is_some() {
        return Err("cancellation-only reservation fabricated ancestry".into());
    }
    Ok(())
}

fn floor_without_controller_ack(
    owners: &mut Owners,
    flight: &RetainedControllerProjectAdmissionV1,
) -> Result<(), Box<dyn Error>> {
    let packet = with_controller_key(|generation, key| {
        Ok(sign_fixed_controller_project_terminal_readback_v1(
            &owners.controller,
            flight.operation(),
            generation,
            key,
        )?)
    })?;
    let reservation = flight.reservation().record_bytes();
    discard_reply(
        ROOT_PROJECT_HISTORY_RETIRE_MAGIC,
        flight.reservation().client_nonce(),
        &[&reservation, &packet],
    )?;
    query_fixed_root_project_history_floor_v1(flight.reservation())?
        .ok_or("lost Root floor reply did not persist")?;
    require_fenced_preview(owners, flight)
}

fn require_fenced_preview(
    owners: &mut Owners,
    flight: &RetainedControllerProjectAdmissionV1,
) -> Result<(), Box<dyn Error>> {
    let before = owners.cuts()?;
    if read_source_project_reservation_status_v1(&mut owners.source)?
        != Some((flight.reservation(), true))
        || read_source_project_admission_status_v1(&mut owners.source)?.is_some()
    {
        return Err("Source lost the exact cancellation-only terminal row".into());
    }
    let preview = preview_project_history_vm_reservation_v1(
        &mut owners.source,
        flight.reservation().client_nonce(),
        flight.reservation().project(),
    );
    // A canceled row refuses even identical preview until the exact ACK. After
    // that ACK the same nonce instead selects issue+1, checked on cold replay.
    if !matches!(preview, Err(JournalError::ProtectedBoundary)) || owners.cuts()? != before {
        return Err("Source advanced before exact borrowed Controller retirement ACK".into());
    }
    Ok(())
}

pub(super) fn reject_present_stage(
    owners: &mut Owners,
    flight: &RetainedControllerProjectAdmissionV1,
) -> Result<(), Box<dyn Error>> {
    let stage = query_fixed_root_current_project_admission_stage_v1()?
        .ok_or("cold stage fixture absent")?;
    let before = owners.cuts()?;
    let packet = dispatch_packet(owners, flight)?;
    if prepare_fixed_root_project_negative_intent_over_socket_v1(flight.reservation(), &packet)
        .is_ok()
        || query_fixed_root_current_project_admission_stage_v1()? != Some(stage)
        || owners.cuts()? != before
    {
        return Err("negative recovery changed a present Root stage or Source cut".into());
    }
    Ok(())
}

fn dispatch_packet(
    owners: &Owners,
    flight: &RetainedControllerProjectAdmissionV1,
) -> Result<[u8; CONTROLLER_PROJECT_DISPATCH_READBACK_BYTES_V1], Box<dyn Error>> {
    with_controller_key(|generation, key| {
        Ok(sign_fixed_controller_project_dispatch_readback_v1(
            &owners.controller,
            flight.operation(),
            generation,
            key,
        )?)
    })
}

pub(super) fn scope() -> Result<ControllerRequestScopeV1, Box<dyn Error>> {
    Ok(ControllerRequestScopeV1::new(ObjectDigest::from_bytes(
        [0xe1; 32],
    ))?)
}

pub(super) fn with_controller_key<T>(
    action: impl FnOnce(u64, &SigningKey) -> Result<T, Box<dyn Error>>,
) -> Result<T, Box<dyn Error>> {
    let seed: [u8; 32] = fs::read(credential_path(
        "aos-sandboxd.service",
        "controller-hold-signing-key",
    ))?
    .try_into()
    .map_err(|_| "invalid installed Controller seed")?;
    let pin = PinnedControllerHoldSignerV1::decode(&fs::read(credential_path(
        "aos-sandboxd.service",
        "controller-hold-public-key",
    ))?)?;
    let key = SigningKey::from_bytes(&seed);
    if pin.verifying_key() != &key.verifying_key() {
        return Err("Controller seed differs from its protected credential pin".into());
    }
    action(pin.generation(), &key)
}

fn discard_reply(magic: &[u8; 8], nonce: [u8; 16], bodies: &[&[u8]]) -> Result<(), Box<dyn Error>> {
    let mut stream = UnixStream::connect(ROOT_SOCKET)?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    if !rustix::net::sockopt::socket_peercred(&stream)?
        .uid
        .is_root()
        || stream.peer_addr()?.as_pathname() != Some(Path::new(ROOT_SOCKET))
    {
        return Err("ambiguous request reached a foreign Root peer".into());
    }
    let mut header = [0; 32];
    header[..8].copy_from_slice(magic);
    header[8..24].copy_from_slice(&nonce);
    stream.write_all(&header)?;
    for body in bodies {
        stream.write_all(body)?;
    }
    stream.shutdown(Shutdown::Write)?;
    // Closing without reading creates an actual lost-reply cut. The caller
    // subsequently uses only the ordinary peer-checked exact query API.
    drop(stream);
    Ok(())
}
