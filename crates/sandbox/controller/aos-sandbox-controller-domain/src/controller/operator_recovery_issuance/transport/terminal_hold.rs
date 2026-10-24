//! Same-child custody of the actual Storage terminal owner.
//!
//! The retained kernel record subject, independently pinned Storage role and
//! original socket are checked around Controller's local CAS. Dropping this
//! frame without settlement deliberately leaves Storage dispatch excluded.

use aos_sandbox_linux::seqpacket::descriptor_subject::ReceivedDescriptorRecord;
use aos_sandbox_protocol::operator_storage_repair_terminal_v4::{
    RepairTerminalRequestV4, RepairTerminalSettlementV4, RepairTerminalWitnessV4,
    verify_terminal_release_v4,
};

use super::*;

pub(crate) struct HeldStorageTerminalV4<'storage> {
    socket: DescriptorSubjectSocket,
    subject: ReceivedDescriptorRecord,
    service: &'storage ResourceInventoryServiceIdentity,
    request: RepairTerminalRequestV4,
    witness: RepairTerminalWitnessV4,
    process: PidFdInfo,
}

pub(crate) enum StorageTerminalAcquisitionV4<'storage> {
    Held(HeldStorageTerminalV4<'storage>),
    /// Historical owner settlement, explicitly not a reconstructed live hold.
    Settled(RepairTerminalSettlementV4, Vec<u8>),
}

pub(crate) fn verify_retained_terminal_readback_v4(
    packet: &[u8],
    expected_cut: [u8; 32],
    signer: &ProtectedOperatorRecoverySignerV1,
    owner: &ProtectedStorageRepairReceiptVerifierV2,
) -> Result<RepairTerminalSettlementV4, OperatorRecoveryIssuanceErrorV1> {
    if packet.len() != 1140 || &packet[..8] != b"AOSORZ04" {
        return Err(OperatorRecoveryIssuanceErrorV1::Binding);
    }
    let historical = RepairTerminalRequestV4::verify_retained_signed_header(
        &packet[8..660], signer.verifier(), signer.generation(),
    ).map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
    if historical.cut_digest() != expected_cut {
        return Err(OperatorRecoveryIssuanceErrorV1::Binding);
    }
    let witness = owner.verify_terminal_witness_v4(&packet[660..868], &historical)?;
    let ack = RepairTerminalSettlementV4::verify(&packet[868..1076], &historical, &witness, signer.verifier())
        .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
    verify_terminal_release_v4(&packet[868..], ack.as_bytes(), owner.verifier())
        .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
    owner.recheck()?;
    signer.credential.recheck().map_err(|_| OperatorRecoveryIssuanceErrorV1::Key)?;
    Ok(ack)
}

impl<'storage> HeldStorageTerminalV4<'storage> {
    pub(crate) fn acquire(
        request: RepairTerminalRequestV4,
        service: &'storage ResourceInventoryServiceIdentity,
        owner: &ProtectedStorageRepairReceiptVerifierV2,
        signer: &ProtectedOperatorRecoverySignerV1,
    ) -> Result<StorageTerminalAcquisitionV4<'storage>, OperatorRecoveryIssuanceErrorV1> {
        owner.recheck()?;
        let mut socket = DescriptorSubjectSocket::connect(Path::new(OPERATOR_STORAGE_REPAIR_SOCKET_PATH_V3))
            .map_err(|_| OperatorRecoveryIssuanceErrorV1::OutcomeUnknown)?;
        send(&mut socket, &request.encode(), request.deadline())
            .map_err(|_| OperatorRecoveryIssuanceErrorV1::OutcomeUnknown)?;
        let subject = receive(&mut socket, request.deadline())
            .map_err(|_| OperatorRecoveryIssuanceErrorV1::OutcomeUnknown)?;
        if !subject.descriptors().is_empty() {
            return Err(OperatorRecoveryIssuanceErrorV1::Binding);
        }
        let process = validate_service_subject(service, subject.subject())?;
        if subject.payload().starts_with(b"AOSORZ04") {
            let packet = subject.payload();
            let ack = verify_retained_terminal_readback_v4(packet, request.cut_digest(), signer, owner)?;
            if !same_process(process, validate_service_subject(service, subject.subject())?) {
                return Err(OperatorRecoveryIssuanceErrorV1::Binding);
            }
            owner.recheck()?;
            signer.credential.recheck().map_err(|_| OperatorRecoveryIssuanceErrorV1::Key)?;
            return Ok(StorageTerminalAcquisitionV4::Settled(ack, packet.to_vec()));
        }
        let witness = owner.verify_terminal_witness_v4(subject.payload(), &request)?;
        let held = Self { socket, subject, service, request, witness, process };
        held.recheck(owner)?;
        Ok(StorageTerminalAcquisitionV4::Held(held))
    }

    pub(crate) fn request(&self) -> &RepairTerminalRequestV4 { &self.request }

    pub(crate) fn witness(&self) -> &RepairTerminalWitnessV4 { &self.witness }

    pub(crate) fn recheck(&self, owner: &ProtectedStorageRepairReceiptVerifierV2) -> Result<(), OperatorRecoveryIssuanceErrorV1> {
        owner.recheck()?;
        let current = validate_service_subject(self.service, self.subject.subject())?;
        if !same_process(self.process, current) || boottime()? >= self.request.deadline() {
            return Err(OperatorRecoveryIssuanceErrorV1::OutcomeUnknown);
        }
        let mut readiness = [PollFd::from_borrowed_fd(
            self.socket.as_fd().map_err(|_| OperatorRecoveryIssuanceErrorV1::OutcomeUnknown)?,
            PollFlags::IN,
        )];
        let zero = rustix::event::Timespec { tv_sec: 0, tv_nsec: 0 };
        match poll(&mut readiness, Some(&zero)) {
            Ok(_) if !readiness[0].revents().intersects(PollFlags::HUP | PollFlags::ERR | PollFlags::NVAL) => Ok(()),
            _ => Err(OperatorRecoveryIssuanceErrorV1::OutcomeUnknown),
        }
    }

    pub(crate) fn settle(mut self, ack: RepairTerminalSettlementV4, owner: &ProtectedStorageRepairReceiptVerifierV2) -> Result<Vec<u8>, OperatorRecoveryIssuanceErrorV1> {
        self.recheck(owner)?;
        send(&mut self.socket, ack.as_bytes(), self.request.deadline())
            .map_err(|_| OperatorRecoveryIssuanceErrorV1::OutcomeUnknown)?;
        let release = receive(&mut self.socket, self.request.deadline())
            .map_err(|_| OperatorRecoveryIssuanceErrorV1::OutcomeUnknown)?;
        if !release.descriptors().is_empty()
            || !same_process(self.process, validate_service_subject(self.service, release.subject())?)
        {
            return Err(OperatorRecoveryIssuanceErrorV1::Binding);
        }
        verify_terminal_release_v4(release.payload(), ack.as_bytes(), owner.verifier())
            .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
        owner.recheck()?;
        let mut readback = b"AOSORZ04".to_vec();
        readback.extend_from_slice(self.request.signed_header());
        readback.extend_from_slice(self.witness.as_bytes());
        readback.extend_from_slice(release.payload());
        Ok(readback)
    }
}
