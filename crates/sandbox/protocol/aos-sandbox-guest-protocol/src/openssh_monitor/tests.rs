//! Hostile public-witness checks; root provenance is tested separately in Linux.

use ed25519_dalek::{Signer as _, SigningKey};
use ssh_key::Certificate;

use super::*;
use crate::openssh_attach_certificate::tests::{builder, certificate, claim, command};

fn string(bytes: &mut Vec<u8>, value: &[u8]) {
    bytes.extend_from_slice(&u32::try_from(value.len()).unwrap().to_be_bytes());
    bytes.extend_from_slice(value);
}

fn fixture() -> (OpenSshGateClaimV1, PublicAttachTicketBindingV2, Vec<u8>) {
    let claim = claim();
    let mut issuer = builder(&claim, 17);
    issuer
        .critical_option("force-command", command(&claim))
        .unwrap();
    issuer.extension("permit-pty", "").unwrap();
    let original_certificate = certificate(issuer, 8);
    let holder = SigningKey::from_bytes(&[17; 32]);
    let mut grant = [0; 416];
    grant[..8].copy_from_slice(b"AOSAPG01");
    grant[8..24].copy_from_slice(&claim.binding.attach_operation_id);
    grant[24..40].copy_from_slice(&claim.binding.execution_id);
    let ticket = PublicAttachTicketBindingV2 {
        operation_id: claim.binding.attach_operation_id,
        execution_id: claim.binding.execution_id,
        incarnation_id: claim.binding.incarnation_id,
        principal_id: claim.binding.principal_id,
        audit_id: claim.binding.audit_id,
        assignment_epoch: claim.binding.assignment_epoch,
        valid_after: 1000,
        expires_at: 1300,
        holder_public_key: holder.verifying_key().to_bytes(),
        request_digest: [20; 32],
        decision_digest: [21; 32],
        pending_grant: grant,
        base_route_digest: claim.route_digest,
        certificate: original_certificate.into_bytes(),
    };
    let binary = Certificate::from_openssh(std::str::from_utf8(&ticket.certificate).unwrap())
        .unwrap()
        .to_bytes()
        .unwrap();
    let session = [22; 32];
    let mut signed_message = Vec::new();
    string(&mut signed_message, &session);
    signed_message.push(50);
    string(&mut signed_message, claim.binding.user.as_bytes());
    string(&mut signed_message, b"ssh-connection");
    string(&mut signed_message, b"publickey");
    signed_message.push(1);
    string(
        &mut signed_message,
        PUBLIC_ATTACH_CERTIFICATE_TYPE_V1.as_bytes(),
    );
    string(&mut signed_message, &binary);
    let packet = packet(&session, &binary, &signed_message, &holder);
    (claim, ticket, packet)
}

fn packet(session: &[u8], certificate: &[u8], data: &[u8], holder: &SigningKey) -> Vec<u8> {
    let mut signature = Vec::new();
    string(&mut signature, b"ssh-ed25519");
    string(&mut signature, &holder.sign(data).to_bytes());
    let mut packet = b"AOSAMR02".to_vec();
    packet.extend_from_slice(&1000u32.to_be_bytes());
    packet.extend_from_slice(&1000u32.to_be_bytes());
    for section in [session, certificate, data, &signature] {
        string(&mut packet, section);
    }
    packet
}

#[test]
fn exact_original_certificate_holder_and_session_are_checked() {
    let (claim, ticket, packet) = fixture();
    let witness = OpenSshMonitorWitnessV2::decode(&packet).unwrap();
    witness
        .validate_original_holder(&claim, &ticket, 1100)
        .unwrap();
    assert_eq!(witness.uid, 1000);
    assert_eq!(witness.session, &[22; 32]);
    assert_eq!(&packet[..20], b"AOSAMR02\0\0\x03\xe8\0\0\x03\xe8\0\0\0 ");

    for now in [999, 1300, 1400] {
        assert!(
            witness
                .validate_original_holder(&claim, &ticket, now)
                .is_err()
        );
    }
    let mut foreign = ticket.clone();
    foreign.holder_public_key = SigningKey::from_bytes(&[23; 32]).verifying_key().to_bytes();
    assert!(
        witness
            .validate_original_holder(&claim, &foreign, 1100)
            .is_err()
    );
    let mut foreign_claim = claim.clone();
    foreign_claim.binding.execution_id = [24; 16];
    assert!(
        witness
            .validate_original_holder(&foreign_claim, &ticket, 1100)
            .is_err()
    );

    let mut second = builder(&claim, 17);
    second.serial(25).unwrap();
    second
        .critical_option("force-command", command(&claim))
        .unwrap();
    second.extension("permit-pty", "").unwrap();
    let mut substituted = ticket.clone();
    substituted.certificate = certificate(second, 8).into_bytes();
    assert!(
        witness
            .validate_original_holder(&claim, &substituted, 1100)
            .is_err()
    );
}

#[test]
fn signed_message_cannot_substitute_session_holder_or_fields() {
    let (claim, ticket, packet_bytes) = fixture();
    let witness = OpenSshMonitorWitnessV2::decode(&packet_bytes).unwrap();
    let holder = SigningKey::from_bytes(&[17; 32]);
    let foreign_session = packet(
        &[26; 32],
        witness.certificate,
        witness.signed_message,
        &holder,
    );
    assert!(
        OpenSshMonitorWitnessV2::decode(&foreign_session)
            .unwrap()
            .validate_original_holder(&claim, &ticket, 1100)
            .is_err()
    );
    let foreign_holder = packet(
        witness.session,
        witness.certificate,
        witness.signed_message,
        &SigningKey::from_bytes(&[27; 32]),
    );
    assert!(
        OpenSshMonitorWitnessV2::decode(&foreign_holder)
            .unwrap()
            .validate_original_holder(&claim, &ticket, 1100)
            .is_err()
    );
    for offset in 0..witness.signed_message.len() {
        let mut data = witness.signed_message.to_vec();
        data[offset] ^= 1;
        let altered = packet(witness.session, witness.certificate, &data, &holder);
        assert!(
            OpenSshMonitorWitnessV2::decode(&altered)
                .unwrap()
                .validate_original_holder(&claim, &ticket, 1100)
                .is_err(),
            "offset {offset}"
        );
    }
}

#[test]
fn unknown_partial_unbounded_trailing_and_root_login_records_fail_closed() {
    let (_, _, packet) = fixture();
    for end in 0..packet.len() {
        assert!(OpenSshMonitorWitnessV2::decode(&packet[..end]).is_err());
    }
    for offset in [7, 16, 17, 18] {
        let mut changed = packet.clone();
        changed[offset] ^= 0x80;
        assert!(OpenSshMonitorWitnessV2::decode(&changed).is_err());
    }
    let mut root = packet.clone();
    root[8..12].fill(0);
    assert!(OpenSshMonitorWitnessV2::decode(&root).is_err());
    let mut trailing = packet;
    trailing.push(0);
    assert!(OpenSshMonitorWitnessV2::decode(&trailing).is_err());
    assert!(
        OpenSshMonitorWitnessV2::decode(&vec![0; OPENSSH_MONITOR_MAXIMUM_RECORD_BYTES_V2 + 1])
            .is_err()
    );
}
