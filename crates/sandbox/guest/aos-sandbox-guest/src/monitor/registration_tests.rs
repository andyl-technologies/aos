//! Native ownership tests without a fabricated installation or child grant.

use super::*;
use std::os::fd::{AsFd as _, AsRawFd as _};

#[test]
fn received_non_pidfd_stays_owned_after_typed_child_refusal() {
    let (mut receiver, endpoint) = SeqpacketSocket::pair_with_record_subjects().unwrap();
    let mut sender = SeqpacketSocket::from_owned(endpoint).unwrap();
    let file = std::fs::File::open("/dev/null").unwrap();
    sender
        .send_with_descriptors(b"invalid child", &[file.as_fd()])
        .unwrap();
    let mut packet = registration::RegistrationPacketV2::default();

    assert!(packet.receive(&mut receiver, true, None).unwrap());
    let path = format!(
        "/proc/self/fd/{}",
        packet.record().unwrap().descriptors()[0].as_raw_fd()
    );
    assert!(packet.admit_child().is_err());

    assert!(std::fs::read_link(&path).is_ok());
    assert!(packet.record().unwrap().descriptors().is_empty());
    assert!(packet.receive(&mut receiver, true, None).is_err());
    assert!(std::fs::read_link(&path).is_ok());
    drop(packet);
    assert!(std::fs::read_link(path).is_err());
}

#[test]
fn registration_without_its_required_right_keeps_the_native_failure() {
    let (mut receiver, endpoint) = SeqpacketSocket::pair_with_record_subjects().unwrap();
    let mut sender = SeqpacketSocket::from_owned(endpoint).unwrap();
    sender.send(b"missing child").unwrap();
    let mut packet = registration::RegistrationPacketV2::default();

    assert!(packet.receive(&mut receiver, true, None).is_err());

    assert!(matches!(packet.received, Some(Err(_))));
    assert!(packet.receive(&mut receiver, true, None).is_err());
}

#[test]
fn registered_receiver_requires_real_queue_and_mode_completion() {
    let (mut receiver, endpoint) = SeqpacketSocket::pair_with_record_subjects().unwrap();
    let mut sender = SeqpacketSocket::from_owned(endpoint).unwrap();
    let mut restriction = aos_sandbox_linux::seqpacket::SeqpacketRightsRestrictionOriginalV6::new();
    assert!(
        receiver
            .receive_registered_guest_monitor_request_retaining_v2(64, &restriction)
            .is_err()
    );

    receiver
        .restrict_incoming_rights_retaining_v6(&mut restriction)
        .unwrap();
    sender.send(b"terminal query").unwrap();
    let record = receiver
        .receive_registered_guest_monitor_request_retaining_v2(64, &restriction)
        .unwrap();

    assert_eq!(record.payload(), b"terminal query");
    assert_eq!(
        SeqpacketSocket::registered_guest_monitor_receive_obligations_v2(64)
            .unwrap()
            .1,
        3
    );
    assert_eq!(
        SeqpacketSocket::guest_monitor_registration_obligations_v2(64)
            .unwrap()
            .1,
        20
    );
    assert!(
        receiver
            .require_rights_restriction_current_v6(&restriction)
            .is_ok()
    );
}

#[test]
fn failed_registration_cannot_prove_an_empty_finished_registry() {
    let (connection, _endpoint) = SeqpacketSocket::pair_with_record_subjects().unwrap();
    let path = format!("/proc/self/fd/{}", connection.as_fd().unwrap().as_raw_fd());
    let mut original = registration::MonitorRegistrationOriginalV2::new(connection);
    original.body = Some(Err(Error::InvalidRequest));
    let registry = MonitorRegistry::default();
    registry.0.lock().unwrap().registration = Some(original);

    assert!(registry.registration_refused());
    assert!(registry.finish_execution([1; 16]).is_err());
    assert!(std::fs::read_link(&path).is_ok());

    registry.close();
    assert!(std::fs::read_link(path).is_err());
}
