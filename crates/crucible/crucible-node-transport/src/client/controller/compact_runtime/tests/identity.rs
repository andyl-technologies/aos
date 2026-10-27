//! Checks original registrar and descriptor identity across the opaque move.

use super::*;

#[test]
fn runtime_reads_keep_the_original_registrar_peer_content_and_descriptor() -> TestResult {
    let (mut handshake, mut original, _peer, reference) = fixture(8);
    let controller = original.as_ref().unwrap();
    let read = controller.original_registrar_read(&handshake)?;
    let peer = controller.peer_pid();
    let executable = controller.peer_executable().clone();
    let content = controller.content(&reference)?.as_ptr();
    let descriptors = controller.retained_descriptor_count_data()?;
    let mut output = None;

    CompactRuntimeController::retain_into(&mut original, &mut output)?;
    let runtime = output.as_mut().unwrap();
    let current = runtime.original_registrar_read(&handshake)?;

    assert!(read.same_original(&current));
    read.ensure_current()?;
    current.ensure_current()?;
    assert_eq!(runtime.peer_pid(), peer);
    assert_eq!(runtime.peer_executable(), &executable);
    assert_eq!(runtime.content(&reference)?.as_ptr(), content);
    assert_eq!(runtime.retained_descriptor_count_data()?, descriptors);
    assert_eq!(runtime.journal_byte_reservations_data()[1..], [0, 0]);

    runtime.fence();
    handshake.contain();

    assert!(runtime.original_registrar_read(&handshake).is_err());
    assert!(read.ensure_current().is_err());
    assert!(current.ensure_current().is_err());
    assert_eq!(runtime.retained_descriptor_count_data()?, descriptors);
    assert_eq!(runtime.content(&reference)?.as_ptr(), content);
    Ok(())
}

#[test]
fn runtime_read_refuses_another_original_handshake_without_revoking_its_owner() -> TestResult {
    let (handshake, mut original, _peer, _reference) = fixture(8);
    let (foreign, _foreign_original, _foreign_peer, _foreign_reference) = fixture(8);
    let original_read = original
        .as_ref()
        .unwrap()
        .original_registrar_read(&handshake)?;
    let mut output = None;
    CompactRuntimeController::retain_into(&mut original, &mut output)?;
    let runtime = output.as_ref().unwrap();

    assert!(runtime.original_registrar_read(&foreign).is_err());

    let current = runtime.original_registrar_read(&handshake)?;
    assert!(original_read.same_original(&current));
    original_read.ensure_current()?;
    current.ensure_current()?;
    assert_eq!(runtime.journal_byte_reservations_data()[1..], [0, 0]);
    Ok(())
}
