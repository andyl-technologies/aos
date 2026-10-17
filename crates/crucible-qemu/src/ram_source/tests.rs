//! Checks response adversaries using real sockets and the original PageIn guard.
//!
//! These are transport components, without QEMU, kernel missing faults, or
//! authenticated RAM authority. The independent native harness supplies those
//! obligations before claiming a guest-visible refusal.

use super::*;
use crucible_linux_resource::host_supervision::HostOperationBudgets;
use crucible_protocol::ram_page::{RAM_PAGE_RESPONSE_HEADER_BYTES, read_ram_page_response};
use std::error::Error;
use std::io::Cursor;

fn emitted_bytes(fault: QemuRamResponseFault) -> Result<Vec<u8>, Box<dyn Error>> {
    let supervisor = HostOperationSupervisor::new(
        HostOperationBudgets::default(),
        Some(Duration::from_secs(5)),
    )?;
    let operation = supervisor.begin(HostOperationClass::PageIn)?;
    let original = supervisor.outer_cap_binding()?;
    let (mut source, mut receiver) = UnixStream::pair()?;
    receiver.set_read_timeout(Some(Duration::from_secs(2)))?;
    send_faulted_response(
        &mut source,
        &operation,
        RamPageResponse {
            binding: RamPageBinding {
                session: [1; 16],
                owner_incarnation: [2; 16],
                source_generation: 3,
                root_digest: [4; 32],
            },
            sequence: 1,
            status: RamPageStatus::Page,
            page: &[0x55; 4096],
            proof: &[0x66; 32],
        },
        fault,
    )?;
    assert_eq!(supervisor.outer_cap_binding()?, original);
    let mut bytes = Vec::new();
    receiver.read_to_end(&mut bytes)?;
    Ok(bytes)
}

#[test]
fn changed_response_byte_preserves_the_original_frame_and_proof() -> Result<(), Box<dyn Error>> {
    let bytes = emitted_bytes(QemuRamResponseFault::ChangedPageByte)?;
    let response = RamPageResponse::decode(&bytes)?;

    assert_eq!(response.page.len(), 4096);
    assert_eq!(response.page[0], 0x54);
    assert!(response.page[1..].iter().all(|byte| *byte == 0x55));
    assert_eq!(response.proof, &[0x66; 32]);
    assert_eq!(response.sequence, 1);
    Ok(())
}

#[test]
fn partial_response_reaches_the_real_reader_as_body_eof() -> Result<(), Box<dyn Error>> {
    let bytes = emitted_bytes(QemuRamResponseFault::TruncatedBody)?;

    assert_eq!(bytes.len(), RAM_PAGE_RESPONSE_HEADER_BYTES + 2048);
    assert!(matches!(
        read_ram_page_response(&mut Cursor::new(bytes)),
        Err(RamPageProtocolError::Io(error)) if error.kind() == io::ErrorKind::UnexpectedEof
    ));
    Ok(())
}

#[test]
fn disconnected_response_reaches_the_real_reader_as_header_eof() -> Result<(), Box<dyn Error>> {
    let bytes = emitted_bytes(QemuRamResponseFault::DisconnectBeforeHeader)?;

    assert!(bytes.is_empty());
    assert!(matches!(
        read_ram_page_response(&mut Cursor::new(bytes)),
        Err(RamPageProtocolError::Io(error)) if error.kind() == io::ErrorKind::UnexpectedEof
    ));
    Ok(())
}

#[test]
fn stale_generation_changes_only_the_typed_source_binding() -> Result<(), Box<dyn Error>> {
    let bytes = emitted_bytes(QemuRamResponseFault::StaleSourceGeneration)?;
    let response = RamPageResponse::decode(&bytes)?;

    assert_eq!(response.binding.source_generation, 4);
    assert_eq!(response.binding.session, [1; 16]);
    assert_eq!(response.binding.owner_incarnation, [2; 16]);
    assert_eq!(response.binding.root_digest, [4; 32]);
    assert_eq!(response.sequence, 1);
    assert_eq!(response.page, &[0x55; 4096]);
    assert_eq!(response.proof, &[0x66; 32]);
    Ok(())
}

#[path = "pending_health_tests.rs"]
mod pending_health;
