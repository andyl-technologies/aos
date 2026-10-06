//! Checks publication after private operational-page staging completes.

use super::*;

#[test]
fn late_read_failure_preserves_every_native_output_byte() {
    let mut output = [0xa5; PAGE_BYTES];
    let status = complete_operational_read(output.as_mut_ptr(), PAGE_BYTES, |scratch| {
        scratch.fill(0x3c);
        Err(RamError::Invariant("injected late authentication refusal"))
    });

    assert_eq!(status, -libc::EIO);
    assert_eq!(output, [0xa5; PAGE_BYTES]);
}

#[test]
fn successful_read_publishes_only_its_authenticated_valid_length() {
    for valid in [1, 7, PAGE_BYTES] {
        let mut output = [0xa5; PAGE_BYTES];
        let status = complete_operational_read(output.as_mut_ptr(), valid, |scratch| {
            scratch.fill(0x3c);
            Ok(())
        });

        assert_eq!(status, 0);
        assert!(output[..valid].iter().all(|byte| *byte == 0x3c));
        assert!(output[valid..].iter().all(|byte| *byte == 0xa5));
    }
}

#[test]
fn invalid_native_output_contract_refuses_before_owner_or_memory_access() {
    let mut output = [0xa5; PAGE_BYTES];
    assert_eq!(operational_read(0, std::ptr::null_mut(), 1), -libc::EINVAL);
    assert_eq!(operational_read(0, output.as_mut_ptr(), 0), -libc::EINVAL);
    assert_eq!(
        operational_read(0, output.as_mut_ptr(), PAGE_BYTES as u32 + 1),
        -libc::EINVAL
    );
    assert_eq!(output, [0xa5; PAGE_BYTES]);
}
