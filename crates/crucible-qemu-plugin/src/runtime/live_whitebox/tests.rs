//! Regression tests for live white-box register discovery.

use super::*;

#[test]
fn zero_register_handle_is_available() {
    let architecture = QemuPluginTargetArchitecture::X86_64;
    let mut registers = LiveWhiteboxRegisters::default();
    registers.observe(architecture, b"rax", std::ptr::null_mut());
    assert!(!registers.complete(architecture));

    let length_handle = std::ptr::without_provenance_mut(4);
    registers.observe(architecture, b"rcx", length_handle);

    assert!(registers.complete(architecture));
    assert_eq!(registers.pointer, Some(std::ptr::null_mut()));
    assert_eq!(registers.length, Some(length_handle));
}
