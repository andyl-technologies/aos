//! Passive Guest receiving bounds for the physical Capture transport.
//!
//! The Host's genuine purpose borrower pays these bytes before sending. These
//! numbers authenticate no descriptor, Session, process, limit or output grant.
//! Complete decoded-spec model geometry is added separately from the actual
//! canonical specification by the existing producer.

/// Bounds fixed Capture transport, native, launch, path and error controls.
///
/// The exact347 compiler measured the complete current three-plane control
/// geometry at 81,456 bytes. The 96 KiB receiving invoice conservatively covers
/// that representation; Guest keeps its actual compiled whole-layout assertion
/// so future growth cannot silently exceed the paid receiving prerequisite.
/// This changes no native Source, profile, kernel or cgroup resource cap.
/// Every Host Capture, launch and lifetime supplier consumes this same total.
pub const CAPTURE_GUEST_CONTROL_BYTES_V2: usize = 96 * 1024;

/// Prices actual specification bytes and the fixed receive/control planes.
///
/// The two native receive samples each request the existing full Agent frame
/// ceiling. The immutable mapping and reconstructed request coexist; decoded
/// semantic models and process/kernel resources are independent caller terms.
#[must_use]
pub fn capture_guest_receiving_bytes_v2(actual_spec_bytes: usize) -> Option<usize> {
    if actual_spec_bytes == 0 || actual_spec_bytes > crate::MAX_AGENT_SEALED_SPEC_BYTES_V1 {
        return None;
    }
    actual_spec_bytes.checked_mul(2)?
        .checked_add(crate::protocol::MAX_AGENT_FRAME_BYTES.checked_mul(2)?)?
        .checked_add(CAPTURE_GUEST_CONTROL_BYTES_V2)
}
