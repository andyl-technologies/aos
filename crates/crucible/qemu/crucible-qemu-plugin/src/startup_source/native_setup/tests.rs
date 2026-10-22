//! Tests borrowed custody and fixed-output validation, without issuing Source.

use super::*;
use std::fs::File;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;

struct Fixture {
    control: UnixStream,
    _peer: UnixStream,
    owners: [File; 6],
    frame: [u8; 61],
}

impl Fixture {
    fn new() -> Self {
        let (control, peer) = UnixStream::pair().unwrap();
        let mut frame = [0; 61];
        frame[..4].copy_from_slice(&57_u32.to_be_bytes());
        frame[4] = 0x15;
        frame[5..13].copy_from_slice(&4096_u64.to_be_bytes());
        frame[21..29].copy_from_slice(&3_u64.to_be_bytes());
        Self {
            control,
            _peer: peer,
            owners: std::array::from_fn(|_| File::open("/dev/null").unwrap()),
            frame,
        }
    }

    fn descriptors(&self) -> [i32; 6] {
        std::array::from_fn(|index| self.owners[index].as_raw_fd())
    }

    fn output(&self, descriptors: &[i32]) -> NativeBorrow {
        NativeBorrow {
            schema_version: 3,
            struct_size: size_of::<NativeBorrow>() as u32,
            control_fd: self.control.as_raw_fd(),
            reserved: 0,
            frame: self.frame.as_ptr(),
            frame_bytes: self.frame.len(),
            descriptors: descriptors.as_ptr(),
            descriptor_count: descriptors.len(),
        }
    }
}

#[test]
fn borrowed_keeper_drop_preserves_every_native_role_and_control() {
    let fixture = Fixture::new();
    let descriptors = fixture.descriptors();
    let output = fixture.output(&descriptors[..5]);
    let keeper = validate_output(&output).unwrap();
    let role = keeper.role(2).unwrap();
    assert!(role.into_owned().is_none());
    drop(keeper);

    for descriptor in descriptors.into_iter().chain([fixture.control.as_raw_fd()]) {
        // SAFETY: the fixture, not the borrowed keeper, owns these live aliases.
        assert!(unsafe { libc::fcntl(descriptor, libc::F_GETFD) } >= 0);
    }
}

#[test]
fn borrow_refuses_wrong_edition_reserved_count_and_alias_overlap() {
    let fixture = Fixture::new();
    let mut descriptors = fixture.descriptors();
    let mut output = fixture.output(&descriptors[..5]);
    output.schema_version = 2;
    assert!(validate_output(&output).is_err());
    output.schema_version = 3;
    output.reserved = 1;
    assert!(validate_output(&output).is_err());
    output.reserved = 0;
    output.descriptor_count = 2;
    assert!(validate_output(&output).is_err());
    output.descriptor_count = 5;
    descriptors[1] = descriptors[0];
    assert!(validate_output(&output).is_err());
    descriptors[1] = fixture.control.as_raw_fd();
    assert!(validate_output(&output).is_err());
}

#[test]
fn malformed_native_view_cannot_leave_source_current() {
    let fixture = Fixture::new();
    let descriptors = fixture.descriptors();
    let mut output = fixture.output(&descriptors[..5]);
    output.reserved = 1;
    let mut source = InstallerStartupSource::retain_native_setup(7);
    source.api = Some(super::super::test_support::InstallerStartupSourceModel::ready().api);
    source.acquisition_attempted = true;

    assert!(
        source
            .complete_native_setup_acquisition(validate_output(&output))
            .is_err()
    );

    assert!(source.check().is_err());
    assert!(source.wait_slice().is_err());
    assert!(source.registration_complete().is_err());
    assert!(source.plan.is_none());
    assert!(source.retained_native_setup().is_none());
    assert!(source.acquire_native_setup().is_err());
    for descriptor in descriptors.into_iter().chain([fixture.control.as_raw_fd()]) {
        // SAFETY: rejection must preserve every alias owned by this fixture.
        assert!(unsafe { libc::fcntl(descriptor, libc::F_GETFD) } >= 0);
    }
}

#[test]
fn selected_frame_refuses_legacy_tag_and_partial_workspace_binding() {
    let mut fixture = Fixture::new();
    let descriptors = fixture.descriptors();
    let keeper = validate_output(&fixture.output(&descriptors[..5])).unwrap();
    assert!(crate::setup::SetupPreparationInput::from_native_setup(&keeper).is_ok());
    fixture.frame[4] = 0x13;
    let keeper = validate_output(&fixture.output(&descriptors[..5])).unwrap();
    assert!(crate::setup::SetupPreparationInput::from_native_setup(&keeper).is_err());
    fixture.frame[4] = 1;
    let keeper = validate_output(&fixture.output(&descriptors[..5])).unwrap();
    assert!(crate::setup::SetupPreparationInput::from_native_setup(&keeper).is_err());
    fixture.frame[4] = 0x15;
    let keeper = validate_output(&fixture.output(&descriptors)).unwrap();
    assert!(crate::setup::SetupPreparationInput::from_native_setup(&keeper).is_err());
}

#[test]
fn native_wake_refusal_does_not_change_owner_flags_or_close_alias() {
    // SAFETY: this syscall has no pointer arguments and returns a new descriptor.
    let raw = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC) };
    assert!(raw >= 0);
    // SAFETY: this fixture alone owns the newly returned alias.
    let owner = unsafe { OwnedFd::from_raw_fd(raw) };
    // SAFETY: the owner stays alive until the borrowed test role returns.
    let role = SetupDescriptor::Native(unsafe { BorrowedFd::borrow_raw(raw) });
    // SAFETY: F_GETFL only observes the owned alias.
    let before = unsafe { libc::fcntl(raw, libc::F_GETFL) };
    assert!(crate::setup::ArmedWakeFd::arm_role(role).is_err());
    // SAFETY: the original owner still holds the same alias.
    assert_eq!(unsafe { libc::fcntl(raw, libc::F_GETFL) }, before);
    assert_eq!(owner.as_raw_fd(), raw);
}
