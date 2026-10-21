//! Exercises fixed ABI views and real borrowed aliases without issuing Source.

use super::*;
use crucible_qemu_protocol::DeviceDigestWorkspaceBinding;
use std::fs::File;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicUsize, Ordering};

struct Fixture {
    control: UnixStream,
    _peer: UnixStream,
    owners: [File; 9],
    frame: [u8; PUBLISHER_SETUP_FRAME_BYTES],
}

impl Fixture {
    fn new(workspace: bool) -> Self {
        let (control, peer) = UnixStream::pair().unwrap();
        let setup = PublisherSetup {
            region_len: 4096,
            process_generation: 7,
            device_digest_workspace: workspace.then_some(DeviceDigestWorkspaceBinding {
                account_generation: 5,
                workspace_generation: 17,
                device: 0,
                inode: 0,
            }),
            lender_generation: 3,
            device: 0,
            inode: 0,
            producer_event: 11,
            receiver_event: 13,
        };

        Self {
            control,
            _peer: peer,
            owners: std::array::from_fn(|_| File::open("/dev/null").unwrap()),
            frame: setup.encode().unwrap(),
        }
    }

    fn descriptors(&self) -> [i32; 6] {
        std::array::from_fn(|index| self.owners[index].as_raw_fd())
    }

    fn output(&self, descriptors: &[i32]) -> Output {
        Output {
            schema_version: 4,
            struct_size: size_of::<Output>() as u32,
            control_fd: self.control.as_raw_fd(),
            reserved: 0,
            frame: self.frame.as_ptr(),
            frame_bytes: self.frame.len(),
            descriptors: descriptors.as_ptr(),
            descriptor_count: descriptors.len(),
            publisher_descriptors: std::array::from_fn(|index| self.owners[index + 6].as_raw_fd()),
            reserved_tail: 0,
        }
    }
}

extern "C" fn invalid_current(_: u64, _: u32, _: usize, _: *mut Output) -> i32 {
    // A successful scalar with no initialized view must still be refused.
    0
}

#[test]
fn publisher_output_matches_the_frozen_native_abi() {
    assert_eq!(size_of::<Output>(), 64);
    assert_eq!(align_of::<Output>(), 8);
    assert_eq!(std::mem::offset_of!(Output, frame), 16);
    assert_eq!(std::mem::offset_of!(Output, descriptors), 32);
    assert_eq!(std::mem::offset_of!(Output, publisher_descriptors), 48);
    assert_eq!(std::mem::offset_of!(Output, reserved_tail), 60);
}

#[test]
fn publisher_borrow_drop_keeps_all_real_aliases_open() {
    for workspace in [false, true] {
        let fixture = Fixture::new(workspace);
        let descriptors = fixture.descriptors();
        let output = fixture.output(&descriptors[..5 + usize::from(workspace)]);

        let keeper = validate_output(&output, invalid_current).unwrap();
        assert_eq!(keeper.has_workspace(), workspace);
        assert_eq!(
            keeper.publisher_setup().unwrap().unwrap().lender_generation,
            3
        );
        let preparation = crate::setup::SetupPreparationInput::from_native_setup(&keeper).unwrap();
        drop(preparation);
        drop(keeper);

        for descriptor in fixture
            .owners
            .iter()
            .map(AsRawFd::as_raw_fd)
            .chain(std::iter::once(fixture.control.as_raw_fd()))
        {
            // SAFETY: F_GETFD only observes each still-live fixture owner.
            assert!(unsafe { libc::fcntl(descriptor, libc::F_GETFD) } >= 0);
        }
    }
}

#[test]
fn publisher_view_refuses_mixed_editions_shapes_and_rosters() {
    for workspace in [false, true] {
        let fixture = Fixture::new(workspace);
        let descriptors = fixture.descriptors();
        let output = || fixture.output(&descriptors[..5 + usize::from(workspace)]);

        for field in 0..9 {
            let mut malformed = output();
            match field {
                0 => malformed.schema_version = 3,
                1 => malformed.struct_size -= 1,
                2 => malformed.reserved = 1,
                3 => malformed.reserved_tail = 1,
                4 => malformed.frame_bytes = 61,
                5 => malformed.frame = std::ptr::null(),
                6 => malformed.descriptor_count = if workspace { 5 } else { 6 },
                7 => malformed.descriptors = std::ptr::null(),
                8 => malformed.control_fd = -1,
                _ => unreachable!(),
            }
            assert!(
                validate_output(&malformed, invalid_current).is_err(),
                "field {field}"
            );
        }

        for index in 0..3 {
            for replacement in [
                -1,
                fixture.control.as_raw_fd(),
                descriptors[0],
                output().publisher_descriptors[(index + 1) % 3],
            ] {
                let mut malformed = output();
                malformed.publisher_descriptors[index] = replacement;
                assert!(validate_output(&malformed, invalid_current).is_err());
            }
        }
    }
}

#[test]
fn publisher_view_refuses_noncanonical_frame_before_borrowing() {
    let fixture = Fixture::new(false);
    let descriptors = fixture.descriptors();
    for offset in [0, 4, 13, 61, 69, 93, 101, 109, 113, 117, 124] {
        let mut frame = fixture.frame;
        frame[offset] ^= 1;
        let mut output = fixture.output(&descriptors[..5]);
        output.frame = frame.as_ptr();

        // Some low-byte identity changes remain canonical; clear the complete
        // generation instead when checking absent lender/notification identity.
        if [61, 93, 101].contains(&offset) {
            frame[offset..offset + 8].fill(0);
        }
        assert!(
            validate_output(&output, invalid_current).is_err(),
            "offset {offset}"
        );
    }
}

static CURRENT_CALLS: AtomicUsize = AtomicUsize::new(0);

extern "C" fn refused_current(_: u64, version: u32, size: usize, _: *mut Output) -> i32 {
    assert_eq!(version, 4);
    assert_eq!(size, size_of::<Output>());
    CURRENT_CALLS.fetch_add(1, Ordering::Relaxed);
    -libc::ESTALE
}

#[test]
fn publisher_current_preserves_first_native_refusal_without_retry_or_transfer() {
    CURRENT_CALLS.store(0, Ordering::Relaxed);
    let fixture = Fixture::new(false);
    let descriptors = fixture.descriptors();
    let keeper = validate_output(&fixture.output(&descriptors[..5]), refused_current).unwrap();

    for _ in 0..2 {
        assert!(
            matches!(keeper.check_current(7), Err(StartupSourceError::NativeStatus { status }) if status == -libc::ESTALE)
        );
    }
    assert!(keeper.begin_publisher_transfer().is_err());
    assert_eq!(CURRENT_CALLS.load(Ordering::Relaxed), 1);
}

#[test]
fn publisher_malformed_current_is_sticky_and_transfer_cannot_reuse_installer_view() {
    let fixture = Fixture::new(false);
    let descriptors = fixture.descriptors();
    let keeper = validate_output(&fixture.output(&descriptors[..5]), invalid_current).unwrap();
    assert!(keeper.check_current(7).is_err());
    assert!(keeper.begin_publisher_transfer().is_err());

    let keeper = validate_output(&fixture.output(&descriptors[..5]), invalid_current).unwrap();
    keeper.begin_publisher_transfer().unwrap();
    assert!(keeper.begin_publisher_transfer().is_err());
    // Transfer disables the installer-only observation; ordinary Source and
    // Runtime-purpose observation remains owned by InstallerStartupSource.
    keeper.check_current(7).unwrap();
}
