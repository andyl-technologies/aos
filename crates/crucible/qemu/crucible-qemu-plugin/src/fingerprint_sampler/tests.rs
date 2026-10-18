//! Fingerprint sampler unit tests.

use super::*;

use crate::{PluginRoundRobinCursor, PluginVcpuRegisterDigest};
use std::ffi::CString;
use std::io::Write as _;
use std::os::fd::IntoRawFd as _;
use std::os::unix::fs::MetadataExt as _;

fn digest_bytes(seed: u8) -> [u8; FINGERPRINT_DIGEST_BYTES] {
    Sha256::digest([seed]).into()
}

fn sealed_material(seed: u8) -> File {
    let name = CString::new("crucible-fingerprint-test")
        .unwrap_or_else(|error| panic!("memfd name: {error}"));
    // SAFETY: `name` is NUL-terminated and flags request a close-on-exec,
    // sealable anonymous file.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_memfd_create,
            name.as_ptr(),
            libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
        ) as c_int
    };
    assert!(fd >= 0, "create test memfd");
    // SAFETY: the successful syscall transfers one owned descriptor.
    let mut file = unsafe { File::from_raw_fd(fd) };
    file.write_all(&[seed])
        .unwrap_or_else(|error| panic!("write test memfd: {error}"));
    // SAFETY: `file` owns `fd`, and `lseek` does not retain it.
    assert_eq!(unsafe { libc::lseek(fd, 0, libc::SEEK_SET) }, 0);
    let seals = libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
    // SAFETY: `file` owns `fd`, and `fcntl` does not retain it.
    assert_eq!(unsafe { libc::fcntl(fd, libc::F_ADD_SEALS, seals) }, 0);
    file
}

fn inputs() -> PluginNvcpuFingerprintInputs {
    let registers = vec![
        match PluginVcpuRegisterDigest::new(0, &[1, 2, 3, 4], 100_000) {
            Ok(register) => register,
            Err(error) => panic!("vcpu 0 register digest: {error}"),
        },
        match PluginVcpuRegisterDigest::new(1, &[5, 6, 7, 8], 100_000) {
            Ok(register) => register,
            Err(error) => panic!("vcpu 1 register digest: {error}"),
        },
    ];
    let cursor = match PluginRoundRobinCursor::new(1, 17, 4096, 2) {
        Ok(cursor) => cursor,
        Err(error) => panic!("rr cursor: {error}"),
    };
    match PluginNvcpuFingerprintInputs::new(registers, cursor) {
        Ok(inputs) => inputs,
        Err(error) => panic!("nvcpu inputs: {error}"),
    }
}

fn captured_material(seed: u8, observed_bytes: u64) -> CapturedFingerprintMaterial {
    CapturedFingerprintMaterial {
        file: sealed_material(seed),
        material_length: 1,
        observed_bytes,
    }
}

fn captured_sample() -> CapturedFingerprintSample {
    let mut sample = sample_metadata(100_000, &inputs(), digest_bytes(0xC0))
        .unwrap_or_else(|error| panic!("sample metadata should assemble: {error}"));
    sample.ram_bytes = 64 * 1024 * 1024;
    sample.device_state_bytes = 4096;
    CapturedFingerprintSample {
        sample,
        ram: captured_material(0xA0, 64 * 1024 * 1024),
        device: captured_material(0xB0, 4096),
    }
}

fn assert_returned_descriptor_closed(fd: RawFd, device: u64, inode: u64) {
    let mut current = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: `current` provides writable storage for one `stat`; a successful
    // call initializes it completely without retaining the pointer.
    if unsafe { libc::fstat(fd, current.as_mut_ptr()) } == 0 {
        // Another parallel test may already have reused the numeric descriptor.
        // It must not still name the transferred file that this call consumed.
        // SAFETY: the successful `fstat` initialized the complete output object.
        let current = unsafe { current.assume_init() };
        assert_ne!((current.st_dev, current.st_ino), (device, inode));
    } else {
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EBADF),
            "consumed descriptor must be closed",
        );
    }
}

#[test]
fn aggregate_capture_rejects_an_aliased_descriptor_before_ownership_transfer() {
    let material = sealed_material(0xA0);
    let metadata = material
        .metadata()
        .unwrap_or_else(|error| panic!("test material metadata: {error}"));
    let fd = material.into_raw_fd();
    let Err(error) = capture_files(fd, 1, 1, fd, 1, 1) else {
        panic!("aliased descriptors must be rejected");
    };

    assert!(matches!(
        error,
        FingerprintSamplerError::InvalidCaptureDescriptor {
            component: "descriptor set"
        }
    ));
    assert_returned_descriptor_closed(fd, metadata.dev(), metadata.ino());
}

#[test]
fn aggregate_capture_rejects_distinct_descriptors_for_the_same_memfd() {
    let material = sealed_material(0xA0);
    let metadata = material
        .metadata()
        .unwrap_or_else(|error| panic!("test material metadata: {error}"));
    let ram_fd = material.into_raw_fd();
    // SAFETY: `ram_fd` is live and `dup` returns a distinct owned descriptor.
    let device_fd = unsafe { libc::dup(ram_fd) };
    assert!(device_fd >= 0);

    let Err(error) = capture_files(ram_fd, 1, 1, device_fd, 1, 1) else {
        panic!("descriptors for one memfd must be rejected");
    };
    assert!(matches!(
        error,
        FingerprintSamplerError::InvalidCaptureDescriptor {
            component: "descriptor set"
        }
    ));
    assert_returned_descriptor_closed(ram_fd, metadata.dev(), metadata.ino());
    assert_returned_descriptor_closed(device_fd, metadata.dev(), metadata.ino());
}

#[test]
fn aggregate_capture_rejects_zero_component_evidence() {
    let mut captured = QemuFingerprintMaterialFds {
        ram_bytes: 1,
        device_bytes: 1,
        device_schema_digest: digest_bytes(0xC0),
        device_schema_sections: 1,
        ..QemuFingerprintMaterialFds::default()
    };

    captured.ram_bytes = 0;
    assert_eq!(
        validate_capture_evidence(&captured),
        Err(FingerprintSamplerError::InvalidCaptureEvidence)
    );
    captured.ram_bytes = 1;
    captured.device_bytes = 0;
    assert_eq!(
        validate_capture_evidence(&captured),
        Err(FingerprintSamplerError::InvalidCaptureEvidence)
    );
    captured.device_bytes = 1;
    captured.device_schema_digest = [0; FINGERPRINT_DIGEST_BYTES];
    assert_eq!(
        validate_capture_evidence(&captured),
        Err(FingerprintSamplerError::InvalidCaptureEvidence)
    );
    captured.device_schema_digest = digest_bytes(0xC0);
    captured.device_schema_sections = 0;
    assert_eq!(
        validate_capture_evidence(&captured),
        Err(FingerprintSamplerError::InvalidCaptureEvidence)
    );
}

#[test]
fn aggregate_capture_rejects_a_descriptor_without_close_on_exec() {
    let file = sealed_material(0xA0);
    let metadata = file
        .metadata()
        .unwrap_or_else(|error| panic!("test material metadata: {error}"));
    let fd = file.as_raw_fd();
    // SAFETY: `file` owns `fd`, and `fcntl` does not retain it.
    assert_eq!(unsafe { libc::fcntl(fd, libc::F_SETFD, 0) }, 0);
    let fd = file.into_raw_fd();

    let Err(error) = capture_file(fd, 1, 1, "guest RAM") else {
        panic!("a descriptor without close-on-exec must be rejected");
    };
    assert!(matches!(
        error,
        FingerprintSamplerError::InvalidCaptureDescriptor {
            component: "guest RAM"
        }
    ));
    assert_returned_descriptor_closed(fd, metadata.dev(), metadata.ino());
}

#[test]
fn detached_capture_digests_every_component_into_the_slot_sample() {
    let sample = captured_sample().digest();

    assert_eq!(sample.sample_icount, 100_000);
    assert_eq!(sample.vcpu_count, 2);
    assert_eq!(sample.rr_current_vcpu, 1);
    assert_eq!(sample.rr_position_in_quantum, 17);
    assert_eq!(sample.rr_switch_quantum, 4096);
    assert_eq!(sample.component_failures, 0);
    assert_eq!(sample.ram_bytes, 64 * 1024 * 1024);
    assert_eq!(sample.ram_digest, digest_bytes(0xA0));
    assert_eq!(sample.device_state_bytes, 4096);
    assert_eq!(sample.device_state_digest, digest_bytes(0xB0));
    assert_eq!(sample.device_state_schema_digest, digest_bytes(0xC0));
    assert_eq!(sample.vcpus[0].retired_instruction_count, 100_000);
    assert_eq!(sample.vcpus[1].retired_instruction_count, 100_000);
    assert_ne!(
        sample.vcpus[0].register_digest,
        sample.vcpus[1].register_digest
    );
}

#[test]
fn resolve_fails_closed_without_the_patched_qemu() {
    // The aggregate capture exports exist only inside patched QEMU, so the
    // complete sampling capability fails closed in a standalone test process.
    assert!(PluginFingerprintSampling::resolve().is_none());
}
