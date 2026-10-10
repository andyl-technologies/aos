//! Fingerprint sampler unit tests.

use super::*;

use crate::{PluginRoundRobinCursor, PluginVcpuRegisterDigest};
use std::ffi::CString;
use std::io::Write as _;
use std::os::fd::IntoRawFd as _;
use std::os::unix::fs::MetadataExt as _;

fn test_workspace() -> Box<[u8; 65_536]> {
    vec![0; 65_536]
        .into_boxed_slice()
        .try_into()
        .unwrap_or_else(|_| panic!("fixed test workspace extent"))
}

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

fn captured_material(seed: u8) -> CapturedFingerprintMaterial {
    CapturedFingerprintMaterial {
        file: sealed_material(seed),
        material_length: 1,
    }
}

fn captured_sample() -> CapturedFingerprintSample {
    let mut sample = sample_metadata(100_000, &inputs(), digest_bytes(0xC0))
        .unwrap_or_else(|error| panic!("sample metadata should assemble: {error}"));
    sample.ram_bytes = 64 * 1024 * 1024;
    sample.ram_digest = [0xA0; 32];
    sample.device_state_bytes = 4096;
    CapturedFingerprintSample {
        sample,
        device: captured_material(0xB0),
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
fn aggregate_capture_rejects_zero_component_evidence() {
    let mut captured = QemuFingerprintCaptureV2 {
        schema: 2,
        logical_edition: 1,
        ram_digest: [1; 32],
        ram_bytes: 1,
        device_bytes: 1,
        device_schema_digest: digest_bytes(0xC0),
        device_schema_sections: 1,
        ..QemuFingerprintCaptureV2::default()
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

    let Err(error) = capture_file(fd, 1, "device state") else {
        panic!("a descriptor without close-on-exec must be rejected");
    };
    assert!(matches!(
        error,
        FingerprintSamplerError::InvalidCaptureDescriptor {
            component: "device state"
        }
    ));
    assert_returned_descriptor_closed(fd, metadata.dev(), metadata.ino());
}

#[test]
fn detached_capture_digests_every_component_into_the_slot_sample() {
    let sample = captured_sample()
        .digest(&mut test_workspace())
        .unwrap_or_else(|error| panic!("complete material should digest: {error}"));

    assert_eq!(sample.sample_icount, 100_000);
    assert_eq!(sample.vcpu_count, 2);
    assert_eq!(sample.rr_current_vcpu, 1);
    assert_eq!(sample.rr_position_in_quantum, 17);
    assert_eq!(sample.rr_switch_quantum, 4096);
    assert_eq!(sample.component_failures, 0);
    assert_eq!(sample.ram_bytes, 64 * 1024 * 1024);
    assert_eq!(sample.ram_digest, [0xA0; 32]);
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
fn detached_capture_refuses_incomplete_component_material() {
    let mut captured = captured_sample();
    captured.device.material_length = 2;

    assert_eq!(
        captured.digest(&mut test_workspace()),
        Err(FingerprintSamplerError::DigestRead {
            component: "device state",
            remaining_bytes: 1,
        })
    );
}

#[test]
fn resolve_fails_closed_without_the_patched_qemu() {
    // The aggregate capture exports exist only inside patched QEMU, so the
    // complete sampling capability fails closed in a standalone test process.
    assert!(PluginFingerprintSampling::resolve().is_none());
}

#[test]
fn aggregate_capture_rejects_wrong_ram_identity_contract() {
    let mut captured = QemuFingerprintCaptureV2 {
        schema: 2,
        logical_edition: 1,
        ram_scope: 0,
        reserved: 0,
        ram_digest: [1; 32],
        ram_bytes: 1,
        device_bytes: 1,
        device_schema_digest: [2; 32],
        device_schema_sections: 1,
        ..QemuFingerprintCaptureV2::default()
    };
    assert!(validate_capture_evidence(&captured).is_ok());
    captured.ram_scope = 1;
    assert_eq!(
        validate_capture_evidence(&captured),
        Err(FingerprintSamplerError::InvalidCaptureEvidence)
    );
    captured.ram_scope = 0;
    captured.logical_edition = 2;
    assert_eq!(
        validate_capture_evidence(&captured),
        Err(FingerprintSamplerError::InvalidCaptureEvidence)
    );
    captured.logical_edition = 1;
    captured.schema = 1;
    assert_eq!(
        validate_capture_evidence(&captured),
        Err(FingerprintSamplerError::InvalidCaptureEvidence)
    );
    assert_eq!(std::mem::size_of::<QemuFingerprintCaptureV2>(), 120);
}

#[derive(Clone, Copy)]
enum ReadStep {
    Interrupted,
    Bytes(usize),
    Eof,
    Failure,
}

struct TranscriptReader {
    payload: Vec<u8>,
    offset: usize,
    steps: std::collections::VecDeque<ReadStep>,
    requests: Vec<usize>,
}

impl Read for TranscriptReader {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        self.requests.push(output.len());
        match self.steps.pop_front().unwrap_or(ReadStep::Eof) {
            ReadStep::Interrupted => Err(std::io::ErrorKind::Interrupted.into()),
            ReadStep::Eof => Ok(0),
            ReadStep::Failure => Err(std::io::ErrorKind::PermissionDenied.into()),
            ReadStep::Bytes(length) => {
                assert!(length <= output.len());
                output[..length].copy_from_slice(&self.payload[self.offset..self.offset + length]);
                self.offset += length;
                Ok(length)
            }
        }
    }
}

#[test]
fn borrowed_digest_preserves_full_stride_short_reads_and_interrupted_requests() {
    let payload: Vec<u8> = (0..70_000).map(|offset| (offset % 251) as u8).collect();
    let expected: [u8; 32] = Sha256::digest(&payload).into();
    let mut reader = TranscriptReader {
        payload,
        offset: 0,
        steps: [
            ReadStep::Interrupted,
            ReadStep::Bytes(1_024),
            ReadStep::Bytes(65_536),
            ReadStep::Bytes(3_440),
        ]
        .into(),
        requests: Vec::new(),
    };
    let mut workspace = test_workspace();

    let actual =
        digest_device_material(&mut reader, 70_000, "device state", &mut workspace).unwrap();

    assert_eq!(actual, expected);
    assert_eq!(reader.requests, [65_536, 65_536, 65_536, 3_440]);
    assert_eq!(reader.offset, 70_000);
    assert!(reader.steps.is_empty());
}

#[test]
fn borrowed_digest_preserves_the_exact_remaining_extent_at_eof_and_io_refusal() {
    for refusal in [ReadStep::Eof, ReadStep::Failure] {
        let mut reader = TranscriptReader {
            payload: vec![0x3a; 100],
            offset: 0,
            steps: [ReadStep::Bytes(7), refusal].into(),
            requests: Vec::new(),
        };
        let mut workspace = test_workspace();

        assert_eq!(
            digest_device_material(&mut reader, 100, "device state", &mut workspace),
            Err(FingerprintSamplerError::DigestRead {
                component: "device state",
                remaining_bytes: 93,
            }),
        );
        assert_eq!(reader.requests, [100, 93]);
        assert_eq!(reader.offset, 7);
    }
}

#[test]
fn borrowed_digest_does_not_read_beyond_the_declared_material() {
    let mut reader = TranscriptReader {
        payload: vec![0x3a; 20],
        offset: 0,
        steps: [ReadStep::Bytes(7), ReadStep::Failure].into(),
        requests: Vec::new(),
    };
    let mut workspace = test_workspace();

    let actual = digest_device_material(&mut reader, 7, "device state", &mut workspace).unwrap();

    assert_eq!(actual, <[u8; 32]>::from(Sha256::digest([0x3a; 7])));
    assert_eq!(reader.requests, [7]);
    assert_eq!(reader.steps.len(), 1);
}

#[test]
fn zero_extent_digest_has_no_read_request() {
    let mut reader = TranscriptReader {
        payload: Vec::new(),
        offset: 0,
        steps: [ReadStep::Failure].into(),
        requests: Vec::new(),
    };
    let mut workspace = test_workspace();

    let actual = digest_device_material(&mut reader, 0, "device state", &mut workspace).unwrap();

    assert_eq!(actual, <[u8; 32]>::from(Sha256::digest([])));
    assert!(reader.requests.is_empty());
    assert_eq!(reader.steps.len(), 1);
}
