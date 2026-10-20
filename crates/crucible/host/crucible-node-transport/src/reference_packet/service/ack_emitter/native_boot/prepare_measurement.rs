//! Remeasures probe and Prepare executables without whole-file buffers.
//!
//! The normative ContentRef framing and before/after change checks match the
//! existing conformance measurement. Generic probes preserve read-to-bound error
//! ordering; selected Prepare preserves its earlier immediate-growth refusal.

use crate::ProviderError;
use crucible_node_format::{ContentRef, HashRef, U64, Validate};
use std::{fs::File, io::Read, os::unix::fs::MetadataExt, path::Path};

const MAXIMUM_EXECUTABLE_BYTES: u64 = 256 * 1024 * 1024;
const STREAM_BUFFER_BYTES: usize = 256 * 1024;
const CONFORMANCE_STREAM_BUFFER_BYTES: usize = 256 * 1024;

// Legacy probes finish their bounded read before comparing the original length
// and post-read metadata. Prepare already refuses immediately on growth. Keep
// both existing error-order contracts while sharing the hash/read loop.
// Both banks batch BLAKE3 updates without sharing their growth policies.
#[derive(Clone, Copy)]
enum GrowthPolicy {
    RefuseImmediately,
    ReadToBound,
}

struct MeasuredExecutableStream {
    length: u64,
    digest: blake3::Hash,
}

/// Reports explicit streamed measurement buffers and borrowed/owned headers.
///
/// Path/ContentRef child heaps, kernel resources, error custody, compiler frames
/// and allocator physical overhead remain separate caller terms. The actual
/// Prepare read buffer comes from the SAME STREAM_BUFFER_BYTES constant below.
pub(crate) const fn original_prepare_executable_measurement_counter_scratch_data() -> usize {
    measurement_counter_scratch_data::<STREAM_BUFFER_BYTES>()
}

/// Reports the complete generic bank and the same conservative headers.
///
/// CompleteBirth uses this public conformance path before service dispatch.
/// Its local array is distinct from the selected Prepare array. Both banks
/// hold 256 KiB; calls are sequential and neither returns or stores its read bank.
/// Compiler spills/copies and physical stack overhead remain outside this
/// explicit requested-layout census, as they do for the existing Prepare path.
pub(crate) const fn original_conformance_executable_measurement_counter_scratch_data() -> usize {
    measurement_counter_scratch_data::<CONFORMANCE_STREAM_BUFFER_BYTES>()
}

const fn measurement_counter_scratch_data<const BUFFER_BYTES: usize>() -> usize {
    std::mem::size_of::<[u8; BUFFER_BYTES]>()
        + std::mem::size_of::<blake3::Hasher>()
        + std::mem::size_of::<File>()
        + 2 * std::mem::size_of::<std::fs::Metadata>()
        + std::mem::size_of::<ContentRef>()
        + std::mem::size_of::<blake3::Hash>()
        + std::mem::size_of::<[u8; 64]>()
        + std::mem::size_of::<&Path>()
        + std::mem::size_of::<&mut File>()
        + std::mem::size_of::<std::io::Error>()
        + 4 * std::mem::size_of::<u64>()
        + 8 * std::mem::size_of::<usize>()
        + std::mem::size_of::<ControllerExecutablePath>()
        + std::mem::size_of::<[u8; 20]>()
        + 2 * std::mem::size_of::<GrowthPolicy>()
        + std::mem::size_of::<MeasuredExecutableStream>()
        + std::mem::size_of::<Result<MeasuredExecutableStream, ProviderError>>()
        + std::mem::size_of::<Result<ContentRef, ProviderError>>()
        + std::mem::size_of::<Result<File, std::io::Error>>()
        + std::mem::size_of::<Result<std::fs::Metadata, std::io::Error>>()
        + std::mem::size_of::<Result<usize, std::io::Error>>()
}

/// Remeasures the actual running image through the kernel's executable link.
pub(in crate::reference_packet::service::ack_emitter::native_boot) fn measure_current_executable()
-> Result<ContentRef, ProviderError> {
    // This selected native service already requires Linux /proc for the host
    // executable. Opening this link measures the running image directly and
    // avoids allocating an OS-returned pathname before its construction grant.
    measure_executable(Path::new("/proc/self/exe"))
}

pub(in crate::reference_packet::service::ack_emitter::native_boot) fn measure_controller_executable(
    pid: U64,
) -> Result<ContentRef, ProviderError> {
    let path = ControllerExecutablePath::new(pid);
    measure_executable(path.as_path()?)
}

const CONTROLLER_PROC_PREFIX: &[u8] = b"/proc/";
const CONTROLLER_EXE_SUFFIX: &[u8] = b"/exe";
const MAXIMUM_PID_DECIMAL_DIGITS: usize = 20;
const CONTROLLER_PATH_BYTES: usize =
    CONTROLLER_PROC_PREFIX.len() + MAXIMUM_PID_DECIMAL_DIGITS + CONTROLLER_EXE_SUFFIX.len();

struct ControllerExecutablePath {
    bytes: [u8; CONTROLLER_PATH_BYTES],
    length: usize,
}

impl ControllerExecutablePath {
    fn new(pid: U64) -> Self {
        // Every u64 has at most twenty decimal digits. The exact path is the
        // previous /proc/{pid}/exe spelling, including zero and oversized PIDs
        // which the subsequent kernel open refuses in the usual way.
        let mut digits = [0u8; MAXIMUM_PID_DECIMAL_DIGITS];
        let mut cursor = digits.len();
        let mut remaining = pid.get();
        loop {
            cursor -= 1;
            digits[cursor] = b'0' + (remaining % 10) as u8;
            remaining /= 10;
            if remaining == 0 {
                break;
            }
        }
        let digits = &digits[cursor..];
        let prefix_end = CONTROLLER_PROC_PREFIX.len();
        let digits_end = prefix_end + digits.len();
        let mut result = Self {
            bytes: [0; CONTROLLER_PATH_BYTES],
            length: digits_end + CONTROLLER_EXE_SUFFIX.len(),
        };
        result.bytes[..prefix_end].copy_from_slice(CONTROLLER_PROC_PREFIX);
        result.bytes[prefix_end..digits_end].copy_from_slice(digits);
        result.bytes[digits_end..result.length].copy_from_slice(CONTROLLER_EXE_SUFFIX);
        result
    }

    fn as_path(&self) -> Result<&Path, ProviderError> {
        let text = std::str::from_utf8(&self.bytes[..self.length])
            .map_err(|_| ProviderError::Frame("Prepare executable path grammar"))?;
        Ok(Path::new(text))
    }
}

pub(crate) fn measure_executable(path: &Path) -> Result<ContentRef, ProviderError> {
    let mut file = File::open(path)?;
    let before = file.metadata()?;
    if before.len() > MAXIMUM_EXECUTABLE_BYTES {
        return Err(ProviderError::ResourceExhausted(
            "probe executable measurement",
        ));
    }
    let reference = measure_stream(&mut file, before.len())?;
    let after = file.metadata()?;
    authenticate_metadata(&before, &after)?;
    Ok(reference)
}

/// Preserves the generic probe's bounded read and post-read error precedence.
///
/// # Errors
/// Returns original file/read errors, the unchanged 256-MiB refusal, or the
/// unchanged correlation refusal for a short/grown/metadata-changed descriptor.
/// A canonical reference is constructed only after those checks pass.
pub(crate) fn measure_conformance_executable(path: &Path) -> Result<ContentRef, ProviderError> {
    let mut file = File::open(path)?;
    let before = file.metadata()?;
    if before.len() > MAXIMUM_EXECUTABLE_BYTES {
        return Err(ProviderError::ResourceExhausted(
            "probe executable measurement",
        ));
    }
    let measured = measure_bounded_stream::<CONFORMANCE_STREAM_BUFFER_BYTES>(
        &mut file,
        before.len(),
        GrowthPolicy::ReadToBound,
    )?;
    let after = file.metadata()?;
    if measured.length != before.len() {
        return Err(ProviderError::Correlation(
            "executable changed during measurement",
        ));
    }
    authenticate_metadata(&before, &after)?;
    reference_from_stream(measured)
}

fn authenticate_metadata(
    before: &std::fs::Metadata,
    after: &std::fs::Metadata,
) -> Result<(), ProviderError> {
    if before.len() != after.len()
        || (
            before.mtime(),
            before.mtime_nsec(),
            before.ctime(),
            before.ctime_nsec(),
        ) != (
            after.mtime(),
            after.mtime_nsec(),
            after.ctime(),
            after.ctime_nsec(),
        )
    {
        return Err(ProviderError::Correlation(
            "executable changed during measurement",
        ));
    }
    Ok(())
}

fn next_read_capacity<const BUFFER_BYTES: usize>(length: u64) -> Result<usize, ProviderError> {
    let remaining = (MAXIMUM_EXECUTABLE_BYTES + 1).checked_sub(length).ok_or(
        ProviderError::ResourceExhausted("probe executable measurement"),
    )?;
    Ok(BUFFER_BYTES.min(
        usize::try_from(remaining)
            .map_err(|_| ProviderError::ResourceExhausted("probe executable measurement"))?,
    ))
}

fn measure_stream(
    reader: &mut impl Read,
    expected_length: u64,
) -> Result<ContentRef, ProviderError> {
    let measured = measure_bounded_stream::<STREAM_BUFFER_BYTES>(
        reader,
        expected_length,
        GrowthPolicy::RefuseImmediately,
    )?;
    if measured.length != expected_length {
        return Err(ProviderError::Correlation(
            "executable changed during measurement",
        ));
    }
    reference_from_stream(measured)
}

fn measure_bounded_stream<const BUFFER_BYTES: usize>(
    reader: &mut impl Read,
    expected_length: u64,
    growth: GrowthPolicy,
) -> Result<MeasuredExecutableStream, ProviderError> {
    if expected_length > MAXIMUM_EXECUTABLE_BYTES {
        return Err(ProviderError::ResourceExhausted(
            "probe executable measurement",
        ));
    }
    // Exact canonical::hash("cnp.blob.v1", bytes) framing, independent of read
    // boundaries. The length is authenticated again by the completed read and
    // the same descriptor's post-read metadata before any reference escapes.
    const DOMAIN: &[u8; 11] = b"cnp.blob.v1";
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"CNP/1\0");
    hasher.update(&11u32.to_be_bytes());
    hasher.update(DOMAIN);
    hasher.update(&expected_length.to_be_bytes());
    let mut bytes = [0u8; BUFFER_BYTES];
    let mut length = 0u64;
    loop {
        // Preserve the existing Take(MAX+1) boundary even on refused growth.
        let maximum = next_read_capacity::<BUFFER_BYTES>(length)?;
        let count = match reader.read(&mut bytes[..maximum]) {
            Ok(0) => break,
            Ok(count) => count,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        };
        length =
            length
                .checked_add(u64::try_from(count).map_err(|_| {
                    ProviderError::ResourceExhausted("probe executable measurement")
                })?)
                .ok_or(ProviderError::ResourceExhausted(
                    "probe executable measurement",
                ))?;
        if length > MAXIMUM_EXECUTABLE_BYTES {
            return Err(ProviderError::ResourceExhausted(
                "probe executable measurement",
            ));
        }
        if length > expected_length && matches!(growth, GrowthPolicy::RefuseImmediately) {
            return Err(ProviderError::Correlation(
                "executable changed during measurement",
            ));
        }
        hasher.update(&bytes[..count]);
    }
    Ok(MeasuredExecutableStream {
        length,
        digest: hasher.finalize(),
    })
}

fn reference_from_stream(measured: MeasuredExecutableStream) -> Result<ContentRef, ProviderError> {
    let length = measured.length;
    let reference = ContentRef {
        hash: HashRef {
            algorithm: "blake3-256".to_owned(),
            domain: "cnp.blob.v1".to_owned(),
            digest: measured.digest.to_hex().to_string(),
        },
        length: U64::new(length),
        media_type: "application/octet-stream".to_owned(),
    };
    reference.validate()?;
    Ok(reference)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crucible_node_format::canonical;
    use std::io::{self, Cursor};
    type TestResult = Result<(), Box<dyn std::error::Error>>;

    struct Split {
        input: Cursor<Vec<u8>>,
        interrupt_once: bool,
    }

    impl Read for Split {
        fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
            if std::mem::take(&mut self.interrupt_once) {
                return Err(io::Error::from(io::ErrorKind::Interrupted));
            }
            let maximum = bytes.len().min(3);
            self.input.read(&mut bytes[..maximum])
        }
    }

    #[test]
    fn split_and_interrupted_full_measurement_matches_normative_content_reference() -> TestResult {
        let bytes: Vec<_> = (0..(STREAM_BUFFER_BYTES + 37))
            .map(|index| (index % 251) as u8)
            .collect();
        let expected = canonical::content_ref(&bytes, "application/octet-stream")?;
        let mut input = Split {
            input: Cursor::new(bytes),
            interrupt_once: true,
        };
        let actual = measure_stream(&mut input, expected.length.get())?;
        assert_eq!(actual, expected);
        assert_eq!(input.input.position(), actual.length.get());
        Ok(())
    }

    #[test]
    fn empty_matches_normative_reference_but_short_growing_and_overlimit_inputs_refuse()
    -> TestResult {
        assert_eq!(
            measure_stream(&mut Cursor::new([]), 0)?,
            canonical::content_ref(b"", "application/octet-stream")?
        );
        assert!(measure_stream(&mut Cursor::new(b"short"), 6).is_err());
        assert!(measure_stream(&mut Cursor::new(b"grown"), 4).is_err());
        let mut unread = Cursor::new(b"must not read");
        assert!(measure_stream(&mut unread, MAXIMUM_EXECUTABLE_BYTES + 1).is_err());
        assert_eq!(unread.position(), 0);
        Ok(())
    }
    #[test]
    fn actual_read_slice_keeps_exact_cap_plus_one_boundary() -> TestResult {
        fn check<const BUFFER_BYTES: usize>() -> TestResult {
            assert_eq!(next_read_capacity::<BUFFER_BYTES>(0)?, BUFFER_BYTES);
            assert_eq!(
                next_read_capacity::<BUFFER_BYTES>(MAXIMUM_EXECUTABLE_BYTES - 3)?,
                4
            );
            assert_eq!(
                next_read_capacity::<BUFFER_BYTES>(MAXIMUM_EXECUTABLE_BYTES)?,
                1
            );
            assert!(next_read_capacity::<BUFFER_BYTES>(MAXIMUM_EXECUTABLE_BYTES + 2).is_err());
            Ok(())
        }

        check::<STREAM_BUFFER_BYTES>()?;
        check::<CONFORMANCE_STREAM_BUFFER_BYTES>()
    }

    #[test]
    fn hard_midstream_error_remains_error_after_an_interrupted_read() {
        struct InterruptedThenError {
            phase: u8,
        }
        impl Read for InterruptedThenError {
            fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
                self.phase += 1;
                match self.phase {
                    1 => {
                        bytes[0] = b'x';
                        Ok(1)
                    }
                    2 => Err(io::Error::from(io::ErrorKind::Interrupted)),
                    _ => Err(io::Error::from(io::ErrorKind::BrokenPipe)),
                }
            }
        }
        let mut input = InterruptedThenError { phase: 0 };
        assert!(measure_stream(&mut input, 2).is_err());
        assert_eq!(input.phase, 3);
    }

    #[test]
    fn growth_policy_preserves_prepare_refusal_and_generic_read_error_precedence() {
        struct GrowthThenError {
            reads: usize,
        }
        impl Read for GrowthThenError {
            fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
                self.reads += 1;
                if self.reads == 1 {
                    bytes[..3].copy_from_slice(b"new");
                    Ok(3)
                } else {
                    Err(io::Error::from(io::ErrorKind::BrokenPipe))
                }
            }
        }

        let mut prepare_reader = GrowthThenError { reads: 0 };
        let mut generic_reader = GrowthThenError { reads: 0 };
        let prepare = measure_bounded_stream::<STREAM_BUFFER_BYTES>(
            &mut prepare_reader,
            1,
            GrowthPolicy::RefuseImmediately,
        );
        let generic = measure_bounded_stream::<CONFORMANCE_STREAM_BUFFER_BYTES>(
            &mut generic_reader,
            1,
            GrowthPolicy::ReadToBound,
        );

        assert!(matches!(
            prepare,
            Err(ProviderError::Correlation(
                "executable changed during measurement"
            ))
        ));
        assert!(
            matches!(generic, Err(ProviderError::Io(error)) if error.kind() == io::ErrorKind::BrokenPipe)
        );
        assert_eq!(prepare_reader.reads, 1);
        assert_eq!(generic_reader.reads, 2);
    }

    #[test]
    fn same_actual_descriptor_metadata_growth_refuses_unchanged_snapshot_passes() -> TestResult {
        use std::io::Write;
        struct CreatedFile(std::path::PathBuf);
        impl Drop for CreatedFile {
            fn drop(&mut self) {
                let _ = std::fs::remove_file(&self.0);
            }
        }
        let serial = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "aos-prepare-measure-{}-{serial}",
            std::process::id()
        ));
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&path)?;
        let _created = CreatedFile(path);
        file.write_all(b"original")?;
        let before = file.metadata()?;
        authenticate_metadata(&before, &file.metadata()?)?;
        assert_eq!(
            crate::conformance::measure_executable(&_created.0)?,
            canonical::content_ref(b"original", "application/octet-stream")?
        );
        file.write_all(b"grown")?;
        assert!(authenticate_metadata(&before, &file.metadata()?).is_err());
        assert_eq!(
            crate::conformance::measure_executable(&_created.0)?,
            canonical::content_ref(b"originalgrown", "application/octet-stream")?
        );
        Ok(())
    }

    #[test]
    fn generic_and_prepare_banks_preserve_independent_policies_and_identical_content() -> TestResult
    {
        struct ObservedRead<'a> {
            input: Cursor<&'a [u8]>,
            largest_slice: usize,
        }

        impl Read for ObservedRead<'_> {
            fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
                self.largest_slice = self.largest_slice.max(output.len());
                self.input.read(output)
            }
        }

        let bytes: Vec<_> = (0..CONFORMANCE_STREAM_BUFFER_BYTES + 37)
            .map(|index| (index % 251) as u8)
            .collect();
        let expected = canonical::content_ref(&bytes, "application/octet-stream")?;
        let mut prepare = ObservedRead {
            input: Cursor::new(bytes.as_slice()),
            largest_slice: 0,
        };
        let mut generic = ObservedRead {
            input: Cursor::new(bytes.as_slice()),
            largest_slice: 0,
        };

        let selected = measure_stream(&mut prepare, expected.length.get())?;
        let measured = measure_bounded_stream::<CONFORMANCE_STREAM_BUFFER_BYTES>(
            &mut generic,
            expected.length.get(),
            GrowthPolicy::ReadToBound,
        )?;
        let ordinary = reference_from_stream(measured)?;

        assert_eq!(selected, expected);
        assert_eq!(ordinary, expected);
        assert_eq!(prepare.largest_slice, STREAM_BUFFER_BYTES);
        assert_eq!(generic.largest_slice, CONFORMANCE_STREAM_BUFFER_BYTES);
        assert_eq!(prepare.input.position(), expected.length.get());
        assert_eq!(generic.input.position(), expected.length.get());
        Ok(())
    }

    #[test]
    fn fixed_controller_path_preserves_all_u64_decimal_spellings() -> TestResult {
        for pid in [0, 1, u32::MAX as u64, u64::MAX] {
            let path = ControllerExecutablePath::new(U64::new(pid));
            assert_eq!(path.as_path()?, Path::new(&format!("/proc/{pid}/exe")));
            assert!(path.length <= path.bytes.len());
        }
        Ok(())
    }

    #[test]
    fn kernel_current_executable_matches_existing_resolved_path_measurement() -> TestResult {
        let resolved = std::env::current_exe()?;
        let expected = measure_executable(&resolved)?;
        assert_eq!(measure_current_executable()?, expected);
        assert_eq!(
            measure_controller_executable(U64::new(u64::from(std::process::id())))?,
            expected
        );
        Ok(())
    }

    #[test]
    #[ignore = "requires the same pinned immutable executable and complete expected ContentRef"]
    fn original_prepare_executable_measurement_performance_sample() -> TestResult {
        let input = std::env::var("CRUCIBLE_PREPARE_MEASUREMENT_INPUT")?;
        let expected = std::env::var("CRUCIBLE_PREPARE_MEASUREMENT_EXPECTED")?;
        let expected: ContentRef = canonical::decode(expected.as_bytes(), 4096)?;
        let path = Path::new(&input);
        let sentinel = File::open(path)?;
        let before = sentinel.metadata()?;

        let started = crate::operational_time::PhysicalMeasurement::begin();
        let actual = measure_executable(path)?;
        let elapsed = started.elapsed();

        authenticate_metadata(&before, &sentinel.metadata()?)?;
        let after = std::fs::metadata(path)?;
        authenticate_metadata(&before, &after)?;
        assert_eq!((before.dev(), before.ino()), (after.dev(), after.ino()));
        assert_eq!(actual, expected);
        println!(
            "{}",
            serde_json::json!({
                "measurement": "original-prepare-executable-api",
                "stream_buffer_bytes": STREAM_BUFFER_BYTES,
                "elapsed_ns": elapsed.as_nanos().to_string(),
                "content": actual,
                "device": after.dev().to_string(),
                "inode": after.ino().to_string(),
            })
        );
        Ok(())
    }

    #[test]
    #[ignore = "requires the same pinned immutable executable selected for performance samples"]
    fn original_prepare_executable_measurement_reference() -> TestResult {
        let input = std::env::var("CRUCIBLE_PREPARE_MEASUREMENT_INPUT")?;
        let reference = crate::conformance::measure_executable(Path::new(&input))?;
        let bytes = canonical::canonical_json(&serde_json::to_value(reference)?)?;
        println!("{}", std::str::from_utf8(&bytes)?);
        Ok(())
    }
}
