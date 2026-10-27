//! Opt-in preservation of fingerprint preimages for replay-oracle diagnosis.
//!
//! A replay-oracle mismatch reports only component digests. When
//! `CRUCIBLE_FINGERPRINT_MATERIAL_DUMP_DIR` names an existing absolute
//! directory, the digest worker also writes each in-window sample's exact RAM
//! and device-projection preimages there, so a failed flight can be compared
//! page by page and section by section. The window is the inclusive logical
//! sample-count range named by `CRUCIBLE_FINGERPRINT_MATERIAL_DUMP_MIN_ICOUNT`
//! and `CRUCIBLE_FINGERPRINT_MATERIAL_DUMP_MAX_ICOUNT`; both are required.
//! Each process writes at most [`MAXIMUM_DUMPS_PER_PROCESS`] samples.
//!
//! Every dump uses one file stem and three files:
//!
//! ```text
//! fpr-<pid>-<sequence>-<icount>.ram     sparse byte-exact RAM preimage
//! fpr-<pid>-<sequence>-<icount>.device  byte-exact device preimage
//! fpr-<pid>-<sequence>-<icount>.meta    key=value digests and sizes
//! ```
//!
//! The RAM file omits all-zero pages as holes, so it costs only the guest's
//! populated memory. The metadata file is written last; a reader treats a
//! stem without metadata as incomplete.
//!
//! Dumping is observation-only. It runs on the digest worker after both
//! digests are final and reads the sealed preimages with positioned reads. A
//! failure prints one bounded diagnostic and never changes the sample.

use std::ffi::OsStr;
use std::fmt::Write as _;
use std::fs::{File, OpenOptions};
use std::io::{self, Write as _};
use std::os::unix::fs::{FileExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU32, Ordering};

use crucible_qemu_shmem::FingerprintSample;

const DIRECTORY_ENVIRONMENT: &str = "CRUCIBLE_FINGERPRINT_MATERIAL_DUMP_DIR";
const MINIMUM_ENVIRONMENT: &str = "CRUCIBLE_FINGERPRINT_MATERIAL_DUMP_MIN_ICOUNT";
const MAXIMUM_ENVIRONMENT: &str = "CRUCIBLE_FINGERPRINT_MATERIAL_DUMP_MAX_ICOUNT";

/// Upper bound on dumps from one QEMU process, so a long run cannot fill disk.
const MAXIMUM_DUMPS_PER_PROCESS: u32 = 4;

/// Hole granularity for the sparse RAM copy.
const PAGE_BYTES: usize = 4096;

/// Positioned-read buffer; a whole number of pages.
const COPY_BUFFER_BYTES: usize = 64 * PAGE_BYTES;

/// Bound on the directory name accepted from the environment.
const MAXIMUM_DIRECTORY_BYTES: usize = 256;

static CONFIGURATION: OnceLock<Option<MaterialDumpConfiguration>> = OnceLock::new();
static DUMPS_RESERVED: AtomicU32 = AtomicU32::new(0);

/// Validated destination and logical sample window for preimage dumps.
#[derive(Clone, Debug, PartialEq, Eq)]
struct MaterialDumpConfiguration {
    directory: PathBuf,
    minimum_icount: u64,
    maximum_icount: u64,
}

impl MaterialDumpConfiguration {
    /// Parses the three opt-in values; any absent or malformed value disables dumping.
    fn parse(
        directory: Option<&OsStr>,
        minimum: Option<&OsStr>,
        maximum: Option<&OsStr>,
    ) -> Option<Self> {
        let directory = Path::new(directory?);
        let directory_bytes = directory.as_os_str().len();
        if !directory.is_absolute()
            || directory_bytes == 0
            || directory_bytes > MAXIMUM_DIRECTORY_BYTES
        {
            return None;
        }
        let minimum_icount = canonical_u64(minimum?)?;
        let maximum_icount = canonical_u64(maximum?)?;
        if minimum_icount > maximum_icount {
            return None;
        }

        Some(Self {
            directory: directory.to_path_buf(),
            minimum_icount,
            maximum_icount,
        })
    }

    fn admits(&self, icount: u64) -> bool {
        (self.minimum_icount..=self.maximum_icount).contains(&icount)
    }
}

/// Parses a decimal value only in its canonical spelling.
fn canonical_u64(value: &OsStr) -> Option<u64> {
    let text = value.to_str()?;
    let parsed = text.parse::<u64>().ok()?;
    (parsed.to_string() == text).then_some(parsed)
}

fn configuration() -> Option<&'static MaterialDumpConfiguration> {
    CONFIGURATION
        .get_or_init(|| {
            // crucible-lint: allow host-nondeterminism-state -- a default-off diagnostic destination is cached once and never reaches control decisions.
            let directory = std::env::var_os(DIRECTORY_ENVIRONMENT);
            // crucible-lint: allow host-nondeterminism-state -- the diagnostic window only selects which finished samples are copied.
            let minimum = std::env::var_os(MINIMUM_ENVIRONMENT);
            // crucible-lint: allow host-nondeterminism-state -- the diagnostic window only selects which finished samples are copied.
            let maximum = std::env::var_os(MAXIMUM_ENVIRONMENT);
            MaterialDumpConfiguration::parse(
                directory.as_deref(),
                minimum.as_deref(),
                maximum.as_deref(),
            )
        })
        .as_ref()
}

/// One finished sample and the sealed preimages its digests cover.
pub(super) struct MaterialDumpInput<'a> {
    pub(super) sample: &'a FingerprintSample,
    pub(super) ram: &'a File,
    pub(super) ram_material_bytes: u64,
    pub(super) device: &'a File,
    pub(super) device_material_bytes: u64,
}

/// Writes the sample's preimages when the opt-in window admits it.
///
/// Errors are reported once on standard error and otherwise ignored, because
/// the diagnostic copy must not change fingerprint publication.
pub(super) fn dump_if_requested(input: &MaterialDumpInput<'_>) {
    let Some(configuration) = configuration() else {
        return;
    };
    if !configuration.admits(input.sample.sample_icount) {
        return;
    }
    let Some(sequence) = reserve_dump(&DUMPS_RESERVED) else {
        return;
    };

    let stem = format!(
        "fpr-{}-{sequence}-{}",
        std::process::id(),
        input.sample.sample_icount
    );
    let result = write_dump(&configuration.directory, &stem, input);
    let mut output = io::stderr().lock();
    // A closed diagnostic sink must not replace the sample.
    let _ = match result {
        Ok(()) => writeln!(
            output,
            "CRUCIBLE-PHASE4-CLOCK-TRACE fingerprint-material stem={stem} ram={} device={}",
            hex::encode(input.sample.ram_digest),
            hex::encode(input.sample.device_state_digest),
        ),
        Err(error) => writeln!(
            output,
            "CRUCIBLE-PHASE4-CLOCK-TRACE fingerprint-material stem={stem} error={error}"
        ),
    };
}

/// Claims the next per-process dump sequence while the cap allows it.
fn reserve_dump(reserved: &AtomicU32) -> Option<u32> {
    reserved
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
            (count < MAXIMUM_DUMPS_PER_PROCESS).then_some(count + 1)
        })
        .ok()
}

fn write_dump(directory: &Path, stem: &str, input: &MaterialDumpInput<'_>) -> io::Result<()> {
    let ram_path = directory.join(format!("{stem}.ram"));
    copy_preimage(input.ram, input.ram_material_bytes, &ram_path, true)?;
    let device_path = directory.join(format!("{stem}.device"));
    copy_preimage(
        input.device,
        input.device_material_bytes,
        &device_path,
        false,
    )?;

    // Metadata last: its presence marks both preimages complete.
    let mut meta = create_dump_file(&directory.join(format!("{stem}.meta")))?;
    meta.write_all(metadata_text(input).as_bytes())?;
    meta.sync_all()
}

fn create_dump_file(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(path)
}

/// Copies one preimage with positioned reads, leaving zero pages as holes when sparse.
fn copy_preimage(source: &File, length: u64, path: &Path, sparse: bool) -> io::Result<()> {
    let destination = create_dump_file(path)?;
    let mut buffer = vec![0_u8; COPY_BUFFER_BYTES];
    let mut offset = 0_u64;

    while offset < length {
        // The minimum is bounded by the local buffer length.
        let requested = (length - offset).min(COPY_BUFFER_BYTES as u64) as usize;
        let chunk = &mut buffer[..requested];
        source.read_exact_at(chunk, offset)?;
        for (index, page) in chunk.chunks(PAGE_BYTES).enumerate() {
            if sparse && page.iter().all(|byte| *byte == 0) {
                continue;
            }
            let page_offset = offset + (index * PAGE_BYTES) as u64;
            destination.write_all_at(page, page_offset)?;
        }
        offset += requested as u64;
    }

    // Trailing holes still count toward the exact preimage length.
    destination.set_len(length)?;
    destination.sync_all()
}

fn metadata_text(input: &MaterialDumpInput<'_>) -> String {
    let sample = input.sample;
    let mut text = String::new();
    // Writing to a String cannot fail.
    let _ = writeln!(text, "pid={}", std::process::id());
    let _ = writeln!(text, "sample_icount={}", sample.sample_icount);
    let _ = writeln!(text, "ram_bytes={}", sample.ram_bytes);
    let _ = writeln!(text, "ram_material_bytes={}", input.ram_material_bytes);
    let _ = writeln!(text, "ram_digest={}", hex::encode(sample.ram_digest));
    let _ = writeln!(text, "device_bytes={}", sample.device_state_bytes);
    let _ = writeln!(
        text,
        "device_material_bytes={}",
        input.device_material_bytes
    );
    let _ = writeln!(
        text,
        "device_digest={}",
        hex::encode(sample.device_state_digest)
    );
    let _ = writeln!(text, "component_failures={}", sample.component_failures);
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(directory: &str, minimum: &str, maximum: &str) -> Option<MaterialDumpConfiguration> {
        MaterialDumpConfiguration::parse(
            Some(OsStr::new(directory)),
            Some(OsStr::new(minimum)),
            Some(OsStr::new(maximum)),
        )
    }

    #[test]
    fn configuration_requires_an_absolute_directory_and_canonical_window() {
        let configuration = parse("/var/tmp/material", "10", "20");
        assert_eq!(
            configuration,
            Some(MaterialDumpConfiguration {
                directory: PathBuf::from("/var/tmp/material"),
                minimum_icount: 10,
                maximum_icount: 20,
            })
        );

        assert_eq!(parse("relative/material", "10", "20"), None);
        assert_eq!(parse("/var/tmp/material", "010", "20"), None);
        assert_eq!(parse("/var/tmp/material", "30", "20"), None);
        assert_eq!(
            MaterialDumpConfiguration::parse(Some(OsStr::new("/var/tmp")), None, None),
            None
        );
    }

    #[test]
    fn window_is_inclusive() {
        let Some(configuration) = parse("/var/tmp/material", "10", "20") else {
            panic!("valid configuration was rejected");
        };

        assert!(!configuration.admits(9));
        assert!(configuration.admits(10));
        assert!(configuration.admits(20));
        assert!(!configuration.admits(21));
    }

    #[test]
    fn reservation_stops_at_the_per_process_cap() {
        let reserved = AtomicU32::new(0);

        let sequences = (0..=MAXIMUM_DUMPS_PER_PROCESS)
            .map(|_| reserve_dump(&reserved))
            .collect::<Vec<_>>();

        assert_eq!(sequences[0], Some(0));
        assert_eq!(
            sequences[MAXIMUM_DUMPS_PER_PROCESS as usize - 1],
            Some(MAXIMUM_DUMPS_PER_PROCESS - 1)
        );
        assert_eq!(sequences[MAXIMUM_DUMPS_PER_PROCESS as usize], None);
    }

    #[test]
    fn sparse_copy_preserves_length_and_nonzero_pages() -> io::Result<()> {
        let directory = std::env::temp_dir().join(format!(
            "crucible-material-dump-test-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&directory)?;
        let source_path = directory.join("source");
        let destination_path = directory.join("destination");
        let _ = std::fs::remove_file(&destination_path);

        let mut bytes = vec![0_u8; PAGE_BYTES * 3 + 17];
        bytes[PAGE_BYTES + 5] = 0xa5;
        bytes[PAGE_BYTES * 3 + 16] = 0x5a;
        std::fs::write(&source_path, &bytes)?;
        let source = File::open(&source_path)?;

        copy_preimage(&source, bytes.len() as u64, &destination_path, true)?;

        assert_eq!(std::fs::read(&destination_path)?, bytes);
        std::fs::remove_dir_all(&directory)
    }
}
