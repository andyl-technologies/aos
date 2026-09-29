//! Opt-in structural-index scale measurements, without a kernel FUSE realizer.
//!
//! The coordinator execs a streaming builder, waits for its exit, then execs a
//! fresh single-thread measurement worker. A sealed memfd mapping holds the
//! encoded index, not a heap Vec. All source descriptors are fixture-only;
//! this does not qualify portable-tree compilation or any production authority.
//! The small profile is the ordinary CI run. `--million` selects exactly
//! 1,000,000 children; a larger validation envelope requires an explicit flag.

#![deny(unsafe_op_in_unsafe_fn)]

#[path = "support/allocation.rs"]
mod allocation;
#[cfg(target_os = "linux")]
#[path = "metadata_scale/fixture.rs"]
mod fixture;
#[path = "support/fixture_runner.rs"]
mod fixture_runner;
#[cfg(target_os = "linux")]
#[path = "metadata_scale/measurement.rs"]
mod measurement;
#[cfg(target_os = "linux")]
#[path = "metadata_scale/report.rs"]
mod report;

#[global_allocator]
static ALLOCATOR: allocation::CountingAllocator = allocation::CountingAllocator;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

const CASE: &str = "metadata_scale_small";

#[cfg(target_os = "linux")]
fn run(arguments: &[String]) -> Result<()> {
    use std::io::{Read, Write};
    use std::process::{Command, Stdio};

    use report::{BuildReport, Config, MeasurementReport};

    struct ReportChild(std::process::Child);

    impl Drop for ReportChild {
        fn drop(&mut self) {
            // A failed read/assertion must not leave our fixture worker alive.
            if !matches!(self.0.try_wait(), Ok(Some(_))) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
    }

    fn child<T: serde::de::DeserializeOwned>(
        mode: &str,
        config: Config,
        path: &std::path::Path,
    ) -> Result<T> {
        let mut process = ReportChild(
            Command::new(std::env::current_exe()?)
                .arg(mode)
                .arg(path)
                .arg(config.profile.name())
                .arg(config.validation_envelope_bytes.to_string())
                .stdout(Stdio::piped())
                .spawn()?,
        );
        let mut output = Vec::new();
        process
            .0
            .stdout
            .take()
            .ok_or("child stdout missing")?
            .take(report::MAX_REPORT_BYTES + 1)
            .read_to_end(&mut output)?;
        if output.len() as u64 > report::MAX_REPORT_BYTES {
            process.0.kill()?;
            process.0.wait()?;
            return Err("bounded child report exceeded its limit".into());
        }
        if !process.0.wait()?.success() {
            return Err("metadata-scale child failed".into());
        }
        Ok(serde_json::from_slice(&output)?)
    }

    if matches!(
        arguments.first().map(String::as_str),
        Some("--build" | "--measure")
    ) {
        if arguments.len() != 4 {
            return Err("internal child requires mode/path/profile/envelope".into());
        }
        let config = Config::child(&arguments[2], arguments[3].parse()?)?;
        let path = std::path::Path::new(&arguments[1]);
        if arguments[0] == "--build" {
            serde_json::to_writer(std::io::stdout().lock(), &fixture::build(path, config)?)?;
        } else {
            serde_json::to_writer(std::io::stdout().lock(), &measurement::run(path, config)?)?;
        }
        return Ok(());
    }

    let config = Config::parse(arguments)?;
    report::check_helpers();
    let temporary = fixture::TemporaryFixture::create()?;
    let construction: BuildReport = child("--build", config, temporary.path())?;
    let measurement: MeasurementReport = child("--measure", config, temporary.path())?;
    assert_eq!(construction.records, config.profile.children() + 1);
    assert_eq!(construction.index_bytes, measurement.index_bytes);
    if config.profile == report::Profile::Small {
        assert!(
            measurement.validated,
            "small normal-ceiling profile must validate"
        );
    }
    temporary.finish()?;

    let label = |name: &str, fallback: &str| -> Result<String> {
        let value = std::env::var(name).unwrap_or_else(|_| fallback.to_owned());
        if value.len() > 256 {
            return Err("metadata report label exceeds 256 bytes".into());
        }
        Ok(value)
    };
    let kernel = std::fs::read_to_string("/proc/sys/kernel/osrelease")?;
    if kernel.len() > 256 {
        return Err("kernel report label exceeds 256 bytes".into());
    }
    let result = report::Report {
        schema: "aos.filesystem.metadata-scale/v1",
        scope: "userspace structural index and logical inode handles; memfd/shmem, not filesystem cache/FUSE/ARC/memcg",
        architecture: std::env::consts::ARCH,
        kernel: kernel.trim().to_owned(),
        hardware_class: label(
            "AOS_METADATA_SCALE_HARDWARE_CLASS",
            "unspecified development host",
        )?,
        source_commit_label: label(
            "AOS_METADATA_SCALE_SOURCE_COMMIT",
            "unspecified; record the exact checkout externally",
        )?,
        concurrency: 1,
        cache_state: "post-validation warm metadata; no cold-cache claim",
        security_profile: "test-fixture only, no production connection or MAC qualification",
        profile: config.profile,
        validation_envelope_bytes: config.validation_envelope_bytes,
        construction,
        measurement,
        temporary_files_removed: true,
    };
    // Coordinator serialization is outside every measured worker phase.
    let encoded = serde_json::to_vec(&result)?;
    if encoded.len() as u64 >= report::MAX_REPORT_BYTES {
        return Err("final metadata report exceeds 64 KiB including newline".into());
    }
    let mut stdout = std::io::stdout().lock();
    stdout.write_all(&encoded)?;
    stdout.write_all(b"\n")?;
    Ok(())
}

fn main() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        let arguments = std::env::args().skip(1).collect::<Vec<_>>();
        if matches!(
            arguments.first().map(String::as_str),
            Some("--build" | "--measure")
        ) || arguments.iter().any(|argument| {
            matches!(
                argument.as_str(),
                "--million" | "--validation-envelope-bytes"
            )
        }) {
            return run(&arguments);
        }
        let invocation = fixture_runner::parse(&arguments, CASE)?;
        fixture_runner::execute(invocation, CASE, &mut std::io::stdout(), || run(&[]))
    }

    #[cfg(not(target_os = "linux"))]
    Err("metadata_scale requires Linux sealed memfds and procfs".into())
}
