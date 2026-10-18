//! Independently guarded fingerprint reads after a modeled publisher dies.

#![cfg(test)]

use super::*;
use std::io::{BufRead, Read, Write};
use std::os::unix::fs::FileExt;
use std::process::{Command, Stdio};

const CHILD_TEST: &str =
    "supervision::host_io_runtime::tests::fingerprint_liveness::fingerprint_process";
const CHILD_ROLE: &str = "CRUCIBLE_FINGERPRINT_TEST_ROLE";
const REGION_PATH: &str = "CRUCIBLE_FINGERPRINT_TEST_REGION";
const OFFSET: &str = "CRUCIBLE_FINGERPRINT_TEST_OFFSET";
const READY: &str = "PUBLICATION_WRITER_READY";

fn child_command(role: &str) -> Result<Command, Box<dyn std::error::Error>> {
    let mut command = Command::new(std::env::current_exe()?);
    command
        .args(["--exact", CHILD_TEST, "--ignored", "--nocapture"])
        .env(CHILD_ROLE, role);
    Ok(command)
}

/// Holds a child until its owner explicitly reaps it, including error unwinding.
struct OwnedProcess(std::process::Child);

impl Drop for OwnedProcess {
    fn drop(&mut self) {
        if !matches!(self.0.try_wait(), Ok(Some(_))) {
            let _kill_result = self.0.kill();
            let _wait_result = self.0.wait();
        }
    }
}

// crucible-lint: allow clippy-disallowed-method -- an independent parent watchdog contains the old spinning reader; it is not modeled time.
#[allow(clippy::disallowed_methods)]
fn guard_reader() -> Result<(), Box<dyn std::error::Error>> {
    let transcript = tempfile::tempfile()?;
    let output = transcript.try_clone()?;
    let mut reader = OwnedProcess(
        child_command("reader")?
            .stdout(Stdio::from(output.try_clone()?))
            .stderr(Stdio::from(output))
            .spawn()?,
    );
    // This guard belongs to the independent parent, so an unbounded slot read
    // cannot prevent it from killing and reaping the reader subprocess.
    use rustix::event::{PollFd, PollFlags, Timespec, poll};
    use rustix::process::{Pid, PidfdFlags, pidfd_open};

    let pid = Pid::from_raw(i32::try_from(reader.0.id())?).ok_or("reader PID is not positive")?;
    let pidfd = pidfd_open(pid, PidfdFlags::empty())?;
    let deadline = std::time::Instant::now() + Duration::from_secs(8);
    let status = loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            reader.0.kill()?;
            reader.0.wait()?;
            break None;
        }
        let timeout = Timespec::try_from(remaining)?;
        let mut descriptors = [PollFd::new(&pidfd, PollFlags::IN)];
        match poll(&mut descriptors, Some(&timeout)) {
            Ok(_) if descriptors[0].revents().contains(PollFlags::IN) => {
                break Some(reader.0.wait()?);
            }
            Ok(_) => continue,
            Err(rustix::io::Errno::INTR) => continue,
            Err(error) => return Err(error.into()),
        }
    };
    let mut retained = String::new();
    let mut transcript = transcript;
    use std::io::{Seek, SeekFrom};
    transcript.seek(SeekFrom::Start(0))?;
    transcript.read_to_string(&mut retained)?;
    assert!(
        status.is_some_and(|status| status.success()),
        "publication reader failed or exceeded its independent parent guard: {status:?}\n{retained}"
    );
    assert!(retained.contains("DEAD_FINGERPRINT_READ_UNAVAILABLE"));
    Ok(())
}

#[test]
fn killed_fingerprint_publisher_cannot_trap_host_reader() -> Result<(), Box<dyn std::error::Error>>
{
    guard_reader()
}

/// Executes only as an independently owned fixture subprocess.
#[test]
#[ignore = "owned publication-writer/reader subprocess entry point"]
fn fingerprint_process() -> Result<(), Box<dyn std::error::Error>> {
    match std::env::var(CHILD_ROLE)?.as_str() {
        "writer" => {
            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(std::env::var(REGION_PATH)?)?;
            let offset = std::env::var(OFFSET)?.parse::<u64>()?;
            // This test models a writer interrupted between its public odd and
            // even sequence stores. It does not impersonate QEMU execution.
            file.write_all_at(&1_u32.to_ne_bytes(), offset)?;
            println!("\n{READY}");
            std::io::stdout().flush()?;
            let mut release = String::new();
            std::io::stdin().read_line(&mut release)?;
            Err("writer was released instead of killed".into())
        }
        "reader" => run_dead_publication_reader(),
        _ => Err("unknown publication fixture role".into()),
    }
}

fn run_dead_publication_reader() -> Result<(), Box<dyn std::error::Error>> {
    use super::publication_access::MappedPublication;
    use std::os::fd::AsRawFd;

    let mapped = MappedPublication::new()?;
    let offset = mapped.layout.fingerprint_sample_off
        + crucible_shmem::FINGERPRINT_SAMPLE_SLOT_GEN_OFFSET as u64;
    // Open only this owned memfd through the reader's exact descriptor. No
    // process discovery or unrelated mapping is involved.
    let region_path = format!(
        "/proc/{}/fd/{}",
        std::process::id(),
        mapped.file.as_raw_fd()
    );
    let mut writer = OwnedProcess(
        child_command("writer")?
            .env(REGION_PATH, region_path)
            .env(OFFSET, offset.to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()?,
    );
    let output = writer.0.stdout.take().ok_or("writer stdout absent")?;
    let mut lines = std::io::BufReader::new(output).lines();
    loop {
        if lines.next().ok_or("writer ended before publication")?? == READY {
            break;
        }
    }
    writer.0.kill()?;
    let status = writer.0.wait()?;
    assert!(!status.success());
    println!("FINGERPRINT_WRITER_KILLED status={status}");
    println!("DEAD_FINGERPRINT_READ_ENTER");
    std::io::stdout().flush()?;

    let result = mapped.channel.fingerprint_sample();
    assert!(
        matches!(
            result,
            Err(
                crate::QemuMappedQuantumShmemHotPathError::FingerprintPublicationUnavailable { .. }
            )
        ),
        "odd publication must be unavailable"
    );
    assert_eq!(
        mapped
            .producer
            .fingerprint_sample(0)?
            .capture_request_generation(),
        0
    );
    println!("DEAD_FINGERPRINT_READ_UNAVAILABLE");
    Ok(())
}
