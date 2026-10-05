//! Independently supervised regressions for interrupted mapped publications.

#![cfg(test)]

use super::*;
use std::io::{BufRead, Read, Write};
use std::os::fd::AsFd;
use std::os::unix::fs::FileExt;
use std::process::{Command, Stdio};

const CHILD_TEST: &str =
    "supervision::host_io_runtime::tests::publication_liveness::publication_process";
const CHILD_ROLE: &str = "CRUCIBLE_PUBLICATION_TEST_ROLE";
const REGION_PATH: &str = "CRUCIBLE_PUBLICATION_TEST_REGION";
const OFFSET: &str = "CRUCIBLE_PUBLICATION_TEST_OFFSET";
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
fn guard_reader(sequence: &str) -> Result<(), Box<dyn std::error::Error>> {
    let transcript = tempfile::tempfile()?;
    let output = transcript.try_clone()?;
    let mut reader = OwnedProcess(
        child_command("reader")?
            .env(OFFSET, sequence)
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
    assert!(retained.contains("DEAD_PUBLICATION_READER_TIMED_OUT"));
    Ok(())
}

#[test]
fn killed_producer_odd_publication_keeps_original_host_deadline()
-> Result<(), Box<dyn std::error::Error>> {
    guard_reader("producer")
}

#[test]
fn odd_scheduler_publication_keeps_original_host_deadline() -> Result<(), Box<dyn std::error::Error>>
{
    guard_reader("scheduler")
}

/// Executes only as an independently owned fixture subprocess.
#[test]
#[ignore = "owned publication-writer/reader subprocess entry point"]
fn publication_process() -> Result<(), Box<dyn std::error::Error>> {
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
    let allocation =
        crucible_shmem::RegionAllocation::new_model(crucible_shmem::RegionConfig::new(1, 2))?;
    let layout = allocation.layout();
    let mut file = tempfile::NamedTempFile::new()?;
    file.write_all(&allocation.setup_region_bytes()?)?;
    let plugin = crucible_shmem::mmap_setup_region(file.as_file().as_fd(), layout.region_size)?;
    let slot = plugin.node_slot(0)?;
    slot.publish_scheduler_advance(
        authorize_advance_ceiling(0, 100, None)?,
        crucible_shmem::AdvanceStopCondition::Ceiling,
    )?;
    slot.publish_reached_icount(0)?;
    let wake = tempfile::tempfile()?;
    let mut runtime = QemuLiveHostIoRuntime::from_shmem_fd(
        file.as_file().as_fd(),
        wake.as_fd(),
        layout.region_size,
        0,
    )?;
    runtime.set_advance_completion_poll_slice(Some(Duration::from_millis(20)))?;

    let offset = layout.node_slots_off
        + if std::env::var(OFFSET)? == "producer" {
            crucible_shmem::NODE_SLOT_PUBLISH_GEN_OFFSET as u64
        } else {
            crucible_shmem::NODE_SLOT_ADVANCE_PUBLICATION_SEQUENCE_OFFSET as u64
        };
    let mut writer = OwnedProcess(
        child_command("writer")?
            .env(REGION_PATH, file.path())
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
    println!("PUBLICATION_WRITER_KILLED status={status}");

    let budget = Duration::from_millis(200);
    println!("DEAD_PUBLICATION_READ_ENTER budget_ms=200");
    let mut outcome = runtime.await_child(QemuAsyncWait::AdvanceCompletion, budget)?;
    while outcome == QemuAsyncWaitOutcome::Pending {
        assert!(runtime.completed_boundary.is_none());
        outcome = runtime.repoll_child(QemuAsyncWait::AdvanceCompletion, budget)?;
    }
    assert_eq!(outcome, QemuAsyncWaitOutcome::TimedOut);
    assert!(runtime.completed_boundary.is_none());
    println!("DEAD_PUBLICATION_READER_TIMED_OUT");
    Ok(())
}
