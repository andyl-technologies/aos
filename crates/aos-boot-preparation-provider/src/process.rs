//! Bounded execution of an authenticated preparation artifact.

use std::io::{self, Read as _};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, bail, ensure};

use crate::handler::Executable;

const MAX_OUTPUT_BYTES: u64 = 256 * 1024;
const PROCESS_POLL_INTERVAL: Duration = Duration::from_millis(5);

pub(super) trait CommandRunner: Send + Sync {
    fn run(&self, executable: &Executable, remaining_millis: u64) -> Result<()>;
}

pub(super) struct ProcessCommandRunner;

impl CommandRunner for ProcessCommandRunner {
    fn run(&self, executable: &Executable, remaining_millis: u64) -> Result<()> {
        ensure!(remaining_millis > 0, "boot preparation deadline expired");
        let mut child = Command::new(executable.path())
            .args(&executable.arguments)
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("starting exact boot preparation executable")?;
        let mut stdout = child
            .stdout
            .take()
            .context("capturing preparation stdout")?;
        let mut stderr = child
            .stderr
            .take()
            .context("capturing preparation stderr")?;
        let stdout_thread = thread::spawn(move || read_bounded(&mut stdout));
        let stderr_thread = thread::spawn(move || read_bounded(&mut stderr));
        let deadline = deadline(remaining_millis)?;

        let status = loop {
            if let Some(status) = child.try_wait().context("waiting for boot preparation")? {
                break status;
            }
            if monotonic_now() >= deadline {
                child
                    .kill()
                    .context("terminating expired boot preparation")?;
                let _ = child.wait();
                bail!("boot preparation exceeded its attempt deadline");
            }
            thread::sleep(PROCESS_POLL_INTERVAL);
        };
        let _stdout = join_reader(stdout_thread, "stdout")?;
        let stderr = join_reader(stderr_thread, "stderr")?;
        ensure!(
            status.success(),
            "boot preparation failed with {status}: {}",
            String::from_utf8_lossy(&stderr)
        );
        Ok(())
    }
}

fn read_bounded(reader: &mut impl io::Read) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader.take(MAX_OUTPUT_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_OUTPUT_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "boot preparation output exceeds its bound",
        ));
    }
    Ok(bytes)
}

fn join_reader(reader: thread::JoinHandle<io::Result<Vec<u8>>>, stream: &str) -> Result<Vec<u8>> {
    reader
        .join()
        .map_err(|_| anyhow::anyhow!("boot preparation {stream} reader panicked"))?
        .with_context(|| format!("reading bounded boot preparation {stream}"))
}

fn deadline(remaining_millis: u64) -> Result<Instant> {
    Instant::now()
        .checked_add(Duration::from_millis(remaining_millis))
        .context("boot preparation deadline overflow")
}

#[allow(clippy::disallowed_methods)]
fn monotonic_now() -> Instant {
    Instant::now()
}
