//! Temporary GC roots owned by a live, pinned Nix store connection.
//!
//! The public Nix 2.24 serve protocol registers roots before paths are imported.
//! Keeping the connection alive protects them until durable generation roots
//! exist; this is store lifecycle protection, separate from artifact admission.

use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Stdio};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, ensure};
use aos_ability_runtime::adapter::CancellationToken;

const MAGIC_CLIENT: u64 = 0x390c9deb;
const MAGIC_SERVER: u64 = 0x5452eecb;
const VERSION: u64 = 0x207;
const ROOT_LIMIT: usize = 16_384;
const PATH_LIMIT: usize = 4096;
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(60);

type Exchange = (Vec<String>, Sender<Result<()>>);

/// Retains expected immutable roots through import, preparation, and commit.
#[derive(Debug)]
pub(crate) struct TemporaryRoots {
    child: Child,
    requests: Option<Sender<Exchange>>,
    worker: Option<JoinHandle<()>>,
    errors: Option<JoinHandle<()>>,
    roots: BTreeSet<String>,
}

impl TemporaryRoots {
    pub(crate) fn open(executable: &Path, cancellation: &CancellationToken) -> Result<Self> {
        let mut command = super::verification::live_store_command(Some(executable))?;
        command
            .args(["--serve", "--write"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0);
        let mut child = command
            .spawn()
            .context("starting temporary Nix root connection")?;
        let input = child.stdin.take().context("temporary root stdin missing")?;
        let output = child
            .stdout
            .take()
            .context("temporary root stdout missing")?;
        let mut stderr = child
            .stderr
            .take()
            .context("temporary root stderr missing")?;
        // Drain diagnostics without accumulating unbounded output or blocking
        // the store child. Exchange errors carry the bounded protocol context.
        let errors = thread::spawn(move || {
            let mut buffer = [0_u8; 4096];
            while let Ok(size) = stderr.read(&mut buffer) {
                if size == 0 {
                    break;
                }
            }
        });
        let (requests, receiver) = mpsc::channel::<Exchange>();
        let (ready, initialized) = mpsc::channel();
        let worker = thread::spawn(move || {
            let mut input = input;
            let mut output = output;
            let handshake = (|| {
                write_word(&mut input, MAGIC_CLIENT)?;
                write_word(&mut input, VERSION)?;
                input.flush()?;
                ensure!(
                    read_word(&mut output)? == MAGIC_SERVER,
                    "Nix root protocol magic mismatch"
                );
                ensure!(
                    read_word(&mut output)? & 0xff00 == 0x200,
                    "unsupported Nix root protocol version"
                );
                Ok(())
            })();
            let initialized = handshake.is_ok();
            let _ = ready.send(handshake);
            if !initialized {
                return;
            }
            while let Ok((roots, response)) = receiver.recv() {
                let result = register(&mut input, &mut output, &roots);
                let succeeded = result.is_ok();
                let _ = response.send(result);
                if !succeeded {
                    break;
                }
            }
        });
        let mut lease = Self {
            child,
            requests: Some(requests),
            worker: Some(worker),
            errors: Some(errors),
            roots: BTreeSet::new(),
        };
        if let Err(error) = wait_exchange(initialized, cancellation) {
            lease.close();
            return Err(error.context("initializing temporary Nix roots"));
        }
        Ok(lease)
    }

    /// Registers canonical paths before they become valid store objects.
    pub(crate) fn retain(
        &mut self,
        roots: impl IntoIterator<Item = String>,
        cancellation: &CancellationToken,
    ) -> Result<()> {
        let mut additional = BTreeSet::new();
        for path in roots {
            let (root, suffix) = crate::deployment::nix::store_root_and_suffix(Path::new(&path))?;
            ensure!(
                root == Path::new(&path) && suffix.as_os_str().is_empty(),
                "temporary root is not canonical"
            );
            ensure!(
                path.len() <= PATH_LIMIT,
                "temporary root path exceeds its limit"
            );
            if !self.roots.contains(&path) {
                additional.insert(path);
            }
        }
        ensure!(
            self.roots.len() + additional.len() <= ROOT_LIMIT,
            "temporary root count exceeds its limit"
        );
        if additional.is_empty() {
            return Ok(());
        }
        let (response, receiver) = mpsc::channel();
        self.requests
            .as_ref()
            .context("temporary Nix root connection is closed")?
            .send((additional.iter().cloned().collect(), response))
            .context("temporary Nix root connection ended")?;
        if let Err(error) = wait_exchange(receiver, cancellation) {
            self.close();
            return Err(error.context("registering temporary Nix roots"));
        }
        self.roots.extend(additional);
        Ok(())
    }

    fn close(&mut self) {
        self.requests.take();
        if let Ok(identifier) = i32::try_from(self.child.id()) {
            if let Some(group) = rustix::process::Pid::from_raw(identifier) {
                let _ = rustix::process::kill_process_group(group, rustix::process::Signal::KILL);
            }
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
        if let Some(errors) = self.errors.take() {
            let _ = errors.join();
        }
    }
}

impl Drop for TemporaryRoots {
    fn drop(&mut self) {
        self.close();
    }
}

#[allow(
    clippy::disallowed_methods,
    reason = "store transport deadlines use host monotonic time"
)]
fn wait_exchange(receiver: Receiver<Result<()>>, cancellation: &CancellationToken) -> Result<()> {
    let deadline = Instant::now() + EXCHANGE_TIMEOUT;
    loop {
        ensure!(
            !cancellation.is_cancelled(),
            "temporary Nix root exchange cancelled"
        );
        ensure!(
            Instant::now() < deadline,
            "temporary Nix root exchange timed out"
        );
        match receiver.recv_timeout(Duration::from_millis(20)) {
            Ok(result) => return result,
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                anyhow::bail!("temporary Nix root connection ended")
            }
        }
    }
}

fn register(input: &mut impl Write, output: &mut impl Read, roots: &[String]) -> Result<()> {
    // QueryValidPaths(lock=true, substitute=false) invokes addTempRoot for
    // every requested path even when it is not yet valid. The response lists
    // validity only; authentication is performed independently by admission.
    write_word(input, 1)?;
    write_word(input, 1)?;
    write_word(input, 0)?;
    write_word(input, roots.len() as u64)?;
    for root in roots {
        write_string(input, root)?;
    }
    input.flush()?;
    let count = usize::try_from(read_word(output)?)?;
    ensure!(
        count <= roots.len(),
        "Nix root response exceeds requested paths"
    );
    let mut returned = BTreeSet::new();
    for _ in 0..count {
        let path = read_string(output)?;
        ensure!(
            roots.contains(&path) && returned.insert(path),
            "Nix root response contains an unexpected path"
        );
    }
    Ok(())
}

fn write_word(output: &mut impl Write, value: u64) -> Result<()> {
    output.write_all(&value.to_le_bytes())?;
    Ok(())
}

fn read_word(input: &mut impl Read) -> Result<u64> {
    let mut bytes = [0_u8; 8];
    input.read_exact(&mut bytes)?;
    Ok(u64::from_le_bytes(bytes))
}

fn write_string(output: &mut impl Write, value: &str) -> Result<()> {
    write_word(output, value.len() as u64)?;
    output.write_all(value.as_bytes())?;
    output.write_all(&[0_u8; 7][..(8 - value.len() % 8) % 8])?;
    Ok(())
}

fn read_string(input: &mut impl Read) -> Result<String> {
    let length = usize::try_from(read_word(input)?)?;
    ensure!(
        length <= PATH_LIMIT,
        "Nix root response path exceeds its limit"
    );
    let mut bytes = vec![0_u8; length];
    input.read_exact(&mut bytes)?;
    let mut padding = [0_u8; 7];
    let padding = &mut padding[..(8 - length % 8) % 8];
    input.read_exact(padding)?;
    ensure!(
        padding.iter().all(|byte| *byte == 0),
        "Nix root response padding is not canonical"
    );
    String::from_utf8(bytes).context("Nix root response path is not UTF-8")
}

/// Computes an expected fixed-output path before importing its bytes.
pub(crate) fn fixed_path(
    executable: &Path,
    digest: aos_contract::Sha256Digest,
    name: &str,
    recursive: bool,
    cancellation: &CancellationToken,
) -> Result<std::path::PathBuf> {
    let mut command = super::verification::live_store_command(Some(executable))?;
    command.arg("--print-fixed-path");
    if recursive {
        command.arg("--recursive");
    }
    command.args(["sha256", &digest.to_string(), name]);
    let environment = command
        .get_envs()
        .filter_map(|(key, value)| value.map(|value| (key.to_owned(), value.to_owned())))
        .collect::<Vec<_>>();
    let output = crate::deployment::process::run_bounded(
        &mut command,
        None,
        64 * 1024,
        &crate::native_deployment::ImportControl(cancellation),
        &environment,
    )?;
    ensure!(
        output.status.success(),
        "computing fixed-output path failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let path = std::path::PathBuf::from(std::str::from_utf8(&output.stdout)?.trim());
    let (root, suffix) = crate::deployment::nix::store_root_and_suffix(&path)?;
    ensure!(
        root == path && suffix.as_os_str().is_empty(),
        "fixed-output locator is not canonical"
    );
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn root_registration_roots_invalid_paths_and_checks_server_response() {
        let root = format!("/nix/store/{}-future-output", "0".repeat(32));
        let mut response = Cursor::new(0_u64.to_le_bytes().to_vec());
        let mut request = Vec::new();

        register(&mut request, &mut response, &[root.clone()]).unwrap();

        let mut request = Cursor::new(request);
        assert_eq!(read_word(&mut request).unwrap(), 1);
        assert_eq!(read_word(&mut request).unwrap(), 1);
        assert_eq!(read_word(&mut request).unwrap(), 0);
        assert_eq!(read_word(&mut request).unwrap(), 1);
        assert_eq!(read_string(&mut request).unwrap(), root);
    }

    #[test]
    fn root_registration_rejects_forged_and_duplicate_response_members() {
        let requested = format!("/nix/store/{}-future-output", "0".repeat(32));
        let mut response = Vec::new();
        write_word(&mut response, 1).unwrap();
        write_string(
            &mut response,
            &format!("/nix/store/{}-other", "1".repeat(32)),
        )
        .unwrap();
        assert!(register(&mut Vec::new(), &mut Cursor::new(response), &[requested]).is_err());
    }

    #[test]
    fn root_exchange_honors_cancellation_before_waiting() {
        let (sender, receiver) = mpsc::channel();
        let cancellation = CancellationToken::default();
        cancellation.cancel();

        assert!(wait_exchange(receiver, &cancellation).is_err());
        drop(sender);
    }
}
