//! Process-level checks for `crucible serve`.

// crucible-lint: allow clippy-disallowed-method -- process-level boundary test intentionally exercises host methods.
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::disallowed_methods, clippy::expect_used, clippy::unwrap_used)]

use std::error::Error;
use std::io::{BufRead, BufReader};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc as std_mpsc;
use std::thread;
use std::time::{Duration, Instant};

use crucible_api::{
    ControlClient, HelloRequest, RPC_PROTOCOL_VERSION, RpcControlClient, RpcEndpoint,
};

#[tokio::test(flavor = "current_thread")]
async fn serve_process_exits_zero_on_sigterm() -> Result<(), Box<dyn Error>> {
    let child = Command::new(env!("CARGO_BIN_EXE_crucible"))
        .args([
            "serve",
            "--listen",
            "127.0.0.1:0",
            "--trusted-unauthenticated-bind",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut child = ChildGuard::new(child);

    let stdout = child
        .inner_mut()
        .stdout
        .take()
        .ok_or("serve child stdout should be piped")?;
    let line = read_first_stdout_line(stdout, Duration::from_secs(5))?;
    let endpoint = parse_serve_endpoint(&line)?;

    let rpc = RpcControlClient::new(RpcEndpoint::http2(endpoint))?;
    let hello = rpc
        .hello(HelloRequest::new(
            "crucible-cli-serve-process-test",
            RPC_PROTOCOL_VERSION,
        ))
        .await?;
    assert_eq!(hello.server_name, "crucible-cli-daemon");

    send_sigterm(child.inner())?;
    let status = wait_for_exit(child.inner_mut(), Duration::from_secs(5))?;
    child.disarm();
    assert!(
        status.success(),
        "serve should exit 0 after SIGTERM, got {status:?}",
    );

    Ok(())
}

struct ChildGuard {
    child: Child,
    kill_on_drop: bool,
}

impl ChildGuard {
    fn new(child: Child) -> Self {
        Self {
            child,
            kill_on_drop: true,
        }
    }

    fn inner(&self) -> &Child {
        &self.child
    }

    fn inner_mut(&mut self) -> &mut Child {
        &mut self.child
    }

    fn disarm(&mut self) {
        self.kill_on_drop = false;
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if self.kill_on_drop {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

fn read_first_stdout_line(
    stdout: impl std::io::Read + Send + 'static,
    timeout: Duration,
) -> Result<String, Box<dyn Error>> {
    let (sender, receiver) = std_mpsc::channel();
    thread::spawn(move || {
        let mut stdout = BufReader::new(stdout);
        let mut line = String::new();
        let result = stdout.read_line(&mut line).map(|_| line);
        let _ = sender.send(result);
    });
    match receiver.recv_timeout(timeout) {
        Ok(Ok(line)) if !line.is_empty() => Ok(line),
        Ok(Ok(_)) => Err("serve child exited before writing its listener announcement".into()),
        Ok(Err(error)) => Err(Box::new(error)),
        Err(std_mpsc::RecvTimeoutError::Timeout) => {
            Err("serve child did not announce its listener before timeout".into())
        }
        Err(std_mpsc::RecvTimeoutError::Disconnected) => {
            Err("serve stdout reader exited without sending a result".into())
        }
    }
}

fn parse_serve_endpoint(line: &str) -> Result<String, Box<dyn Error>> {
    let endpoint = line
        .split_whitespace()
        .find(|part| part.starts_with("http://"))
        .ok_or("serve announcement should include http endpoint")?;
    Ok(endpoint.to_owned())
}

fn send_sigterm(child: &Child) -> Result<(), Box<dyn Error>> {
    let pid = i32::try_from(child.id())?;
    // SAFETY: `pid` is the live child process id returned by `std::process::Child`.
    // Sending SIGTERM does not dereference memory and reports failure via errno.
    let rc = unsafe { libc::kill(pid, libc::SIGTERM) };
    if rc == 0 {
        Ok(())
    } else {
        Err(Box::new(std::io::Error::last_os_error()))
    }
}

fn wait_for_exit(child: &mut Child, timeout: Duration) -> Result<ExitStatus, Box<dyn Error>> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err("serve process did not exit before timeout".into());
        }
        thread::sleep(Duration::from_millis(10));
    }
}
