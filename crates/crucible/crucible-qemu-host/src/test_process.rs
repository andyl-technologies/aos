//! Isolates process-wide descriptor observations from concurrent launch fixtures.

use std::io;
use std::process::Command;

/// Runs one exact test in a fresh process, returning true only to its parent.
///
/// The child executes the unchanged assertions alone. A concurrent pre-exec
/// child in the parent test runner can otherwise retain a transient copy of a
/// socket and make its final-owner EOF observation depend on unrelated tests.
///
/// # Errors
/// Returns executable or process I/O errors, a child test failure, or an
/// exact-selector failure that did not execute one successful test.
pub(crate) fn run_isolated(module: &str, test: &str) -> Result<bool, io::Error> {
    const CHILD_TEST: &str = "CRUCIBLE_DESCRIPTOR_OBSERVATION_TEST";

    let module = module.split_once("::").map_or(module, |(_, module)| module);
    let name = format!("{module}::{test}");
    if std::env::var(CHILD_TEST).as_deref() == Ok(name.as_str()) {
        return Ok(false);
    }

    let output = Command::new(std::env::current_exe()?)
        .args(["--exact", &name, "--nocapture", "--test-threads=1"])
        .env(CHILD_TEST, &name)
        .output()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !output.status.success() || !stdout.contains("test result: ok. 1 passed; 0 failed;") {
        return Err(io::Error::other(format!(
            "isolated descriptor observation {name} failed: {}\n{stdout}\n{stderr}",
            output.status
        )));
    }

    Ok(true)
}
