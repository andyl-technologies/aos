//! Bounded live-store NAR identity and reference verification.
//!
//! Consumers compare authenticated catalogs with realized store contents before
//! rooting or executing artifacts. Streaming hashes bound memory independently
//! of payload size; all subprocesses have fixed deadlines and bounded errors.

use std::io::Read;
use std::path::{Component, Path};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use aos_contract::Sha256Digest;
use aos_core::nix::configure_aos_nix_store;

const STORE_VERIFY_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const STORE_VERIFY_ERROR_LIMIT: u64 = 64 * 1024;
const STORE_VERIFY_OUTPUT_LIMIT: u64 = 16 * 1024 * 1024;

pub(crate) fn dump_store_path_identity(store_path: &str) -> anyhow::Result<(Sha256Digest, u64)> {
    dump_store_path_identity_in(store_path, None)
}

pub(crate) fn verify_store_object_in(
    store_path: &str,
    expected_hash: Sha256Digest,
    expected_size: u64,
    expected_references: &[String],
    executable: Option<&Path>,
) -> anyhow::Result<()> {
    use anyhow::{Context as _, ensure};

    let (root, suffix) = crate::deployment::nix::store_root_and_suffix(Path::new(store_path))
        .context("retention member does not name a canonical Nix store path")?;
    ensure!(
        suffix.as_os_str().is_empty(),
        "retention member is not a store root"
    );
    ensure!(
        root.as_os_str() == std::ffi::OsStr::new(store_path),
        "retention member path is not canonical"
    );
    run_store_check_in(store_path, &["--check-validity"], executable)?;

    let (actual_hash, actual_size) = dump_store_path_identity_in(store_path, executable)?;
    ensure!(
        actual_hash == expected_hash,
        "store object {store_path} NAR mismatch: expected {expected_hash}, observed {actual_hash}"
    );
    ensure!(
        actual_size == expected_size,
        "store object {store_path} NAR size mismatch: expected {expected_size}, observed {actual_size}"
    );

    let actual_references = query_reference_hashes_in(store_path, executable)?;
    ensure!(
        actual_references == expected_references,
        "store object {store_path} direct references differ from its authenticated catalog"
    );
    Ok(())
}

fn run_store_check_in(
    store_path: &str,
    arguments: &[&str],
    executable: Option<&Path>,
) -> anyhow::Result<()> {
    use anyhow::{Context as _, bail};

    let status = live_store_command(executable)?
        .args(arguments)
        .arg(store_path)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("starting nix-store {} {store_path}", arguments.join(" ")))?;
    let (status, stderr) = wait_for_store_command(status)?;
    if !status.success() {
        bail!(
            "nix-store {} {store_path} failed: {}",
            arguments.join(" "),
            String::from_utf8_lossy(&stderr).trim()
        );
    }
    Ok(())
}

pub(crate) fn query_store_paths_in(
    arguments: &[&str],
    store_path: &str,
    executable: Option<&Path>,
) -> anyhow::Result<Vec<String>> {
    use anyhow::{Context as _, ensure};

    let mut paths = run_store_query(store_path, arguments, executable)?
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect::<Vec<_>>();
    for path in &paths {
        let (root, suffix) = crate::deployment::nix::store_root_and_suffix(Path::new(path))
            .with_context(|| format!("nix-store returned malformed path {path:?}"))?;
        ensure!(
            suffix.as_os_str().is_empty(),
            "nix-store returned a path suffix"
        );
        ensure!(
            root.as_os_str() == std::ffi::OsStr::new(path),
            "nix-store returned a noncanonical path"
        );
    }
    paths.sort();
    let original_len = paths.len();
    paths.dedup();
    ensure!(
        paths.len() == original_len,
        "nix-store returned a duplicate store path"
    );
    Ok(paths)
}

pub(crate) fn query_reference_hashes_in(
    store_path: &str,
    executable: Option<&Path>,
) -> anyhow::Result<Vec<String>> {
    use anyhow::Context as _;

    let references = query_store_paths_in(&["--query", "--references"], store_path, executable)?;
    references
        .into_iter()
        .filter(|reference| reference != store_path)
        .map(|reference| {
            let name = Path::new(&reference)
                .file_name()
                .and_then(|name| name.to_str())
                .with_context(|| {
                    format!("store reference has no UTF-8 object name: {reference}")
                })?;
            let hash = name
                .get(..32)
                .context("validated store reference has no 32-byte hash prefix")?;
            Ok(hash.to_string())
        })
        .collect()
}

fn run_store_query(
    store_path: &str,
    arguments: &[&str],
    executable: Option<&Path>,
) -> anyhow::Result<String> {
    use anyhow::{Context as _, bail};

    let mut child = live_store_command(executable)?
        .args(arguments)
        .arg(store_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("starting nix-store {} {store_path}", arguments.join(" ")))?;
    let Some(stdout) = child.stdout.take() else {
        terminate_and_reap(&mut child);
        bail!("nix-store query stdout was not piped");
    };
    let output = thread::spawn(move || read_bounded(stdout, STORE_VERIFY_OUTPUT_LIMIT));
    let process_result = wait_for_store_command(child);
    let output_result = output
        .join()
        .map_err(|_| anyhow::anyhow!("nix-store stdout worker panicked"))?;
    let (status, stderr) = process_result?;
    let output = output_result?;
    if !status.success() {
        bail!(
            "nix-store {} {store_path} failed: {}",
            arguments.join(" "),
            String::from_utf8_lossy(&stderr).trim()
        );
    }
    String::from_utf8(output).context("nix-store query output is not UTF-8")
}

pub(crate) fn dump_store_path_identity_in(
    store_path: &str,
    executable: Option<&Path>,
) -> anyhow::Result<(Sha256Digest, u64)> {
    let selected = live_store_command(executable)?;
    let tool = Path::new(selected.get_program());
    let tool = if tool.is_absolute() {
        tool.to_owned()
    } else {
        std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
            .map(|directory| directory.join(tool))
            .find(|candidate| candidate.is_file())
            .ok_or_else(|| anyhow::anyhow!("selected Nix store executable is unavailable"))?
    };
    let mut command = aos_core::nix::identity::store_nar_command(&tool, store_path)?;
    for (key, value) in selected.get_envs() {
        match value {
            Some(value) => {
                command.env(key, value);
            }
            None => {
                command.env_remove(key);
            }
        }
    }
    aos_core::nix::identity::hash_nar_command(command, STORE_VERIFY_TIMEOUT)
}

pub(crate) fn live_store_command(executable: Option<&Path>) -> anyhow::Result<Command> {
    let configured = executable
        .map(|path| path.as_os_str().to_owned())
        .or_else(|| std::env::var_os("AOS_NIX_STORE"));
    let executable = match configured {
        Some(executable) => {
            let path = Path::new(&executable);
            if !path.is_absolute()
                || path
                    .components()
                    .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
            {
                anyhow::bail!("AOS_NIX_STORE must name a canonical absolute executable path");
            }
            executable
        }
        None => "nix-store".into(),
    };
    let mut command = Command::new(executable);
    configure_aos_nix_store(&mut command)?;

    // The hermetic package test seeds a private Nix database from Nix's own
    // realized reference graph. Scope that database to this verifier's child
    // processes so parallel tests cannot change process-global store routing.
    #[cfg(test)]
    for (source, target) in [
        ("AOS_TEST_ABILITY_NIX_STORE_DIR", "NIX_STORE_DIR"),
        ("AOS_TEST_ABILITY_NIX_STATE_DIR", "NIX_STATE_DIR"),
        ("AOS_TEST_ABILITY_NIX_LOG_DIR", "NIX_LOG_DIR"),
        ("AOS_TEST_ABILITY_NIX_REMOTE", "NIX_REMOTE"),
    ] {
        if let Some(value) = std::env::var_os(source) {
            command.env(target, value);
        }
    }

    Ok(command)
}

#[allow(
    clippy::disallowed_methods,
    reason = "nix-store subprocess deadlines use host monotonic time outside replayable ability state"
)]
fn wait_for_store_command(
    mut child: std::process::Child,
) -> anyhow::Result<(std::process::ExitStatus, Vec<u8>)> {
    use anyhow::Context as _;

    let Some(stderr) = child.stderr.take() else {
        terminate_and_reap(&mut child);
        anyhow::bail!("nix-store stderr was not piped");
    };
    let stderr = thread::spawn(move || read_bounded(stderr, STORE_VERIFY_ERROR_LIMIT));
    let deadline = Instant::now() + STORE_VERIFY_TIMEOUT;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Ok(status),
            Ok(None) if Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(20));
            }
            Ok(None) => {
                break Err(anyhow::anyhow!(
                    "nix-store verification exceeded {} seconds",
                    STORE_VERIFY_TIMEOUT.as_secs()
                ));
            }
            Err(source) => break Err(source).context("polling nix-store"),
        }
    };
    if status.is_err() {
        // Dropping Child does not terminate or reap it. Close the process before
        // joining readers so every error path retains subprocess ownership.
        terminate_and_reap(&mut child);
    }
    let stderr_result = stderr
        .join()
        .map_err(|_| anyhow::anyhow!("nix-store stderr worker panicked"))?;
    let status = status?;
    let mut stderr = stderr_result?;
    if stderr.len() > STORE_VERIFY_ERROR_LIMIT as usize {
        stderr.truncate(STORE_VERIFY_ERROR_LIMIT as usize);
    }
    Ok((status, stderr))
}

fn read_bounded(mut reader: impl Read, limit: u64) -> Result<Vec<u8>, std::io::Error> {
    let capacity = usize::try_from(limit).unwrap_or(usize::MAX);
    let mut retained = Vec::with_capacity(capacity.min(64 * 1024));
    let mut total = 0_u64;
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        total = total.saturating_add(count as u64);
        if retained.len() < capacity {
            let remaining = capacity - retained.len();
            retained.extend_from_slice(&buffer[..count.min(remaining)]);
        }
    }
    if total > limit {
        return Err(std::io::Error::other(format!(
            "subprocess output exceeds {limit} bytes"
        )));
    }
    Ok(retained)
}

fn terminate_and_reap(child: &mut std::process::Child) {
    let _ = child.kill();
    let _ = child.wait();
}
