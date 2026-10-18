//! Bounded subprocess execution for the selected `nix-store` artifact.

use std::collections::BTreeMap;
use std::io::{self, Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

use anyhow::{Context as _, Result, bail, ensure};

use crate::artifact::ArtifactStoreCommands;
use crate::handler::{
    Executable, RegistrationRecord, StoreCommands, deadline, monotonic_now, parse_registration,
    remaining,
};

const MAX_COMMAND_OUTPUT_BYTES: u64 = 64 * 1024 * 1024;
const MAX_ARGUMENT_BYTES: usize = 96 * 1024;
const MAX_ARGUMENTS_PER_COMMAND: usize = 512;
const PROCESS_POLL_INTERVAL: Duration = Duration::from_millis(5);

pub(super) struct ProcessStoreCommands;

impl StoreCommands for ProcessStoreCommands {
    fn probe(&self, executable: &Executable, remaining_millis: u64) -> Result<()> {
        run_command(
            executable,
            &["--check-validity", "--print-invalid"],
            &[],
            remaining_millis,
        )?;
        Ok(())
    }

    fn records_match(
        &self,
        executable: &Executable,
        expected: &BTreeMap<String, RegistrationRecord>,
        remaining_millis: u64,
    ) -> Result<bool> {
        let deadline = deadline(remaining_millis)?;
        for paths in argument_batches(expected.keys().map(String::as_str)) {
            let mut validity_arguments = vec!["--check-validity", "--print-invalid"];
            validity_arguments.extend(paths.iter().copied());
            let invalid = run_command(executable, &validity_arguments, &[], remaining(deadline)?)?;
            if !invalid.is_empty() {
                return Ok(false);
            }

            let mut dump_arguments = vec!["--dump-db"];
            dump_arguments.extend(paths.iter().copied());
            let current = run_command(executable, &dump_arguments, &[], remaining(deadline)?)?;
            let current = parse_registration(&current)?;
            for path in paths {
                if current.get(path) != expected.get(path) {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }

    fn initialize(&self, executable: &Executable, remaining_millis: u64) -> Result<()> {
        run_command(executable, &["--init"], &[], remaining_millis)?;
        Ok(())
    }

    fn load(
        &self,
        executable: &Executable,
        registration: &[u8],
        remaining_millis: u64,
    ) -> Result<()> {
        run_command(executable, &["--load-db"], registration, remaining_millis)?;
        Ok(())
    }
}

impl ArtifactStoreCommands for ProcessStoreCommands {
    fn add_fixed(
        &self,
        executable: &Path,
        source: &Path,
        remaining_millis: u64,
    ) -> Result<PathBuf> {
        let source = source
            .to_str()
            .context("transaction blob input path is not UTF-8")?;
        let output = run_path_command(
            executable,
            &["--add-fixed", "sha256", source],
            &[],
            remaining_millis,
        )?;
        parse_one_path(&output, "added fixed-output store path")
    }

    fn dump(&self, executable: &Path, store_path: &Path, remaining_millis: u64) -> Result<Vec<u8>> {
        let store_path = store_path
            .to_str()
            .context("content-addressed store path is not UTF-8")?;
        run_path_command(executable, &["--dump", store_path], &[], remaining_millis)
    }

    fn references(
        &self,
        executable: &Path,
        store_path: &Path,
        remaining_millis: u64,
    ) -> Result<Vec<PathBuf>> {
        let store_path = store_path
            .to_str()
            .context("content-addressed store path is not UTF-8")?;
        let output = run_path_command(
            executable,
            &["--query", "--references", store_path],
            &[],
            remaining_millis,
        )?;
        let text = std::str::from_utf8(&output).context("Nix reference output is not UTF-8")?;
        ensure!(
            text.is_empty() || text.ends_with('\n'),
            "Nix reference output has a truncated final line"
        );
        Ok(text.lines().map(PathBuf::from).collect())
    }

    fn is_valid(
        &self,
        executable: &Path,
        store_path: &Path,
        remaining_millis: u64,
    ) -> Result<bool> {
        let store_path = store_path
            .to_str()
            .context("content-addressed store path is not UTF-8")?;
        let invalid = run_path_command(
            executable,
            &["--check-validity", "--print-invalid", store_path],
            &[],
            remaining_millis,
        )?;
        Ok(invalid.is_empty())
    }
}

fn run_command(
    executable: &Executable,
    arguments: &[&str],
    input: &[u8],
    remaining_millis: u64,
) -> Result<Vec<u8>> {
    run_path_command(&executable.path(), arguments, input, remaining_millis)
}

fn run_path_command(
    executable: &Path,
    arguments: &[&str],
    input: &[u8],
    remaining_millis: u64,
) -> Result<Vec<u8>> {
    ensure!(remaining_millis > 0, "Nix store command deadline expired");
    let mut child = Command::new(executable)
        .args(arguments)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("starting bundled Nix store executable")?;
    collect_child(&mut child, input, remaining_millis)
}

fn collect_child(
    child: &mut std::process::Child,
    input: &[u8],
    remaining_millis: u64,
) -> Result<Vec<u8>> {
    let mut stdin = child.stdin.take().context("capturing Nix store stdin")?;
    let mut stdout = child.stdout.take().context("capturing Nix store stdout")?;
    let mut stderr = child.stderr.take().context("capturing Nix store stderr")?;
    let input = input.to_vec();
    let input_thread = thread::spawn(move || -> io::Result<()> {
        stdin.write_all(&input)?;
        drop(stdin);
        Ok(())
    });
    let stdout_thread = thread::spawn(move || read_bounded(&mut stdout));
    let stderr_thread = thread::spawn(move || read_bounded(&mut stderr));
    let deadline = deadline(remaining_millis)?;

    let status = loop {
        if let Some(status) = child.try_wait().context("waiting for Nix store command")? {
            break status;
        }
        if monotonic_now() >= deadline {
            child
                .kill()
                .context("terminating expired Nix store command")?;
            let _ = child.wait();
            bail!("Nix store command exceeded its attempt deadline");
        }
        thread::sleep(PROCESS_POLL_INTERVAL);
    };
    input_thread
        .join()
        .map_err(|_| anyhow::anyhow!("Nix store stdin writer panicked"))?
        .context("writing Nix store command input")?;
    let stdout = join_reader(stdout_thread, "stdout")?;
    let stderr = join_reader(stderr_thread, "stderr")?;
    ensure!(
        status.success(),
        "Nix store command failed with {status}: {}",
        String::from_utf8_lossy(&stderr)
    );
    Ok(stdout)
}

fn parse_one_path(output: &[u8], label: &str) -> Result<PathBuf> {
    let text = std::str::from_utf8(output).with_context(|| format!("{label} is not UTF-8"))?;
    let mut lines = text.lines();
    let path = lines.next().with_context(|| format!("{label} is empty"))?;
    ensure!(lines.next().is_none(), "{label} contains multiple paths");
    Ok(PathBuf::from(path))
}

fn read_bounded(reader: &mut impl io::Read) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_COMMAND_OUTPUT_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_COMMAND_OUTPUT_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Nix store command output exceeds its bound",
        ));
    }
    Ok(bytes)
}

fn join_reader(reader: thread::JoinHandle<io::Result<Vec<u8>>>, stream: &str) -> Result<Vec<u8>> {
    reader
        .join()
        .map_err(|_| anyhow::anyhow!("Nix store {stream} reader panicked"))?
        .with_context(|| format!("reading bounded Nix store {stream}"))
}

pub(super) fn argument_batches<'a>(paths: impl IntoIterator<Item = &'a str>) -> Vec<Vec<&'a str>> {
    let mut batches = Vec::new();
    let mut current = Vec::new();
    let mut bytes: usize = 0;
    for path in paths {
        if !current.is_empty()
            && (current.len() >= MAX_ARGUMENTS_PER_COMMAND
                || bytes.saturating_add(path.len() + 1) > MAX_ARGUMENT_BYTES)
        {
            batches.push(std::mem::take(&mut current));
            bytes = 0;
        }
        current.push(path);
        bytes = bytes.saturating_add(path.len() + 1);
    }
    if !current.is_empty() {
        batches.push(current);
    }
    batches
}
