//! Queries complete store closures through the selected source-built Nix tool.

use std::collections::BTreeSet;
use std::io::Read;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use anyhow::{Context, Result, ensure};

const CLOSURE_BYTES: u64 = 32 * 1024 * 1024;

pub(crate) fn closure_paths(
    command: &mut Command,
    roots: &BTreeSet<PathBuf>,
) -> Result<BTreeSet<PathBuf>> {
    let mut child = command
        .args(["--query", "--requisites"])
        .args(roots)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()?;
    let mut bytes = Vec::new();
    let read = child
        .stdout
        .take()
        .context("closure query has no stdout")?
        .take(CLOSURE_BYTES + 1)
        .read_to_end(&mut bytes);
    if read.is_err() || bytes.len() as u64 > CLOSURE_BYTES {
        let _ = child.kill();
        let _ = child.wait();
        read?;
        anyhow::bail!("store closure exceeds its bounded inventory");
    }
    ensure!(
        child.wait()?.success(),
        "selected store closure query failed"
    );
    let mut paths = BTreeSet::new();
    for line in std::str::from_utf8(&bytes)?.lines() {
        aos_release::artifact::require_store_path(line, line.ends_with(".drv"))?;
        let root = PathBuf::from(line);
        paths.insert(root);
    }
    ensure!(
        roots.is_subset(&paths),
        "closure query omitted an admitted root"
    );
    Ok(paths)
}
