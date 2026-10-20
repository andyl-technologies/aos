//! Protected actual body files with exact commitments and bounded consumption.

use std::{fs::File, io::Read as _, os::unix::fs::MetadataExt as _, path::Path};

use anyhow::{ensure, Result};
use rustix::fs::{open, Mode, OFlags};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};

const MAX_BODY_BYTES: usize = 8 * 1024 * 1024;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct BodyFile {
    pub(super) file: String,
    pub(super) sha256: String,
    pub(super) byte_size: String,
}

pub(super) fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub(super) fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(super) fn read(reference: &BodyFile, consumed: &mut usize) -> Result<Vec<u8>> {
    ensure!(valid_digest(&reference.sha256), "invalid body digest");
    let expected = reference.byte_size.parse::<usize>()?;
    ensure!(
        expected.to_string() == reference.byte_size,
        "noncanonical size"
    );
    ensure!(expected <= MAX_BODY_BYTES, "body exceeds capture bound");
    *consumed = consumed
        .checked_add(expected)
        .ok_or_else(|| anyhow::anyhow!("size overflow"))?;
    ensure!(
        *consumed <= super::MAX_CORPUS_BYTES,
        "excessive selected corpus"
    );
    let bytes = protected_read(Path::new(&reference.file), MAX_BODY_BYTES)?;
    ensure!(
        bytes.len() == expected && digest(&bytes) == reference.sha256,
        "body differs"
    );
    Ok(bytes)
}

pub(super) fn read_manifest(path: &Path) -> Result<Vec<u8>> {
    protected_read(path, 1024 * 1024)
}

fn protected_read(path: &Path, maximum: usize) -> Result<Vec<u8>> {
    let descriptor = open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )?;
    let mut file = File::from(descriptor);
    let before = file.metadata()?;
    ensure!(
        before.is_file()
            && before.uid() == rustix::process::getuid().as_raw()
            && before.mode() & 0o077 == 0
            && before.len() <= maximum as u64,
        "body custody or bound differs"
    );
    let mut bytes = Vec::with_capacity(usize::try_from(before.len())?);
    (&mut file)
        .take((maximum + 1) as u64)
        .read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    ensure!(
        bytes.len() <= maximum
            && bytes.len() as u64 == before.len()
            && before.dev() == after.dev()
            && before.ino() == after.ino()
            && before.len() == after.len()
            && before.mtime() == after.mtime()
            && before.mtime_nsec() == after.mtime_nsec()
            && before.ctime() == after.ctime()
            && before.ctime_nsec() == after.ctime_nsec(),
        "body changed during observation"
    );
    Ok(bytes)
}
