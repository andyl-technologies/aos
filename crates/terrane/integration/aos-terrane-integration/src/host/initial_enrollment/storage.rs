//! Publishes bounded protected enrollment ledgers with file and parent durability.

use super::super::{HostConfig, parse_error, protected_text};
use super::{InitialLedger, model::MAX_BYTES, validation};
use std::{
    fs::{self, OpenOptions},
    io::{self, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};
use terrane_linux::host_quota::open_host_path;

pub(super) fn encode(ledger: &InitialLedger, config: &HostConfig) -> io::Result<String> {
    validation::validate(ledger, config)?;
    let text = toml::to_string(ledger).map_err(parse_error)?;
    if text.len() > MAX_BYTES {
        return Err(io::Error::other(
            "complete initial ledger exceeds its encoded bound",
        ));
    }
    Ok(text)
}

pub(super) fn read(path: &Path, config: &HostConfig) -> io::Result<InitialLedger> {
    let ledger = toml::from_str(&protected_text(path)?).map_err(parse_error)?;
    validation::validate(&ledger, config)?;
    Ok(ledger)
}

pub(super) fn persist(
    path: &Path,
    ledger: &InitialLedger,
    config: &HostConfig,
    first: bool,
) -> io::Result<()> {
    let text = encode(ledger, config)?;
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::other("initial ledger has no parent"))?;
    let directory = open_host_path(parent, true)?;
    let metadata = directory.metadata()?;
    if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err(io::Error::other("initial ledger parent is not protected"));
    }
    static SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let sequence = SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let temporary = parent.join(format!(
        ".terrane-initial-ledger-{}-{sequence}",
        std::process::id()
    ));
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)?;
    // The first ledger never replaces another administrative history. Later
    // publication changes only the phase while both administrative locks remain held.
    let result = (|| {
        output.write_all(text.as_bytes())?;
        output.sync_all()?;
        if first {
            fs::hard_link(&temporary, path)?;
            directory.sync_all()?;
            fs::remove_file(&temporary)?;
        } else {
            fs::rename(&temporary, path)?;
        }
        directory.sync_all()
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}
