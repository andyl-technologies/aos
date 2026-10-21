//! Checks cold quarantine accounting without treating opaque bytes as content.

use super::{IdentityKind, Inputs, NativeMetadataOwner, STATE, TERRANE_V1, invalid};
use std::{fs, io, os::unix::fs::MetadataExt, time::UNIX_EPOCH};
use terrane_sdk::{
    host::cache::CacheState,
    store::{Clock, TokioClock, TokioLocalFs},
};

const ORIGINAL: &[u8] = b"expected original quarantine plaintext";
const CORRUPT: &[u8] = b"damaged retained quarantine plaintext";

fn name() -> io::Result<String> {
    Ok(TERRANE_V1
        .calculate(IdentityKind::Chunk, ORIGINAL)
        .map_err(io::Error::other)?
        .digest()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

/// Seeds untrusted original quarantine candidates before native roles start.
///
/// # Errors
/// Refuses unsupported domains, failed project inheritance or native durability.
pub(crate) fn seed() -> io::Result<()> {
    let inputs = Inputs::load()?;
    let (filename, uid) = match inputs.domain.as_str() {
        "tenant:quarantine-only" => (name()?, 841),
        "tenant:quarantine-unknown" => ("unrecognized-name".to_owned(), 841),
        "tenant:quarantine-foreign" => (name()?, 842),
        _ => return Err(invalid("unknown quarantine seed domain")),
    };
    super::write(
        &inputs,
        &inputs.root.join("quarantine").join(filename),
        CORRUPT,
        uid,
        uid,
        0o600,
    )?;
    fs::File::open(inputs.root.join("quarantine"))?.sync_all()?;
    println!("SEEDED opaque quarantine candidate; no content or recovery authority");
    Ok(())
}

/// Reconciles actual opaque custody or refuses unsupported original candidates.
///
/// # Errors
/// Refuses lost original bytes, allocation or project custody, any valid-content
/// claim over quarantine, missing genuine Resume or changed rejected policy.
pub(crate) fn run(
    mode: &str,
    owner: &NativeMetadataOwner,
    runtime: &tokio::runtime::Runtime,
    inputs: &Inputs,
    original: Option<Vec<u8>>,
) -> io::Result<()> {
    if original.is_some() {
        return Err(invalid(
            "quarantine fixture must begin without decoded policy",
        ));
    }
    let policy = inputs.root.join("state/cache/records.toml");
    let result = runtime.block_on(owner.recover());
    if mode == "refuse-quarantine" {
        let error = result
            .err()
            .ok_or_else(|| invalid("unsafe quarantine completed recovery"))?;
        if policy.exists() {
            return Err(invalid(
                "unsafe quarantine created a funded recovery snapshot",
            ));
        }
        println!("PASS unsafe original quarantine refused before funding or Resume: {error}");
        return Ok(());
    }
    let completed = result?;
    completed.check_current()?;
    let path = inputs.root.join("quarantine").join(name()?);
    let before = fs::metadata(&path)?;
    let allocation = before
        .blocks()
        .checked_mul(512)
        .ok_or_else(|| invalid("quarantine allocation overflow"))?;
    if allocation == 0
        || completed.synchronized_quarantined_inode_bytes() != allocation
        || completed.synchronized_quarantined_inodes() != 1
        || completed.synchronized_retained_inode_bytes() < allocation
        || completed.charged_reserved_bytes() < allocation
    {
        return Err(invalid(
            "quarantine inode omitted from synchronized allocation",
        ));
    }
    let state = runtime
        .block_on(CacheState::load(
            &TokioLocalFs,
            &inputs.root.join("state/cache"),
            STATE,
        ))
        .map_err(io::Error::other)?
        .ok_or_else(|| invalid("completed recovery omitted durable policy"))?;
    if !state.pins.is_empty() || !state.leases.is_empty() || !state.residences.is_empty() {
        return Err(invalid("opaque quarantine bytes became verified backing"));
    }
    runtime
        .block_on(owner.resume_recovered(completed))
        .map_err(io::Error::other)?;
    let identity = TERRANE_V1
        .calculate(IdentityKind::Chunk, ORIGINAL)
        .map_err(io::Error::other)?;
    let expires = TokioClock
        .now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_secs()
        .checked_add(30)
        .ok_or_else(|| invalid("consumer expiry overflow"))?;
    let error = runtime
        .block_on(owner.pin_resident_chunk(identity, expires))
        .err()
        .ok_or_else(|| invalid("quarantine supplied a consumer source"))?;
    if error.kind() != io::ErrorKind::NotFound || fs::metadata(&path)?.ino() != before.ino() {
        return Err(invalid(
            "quarantine was served or lost original native custody",
        ));
    }
    println!(
        "PASS actual cold quarantine retained charged original inode across recovery and Resume without content, pins or residences"
    );
    Ok(())
}
