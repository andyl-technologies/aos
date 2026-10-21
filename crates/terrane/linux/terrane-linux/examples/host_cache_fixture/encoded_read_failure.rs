//! Exercises retained encoded read denial and exact original quarantine.

use super::config::Inputs;
use std::{
    fs,
    io::{self, BufRead, Write},
    time::UNIX_EPOCH,
};
use terrane_format::identity::{Descriptor, IdentityKind, TERRANE_V1};
use terrane_linux::host_cache::NativeMetadataOwner;
use terrane_sdk::store::{ChunkPosition, Clock, TokioClock};

/// Exercises native corruption through independent actual consumer grants.
///
/// # Errors
/// Refuses invalid setup, revived aliases, changed funding or missing quarantine.
pub(super) fn run(
    owner: &NativeMetadataOwner,
    runtime: &tokio::runtime::Runtime,
    inputs: &Inputs,
    original: Option<Vec<u8>>,
) -> io::Result<()> {
    if inputs.domain != "tenant:encoded-read-failure" || original.is_some() {
        return Err(invalid("encoded failure requires a fresh dedicated domain"));
    }
    let completed = runtime.block_on(owner.recover())?;
    runtime
        .block_on(owner.resume_recovered(completed))
        .map_err(io::Error::other)?;

    let plaintext = b"original encoded consumer custody";
    let identity = TERRANE_V1
        .calculate(IdentityKind::Chunk, plaintext)
        .map_err(io::Error::other)?;
    let descriptor =
        Descriptor::from_identity(&TERRANE_V1, &identity, plaintext).map_err(io::Error::other)?;
    let encoded = [vec![0], plaintext.to_vec()].concat();
    let admission = runtime
        .block_on(owner.admit_chunk(descriptor, ChunkPosition::Final, encoded))
        .map_err(io::Error::other)?;
    runtime
        .block_on(admission.into_cache(owner))
        .map_err(io::Error::other)?;
    let expires = TokioClock
        .now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_secs()
        .checked_add(90)
        .ok_or_else(|| invalid("encoded failure deadline overflow"))?;
    let first = runtime.block_on(owner.pin_resident_chunk(identity.clone(), expires))?;
    let alias = runtime.block_on(owner.pin_resident_chunk(identity, expires))?;
    if first.read_verified()? != plaintext || alias.read_verified()? != plaintext {
        return Err(invalid("encoded failure lacks genuine verified consumers"));
    }
    let policy = inputs.root.join("state/cache/records.toml");
    let records = fs::read(&policy)?;
    let stalled = runtime.block_on(owner.stall_policy_for_fixture())?;
    emit("READY genuine encoded consumers verified with physical policy held")?;
    control("damaged")?;
    if first.read_verified().is_ok() || fs::read(&policy)? != records {
        return Err(invalid(
            "damaged encoded original served or funding changed",
        ));
    }
    emit("READY original encoded failure latched before restoring bytes")?;
    control("restored")?;
    if alias.read_verified().is_ok()
        || alias.read_encoded().is_ok()
        || first.read_verified().is_ok()
    {
        return Err(invalid("restored bytes revived original encoded aliases"));
    }
    drop(stalled);
    if runtime.block_on(owner.sweep_consumer_leases()).is_ok() || fs::read(&policy)? != records {
        return Err(invalid("encoded failed read released original funding"));
    }
    emit("READY actual encoded failed-read quarantine completed with original funding retained")?;
    control("finish")?;
    emit(
        "PASS actual encoded read failure denies all original consumer aliases after byte restoration and quarantines original inode without funding release",
    )
}

fn control(expected: &str) -> io::Result<()> {
    let mut line = String::new();
    io::stdin().lock().read_line(&mut line)?;
    if line.trim_end() != expected {
        return Err(invalid("unexpected encoded failure control"));
    }
    Ok(())
}

fn emit(message: &str) -> io::Result<()> {
    let mut output = io::stdout().lock();
    writeln!(output, "{message}")?;
    output.flush()
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::other(message)
}
