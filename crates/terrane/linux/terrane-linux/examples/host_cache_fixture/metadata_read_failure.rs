//! Exercises independent metadata consumers over a genuine admitted native pair.

use super::{admission, config::Inputs};
use std::{
    fs,
    io::{self, BufRead, Write},
    time::UNIX_EPOCH,
};
use terrane_format::identity::{IdentityKind, TERRANE_V1};
use terrane_linux::host_cache::NativeMetadataOwner;
use terrane_sdk::{
    pack::PackReader,
    store::{Clock, TokioClock},
};

/// Checks permanent alias denial and retained funding after actual pair damage.
///
/// # Errors
/// Refuses invalid setup, revived aliases or any unexpected physical outcome.
pub(super) fn run(
    owner: &NativeMetadataOwner,
    runtime: &tokio::runtime::Runtime,
    inputs: &Inputs,
    original: Option<Vec<u8>>,
) -> io::Result<()> {
    if !matches!(
        inputs.domain.as_str(),
        "tenant:metadata-pack-read-failure" | "tenant:metadata-index-read-failure"
    ) || original.is_some()
    {
        return Err(invalid(
            "metadata failure requires a fresh dedicated domain",
        ));
    }
    let completed = runtime.block_on(owner.recover())?;
    runtime
        .block_on(owner.resume_recovered(completed))
        .map_err(io::Error::other)?;
    let pair = admission::metadata_pair()?;
    let reader = PackReader::open(&pair.pack).map_err(io::Error::other)?;
    let entry = reader
        .entries()
        .first()
        .ok_or_else(|| invalid("metadata fixture lacks a record"))?;
    let identity = TERRANE_V1
        .from_digest(IdentityKind::Manifest, entry.hash())
        .map_err(io::Error::other)?;
    let start = usize::try_from(entry.offset()).map_err(io::Error::other)?;
    let end = start
        .checked_add(usize::try_from(entry.body_len()).map_err(io::Error::other)?)
        .ok_or_else(|| invalid("metadata fixture range overflow"))?;
    let expected = pair
        .pack
        .get(start..end)
        .ok_or_else(|| invalid("metadata fixture body absent"))?
        .to_vec();
    let admission = runtime
        .block_on(owner.admit_metadata_pack(pair.id, pair.pack, pair.index))
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
        .ok_or_else(|| invalid("metadata failure deadline overflow"))?;
    let retained = runtime.block_on(owner.retain_manifest(identity.clone()))?;
    retained.check_current()?;
    let first = runtime.block_on(owner.pin_resident_metadata(identity.clone(), expires))?;
    let alias = runtime.block_on(owner.pin_resident_metadata(identity, expires))?;
    if first.read_verified()? != expected || alias.read_encoded()? != expected {
        return Err(invalid("metadata failure lacks genuine verified consumers"));
    }
    let policy = inputs.root.join("state/cache/records.toml");
    let records = fs::read(&policy)?;
    let stalled = runtime.block_on(owner.stall_policy_for_fixture())?;
    emit("READY genuine metadata consumers verified with physical policy held")?;
    control("damaged")?;
    // Exercise both reporting directions: reconstruction first for the pack,
    // consumer first for the detached index. They share the original observation.
    let served = if inputs.domain == "tenant:metadata-pack-read-failure" {
        retained.check_native_backing().is_ok()
    } else {
        first.read_verified().is_ok()
    };
    if served
        || first.read_verified().is_ok()
        || retained.check_native_backing().is_ok()
        || fs::read(&policy)? != records
    {
        return Err(invalid(
            "damaged metadata original served or funding changed",
        ));
    }
    emit("READY original metadata failure latched before restoring bytes")?;
    control("restored")?;
    if first.read_verified().is_ok()
        || alias.read_verified().is_ok()
        || alias.read_encoded().is_ok()
        || retained.check_native_backing().is_ok()
    {
        return Err(invalid("restored bytes revived original metadata aliases"));
    }
    drop(stalled);
    if runtime.block_on(owner.sweep_consumer_leases()).is_ok() || fs::read(&policy)? != records {
        return Err(invalid("metadata failure released original funding"));
    }
    emit("READY actual metadata failed-read quarantine completed with original funding retained")?;
    control("finish")?;
    emit(
        "PASS actual retained reconstruction and independent consumers share permanent denial and original pair quarantine after either reader reports corruption",
    )?;
    emit(
        "PASS actual metadata consumer failure denies all original aliases after byte restoration and quarantines both original pack and index without funding release",
    )
}

fn control(expected: &str) -> io::Result<()> {
    let mut line = String::new();
    io::stdin().lock().read_line(&mut line)?;
    if line.trim_end() != expected {
        return Err(invalid("unexpected metadata failure control"));
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
