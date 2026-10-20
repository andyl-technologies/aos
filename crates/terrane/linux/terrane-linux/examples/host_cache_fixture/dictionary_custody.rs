//! Retains a genuine dictionary whose plaintext identity equals its dependent.
//!
//! Different canonical codec bodies remain distinct actual admitted jobs. An
//! identity comparison cannot replace their native dependency relationship.

use super::{config::{HOLD, Inputs, STATE}, manifest_publication};
use std::{fs::{self, File}, io::{self, BufRead, Write}, os::unix::fs::MetadataExt};
use terrane_sdk::{host::cache::CacheState, store::{ChunkPosition, TokioLocalFs}};
use terrane_format::{chunking::ChunkProfile, identity::{Descriptor, IdentityKind, TERRANE_V1}};
use terrane_linux::host_cache::NativeMetadataOwner;

/// Exercises real codec variants, cache handoff and dictionary-transfer refusal.
///
/// # Errors
/// Refuses changed actual bytes, lost dependency protection, producer funding
/// left after handoff, premature source retirement or incorrect native outcomes.
pub(super) fn run(
    owner: &NativeMetadataOwner,
    runtime: &tokio::runtime::Runtime,
    inputs: &Inputs,
    original: Option<Vec<u8>>,
) -> io::Result<()> {
    if inputs.domain != "tenant:dictionary-custody" || original.is_some() {
        return Err(invalid("dictionary custody requires a fresh dedicated domain"));
    }
    let completed = runtime.block_on(owner.recover())?;
    runtime.block_on(owner.resume_recovered(completed)).map_err(io::Error::other)?;
    let bytes = manifest_publication::nonfinal_fixture_chunk()?;
    let identity = TERRANE_V1.calculate(IdentityKind::Chunk, &bytes).map_err(io::Error::other)?;
    let descriptor = Descriptor::from_identity(&TERRANE_V1, &identity, &bytes).map_err(io::Error::other)?;
    let raw = [vec![0], bytes.clone()].concat();
    let encoded = terrane_sdk::codec::encode_chunk(&bytes, ChunkProfile::cdc_1m([0; 32]).maximum(),
        3, Some(&bytes)).map_err(io::Error::other)?;
    if encoded.first() != Some(&2) || encoded.get(1..33) != Some(identity.digest()) {
        return Err(invalid("fixture lacks a genuine same-identity dictionary encoding"));
    }
    let dictionary = runtime.block_on(owner.admit_chunk(descriptor.clone(), ChunkPosition::Final,
        raw.clone())).map_err(io::Error::other)?;
    runtime.block_on(dictionary.into_cache(owner)).map_err(io::Error::other)?;
    let dependent = runtime.block_on(owner.admit_chunk(descriptor.clone(), ChunkPosition::NonFinal,
        encoded.clone())).map_err(io::Error::other)?;
    let report = runtime.block_on(dependent.into_cache(owner)).map_err(io::Error::other)?;
    let hash: String = identity.digest().iter().map(|byte| format!("{byte:02x}")).collect();
    let directory = inputs.root.join("chunks").join(&hash[..2]);
    let dictionary_path = directory.join(format!("{hash}.0"));
    let dependent_path = directory.join(format!("{hash}.2"));
    let original_dictionary = File::open(&dictionary_path)?.metadata()?;
    let original_dependent = File::open(&dependent_path)?.metadata()?;
    if original_dictionary.ino() == original_dependent.ino()
        || fs::read(&dictionary_path)? != raw || fs::read(&dependent_path)? != encoded {
        return Err(invalid("dictionary fixture lost its distinct original admitted inodes"));
    }
    let state = load(runtime, inputs)?;
    check(&state, &hash, 2)?;
    if report.future_hold_bytes != HOLD {
        return Err(invalid("same-identity handoff retained producer funding"));
    }
    let before = fs::read(inputs.root.join("state/cache/records.toml"))?;
    let error = runtime.block_on(owner.publish_inline(descriptor, raw.clone()))
        .err().ok_or_else(|| invalid("live dictionary was retired for inline publication"))?;
    if error.kind() != io::ErrorKind::WouldBlock
        || fs::read(inputs.root.join("state/cache/records.toml"))? != before
        || fs::metadata(&dictionary_path)?.ino() != original_dictionary.ino()
        || fs::metadata(&dependent_path)?.ino() != original_dependent.ino() {
        return Err(invalid("dictionary transfer refusal changed original backing or policy"));
    }
    runtime.block_on(owner.sweep_consumer_leases())?;
    let expires = state.leases.iter().filter(|lease| lease.owner.starts_with("admission-grace:"))
        .map(|lease| lease.expires).max().ok_or_else(|| invalid("dictionary grace absent"))?;
    emit(&format!("DICTIONARY_CUSTODY_GRACE expires={expires} hash={hash} charged_reserved_bytes={} future_hold_bytes={}",
        report.charged_reserved_bytes, report.future_hold_bytes))?;
    emit("READY same-identity dictionary retains its actual dependent after producer handoff")?;
    control("after-grace")?;
    check(&load(runtime, inputs)?, &hash, 0)?;
    if fs::metadata(&dictionary_path)?.ino() != original_dictionary.ino()
        || fs::metadata(&dependent_path)?.ino() != original_dependent.ino()
        || fs::read(&dictionary_path)? != raw || fs::read(&dependent_path)? != encoded {
        return Err(invalid("same-identity dictionary lost original bytes through release grace"));
    }
    emit("READY same-identity dictionary remains protected after actual producer grace")?;
    control("finish")?;
    emit("PASS actual distinct codec inodes retain same-identity dictionary dependency and refuse retirement while its admitted dependent survives; no Ready")
}

fn check(state: &CacheState, hash: &str, grace: usize) -> io::Result<()> {
    let dependencies: Vec<_> = state.pins.iter().filter(|pin| pin.owner.starts_with("cache-dependency:")).collect();
    if state.reservations.len() != 1 || state.reservations.iter().any(|hold| hold.bytes != HOLD)
        || dependencies.len() != 1 || dependencies.iter().any(|pin| pin.hash != hash)
        || state.leases.iter().filter(|lease| lease.owner.starts_with("cache-dependency:")).count() != 1
        || state.leases.iter().filter(|lease| lease.owner.starts_with("admission-grace:")).count() != grace
        || state.pins.iter().any(|pin| pin.owner.starts_with("admission:"))
        || state.leases.iter().any(|lease| lease.owner.starts_with("admission:")) {
        return Err(invalid("same-identity dictionary lost its genuine dependency promise"));
    }
    Ok(())
}

fn load(runtime: &tokio::runtime::Runtime, inputs: &Inputs) -> io::Result<CacheState> {
    runtime.block_on(CacheState::load(&TokioLocalFs, &inputs.root.join("state/cache"), STATE))
        .map_err(io::Error::other)?.ok_or_else(|| invalid("dictionary custody policy absent"))
}

fn emit(message: &str) -> io::Result<()> {
    writeln!(io::stdout().lock(), "{message}")?;
    io::stdout().flush()
}

fn control(expected: &str) -> io::Result<()> {
    let mut line = String::new();
    io::stdin().lock().read_line(&mut line)?;
    if line.trim_end() != expected { return Err(invalid("dictionary custody control mismatch")); }
    Ok(())
}

fn invalid(message: &'static str) -> io::Error { io::Error::other(message) }
