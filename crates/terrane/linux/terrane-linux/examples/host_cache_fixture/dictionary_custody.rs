//! Retains a genuine dictionary while its actual admitted dependent survives.
//!
//! The two canonical bodies have distinct identities and original native jobs.
//! Their actual dependency relationship survives producer handoff and grace.

use super::{
    config::{HOLD, Inputs, STATE},
    manifest_publication,
};
use std::{
    fs::{self, File},
    io::{self, BufRead, Write},
    os::unix::fs::MetadataExt,
};
use terrane_format::identity::{Descriptor, IdentityKind, TERRANE_V1};
use terrane_linux::host_cache::{NativeChunkAdmissionError, NativeMetadataOwner};
use terrane_sdk::{
    host::cache::CacheState,
    store::{ChunkPosition, TokioLocalFs},
};

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
        return Err(invalid(
            "dictionary custody requires a fresh dedicated domain",
        ));
    }

    let completed = runtime.block_on(owner.recover())?;
    runtime
        .block_on(owner.resume_recovered(completed))
        .map_err(io::Error::other)?;

    let data = manifest_publication::data(false, true)?;
    let dictionary_bytes = data
        .dictionary
        .as_ref()
        .ok_or_else(|| invalid("dictionary custody fixture lacks its actual dictionary"))?;
    let identity = TERRANE_V1
        .calculate(IdentityKind::Chunk, dictionary_bytes)
        .map_err(io::Error::other)?;
    let dictionary_descriptor = Descriptor::from_identity(&TERRANE_V1, &identity, dictionary_bytes)
        .map_err(io::Error::other)?;
    let dependent_identity = TERRANE_V1
        .calculate(IdentityKind::Chunk, &data.first)
        .map_err(io::Error::other)?;
    let dependent_descriptor =
        Descriptor::from_identity(&TERRANE_V1, &dependent_identity, &data.first)
            .map_err(io::Error::other)?;
    let raw = [vec![0], dictionary_bytes.to_vec()].concat();
    let encoded = data.encoded_first;
    if encoded.first() != Some(&2)
        || encoded.get(1..33) != Some(identity.digest())
        || dependent_identity == identity
    {
        return Err(invalid(
            "fixture lacks a genuine distinct dictionary-dependent encoding",
        ));
    }

    let dictionary = runtime
        .block_on(owner.admit_chunk(
            dictionary_descriptor.clone(),
            ChunkPosition::Final,
            raw.clone(),
        ))
        .map_err(io::Error::other)?;
    runtime
        .block_on(dictionary.into_cache(owner))
        .map_err(io::Error::other)?;
    let dependent = runtime
        .block_on(owner.admit_chunk(
            dependent_descriptor,
            ChunkPosition::NonFinal,
            encoded.clone(),
        ))
        .map_err(io::Error::other)?;
    let report = runtime
        .block_on(dependent.into_cache(owner))
        .map_err(io::Error::other)?;

    let hash: String = identity
        .digest()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let dependent_hash: String = dependent_identity
        .digest()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let directory = inputs.root.join("chunks").join(&hash[..2]);
    let dictionary_path = directory.join(format!("{hash}.0"));
    let dependent_path = inputs
        .root
        .join("chunks")
        .join(&dependent_hash[..2])
        .join(format!("{dependent_hash}.2"));
    let original_dictionary = File::open(&dictionary_path)?.metadata()?;
    let original_dependent = File::open(&dependent_path)?.metadata()?;
    if original_dictionary.ino() == original_dependent.ino()
        || fs::read(&dictionary_path)? != raw
        || fs::read(&dependent_path)? != encoded
    {
        return Err(invalid(
            "dictionary fixture lost its distinct original admitted inodes",
        ));
    }

    let state = load(runtime, inputs)?;
    check(&state, &hash, 2)?;
    if report.future_hold_bytes != HOLD {
        return Err(invalid("handoff retained producer funding"));
    }

    let before = fs::read(inputs.root.join("state/cache/records.toml"))?;
    let error = runtime
        .block_on(owner.publish_inline(dictionary_descriptor, raw.clone()))
        .err()
        .ok_or_else(|| invalid("live dictionary was retired for inline publication"))?;
    let NativeChunkAdmissionError::Accepted(error) = error else {
        return Err(invalid(
            "dictionary refusal did not reach the physical owner",
        ));
    };
    if error.kind() != io::ErrorKind::WouldBlock {
        return Err(io::Error::other(format!(
            "dictionary retirement returned an unexpected error: {error:?}"
        )));
    }
    if fs::read(inputs.root.join("state/cache/records.toml"))? != before {
        return Err(invalid("dictionary retirement refusal changed policy"));
    }
    if fs::metadata(&dictionary_path)?.ino() != original_dictionary.ino()
        || fs::metadata(&dependent_path)?.ino() != original_dependent.ino()
    {
        return Err(invalid(
            "dictionary retirement refusal changed original inodes",
        ));
    }

    runtime.block_on(owner.sweep_consumer_leases())?;
    let expires = state
        .leases
        .iter()
        .filter(|lease| lease.owner.starts_with("admission-grace:"))
        .map(|lease| lease.expires)
        .max()
        .ok_or_else(|| invalid("dictionary grace absent"))?;
    emit(&format!(
        "DICTIONARY_CUSTODY_GRACE expires={expires} hash={hash} dependent_hash={dependent_hash} charged_reserved_bytes={} future_hold_bytes={}",
        report.charged_reserved_bytes, report.future_hold_bytes
    ))?;
    emit(
        "READY genuine dictionary remains protected by its actual admitted dependent after producer handoff",
    )?;

    control("after-grace")?;
    check(&load(runtime, inputs)?, &hash, 0)?;
    if fs::metadata(&dictionary_path)?.ino() != original_dictionary.ino()
        || fs::metadata(&dependent_path)?.ino() != original_dependent.ino()
        || fs::read(&dictionary_path)? != raw
        || fs::read(&dependent_path)? != encoded
    {
        return Err(invalid(
            "dictionary lost original bytes through release grace",
        ));
    }

    emit("READY actual dictionary remains protected after producer grace")?;
    control("finish")?;
    emit(
        "PASS actual original dictionary and admitted dependent retain dependency protection and refuse dictionary retirement through actual grace; no Ready",
    )
}

fn check(state: &CacheState, hash: &str, grace: usize) -> io::Result<()> {
    let dependencies: Vec<_> = state
        .pins
        .iter()
        .filter(|pin| pin.owner.starts_with("cache-dependency:"))
        .collect();
    if state.reservations.len() != 1
        || state.reservations.iter().any(|hold| hold.bytes != HOLD)
        || dependencies.len() != 1
        || dependencies.iter().any(|pin| pin.hash != hash)
        || state
            .leases
            .iter()
            .filter(|lease| lease.owner.starts_with("cache-dependency:"))
            .count()
            != 1
        || state
            .leases
            .iter()
            .filter(|lease| lease.owner.starts_with("admission-grace:"))
            .count()
            != grace
        || state
            .pins
            .iter()
            .any(|pin| pin.owner.starts_with("admission:"))
        || state
            .leases
            .iter()
            .any(|lease| lease.owner.starts_with("admission:"))
    {
        return Err(invalid("dictionary lost its genuine dependency promise"));
    }
    Ok(())
}

fn load(runtime: &tokio::runtime::Runtime, inputs: &Inputs) -> io::Result<CacheState> {
    runtime
        .block_on(CacheState::load(
            &TokioLocalFs,
            &inputs.root.join("state/cache"),
            STATE,
        ))
        .map_err(io::Error::other)?
        .ok_or_else(|| invalid("dictionary custody policy absent"))
}

fn emit(message: &str) -> io::Result<()> {
    writeln!(io::stdout().lock(), "{message}")?;
    io::stdout().flush()
}

fn control(expected: &str) -> io::Result<()> {
    let mut line = String::new();
    io::stdin().lock().read_line(&mut line)?;
    if line.trim_end() != expected {
        return Err(invalid("dictionary custody control mismatch"));
    }
    Ok(())
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::other(message)
}
