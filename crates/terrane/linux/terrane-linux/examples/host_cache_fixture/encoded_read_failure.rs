//! Exercises retained encoded read denial and exact original quarantine.

use super::{config::Inputs, lower_fetch, manifest_publication};
use std::{
    fs,
    io::{self, BufRead, Write},
    time::{Duration, UNIX_EPOCH},
};
use terrane_format::identity::{Descriptor, IdentityKind, TERRANE_V1};
use terrane_linux::host_cache::{NativeChunkFetchRequest, NativeMetadataOwner};
use terrane_sdk::{
    host::cache::CircuitBreaker,
    repository::MetadataValidator,
    store::{ChunkPosition, Clock, TokioClock},
};

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
    let with_dictionary = inputs.domain == "tenant:encoded-dictionary-read-failure";
    if (!with_dictionary && inputs.domain != "tenant:encoded-read-failure") || original.is_some() {
        return Err(invalid("encoded failure requires a fresh dedicated domain"));
    }
    let completed = runtime.block_on(owner.recover())?;
    runtime
        .block_on(owner.resume_recovered(completed))
        .map_err(io::Error::other)?;

    let profile = inputs.owner_config()?.location.chunk_profile().clone();
    let plaintext = if with_dictionary {
        manifest_publication::data(false, false)?.first
    } else {
        b"original encoded consumer custody".to_vec()
    };
    let identity = TERRANE_V1
        .calculate(IdentityKind::Chunk, &plaintext)
        .map_err(io::Error::other)?;
    let descriptor =
        Descriptor::from_identity(&TERRANE_V1, &identity, &plaintext).map_err(io::Error::other)?;
    let dictionary = if with_dictionary {
        let bytes = plaintext
            .get(..profile.minimum() - 1)
            .ok_or_else(|| invalid("missing dictionary prefix"))?;
        let identity = TERRANE_V1
            .calculate(IdentityKind::Chunk, bytes)
            .map_err(io::Error::other)?;
        let descriptor =
            Descriptor::from_identity(&TERRANE_V1, &identity, bytes).map_err(io::Error::other)?;
        let encoded = [vec![0], bytes.to_vec()].concat();
        let admission = runtime
            .block_on(owner.admit_chunk(descriptor, ChunkPosition::Final, encoded))
            .map_err(io::Error::other)?;
        // Keep this genuine dictionary producer receipt. Its reservation must
        // remain distinct from the dependent's completed cache handoff.
        Some((admission, bytes.to_vec()))
    } else {
        None
    };
    let (position, encoded) = if let Some((_, dictionary)) = &dictionary {
        let encoded =
            terrane_sdk::codec::encode_chunk(&plaintext, profile.maximum(), 3, Some(dictionary))
                .map_err(io::Error::other)?;
        if encoded.first() != Some(&2) {
            return Err(invalid("fixture lacks genuine dictionary encoding"));
        }
        (ChunkPosition::NonFinal, encoded)
    } else {
        (ChunkPosition::Final, [vec![0], plaintext.clone()].concat())
    };
    let admission = runtime
        .block_on(owner.admit_chunk(descriptor.clone(), position, encoded.clone()))
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
    let alias = runtime.block_on(owner.pin_resident_chunk(identity.clone(), expires))?;
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

    let mut corrupt = encoded.clone();
    let codec = corrupt
        .first_mut()
        .ok_or_else(|| invalid("missing original encoded envelope"))?;
    *codec = 0xff;
    let lower = [
        lower_fetch::LowerChunk::new(identity.clone(), corrupt),
        lower_fetch::LowerChunk::new(identity, encoded.clone()),
    ];
    let mut circuits = [
        CircuitBreaker::new(1, Duration::from_secs(5)).map_err(io::Error::other)?,
        CircuitBreaker::new(1, Duration::from_secs(5)).map_err(io::Error::other)?,
    ];
    let validator = MetadataValidator::new(profile);
    let fetched = runtime
        .block_on(owner.read_or_fetch_chunk(
            &lower,
            &mut circuits,
            &TokioClock,
            expires,
            NativeChunkFetchRequest {
                descriptor: &descriptor,
                position,
                dictionary: dictionary.as_ref().map(|(_, bytes)| bytes.as_slice()),
                budget: Duration::from_secs(5),
            },
            &validator,
        ))
        .map_err(io::Error::other)?;
    if fetched.encoded_bytes() != encoded || lower.iter().any(|source| source.calls() != 1) {
        return Err(invalid(
            "lower refetch did not reject corrupt bytes and verify its good fallback",
        ));
    }
    let (_, admission) = fetched.into_parts();
    let admission = admission
        .ok_or_else(|| invalid("rejected original unexpectedly returned a resident read"))?;
    let failed = match admission {
        Ok(ticket) => runtime.block_on(ticket.finish()).is_err(),
        Err(_) => true,
    };
    if !failed
        || fs::read(&policy)? != records
        || alias.read_verified().is_ok()
        || first.read_encoded().is_ok()
    {
        return Err(invalid(
            "verified lower refetch revived rejected native custody or changed original protection",
        ));
    }
    emit(
        "PASS automatic original-then-lower read preserves permanent rejected aliases and actual quarantine funding",
    )?;
    emit(
        "READY verified good lower refetch returned while rejected aliases, original quarantine and funding remain retained",
    )?;
    control("refetch-checked")?;
    if with_dictionary {
        emit(
            "PASS actual encoded read failure retains producer-funded original dictionary and dependency pins while denying dependent aliases and quarantining only its original inode",
        )
    } else {
        emit(
            "PASS actual encoded read failure denies all original consumer aliases after byte restoration and quarantines original inode without funding release",
        )
    }
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
