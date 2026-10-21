//! Exercises original resident reads and actual circuit-controlled lower fallback.

use super::{config::Inputs, lower_fetch::LowerChunk};
use std::{
    io,
    time::{Duration, UNIX_EPOCH},
};
use terrane_format::{
    chunking::ChunkProfile,
    identity::{Descriptor, IdentityKind, TERRANE_V1},
};
use terrane_linux::host_cache::{NativeChunkFetchRequest, NativeMetadataOwner};
use terrane_sdk::{
    host::cache::CircuitBreaker,
    repository::MetadataValidator,
    store::{ChunkPosition, Clock, TokioClock},
};

/// Checks a fetched native admission, resident hit and invalid-context refusal.
///
/// # Errors
/// Refuses a reused domain, failed genuine recovery, wrong provider dispatch,
/// missing actual cache handoff, changed canonical bytes or unexpected fallback.
pub(super) fn run(
    owner: &NativeMetadataOwner,
    runtime: &tokio::runtime::Runtime,
    inputs: &Inputs,
    original: Option<Vec<u8>>,
) -> io::Result<()> {
    if inputs.domain != "tenant:read-through" || original.is_some() {
        return Err(invalid("read-through requires its fresh isolated domain"));
    }
    let completed = runtime.block_on(owner.recover())?;
    runtime
        .block_on(owner.resume_recovered(completed))
        .map_err(io::Error::other)?;
    let plaintext = b"actual verified native read-through content";
    let identity = TERRANE_V1
        .calculate(IdentityKind::Chunk, plaintext)
        .map_err(io::Error::other)?;
    let descriptor =
        Descriptor::from_identity(&TERRANE_V1, &identity, plaintext).map_err(io::Error::other)?;
    let mut encoded = vec![0];
    encoded.extend_from_slice(plaintext);
    let lower = [
        LowerChunk::new(identity.clone(), vec![0xff]),
        LowerChunk::new(identity.clone(), encoded.clone()),
    ];
    let mut circuits = [
        CircuitBreaker::new(1, Duration::from_secs(5)).map_err(io::Error::other)?,
        CircuitBreaker::new(1, Duration::from_secs(5)).map_err(io::Error::other)?,
    ];
    let validator = MetadataValidator::new(ChunkProfile::cdc_1m([0; 32]));
    let expires = TokioClock
        .now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_secs()
        .checked_add(90)
        .ok_or_else(|| invalid("read-through deadline overflows"))?;
    let request = || NativeChunkFetchRequest {
        descriptor: &descriptor,
        position: ChunkPosition::Final,
        dictionary: None,
        budget: Duration::from_secs(5),
    };
    let first = runtime
        .block_on(owner.read_or_fetch_chunk(
            &lower,
            &mut circuits,
            &TokioClock,
            expires,
            request(),
            &validator,
        ))
        .map_err(io::Error::other)?;
    if first.encoded_bytes() != encoded || lower.iter().any(|child| child.calls() != 1) {
        return Err(invalid(
            "missing original did not reject corrupt lower and fetch exact good copy",
        ));
    }
    let (_, submission) = first.into_parts();
    let ticket = submission
        .ok_or_else(|| invalid("missing original returned a resident result"))?
        .map_err(io::Error::other)?;
    let admitted = runtime
        .block_on(ticket.finish())
        .map_err(io::Error::other)?;
    runtime
        .block_on(admitted.into_cache(owner))
        .map_err(io::Error::other)?;
    let resident = runtime
        .block_on(owner.read_or_fetch_chunk(
            &lower,
            &mut circuits,
            &TokioClock,
            expires,
            request(),
            &validator,
        ))
        .map_err(io::Error::other)?;
    if resident.encoded_bytes() != encoded
        || resident.into_parts().1.is_some()
        || lower.iter().any(|child| child.calls() != 1)
    {
        return Err(invalid(
            "actual original resident read retried lower or created a new admission",
        ));
    }
    let wrong = Descriptor::from_wire(
        &TERRANE_V1,
        descriptor.algorithm(),
        descriptor.domain(),
        descriptor.digest(),
        descriptor.size() + 1,
    )
    .map_err(io::Error::other)?;
    let refused = runtime.block_on(owner.read_or_fetch_chunk(
        &lower,
        &mut circuits,
        &TokioClock,
        expires,
        NativeChunkFetchRequest {
            descriptor: &wrong,
            ..request()
        },
        &validator,
    ));
    if refused.is_ok() || lower.iter().any(|child| child.calls() != 1) {
        return Err(invalid(
            "wrong resident context retried lower or returned bytes",
        ));
    }
    let wrong_kind = Descriptor::from_wire(
        &TERRANE_V1,
        descriptor.algorithm(),
        TERRANE_V1
            .domain(IdentityKind::Node)
            .map_err(io::Error::other)?,
        descriptor.digest(),
        descriptor.size(),
    )
    .map_err(io::Error::other)?;
    let snapshot = inputs.root.join("state/cache/records.toml");
    let before = std::fs::read(&snapshot)?;
    let refused = runtime.block_on(owner.read_or_fetch_chunk(
        &lower,
        &mut circuits,
        &TokioClock,
        expires,
        NativeChunkFetchRequest {
            descriptor: &wrong_kind,
            ..request()
        },
        &validator,
    ));
    let direct = runtime.block_on(owner.fetch_chunk(
        &lower,
        &mut circuits,
        &TokioClock,
        NativeChunkFetchRequest {
            descriptor: &wrong_kind,
            ..request()
        },
        &validator,
    ));
    if refused.is_ok()
        || direct.is_ok()
        || lower.iter().any(|child| child.calls() != 1)
        || std::fs::read(snapshot)? != before
    {
        return Err(invalid(
            "wrong descriptor kind dispatched native or lower effects",
        ));
    }
    println!(
        "PASS actual original-then-lower read rejects corrupt provider, completes genuine admission, serves resident without lower traffic and refuses wrong context"
    );
    Ok(())
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::other(message)
}
